"""Simple-WireGuard HTTP API + static PWA."""
import asyncio
import collections
import logging
import re
import time
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import backup, config, db, logsetup, notify, security, wg

logsetup.setup()
log = logging.getLogger("swg")
app = FastAPI(title="Simple-WireGuard", docs_url=None, redoc_url=None, openapi_url=None)
COOKIE = "swg_session"
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")
_rate: dict[str, collections.deque] = collections.defaultdict(collections.deque)
_peer_online: dict[str, bool] = {}


# --- helpers ----------------------------------------------------------------

def client_ip(request: Request) -> str:
    # nginx sets X-Real-IP; the app itself only listens on 127.0.0.1.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "-")


def rate_limited(key: str, limit: int, window: int) -> bool:
    now = time.time()
    dq = _rate[key]
    while dq and dq[0] < now - window:
        dq.popleft()
    if len(dq) >= limit:
        return True
    dq.append(now)
    return False


def fail(status: int, msg: str):
    raise HTTPException(status_code=status, detail=msg)


def set_session_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(COOKIE, token, httponly=True, secure=not config.DEV, samesite="strict",
                    path="/", max_age=config.SESSION_MAX_SECONDS)


def create_session(user_id: int, stage: str, request: Request, resp: Response) -> str:
    token, csrf, now = security.new_token(), security.new_token(), int(time.time())
    db.ex("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
          (security.sha256(token), user_id, csrf, stage, now, now, client_ip(request),
           (request.headers.get("user-agent") or "")[:200]))
    set_session_cookie(resp, token)
    return csrf


def load_session(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    s = db.one("SELECT s.*, u.username, u.role, u.must_change_password FROM sessions s "
               "JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?", (security.sha256(token),))
    if not s:
        return None
    now = int(time.time())
    limit_idle = config.PREAUTH_SECONDS if s["stage"] != "full" else config.SESSION_IDLE_SECONDS
    if now - s["last_seen"] > limit_idle or now - s["created_at"] > config.SESSION_MAX_SECONDS:
        db.ex("DELETE FROM sessions WHERE id_hash = ?", (s["id_hash"],))
        return None
    return s


def check_csrf(request: Request, s) -> None:
    if request.method not in ("GET", "HEAD") and \
            not security.secrets.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
        fail(403, "CSRF-Prüfung fehlgeschlagen")


def preauth(request: Request):
    s = load_session(request)
    if not s or s["stage"] not in ("totp", "enroll"):
        fail(401, "Bitte erneut anmelden")
    check_csrf(request, s)
    return s


def auth(request: Request):
    s = load_session(request)
    if not s or s["stage"] != "full":
        fail(401, "Nicht angemeldet")
    check_csrf(request, s)
    db.ex("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (int(time.time()), s["id_hash"]))
    return s


def admin(s=Depends(auth)):
    if s["role"] != "admin":
        fail(403, "Nur für Administratoren")
    return s


def audit(request: Request, s, action: str, detail: str = "") -> None:
    db.audit(action, s["username"] if s else None, client_ip(request), detail)


def apply_or_warn() -> str | None:
    try:
        wg.apply()
        return None
    except wg.AgentError as exc:
        log.error("apply failed: %s", exc)
        notify.send("notify_system", "Fehler beim Anwenden", str(exc), 1)
        return f"Gespeichert, aber nicht auf das Interface angewendet: {exc}"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.exception_handler(ValueError)
async def value_error(_request: Request, exc: ValueError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


# --- auth -------------------------------------------------------------------

class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class CodeIn(BaseModel):
    code: str = Field(max_length=10)


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, response: Response):
    ip = client_ip(request)
    if rate_limited("login:" + ip, 10, 300):
        fail(429, "Zu viele Anmeldeversuche, bitte später erneut versuchen")
    u = db.one("SELECT * FROM users WHERE username = ?", (body.username,))
    now = int(time.time())
    ok = security.verify_password(u["password_hash"] if u else None, body.password)
    if u and u["locked_until"] > now:
        db.audit("login_locked", body.username, ip)
        fail(423, "Konto vorübergehend gesperrt")
    if not ok:
        if u:
            cnt = u["failed_count"] + 1
            locked = now + config.LOCKOUT_SECONDS if cnt >= config.LOCKOUT_THRESHOLD else 0
            db.ex("UPDATE users SET failed_count = ?, locked_until = ? WHERE id = ?",
                  (0 if locked else cnt, locked, u["id"]))
            if locked:
                db.audit("account_locked", u["username"], ip, f"{cnt} Fehlversuche")
                notify.send("notify_login_failed", "Konto gesperrt",
                            f"Benutzer {u['username']} nach {cnt} Fehlversuchen gesperrt (IP {ip})", 1)
        db.audit("login_failed", body.username[:64], ip)
        fail(401, "Benutzername oder Passwort falsch")
    stage = "totp" if u["totp_enabled"] else "enroll"
    csrf = create_session(u["id"], stage, request, response)
    return {"stage": stage, "csrf": csrf}


@app.post("/api/auth/totp")
def login_totp(body: CodeIn, request: Request, response: Response, s=Depends(preauth)):
    if s["stage"] != "totp":
        fail(400, "Falscher Anmeldeschritt")
    if rate_limited("totp:" + str(s["user_id"]), 5, 300):
        fail(429, "Zu viele Versuche")
    u = db.one("SELECT * FROM users WHERE id = ?", (s["user_id"],))
    step = security.verify_totp(security.decrypt(u["totp_secret_enc"]) or "", body.code, u["totp_last_step"])
    if step is None:
        db.audit("totp_failed", u["username"], client_ip(request))
        fail(401, "Code ungültig")
    return _finish_login(u, step, s, request, response)


def _finish_login(u, step, s, request, response):
    db.ex("DELETE FROM sessions WHERE id_hash = ?", (s["id_hash"],))
    db.ex("UPDATE users SET totp_last_step = ?, failed_count = 0, locked_until = 0, last_login = ? WHERE id = ?",
          (step, int(time.time()), u["id"]))
    csrf = create_session(u["id"], "full", request, response)  # new id: no session fixation
    db.audit("login", u["username"], client_ip(request))
    notify.send("notify_login", "Anmeldung", f"{u['username']} hat sich angemeldet (IP {client_ip(request)})")
    return {"stage": "full", "csrf": csrf}


@app.get("/api/auth/enroll")
def enroll_get(s=Depends(preauth)):
    if s["stage"] != "enroll":
        fail(400, "TOTP bereits eingerichtet")
    u = db.one("SELECT * FROM users WHERE id = ?", (s["user_id"],))
    secret = security.decrypt(u["totp_secret_enc"])
    if not secret:
        secret = security.new_totp_secret()
        db.ex("UPDATE users SET totp_secret_enc = ? WHERE id = ?", (security.encrypt(secret), u["id"]))
    uri = security.totp_uri(secret, u["username"])
    return {"secret": secret, "uri": uri, "qr": security.qr_svg_data_uri(uri)}


@app.post("/api/auth/enroll")
def enroll_post(body: CodeIn, request: Request, response: Response, s=Depends(preauth)):
    if s["stage"] != "enroll":
        fail(400, "TOTP bereits eingerichtet")
    u = db.one("SELECT * FROM users WHERE id = ?", (s["user_id"],))
    step = security.verify_totp(security.decrypt(u["totp_secret_enc"]) or "", body.code, 0)
    if step is None:
        fail(401, "Code ungültig – Uhrzeit des Smartphones prüfen")
    db.ex("UPDATE users SET totp_enabled = 1 WHERE id = ?", (u["id"],))
    db.audit("totp_enrolled", u["username"], client_ip(request))
    return _finish_login(u, step, s, request, response)


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    s = load_session(request)
    if s:
        check_csrf(request, s)
        db.ex("DELETE FROM sessions WHERE id_hash = ?", (s["id_hash"],))
        audit(request, s, "logout")
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    s = load_session(request)
    if not s:
        return {"authenticated": False, "version": config.version()}
    return {"authenticated": s["stage"] == "full", "stage": s["stage"], "csrf": s["csrf"],
            "username": s["username"], "role": s["role"],
            "must_change_password": bool(s["must_change_password"]), "version": config.version()}


# --- account ----------------------------------------------------------------

class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


@app.post("/api/account/password")
def change_password(body: PasswordIn, request: Request, s=Depends(auth)):
    u = db.one("SELECT * FROM users WHERE id = ?", (s["user_id"],))
    if not security.verify_password(u["password_hash"], body.current):
        fail(400, "Aktuelles Passwort falsch")
    if problem := security.password_problem(body.new):
        fail(400, problem)
    db.ex("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
          (security.hash_password(body.new), u["id"]))
    db.ex("DELETE FROM sessions WHERE user_id = ? AND id_hash != ?", (u["id"], s["id_hash"]))
    audit(request, s, "password_changed")
    return {"ok": True}


@app.get("/api/account/sessions")
def my_sessions(s=Depends(auth)):
    rows = db.q("SELECT id_hash, created_at, last_seen, ip, user_agent FROM sessions "
                "WHERE user_id = ? AND stage = 'full' ORDER BY last_seen DESC", (s["user_id"],))
    return [{"id": r["id_hash"][:16], "created_at": r["created_at"], "last_seen": r["last_seen"],
             "ip": r["ip"], "user_agent": r["user_agent"], "current": r["id_hash"] == s["id_hash"]}
            for r in rows]


@app.delete("/api/account/sessions/{sid}")
def revoke_session(sid: str, request: Request, s=Depends(auth)):
    if not re.fullmatch(r"[0-9a-f]{16}", sid):
        fail(400, "Ungültige Sitzung")
    db.ex("DELETE FROM sessions WHERE user_id = ? AND substr(id_hash, 1, 16) = ? AND id_hash != ?",
          (s["user_id"], sid, s["id_hash"]))
    audit(request, s, "session_revoked", sid)
    return {"ok": True}


# --- dashboard --------------------------------------------------------------

def peer_runtime() -> tuple[dict, bool, str | None]:
    try:
        st = wg.status()
        return {p["public_key"]: p for p in st.get("peers", [])}, bool(st.get("up")), None
    except wg.AgentError as exc:
        return {}, False, str(exc)


def peer_out(r, rt: dict) -> dict:
    live = rt.get(r["public_key"], {})
    hs = live.get("latest_handshake", 0)
    now = int(time.time())
    expired = bool(r["expires_at"] and r["expires_at"] <= now)
    return {"id": r["id"], "name": r["name"], "description": r["description"], "public_key": r["public_key"],
            "address": r["address"], "client_allowed_ips": r["client_allowed_ips"], "dns": r["dns"],
            "keepalive": r["keepalive"], "enabled": bool(r["enabled"]), "expires_at": r["expires_at"],
            "expired": expired, "has_private_key": bool(r["private_key_enc"]),
            "has_psk": bool(r["preshared_key_enc"]), "created_at": r["created_at"],
            "updated_at": r["updated_at"], "created_by": r["created_by"],
            "endpoint": live.get("endpoint"), "latest_handshake": hs or None,
            "online": bool(hs and now - hs < config.ONLINE_HANDSHAKE_SECONDS),
            "rx": live.get("rx", 0), "tx": live.get("tx", 0)}


@app.get("/api/dashboard")
def dashboard(s=Depends(auth)):
    rt, up, err = peer_runtime()
    peers = [peer_out(r, rt) for r in db.q("SELECT * FROM peers ORDER BY name")]
    cfg = config.server_cfg()
    now = int(time.time())
    soon = [p for p in peers if p["expires_at"] and now < p["expires_at"] < now + 7 * 86400]
    return {
        "version": config.version(),
        "interface": {"name": cfg["iface"], "up": up, "error": err, "endpoint": cfg["endpoint"],
                      "listen_port": cfg["listen_port"], "subnet": cfg["subnet"],
                      "server_address": cfg["server_address"], "public_key": cfg["public_key"]},
        "counts": {"total": len(peers), "enabled": sum(p["enabled"] for p in peers),
                   "online": sum(p["online"] for p in peers), "expired": sum(p["expired"] for p in peers),
                   "expiring_soon": len(soon)},
        "traffic": {"rx": sum(p["rx"] for p in peers), "tx": sum(p["tx"] for p in peers)},
        "top_peers": sorted(peers, key=lambda p: p["rx"] + p["tx"], reverse=True)[:5],
        "online_peers": [p for p in peers if p["online"]],
        "expiring": soon,
        "recent_audit": [dict(r) for r in db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 8")],
    }


# --- peers ------------------------------------------------------------------

class PeerIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=500)
    address: str | None = Field(default=None, max_length=64)
    client_allowed_ips: str = Field(default="0.0.0.0/0, ::/0", max_length=1000)
    dns: str | None = Field(default=None, max_length=300)
    keepalive: int = Field(default=25, ge=0, le=3600)
    enabled: bool = True
    expires_at: int | None = None
    use_psk: bool = True
    public_key: str | None = Field(default=None, max_length=64)


def _peer_or_404(pid: int):
    r = db.one("SELECT * FROM peers WHERE id = ?", (pid,))
    if not r:
        fail(404, "Peer nicht gefunden")
    return r


@app.get("/api/peers")
def list_peers(s=Depends(auth)):
    rt, _up, _err = peer_runtime()
    return [peer_out(r, rt) for r in db.q("SELECT * FROM peers ORDER BY name COLLATE NOCASE")]


@app.get("/api/peers/defaults")
def peer_defaults(s=Depends(auth)):
    cfg = config.server_cfg()
    return {"address": wg.next_free_address(), "dns": db.get_setting("default_dns", cfg.get("dns", "")),
            "client_allowed_ips": db.get_setting("default_allowed_ips", "0.0.0.0/0, ::/0"),
            "keepalive": int(db.get_setting("default_keepalive", "25")), "subnet": cfg["subnet"]}


@app.post("/api/peers")
def create_peer(body: PeerIn, request: Request, s=Depends(admin)):
    cfg = config.server_cfg()
    name = body.name.strip()
    if db.one("SELECT id FROM peers WHERE name = ? COLLATE NOCASE", (name,)):
        fail(400, "Name bereits vergeben")
    address = wg.validate_address(body.address) if body.address else wg.next_free_address()
    if body.public_key:
        if not wg.KEY_RE.match(body.public_key.strip()):
            fail(400, "Ungültiger öffentlicher Schlüssel")
        priv, pub = None, body.public_key.strip()
    else:
        priv, pub = wg.genkeypair()
    if db.one("SELECT id FROM peers WHERE public_key = ?", (pub,)):
        fail(400, "Öffentlicher Schlüssel bereits vorhanden")
    now = int(time.time())
    dns = wg.validate_dns(body.dns if body.dns is not None else db.get_setting("default_dns", cfg.get("dns", "")))
    cur = db.ex(
        "INSERT INTO peers(name, description, public_key, private_key_enc, preshared_key_enc, address,"
        " client_allowed_ips, dns, keepalive, enabled, expires_at, created_at, updated_at, created_by)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (name, body.description.strip(), pub, security.encrypt(priv),
         security.encrypt(wg.genpsk()) if body.use_psk else None, address,
         wg.validate_cidr_list(body.client_allowed_ips), dns, body.keepalive, int(body.enabled),
         body.expires_at, now, now, s["username"]))
    audit(request, s, "peer_created", f"{name} ({address})")
    notify.send("notify_peer_changes", "Peer angelegt", f"{name} ({address}) von {s['username']}")
    return {"id": cur.lastrowid, "warning": apply_or_warn()}


@app.put("/api/peers/{pid}")
def update_peer(pid: int, body: PeerIn, request: Request, s=Depends(admin)):
    r = _peer_or_404(pid)
    name = body.name.strip()
    if db.one("SELECT id FROM peers WHERE name = ? COLLATE NOCASE AND id != ?", (name, pid)):
        fail(400, "Name bereits vergeben")
    address = wg.validate_address(body.address, pid) if body.address else r["address"]
    psk = r["preshared_key_enc"]
    if body.use_psk and not psk:
        psk = security.encrypt(wg.genpsk())
    elif not body.use_psk:
        psk = None
    db.ex("UPDATE peers SET name=?, description=?, address=?, client_allowed_ips=?, dns=?, keepalive=?,"
          " enabled=?, expires_at=?, preshared_key_enc=?, updated_at=? WHERE id=?",
          (name, body.description.strip(), address, wg.validate_cidr_list(body.client_allowed_ips),
           wg.validate_dns(body.dns or ""), body.keepalive, int(body.enabled), body.expires_at, psk,
           int(time.time()), pid))
    audit(request, s, "peer_updated", name)
    notify.send("notify_peer_changes", "Peer geändert", f"{name} von {s['username']}")
    return {"ok": True, "warning": apply_or_warn()}


@app.post("/api/peers/{pid}/toggle")
def toggle_peer(pid: int, request: Request, s=Depends(admin)):
    r = _peer_or_404(pid)
    new = 0 if r["enabled"] else 1
    db.ex("UPDATE peers SET enabled = ?, updated_at = ? WHERE id = ?", (new, int(time.time()), pid))
    audit(request, s, "peer_enabled" if new else "peer_disabled", r["name"])
    notify.send("notify_peer_changes", "Peer " + ("aktiviert" if new else "deaktiviert"), r["name"])
    return {"enabled": bool(new), "warning": apply_or_warn()}


@app.post("/api/peers/{pid}/rotate")
def rotate_peer(pid: int, request: Request, s=Depends(admin)):
    r = _peer_or_404(pid)
    priv, pub = wg.genkeypair()
    db.ex("UPDATE peers SET public_key=?, private_key_enc=?, preshared_key_enc=?, updated_at=? WHERE id=?",
          (pub, security.encrypt(priv), security.encrypt(wg.genpsk()) if r["preshared_key_enc"] else None,
           int(time.time()), pid))
    audit(request, s, "peer_keys_rotated", r["name"])
    return {"ok": True, "warning": apply_or_warn()}


@app.delete("/api/peers/{pid}")
def delete_peer(pid: int, request: Request, s=Depends(admin)):
    r = _peer_or_404(pid)
    db.ex("DELETE FROM peers WHERE id = ?", (pid,))
    audit(request, s, "peer_deleted", f"{r['name']} ({r['address']})")
    notify.send("notify_peer_changes", "Peer gelöscht", f"{r['name']} von {s['username']}")
    return {"ok": True, "warning": apply_or_warn()}


def _safe_filename(name: str) -> str:
    return (re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-") or "peer")[:15]


@app.get("/api/peers/{pid}/config")
def peer_config(pid: int, request: Request, s=Depends(admin)):
    r = _peer_or_404(pid)
    text = wg.client_config(r)
    audit(request, s, "peer_config_downloaded", r["name"])
    return PlainTextResponse(text, headers={
        "Content-Disposition": f'attachment; filename="{_safe_filename(r["name"])}.conf"'})


@app.get("/api/peers/{pid}/qr")
def peer_qr(pid: int, request: Request, s=Depends(admin)):
    r = _peer_or_404(pid)
    text = wg.client_config(r)
    audit(request, s, "peer_qr_shown", r["name"])
    return {"qr": security.qr_svg_data_uri(text, scale=4), "config": text}


# --- users ------------------------------------------------------------------

class UserIn(BaseModel):
    username: str = Field(max_length=32)
    role: str = Field(default="admin", pattern="^(admin|viewer)$")
    password: str | None = Field(default=None, max_length=256)


class UserUpdate(BaseModel):
    role: str = Field(pattern="^(admin|viewer)$")


def _user_out(r) -> dict:
    return {"id": r["id"], "username": r["username"], "role": r["role"], "totp_enabled": bool(r["totp_enabled"]),
            "locked": r["locked_until"] > time.time(), "created_at": r["created_at"],
            "last_login": r["last_login"], "must_change_password": bool(r["must_change_password"])}


def _admin_count() -> int:
    return db.one("SELECT COUNT(*) c FROM users WHERE role = 'admin'")["c"]


@app.get("/api/users")
def list_users(s=Depends(admin)):
    return [_user_out(r) for r in db.q("SELECT * FROM users ORDER BY username")]


@app.post("/api/users")
def create_user(body: UserIn, request: Request, s=Depends(admin)):
    if not USERNAME_RE.match(body.username):
        fail(400, "Benutzername: 3–32 Zeichen, a-z 0-9 . _ -")
    if db.one("SELECT id FROM users WHERE username = ?", (body.username,)):
        fail(400, "Benutzer existiert bereits")
    pw = body.password or security.generate_password()
    if problem := security.password_problem(pw):
        fail(400, problem)
    db.ex("INSERT INTO users(username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,1,?)",
          (body.username, security.hash_password(pw), body.role, int(time.time())))
    audit(request, s, "user_created", f"{body.username} ({body.role})")
    return {"ok": True, "initial_password": None if body.password else pw}


@app.put("/api/users/{uid}")
def update_user(uid: int, body: UserUpdate, request: Request, s=Depends(admin)):
    r = db.one("SELECT * FROM users WHERE id = ?", (uid,))
    if not r:
        fail(404, "Benutzer nicht gefunden")
    if r["role"] == "admin" and body.role != "admin" and _admin_count() <= 1:
        fail(400, "Der letzte Administrator kann nicht herabgestuft werden")
    db.ex("UPDATE users SET role = ? WHERE id = ?", (body.role, uid))
    audit(request, s, "user_role_changed", f"{r['username']} -> {body.role}")
    return {"ok": True}


@app.post("/api/users/{uid}/reset-totp")
def user_reset_totp(uid: int, request: Request, s=Depends(admin)):
    r = db.one("SELECT * FROM users WHERE id = ?", (uid,))
    if not r:
        fail(404, "Benutzer nicht gefunden")
    db.ex("UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?", (uid,))
    db.ex("DELETE FROM sessions WHERE user_id = ?", (uid,))
    audit(request, s, "user_totp_reset", r["username"])
    return {"ok": True}


@app.post("/api/users/{uid}/unlock")
def user_unlock(uid: int, request: Request, s=Depends(admin)):
    db.ex("UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?", (uid,))
    audit(request, s, "user_unlocked", str(uid))
    return {"ok": True}


@app.delete("/api/users/{uid}")
def delete_user(uid: int, request: Request, s=Depends(admin)):
    r = db.one("SELECT * FROM users WHERE id = ?", (uid,))
    if not r:
        fail(404, "Benutzer nicht gefunden")
    if r["id"] == s["user_id"]:
        fail(400, "Eigenes Konto kann nicht gelöscht werden")
    if r["role"] == "admin" and _admin_count() <= 1:
        fail(400, "Der letzte Administrator kann nicht gelöscht werden")
    db.ex("DELETE FROM users WHERE id = ?", (uid,))
    audit(request, s, "user_deleted", r["username"])
    return {"ok": True}


# --- settings ---------------------------------------------------------------

class SettingsIn(BaseModel):
    default_dns: str = Field(max_length=300)
    default_allowed_ips: str = Field(max_length=1000)
    default_keepalive: int = Field(ge=0, le=3600)
    notifications: dict[str, bool]


class PushoverIn(BaseModel):
    token: str = Field(default="", max_length=64)
    user: str = Field(default="", max_length=64)
    clear: bool = False


@app.get("/api/settings")
def get_settings(s=Depends(admin)):
    cfg = config.server_cfg()
    token, user = notify.credentials()
    return {"default_dns": db.get_setting("default_dns", cfg.get("dns", "")),
            "default_allowed_ips": db.get_setting("default_allowed_ips", "0.0.0.0/0, ::/0"),
            "default_keepalive": int(db.get_setting("default_keepalive", "25")),
            "notifications": {k: notify.enabled(k) for k in notify.EVENTS},
            "notification_labels": notify.EVENTS,
            # Never return secrets - only a masked hint.
            "pushover": {"configured": bool(token and user),
                         "token_hint": ("…" + token[-4:]) if token else "",
                         "user_hint": ("…" + user[-4:]) if user else ""},
            "server": cfg}


@app.put("/api/settings")
def put_settings(body: SettingsIn, request: Request, s=Depends(admin)):
    db.set_setting("default_dns", wg.validate_dns(body.default_dns))
    db.set_setting("default_allowed_ips", wg.validate_cidr_list(body.default_allowed_ips))
    db.set_setting("default_keepalive", body.default_keepalive)
    for k, v in body.notifications.items():
        if k in notify.EVENTS:
            db.set_setting(k, "1" if v else "0")
    audit(request, s, "settings_changed")
    return {"ok": True}


@app.put("/api/settings/pushover")
def put_pushover(body: PushoverIn, request: Request, s=Depends(admin)):
    if body.clear:
        db.set_setting("pushover_token_enc", None)
        db.set_setting("pushover_user_enc", None)
        audit(request, s, "pushover_cleared")
        return {"ok": True}
    for val, key in ((body.token, "pushover_token_enc"), (body.user, "pushover_user_enc")):
        if val:
            if not re.fullmatch(r"[A-Za-z0-9]{30}", val.strip()):
                fail(400, "Pushover-Schlüssel haben 30 alphanumerische Zeichen")
            db.set_setting(key, security.encrypt(val.strip()))
    audit(request, s, "pushover_updated")
    return {"ok": True}


@app.post("/api/settings/pushover/test")
def test_pushover(request: Request, s=Depends(admin)):
    try:
        notify.send_sync("Simple-WireGuard: Test", f"Testnachricht von {s['username']} – alles funktioniert.")
    except Exception as exc:  # noqa: BLE001
        fail(400, str(exc))
    audit(request, s, "pushover_test")
    return {"ok": True}


# --- backup -----------------------------------------------------------------

class ExportIn(BaseModel):
    passphrase: str = Field(min_length=12, max_length=256)
    include_users: bool = False


class RestoreIn(BaseModel):
    passphrase: str = Field(max_length=256)
    backup: dict
    include_users: bool = False


@app.post("/api/backup/export")
def export_backup(body: ExportIn, request: Request, s=Depends(admin)):
    blob = backup.export(body.passphrase, body.include_users)
    audit(request, s, "backup_exported", f"users={body.include_users}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return JSONResponse(blob, headers={
        "Content-Disposition": f'attachment; filename="simple-wireguard-backup-{stamp}.swgbak"'})


@app.post("/api/backup/restore")
def restore_backup(body: RestoreIn, request: Request, s=Depends(admin)):
    if rate_limited("restore:" + str(s["user_id"]), 5, 600):
        fail(429, "Zu viele Versuche")
    result = backup.restore(body.backup, body.passphrase, body.include_users)
    audit(request, s, "backup_restored", str(result))
    notify.send("notify_system", "Sicherung wiederhergestellt",
                f"{result['peers']} Peers durch {s['username']}", 1)
    result["warning"] = apply_or_warn()
    return result


# --- audit / system ---------------------------------------------------------

@app.get("/api/audit")
def get_audit(limit: int = 200, before: int | None = None, q: str = "", s=Depends(admin)):
    limit = max(1, min(limit, 500))
    sql, args = "SELECT * FROM audit WHERE 1=1", []
    if before:
        sql += " AND id < ?"
        args.append(before)
    if q:
        sql += " AND (action LIKE ? OR username LIKE ? OR detail LIKE ? OR ip LIKE ?)"
        args += [f"%{q[:64]}%"] * 4
    return [dict(r) for r in db.q(sql + " ORDER BY id DESC LIMIT ?", (*args, limit))]


@app.post("/api/system/restart")
def restart_interface(request: Request, s=Depends(admin)):
    try:
        wg.restart()
    except wg.AgentError as exc:
        fail(502, str(exc))
    audit(request, s, "interface_restarted")
    notify.send("notify_system", "Interface neu gestartet", f"durch {s['username']}")
    return {"ok": True}


@app.get("/api/health")
def health():
    return {"status": "ok"}


# --- background jobs --------------------------------------------------------

def housekeeping() -> None:
    now = int(time.time())
    db.ex("DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
          (now - config.SESSION_IDLE_SECONDS, now - config.SESSION_MAX_SECONDS))
    db.ex("DELETE FROM audit WHERE ts < ?", (now - 365 * 86400,))
    # Expired peers: disable them for real so the state is visible and explicit.
    expired = db.q("SELECT id, name FROM peers WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at <= ?",
                   (now,))
    if expired:
        db.ex("UPDATE peers SET enabled = 0, updated_at = ? WHERE enabled = 1 AND expires_at <= ?", (now, now))
        for p in expired:
            db.audit("peer_expired", "system", None, p["name"])
            notify.send("notify_expiry", "Peer abgelaufen", f"{p['name']} wurde automatisch deaktiviert")
        apply_or_warn()
    rt, _up, _err = peer_runtime()
    names = {r["public_key"]: r["name"] for r in db.q("SELECT public_key, name FROM peers")}
    for key, live in rt.items():
        hs = live.get("latest_handshake", 0)
        online = bool(hs and now - hs < config.ONLINE_HANDSHAKE_SECONDS)
        prev = _peer_online.get(key)
        _peer_online[key] = online
        if prev is not None and prev != online and key in names:
            notify.send("notify_peer_online", "Peer " + ("online" if online else "offline"),
                        f"{names[key]}" + (f" von {live.get('endpoint')}" if online else ""))


async def _loop():
    while True:
        try:
            await asyncio.to_thread(housekeeping)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    db.init()
    log.info("Simple-WireGuard %s started", config.version())
    try:
        await asyncio.to_thread(wg.apply)
    except Exception as exc:  # noqa: BLE001
        log.warning("initial apply failed: %s", exc)
    asyncio.create_task(_loop())


if config.WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=config.WEB_DIR, html=True), name="web")
