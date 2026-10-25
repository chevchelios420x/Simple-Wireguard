"""Encrypted configuration backup (scrypt + AES-256-GCM, passphrase chosen by the admin)."""
import base64
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config, db, security

FORMAT = "simple-wireguard-backup"
PEER_FIELDS = ("name", "description", "public_key", "address", "client_allowed_ips", "dns",
               "keepalive", "enabled", "expires_at", "created_at", "updated_at", "created_by")
USER_FIELDS = ("username", "password_hash", "role", "totp_enabled", "must_change_password", "created_at")
SECRET_SETTINGS = ("pushover_token_enc", "pushover_user_enc")


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def export(passphrase: str, include_users: bool) -> dict:
    peers = []
    for r in db.q("SELECT * FROM peers ORDER BY id"):
        p = {k: r[k] for k in PEER_FIELDS}
        p["private_key"] = security.decrypt(r["private_key_enc"])
        p["preshared_key"] = security.decrypt(r["preshared_key_enc"])
        peers.append(p)
    settings = {}
    for r in db.q("SELECT key, value FROM settings"):
        if r["key"] in SECRET_SETTINGS:
            settings[r["key"].removesuffix("_enc")] = security.decrypt(r["value"])
        else:
            settings[r["key"]] = r["value"]
    payload = {"peers": peers, "settings": settings, "server": config.server_cfg()}
    if include_users:
        payload["users"] = []
        for r in db.q("SELECT * FROM users ORDER BY id"):
            u = {k: r[k] for k in USER_FIELDS}
            u["totp_secret"] = security.decrypt(r["totp_secret_enc"])
            payload["users"].append(u)
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(passphrase, salt)).encrypt(nonce, json.dumps(payload).encode(), FORMAT.encode())
    return {"format": FORMAT, "version": config.version(), "created_at": int(time.time()),
            "kdf": "scrypt-n32768-r8-p1", "cipher": "aes-256-gcm",
            "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(ct).decode(), "counts": {"peers": len(peers),
                                                             "users": len(payload.get("users", []))}}


def decrypt_backup(blob: dict, passphrase: str) -> dict:
    if blob.get("format") != FORMAT:
        raise ValueError("Keine gültige Simple-WireGuard-Sicherung")
    try:
        key = _key(passphrase, base64.b64decode(blob["salt"]))
        pt = AESGCM(key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["data"]),
                                 FORMAT.encode())
    except Exception:
        raise ValueError("Passphrase falsch oder Datei beschädigt")
    return json.loads(pt)


def restore(blob: dict, passphrase: str, include_users: bool) -> dict:
    data = decrypt_backup(blob, passphrase)
    warnings = []
    srv = config.server_cfg()
    if data.get("server", {}).get("public_key") != srv.get("public_key"):
        warnings.append("Server-Schlüssel weicht ab: Clients brauchen neue Configs, "
                        "oder /etc/simple-wireguard vom alten Server übernehmen.")
    if data.get("server", {}).get("subnet") != srv.get("subnet"):
        warnings.append("VPN-Subnetz weicht ab: Peers außerhalb des Subnetzes werden übersprungen.")
    import ipaddress
    net = ipaddress.ip_network(srv["subnet"], strict=False)
    restored = 0
    with db.tx() as c:
        c.execute("DELETE FROM peers")
        for p in data.get("peers", []):
            if ipaddress.ip_address(p["address"]) not in net:
                continue
            c.execute(
                "INSERT INTO peers(name, description, public_key, private_key_enc, preshared_key_enc, address,"
                " client_allowed_ips, dns, keepalive, enabled, expires_at, created_at, updated_at, created_by)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (p["name"], p["description"], p["public_key"], security.encrypt(p.get("private_key")),
                 security.encrypt(p.get("preshared_key")), p["address"], p["client_allowed_ips"], p["dns"],
                 p["keepalive"], p["enabled"], p["expires_at"], p["created_at"], p["updated_at"],
                 p["created_by"]))
            restored += 1
        for k, v in data.get("settings", {}).items():
            if k in ("pushover_token", "pushover_user"):
                k, v = k + "_enc", security.encrypt(v)
            c.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET"
                      " value = excluded.value", (k, v))
        users = 0
        if include_users and data.get("users"):
            c.execute("DELETE FROM sessions")
            c.execute("DELETE FROM users")
            for u in data["users"]:
                c.execute("INSERT INTO users(username, password_hash, role, totp_secret_enc, totp_enabled,"
                          " must_change_password, created_at) VALUES (?,?,?,?,?,?,?)",
                          (u["username"], u["password_hash"], u["role"], security.encrypt(u.get("totp_secret")),
                           u["totp_enabled"], u["must_change_password"], u["created_at"]))
                users += 1
    return {"peers": restored, "users": users, "warnings": warnings}
