#!/usr/bin/env python3
"""Simple-WireGuard privileged agent.

Runs as root and exposes a *minimal* command set over a unix socket to the
unprivileged web application (user ``swg``). It deliberately uses the Python
standard library only, so the root-side attack surface stays small.

Security model:
  * Only uid 0 and the ``swg`` user may talk to the socket (SO_PEERCRED).
  * The [Interface] section (incl. PostUp/PostDown and the server private key)
    lives in a root-only file and can never be influenced by the web app.
  * Peers are validated strictly (key format, address inside the VPN subnet,
    uniqueness) before anything is written.
"""
import ipaddress
import json
import logging
import logging.handlers
import os
import pwd
import re
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading

ETC = os.environ.get("SWG_ETC", "/etc/simple-wireguard")
SERVER_JSON = os.path.join(ETC, "server.json")
INTERFACE_CONF = os.path.join(ETC, "interface.conf")
SOCK_PATH = os.environ.get("SWG_AGENT_SOCK", "/run/simple-wireguard/agent.sock")
LOG_FILE = os.environ.get("SWG_AGENT_LOG", "/var/log/simple-wireguard/agent.log")
APP_USER = "swg"
MAX_REQUEST = 4 * 1024 * 1024
MAX_PEERS = 5000

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_=+.-]{1,15}$")

log = logging.getLogger("swg-agent")
_lock = threading.Lock()


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s agent: %(message)s")
    try:
        fh = logging.handlers.WatchedFileHandler(LOG_FILE)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError:
        pass
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    log.addHandler(sh)


def load_server():
    with open(SERVER_JSON, encoding="utf-8") as f:
        cfg = json.load(f)
    if not IFACE_RE.match(cfg.get("iface", "")):
        raise ValueError("invalid interface name in server.json")
    return cfg


def run(cmd, input_data=None):
    res = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {res.stderr.strip()[:300]}")
    return res.stdout


def iface_up(iface):
    return os.path.isdir(f"/sys/class/net/{iface}")


def cmd_status(_req):
    cfg = load_server()
    iface = cfg["iface"]
    if not iface_up(iface):
        return {"up": False, "peers": []}
    out = run(["wg", "show", iface, "dump"])
    lines = out.strip().splitlines()
    result = {"up": True, "peers": []}
    if lines:
        head = lines[0].split("\t")
        # head[0] is the private key - never return it.
        result["public_key"] = head[1]
        result["listen_port"] = int(head[2]) if head[2].isdigit() else None
    for line in lines[1:]:
        p = line.split("\t")
        if len(p) < 8:
            continue
        result["peers"].append({
            "public_key": p[0],
            "endpoint": None if p[2] == "(none)" else p[2],
            "allowed_ips": p[3],
            "latest_handshake": int(p[4]) if p[4].isdigit() else 0,
            "rx": int(p[5]) if p[5].isdigit() else 0,
            "tx": int(p[6]) if p[6].isdigit() else 0,
        })
    return result


def validate_peers(peers, cfg):
    if not isinstance(peers, list) or len(peers) > MAX_PEERS:
        raise ValueError("peers must be a list")
    net = ipaddress.ip_network(cfg["subnet"], strict=False)
    server_ip = ipaddress.ip_address(cfg["server_address"])
    seen_keys, seen_ips, clean = set(), set(), []
    for p in peers:
        if not isinstance(p, dict):
            raise ValueError("peer must be an object")
        pub, psk, addr = p.get("public_key", ""), p.get("preshared_key"), p.get("address", "")
        if not isinstance(pub, str) or not KEY_RE.match(pub):
            raise ValueError("invalid public key")
        if psk is not None and (not isinstance(psk, str) or not KEY_RE.match(psk)):
            raise ValueError("invalid preshared key")
        ip = ipaddress.ip_address(addr)
        if ip not in net or ip in (net.network_address, net.broadcast_address, server_ip):
            raise ValueError(f"address {addr} not allowed")
        if pub in seen_keys or ip in seen_ips:
            raise ValueError("duplicate peer key or address")
        seen_keys.add(pub)
        seen_ips.add(ip)
        clean.append((pub, psk, ip))
    return clean


def cmd_apply(req):
    cfg = load_server()
    iface = cfg["iface"]
    peers = validate_peers(req.get("peers"), cfg)
    with open(INTERFACE_CONF, encoding="utf-8") as f:
        header = f.read().rstrip() + "\n"
    parts = [header, "\n# --- Peers managed by Simple-WireGuard (do not edit) ---\n"]
    for pub, psk, ip in peers:
        parts.append(f"\n[Peer]\nPublicKey = {pub}\n")
        if psk:
            parts.append(f"PresharedKey = {psk}\n")
        parts.append(f"AllowedIPs = {ip}/{ip.max_prefixlen}\n")
    target = f"/etc/wireguard/{iface}.conf"
    with _lock:
        fd, tmp = tempfile.mkstemp(dir="/etc/wireguard", prefix=".swg-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("".join(parts))
            os.replace(tmp, target)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        if iface_up(iface):
            stripped = run(["wg-quick", "strip", iface])
            with tempfile.NamedTemporaryFile("w", dir="/run/simple-wireguard", delete=True) as tf:
                os.fchmod(tf.fileno(), 0o600)
                tf.write(stripped)
                tf.flush()
                run(["wg", "syncconf", iface, tf.name])
        else:
            run(["systemctl", "start", f"wg-quick@{iface}"])
    log.info("applied %d peers to %s", len(peers), iface)
    return {"applied": len(peers)}


def cmd_restart(_req):
    iface = load_server()["iface"]
    run(["systemctl", "restart", f"wg-quick@{iface}"])
    log.warning("interface %s restarted on request", iface)
    return {"restarted": True}


COMMANDS = {"status": cmd_status, "apply": cmd_apply, "restart": cmd_restart}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        if uid not in self.server.allowed_uids:
            log.warning("rejected connection from uid %s", uid)
            return
        try:
            raw = self.rfile.readline(MAX_REQUEST)
            req = json.loads(raw)
            fn = COMMANDS.get(req.get("cmd"))
            if fn is None:
                raise ValueError("unknown command")
            resp = {"ok": True, "result": fn(req)}
        except Exception as exc:  # noqa: BLE001 - report every failure to caller
            log.error("command failed: %s", exc)
            resp = {"ok": False, "error": str(exc)[:500]}
        self.wfile.write((json.dumps(resp) + "\n").encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    setup_logging()
    allowed = {0}
    try:
        app_pw = pwd.getpwnam(APP_USER)
        allowed.add(app_pw.pw_uid)
    except KeyError:
        app_pw = None
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
    old = os.umask(0o117)
    srv = Server(SOCK_PATH, Handler)
    os.umask(old)
    if app_pw:
        os.chown(SOCK_PATH, 0, app_pw.pw_gid)
    os.chmod(SOCK_PATH, 0o660)
    srv.allowed_uids = allowed
    log.info("agent listening on %s", SOCK_PATH)
    srv.serve_forever()


if __name__ == "__main__":
    main()
