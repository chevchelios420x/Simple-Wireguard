"""WireGuard helpers: key generation, address allocation, client configs, agent RPC."""
import base64
import ipaddress
import json
import os
import re
import socket
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import config, db, security

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")


class AgentError(RuntimeError):
    pass


def genkeypair() -> tuple[str, str]:
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    priv = X25519PrivateKey.from_private_bytes(bytes(raw))
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(bytes(raw)).decode(), base64.b64encode(pub).decode()


def genpsk() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def next_free_address() -> str:
    cfg = config.server_cfg()
    net = ipaddress.ip_network(cfg["subnet"], strict=False)
    used = {r["address"] for r in db.q("SELECT address FROM peers")}
    used.add(cfg["server_address"])
    for host in net.hosts():
        if str(host) not in used:
            return str(host)
    raise ValueError("Keine freie IP-Adresse mehr im VPN-Subnetz")


def validate_address(addr: str, peer_id: int | None = None) -> str:
    cfg = config.server_cfg()
    net = ipaddress.ip_network(cfg["subnet"], strict=False)
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        raise ValueError("Ungültige IP-Adresse")
    if ip not in net or ip in (net.network_address, net.broadcast_address) or str(ip) == cfg["server_address"]:
        raise ValueError(f"Adresse muss im Subnetz {net} liegen und darf nicht die Server-IP sein")
    other = db.one("SELECT id FROM peers WHERE address = ? AND id IS NOT ?", (str(ip), peer_id))
    if other:
        raise ValueError("Adresse ist bereits vergeben")
    return str(ip)


def validate_cidr_list(value: str) -> str:
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items:
        raise ValueError("Mindestens ein Netz angeben")
    try:
        return ", ".join(str(ipaddress.ip_network(v, strict=False)) for v in items)
    except ValueError:
        raise ValueError("Ungültige Netzliste (CIDR, kommagetrennt)")


def validate_dns(value: str) -> str:
    items = [v.strip() for v in value.split(",") if v.strip()]
    for v in items:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", v):
                raise ValueError("Ungültiger DNS-Eintrag")
    return ", ".join(items)


def client_config(peer) -> str:
    cfg = config.server_cfg()
    priv = security.decrypt(peer["private_key_enc"])
    if not priv:
        raise ValueError("Für diesen Peer ist kein privater Schlüssel gespeichert (eigener Schlüssel importiert)")
    net = ipaddress.ip_network(cfg["subnet"], strict=False)
    lines = ["[Interface]", f"# {peer['name']}", f"PrivateKey = {priv}",
             f"Address = {peer['address']}/{net.prefixlen}"]
    if peer["dns"]:
        lines.append(f"DNS = {peer['dns']}")
    if cfg.get("mtu"):
        lines.append(f"MTU = {cfg['mtu']}")
    lines += ["", "[Peer]", f"PublicKey = {cfg['public_key']}"]
    psk = security.decrypt(peer["preshared_key_enc"])
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines += [f"AllowedIPs = {peer['client_allowed_ips']}",
              f"Endpoint = {cfg['endpoint']}:{cfg['listen_port']}"]
    if peer["keepalive"]:
        lines.append(f"PersistentKeepalive = {peer['keepalive']}")
    return "\n".join(lines) + "\n"


# --- agent RPC ------------------------------------------------------------

def _agent(cmd: str, **payload):
    if config.DEV:
        return {"up": True, "peers": []} if cmd == "status" else {}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            s.connect(config.AGENT_SOCK)
            s.sendall((json.dumps({"cmd": cmd, **payload}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        raise AgentError(f"Agent nicht erreichbar: {exc}")
    resp = json.loads(buf or b"{}")
    if not resp.get("ok"):
        raise AgentError(resp.get("error", "unbekannter Agent-Fehler"))
    return resp["result"]


def status() -> dict:
    return _agent("status")


def restart() -> dict:
    return _agent("restart")


def apply() -> int:
    """Push all active peers to the interface."""
    now = int(time.time())
    rows = db.q("SELECT public_key, preshared_key_enc, address FROM peers "
                "WHERE enabled = 1 AND (expires_at IS NULL OR expires_at > ?)", (now,))
    peers = [{"public_key": r["public_key"], "preshared_key": security.decrypt(r["preshared_key_enc"]),
              "address": r["address"]} for r in rows]
    _agent("apply", peers=peers)
    return len(peers)
