"""Paths and runtime configuration (overridable via environment for development)."""
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get("SWG_ROOT", "/opt/simple-wireguard"))
ETC = Path(os.environ.get("SWG_ETC", "/etc/simple-wireguard"))
VAR = Path(os.environ.get("SWG_VAR", "/var/lib/simple-wireguard"))
LOG_DIR = Path(os.environ.get("SWG_LOG", "/var/log/simple-wireguard"))
WEB_DIR = Path(os.environ.get("SWG_WEB", str(ROOT / "web")))
AGENT_SOCK = os.environ.get("SWG_AGENT_SOCK", "/run/simple-wireguard/agent.sock")
DB_PATH = VAR / "swg.db"
SECRET_KEY_FILE = ETC / "secret.key"
SERVER_JSON = ETC / "server.json"
DEV = os.environ.get("SWG_DEV") == "1"

SESSION_IDLE_SECONDS = 30 * 60
SESSION_MAX_SECONDS = 12 * 3600
PREAUTH_SECONDS = 5 * 60
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 15 * 60
ONLINE_HANDSHAKE_SECONDS = 180
MIN_PASSWORD_LENGTH = 12


def version() -> str:
    for p in (ROOT / "VERSION", Path(__file__).resolve().parents[2] / "VERSION"):
        if p.exists():
            return p.read_text().strip()
    return "unknown"


def server_cfg() -> dict:
    with open(SERVER_JSON, encoding="utf-8") as f:
        return json.load(f)
