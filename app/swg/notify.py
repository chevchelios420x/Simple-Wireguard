"""Pushover notifications. Credentials are stored Fernet-encrypted in the settings table."""
import json
import logging
import threading
import urllib.parse
import urllib.request

from . import db, security

log = logging.getLogger("swg.notify")
API = "https://api.pushover.net/1/messages.json"

EVENTS = {
    "notify_login": "Erfolgreiche Anmeldung",
    "notify_login_failed": "Konto gesperrt nach Fehlversuchen",
    "notify_peer_changes": "Peer angelegt, geändert oder gelöscht",
    "notify_peer_online": "Peer verbindet / trennt sich",
    "notify_expiry": "Peer abgelaufen und deaktiviert",
    "notify_system": "Systemereignisse (Restore, Interface-Neustart, Fehler)",
}
DEFAULTS = {"notify_login": "0", "notify_login_failed": "1", "notify_peer_changes": "1",
            "notify_peer_online": "0", "notify_expiry": "1", "notify_system": "1"}


def credentials():
    return (security.decrypt(db.get_setting("pushover_token_enc")),
            security.decrypt(db.get_setting("pushover_user_enc")))


def enabled(event: str) -> bool:
    return db.get_setting(event, DEFAULTS.get(event, "0")) == "1"


def send_sync(title: str, message: str, priority: int = 0) -> None:
    token, user = credentials()
    if not token or not user:
        raise RuntimeError("Pushover ist nicht konfiguriert")
    data = urllib.parse.urlencode({"token": token, "user": user, "title": title[:250],
                                   "message": message[:1024], "priority": priority}).encode()
    req = urllib.request.Request(API, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read() or b"{}")
    if body.get("status") != 1:
        raise RuntimeError("Pushover-Fehler: " + ", ".join(body.get("errors", ["unbekannt"])))


def send(event: str, title: str, message: str, priority: int = 0) -> None:
    """Fire-and-forget if the event is enabled and Pushover is configured."""
    if not enabled(event) or not all(credentials()):
        return

    def _run():
        try:
            send_sync("Simple-WireGuard: " + title, message, priority)
        except Exception as exc:  # noqa: BLE001
            log.warning("pushover failed: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
