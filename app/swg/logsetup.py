"""Logging: app.log (operational) and audit.log (security relevant), rotated by logrotate."""
import logging
import logging.handlers

from . import config

FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def setup() -> None:
    root = logging.getLogger("swg")
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    fmt = logging.Formatter(FMT)
    targets = {"swg": "app.log", "swg.audit": "audit.log"}
    for name, filename in targets.items():
        lg = logging.getLogger(name)
        try:
            config.LOG_DIR.mkdir(parents=True, exist_ok=True)
            # WatchedFileHandler reopens the file after logrotate moved it.
            h = logging.handlers.WatchedFileHandler(config.LOG_DIR / filename)
        except OSError:
            h = logging.StreamHandler()
        h.setFormatter(fmt)
        lg.addHandler(h)
    logging.getLogger("swg.audit").propagate = False
