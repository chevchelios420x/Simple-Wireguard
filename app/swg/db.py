"""SQLite persistence layer."""
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import config

audit_log = logging.getLogger("swg.audit")
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    totp_secret_enc TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    stage TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL UNIQUE,
    private_key_enc TEXT,
    preshared_key_enc TEXT,
    address TEXT NOT NULL UNIQUE,
    client_allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
    dns TEXT NOT NULL DEFAULT '',
    keepalive INTEGER NOT NULL DEFAULT 25,
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    created_by TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    username TEXT,
    ip TEXT,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"""
SCHEMA_VERSION = "1"


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(config.DB_PATH, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA secure_delete = ON")
        _local.conn = c
    return c


@contextmanager
def tx():
    c = conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def init() -> None:
    config.VAR.mkdir(parents=True, exist_ok=True)
    conn().executescript(SCHEMA)
    conn().execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)", (SCHEMA_VERSION,))


def q(sql: str, args=()) -> list[sqlite3.Row]:
    return conn().execute(sql, args).fetchall()


def one(sql: str, args=()):
    return conn().execute(sql, args).fetchone()


def ex(sql: str, args=()) -> sqlite3.Cursor:
    return conn().execute(sql, args)


def get_setting(key: str, default=None):
    r = one("SELECT value FROM settings WHERE key = ?", (key,))
    return r["value"] if r else default


def set_setting(key: str, value) -> None:
    ex("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
       (key, None if value is None else str(value)))


def audit(action: str, username: str | None = None, ip: str | None = None, detail: str = "") -> None:
    ex("INSERT INTO audit(ts, username, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
       (int(time.time()), username, ip, action, detail[:1000]))
    audit_log.info("action=%s user=%s ip=%s detail=%s", action, username or "-", ip or "-", detail)
