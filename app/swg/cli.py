"""swg-admin: local emergency / administration CLI (root only, runs as user swg)."""
import argparse
import getpass
import sys
import time

from . import config, db, logsetup, security


def _user(name):
    u = db.one("SELECT * FROM users WHERE username = ?", (name,))
    if not u:
        sys.exit(f"Benutzer '{name}' nicht gefunden")
    return u


def _password(args) -> str:
    if args.generate:
        return security.generate_password()
    pw = getpass.getpass("Neues Passwort: ")
    if pw != getpass.getpass("Wiederholen: "):
        sys.exit("Passwörter stimmen nicht überein")
    if problem := security.password_problem(pw):
        sys.exit(problem)
    return pw


def cmd_list(_a):
    rows = db.q("SELECT * FROM users ORDER BY username")
    print(f"{'BENUTZER':20} {'ROLLE':8} {'TOTP':5} {'GESPERRT':9} LETZTER LOGIN")
    for r in rows:
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_login"])) if r["last_login"] else "-"
        print(f"{r['username']:20} {r['role']:8} {'ja' if r['totp_enabled'] else 'nein':5} "
              f"{'ja' if r['locked_until'] > time.time() else 'nein':9} {last}")


def cmd_create(a):
    if db.one("SELECT id FROM users WHERE username = ?", (a.username,)):
        sys.exit("Benutzer existiert bereits")
    pw = _password(a)
    db.ex("INSERT INTO users(username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,1,?)",
          (a.username, security.hash_password(pw), a.role, int(time.time())))
    db.audit("user_created", "cli", "local", a.username)
    print(f"Benutzer '{a.username}' angelegt." + (f"\nInitiales Passwort: {pw}" if a.generate else ""))


def cmd_reset_password(a):
    u = _user(a.username)
    pw = _password(a)
    db.ex("UPDATE users SET password_hash = ?, must_change_password = 1, failed_count = 0, locked_until = 0 "
          "WHERE id = ?", (security.hash_password(pw), u["id"]))
    db.ex("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
    db.audit("password_reset", "cli", "local", u["username"])
    print(f"Passwort für '{u['username']}' zurückgesetzt, alle Sitzungen beendet."
          + (f"\nNeues Passwort: {pw}" if a.generate else ""))


def cmd_reset_totp(a):
    u = _user(a.username)
    db.ex("UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?", (u["id"],))
    db.ex("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
    db.audit("totp_reset", "cli", "local", u["username"])
    print(f"TOTP für '{u['username']}' zurückgesetzt. Beim nächsten Login wird neu eingerichtet.")


def cmd_unlock(a):
    u = _user(a.username)
    db.ex("UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?", (u["id"],))
    db.audit("user_unlocked", "cli", "local", u["username"])
    print(f"'{u['username']}' entsperrt.")


def cmd_delete(a):
    u = _user(a.username)
    db.ex("DELETE FROM users WHERE id = ?", (u["id"],))
    db.audit("user_deleted", "cli", "local", u["username"])
    print(f"'{u['username']}' gelöscht.")


def cmd_logout_all(_a):
    n = db.ex("DELETE FROM sessions").rowcount
    db.audit("sessions_revoked", "cli", "local", str(n))
    print(f"{n} Sitzungen beendet.")


def cmd_init(a):
    """Used by install.sh: create the first admin if no user exists."""
    db.init()
    if db.one("SELECT COUNT(*) c FROM users")["c"]:
        return
    pw = security.generate_password()
    db.ex("INSERT INTO users(username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,1,?)",
          (a.username, security.hash_password(pw), "admin", int(time.time())))
    db.audit("user_created", "installer", "local", a.username)
    print(f"INITIAL_ADMIN={a.username}\nINITIAL_PASSWORD={pw}")


def main():
    logsetup.setup()
    p = argparse.ArgumentParser(prog="swg-admin", description="Simple-WireGuard Administration")
    p.add_argument("--version", action="version", version=config.version())
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("list-users", help="Benutzer auflisten").set_defaults(fn=cmd_list)
    c = sp.add_parser("create-user", help="Benutzer anlegen")
    c.add_argument("username")
    c.add_argument("--role", choices=["admin", "viewer"], default="admin")
    c.add_argument("--generate", action="store_true", help="Passwort generieren")
    c.set_defaults(fn=cmd_create)
    r = sp.add_parser("reset-password", help="Passwort überschreiben (Notfall)")
    r.add_argument("username")
    r.add_argument("--generate", action="store_true", help="Passwort generieren")
    r.set_defaults(fn=cmd_reset_password)
    for name, fn, hlp in (("reset-totp", cmd_reset_totp, "TOTP zurücksetzen (Notfall)"),
                          ("unlock", cmd_unlock, "Gesperrtes Konto entsperren"),
                          ("delete-user", cmd_delete, "Benutzer löschen")):
        x = sp.add_parser(name, help=hlp)
        x.add_argument("username")
        x.set_defaults(fn=fn)
    sp.add_parser("logout-all", help="Alle Sitzungen beenden").set_defaults(fn=cmd_logout_all)
    i = sp.add_parser("init")
    i.add_argument("--username", default="admin")
    i.set_defaults(fn=cmd_init)
    a = p.parse_args()
    db.init()
    a.fn(a)


if __name__ == "__main__":
    main()
