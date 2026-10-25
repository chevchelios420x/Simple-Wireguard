"""Password hashing, secret encryption and TOTP."""
import base64
import hashlib
import io
import os
import secrets
import time

import pyotp
import segno
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

from . import config

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash(secrets.token_hex(16))
_fernet = None


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(hashed: str | None, pw: str) -> bool:
    """Constant work even for unknown users (hashed=None)."""
    try:
        return _ph.verify(hashed or _DUMMY_HASH, pw) and hashed is not None
    except (VerificationError, InvalidHashError):
        return False


def password_problem(pw: str) -> str | None:
    if len(pw) < config.MIN_PASSWORD_LENGTH:
        return f"Passwort muss mindestens {config.MIN_PASSWORD_LENGTH} Zeichen lang sein"
    if len(pw) > 256:
        return "Passwort ist zu lang"
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                   any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    if classes < 3:
        return "Passwort braucht mind. 3 von: Klein-, Großbuchstaben, Ziffern, Sonderzeichen"
    return None


def generate_password(length: int = 20) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if password_problem(pw) is None:
            return pw


def fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(config.SECRET_KEY_FILE.read_bytes().strip())
    return _fernet


def encrypt(value: str | None) -> str | None:
    if value is None:
        return None
    return fernet().encrypt(value.encode()).decode()


def decrypt(token: str | None) -> str | None:
    if token is None:
        return None
    try:
        return fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


# --- TOTP -----------------------------------------------------------------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Simple-WireGuard")


def qr_svg_data_uri(data: str, scale: int = 5) -> str:
    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="svg", scale=scale, border=2, xmldecl=False,
                                     dark="#0f172a", light="#ffffff")
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the matched time step (to prevent replay) or None."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):
        if step > (last_step or 0) and secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def generate_secret_key_file(path) -> None:
    path.write_bytes(Fernet.generate_key())
    os.chmod(path, 0o640)
