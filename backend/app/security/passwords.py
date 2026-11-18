"""Password hashing (Argon2id) and password policy."""

from __future__ import annotations

from contextlib import suppress

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.errors import ValidationFailedError

MIN_LENGTH = 12
MAX_LENGTH = 128  # bounds hashing cost; Argon2 input length is otherwise unlimited

# argon2-cffi defaults are Argon2id, t=3, m=64 MiB, p=4 (RFC 9106 "second recommended" profile).
_hasher = PasswordHasher()
# Used to spend the same time on unknown usernames as on real ones (no user enumeration by timing).
_DUMMY_HASH = _hasher.hash("aegis-timing-equaliser-not-a-real-password")

_COMMON = {"password1234", "123456789012", "qwertyuiop12", "administrator", "changeme1234", "welcome12345",
           "passw0rd1234", "letmein12345", "p@ssw0rd1234", "aegisaegis12"}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        _burn(password)  # unknown user: spend the same time as a real verification
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _burn(password: str) -> None:
    with suppress(VerifyMismatchError, VerificationError, InvalidHashError):
        _hasher.verify(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def check_policy(password: str, username: str = "") -> None:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        problems.append(f"at most {MAX_LENGTH} characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if password.lower() in _COMMON or len(set(password)) < 5:
        problems.append("is too common or too repetitive")
    if problems:
        raise ValidationFailedError("Password " + "; ".join(problems) + ".")
