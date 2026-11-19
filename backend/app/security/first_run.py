"""First-run setup: the owner creates the first administrator in the browser. There are no default credentials.

While the database has no users, AEGIS generates a one-time **setup code** at start-up and shows it only to whoever
controls the machine: it is printed on the server console and written to ``<data_dir>/first-run-setup-code.txt``.
Claiming the installation needs that code, so someone who merely reaches the web page first cannot take it over.

* The code has about 79 bits of entropy. Only its SHA-256 is kept in memory, and comparison is constant-time.
* Attempts share the login rate limits. The code is single-use: it is cleared once the first account exists.
* Setup is refused as soon as any user exists. A lock plus a re-check inside the transaction stop two parallel
  requests from both succeeding.
* A restart while setup is still pending issues a new code and invalidates the old one.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sys
import threading
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AegisError, ConflictError
from app.models import Role, User
from app.services.user_service import create_user

logger = logging.getLogger(__name__)

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L: easy to read off a console
GROUPS, GROUP_LEN = 4, 4
CODE_FILE = "first-run-setup-code.txt"


class InvalidSetupCodeError(AegisError):
    code = "invalid_setup_code"
    http_status = 403


def _digest(code: str) -> bytes:
    return hashlib.sha256(normalise(code).encode()).digest()


def normalise(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


class FirstRunSetup:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._lock = threading.Lock()
        self._digest: bytes | None = None

    @property
    def code_file(self) -> Path:
        return self._settings.data_dir / CODE_FILE

    def needs_setup(self, db: Session) -> bool:
        return user_count(db) == 0

    def prepare(self, db: Session) -> str | None:
        """At start-up: issue and announce a setup code if no user exists. Returns the code (for tests)."""
        with self._lock:
            if not self.needs_setup(db):
                self._digest = None
                self._remove_file()
                return None
            code = "-".join("".join(secrets.choice(ALPHABET) for _ in range(GROUP_LEN)) for _ in range(GROUPS))
            self._digest = _digest(code)
            self._write_file(code)
            self._announce(code)
            return code

    def complete(self, db: Session, code: str, username: str, password: str) -> User:
        """Verify the code and create the first administrator. The caller commits."""
        with self._lock:
            if not self.needs_setup(db):
                raise ConflictError("AEGIS is already set up. Sign in instead.")
            if self._digest is None or not hmac.compare_digest(self._digest, _digest(code)):
                raise InvalidSetupCodeError("The setup code is not correct. Copy it from the AEGIS server window "
                                            f"or from {CODE_FILE} in the data folder.")
            user = create_user(db, username, password, Role.ADMIN.value)  # same username/password policy as always
            if user_count(db) != 1:  # defensive: someone else created a user in the meantime
                raise ConflictError("AEGIS is already set up. Sign in instead.")
            self._digest = None
            self._remove_file()
            return user

    # -- helpers ---------------------------------------------------------------------------------------------------
    def _write_file(self, code: str) -> None:
        try:
            self.code_file.write_text(
                "AEGIS first-run setup code (single use; deleted automatically after setup):\n" + code + "\n",
                encoding="utf-8")
            self.code_file.chmod(0o600)  # owner-only where the OS supports it
        except OSError:
            logger.warning("Could not write %s; use the setup code printed on the console.", CODE_FILE)

    def _remove_file(self) -> None:
        try:
            self.code_file.unlink(missing_ok=True)
        except OSError:
            logger.warning("Could not delete %s; please delete it manually.", CODE_FILE)

    def _announce(self, code: str) -> None:
        # Printed directly (not logged) so it never lands in log files or log shipping, and so the redaction
        # filter does not hide it from the one person who needs it.
        line = "=" * 64
        print(f"\n{line}\n  AEGIS FIRST-RUN SETUP\n  No accounts exist yet. Open AEGIS in your browser and enter this\n"
              f"  one-time setup code to create your administrator account:\n\n      {code}\n\n"
              f"  (also saved to {self.code_file})\n{line}\n", file=sys.stderr, flush=True)
        logger.warning("First-run setup pending: the setup code was printed on the console and saved to %s.",
                       CODE_FILE)
