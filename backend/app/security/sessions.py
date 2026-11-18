"""Server-side sessions.

The browser holds a random 256-bit token in an HttpOnly, SameSite=Strict cookie. The database
stores only its SHA-256, so a database leak does not reveal usable session tokens. Each session
also has a CSRF token (again stored hashed) that must accompany every state-changing request.
Sessions expire after an idle period and after an absolute lifetime.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuthSession, User

COOKIE_NAME = "aegis_session"
CSRF_HEADER = "X-CSRF-Token"
LAST_SEEN_RESOLUTION = timedelta(seconds=60)  # avoid a DB write on every request


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass
class IssuedSession:
    token: str
    csrf_token: str
    expires_at: datetime


class SessionManager:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.idle = timedelta(minutes=settings.session_idle_minutes)
        self.absolute = timedelta(hours=settings.session_absolute_hours)

    def create(self, db: Session, user: User, *, ip: str | None, user_agent: str | None) -> IssuedSession:
        now = datetime.now(UTC)
        db.execute(delete(AuthSession).where(AuthSession.expires_at < now))  # housekeeping
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expires = now + self.absolute
        db.add(AuthSession(token_hash=_hash(token), csrf_token_hash=_hash(csrf), user_id=user.id, expires_at=expires,
                           last_seen_at=now, ip=(ip or "")[:45] or None, user_agent=(user_agent or "")[:256] or None))
        return IssuedSession(token=token, csrf_token=csrf, expires_at=expires)

    def resolve(self, db: Session, token: str | None) -> tuple[AuthSession, User] | None:
        """Return the live session and its active user, or None. Expired sessions are deleted."""
        if not token or len(token) > 128:
            return None
        row = db.scalar(select(AuthSession).where(AuthSession.token_hash == _hash(token)))
        if row is None:
            return None
        now = datetime.now(UTC)
        if _aware(row.expires_at) <= now or now - _aware(row.last_seen_at) > self.idle:
            db.delete(row)
            db.commit()
            return None
        user = db.get(User, row.user_id)
        if user is None or not user.is_active:
            return None
        if now - _aware(row.last_seen_at) > LAST_SEEN_RESOLUTION:
            row.last_seen_at = now
            db.commit()
        return row, user

    @staticmethod
    def check_csrf(row: AuthSession, presented: str | None) -> bool:
        if not presented or len(presented) > 128:
            return False
        return hmac.compare_digest(row.csrf_token_hash, _hash(presented))

    @staticmethod
    def rotate_csrf(db: Session, row: AuthSession) -> str:
        csrf = secrets.token_urlsafe(32)
        row.csrf_token_hash = _hash(csrf)
        db.commit()
        return csrf

    @staticmethod
    def revoke(db: Session, row: AuthSession) -> None:
        db.delete(row)
        db.commit()

    @staticmethod
    def revoke_all(db: Session, user_id: int, *, except_id: int | None = None) -> int:
        conditions = [AuthSession.user_id == user_id]
        if except_id is not None:
            conditions.append(AuthSession.id != except_id)
        return db.execute(delete(AuthSession).where(*conditions)).rowcount or 0
