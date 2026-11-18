"""User administration with safety rails (no default accounts, never lose the last administrator)."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.models import Role, User
from app.security.passwords import check_policy, hash_password, needs_rehash, verify_password

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ROLE_RANK = {Role.VIEWER.value: 1, Role.ANALYST.value: 2, Role.ADMIN.value: 3}


def normalise_username(username: str) -> str:
    name = (username or "").strip().lower()
    if not USERNAME.match(name):
        raise ValidationFailedError("Usernames are 3-64 characters: lower-case letters, digits, '.', '_' or '-'.")
    return name


def validate_role(role: str) -> str:
    if role not in ROLE_RANK:
        raise ValidationFailedError(f"Role must be one of {', '.join(ROLE_RANK)}.")
    return role


def active_admins(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)
                     .where(User.role == Role.ADMIN.value, User.is_active.is_(True))) or 0


def create_user(db: Session, username: str, password: str, role: str) -> User:
    name = normalise_username(username)
    validate_role(role)
    check_policy(password, name)
    if db.scalar(select(User.id).where(User.username == name)):
        raise ConflictError("A user with that name already exists.")
    user = User(username=name, password_hash=hash_password(password), role=role, is_active=True)
    db.add(user)
    db.flush()
    return user


def update_user(db: Session, actor: User, user_id: int, *, role: str | None = None,
                is_active: bool | None = None) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found.")
    demoting = role is not None and role != Role.ADMIN.value and user.role == Role.ADMIN.value
    deactivating = is_active is False and user.is_active
    if user.id == actor.id and (demoting or deactivating):
        raise ValidationFailedError("You cannot demote or deactivate your own account.")
    if (demoting or deactivating) and user.role == Role.ADMIN.value and active_admins(db) <= 1:
        raise ValidationFailedError("At least one active administrator must remain.")
    if role is not None:
        user.role = validate_role(role)
    if is_active is not None:
        user.is_active = is_active
        if is_active:
            user.failed_attempts, user.locked_until = 0, None
    return user


def set_password(db: Session, user: User, new_password: str) -> None:
    check_policy(new_password, user.username)
    user.password_hash = hash_password(new_password)
    user.failed_attempts, user.locked_until = 0, None


class LoginOutcome:
    OK, INVALID, LOCKED, INACTIVE = "ok", "invalid", "locked", "inactive"


def authenticate(db: Session, settings: Settings, username: str, password: str) -> tuple[str, User | None]:
    """Verify credentials with lockout. The caller shows the same message for every failure."""
    try:
        name = normalise_username(username)
    except ValidationFailedError:
        verify_password(None, password)
        return LoginOutcome.INVALID, None
    user = db.scalar(select(User).where(User.username == name))
    if user is None:
        verify_password(None, password)  # equalise timing
        return LoginOutcome.INVALID, None
    now = datetime.now(UTC)
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=UTC)  # SQLite returns naive datetimes
    if locked_until and locked_until > now:
        verify_password(None, password)
        return LoginOutcome.LOCKED, user
    if not verify_password(user.password_hash, password):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= settings.login_max_failures:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_attempts = 0
            db.commit()
            return LoginOutcome.LOCKED, user
        db.commit()
        return LoginOutcome.INVALID, user
    if not user.is_active:
        return LoginOutcome.INACTIVE, user
    user.failed_attempts, user.locked_until, user.last_login_at = 0, None, now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.commit()
    return LoginOutcome.OK, user
