"""Audit logging. Entries are written in the caller's transaction or their own; details never contain secrets."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger("aegis.audit")
_FORBIDDEN_KEYS = ("password", "token", "secret", "csrf", "cookie")


def _value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:300]


def _clean(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop secret-looking keys and cap values; audit entries must never contain credentials."""
    if not detail:
        return None
    return {k: _value(v) for k, v in detail.items() if not any(f in k.lower() for f in _FORBIDDEN_KEYS)}


def audit(session: Session, action: str, outcome: str, *, user_id: int | None = None, username: str | None = None,
          target_type: str | None = None, target_id: str | int | None = None, ip: str | None = None,
          detail: dict[str, Any] | None = None, commit: bool = True) -> None:
    session.add(AuditLog(action=action[:64], outcome=outcome[:16], user_id=user_id,
                         username=(username or "")[:64] or None, target_type=target_type,
                         target_id=str(target_id)[:64] if target_id is not None else None, ip=(ip or "")[:45] or None,
                         detail=_clean(detail)))
    if commit:
        session.commit()
    logger.info("audit action=%s outcome=%s user=%s target=%s:%s ip=%s", action, outcome, username, target_type,
                target_id, ip)
