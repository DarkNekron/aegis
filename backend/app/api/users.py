"""User administration (Administrator only) and the audit log."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.core.errors import NotFoundError
from app.models import AuditLog, User
from app.security.audit import audit
from app.security.deps import Principal, client_ip, require_role
from app.services.user_service import create_user, set_password, update_user

router = APIRouter(prefix="/api", tags=["administration"])
Admin = Annotated[Principal, Depends(require_role("admin"))]
RoleName = Literal["admin", "analyst", "viewer"]


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: RoleName


class UserUpdate(BaseModel):
    role: RoleName | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=1, max_length=256)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _view(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active,
            "locked": bool(user.locked_until and _aware(user.locked_until) > datetime.now(UTC)),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "created_at": user.created_at.isoformat()}


@router.get("/users")
def list_users(admin: Admin) -> dict:
    users = admin.db.scalars(select(User).order_by(User.username)).all()
    return {"items": [_view(u) for u in users]}


@router.post("/users", status_code=201)
def add_user(body: UserCreate, request: Request, admin: Admin) -> dict:
    user = create_user(admin.db, body.username, body.password, body.role)
    audit(admin.db, "user_create", "success", user_id=admin.user.id, username=admin.user.username,
          target_type="user", target_id=user.id, ip=client_ip(request), detail={"role": body.role,
                                                                                  "new_user": user.username})
    return _view(user)


@router.patch("/users/{user_id}")
def edit_user(user_id: int, body: UserUpdate, request: Request, admin: Admin) -> dict:
    user = update_user(admin.db, admin.user, user_id, role=body.role, is_active=body.is_active)
    if body.is_active is False:
        request.app.state.sessions.revoke_all(admin.db, user.id)
    audit(admin.db, "user_update", "success", user_id=admin.user.id, username=admin.user.username,
          target_type="user", target_id=user.id, ip=client_ip(request), detail=body.model_dump(exclude_none=True))
    return _view(user)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, body: PasswordReset, request: Request, admin: Admin) -> dict:
    user = admin.db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found.")
    set_password(admin.db, user, body.new_password)
    revoked = request.app.state.sessions.revoke_all(admin.db, user.id)
    audit(admin.db, "password_reset", "success", user_id=admin.user.id, username=admin.user.username,
          target_type="user", target_id=user.id, ip=client_ip(request), detail={"sessions_revoked": revoked})
    return {"status": "reset", "sessions_revoked": revoked}


@router.get("/audit")
def audit_log(admin: Admin, offset: Annotated[int, Query(ge=0)] = 0,
              limit: Annotated[int, Query(ge=1, le=500)] = 100,
              action: Annotated[str | None, Query(max_length=64)] = None) -> dict:
    conditions = [AuditLog.action == action] if action else []
    total = admin.db.scalar(select(func.count()).select_from(AuditLog).where(*conditions))
    rows = admin.db.scalars(select(AuditLog).where(*conditions).order_by(AuditLog.id.desc())
                            .offset(offset).limit(limit)).all()
    return {"total": total, "items": [
        {"id": r.id, "ts": r.ts.isoformat(), "username": r.username, "action": r.action, "outcome": r.outcome,
         "target_type": r.target_type, "target_id": r.target_id, "ip": r.ip, "detail": r.detail} for r in rows]}
