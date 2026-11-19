"""Authentication endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.errors import AegisError
from app.security.audit import audit
from app.security.deps import ForbiddenError, Principal, client_ip, current_principal, db_session, origin_ok
from app.security.passwords import verify_password
from app.security.sessions import COOKIE_NAME, SessionManager
from app.services.user_service import LoginOutcome, authenticate, set_password

router = APIRouter(prefix="/api/auth", tags=["auth"])
GENERIC_FAILURE = "Invalid username or password."  # identical for every failure: no account enumeration


class InvalidCredentialsError(AegisError):
    code = "invalid_credentials"
    http_status = 401


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


def _user_view(user) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role}


def _set_cookie(response: Response, request: Request, token: str, max_age: int) -> None:
    response.set_cookie(COOKIE_NAME, token, max_age=max_age, httponly=True, samesite="strict",
                        secure=request.app.state.settings.cookie_secure, path="/")


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response,
          db: Annotated[Session, Depends(db_session)]) -> dict:
    settings = request.app.state.settings
    limiter = request.app.state.rate_limiter
    ip = client_ip(request)
    limiter.hit("login-ip", ip, settings.rate_limit_login_per_min)
    limiter.hit("login-user", body.username.strip().lower()[:64], settings.rate_limit_login_per_min)

    outcome, user = authenticate(db, settings, body.username, body.password)
    if outcome != LoginOutcome.OK:
        audit(db, "login", "failure", user_id=user.id if user else None, username=body.username[:64], ip=ip,
              detail={"reason": outcome})
        raise InvalidCredentialsError(GENERIC_FAILURE)

    manager: SessionManager = request.app.state.sessions
    issued = manager.create(db, user, ip=ip, user_agent=request.headers.get("user-agent"))
    audit(db, "login", "success", user_id=user.id, username=user.username, ip=ip, commit=False)
    db.commit()
    _set_cookie(response, request, issued.token, int(manager.absolute.total_seconds()))
    return {"user": _user_view(user), "csrf_token": issued.csrf_token}


class FirstRunRequest(BaseModel):
    setup_code: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.get("/setup-status")
def setup_status(request: Request, db: Annotated[Session, Depends(db_session)]) -> dict:
    """Public: tells the login page whether to show first-run setup. No other information is exposed."""
    return {"needs_setup": request.app.state.first_run.needs_setup(db)}


@router.post("/setup")
def first_run_setup(body: FirstRunRequest, request: Request, response: Response,
                    db: Annotated[Session, Depends(db_session)]) -> dict:
    """Create the first administrator (only while no user exists, and only with the one-time setup code)."""
    settings = request.app.state.settings
    ip = client_ip(request)
    if not origin_ok(request):
        raise ForbiddenError("Cross-origin request rejected.")
    request.app.state.rate_limiter.hit("login-ip", ip, settings.rate_limit_login_per_min)
    try:
        user = request.app.state.first_run.complete(db, body.setup_code, body.username, body.password)
    except AegisError as exc:
        db.rollback()
        audit(db, "first_run_setup", "failure", username=body.username[:64], ip=ip, detail={"reason": exc.code})
        raise
    manager: SessionManager = request.app.state.sessions
    issued = manager.create(db, user, ip=ip, user_agent=request.headers.get("user-agent"))
    audit(db, "first_run_setup", "success", user_id=user.id, username=user.username, ip=ip, target_type="user",
          target_id=user.id, detail={"role": user.role}, commit=False)
    db.commit()
    _set_cookie(response, request, issued.token, int(manager.absolute.total_seconds()))
    return {"user": _user_view(user), "csrf_token": issued.csrf_token}


@router.post("/logout")
def logout(request: Request, response: Response, principal: Annotated[Principal, Depends(current_principal)]) -> dict:
    audit(principal.db, "logout", "success", user_id=principal.user.id, username=principal.user.username,
          ip=client_ip(request), commit=False)
    request.app.state.sessions.revoke(principal.db, principal.session)
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/me")
def me(principal: Annotated[Principal, Depends(current_principal)]) -> dict:
    return {"user": _user_view(principal.user)}


@router.get("/csrf")
def csrf(request: Request, principal: Annotated[Principal, Depends(current_principal)]) -> dict:
    """Issue a fresh CSRF token for the current session (e.g. after a page reload).

    Safe as GET: the response is readable only by a same-origin page, and the cookie is SameSite=Strict.
    """
    return {"csrf_token": request.app.state.sessions.rotate_csrf(principal.db, principal.session)}


@router.post("/change-password")
def change_password(body: PasswordChange, request: Request,
                    principal: Annotated[Principal, Depends(current_principal)]) -> dict:
    user, db = principal.user, principal.db
    if not verify_password(user.password_hash, body.current_password):
        audit(db, "password_change", "failure", user_id=user.id, username=user.username, ip=client_ip(request))
        raise InvalidCredentialsError("The current password is incorrect.")
    set_password(db, user, body.new_password)
    revoked = request.app.state.sessions.revoke_all(db, user.id, except_id=principal.session.id)
    audit(db, "password_change", "success", user_id=user.id, username=user.username, ip=client_ip(request),
          detail={"other_sessions_revoked": revoked})
    return {"status": "changed", "other_sessions_revoked": revoked}
