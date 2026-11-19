"""FastAPI dependencies: authentication, role checks, CSRF/Origin protection and API rate limiting.

Usage on a router or endpoint::

    Depends(require_role("analyst"))   # authenticated, role >= analyst, and CSRF-checked if unsafe method
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.errors import AegisError
from app.models import AuthSession, User
from app.security.sessions import COOKIE_NAME, CSRF_HEADER, SessionManager
from app.services.user_service import ROLE_RANK

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class NotAuthenticatedError(AegisError):
    code = "not_authenticated"
    http_status = 401


class ForbiddenError(AegisError):
    code = "forbidden"
    http_status = 403


@dataclass
class Principal:
    user: User
    session: AuthSession
    db: Session

    @property
    def role_rank(self) -> int:
        return ROLE_RANK.get(self.user.role, 0)


def client_ip(request: Request) -> str:
    # No proxy headers are trusted: AEGIS binds to loopback by default (see SECURITY.md).
    return request.client.host if request.client else "unknown"


def db_session(request: Request) -> Iterator[Session]:
    yield from request.app.state.db.session_scope()


def origin_ok(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True  # same-origin fetches from older browsers / non-browser clients; CSRF token still required
    host = request.headers.get("host", "")
    return urlsplit(origin).netloc == host


def current_principal(request: Request, db: Annotated[Session, Depends(db_session)]) -> Principal:
    manager: SessionManager = request.app.state.sessions
    resolved = manager.resolve(db, request.cookies.get(COOKIE_NAME))
    if resolved is None:
        raise NotAuthenticatedError("Authentication required.")
    row, user = resolved
    if request.method not in SAFE_METHODS:
        if not origin_ok(request):
            raise ForbiddenError("Cross-origin request rejected.")
        if not manager.check_csrf(row, request.headers.get(CSRF_HEADER)):
            raise ForbiddenError("Missing or invalid CSRF token.")
    settings = request.app.state.settings
    request.app.state.rate_limiter.hit("api", f"user:{user.id}", settings.rate_limit_api_per_min)
    request.state.user_id, request.state.username = user.id, user.username
    return Principal(user=user, session=row, db=db)


def require_role(minimum: str) -> Callable[..., Principal]:
    needed = ROLE_RANK[minimum]

    def dependency(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if principal.role_rank < needed:
            raise ForbiddenError(f"This action requires the {minimum} role.")
        return principal

    return dependency
