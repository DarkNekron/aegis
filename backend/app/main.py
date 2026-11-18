"""AEGIS application factory.

Run locally (single process, see docs/ARCHITECTURE.md §1):

    cd backend
    .venv\\Scripts\\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api import auth, system, users
from app.core.config import Settings, get_settings
from app.core.jobs import JobRunner
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware, install_error_handlers
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.cache import GraphCache
from app.graph_engine.service import GraphService
from app.security.rate_limit import RateLimiter
from app.security.sessions import SessionManager

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, *, resources: ResourceManager | None = None) -> FastAPI:
    settings = settings or get_settings()
    secret = settings.secret_key.get_secret_value() if settings.secret_key else ""
    configure_logging(settings.log_level, extra_secrets=[secret])

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = Database(settings.database_url)
        db.migrate()
        rm = resources or ResourceManager(settings)
        app.state.settings = settings
        app.state.db = db
        app.state.resources = rm
        app.state.jobs = JobRunner(settings, rm)
        app.state.graphs = GraphService(db, rm, GraphCache(settings.graph_cache_size))
        app.state.sessions = SessionManager(settings)
        app.state.rate_limiter = RateLimiter()
        app.state.started_monotonic = time.monotonic()
        logger.info("AEGIS %s started (%s, db=%s)", __version__, settings.env,
                    "sqlite" if settings.is_sqlite else "external")
        try:
            yield
        finally:
            app.state.jobs.shutdown(wait=True)
            app.state.graphs.cache.invalidate()
            db.dispose()
            logger.info("AEGIS stopped")

    app = FastAPI(
        title="AEGIS",
        summary="Active Directory Attack Path Discovery & Intelligence Engine",
        version=__version__,
        docs_url="/api/docs" if settings.env != "production" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.env != "production" else None,
        lifespan=lifespan,
    )
    app.add_middleware(RequestContextMiddleware)
    install_error_handlers(app)
    app.include_router(system.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    return app


app = create_app()
