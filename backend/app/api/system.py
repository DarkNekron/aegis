"""Liveness and system-health endpoints (the data behind the System Health page).

Note: ``/api/system/*`` becomes authenticated (viewer role or higher) in the security stage
(roadmap 5.0). ``/api/health`` stays public and reveals nothing beyond "up" and the version.
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request

from app import __version__
from app.api.deps import get_database, get_jobs, get_resources, get_settings_dep
from app.core.config import Settings
from app.core.jobs import JobRunner
from app.core.resources import ResourceManager
from app.db.session import Database

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health", summary="Liveness probe")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/system/health", summary="Resource usage, limits, job queue and database status")
def system_health(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings_dep)],
    resources: Annotated[ResourceManager, Depends(get_resources)],
    jobs: Annotated[JobRunner, Depends(get_jobs)],
    db: Annotated[Database, Depends(get_database)],
) -> dict[str, Any]:
    snap = resources.snapshot()
    try:
        db_ok = db.ping()
    except Exception:
        db_ok = False

    warnings: list[str] = []
    if snap.available_ram_mb < settings.min_free_ram_mb:
        warnings.append(
            f"Free RAM ({snap.available_ram_mb} MB) is below the {settings.min_free_ram_mb} MB reserve; "
            "heavy analyses will be refused until memory is freed."
        )
    if snap.disk_free_mb < settings.min_free_disk_mb:
        warnings.append(f"Free disk space ({snap.disk_free_mb} MB) is below the configured minimum.")
    if settings.uses_ephemeral_secret:
        warnings.append("AEGIS_SECRET_KEY is not set; sessions will reset when the server restarts.")
    if not db_ok:
        warnings.append("The database is not responding.")

    return {
        "status": "degraded" if warnings else "ok",
        "version": __version__,
        "environment": settings.env,
        "uptime_seconds": int(time.monotonic() - request.app.state.started_monotonic),
        "platform": resources.platform_info(),
        "resources": snap.to_dict(),
        "limits": settings.public_limits(),
        "jobs": jobs.stats(),
        "graph_cache": request.app.state.graphs.cache.stats(),
        "database": {
            "ok": db_ok,
            "engine": "sqlite" if settings.is_sqlite else "postgresql",
            "size_bytes": db.size_bytes(),
        },
        "warnings": warnings,
    }
