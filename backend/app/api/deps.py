"""FastAPI dependencies that expose application services stored on ``app.state``."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.jobs import JobRunner
from app.core.resources import ResourceManager
from app.db.session import Database


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_database(request: Request) -> Database:
    return request.app.state.db


def get_db(request: Request) -> Iterator[Session]:
    yield from request.app.state.db.session_scope()


def get_resources(request: Request) -> ResourceManager:
    return request.app.state.resources


def get_jobs(request: Request) -> JobRunner:
    return request.app.state.jobs
