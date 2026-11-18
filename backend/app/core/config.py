"""Application settings, loaded from environment variables (prefix ``AEGIS_``) and ``.env``.

Defaults are deliberately conservative: they are derived from the hardware assessment in
``docs/SYSTEM_ASSESSMENT.md`` (16 GB laptop, ~2 GB free RAM during normal work).
"""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, PrivateAttr, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> repository root
REPO_ROOT = Path(__file__).resolve().parents[3]

logger = logging.getLogger(__name__)

MIN_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8-sig",  # tolerate a BOM (PowerShell 5.1 writes one)
        extra="ignore",
        validate_default=True,
    )

    _ephemeral_secret: bool = PrivateAttr(default=False)

    # --- Core ---
    env: Literal["development", "production", "test"] = "development"
    secret_key: SecretStr | None = None
    data_dir: Path = Path("data")
    database_url: str | None = None  # derived from data_dir when unset
    host: str = "127.0.0.1"
    port: int = Field(8000, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- Sessions & auth ---
    session_idle_minutes: int = Field(30, ge=5, le=24 * 60)
    session_absolute_hours: int = Field(8, ge=1, le=72)
    cookie_secure: bool = False
    login_max_failures: int = Field(5, ge=1, le=50)
    login_lockout_minutes: int = Field(15, ge=1, le=24 * 60)

    # --- Rate limiting (requests per minute) ---
    rate_limit_login_per_min: int = Field(10, ge=1, le=1000)
    rate_limit_api_per_min: int = Field(300, ge=10, le=100_000)

    # --- Resource limits ---
    max_analysis_workers: int = Field(1, ge=1, le=8)
    max_light_workers: int = Field(2, ge=1, le=8)
    max_pending_jobs: int = Field(8, ge=1, le=256)
    job_timeout_seconds: int = Field(180, ge=5, le=3600)
    min_free_ram_mb: int = Field(768, ge=0)
    min_free_disk_mb: int = Field(1024, ge=0)
    graph_cache_size: int = Field(1, ge=1, le=8)
    max_graph_nodes: int = Field(150_000, ge=10)
    max_graph_edges: int = Field(1_500_000, ge=10)

    # --- Import limits ---
    max_upload_mb: int = Field(512, ge=1, le=10_240)
    max_zip_uncompressed_mb: int = Field(2048, ge=1, le=50_000)
    max_zip_members: int = Field(500, ge=1, le=100_000)
    max_zip_ratio: int = Field(100, ge=2, le=10_000)
    ingest_batch_size: int = Field(2000, ge=100, le=50_000)

    # --- Analysis ---
    max_path_depth: int = Field(10, ge=1, le=25)
    max_alternative_paths: int = Field(5, ge=1, le=50)
    centrality_sample_size: int = Field(256, ge=8, le=100_000)
    ui_max_elements: int = Field(1500, ge=50, le=20_000)
    frontend_dist: Path = Path("frontend/dist")  # built UI served by the backend when present

    @field_validator("data_dir", "frontend_dist")
    @classmethod
    def _resolve_data_dir(cls, value: Path) -> Path:
        # Relative paths are anchored to the repository root, never the current working directory.
        return value if value.is_absolute() else (REPO_ROOT / value).resolve()

    @model_validator(mode="after")
    def _finalise(self) -> Settings:
        if not self.database_url:
            self.database_url = f"sqlite:///{(self.data_dir / 'aegis.db').as_posix()}"

        key = self.secret_key.get_secret_value() if self.secret_key else ""
        if len(key) < MIN_SECRET_KEY_LENGTH:
            if self.env == "production":
                raise ValueError(
                    f"AEGIS_SECRET_KEY must be set to at least {MIN_SECRET_KEY_LENGTH} characters in production"
                )
            # Development/test: use an ephemeral key. Sessions will not survive a restart.
            self.secret_key = SecretStr(secrets.token_urlsafe(48))
            self._ephemeral_secret = True
        else:
            self._ephemeral_secret = False
        return self

    @property
    def uses_ephemeral_secret(self) -> bool:
        return self._ephemeral_secret

    @property
    def is_sqlite(self) -> bool:
        return bool(self.database_url and self.database_url.startswith("sqlite"))

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_zip_uncompressed_bytes(self) -> int:
        return self.max_zip_uncompressed_mb * 1024 * 1024

    def public_limits(self) -> dict[str, int]:
        """Resource limits that are safe to show in the UI (no secrets, no paths)."""
        return {
            "max_analysis_workers": self.max_analysis_workers,
            "max_light_workers": self.max_light_workers,
            "max_pending_jobs": self.max_pending_jobs,
            "job_timeout_seconds": self.job_timeout_seconds,
            "min_free_ram_mb": self.min_free_ram_mb,
            "min_free_disk_mb": self.min_free_disk_mb,
            "graph_cache_size": self.graph_cache_size,
            "max_graph_nodes": self.max_graph_nodes,
            "max_graph_edges": self.max_graph_edges,
            "max_upload_mb": self.max_upload_mb,
            "max_zip_uncompressed_mb": self.max_zip_uncompressed_mb,
            "max_zip_members": self.max_zip_members,
            "max_zip_ratio": self.max_zip_ratio,
            "max_path_depth": self.max_path_depth,
            "max_alternative_paths": self.max_alternative_paths,
            "ui_max_elements": self.ui_max_elements,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    if settings.uses_ephemeral_secret:
        logger.warning("AEGIS_SECRET_KEY not set: using an ephemeral key (sessions reset on restart).")
    return settings
