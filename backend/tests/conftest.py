from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.resources import ResourceManager, ResourceSnapshot


class FakeProbe:
    """Deterministic resource readings; tests mutate ``available_ram_mb`` / ``disk_free_mb``."""

    def __init__(self, available_ram_mb: int = 4096, disk_free_mb: int = 50_000):
        self.available_ram_mb = available_ram_mb
        self.disk_free_mb = disk_free_mb

    def __call__(self) -> ResourceSnapshot:
        return ResourceSnapshot(
            timestamp=time.time(), total_ram_mb=16_000, available_ram_mb=self.available_ram_mb, ram_percent=50.0,
            cpu_percent=10.0, cpu_logical=20, cpu_physical=14, process_rss_mb=120,
            disk_total_mb=900_000, disk_free_mb=self.disk_free_mb,
        )


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = {"env": "test", "data_dir": tmp_path / "data", "_env_file": None} | overrides
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def probe() -> FakeProbe:
    return FakeProbe()


@pytest.fixture
def resources(settings: Settings, probe: FakeProbe) -> ResourceManager:
    return ResourceManager(settings, probe=probe)


@pytest.fixture
def client(settings: Settings, resources: ResourceManager) -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app(settings, resources=resources)) as c:
        yield c


# ---------------------------------------------------------------- authentication helpers
PASSWORD = "Correct-Horse-Battery-9"


def add_user(client: TestClient, username: str, role: str, password: str = PASSWORD) -> int:
    from app.services.user_service import create_user

    with client.app.state.db.session() as s:
        user = create_user(s, username, password, role)
        s.commit()
        return user.id


def login(client: TestClient, username: str, password: str = PASSWORD) -> str:
    """Log in (sets the session cookie on the client) and return the CSRF token."""
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def as_role(client: TestClient, role: str) -> TestClient:
    add_user(client, f"{role}-user", role)
    client.headers["X-CSRF-Token"] = login(client, f"{role}-user")
    return client


@pytest.fixture
def viewer_client(client: TestClient) -> TestClient:
    return as_role(client, "viewer")


@pytest.fixture
def admin_client(client: TestClient) -> TestClient:
    return as_role(client, "admin")
