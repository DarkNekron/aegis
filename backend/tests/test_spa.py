"""Single-process mode: the backend serves the built UI without shadowing the API."""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_settings


@pytest.fixture
def spa_client(tmp_path, resources):
    from app.main import create_app

    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    index = '<!doctype html><div id="root"></div><script type="module" src="/assets/app.js"></script>'
    (dist / "index.html").write_text(index)
    (dist / "assets" / "app.js").write_text("console.log('aegis')")
    (tmp_path / "secret.txt").write_text("outside the build directory")
    settings = make_settings(tmp_path, frontend_dist=dist)
    with TestClient(create_app(settings, resources=resources)) as c:
        yield c


def test_index_and_client_routes(spa_client):
    for path in ("/", "/paths", "/settings/anything"):
        r = spa_client.get(path)
        assert r.status_code == 200 and 'id="root"' in r.text, path
        assert r.headers["cache-control"] == "no-store"
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"


def test_assets_are_cached_immutably(spa_client):
    r = spa_client.get("/assets/app.js")
    assert r.status_code == 200 and "aegis" in r.text
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"


def test_traversal_never_leaves_the_build_directory(spa_client):
    for path in ("/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"):
        r = spa_client.get(path)
        assert "outside the build directory" not in r.text, path


def test_api_is_not_shadowed(spa_client):
    r = spa_client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.json()["error"]["code"] == "http_404"
    assert spa_client.get("/api/health").json()["status"] == "ok"
    assert spa_client.get("/api/system/health").status_code == 401


def test_no_build_means_api_only(tmp_path, resources):
    from app.main import create_app

    settings = make_settings(tmp_path, frontend_dist=tmp_path / "missing")
    with TestClient(create_app(settings, resources=resources)) as c:
        assert c.get("/").status_code == 404
        assert c.get("/api/health").status_code == 200
