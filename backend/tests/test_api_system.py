import logging

from app import __version__
from app.core.logging import RedactingFilter


def test_health_is_minimal(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": __version__}


def test_security_headers_present(client):
    r = client.get("/api/health")
    h = r.headers
    assert "default-src 'self'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    assert len(h["x-request-id"]) >= 8


def test_valid_request_id_is_propagated_and_invalid_one_replaced(client):
    assert client.get("/api/health", headers={"X-Request-ID": "abc-12345678"}).headers["x-request-id"] == \
        "abc-12345678"
    replaced = client.get("/api/health", headers={"X-Request-ID": "<script>"}).headers["x-request-id"]
    assert replaced != "<script>" and replaced.isalnum()


def test_system_health_reports_resources_limits_jobs_and_db(client):
    body = client.get("/api/system/health").json()
    assert body["status"] in {"ok", "degraded"}
    assert body["database"] == {"ok": True, "engine": "sqlite", "size_bytes": body["database"]["size_bytes"]}
    assert body["resources"]["available_ram_mb"] == 4096
    assert body["limits"]["max_analysis_workers"] == 1
    assert "queued" in body["jobs"]
    assert "secret" not in str(body).lower().replace("aegis_secret_key", "")


def test_system_health_warns_on_low_memory(client, probe):
    probe.available_ram_mb = 100
    body = client.get("/api/system/health").json()
    assert body["status"] == "degraded"
    assert any("Free RAM" in w for w in body["warnings"])


def test_unknown_route_returns_structured_error(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404
    err = r.json()["error"]
    assert err["code"] == "http_404" and err["request_id"]


def test_unhandled_exception_hides_details(settings, resources):
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(settings, resources=resources)

    @app.get("/api/_boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/_boom")
    assert r.status_code == 500
    assert "hunter2" not in r.text
    assert r.json()["error"]["code"] == "internal_error"


def test_log_redaction():
    f = RedactingFilter(extra_secrets=["my-very-secret-key-value"])
    record = logging.LogRecord("t", logging.INFO, __file__, 1,
                               "login password=hunter2 token: abc123 key=%s Authorization: Bearer eyJhbGciOi.x.y",
                               ("my-very-secret-key-value",), None)
    f.filter(record)
    msg = record.getMessage()
    for leaked in ("hunter2", "abc123", "my-very-secret-key-value", "eyJhbGciOi"):
        assert leaked not in msg
    assert "[REDACTED]" in msg
