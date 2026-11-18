"""Stage 5.0: authentication, sessions, CSRF, RBAC, rate limiting, lockout and audit."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.core.errors import ValidationFailedError
from app.models import AuditLog, AuthSession, User
from app.security.passwords import check_policy, hash_password, verify_password
from app.security.rate_limit import RateLimitedError, RateLimiter
from app.security.sessions import COOKIE_NAME
from tests.conftest import PASSWORD, add_user, login, make_settings


def audit_actions(client):
    with client.app.state.db.session() as s:
        return [(a.action, a.outcome, a.username) for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


# ------------------------------------------------------------------ passwords
def test_argon2id_hashing():
    h = hash_password(PASSWORD)
    assert h.startswith("$argon2id$") and PASSWORD not in h
    assert verify_password(h, PASSWORD) and not verify_password(h, PASSWORD + "x")
    assert not verify_password(None, PASSWORD) and not verify_password("not-a-hash", PASSWORD)


@pytest.mark.parametrize("password,username", [
    ("short", "alice"), ("x" * 129, "alice"), ("alice-is-great-2026", "alice"), ("password1234", "bob"),
    ("aaaaaaaaaaaaaaaa", "bob"),
])
def test_password_policy_rejects(password, username):
    with pytest.raises(ValidationFailedError):
        check_policy(password, username)


def test_password_policy_accepts_reasonable_passphrase():
    check_policy("Correct-Horse-Battery-9", "alice")


# ------------------------------------------------------------------ login, cookie, session
def test_login_sets_hardened_cookie_and_stores_only_hashes(client):
    add_user(client, "alice", "analyst")
    r = client.post("/api/auth/login", json={"username": "Alice", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["user"] == {"id": body["user"]["id"], "username": "alice", "role": "analyst"}
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    token = client.cookies.get(COOKIE_NAME)
    with client.app.state.db.session() as s:
        row = s.scalar(select(AuthSession))
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert token not in (row.token_hash, row.csrf_token_hash)
        assert row.csrf_token_hash == hashlib.sha256(body["csrf_token"].encode()).hexdigest()
    assert client.get("/api/auth/me").json()["user"]["username"] == "alice"


def test_secure_cookie_flag_when_configured(tmp_path, resources):
    from app.main import create_app

    settings = make_settings(tmp_path, cookie_secure=True)
    with TestClient(create_app(settings, resources=resources), base_url="https://testserver") as c:
        add_user(c, "alice", "viewer")
        r = c.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
        assert "secure" in r.headers["set-cookie"].lower()


@pytest.mark.parametrize("username,password", [("alice", "wrong-password-123"), ("nobody", PASSWORD),
                                               ("bad name!", PASSWORD)])
def test_failures_are_indistinguishable(client, username, password):
    add_user(client, "alice", "viewer")
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 401
    assert r.json()["error"]["message"] == "Invalid username or password."
    assert COOKIE_NAME not in client.cookies


def test_lockout_after_repeated_failures_even_with_correct_password(client):
    add_user(client, "alice", "viewer")
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "alice", "password": "wrong-password-123"})
    r = client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["error"]["message"] == "Invalid username or password."
    with client.app.state.db.session() as s:
        assert s.scalar(select(User.locked_until).where(User.username == "alice")) is not None
        s.execute(update(User).where(User.username == "alice")
                  .values(locked_until=datetime.now(UTC) - timedelta(seconds=1)))
        s.commit()
    assert client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD}).status_code == 200
    reasons = [a for a in audit_actions(client) if a[0] == "login"]
    assert reasons[-1] == ("login", "success", "alice") and ("login", "failure", "alice") in reasons


def test_login_rate_limit(client):
    for i in range(10):
        client.post("/api/auth/login", json={"username": f"user{i}", "password": "x" * 12})
    r = client.post("/api/auth/login", json={"username": "another", "password": "x" * 12})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_inactive_user_cannot_log_in_or_use_existing_session(client):
    uid = add_user(client, "alice", "viewer")
    login(client, "alice")
    with client.app.state.db.session() as s:
        s.execute(update(User).where(User.id == uid).values(is_active=False))
        s.commit()
    assert client.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD}).status_code == 401


def test_idle_and_absolute_expiry(client):
    add_user(client, "alice", "viewer")
    login(client, "alice")
    with client.app.state.db.session() as s:
        s.execute(update(AuthSession).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=31)))
        s.commit()
    assert client.get("/api/auth/me").status_code == 401  # idle timeout (30 min)
    login(client, "alice")
    with client.app.state.db.session() as s:
        s.execute(update(AuthSession).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        s.commit()
    assert client.get("/api/auth/me").status_code == 401  # absolute lifetime


def test_logout_revokes_session_server_side(client):
    add_user(client, "alice", "viewer")
    csrf = login(client, "alice")
    stolen = client.cookies.get(COOKIE_NAME)
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    client.cookies.set(COOKIE_NAME, stolen)  # replaying the old cookie must not work
    assert client.get("/api/auth/me").status_code == 401


# ------------------------------------------------------------------ CSRF and origin
def test_state_changing_requests_need_csrf_token(client):
    add_user(client, "admin1", "admin")
    csrf = login(client, "admin1")
    payload = {"username": "bob", "password": PASSWORD, "role": "viewer"}
    assert client.post("/api/users", json=payload).status_code == 403
    assert client.post("/api/users", json=payload, headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert client.post("/api/users", json=payload, headers={"X-CSRF-Token": csrf}).status_code == 201


def test_cross_origin_requests_rejected(client):
    add_user(client, "admin1", "admin")
    csrf = login(client, "admin1")
    r = client.post("/api/users", json={"username": "bob", "password": PASSWORD, "role": "viewer"},
                    headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"})
    assert r.status_code == 403 and "Cross-origin" in r.json()["error"]["message"]


def test_csrf_rotation_invalidates_previous_token(client):
    add_user(client, "admin1", "admin")
    old = login(client, "admin1")
    new = client.get("/api/auth/csrf").json()["csrf_token"]
    payload = {"username": "bob", "password": PASSWORD, "role": "viewer"}
    assert client.post("/api/users", json=payload, headers={"X-CSRF-Token": old}).status_code == 403
    assert client.post("/api/users", json=payload, headers={"X-CSRF-Token": new}).status_code == 201


# ------------------------------------------------------------------ RBAC
@pytest.mark.parametrize("role,expected", [("viewer", 403), ("analyst", 403), ("admin", 200)])
def test_user_administration_is_admin_only(client, role, expected):
    add_user(client, f"{role}1", role)
    client.headers["X-CSRF-Token"] = login(client, f"{role}1")
    assert client.get("/api/users").status_code == expected
    assert client.get("/api/audit").status_code == expected


def test_unauthenticated_requests_rejected(client):
    for method, path in [("get", "/api/users"), ("get", "/api/audit"), ("get", "/api/auth/me"),
                         ("post", "/api/auth/logout"), ("get", "/api/system/health")]:
        assert getattr(client, method)(path).status_code == 401, path


def test_admin_user_lifecycle_and_safety_rails(admin_client):
    c = admin_client
    created = c.post("/api/users", json={"username": "Bob.Smith", "password": PASSWORD, "role": "analyst"})
    assert created.status_code == 201 and created.json()["username"] == "bob.smith"
    bob = created.json()["id"]
    duplicate = {"username": "bob.smith", "password": PASSWORD, "role": "viewer"}
    assert c.post("/api/users", json=duplicate).status_code == 409
    assert c.post("/api/users", json={"username": "weak", "password": "short", "role": "viewer"}).status_code == 422
    assert c.post("/api/users", json={"username": "x", "password": PASSWORD, "role": "root"}).status_code == 422
    assert c.patch(f"/api/users/{bob}", json={"role": "viewer"}).json()["role"] == "viewer"

    me = next(u for u in c.get("/api/users").json()["items"] if u["username"] == "admin-user")
    assert c.patch(f"/api/users/{me['id']}", json={"role": "viewer"}).status_code == 422       # not yourself
    assert c.patch(f"/api/users/{me['id']}", json={"is_active": False}).status_code == 422
    assert c.post(f"/api/users/{bob}/reset-password", json={"new_password": "Another-Strong-Pass-7"}).status_code == 200
    assert c.patch("/api/users/99999", json={"role": "viewer"}).status_code == 404

    actions = [a[0] for a in audit_actions(c)]
    assert {"user_create", "user_update", "password_reset"} <= set(actions)
    log = c.get("/api/audit", params={"action": "user_create"}).json()
    assert log["total"] == 1 and "password" not in str(log).lower()


def test_last_admin_cannot_be_removed(client):
    from app.services.user_service import update_user

    add_user(client, "admin1", "admin")
    second = add_user(client, "admin2", "admin")
    client.headers["X-CSRF-Token"] = login(client, "admin1")
    assert client.patch(f"/api/users/{second}", json={"role": "analyst"}).status_code == 200
    # admin1 is now the only active admin. Through the API self-demotion is blocked first; the service-level
    # guard protects every other caller (CLI, future endpoints).
    with client.app.state.db.session() as s:
        only_admin = s.scalar(select(User).where(User.username == "admin1"))
        other = s.get(User, second)
        for change in ({"role": "viewer"}, {"is_active": False}):
            with pytest.raises(ValidationFailedError, match="At least one active administrator"):
                update_user(s, other, only_admin.id, **change)


def test_deactivating_a_user_kills_their_sessions(client):
    bob = add_user(client, "bob", "viewer")
    add_user(client, "admin1", "admin")
    bob_client = TestClient(client.app)
    login(bob_client, "bob")
    client.headers["X-CSRF-Token"] = login(client, "admin1")
    assert client.patch(f"/api/users/{bob}", json={"is_active": False}).status_code == 200
    assert bob_client.get("/api/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(client):
    add_user(client, "alice", "viewer")
    other = TestClient(client.app)
    login(other, "alice")
    csrf = login(client, "alice")
    bad = client.post("/api/auth/change-password", headers={"X-CSRF-Token": csrf},
                      json={"current_password": "wrong-one-1234", "new_password": "Brand-New-Pass-42"})
    assert bad.status_code == 401
    ok = client.post("/api/auth/change-password", headers={"X-CSRF-Token": csrf},
                     json={"current_password": PASSWORD, "new_password": "Brand-New-Pass-42"})
    assert ok.json()["other_sessions_revoked"] == 1
    assert other.get("/api/auth/me").status_code == 401 and client.get("/api/auth/me").status_code == 200
    relogin = client.post("/api/auth/login", json={"username": "alice", "password": "Brand-New-Pass-42"})
    assert relogin.status_code == 200


# ------------------------------------------------------------------ rate limiter unit + CLI bootstrap
def test_rate_limiter_refills_and_is_bounded():
    now = [0.0]
    limiter = RateLimiter(max_keys=3, clock=lambda: now[0])
    for _ in range(2):
        limiter.hit("s", "k", per_minute=2)
    with pytest.raises(RateLimitedError):
        limiter.hit("s", "k", per_minute=2)
    now[0] += 30  # one token refilled
    limiter.hit("s", "k", per_minute=2)
    for key in ("a", "b", "c", "d"):
        limiter.hit("s", key, per_minute=5)
    assert len(limiter._buckets) == 3


def test_cli_create_user_prompts_for_password(tmp_path, monkeypatch, capsys):
    from app.cli import main
    from app.core.config import get_settings

    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "cli"))
    monkeypatch.setenv("AEGIS_ENV", "test")
    answers = iter([PASSWORD, PASSWORD, PASSWORD, "different-Pass-99"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    get_settings.cache_clear()
    try:
        assert main(["create-user", "root-admin", "--role", "admin"]) == 0
        assert "Created admin 'root-admin'" in capsys.readouterr().out
        assert main(["create-user", "other", "--role", "viewer"]) == 2  # mismatched confirmation
    finally:
        get_settings.cache_clear()
