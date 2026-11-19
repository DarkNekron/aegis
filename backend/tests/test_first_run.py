"""First-run setup: no default credentials; the owner creates the first admin with a one-time setup code."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.security.first_run import CODE_FILE, normalise
from tests.conftest import PASSWORD, add_user, make_settings


def code_of(client: TestClient) -> str:
    return client.app.state.first_run.code_file.read_text(encoding="utf-8").splitlines()[1]


def setup(client: TestClient, code: str, username: str = "owner", password: str = PASSWORD, **headers):
    return client.post("/api/auth/setup", json={"setup_code": code, "username": username, "password": password},
                       headers=headers)


def test_fresh_install_needs_setup_and_has_no_users(client: TestClient) -> None:
    assert client.get("/api/auth/setup-status").json() == {"needs_setup": True}
    assert client.get("/api/auth/me").status_code == 401
    code = code_of(client)
    assert len(normalise(code)) == 16 and code.count("-") == 3


def test_code_is_printed_on_console_not_logged(settings, resources, capsys, caplog) -> None:
    from app.main import create_app

    with TestClient(create_app(settings, resources=resources)) as c:
        code = code_of(c)
    assert code in capsys.readouterr().err
    assert code not in caplog.text


def test_setup_creates_admin_signs_in_and_locks(client: TestClient) -> None:
    code = code_of(client)
    r = setup(client, code.lower().replace("-", " "))  # forgiving about case, spaces and dashes
    assert r.status_code == 200, r.text
    assert r.json()["user"] == {"id": 1, "username": "owner", "role": "admin"}
    assert client.get("/api/auth/me").json()["user"]["username"] == "owner"  # session cookie set
    assert client.get("/api/auth/setup-status").json() == {"needs_setup": False}
    assert not client.app.state.first_run.code_file.exists()  # code file removed
    # the same code cannot be used again, nor can anyone set up a second "first" admin
    assert setup(client, code, "intruder").status_code == 409


def test_wrong_code_is_rejected_and_audited(client: TestClient) -> None:
    r = setup(client, "AAAA-BBBB-CCCC-DDDD")
    assert r.status_code == 403 and r.json()["error"]["code"] == "invalid_setup_code"
    assert client.get("/api/auth/setup-status").json() == {"needs_setup": True}
    from app.models import AuditLog

    with client.app.state.db.session() as s:
        row = s.query(AuditLog).filter_by(action="first_run_setup").one()
        assert row.outcome == "failure"


@pytest.mark.parametrize(("username", "password"), [("owner", "short"), ("owner", "owner-is-in-this-password"),
                                                    ("Bad Name!", PASSWORD)])
def test_password_and_username_policy_apply(client: TestClient, username: str, password: str) -> None:
    r = setup(client, code_of(client), username, password)
    assert r.status_code == 422
    assert client.get("/api/auth/setup-status").json() == {"needs_setup": True}  # nothing half-created


def test_password_is_stored_as_argon2id(client: TestClient) -> None:
    setup(client, code_of(client))
    from app.models import User

    with client.app.state.db.session() as s:
        stored = s.query(User).one().password_hash
    assert stored.startswith("$argon2id$") and PASSWORD not in stored


def test_cross_origin_setup_is_rejected(client: TestClient) -> None:
    r = setup(client, code_of(client), origin="https://evil.example")
    assert r.status_code == 403
    assert client.get("/api/auth/setup-status").json() == {"needs_setup": True}


def test_setup_attempts_are_rate_limited(tmp_path, resources) -> None:
    from app.main import create_app

    settings = make_settings(tmp_path, rate_limit_login_per_min=3)
    with TestClient(create_app(settings, resources=resources)) as c:
        statuses = [setup(c, "AAAA-BBBB-CCCC-DDDD").status_code for _ in range(5)]
    assert statuses[:3] == [403, 403, 403] and statuses[3] == 429


def test_no_setup_code_when_users_exist(tmp_path, resources) -> None:
    from app.main import create_app

    settings = make_settings(tmp_path)
    with TestClient(create_app(settings, resources=resources)) as c:
        add_user(c, "someone", "admin")
    with TestClient(create_app(settings, resources=resources)) as c:  # restart
        assert c.get("/api/auth/setup-status").json() == {"needs_setup": False}
        assert not (settings.data_dir / CODE_FILE).exists()
        assert setup(c, "AAAA-BBBB-CCCC-DDDD").status_code == 409


def test_restart_issues_a_new_code(tmp_path, resources) -> None:
    from app.main import create_app

    settings = make_settings(tmp_path)
    with TestClient(create_app(settings, resources=resources)) as c:
        old = code_of(c)
    with TestClient(create_app(settings, resources=resources)) as c:
        assert setup(c, old).status_code == 403
        assert setup(c, code_of(c)).status_code == 200
