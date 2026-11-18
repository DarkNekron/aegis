import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import REPO_ROOT, Settings


def test_defaults_are_conservative(tmp_path):
    s = Settings(env="test", data_dir=tmp_path, _env_file=None)
    assert s.max_analysis_workers == 1
    assert s.min_free_ram_mb == 768
    assert s.max_upload_bytes == 512 * 1024 * 1024
    assert s.host == "127.0.0.1"  # loopback only by default


def test_database_url_derived_from_data_dir(tmp_path):
    s = Settings(env="test", data_dir=tmp_path, _env_file=None)
    assert s.database_url == f"sqlite:///{(tmp_path / 'aegis.db').as_posix()}"
    assert s.is_sqlite


def test_relative_data_dir_is_anchored_to_repo_root():
    s = Settings(env="test", data_dir=Path("data"), _env_file=None)
    assert s.data_dir == (REPO_ROOT / "data").resolve()


def test_missing_secret_in_development_uses_ephemeral_key(tmp_path):
    s = Settings(env="development", data_dir=tmp_path, _env_file=None)
    assert s.uses_ephemeral_secret
    assert len(s.secret_key.get_secret_value()) >= 32


def test_production_requires_strong_secret(tmp_path):
    with pytest.raises(ValidationError, match="AEGIS_SECRET_KEY"):
        Settings(env="production", data_dir=tmp_path, secret_key="short", _env_file=None)
    ok = Settings(env="production", data_dir=tmp_path, secret_key="x" * 40, _env_file=None)
    assert not ok.uses_ephemeral_secret


def test_secret_is_not_exposed_in_repr_or_public_limits(tmp_path):
    s = Settings(env="production", data_dir=tmp_path, secret_key="supersecretvalue" * 3, _env_file=None)
    assert "supersecretvalue" not in repr(s)
    assert "secret" not in str(s.public_limits()).lower()


@pytest.mark.parametrize("field,value", [("max_analysis_workers", 0), ("max_path_depth", 99), ("port", 70000)])
def test_out_of_range_values_rejected(tmp_path, field, value):
    with pytest.raises(ValidationError):
        Settings(env="test", data_dir=tmp_path, _env_file=None, **{field: value})


def test_env_example_template_parses_cleanly(monkeypatch):
    """The shipped .env.example (with inline comments) must load without errors or stray text."""
    for key in [k for k in os.environ if k.startswith("AEGIS_")]:
        monkeypatch.delenv(key)
    s = Settings(_env_file=REPO_ROOT / ".env.example")
    assert s.env == "development"
    assert s.max_pending_jobs == 8
    assert s.min_free_ram_mb == 768
    assert s.min_free_disk_mb == 1024
    assert s.host == "127.0.0.1"
    assert s.data_dir == (REPO_ROOT / "data").resolve()
    assert s.uses_ephemeral_secret  # template ships with an empty secret


def test_environment_variables_are_read(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_MAX_GRAPH_NODES", "1234")
    s = Settings(env="test", data_dir=tmp_path, _env_file=None)
    assert s.max_graph_nodes == 1234
