import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError

import app.models  # noqa: F401
from app.db.base import Base
from app.db.session import Database
from app.models import AdEdge, AdObject, ImportJob, Snapshot


@pytest.fixture
def db(settings):
    database = Database(settings.database_url)
    database.migrate()
    yield database
    database.dispose()


def test_migrations_create_all_tables(db):
    tables = set(inspect(db.engine).get_table_names())
    expected = {t.name for t in Base.metadata.sorted_tables}
    assert expected <= tables
    assert "alembic_version" in tables


def test_migrations_match_models(db):
    """Fails if a model was changed without generating a migration."""
    with db.engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_migrate_is_idempotent(db):
    db.migrate()
    db.migrate()


def test_sqlite_pragmas(db):
    with db.engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert conn.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"


def _snapshot_with_edge(session):
    snap = Snapshot(name="test")
    session.add(snap)
    session.flush()
    a = AdObject(snapshot_id=snap.id, object_id="S-1-5-21-1-1001", kind="User", name="ALICE@CORP.LOCAL")
    b = AdObject(snapshot_id=snap.id, object_id="S-1-5-21-1-512", kind="Group", name="DOMAIN ADMINS@CORP.LOCAL")
    session.add_all([a, b])
    session.flush()
    session.add(AdEdge(snapshot_id=snap.id, src_object_pk=a.id, dst_object_pk=b.id, kind="MemberOf",
                       data_source="test", evidence={"file": "groups.json"}))
    session.add(ImportJob(snapshot_id=snap.id, filename="x.json", sha256="0" * 64, size_bytes=10, status="done"))
    session.commit()
    return snap, a, b


def test_object_id_unique_per_snapshot(db):
    with db.session() as s:
        snap, _, _ = _snapshot_with_edge(s)
        s.add(AdObject(snapshot_id=snap.id, object_id="S-1-5-21-1-1001", kind="User", name="DUP"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_duplicate_edge_rejected(db):
    with db.session() as s:
        snap, a, b = _snapshot_with_edge(s)
        s.add(AdEdge(snapshot_id=snap.id, src_object_pk=a.id, dst_object_pk=b.id, kind="MemberOf",
                     data_source="other"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_deleting_snapshot_cascades_to_its_data(db):
    with db.session() as s:
        snap, _, _ = _snapshot_with_edge(s)
        s.execute(text("DELETE FROM snapshots WHERE id = :id"), {"id": snap.id})
        s.commit()
        assert s.scalar(select(AdObject).limit(1)) is None
        assert s.scalar(select(AdEdge).limit(1)) is None
        assert s.scalar(select(ImportJob).limit(1)) is None


def test_json_columns_round_trip(db):
    with db.session() as s:
        _snapshot_with_edge(s)
    with db.session() as s:
        edge = s.scalar(select(AdEdge))
        assert edge.evidence == {"file": "groups.json"}


def test_ping_and_size(db):
    assert db.ping()
    assert db.size_bytes() > 0
