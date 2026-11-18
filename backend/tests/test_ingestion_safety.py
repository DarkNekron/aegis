"""Hostile and malformed input: unsafe archives, broken files, limits, cancellation and rollback."""

import io
import json
import zipfile

import pytest
from sqlalchemy import func, select

from app.core.errors import (
    JobCancelledError,
    LimitExceededError,
    MalformedInputError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)
from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.ingestion.service import ImportService
from app.ingestion.sources import ByteBudget, GuardedStream
from app.ingestion.uploads import UploadWriter
from app.models import AdEdge, AdObject, ImportJob, IngestStagedEdge, Snapshot
from tests.bh_builders import bh_file, sharphound_zip, small_domain, user, write_json, write_zip
from tests.conftest import FakeProbe, make_settings


@pytest.fixture
def db(settings):
    database = Database(settings.database_url)
    database.migrate()
    yield database
    database.dispose()


@pytest.fixture
def service(db, settings, resources):
    return ImportService(db, settings, resources)


def count(db, model):
    with db.session() as s:
        return s.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------- unsafe archives
@pytest.mark.parametrize("member", ["../evil.json", "a/../../evil.json", "/etc/evil.json", "C:/evil.json",
                                    "..\\evil.json"])
def test_path_traversal_and_absolute_paths_rejected(tmp_path, service, member):
    path = write_zip(tmp_path / "bad.zip", {member: bh_file("users", [])})
    snap = service.create_snapshot("s")
    with pytest.raises(UnsafeArchiveError):
        service.import_file(snap, path, "bad.zip")


def test_symlink_member_rejected(tmp_path, service):
    path = tmp_path / "link.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("users.json")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(UnsafeArchiveError, match="symbolic link"):
        service.import_file(service.create_snapshot("s"), path, "link.zip")


def test_compression_bomb_rejected_by_ratio(tmp_path, service):
    path = write_zip(tmp_path / "bomb.zip", {"users.json": b" " * (5 * 1024 * 1024)})  # ~5 MB -> few KB
    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        service.import_file(service.create_snapshot("s"), path, "bomb.zip")


def test_total_uncompressed_size_limit(tmp_path, db, resources):
    settings = make_settings(tmp_path, max_zip_uncompressed_mb=1, max_zip_ratio=10_000)
    svc = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe()))
    big = json.dumps(bh_file("users", [user(i, f"U{i}") for i in range(4000)]))  # > 1 MB of JSON
    path = write_zip(tmp_path / "big.zip", {"users.json": big})
    with pytest.raises(UnsafeArchiveError, match="uncompressed size"):
        svc.import_file(svc.create_snapshot("s"), path, "big.zip")


def test_too_many_members(tmp_path, db):
    settings = make_settings(tmp_path, max_zip_members=3)
    svc = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe()))
    path = write_zip(tmp_path / "many.zip", {f"f{i}_users.json": bh_file("users", []) for i in range(4)})
    with pytest.raises(UnsafeArchiveError, match="entries"):
        svc.import_file(svc.create_snapshot("s"), path, "many.zip")


def test_password_protected_zip_rejected(tmp_path, service):
    # zipfile cannot write encrypted entries, so set the "encrypted" flag in the central directory directly
    path = write_zip(tmp_path / "enc.zip", {"users.json": bh_file("users", [])})
    data = bytearray(path.read_bytes())
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 0x1
    path.write_bytes(bytes(data))
    with pytest.raises(UnsafeArchiveError, match="password"):
        service.import_file(service.create_snapshot("s"), path, "enc.zip")


def test_guarded_stream_enforces_limits_while_reading():
    raw = io.BytesIO(b"x" * 100)
    stream = io.BufferedReader(GuardedStream(raw, member_limit=50, budget=None))
    with pytest.raises(UnsafeArchiveError, match="larger than its declared size"):
        stream.read()
    budget = ByteBudget(30)
    stream = io.BufferedReader(GuardedStream(io.BytesIO(b"y" * 40), member_limit=None, budget=budget))
    with pytest.raises(UnsafeArchiveError, match="expands beyond"):
        stream.read()


def test_non_data_members_skipped_with_warning(tmp_path, service):
    files = {f"{t}.json": c for t, c in small_domain().items()}
    files["readme.txt"] = "hello"
    files["nested.zip"] = b"PK\x03\x04junk"
    result = service.import_file(service.create_snapshot("s"), write_zip(tmp_path / "x.zip", files), "x.zip")
    assert result.status == "succeeded"
    assert sum("Skipped" in w for w in result.summary["warnings"]) == 2


# ---------------------------------------------------------------- file type validation
def test_extension_and_content_must_agree(tmp_path, service):
    snap = service.create_snapshot("s")
    fake_zip = tmp_path / "x.zip"
    fake_zip.write_text("{}")
    with pytest.raises(UnsupportedFormatError, match="not a ZIP"):
        service.import_file(snap, fake_zip, "x.zip")
    zip_as_json = sharphound_zip(tmp_path / "real.zip")
    with pytest.raises(UnsupportedFormatError, match="rename it to .zip"):
        service.import_file(snap, zip_as_json, "data.json")
    exe = tmp_path / "x.exe"
    exe.write_bytes(b"MZ")
    with pytest.raises(UnsupportedFormatError, match="Unsupported file type"):
        service.import_file(snap, exe, "x.exe")


def test_corrupt_zip(tmp_path, service):
    path = tmp_path / "broken.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 50)
    with pytest.raises(MalformedInputError, match="corrupt"):
        service.import_file(service.create_snapshot("s"), path, "broken.zip")


def test_empty_file(tmp_path, service):
    path = tmp_path / "empty.json"
    path.write_bytes(b"")
    with pytest.raises(MalformedInputError, match="empty"):
        service.import_file(service.create_snapshot("s"), path, "empty.json")


# ---------------------------------------------------------------- malformed content
def test_truncated_json_member_keeps_other_files_and_marks_partial(tmp_path, service, db):
    files = {f"{t}.json": c for t, c in small_domain().items()}
    files["computers.json"] = json.dumps(small_domain()["computers"])[:300]  # truncated mid-object
    result = service.import_file(service.create_snapshot("s"), write_zip(tmp_path / "t.zip", files), "t.zip")
    assert result.status == "partial"
    bad = next(f for f in result.summary["files"] if f["name"] == "computers.json")
    assert "invalid or truncated JSON" in bad["error"]
    assert result.summary["objects_inserted"] > 0


def test_invalid_records_are_skipped_and_reported(tmp_path, service, db):
    items = [user(1101, "ALICE"), {"ObjectIdentifier": "bad id with spaces", "Properties": {}}, "not-an-object",
             {"Properties": {"name": "no id"}}]
    path = write_json(tmp_path / "users.json", bh_file("users", items))
    snap = service.create_snapshot("s")
    result = service.import_file(snap, path, "users.json")
    assert result.status == "partial"
    assert result.summary["item_errors"] == 3
    locations = {e["location"] for e in result.summary["errors"]}
    assert {"data[1]", "data[2]", "data[3]"} <= locations
    assert count(db, AdObject) >= 1


def test_unrecognised_json_and_opengraph(tmp_path, service):
    snap = service.create_snapshot("s")
    result = service.import_file(snap, write_json(tmp_path / "x.json", {"hello": "world"}), "x.json")
    assert result.status == "failed" and "not a recognised format" in result.summary["files"][0]["error"]
    snap2 = service.create_snapshot("s2")
    result = service.import_file(snap2, write_json(tmp_path / "g.json", {"graph": {"nodes": []}}), "g.json")
    assert "OpenGraph" in result.summary["files"][0]["error"]


def test_top_level_array_rejected(tmp_path, service):
    result = service.import_file(service.create_snapshot("s"), write_json(tmp_path / "a.json", [1, 2]), "a.json")
    assert result.status == "failed"


def test_hostile_strings_are_sanitised(tmp_path, service, db):
    evil = user(1101, "ALICE")
    evil["Properties"]["name"] = "ADMIN\u202eFDP.EXE\x00\x07<script>" + "A" * 2000
    evil["Properties"]["description"] = "line1\nline2\t\x1b[31mred"
    snap = service.create_snapshot("s")
    service.import_file(snap, write_json(tmp_path / "users.json", bh_file("users", [evil])), "users.json")
    with db.session() as s:
        obj = s.scalar(select(AdObject))
    assert "\u202e" not in obj.name and "\x00" not in obj.name and "\x07" not in obj.name
    assert len(obj.name) <= 512
    assert "\x1b" not in obj.properties["description"] and "\n" not in obj.properties["description"]
    # HTML is stored as text; escaping is the renderer's job (React / Jinja2 autoescape)
    assert "<script>" in obj.name


# ---------------------------------------------------------------- limits, cancellation, rollback
def test_node_limit_aborts_and_rolls_back_everything(tmp_path, db):
    settings = make_settings(tmp_path, max_graph_nodes=10)
    svc = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe()))
    snap = svc.create_snapshot("s")
    path = write_json(tmp_path / "users.json", bh_file("users", [user(1000 + i, f"U{i}") for i in range(25)]))
    with pytest.raises(LimitExceededError, match="AEGIS_MAX_GRAPH_NODES"):
        svc.import_file(snap, path, "users.json")
    assert count(db, AdObject) == 0 and count(db, AdEdge) == 0 and count(db, IngestStagedEdge) == 0
    with db.session() as s:
        assert s.scalar(select(ImportJob.status)) == "failed"
        assert s.get(Snapshot, snap).status == "failed"


def test_edge_limit(tmp_path, db):
    settings = make_settings(tmp_path, max_graph_edges=10)
    svc = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe()))
    with pytest.raises(LimitExceededError, match="AEGIS_MAX_GRAPH_EDGES"):
        svc.import_file(svc.create_snapshot("s"), sharphound_zip(tmp_path / "c.zip"), "c.zip")
    assert count(db, AdEdge) == 0


def test_cancelled_import_rolls_back(tmp_path, service, db):
    token = CancellationToken()
    snap = service.create_snapshot("s")
    # Cancel as soon as data starts flowing (the user pressing "Cancel" mid-import).
    with pytest.raises(JobCancelledError):
        service.import_file(snap, sharphound_zip(tmp_path / "c.zip"), "c.zip", token=token,
                            progress=lambda fraction, message: token.cancel())
    assert count(db, AdObject) == 0
    with db.session() as s:
        assert s.scalar(select(ImportJob.status)) == "cancelled"


def test_failed_second_import_keeps_first_import_data(tmp_path, service, db):
    snap = service.create_snapshot("s")
    service.import_file(snap, sharphound_zip(tmp_path / "c.zip"), "c.zip")
    before = count(db, AdObject)
    with pytest.raises(UnsafeArchiveError):
        service.import_file(snap, write_zip(tmp_path / "bad.zip", {"../x.json": "{}"}), "bad.zip")
    assert count(db, AdObject) == before
    with db.session() as s:
        assert s.get(Snapshot, snap).status == "ready"


def test_low_disk_space_refuses_import(tmp_path, db):
    settings = make_settings(tmp_path, min_free_disk_mb=1024)
    svc = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe(disk_free_mb=500)))
    from app.core.errors import InsufficientResourcesError

    with pytest.raises(InsufficientResourcesError):
        svc.import_file(svc.create_snapshot("s"), sharphound_zip(tmp_path / "c.zip"), "c.zip")


def test_progress_is_reported(tmp_path, service):
    seen = []
    service.import_file(service.create_snapshot("s"), sharphound_zip(tmp_path / "c.zip"), "c.zip",
                        progress=lambda f, m: seen.append(f))
    assert seen and seen[-1] == 1.0 and all(0 <= f <= 1 for f in seen)


# ---------------------------------------------------------------- upload writer
def test_upload_writer_enforces_size_and_cleans_up(tmp_path):
    writer = UploadWriter(tmp_path / "up", "../../evil/../data.zip", max_bytes=10)
    assert writer.path.parent == tmp_path / "up" and writer.original_name == "data.zip"
    writer.write(b"12345")
    with pytest.raises(LimitExceededError):
        writer.write(b"678901")
    assert not writer.path.exists()

    ok = UploadWriter(tmp_path / "up", "users.json", max_bytes=100)
    ok.write(b"{}")
    saved = ok.finish()
    assert saved.size == 2 and len(saved.sha256) == 64 and saved.path.read_bytes() == b"{}"
    with pytest.raises(UnsupportedFormatError):
        UploadWriter(tmp_path / "up", "payload.exe", max_bytes=100)
