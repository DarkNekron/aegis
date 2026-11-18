"""Module 7: historical comparison against the corp-small -> corp-small-v2 ground truth."""

import json

import pytest

from app.comparison.engine import SnapshotComparator
from app.core.config import REPO_ROOT
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.analysis import AnalysisParams
from app.graph_engine.cache import GraphCache
from app.graph_engine.service import GraphService
from app.ingestion.service import ImportService
from app.services.analysis_service import AnalysisService
from tests.conftest import FakeProbe, make_settings

SAMPLES = REPO_ROOT / "sample_data"
CHANGES = json.loads((SAMPLES / "corp-small-v2" / "ground_truth.json").read_text(encoding="utf-8"))["changes"]


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("cmp"))
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings, probe=FakeProbe())
    imports = ImportService(db, settings, resources)
    analyses = AnalysisService(db, settings, GraphService(db, resources, GraphCache(2)))
    ids = {}
    for name in ("corp-small", "corp-small-v2"):
        snap = imports.create_snapshot(name, is_sample=True)
        imports.import_file(snap, SAMPLES / name / f"{name}.zip", f"{name}.zip")
        ids[name] = (snap, analyses.run(snap, params=AnalysisParams(alternatives_per_source=5)))
    yield db, imports, ids
    db.dispose()


@pytest.fixture(scope="module")
def report(env):
    db, _, ids = env
    with db.session() as s:
        return SnapshotComparator(s).compare(ids["corp-small"][0], ids["corp-small-v2"][0])


def triples(category):
    return sorted([i["src"]["name"], i["kind"], i["dst"]["name"]] for i in category["items"])


def test_account_changes(report):
    assert report["objects"]["users_added"] == CHANGES["new_users"]
    assert report["objects"]["users_removed"] == CHANGES["removed_users"]
    assert report["objects"]["groups_added"] == [] and report["objects"]["groups_removed"] == []
    assert report["objects"]["changed"]["count"] == 0  # no renames or status changes


def test_membership_changes_exclude_implied_primary_groups(report):
    added = report["relationships"]["added"]["categories"]["memberships"]
    removed = report["relationships"]["removed"]["categories"]["memberships"]
    assert [[s, d] for s, _, d in triples(added)] == sorted(CHANGES["membership_added"])
    assert [[s, d] for s, _, d in triples(removed)] == sorted(CHANGES["membership_removed"])
    assert added["implied_by_account_changes"] == 1 and removed["implied_by_account_changes"] == 1


def test_acl_and_session_changes(report):
    added, removed = report["relationships"]["added"]["categories"], report["relationships"]["removed"]["categories"]
    assert triples(added["acl"]) == sorted(CHANGES["relationships_added"])
    removed_security = triples(removed["acl"]) + triples(removed["sessions"])
    assert sorted(removed_security) == sorted(CHANGES["relationships_removed"])
    assert "admin_rights" not in added and "admin_rights" not in removed


def test_attack_path_and_exposure_changes(report):
    paths = report["attack_paths"]
    assert paths["available"] is True
    assert paths["newly_exposed"] == CHANGES["sources_newly_exposed"]
    assert paths["no_longer_exposed"] == CHANGES["sources_no_longer_exposed"]
    assert paths["old_total"] == 8
    assert paths["resolved"]["count"] + paths["persisting"] == 8
    assert paths["appeared"]["count"] + paths["persisting"] == paths["new_total"]
    new_sources = {p["source"]["name"] for p in paths["appeared"]["items"]}
    assert {"DAVE@AEGISLAB.LOCAL", "BOB@AEGISLAB.LOCAL"} <= new_sources  # DAVE new; BOB moved to DEVOPS


def test_risk_change_and_summary(report):
    risk = report["risk"]
    assert risk["change"] == pytest.approx(risk["new"]["score"] - risk["old"]["score"], abs=0.01)
    text = " ".join(report["summary"])
    assert "1 new and 1 removed user account(s)" in text and "Newly exposed identities: DAVE@AEGISLAB.LOCAL" in text
    assert "Environment risk" in text
    assert report["privilege"] == {"newly_tier0": [], "no_longer_tier0": [], "reliable": True}


def test_reverse_comparison_is_symmetric(env, report):
    db, _, ids = env
    with db.session() as s:
        reverse = SnapshotComparator(s).compare(ids["corp-small-v2"][0], ids["corp-small"][0])
    assert reverse["objects"]["users_added"] == report["objects"]["users_removed"]
    assert reverse["relationships"]["added"]["count"] == report["relationships"]["removed"]["count"]
    assert reverse["attack_paths"]["newly_exposed"] == report["attack_paths"]["no_longer_exposed"]


def test_identical_snapshots_show_no_differences(env):
    db, imports, ids = env
    copy = imports.create_snapshot("corp-small copy")
    imports.import_file(copy, SAMPLES / "corp-small" / "corp-small.zip", "copy.zip")
    with db.session() as s:
        r = SnapshotComparator(s).compare(ids["corp-small"][0], copy)
    assert r["objects"]["added"]["count"] == r["objects"]["removed"]["count"] == 0
    assert r["relationships"]["added"]["count"] == r["relationships"]["removed"]["count"] == 0
    assert r["attack_paths"]["available"] is False  # the copy has no analysis yet
    assert r["privilege"]["reliable"] is False


def test_renamed_and_disabled_object_is_reported_as_changed(env, tmp_path):
    from tests.bh_builders import bh_file, user, write_json

    db, imports, _ = env
    a, b = imports.create_snapshot("a"), imports.create_snapshot("b")
    imports.import_file(a, write_json(tmp_path / "a.json", bh_file("users", [user(1101, "ALICE")])), "a.json")
    renamed = user(1101, "ALICE.SMITH")
    renamed["Properties"]["enabled"] = False
    imports.import_file(b, write_json(tmp_path / "b.json", bh_file("users", [renamed])), "b.json")
    with db.session() as s:
        r = SnapshotComparator(s).compare(a, b)
    assert r["objects"]["added"]["count"] == 0  # matched on SID, not name
    change = r["objects"]["changed"]["items"][0]["changes"]
    assert change["name"] == ["ALICE@CORP.LOCAL", "ALICE.SMITH@CORP.LOCAL"] and change["enabled"] == [True, False]


def test_invalid_requests(env):
    db, _, ids = env
    snap, analysis = ids["corp-small"]
    with db.session() as s:
        comparator = SnapshotComparator(s)
        with pytest.raises(ValidationFailedError):
            comparator.compare(snap, snap)
        with pytest.raises(NotFoundError):
            comparator.compare(snap, 99_999)
        with pytest.raises(ValidationFailedError, match="not a completed analysis"):
            comparator.compare(snap, ids["corp-small-v2"][0], new_analysis_id=analysis)  # wrong snapshot


def test_comparison_api(viewer_client):
    c = viewer_client
    assert c.get("/api/comparisons", params={"old_snapshot": 1, "new_snapshot": 2}).status_code == 404
    assert c.get("/api/comparisons", params={"old_snapshot": 1}).status_code == 422
