"""Stage 3.2: sample datasets import cleanly and their ground truth is independently verified.

The ground truth in sample_data/*/ground_truth.json was derived by hand (corp-small) or by
construction (corp-medium). These tests recompute it with the reference implementation in
tests/reference_paths.py from the *imported database*, so any mistake in the hand analysis, the
generator or the ingestion pipeline shows up here before the real engine is built.
"""

import importlib.util
import json
from collections import Counter

import pytest
from sqlalchemy import select

from app.core.config import REPO_ROOT
from app.db.session import Database
from app.ingestion.service import ImportService
from app.models import AdObject
from tests.reference_paths import RefGraph

SAMPLES = REPO_ROOT / "sample_data"


def truth(name: str) -> dict:
    return json.loads((SAMPLES / name / "ground_truth.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def imported(tmp_path_factory):
    """Import every dataset once (module scope keeps the medium dataset fast)."""
    from app.core.resources import ResourceManager
    from tests.conftest import FakeProbe, make_settings

    tmp = tmp_path_factory.mktemp("samples")
    settings = make_settings(tmp)
    db = Database(settings.database_url)
    db.migrate()
    service = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe()))
    results = {}
    for name in ("corp-small", "corp-small-v2", "corp-medium"):
        snap = service.create_snapshot(name, is_sample=True)
        results[name] = (snap, service.import_file(snap, SAMPLES / name / f"{name}.zip", f"{name}.zip"))
    yield db, results
    db.dispose()


def graph(imported, name) -> RefGraph:
    db, results = imported
    with db.session() as s:
        return RefGraph.load(s, results[name][0], truth(name)["conventions"]["traversable"])


# ------------------------------------------------------------------ import quality
@pytest.mark.parametrize("name", ["corp-small", "corp-small-v2", "corp-medium"])
def test_dataset_imports_cleanly(imported, name):
    _, results = imported
    result = results[name][1]
    assert result.status == "succeeded", result.summary["errors"][:5]
    assert result.summary["item_errors"] == 0
    expected_placeholders = len(truth(name).get("expected_placeholders", [])) if name == "corp-small" else None
    if expected_placeholders is not None:
        assert result.summary["placeholders_created"] == expected_placeholders


def test_sample_data_is_labelled_synthetic(imported):
    db, results = imported
    for name in ("corp-small", "corp-medium"):
        assert truth(name)["synthetic"] is True
        with db.session() as s:
            obj = s.scalar(select(AdObject).where(AdObject.snapshot_id == results[name][0], AdObject.kind == "User"))
        assert obj.properties["description"] == "AEGIS synthetic sample data"


# ------------------------------------------------------------------ corp-small: hand-derived truth
def test_corp_small_tier0_classification(imported):
    g, t = graph(imported, "corp-small"), truth("corp-small")
    assert sorted(g.names[i] for i in g.tier0 if i not in g.placeholder) == t["tier0"]
    for name in t["not_tier0"]:
        assert g.by_name[name] not in g.tier0


def test_corp_small_sources_and_shortest_hops(imported):
    g, t = graph(imported, "corp-small"), truth("corp-small")
    hops = {g.names[s]: h for s, h in g.shortest_hops().items()}
    assert hops == t["shortest_hops"]
    assert sorted(hops) == t["sources_with_paths"]
    no_path = {g.names[s] for s in g.sources()} - set(hops)
    assert sorted(no_path) == t["sources_without_paths"]
    assert g.by_name["ERIN@AEGISLAB.LOCAL"] not in g.sources()  # disabled


def test_corp_small_every_path_is_exactly_as_documented(imported):
    g, t = graph(imported, "corp-small"), truth("corp-small")
    found = sorted(g.named(path) for path in g.all_paths())
    expected = sorted(p["edges"] for p in t["all_paths"])
    assert found == expected
    for p in t["all_paths"]:
        assert len(p["edges"]) == p["hops"]
        assert g.classify(_ids(g, p["edges"])) == p["classification"], p["id"]


def _ids(g, named):
    return [(g.by_name[a], k, g.by_name[b]) for a, k, b in named]


def test_corp_small_choke_point(imported):
    g, t = graph(imported, "corp-small"), truth("corp-small")
    counts = Counter(tuple(e) for path in g.all_paths() for e in g.named(path))
    top_edge, top_count = counts.most_common(1)[0]
    assert list(top_edge) == t["choke_points"][0]["edge"] and top_count == t["choke_points"][0]["paths_through"]


def test_corp_small_min_cut(imported):
    g, t = graph(imported, "corp-small"), truth("corp-small")
    cut = g.edge_ids(t["min_cut"]["edges"])
    assert len(cut) == t["min_cut"]["size"]
    assert g.shortest_hops(removed=cut) == {}  # the cut disconnects every source
    # Lower bound: the witness paths are pairwise edge-disjoint, so no smaller cut exists (max-flow = min-cut).
    witness_ids = t["min_cut"]["edge_disjoint_witness_paths"]
    witnesses = [set(_ids(g, p["edges"])) for p in t["all_paths"] if p["id"] in witness_ids]
    assert len(witnesses) == t["min_cut"]["size"]
    for i, a in enumerate(witnesses):
        for b in witnesses[i + 1:]:
            assert not a & b
    # Uniqueness: dropping any single cut edge from the cut leaves some source exposed.
    for edge in cut:
        assert g.shortest_hops(removed=cut - {edge}) != {}


@pytest.mark.parametrize("index", [0, 1])
def test_corp_small_remediation_simulations(imported, index):
    g, t = graph(imported, "corp-small"), truth("corp-small")
    sim = t["simulations"][index]
    removed = g.edge_ids(sim["remove"])
    before, after = g.all_paths(), g.all_paths(removed=removed)
    assert (len(before), len(after)) == (sim["paths_before"], sim["paths_after"])
    exposed_before = {g.names[s] for s in g.shortest_hops()}
    exposed_after = {g.names[s] for s in g.shortest_hops(removed=removed)}
    assert sorted(exposed_after) == sim["sources_still_exposed"]
    assert sorted(exposed_before - exposed_after) == sim["sources_losing_all_paths"]


# ------------------------------------------------------------------ corp-small-v2: change ground truth
def test_corp_small_v2_paths(imported):
    g, t = graph(imported, "corp-small-v2"), truth("corp-small-v2")
    hops = {g.names[s]: h for s, h in g.shortest_hops().items()}
    assert hops == t["shortest_hops"]
    assert sorted({g.names[s] for s in g.sources()} - set(hops)) == t["sources_without_paths"]


def test_corp_small_v2_changes(imported):
    old, new, t = graph(imported, "corp-small"), graph(imported, "corp-small-v2"), truth("corp-small-v2")["changes"]

    def users(g):
        return {g.names[i] for i, k in g.kinds.items() if k in ("User", "ServiceAccount")}

    def named_edges(g, kinds=None):
        return {(g.names[s], k, g.names[d]) for s, k, d in g.edges if kinds is None or k in kinds}

    assert sorted(users(new) - users(old)) == t["new_users"]
    assert sorted(users(old) - users(new)) == t["removed_users"]
    member_old = {(a, b) for a, _, b in named_edges(old, {"MemberOf"})}
    member_new = {(a, b) for a, _, b in named_edges(new, {"MemberOf"})}
    primary = "DOMAIN USERS@AEGISLAB.LOCAL"  # primary-group membership comes and goes with the account
    added = member_new - member_old - {(u, primary) for u in t["new_users"]}
    removed = member_old - member_new - {(u, primary) for u in t["removed_users"]}
    assert sorted(map(list, added)) == sorted(t["membership_added"])
    assert sorted(map(list, removed)) == sorted(t["membership_removed"])
    non_member_old = named_edges(old) - {e for e in named_edges(old) if e[1] in ("MemberOf", "Contains", "CanRDP")}
    non_member_new = named_edges(new) - {e for e in named_edges(new) if e[1] in ("MemberOf", "Contains", "CanRDP")}
    assert sorted(map(list, non_member_new - non_member_old)) == sorted(t["relationships_added"])
    assert sorted(map(list, non_member_old - non_member_new)) == sorted(t["relationships_removed"])
    exposed_old = {old.names[s] for s in old.shortest_hops()}
    exposed_new = {new.names[s] for s in new.shortest_hops()}
    assert sorted(exposed_new - exposed_old) == t["sources_newly_exposed"]
    assert sorted(exposed_old - exposed_new) == t["sources_no_longer_exposed"]


# ------------------------------------------------------------------ corp-medium: truth by construction
def test_corp_medium_exactly_planted_sources_have_paths(imported):
    g, t = graph(imported, "corp-medium"), truth("corp-medium")
    hops = {g.names[s]: h for s, h in g.shortest_hops().items()}
    assert hops == t["shortest_hops"]
    assert len(hops) == t["sources_with_paths_count"]
    assert len(g.sources()) > 2500  # the noise population is really there


def test_corp_medium_planted_edges_exist_and_decoys_are_inert(imported):
    g, t = graph(imported, "corp-medium"), truth("corp-medium")
    for planted in t["planted_paths"]:
        assert set(_ids(g, planted["edges"])) <= g.edges, planted["id"]
        assert g.classify(_ids(g, planted["edges"])) == planted["classification"], planted["id"]
    hops = g.shortest_hops()
    for decoy in t["decoys"]:
        assert g.by_name[decoy["source"]] not in hops, decoy["id"]


# ------------------------------------------------------------------ inventory example + determinism
def test_inventory_example_imports(tmp_path, settings, resources):
    db = Database(settings.database_url)
    db.migrate()
    try:
        service = ImportService(db, settings, resources)
        snap = service.create_snapshot("inventory", is_sample=True)
        for fname in ("objects.csv", "relationships.csv", "inventory.json"):
            result = service.import_file(snap, SAMPLES / "inventory-example" / fname, fname)
            assert result.status == "succeeded", (fname, result.summary["errors"])
    finally:
        db.dispose()


def test_committed_sample_data_matches_generator(tmp_path):
    spec = importlib.util.spec_from_file_location("gen", REPO_ROOT / "scripts" / "generate_sample_data.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for path in gen.write_all(tmp_path):
        committed = SAMPLES / path.relative_to(tmp_path)
        assert committed.read_bytes() == path.read_bytes(), f"{committed} is stale: run scripts/generate_sample_data.py"
