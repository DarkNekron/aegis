"""Module 2: rules table, tier-0 classification, graph construction, views and caching."""

import json
import threading
from collections import deque

import pytest
from sqlalchemy import select

from app.core.config import REPO_ROOT
from app.core.errors import InsufficientResourcesError, JobCancelledError, LimitExceededError
from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.builder import GraphBuilder
from app.graph_engine.cache import GraphCache
from app.graph_engine.config import TIER0_CATEGORIES, AnalysisConfig, load_config, save_config
from app.graph_engine.rules import INFORMATIONAL, RULES, rule_for, traversable_kinds
from app.graph_engine.service import GraphService
from app.ingestion.service import ImportService
from app.models import AdObject
from tests.bh_builders import bh_file, group, user, write_json
from tests.conftest import FakeProbe, make_settings
from tests.reference_paths import RefGraph

SAMPLES = REPO_ROOT / "sample_data"


def truth(name):
    return json.loads((SAMPLES / name / "ground_truth.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("graph")
    settings = make_settings(tmp)
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings, probe=FakeProbe())
    svc = ImportService(db, settings, resources)
    snaps = {}
    for name in ("corp-small", "corp-small-v2", "corp-medium"):
        snaps[name] = svc.create_snapshot(name, is_sample=True)
        svc.import_file(snaps[name], SAMPLES / name / f"{name}.zip", f"{name}.zip")
    yield db, settings, resources, snaps
    db.dispose()


def build(env, name, **kw):
    db, _, resources, snaps = env
    return GraphBuilder(db, resources).build(snaps[name], **kw)


def names(graph, nodes):
    return sorted(graph.name(n) for n in nodes)


# ------------------------------------------------------------------ rules
def test_rules_cover_the_documented_conventions():
    conventions = truth("corp-small")["conventions"]
    assert set(conventions["traversable"]) == traversable_kinds()
    for kind in ("CanRDP", "CanPSRemote", "ExecuteDCOM", "TrustedBy", "GetChanges", "GetChangesAll"):
        assert not rule_for(kind, "Computer").traversable and not rule_for(kind, "Domain").traversable
        assert kind in INFORMATIONAL


@pytest.mark.parametrize("kind,target,traversable,conditional", [
    ("GenericWrite", "Group", True, False),          # write member attribute
    ("GenericWrite", "User", True, True),            # shadow creds / targeted kerberoast
    ("GenericWrite", "Computer", True, True),        # RBCD
    ("GenericWrite", "Domain", False, False),        # no direct escalation
    ("GenericAll", "Computer", True, True),
    ("GenericAll", "CertTemplate", False, False),    # ADCS rules not implemented yet: never guess
    ("WriteDacl", "Domain", True, False),
    ("AllExtendedRights", "Domain", True, False),    # includes replication rights
    ("AllExtendedRights", "Group", False, False),
    ("AddMember", "User", False, False),             # only meaningful on groups
    ("HasSession", "User", True, True),
    ("AdminTo", "Computer", True, False),
    ("MemberOf", "Unknown", False, False),           # unknown object type: cannot reason about it
    ("TotallyNewEdge", "User", False, False),        # unknown relationship type
])
def test_rule_resolution_depends_on_target_kind(kind, target, traversable, conditional):
    rule = rule_for(kind, target)
    assert (rule.traversable, rule.conditional) == (traversable, conditional)


def test_every_traversable_rule_explains_and_remediates():
    for kind, kind_rules in RULES.items():
        for rule in [kind_rules.default, *kind_rules.by_target.values()]:
            if rule.traversable:
                assert rule.technique and "{src}" in rule.explanation and "{dst}" in rule.explanation, kind
                assert rule.remediate("A", "B", kind) and "{" not in rule.remediate("A", "B", kind), kind
                assert rule.explain("A", "B").count("A") >= 1
                assert 0 < rule.severity <= 1 and rule.cost > 0


# ------------------------------------------------------------------ construction vs ground truth
@pytest.mark.parametrize("name", ["corp-small", "corp-small-v2", "corp-medium"])
def test_tier0_and_sources_match_reference(env, name):
    db, _, _, snaps = env
    graph = build(env, name)
    with db.session() as s:
        ref = RefGraph.load(s, snaps[name], truth(name)["conventions"]["traversable"])
    assert set(graph.tier0) == ref.tier0
    assert set(graph.sources) == ref.sources()


def test_corp_small_graph_shape_and_reasons(env):
    graph, t = build(env, "corp-small"), truth("corp-small")
    assert names(graph, [n for n in graph.tier0 if not graph.node(n)["placeholder"]]) == t["tier0"]
    reasons = {graph.name(n): "; ".join(r) for n, r in graph.tier0_reasons.items()}
    assert reasons["DA_JOHN@AEGISLAB.LOCAL"] == "member of DOMAIN ADMINS@AEGISLAB.LOCAL"
    assert "DCSync" in reasons["REPL-SVC@AEGISLAB.LOCAL"]
    assert reasons["SVC_REPL@AEGISLAB.LOCAL"] == "member of REPL-SVC@AEGISLAB.LOCAL"
    assert "domain admins" in reasons["DOMAIN ADMINS@AEGISLAB.LOCAL"]
    by_name = {graph.name(n): n for n in graph.g}
    assert by_name["HALF-REPL@AEGISLAB.LOCAL"] not in graph.tier0
    assert by_name["PARTNER.LOCAL"] not in graph.tier0 and graph.node(by_name["PARTNER.LOCAL"])["placeholder"]
    # derived DCSync edge for the holder of both rights only
    dcsync = [(graph.name(u), graph.name(v)) for u, v, k in graph.g.edges(keys=True) if k == f"dcsync:{u}:{v}"]
    assert dcsync == [("REPL-SVC@AEGISLAB.LOCAL", "AEGISLAB.LOCAL")]
    assert graph.stats.derived_edges == 1 and len(next(iter(graph.derived_evidence.values()))) == 2


def test_traversable_view_excludes_informational_edges(env):
    graph = build(env, "corp-small")
    view = graph.view()
    kinds = {d["kind"] for _, _, d in view.edges(data=True)}
    assert kinds.isdisjoint({"CanRDP", "TrustedBy", "GetChanges", "GetChangesAll"})
    assert {"MemberOf", "AdminTo", "HasSession", "DCSync", "GPLink", "Contains"} <= kinds


def bfs_hops(graph, view):
    """Plain reverse BFS on the engine's own view (sanity check before the real path engine)."""
    dist = dict.fromkeys(graph.tier0, 0)
    queue = deque(graph.tier0)
    while queue:
        node = queue.popleft()
        for pred in view.predecessors(node):
            if pred not in dist:
                dist[pred] = dist[node] + 1
                queue.append(pred)
    return {graph.name(s): dist[s] for s in graph.sources if s in dist}


@pytest.mark.parametrize("name", ["corp-small", "corp-small-v2", "corp-medium"])
def test_engine_graph_reproduces_ground_truth_hops(env, name):
    graph = build(env, name)
    assert bfs_hops(graph, graph.view()) == truth(name)["shortest_hops"]


def test_views_never_mutate_the_base_graph(env):
    graph = build(env, "corp-small")
    before = (graph.g.number_of_nodes(), graph.g.number_of_edges())
    by_name = {graph.name(n): n for n in graph.g}
    srv, john = by_name["SRV-APP01.AEGISLAB.LOCAL"], by_name["DA_JOHN@AEGISLAB.LOCAL"]
    session_key = next(k for k, d in graph.g[srv][john].items() if d["kind"] == "HasSession")
    view = graph.view(removed_edges=[(srv, john, session_key)], disabled_nodes=[by_name["ALICE@AEGISLAB.LOCAL"]])
    hops = bfs_hops(graph, view)
    assert "BOB@AEGISLAB.LOCAL" not in hops and "GRACE@AEGISLAB.LOCAL" not in hops  # lost the session path
    assert "ALICE@AEGISLAB.LOCAL" not in hops                                     # disabled: no outgoing edges
    assert hops["CAROL@AEGISLAB.LOCAL"] == 3
    assert (graph.g.number_of_nodes(), graph.g.number_of_edges()) == before
    assert graph.g.has_edge(srv, john, session_key)
    with pytest.raises(Exception):  # noqa: B017 - networkx views are frozen
        view.add_edge(1, 2)


def test_tier0_classification_is_persisted(env):
    db, _, _, snaps = env
    build(env, "corp-small")
    with db.session() as s:
        rows = s.execute(select(AdObject.name, AdObject.tier0_reason).where(
            AdObject.snapshot_id == snaps["corp-small"], AdObject.is_tier0.is_(True))).all()
    persisted = dict(rows)
    assert sorted(n for n in persisted if n != "PARTNER.LOCAL") == truth("corp-small")["tier0"]
    assert persisted["SVC_BACKUP@AEGISLAB.LOCAL"] == "member of BACKUP OPERATORS@AEGISLAB.LOCAL"


# ------------------------------------------------------------------ configuration
def test_disabling_a_category_changes_classification(env):
    config = AnalysisConfig(tier0_categories=[c for c in TIER0_CATEGORIES if c != "operators"])
    graph = build(env, "corp-small", config=config, persist_tier0=False)
    tier0 = names(graph, graph.tier0)
    assert "BACKUP OPERATORS@AEGISLAB.LOCAL" not in tier0 and "SVC_BACKUP@AEGISLAB.LOCAL" not in tier0
    assert "SVC_BACKUP@AEGISLAB.LOCAL" in names(graph, graph.sources)


def test_custom_tier0_object(env):
    db, _, _, snaps = env
    with db.session() as s:
        helpdesk_id = s.scalar(select(AdObject.object_id).where(
            AdObject.snapshot_id == snaps["corp-small"], AdObject.name == "HELPDESK@AEGISLAB.LOCAL"))
    graph = build(env, "corp-small", config=AnalysisConfig(custom_tier0_object_ids=[helpdesk_id.lower()]),
                  persist_tier0=False)
    tier0 = names(graph, graph.tier0)
    assert "HELPDESK@AEGISLAB.LOCAL" in tier0 and "BOB@AEGISLAB.LOCAL" in tier0  # BOB is a member


def test_imported_highvalue_hint_is_not_trusted_by_default(tmp_path, settings, resources):
    db = Database(settings.database_url)
    db.migrate()
    try:
        svc = ImportService(db, settings, resources)
        snap = svc.create_snapshot("hints")
        g = group(1300, "FINANCE")
        g["Properties"]["highvalue"] = True
        g["Members"] = [{"ObjectIdentifier": "S-1-5-21-1000-2000-3000-1101", "ObjectType": "User"}]
        svc.import_file(snap, write_json(tmp_path / "g.json", bh_file("groups", [g])), "g.json")
        svc.import_file(snap, write_json(tmp_path / "u.json", bh_file("users", [user(1101, "ALICE")])), "u.json")
        builder = GraphBuilder(db, resources)
        plain = builder.build(snap, persist_tier0=False)
        assert not any(plain.name(n).startswith("FINANCE") for n in plain.tier0)
        trusting = builder.build(snap, config=AnalysisConfig(trust_input_hints=True), persist_tier0=False)
        assert {"FINANCE@CORP.LOCAL", "ALICE@CORP.LOCAL"} <= set(names(trusting, trusting.tier0))
    finally:
        db.dispose()


def test_config_persistence_and_validation(env):
    db = env[0]
    with db.session() as s:
        assert load_config(s) == AnalysisConfig()
        save_config(s, AnalysisConfig(traverse_trusts=True, custom_tier0_object_ids=[" s-1-2 "]))
    with db.session() as s:
        cfg = load_config(s)
        assert cfg.traverse_trusts and cfg.custom_tier0_object_ids == ["S-1-2"]
        save_config(s, AnalysisConfig())
    with pytest.raises(ValueError):
        AnalysisConfig(tier0_categories=["domain", "made_up"])


def test_traverse_trusts_option(env):
    graph = build(env, "corp-small", config=AnalysisConfig(traverse_trusts=True), persist_tier0=False)
    trust = [d for _, _, d in graph.g.edges(data=True) if d["kind"] == "TrustedBy"]
    assert trust and all(d["t"] and d["cond"] for d in trust)


# ------------------------------------------------------------------ resource limits and cancellation
def test_graph_limits_and_low_memory(env, tmp_path):
    db, _, _, snaps = env
    small = make_settings(tmp_path, max_graph_nodes=10)
    with pytest.raises(LimitExceededError):
        GraphBuilder(db, ResourceManager(small, probe=FakeProbe())).build(snaps["corp-small"])
    low = make_settings(tmp_path, min_free_ram_mb=768)
    with pytest.raises(InsufficientResourcesError):
        GraphBuilder(db, ResourceManager(low, probe=FakeProbe(available_ram_mb=500))).build(snaps["corp-small"])


def test_build_is_cancellable(env):
    token = CancellationToken()
    token.cancel()
    with pytest.raises(JobCancelledError):
        build(env, "corp-medium", token=token)


# ------------------------------------------------------------------ cache
def test_cache_reuses_rebuilds_on_new_import_and_evicts(env, tmp_path):
    db, settings, resources, snaps = env
    service = GraphService(db, resources, GraphCache(capacity=1))
    first = service.get(snaps["corp-small"])
    assert service.get(snaps["corp-small"]) is first
    assert service.cache.stats()["builds"] == 1 and service.cache.stats()["hits"] >= 1

    service.get(snaps["corp-small-v2"])            # capacity 1: evicts corp-small
    assert service.cache.stats()["entries"] == 1
    assert service.get(snaps["corp-small"]) is not first

    svc = ImportService(db, settings, resources)
    extra = bh_file("users", [user(1999, "LATECOMER")])
    svc.import_file(snaps["corp-small"], write_json(tmp_path / "late.json", extra), "late.json")
    rebuilt = service.get(snaps["corp-small"])
    assert rebuilt.version != first.version
    assert any(rebuilt.name(n) == "LATECOMER@CORP.LOCAL" for n in rebuilt.g)


def test_concurrent_requests_build_once(env):
    db, _, resources, snaps = env
    cache = GraphCache(capacity=2)
    calls = []

    def slow_build():
        calls.append(1)
        return GraphBuilder(db, resources).build(snaps["corp-small"], persist_tier0=False)

    results = []
    threads = [threading.Thread(target=lambda: results.append(cache.get_or_build(snaps["corp-small"], "v1",
                                                                                 slow_build)))
               for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(calls) == 1 and len({id(r) for r in results}) == 1


def test_health_endpoint_reports_cache(client):
    assert client.get("/api/system/health").json()["graph_cache"]["capacity"] == 1
