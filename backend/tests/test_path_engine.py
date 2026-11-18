"""Module 3: attack-path engine against hand-derived ground truth and independent oracles."""

import json
import random
import time

import networkx as nx
import pytest

from app.core.config import REPO_ROOT
from app.core.errors import JobCancelledError
from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.algorithms.alternatives import enumerate_paths, k_shortest_paths
from app.graph_engine.algorithms.centrality import betweenness
from app.graph_engine.algorithms.flow import min_edge_cut
from app.graph_engine.algorithms.index import TraversalIndex
from app.graph_engine.algorithms.shortest import path_length, reverse_shortest
from app.graph_engine.analysis import CONDITIONAL, DISCLAIMER, POTENTIAL, AnalysisParams, PathAnalyzer
from app.graph_engine.builder import GraphBuilder
from app.graph_engine.config import AnalysisConfig
from app.graph_engine.model import ADGraph
from app.ingestion.service import ImportService
from tests.conftest import FakeProbe, make_settings

SAMPLES = REPO_ROOT / "sample_data"
PARAMS = AnalysisParams(max_depth=10, alternatives_per_source=5)


def truth(name):
    return json.loads((SAMPLES / name / "ground_truth.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def graphs(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("paths"))
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings, probe=FakeProbe())
    svc = ImportService(db, settings, resources)
    built = {}
    for name in ("corp-small", "corp-small-v2", "corp-medium"):
        snap = svc.create_snapshot(name, is_sample=True)
        svc.import_file(snap, SAMPLES / name / f"{name}.zip", f"{name}.zip")
        built[name] = GraphBuilder(db, resources).build(snap)
    yield built
    db.dispose()


def run(graph, **kw):
    return PathAnalyzer(graph).run(kw.pop("params", PARAMS), token=CancellationToken(60), **kw)


def named(graph, path):
    return [[graph.name(s.src), s.kind, graph.name(s.dst)] for s in path.steps]


def by_name(graph):
    return {graph.name(n): n for n in graph.g}


def edge_refs(graph, named_edges):
    lookup = by_name(graph)
    refs = []
    for a, kind, b in named_edges:
        u, v = lookup[a], lookup[b]
        refs.append(next((u, v, k) for k, d in graph.g[u][v].items() if d["kind"] == kind))
    return refs


# ------------------------------------------------------------------ ground truth: corp-small
def test_shortest_hops_and_unexposed_sources(graphs):
    g, t = graphs["corp-small"], truth("corp-small")
    result = run(g)
    assert {g.name(s): h for s, (h, _) in result.exposure.items()} == t["shortest_hops"]
    unexposed = {g.name(s) for s in g.sources} - {g.name(s) for s in result.exposure}
    assert sorted(unexposed) == t["sources_without_paths"]


def test_every_documented_path_is_found_with_its_classification(graphs):
    g, t = graphs["corp-small"], truth("corp-small")
    result = run(g)
    found = {json.dumps(named(g, p)): p for p in result.paths}
    assert sorted(found) == sorted(json.dumps(p["edges"]) for p in t["all_paths"])
    for expected in t["all_paths"]:
        path = found[json.dumps(expected["edges"])]
        assert path.hops == expected["hops"] and path.classification == expected["classification"], expected["id"]


def test_shortest_path_per_source_is_marked(graphs):
    g, t = graphs["corp-small"], truth("corp-small")
    result = run(g)
    shortest = {g.name(p.source): p.hops for p in result.paths if p.shortest_for_source}
    assert shortest == t["shortest_hops"]


def test_path_explanations_conditions_and_signature(graphs):
    g = graphs["corp-small"]
    result = run(g)
    p6 = next(p for p in result.paths if g.name(p.source) == "GRACE@AEGISLAB.LOCAL")
    assert p6.classification == CONDITIONAL
    assert p6.summary.startswith("GRACE@AEGISLAB.LOCAL can reach DA_JOHN@AEGISLAB.LOCAL in 4 steps")
    assert "member of DOMAIN ADMINS" in p6.summary
    assert any("point-in-time" in c for c in p6.conditions)
    assert len(p6.narrative) == 4 + 2 and p6.narrative[-1] == DISCLAIMER
    assert "GRACE@AEGISLAB.LOCAL can modify SERVERS-POLICY@AEGISLAB.LOCAL" in p6.narrative[0]
    assert len(p6.signature) == 64
    p1 = next(p for p in result.paths if p.hops == 1 and g.name(p.source) == "ALICE@AEGISLAB.LOCAL")
    assert p1.classification == POTENTIAL and p1.conditions == []
    assert p1.confidence == pytest.approx(0.95)  # one ACL edge


def test_signature_is_stable_across_snapshots(graphs):
    old = {json.dumps(named(graphs["corp-small"], p)): p.signature for p in run(graphs["corp-small"]).paths}
    new = {json.dumps(named(graphs["corp-small-v2"], p)): p.signature for p in run(graphs["corp-small-v2"]).paths}
    common = old.keys() & new.keys()
    assert common and all(old[k] == new[k] for k in common)


def test_choke_point(graphs):
    g, t = graphs["corp-small"], truth("corp-small")
    top = run(g).choke_steps[0]
    expected = t["choke_points"][0]
    assert [top["src_name"], top["kinds"][0], top["dst_name"]] == expected["edge"]
    assert top["paths"] == expected["paths_through"]


def test_min_cut_matches_unique_ground_truth(graphs):
    g, t = graphs["corp-small"], truth("corp-small")
    cut = run(g).min_cut
    assert cut["size"] == t["min_cut"]["size"]
    found = sorted([s["src_name"], s["kinds"][0], s["dst_name"]] for s in cut["steps"])
    assert found == t["min_cut"]["edges"]


@pytest.mark.parametrize("index", [0, 1])
def test_remediation_simulations(graphs, index):
    g, sim = graphs["corp-small"], truth("corp-small")["simulations"][index]
    before = run(g)
    after = run(g, removed_edges=tuple(edge_refs(g, sim["remove"])))
    assert (len(before.paths), len(after.paths)) == (sim["paths_before"], sim["paths_after"])
    exposed_before = {g.name(s) for s in before.exposure}
    exposed_after = {g.name(s) for s in after.exposure}
    assert sorted(exposed_after) == sim["sources_still_exposed"]
    assert sorted(exposed_before - exposed_after) == sim["sources_losing_all_paths"]
    assert g.g.number_of_edges() > 0 and len(run(g).paths) == sim["paths_before"]  # base graph untouched


def test_disabling_an_identity_removes_its_paths(graphs):
    g = graphs["corp-small"]
    alice = by_name(g)["ALICE@AEGISLAB.LOCAL"]
    result = run(g, disabled_nodes=(alice,))
    assert alice not in result.exposure and all(p.source != alice for p in result.paths)


def test_multi_hop_discovery_between_chosen_objects(graphs):
    g = graphs["corp-small"]
    names = by_name(g)
    paths, truncated = PathAnalyzer(g).paths_between(names["BOB@AEGISLAB.LOCAL"], {names["SRV-APP01.AEGISLAB.LOCAL"]},
                                                     max_depth=6, limit=10, token=CancellationToken())
    assert not truncated and [named(g, p) for p in paths] == [
        [["BOB@AEGISLAB.LOCAL", "MemberOf", "HELPDESK@AEGISLAB.LOCAL"],
         ["HELPDESK@AEGISLAB.LOCAL", "AdminTo", "SRV-APP01.AEGISLAB.LOCAL"]]]
    everything, _ = PathAnalyzer(g).paths_between(names["ALICE@AEGISLAB.LOCAL"], set(g.tier0), max_depth=10,
                                                  limit=100, token=CancellationToken())
    assert [p.hops for p in everything] == [1, 3]


def test_parallel_edges_are_collapsed_with_alternatives(graphs):
    g = graphs["corp-small"]
    names = by_name(g)
    # REPL-SVC -> domain has GetChanges, GetChangesAll and the derived DCSync: only DCSync is traversable
    index = TraversalIndex(g)
    step = index.step(names["SRV-APP01.AEGISLAB.LOCAL"], names["DA_JOHN@AEGISLAB.LOCAL"])
    assert g.g[names["SRV-APP01.AEGISLAB.LOCAL"]][names["DA_JOHN@AEGISLAB.LOCAL"]][step.key]["kind"] == "HasSession"
    assert names["REPL-SVC@AEGISLAB.LOCAL"] not in index.succ  # tier-0 nodes have no outgoing steps


# ------------------------------------------------------------------ ground truth: v2 and corp-medium
def test_v2_hops(graphs):
    g = graphs["corp-small-v2"]
    assert {g.name(s): h for s, (h, _) in run(g).exposure.items()} == truth("corp-small-v2")["shortest_hops"]


def test_corp_medium_precision_and_planted_paths(graphs):
    g, t = graphs["corp-medium"], truth("corp-medium")
    started = time.perf_counter()
    result = run(g)
    elapsed = time.perf_counter() - started
    assert {g.name(s): h for s, (h, _) in result.exposure.items()} == t["shortest_hops"]
    shortest = {g.name(p.source): named(g, p) for p in result.paths if p.shortest_for_source}
    for planted in t["planted_paths"]:
        assert shortest[planted["source"]] == planted["edges"], planted["id"]
    for decoy in t["decoys"]:
        assert decoy["source"] not in shortest
    assert not result.truncated and elapsed < 30


# ------------------------------------------------------------------ limits and cancellation
def test_cancellation_and_depth_limit(graphs):
    token = CancellationToken()
    token.cancel()
    with pytest.raises(JobCancelledError):
        PathAnalyzer(graphs["corp-medium"]).run(PARAMS, token=token)
    shallow = run(graphs["corp-small"], params=AnalysisParams(max_depth=2, alternatives_per_source=5))
    assert all(p.hops <= 2 for p in shallow.paths)
    assert {graphs["corp-small"].name(s) for s in shallow.exposure} == {
        "ALICE@AEGISLAB.LOCAL", "IVAN@AEGISLAB.LOCAL", "SVC_SQL@AEGISLAB.LOCAL"}
    assert shallow.beyond_depth > 0


def test_params_never_exceed_admin_ceilings(tmp_path):
    settings = make_settings(tmp_path, max_path_depth=6, max_alternative_paths=2)
    params = AnalysisParams.from_settings(settings, max_depth=20, alternatives_per_source=10)
    assert (params.max_depth, params.alternatives_per_source) == (6, 2)


def test_max_paths_truncates(graphs):
    result = run(graphs["corp-small"], params=AnalysisParams(alternatives_per_source=5, max_paths=3))
    assert result.truncated and len(result.paths) == 3


# ------------------------------------------------------------------ property tests vs independent oracles
def random_graph(seed: int) -> ADGraph:
    rng = random.Random(seed)  # noqa: S311 - test data
    n = rng.randint(8, 14)
    g = nx.MultiDiGraph()
    for i in range(n):
        g.add_node(i, oid=f"N{i}", kind="User", name=f"N{i}", enabled=True, placeholder=False, tier0=False)
    key = 0
    for u in range(n):
        for v in range(n):
            if u != v and rng.random() < 0.22:
                for _ in range(rng.choice([1, 1, 1, 2])):  # occasional parallel edges
                    key += 1
                    g.add_edge(u, v, key=key, kind="GenericAll", t=rng.random() > 0.1, cond=False,
                               w=rng.choice([0.5, 1.0, 1.5, 2.0]), sev=0.9, conf=0.9)
    tier0 = frozenset(rng.sample(range(n), 2))
    return ADGraph(snapshot_id=0, version="r", config=AnalysisConfig(), g=g, tier0=tier0,
                   tier0_reasons={t: ["test"] for t in tier0}, sources=frozenset(set(range(n)) - tier0))


def oracle_digraph(index: TraversalIndex) -> nx.DiGraph:
    d = nx.DiGraph()
    d.add_nodes_from(index.graph.g.nodes)
    for u, row in index.succ.items():
        for v, step in row.items():
            d.add_edge(u, v, w=step.w)
    return d


def brute_force_paths(index, source):
    d = oracle_digraph(index)
    d.add_node("T")
    for t in index.tier0:
        d.add_edge(t, "T", w=0.0)
    paths = [p[:-1] for p in nx.all_simple_paths(d, source, "T")]
    return sorted(paths, key=lambda p: path_length(index, p))


@pytest.mark.parametrize("seed", range(40))
def test_algorithms_agree_with_oracles_on_random_graphs(seed):
    graph = random_graph(seed)
    index = TraversalIndex(graph)
    token = CancellationToken(30)
    dist = reverse_shortest(index, max_depth=25, token=token)
    for source in sorted(graph.sources):
        everything = brute_force_paths(index, source)
        if not everything:
            assert source not in dist.length
            continue
        assert dist.length[source] == path_length(index, everything[0])                 # optimal (hops, cost)
        yen = k_shortest_paths(index, source, k=4, max_depth=25, token=token)
        assert [path_length(index, p) for p in yen] == [path_length(index, p) for p in everything[:4]]
        assert len({tuple(p) for p in yen}) == len(yen)                                 # loopless & distinct
        enumerated, _ = enumerate_paths(index, source, set(graph.tier0), max_depth=25, limit=10_000, token=token)
        assert sorted(map(tuple, enumerated)) == sorted(map(tuple, everything))         # exhaustive

    exposed = {s for s in graph.sources if s in dist.length}
    cut = min_edge_cut(index, exposed, set(dist.length), token=token)
    flow_net = oracle_digraph(index)
    for s in exposed:
        flow_net.add_edge("S", s, capacity=float("inf"))
    for t in graph.tier0:
        flow_net.add_edge(t, "T", capacity=float("inf"))
    for u, v in list(flow_net.edges):
        flow_net[u][v].setdefault("capacity", 1)
    expected = nx.maximum_flow_value(flow_net, "S", "T") if exposed else 0
    assert cut.size == expected == len(cut.steps)
    removed = [(u, v, k) for u, v in cut.steps for k in index.step(u, v).keys]
    after = reverse_shortest(TraversalIndex(graph, removed_edges=removed), max_depth=25, token=token)
    assert not exposed & set(after.length)                                               # the cut disconnects

    relevant = set(dist.length)
    scores, sampled = betweenness(index, relevant, sample_size=1000, token=token)
    oracle = nx.betweenness_centrality(oracle_digraph(index).subgraph(relevant), normalized=False)
    assert not sampled and all(scores[n] == pytest.approx(oracle[n]) for n in relevant)


def test_sampled_betweenness_is_reproducible(graphs):
    g = graphs["corp-medium"]
    index = TraversalIndex(g)
    relevant = set(reverse_shortest(index, max_depth=10, token=CancellationToken()).length)
    a, sampled = betweenness(index, relevant, sample_size=20, token=CancellationToken())
    b, _ = betweenness(index, relevant, sample_size=20, token=CancellationToken())
    assert sampled and a == b
