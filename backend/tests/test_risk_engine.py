"""Module 4: transparent risk scoring, persistence of analyses and analyst validation."""

import json

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.core.config import REPO_ROOT
from app.core.errors import JobCancelledError, NotFoundError, ValidationFailedError
from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.analysis import CONDITIONAL, POTENTIAL, AnalysisParams, PathAnalyzer
from app.graph_engine.builder import GraphBuilder
from app.graph_engine.cache import GraphCache
from app.graph_engine.service import GraphService
from app.ingestion.service import ImportService
from app.models import Analysis, AttackPath
from app.risk_engine.config import DEFAULT_WEIGHTS, RiskConfig, load_risk_config, save_risk_config
from app.risk_engine.scoring import VALIDATED, RiskScorer
from app.services.analysis_service import AnalysisService
from tests.bh_builders import DOM, ace, bh_file, group, sid, user, write_json
from tests.conftest import FakeProbe, make_settings

SAMPLES = REPO_ROOT / "sample_data"
PARAMS = AnalysisParams(alternatives_per_source=5)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("risk"))
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings, probe=FakeProbe())
    svc = ImportService(db, settings, resources)
    snap = svc.create_snapshot("corp-small", is_sample=True)
    svc.import_file(snap, SAMPLES / "corp-small" / "corp-small.zip", "corp-small.zip")
    graph = GraphBuilder(db, resources).build(snap)
    yield {"db": db, "settings": settings, "resources": resources, "snap": snap, "graph": graph}
    db.dispose()


def scored(graph, config=None):
    result = PathAnalyzer(graph).run(PARAMS, token=CancellationToken())
    scorer = RiskScorer(config or RiskConfig())
    return result, scorer.score_analysis(graph, result), scorer


def by_source(graph, result, scores, name, hops):
    path = next(p for p in result.paths if graph.name(p.source) == name and p.hops == hops)
    return path, scores[path.signature]


# ------------------------------------------------------------------ the model itself
def test_documented_example_ivan_scores_exactly(env):
    """The worked example in docs/RISK_SCORING.md."""
    graph = env["graph"]
    result, scores, _ = scored(graph)
    _, s = by_source(graph, result, scores, "IVAN@AEGISLAB.LOCAL", 2)
    values = {k: v["value"] for k, v in s.breakdown.items()}
    assert values == pytest.approx({
        "destination_privilege": 1.0, "exploitability": 1.0, "proximity": 0.85,
        "relationship_severity": (0.6 + 0.95) / 2, "confidence": 0.95, "exposure": 0.2380,
        "alternatives": 0.0, "evidence_completeness": 1.0, "asset_criticality": 0.0}, abs=1e-4)
    assert s.score == pytest.approx(81.90, abs=0.01) and s.severity == "Critical" and not s.capped


def test_breakdown_is_complete_and_sums_to_the_score(env):
    result, scores, _ = scored(env["graph"])
    for s in scores.values():
        assert set(s.breakdown) == set(DEFAULT_WEIGHTS)
        assert sum(f["points"] for f in s.breakdown.values()) == pytest.approx(s.score, abs=0.05)
        assert all(f["why"] for f in s.breakdown.values())
        assert 0 <= s.score <= 100
    ranked = [scores[p.signature].score for p in result.paths]
    assert ranked == sorted(ranked, reverse=True)  # paths are ordered by risk


def test_not_everything_is_critical(env):
    _, scores, _ = scored(env["graph"])
    severities = [s.severity for s in scores.values()]
    assert severities.count("Critical") == 2 and severities.count("High") == 6


def test_conditional_paths_are_capped_until_validated(env):
    graph = env["graph"]
    lenient = RiskConfig(bands={"Critical": 50.0, "High": 30.0, "Medium": 10.0})
    result, scores, _ = scored(graph, lenient)
    for p in result.paths:
        s = scores[p.signature]
        if p.classification == CONDITIONAL:
            assert s.severity == "High" and s.capped
        else:
            assert s.severity == "Critical" and not s.capped


def test_weights_change_scores_transparently(env):
    graph = env["graph"]
    heavy = dict(DEFAULT_WEIGHTS) | {"exploitability": 3.0}
    result, scores, _ = scored(graph, RiskConfig(weights=heavy))
    top = [p.classification for p in result.paths[:3]]
    assert top == [POTENTIAL] * 3  # unconditional paths now dominate the ranking
    weights = next(iter(scores.values())).breakdown
    assert sum(weights[k]["weight"] for k in DEFAULT_WEIGHTS) == pytest.approx(1.0, abs=1e-3)


def test_proximity_decays_with_hops():
    cfg = RiskConfig()
    assert [round(cfg.hop_decay ** (h - 1), 4) for h in (1, 2, 3, 5)] == [1.0, 0.85, 0.7225, 0.522]


def test_asset_criticality_adds_points(env):
    graph = env["graph"]
    srv = next(n for n in graph.g if graph.name(n) == "SRV-APP01.AEGISLAB.LOCAL")
    plain_result, plain, _ = scored(graph)
    config = RiskConfig(asset_criticality={graph.g.nodes[srv]["oid"].lower(): 1.0})
    result, crit, _ = scored(graph, config)
    for p in result.paths:
        delta = crit[p.signature].score - plain[p.signature].score
        assert delta == pytest.approx(3.0 if srv in p.nodes else 0.0, abs=0.01)
        if srv in p.nodes:
            assert "SRV-APP01" in crit[p.signature].breakdown["asset_criticality"]["why"]


@pytest.mark.parametrize("bad", [
    {"weights": {"destination_privilege": 1.0}},
    {"weights": dict(DEFAULT_WEIGHTS) | {"proximity": -1}},
    {"bands": {"Critical": 50, "High": 60, "Medium": 40}},
    {"category_privilege": {"domain": 1.5}},
    {"conditional_max_severity": "Severe"},
    {"unexpected": 1},
])
def test_invalid_configuration_rejected(bad):
    with pytest.raises(ValidationError):
        RiskConfig(**bad)


def test_risk_config_persistence(env):
    with env["db"].session() as s:
        assert load_risk_config(s) == RiskConfig()
        save_risk_config(s, RiskConfig(hop_decay=0.9))
    with env["db"].session() as s:
        assert load_risk_config(s).hop_decay == 0.9
        save_risk_config(s, RiskConfig())


# ------------------------------------------------------------------ factor edge cases on purpose-built data
def test_multi_category_member_gets_highest_privilege_and_placeholder_penalty(tmp_path, settings, resources):
    db = Database(settings.database_url)
    db.migrate()
    try:
        svc = ImportService(db, settings, resources)
        snap = svc.create_snapshot("edge cases")
        backup_ops = "CORP.LOCAL-S-1-5-32-551"
        both = user(1150, "BOTH")
        lonely = user(1151, "LONELY")
        lonely["PrimaryGroupSID"] = sid(4444)  # group missing from the collection -> placeholder
        groups = [group(512, "DOMAIN ADMINS", members=[(sid(1150), "User")],
                        aces=[ace(sid(4444), "GenericAll", ptype="Group")]),
                  group(backup_ops, "BACKUP OPERATORS", members=[(sid(1150), "User")]),
                  group(513, "DOMAIN USERS")]
        svc.import_file(snap, write_json(tmp_path / "u.json", bh_file("users", [both, lonely])), "u.json")
        svc.import_file(snap, write_json(tmp_path / "g.json", bh_file("groups", groups)), "g.json")
        svc.import_file(snap, write_json(tmp_path / "d.json", bh_file("domains", [
            {"ObjectIdentifier": DOM, "Properties": {"name": "CORP.LOCAL"}, "Aces": []}])), "d.json")
        graph = GraphBuilder(db, resources).build(snap)
        both_node = next(n for n in graph.g if graph.name(n) == "BOTH@CORP.LOCAL")
        assert graph.tier0_categories[both_node] == {"domain_admins", "operators"}  # fixpoint, not first-reached

        result, scores, _ = scored(graph)
        path, s = by_source(graph, result, scores, "LONELY@CORP.LOCAL", 2)
        assert graph.g.nodes[path.nodes[1]]["placeholder"]
        assert s.breakdown["evidence_completeness"]["value"] == pytest.approx(2 / 3, abs=1e-3)
        assert "not collected" in s.breakdown["evidence_completeness"]["why"]
    finally:
        db.dispose()


# ------------------------------------------------------------------ persistence service
@pytest.fixture
def analyses(env):
    return AnalysisService(env["db"], env["settings"], GraphService(env["db"], env["resources"], GraphCache(1)))


def test_analysis_is_persisted_with_scored_paths(env, analyses):
    truth = json.loads((SAMPLES / "corp-small" / "ground_truth.json").read_text(encoding="utf-8"))
    analysis_id = analyses.run(env["snap"], params=PARAMS)
    analysis = analyses.get(analysis_id)
    assert analysis.status == "succeeded" and analysis.finished_at is not None
    summary = analysis.summary
    assert summary["paths_total"] == 8 and summary["exposed_sources"] == 6
    assert summary["paths_by_severity"] == {"Critical": 2, "High": 6, "Medium": 0, "Low": 0}
    assert summary["environment_risk"]["score"] == pytest.approx(84.17, abs=0.01)
    cut = sorted([c["src"]["name"], c["kinds"][0], c["dst"]["name"]] for c in summary["min_cut"]["steps"])
    assert cut == truth["min_cut"]["edges"]
    assert summary["choke_points"][0]["paths"] == 3
    assert all(t["object_id"] for t in summary["targets"])

    total, page = analyses.list_paths(analysis_id, limit=3)
    assert total == 8 and len(page) == 3 and page[0].score >= page[1].score >= page[2].score
    first = page[0]
    assert first.details["summary"].startswith("IVAN@AEGISLAB.LOCAL")
    assert first.details["narrative"][-1].startswith("Derived from collected directory data")
    assert first.score_breakdown["factors"]["destination_privilege"]["value"] == 1.0
    total_cond, _ = analyses.list_paths(analysis_id, classification=CONDITIONAL)
    total_high, _ = analyses.list_paths(analysis_id, severity="High")
    assert (total_cond, total_high) == (5, 6)
    _, rest = analyses.list_paths(analysis_id, offset=6, limit=10)
    assert len(rest) == 2


def test_validating_a_path_rescores_and_lifts_the_cap(env, analyses):
    analysis_id = analyses.run(env["snap"], params=PARAMS)
    _, rows = analyses.list_paths(analysis_id, limit=50)
    bob = next(p for p in rows if p.details["summary"].startswith("BOB@"))
    before = bob.score
    validated = analyses.validate_path(bob.id, user_id=None, note="Confirmed in the lab on 2026-11-18")
    weight = bob.score_breakdown["factors"]["exploitability"]["weight"]
    assert validated.classification == VALIDATED
    assert validated.score == pytest.approx(before + 100 * weight * (1 - 0.7), abs=0.02)
    assert validated.validated_at is not None
    assert validated.score_breakdown["factors"]["exploitability"]["why"] == "validated by an analyst"
    with pytest.raises(NotFoundError):
        analyses.validate_path(999_999, user_id=None)


def test_failures_are_recorded(env, analyses):
    with pytest.raises(NotFoundError):
        analyses.run(999_999)
    token = CancellationToken()
    token.cancel()
    analyses.graphs.cache.invalidate()
    with pytest.raises(JobCancelledError):
        analyses.run(env["snap"], token=token)
    with env["db"].session() as s:
        last = s.scalars(select(Analysis).order_by(Analysis.id.desc())).first()
        assert last.status == "cancelled" and "cancelled" in last.error
        assert s.scalar(select(func.count()).select_from(AttackPath).where(AttackPath.analysis_id == last.id)) == 0


def test_list_paths_validation(env, analyses):
    analysis_id = analyses.run(env["snap"], params=PARAMS)
    for kwargs in ({"limit": 0}, {"limit": 501}, {"offset": -1}, {"severity": "Severe"}):
        with pytest.raises(ValidationFailedError):
            analyses.list_paths(analysis_id, **kwargs)
    with pytest.raises(NotFoundError):
        analyses.list_paths(999_999)


def test_cli_analyze(tmp_path, monkeypatch, capsys):
    from app.cli import main
    from app.core.config import get_settings

    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "cli"))
    monkeypatch.setenv("AEGIS_ENV", "test")
    get_settings.cache_clear()
    try:
        assert main(["create-snapshot", "s", "--sample"]) == 0
        assert main(["import", "1", str(SAMPLES / "corp-small" / "corp-small.zip")]) == 0
        capsys.readouterr()
        assert main(["analyze", "1", "--top", "2"]) == 0
        out = capsys.readouterr().out
        assert "environment risk" in out and "Critical" in out and out.count("hop(s)") == 2
    finally:
        get_settings.cache_clear()
