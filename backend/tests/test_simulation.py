"""Module 6: remediation simulation against ground truth; the real graph and database stay untouched."""

import json
import time

import pytest
from sqlalchemy import func, select

from app.core.config import REPO_ROOT
from app.core.errors import ValidationFailedError
from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.analysis import AnalysisParams
from app.graph_engine.builder import GraphBuilder
from app.ingestion.service import ImportService
from app.models import AdEdge, AdObject
from app.risk_engine.config import RiskConfig
from app.risk_engine.scoring import RiskScorer
from app.simulation.engine import SimulationRequest, Simulator
from tests.conftest import FakeProbe, add_user, login, make_settings

SAMPLE = REPO_ROOT / "sample_data" / "corp-small" / "corp-small.zip"
TRUTH = json.loads((REPO_ROOT / "sample_data" / "corp-small" / "ground_truth.json").read_text(encoding="utf-8"))
PARAMS = AnalysisParams(alternatives_per_source=5)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("sim"))
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings, probe=FakeProbe())
    svc = ImportService(db, settings, resources)
    snap = svc.create_snapshot("corp-small", is_sample=True)
    svc.import_file(snap, SAMPLE, "corp-small.zip")
    graph = GraphBuilder(db, resources).build(snap)
    yield db, graph
    db.dispose()


def simulate(graph, *actions):
    request = SimulationRequest.model_validate({"actions": list(actions)})
    return Simulator(graph, RiskScorer(RiskConfig()), PARAMS).run(request.actions, token=CancellationToken())


def node(graph, name):
    return next(n for n in graph.g if graph.name(n) == f"{name}@AEGISLAB.LOCAL"
                or graph.name(n) == f"{name}.AEGISLAB.LOCAL")


def names(objs):
    return sorted(o["name"] for o in objs)


# ------------------------------------------------------------------ ground truth simulations
def test_removing_the_domain_admin_session(env):
    _, graph = env
    expected = TRUTH["simulations"][0]
    r = simulate(graph, {"type": "remove_session", "user": node(graph, "DA_JOHN"),
                         "computer": node(graph, "SRV-APP01")})
    assert (r["paths_before"], r["paths_after"]) == (expected["paths_before"], expected["paths_after"])
    assert names(r["identities_secured"]) == expected["sources_losing_all_paths"]
    assert names(r["identities_still_exposed"]) == expected["sources_still_exposed"]
    assert r["paths_eliminated"] == 3 and r["removed_relationships"] == 1
    assert r["environment_risk_after"]["score"] < r["environment_risk_before"]["score"]


def test_removing_the_writedacl_acl(env):
    _, graph = env
    expected = TRUTH["simulations"][1]
    r = simulate(graph, {"type": "remove_acl", "principal": node(graph, "IT-ADMINS"),
                         "target": node(graph, "DOMAIN ADMINS"), "kinds": ["WriteDacl"]})
    assert (r["paths_before"], r["paths_after"]) == (expected["paths_before"], expected["paths_after"])
    assert names(r["identities_secured"]) == expected["sources_losing_all_paths"]
    assert r["severity_before"]["Critical"] == 2 and r["severity_after"]["Critical"] == 0  # both Critical paths gone


def test_applying_the_minimum_cut_eliminates_every_path(env):
    _, graph = env
    r = simulate(graph, {"type": "apply_min_cut"})
    assert r["paths_after"] == 0 and r["exposed_after"] == 0 and r["removed_relationships"] == 4
    assert r["environment_risk_after"]["score"] == 0.0
    assert r["environment_risk_change"] == pytest.approx(-r["environment_risk_before"]["score"])
    assert r["tier0_still_reachable"] == []


# ------------------------------------------------------------------ every action type
def test_disabling_an_identity(env):
    _, graph = env
    r = simulate(graph, {"type": "disable_identity", "object": node(graph, "ALICE")})
    assert names(r["identities_secured"]) == ["ALICE@AEGISLAB.LOCAL"] and r["paths_after"] == 6
    assert r["actions"][0]["object"]["name"] == "ALICE@AEGISLAB.LOCAL"


def test_removing_a_membership_and_admin_right(env):
    _, graph = env
    r = simulate(graph, {"type": "remove_membership", "member": node(graph, "BOB"), "group": node(graph, "HELPDESK")})
    assert names(r["identities_secured"]) == ["BOB@AEGISLAB.LOCAL"]
    r = simulate(graph, {"type": "remove_admin", "principal": node(graph, "HELPDESK"),
                         "computer": node(graph, "SRV-APP01")})
    secured = names(r["identities_secured"])
    assert secured == ["BOB@AEGISLAB.LOCAL"]  # ALICE keeps her 1-hop path; GRACE still reaches SRV-APP01 via GPO
    remaining_alice = [p for p in r["remaining"] if p["source"]["name"] == "ALICE@AEGISLAB.LOCAL"]
    assert [p["hops"] for p in remaining_alice] == [1]


def test_removing_all_sessions_of_a_user_and_a_whole_step(env):
    _, graph = env
    everywhere = simulate(graph, {"type": "remove_session", "user": node(graph, "DA_JOHN")})
    assert everywhere["paths_after"] == 5
    step = simulate(graph, {"type": "remove_step", "src": node(graph, "ALICE"), "dst": node(graph, "SVC_BACKUP")})
    assert step["paths_after"] == 7


def test_remove_relationship_by_key_and_combined_actions(env):
    _, graph = env
    ivan, it_admins = node(graph, "IVAN"), node(graph, "IT-ADMINS")
    key = next(k for k, d in graph.g[ivan][it_admins].items() if d["kind"] == "MemberOf")
    r = simulate(graph, {"type": "remove_relationship", "edge_key": key},
                 {"type": "disable_identity", "object": node(graph, "SVC_SQL")})
    assert names(r["identities_secured"]) == ["IVAN@AEGISLAB.LOCAL", "SVC_SQL@AEGISLAB.LOCAL"]
    assert r["removed_relationships"] == 1 and r["disabled_identities"] == 1


@pytest.mark.parametrize("action,message", [
    ({"type": "remove_membership", "member": 999999, "group": 1}, "does not exist"),
    ({"type": "remove_relationship", "edge_key": 999999}, "does not exist"),
    ({"type": "remove_session", "user": "ALICE"}, "no recorded sessions"),
    ({"type": "remove_admin", "principal": "ALICE", "computer": "SRV-APP01"}, "No AdminTo relationship"),
])
def test_invalid_actions_are_rejected(env, action, message):
    _, graph = env
    action = {k: (node(graph, v) if isinstance(v, str) and k not in ("type",) else v) for k, v in action.items()}
    with pytest.raises(ValidationFailedError, match=message):
        simulate(graph, action)


def test_unknown_action_type_rejected_by_schema():
    with pytest.raises(ValueError):
        SimulationRequest.model_validate({"actions": [{"type": "delete_domain"}]})
    with pytest.raises(ValueError):
        SimulationRequest.model_validate({"actions": []})


def test_simulation_never_modifies_graph_or_database(env):
    db, graph = env
    edges_before, nodes_before = graph.g.number_of_edges(), graph.g.number_of_nodes()
    with db.session() as s:
        db_edges = s.scalar(select(func.count()).select_from(AdEdge))
        db_objects = s.scalar(select(func.count()).select_from(AdObject))
    simulate(graph, {"type": "apply_min_cut"}, {"type": "disable_identity", "object": node(graph, "CAROL")})
    assert (graph.g.number_of_edges(), graph.g.number_of_nodes()) == (edges_before, nodes_before)
    with db.session() as s:
        assert s.scalar(select(func.count()).select_from(AdEdge)) == db_edges
        assert s.scalar(select(func.count()).select_from(AdObject)) == db_objects
    assert simulate(graph, {"type": "remove_step", "src": node(graph, "ALICE"),
                            "dst": node(graph, "SVC_BACKUP")})["paths_before"] == 8  # baseline intact


# ------------------------------------------------------------------ API
def wait_job(client, job_id):
    for _ in range(600):
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_simulation_api(client):
    add_user(client, "analyst1", "analyst")
    client.headers["X-CSRF-Token"] = login(client, "analyst1")
    snap = client.post("/api/snapshots", json={"name": "s", "is_sample": True}).json()["id"]
    upload = client.post(f"/api/snapshots/{snap}/imports", params={"filename": "c.zip"}, content=SAMPLE.read_bytes())
    assert wait_job(client, upload.json()["job"]["id"])["status"] == "succeeded"
    job = wait_job(client, client.post(f"/api/snapshots/{snap}/analyses", json={"alternatives_per_source": 5})
                   .json()["job"]["id"])
    analysis_id = job["result"]["analysis_id"]

    response = client.post(f"/api/analyses/{analysis_id}/simulations", json={"actions": [{"type": "apply_min_cut"}]})
    assert response.status_code == 202
    sim_job = wait_job(client, response.json()["job"]["id"])
    assert sim_job["status"] == "succeeded"
    sim = client.get(f"/api/simulations/{sim_job['result']['simulation_id']}").json()
    assert sim["result"]["paths_after"] == 0 and sim["result"]["baseline_is_current"] is True
    assert client.get(f"/api/analyses/{analysis_id}/simulations").json()["total"] == 1

    bad = client.post(f"/api/analyses/{analysis_id}/simulations",
                      json={"actions": [{"type": "remove_membership", "member": 999999, "group": 1}]})
    failed = wait_job(client, bad.json()["job"]["id"])
    assert failed["status"] == "failed" and failed["error_code"] == "validation_failed"
    assert client.post("/api/analyses/999/simulations", json={"actions": [{"type": "apply_min_cut"}]}
                       ).status_code == 404
    assert client.post(f"/api/analyses/{analysis_id}/simulations", json={"actions": [{"type": "nuke"}]}
                       ).status_code == 422

    add_user(client, "reader", "viewer")
    client.headers["X-CSRF-Token"] = login(client, "reader")
    assert client.post(f"/api/analyses/{analysis_id}/simulations",
                       json={"actions": [{"type": "apply_min_cut"}]}).status_code == 403
    assert client.get(f"/api/analyses/{analysis_id}/simulations").status_code == 200


def test_environment_risk_never_increases_when_any_relationship_is_removed(env):
    """Property: remediation can only lower overall risk (guards against non-monotone metrics)."""
    _, graph = env
    baseline = simulate(graph, {"type": "apply_min_cut"})["environment_risk_before"]["score"]
    traversable = [(u, v, k) for u, v, k, d in graph.g.edges(keys=True, data=True)
                   if d["t"] and u not in graph.tier0 and isinstance(k, int)]
    assert len(traversable) > 20
    for _u, _v, key in traversable:
        after = simulate(graph, {"type": "remove_relationship", "edge_key": key})["environment_risk_after"]["score"]
        assert after <= baseline + 1e-9, key
