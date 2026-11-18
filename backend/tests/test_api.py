"""Stage 5.1: the HTTP API end to end (upload -> import job -> analysis job -> paths -> graph -> dashboard)."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import REPO_ROOT
from tests.conftest import add_user, login, make_settings

SAMPLE = REPO_ROOT / "sample_data" / "corp-small" / "corp-small.zip"
TRUTH = json.loads((REPO_ROOT / "sample_data" / "corp-small" / "ground_truth.json").read_text(encoding="utf-8"))


def wait_job(client, job_id, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.fixture
def analyst(client):
    add_user(client, "analyst1", "analyst")
    client.headers["X-CSRF-Token"] = login(client, "analyst1")
    return client


def upload(client, snapshot_id, path=SAMPLE, name="corp-small.zip"):
    return client.post(f"/api/snapshots/{snapshot_id}/imports", params={"filename": name},
                       content=path.read_bytes(), headers={"Content-Type": "application/octet-stream"})


@pytest.fixture
def analysed(analyst):
    snap = analyst.post("/api/snapshots", json={"name": "Sample: corp-small", "is_sample": True}).json()["id"]
    job = wait_job(analyst, upload(analyst, snap).json()["job"]["id"])
    assert job["status"] == "succeeded", job
    job = wait_job(analyst, analyst.post(f"/api/snapshots/{snap}/analyses", json={"alternatives_per_source": 5})
                   .json()["job"]["id"])
    assert job["status"] == "succeeded", job
    return analyst, snap, job["result"]["analysis_id"]


# ------------------------------------------------------------------ full flow
def test_upload_import_and_snapshot_detail(analyst, settings):
    created = analyst.post("/api/snapshots", json={"name": "Lab", "is_sample": True})
    assert created.status_code == 201 and created.json()["status"] == "empty"
    snap = created.json()["id"]
    response = upload(analyst, snap)
    assert response.status_code == 202
    job = wait_job(analyst, response.json()["job"]["id"])
    assert job["status"] == "succeeded" and job["result"]["status"] == "succeeded"
    detail = analyst.get(f"/api/snapshots/{snap}").json()
    assert detail["status"] == "ready" and detail["stats"]["objects_by_kind"]["User"] >= 10
    assert detail["imports"][0]["filename"] == "corp-small.zip" and len(detail["imports"][0]["sha256"]) == 64
    assert list((settings.data_dir / "uploads").iterdir()) == []  # raw upload deleted after import
    listing = analyst.get("/api/snapshots").json()
    assert listing["total"] == 1 and listing["items"][0]["is_sample"] is True


def test_identity_explorer(analysed):
    client, snap, _ = analysed
    found = client.get(f"/api/snapshots/{snap}/objects", params={"q": "alice"}).json()
    assert found["total"] == 1 and found["items"][0]["name"] == "ALICE@AEGISLAB.LOCAL"
    tier0 = client.get(f"/api/snapshots/{snap}/objects", params={"tier0": True, "limit": 100}).json()
    assert sorted(o["name"] for o in tier0["items"] if not o["placeholder"]) == TRUTH["tier0"]
    assert client.get(f"/api/snapshots/{snap}/objects", params={"q": "%"}).json()["total"] == 0  # LIKE escaped
    alice = found["items"][0]["id"]
    detail = client.get(f"/api/objects/{alice}").json()
    assert detail["relationship_counts"]["outgoing"] >= 3 and "description" in detail["properties"]
    rels = client.get(f"/api/objects/{alice}/relationships", params={"direction": "out"}).json()
    kinds = {r["kind"] for r in rels["items"]}
    assert {"GenericAll", "ForceChangePassword", "MemberOf"} <= kinds
    assert all(r["evidence"]["source_file"] for r in rels["items"])
    assert client.get(f"/api/objects/{alice}/relationships", params={"direction": "sideways"}).status_code == 422


def test_analysis_results_paths_evidence_and_validation(analysed):
    client, snap, analysis_id = analysed
    analysis = client.get(f"/api/analyses/{analysis_id}").json()
    assert analysis["status"] == "succeeded" and analysis["paths_total"] == 8
    assert analysis["summary"]["min_cut"]["size"] == 4
    assert client.get(f"/api/snapshots/{snap}/analyses").json()["total"] == 1

    page = client.get(f"/api/analyses/{analysis_id}/paths", params={"limit": 3}).json()
    assert page["total"] == 8 and [p["score"] for p in page["items"]] == sorted(
        (p["score"] for p in page["items"]), reverse=True)
    critical = client.get(f"/api/analyses/{analysis_id}/paths", params={"severity": "Critical"}).json()
    assert critical["total"] == 2
    assert client.get(f"/api/analyses/{analysis_id}/paths", params={"severity": "Huge"}).status_code == 422

    bob = next(p for p in client.get(f"/api/analyses/{analysis_id}/paths").json()["items"]
               if p["source"]["name"] == "BOB@AEGISLAB.LOCAL")
    full = client.get(f"/api/paths/{bob['id']}").json()
    assert len(full["steps"]) == 3 and full["conditions"] and full["score_breakdown"]["factors"]
    evidence = client.get(f"/api/paths/{bob['id']}/evidence").json()["steps"]
    assert [s["step"] for s in evidence] == ["MemberOf", "AdminTo", "HasSession"]
    assert evidence[2]["records"][0]["data_source"] == "bloodhound:sessions"
    graph = client.get(f"/api/paths/{bob['id']}/graph").json()["elements"]
    assert len(graph["nodes"]) == 4 and [e["data"]["step"] for e in graph["edges"]] == [1, 2, 3]

    validated = client.post(f"/api/paths/{bob['id']}/validate", json={"note": "Confirmed in lab"}).json()
    assert validated["classification"] == "validated_security_exposure" and validated["score"] > bob["score"]


def test_dcsync_evidence_shows_both_replication_rights(analysed, tmp_path):
    client, snap, analysis_id = analysed
    # Engine-level: REPL-SVC is tier-0 itself, so check the derived edge through the neighbourhood view.
    repl = client.get(f"/api/snapshots/{snap}/objects", params={"q": "REPL-SVC"}).json()["items"][0]["id"]
    hood = client.get(f"/api/snapshots/{snap}/graph/neighborhood", params={"node": repl}).json()
    kinds = {e["data"]["kind"] for e in hood["elements"]["edges"]}
    assert {"DCSync", "GetChanges", "GetChangesAll", "MemberOf"} <= kinds


def test_neighborhood_is_capped_and_filterable(analysed, client):
    client_, snap, _ = analysed
    client_.app.state.settings.ui_max_elements = 50  # pydantic settings are mutable
    domain = client_.get(f"/api/snapshots/{snap}/objects", params={"kind": "Domain"}).json()["items"][0]["id"]
    hood = client_.get(f"/api/snapshots/{snap}/graph/neighborhood", params={"node": domain, "depth": 3}).json()
    assert hood["truncated"] is True
    assert len(hood["elements"]["nodes"]) + len(hood["elements"]["edges"]) <= 50
    nodes = {n["data"]["id"] for n in hood["elements"]["nodes"]}
    assert all(e["data"]["source"] in nodes and e["data"]["target"] in nodes for e in hood["elements"]["edges"])
    only = client_.get(f"/api/snapshots/{snap}/graph/neighborhood",
                       params={"node": domain, "traversable_only": True}).json()
    assert all(e["data"]["traversable"] for e in only["elements"]["edges"])
    assert client_.get(f"/api/snapshots/{snap}/graph/neighborhood", params={"node": 999999}).status_code == 404


def test_dashboard_is_computed_from_data(analysed):
    client, snap, _ = analysed
    d = client.get("/api/dashboard").json()
    assert d["snapshot"]["id"] == snap
    assert d["stats"]["users"] == 16 and d["stats"]["groups"] == 15 and d["stats"]["computers"] == 4
    assert d["stats"]["privileged_accounts"] == 5  # ADMINISTRATOR, KRBTGT, DA_JOHN, SVC_BACKUP, SVC_REPL
    assert d["findings"] == {"attack_paths": 8, "critical_paths": 2, "high_risk_relationships":
                             d["findings"]["high_risk_relationships"], "unresolved_findings": 8,
                             "exposed_identities": 6}
    assert d["findings"]["high_risk_relationships"] > 0
    assert d["analysis"]["environment_risk"]["score"] == pytest.approx(74.88, abs=0.01)


def test_dashboard_without_data(viewer_client):
    assert viewer_client.get("/api/dashboard").json() == {"snapshot": None, "stats": None, "analysis": None}


def test_settings_endpoints(analysed):
    client, snap, _ = analysed
    current = client.get("/api/settings/analysis").json()
    assert "domain_admins" in current["categories"]
    assert client.put("/api/settings/analysis", json=current["config"]).status_code == 403  # analyst
    add_user(client, "boss", "admin")
    client.headers["X-CSRF-Token"] = login(client, "boss")
    cfg = current["config"] | {"tier0_categories": [c for c in current["categories"] if c != "operators"]}
    assert client.put("/api/settings/analysis", json=cfg).status_code == 200
    assert client.put("/api/settings/analysis", json=cfg | {"tier0_categories": ["nope"]}).status_code == 422
    risk = client.get("/api/settings/risk").json()["config"]
    assert client.put("/api/settings/risk", json=risk | {"hop_decay": 0.9}).status_code == 200
    assert client.put("/api/settings/risk", json=risk | {"bands": {"Critical": 10, "High": 20, "Medium": 5}}
                      ).status_code == 422
    # new analysis reflects the changed tier-0 categories
    job = client.post(f"/api/snapshots/{snap}/analyses").json()["job"]["id"]
    result = wait_job(client, job)
    paths = client.get(f"/api/analyses/{result['result']['analysis_id']}/paths").json()
    assert all("SVC_BACKUP" not in p["target"]["name"] for p in paths["items"])
    actions = [e["action"] for e in client.get("/api/audit").json()["items"]]
    assert actions.count("settings_update") == 2 and "import_submit" in actions and "analysis_submit" in actions


# ------------------------------------------------------------------ authorisation and input safety
def test_viewer_is_read_only(analysed):
    client, snap, analysis_id = analysed
    add_user(client, "reader", "viewer")
    client.headers["X-CSRF-Token"] = login(client, "reader")
    assert client.get(f"/api/analyses/{analysis_id}/paths").status_code == 200
    assert client.post("/api/snapshots", json={"name": "x"}).status_code == 403
    assert upload(client, snap).status_code == 403
    assert client.post(f"/api/snapshots/{snap}/analyses").status_code == 403
    assert client.delete(f"/api/snapshots/{snap}").status_code == 403
    assert client.get("/api/settings/risk").status_code == 403


def test_upload_limits_and_validation(tmp_path, resources):
    from app.main import create_app

    settings = make_settings(tmp_path, max_upload_mb=1)
    with TestClient(create_app(settings, resources=resources)) as c:
        add_user(c, "analyst1", "analyst")
        c.headers["X-CSRF-Token"] = login(c, "analyst1")
        snap = c.post("/api/snapshots", json={"name": "s"}).json()["id"]
        big = c.post(f"/api/snapshots/{snap}/imports", params={"filename": "big.json"}, content=b"{" * (2 * 2**20))
        assert big.status_code == 413
        streamed = c.post(f"/api/snapshots/{snap}/imports", params={"filename": "big.json"},
                          content=iter([b"{" * 600_000, b"{" * 600_000]))  # chunked: no Content-Length
        assert streamed.status_code == 413
        assert c.post(f"/api/snapshots/{snap}/imports", params={"filename": "x.exe"}, content=b"MZ").status_code == 415
        assert c.post(f"/api/snapshots/{snap}/imports", params={"filename": "e.json"}, content=b"").status_code == 422
        assert c.post("/api/snapshots/999/imports", params={"filename": "a.json"}, content=b"{}").status_code == 404
        assert list((settings.data_dir / "uploads").iterdir()) == []  # nothing left behind
        bad = c.post(f"/api/snapshots/{snap}/imports", params={"filename": "../../evil.zip"},
                     content=(REPO_ROOT / "sample_data" / "corp-small" / "corp-small.zip").read_bytes())
        assert bad.status_code == 202  # name is reduced to its basename; stored under a random name
        assert wait_job(c, bad.json()["job"]["id"])["status"] == "succeeded"


def test_oversized_json_body_rejected(analyst):
    r = analyst.post("/api/snapshots", content=b'{"name": "' + b"a" * (2 * 2**20) + b'"}',
                     headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_analysis_requires_ready_snapshot_and_admin_can_delete(analyst):
    snap = analyst.post("/api/snapshots", json={"name": "empty"}).json()["id"]
    assert analyst.post(f"/api/snapshots/{snap}/analyses").status_code == 422
    add_user(analyst, "boss", "admin")
    analyst.headers["X-CSRF-Token"] = login(analyst, "boss")
    assert analyst.delete(f"/api/snapshots/{snap}").status_code == 200
    assert analyst.get(f"/api/snapshots/{snap}").status_code == 404


def test_failed_import_job_reports_safe_error(analyst):
    snap = analyst.post("/api/snapshots", json={"name": "s"}).json()["id"]
    evil = analyst.post(f"/api/snapshots/{snap}/imports", params={"filename": "x.zip"}, content=b"PK\x03\x04garbage")
    job = wait_job(analyst, evil.json()["job"]["id"])
    assert job["status"] == "failed" and job["error_code"] == "malformed_input"
    assert "Traceback" not in json.dumps(job)


def test_job_cancel_endpoint(analyst):
    def loop_until_cancelled(ctx):
        while True:
            ctx.token.checkpoint(every=1)
            time.sleep(0.01)

    job = analyst.app.state.jobs.submit("blocker", loop_until_cancelled)
    response = analyst.post(f"/api/jobs/{job.id}/cancel")
    assert response.status_code == 200
    assert wait_job(analyst, job.id)["status"] == "cancelled"
    assert analyst.get("/api/jobs").json()["items"][0]["id"] == job.id
    assert analyst.get("/api/jobs/nope").status_code == 404
