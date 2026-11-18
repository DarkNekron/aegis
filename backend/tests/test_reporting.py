"""Module 8: report data model, HTML/PDF rendering (incl. hostile names) and the report API."""

import hashlib
import json
import re
import time

import pytest

from app.core.config import REPO_ROOT
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.analysis import AnalysisParams
from app.graph_engine.cache import GraphCache
from app.graph_engine.service import GraphService
from app.ingestion.service import ImportService
from app.reporting import pdf as pdf_module
from app.reporting.html import render_html
from app.reporting.model import SECTIONS, ReportBuilder
from app.reporting.pdf import esc, render_pdf
from app.services.analysis_service import AnalysisService
from tests.bh_builders import ace, bh_file, group, sid, user, write_json
from tests.conftest import FakeProbe, add_user, login, make_settings

SAMPLES = REPO_ROOT / "sample_data"
HOSTILE = "<script>alert(1)</script><font size='60'>EVIL</font><img src='x'/>&amp;"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("rep")
    settings = make_settings(tmp)
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings, probe=FakeProbe())
    graphs = GraphService(db, resources, GraphCache(3))
    imports, analyses = ImportService(db, settings, resources), AnalysisService(db, settings, graphs)
    params = AnalysisParams(alternatives_per_source=5)
    out = {}
    for name in ("corp-small", "corp-small-v2"):
        snap = imports.create_snapshot(name, is_sample=True)
        imports.import_file(snap, SAMPLES / name / f"{name}.zip", f"{name}.zip")
        out[name] = (snap, analyses.run(snap, params=params))
    # a dataset whose only exposed user has a hostile name
    hostile = imports.create_snapshot("hostile")
    evil = user(1101, "X")
    evil["Properties"]["name"] = HOSTILE
    files = [("u.json", bh_file("users", [evil])),
             ("g.json", bh_file("groups", [group(512, "DOMAIN ADMINS", aces=[ace(sid(1101), "GenericAll")])]))]
    for fname, content in files:
        imports.import_file(hostile, write_json(tmp / fname, content), fname)
    out["hostile"] = (hostile, analyses.run(hostile, params=params))
    yield db, graphs, out
    db.dispose()


def build(env, name, **kw):
    db, graphs, out = env
    snap, analysis = out[name]
    with db.session() as s:
        return ReportBuilder(s).build(analysis, graph=graphs.get(snap), **kw)


def test_report_has_all_thirteen_sections_with_real_numbers(env):
    report = build(env, "corp-small", generated_by="analyst1")
    assert report["meta"]["sections"] == SECTIONS and len(SECTIONS) == 13
    for key in SECTIONS:
        assert report[key] is not None, key
    assert report["attack_paths"]["total"] == 8
    assert report["attack_paths"]["by_severity"] == {"Critical": 2, "High": 6, "Medium": 0, "Low": 0}
    assert report["privileged_exposure"]["exposed_identities"] == 6
    recommendations = report["recommendations"]
    assert recommendations["minimum_cut_size"] == 4 and len(recommendations["priority_actions"]) == 4
    sim = report["simulations"]["minimum_cut"]
    assert (sim["paths_before"], sim["paths_after"], sim["risk_after"]) == (8, 0, 0.0)
    assert report["meta"]["sample_data"] is True and report["meta"]["generated_by"] == "analyst1"
    assert any("6 of 9 enabled identities (66.7%)" in m for m in report["executive_summary"]["messages"])
    assert any("shortest route to tier-0 takes 1 step" in m for m in report["executive_summary"]["messages"])
    critical = report["critical_findings"]
    assert critical[0]["severity"] == "Critical" and critical[0]["score_breakdown"]
    evidence = report["technical_evidence"][0]["steps"][0]["records"][0]
    assert evidence["source_file"].endswith(".json") and evidence["data_source"].startswith("bloodhound:")
    json.dumps(report, default=str)  # the model is the JSON export


def test_remediation_actions_use_rule_text(env):
    actions = build(env, "corp-small")["recommendations"]["priority_actions"]
    session = next(a for a in actions if "HasSession" in a["relationship"])
    assert "Stop DA_JOHN@AEGISLAB.LOCAL logging on to SRV-APP01.AEGISLAB.LOCAL" in session["action"]


def test_change_section_when_comparing_with_previous_snapshot(env):
    _, _, out = env
    report = build(env, "corp-small-v2", previous_snapshot_id=out["corp-small"][0])
    assert report["meta"]["sections"][-2:] == ["changes", "conclusion"]
    assert any("Newly exposed identities: DAVE@AEGISLAB.LOCAL" in line for line in report["changes"]["summary"])


def test_html_report_is_complete_and_self_contained(env):
    html = render_html(build(env, "corp-small"))
    for title in ("Executive Summary", "Assessment Scope", "Methodology", "Environment Overview",
                  "Directory Statistics", "Privileged Identity Exposure", "Attack Path Analysis", "Critical Findings",
                  "Technical Evidence", "Risk Assessment", "Remediation Recommendations",
                  "Remediation Simulation Results", "Conclusion"):
        assert title in html
    assert "<script" not in html.lower() and "http://" not in html and "https://" not in html
    assert "Sample data." in html


def test_hostile_names_are_inert_in_html_and_pdf(env):
    report = build(env, "hostile")
    assert report["attack_paths"]["total"] == 1 and HOSTILE in report["attack_paths"]["paths"][0]["source"]
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img" not in html and "<font" not in html
    pdf = render_pdf(report)  # ReportLab markup in the name must not be interpreted or crash rendering
    assert pdf.startswith(b"%PDF") and len(pdf) > 10_000
    assert esc(HOSTILE).startswith("&lt;script&gt;") and "&amp;amp;" in esc(HOSTILE)


def test_pdf_report_renders(env):
    pdf = render_pdf(build(env, "corp-small-v2", previous_snapshot_id=env[2]["corp-small"][0]))
    assert pdf.startswith(b"%PDF") and pdf.rstrip().endswith(b"%%EOF")
    pages = len(re.findall(rb"/Type /Page[^s]", pdf))
    assert 8 <= pages <= 30, pages


def test_ascii_fallback_without_unicode_font(monkeypatch):
    monkeypatch.setattr(pdf_module, "UNICODE_FONTS", False)
    assert pdf_module.esc("A → B ≥ C — D") == "A -&gt; B &gt;= C - D"


def test_report_without_any_paths(env, tmp_path):
    db, graphs, _ = env
    settings = make_settings(tmp_path)
    imports = ImportService(db, settings, ResourceManager(settings, probe=FakeProbe()))
    snap = imports.create_snapshot("quiet")
    imports.import_file(snap, write_json(tmp_path / "u.json", bh_file("users", [user(1101, "ALICE")])), "u.json")
    analysis = AnalysisService(db, settings, graphs).run(snap)
    with db.session() as s:
        report = ReportBuilder(s).build(analysis, graph=graphs.get(snap))
    assert report["attack_paths"]["total"] == 0 and report["simulations"]["minimum_cut"] is None
    assert "No attack paths to tier-0" in " ".join(report["conclusion"])
    assert render_pdf(report).startswith(b"%PDF") and "No Critical or High findings" in render_html(report)


# ------------------------------------------------------------------ API
def wait_job(client, job_id):
    for _ in range(1200):
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_report_api_generate_list_download(client, settings):
    add_user(client, "analyst1", "analyst")
    client.headers["X-CSRF-Token"] = login(client, "analyst1")
    snap = client.post("/api/snapshots", json={"name": "Corp / Lab: Nov", "is_sample": True}).json()["id"]
    up = client.post(f"/api/snapshots/{snap}/imports", params={"filename": "c.zip"},
                     content=(SAMPLES / "corp-small" / "corp-small.zip").read_bytes())
    assert wait_job(client, up.json()["job"]["id"])["status"] == "succeeded"
    analysis = wait_job(client, client.post(f"/api/snapshots/{snap}/analyses").json()["job"]["id"])["result"][
        "analysis_id"]

    job = wait_job(client, client.post(f"/api/analyses/{analysis}/reports", json={}).json()["job"]["id"])
    assert job["status"] == "succeeded" and len(job["result"]["report_ids"]) == 3
    listing = client.get("/api/reports", params={"snapshot_id": snap}).json()
    assert listing["total"] == 3 and {r["format"] for r in listing["items"]} == {"pdf", "html", "json"}

    for item in listing["items"]:
        r = client.get(f"/api/reports/{item['id']}/download")
        assert r.status_code == 200
        disposition = r.headers["content-disposition"]
        assert disposition.startswith("attachment;") and "Corp-Lab-Nov" in disposition and "/" not in disposition
        assert hashlib.sha256(r.content).hexdigest() == item["sha256"] == r.headers["x-report-sha256"]
    assert client.post(f"/api/analyses/{analysis}/reports", json={"formats": ["docx"]}).status_code == 422
    assert client.post("/api/analyses/999/reports", json={}).status_code == 404

    # a tampered path can never escape the reports directory
    from app.models import Report

    with client.app.state.db.session() as s:
        s.get(Report, listing["items"][0]["id"]).path = "../aegis.db"
        s.commit()
    assert client.get(f"/api/reports/{listing['items'][0]['id']}/download").status_code == 404

    add_user(client, "reader", "viewer")
    client.headers["X-CSRF-Token"] = login(client, "reader")
    assert client.post(f"/api/analyses/{analysis}/reports", json={}).status_code == 403
    assert client.get(f"/api/reports/{listing['items'][1]['id']}/download").status_code == 200
