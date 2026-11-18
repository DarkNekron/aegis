"""Background jobs, analyses, attack paths (with evidence) and graph views for the UI."""

from __future__ import annotations

from collections import deque
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.common import Analyst, Limit, Offset, Viewer, analysis_view, iso, path_view
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.jobs import JobContext, JobKind
from app.graph_engine.analysis import AnalysisParams
from app.models import AdEdge, AdObject, Analysis, AttackPath, Snapshot
from app.security.audit import audit
from app.security.deps import client_ip

router = APIRouter(prefix="/api", tags=["analysis"])


# ------------------------------------------------------------------ jobs
@router.get("/jobs")
def list_jobs(request: Request, viewer: Viewer) -> dict:
    return {"items": [j.public_view() for j in request.app.state.jobs.list()[:200]]}


@router.get("/jobs/{job_id}")
def get_job(job_id: str, request: Request, viewer: Viewer) -> dict:
    job = request.app.state.jobs.get(job_id)
    view = job.public_view()
    if job.status.value == "succeeded" and isinstance(job.result, dict):
        view["result"] = job.result  # small, JSON-safe summaries only
    return view


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, request: Request, analyst: Analyst) -> dict:
    job = request.app.state.jobs.cancel(job_id)
    audit(analyst.db, "job_cancel", "success", user_id=analyst.user.id, username=analyst.user.username,
          target_type="job", target_id=job_id, ip=client_ip(request), detail={"name": job.name})
    return job.public_view()


# ------------------------------------------------------------------ analyses
class AnalysisRequest(BaseModel):
    max_depth: int | None = Field(default=None, ge=1, le=25)
    alternatives_per_source: int | None = Field(default=None, ge=1, le=50)
    max_paths: int | None = Field(default=None, ge=1, le=1_000_000)


@router.post("/snapshots/{snapshot_id}/analyses", status_code=202)
def start_analysis(snapshot_id: int, request: Request, analyst: Analyst, body: AnalysisRequest | None = None) -> dict:
    state = request.app.state
    snap = analyst.db.get(Snapshot, snapshot_id)
    if snap is None:
        raise NotFoundError("Snapshot not found.")
    if snap.status != "ready":
        raise ValidationFailedError(f"The snapshot is '{snap.status}'; import data before analysing it.")
    overrides = (body.model_dump(exclude_none=True) if body else {})
    params = AnalysisParams.from_settings(state.settings, **overrides)
    stats = snap.stats or {}
    estimate = state.resources.estimate_graph_memory_mb(stats.get("objects_total", 0),
                                                        stats.get("relationships_total", 0))
    user_id = analyst.user.id

    def run(ctx: JobContext) -> dict:
        analysis_id = state.analyses.run(snapshot_id, params=params, token=ctx.token, created_by=user_id)
        return {"analysis_id": analysis_id}

    job = state.jobs.submit(f"Analyse snapshot {snapshot_id}", run, kind=JobKind.HEAVY, estimated_memory_mb=estimate)
    audit(analyst.db, "analysis_submit", "success", user_id=analyst.user.id, username=analyst.user.username,
          target_type="snapshot", target_id=snapshot_id, ip=client_ip(request),
          detail={"job": job.id, **params.model_dump()})
    return {"job": job.public_view()}


@router.get("/snapshots/{snapshot_id}/analyses")
def list_analyses(snapshot_id: int, viewer: Viewer, offset: Offset = 0, limit: Limit = 50) -> dict:
    cond = Analysis.snapshot_id == snapshot_id
    total = viewer.db.scalar(select(func.count()).select_from(Analysis).where(cond))
    rows = viewer.db.scalars(select(Analysis).where(cond).order_by(Analysis.id.desc()).offset(offset).limit(limit))
    return {"total": total, "items": [analysis_view(a) for a in rows]}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: int, request: Request, viewer: Viewer) -> dict:
    return analysis_view(request.app.state.analyses.get(analysis_id), full=True)


@router.get("/analyses/{analysis_id}/paths")
def list_paths(analysis_id: int, request: Request, viewer: Viewer, offset: Offset = 0, limit: Limit = 50,
               severity: Annotated[str | None, Query(max_length=16)] = None,
               classification: Annotated[str | None, Query(max_length=40)] = None,
               source: int | None = None, target: int | None = None) -> dict:
    total, rows = request.app.state.analyses.list_paths(analysis_id, offset=offset, limit=limit, severity=severity,
                                                        classification=classification, source_pk=source,
                                                        target_pk=target)
    return {"total": total, "items": [path_view(p) for p in rows]}


def _get_path(db, path_id: int) -> AttackPath:
    path = db.get(AttackPath, path_id)
    if path is None:
        raise NotFoundError("Attack path not found.")
    return path


@router.get("/paths/{path_id}")
def get_path(path_id: int, viewer: Viewer) -> dict:
    return path_view(_get_path(viewer.db, path_id), full=True)


@router.get("/paths/{path_id}/evidence")
def path_evidence(path_id: int, viewer: Viewer) -> dict:
    """Evidence for every step, read from the collected data (derived DCSync shows both replication rights)."""
    path = _get_path(viewer.db, path_id)
    out = []
    for step in (path.details or {}).get("steps", []):
        key = step["edge_key"]
        if isinstance(key, str) and key.startswith("dcsync:"):
            rows = viewer.db.scalars(select(AdEdge).where(
                AdEdge.src_object_pk == step["src"], AdEdge.dst_object_pk == step["dst"],
                AdEdge.kind.in_(["GetChanges", "GetChangesAll"]))).all()
            derived = True
        else:
            rows = [e for e in [viewer.db.get(AdEdge, key)] if e is not None]
            derived = False
        out.append({"step": step["kind"], "src": step["src"], "dst": step["dst"], "derived": derived, "records": [
            {"edge_id": e.id, "kind": e.kind, "data_source": e.data_source, "collected_at": iso(e.collected_at),
             "is_inherited": e.is_inherited, "confidence": e.confidence, "evidence": e.evidence} for e in rows]})
    return {"path_id": path_id, "steps": out}


class Validation(BaseModel):
    note: str = Field(min_length=3, max_length=500)


@router.post("/paths/{path_id}/validate")
def validate_path(path_id: int, body: Validation, request: Request, analyst: Analyst) -> dict:
    path = request.app.state.analyses.validate_path(path_id, analyst.user.id, body.note)
    audit(analyst.db, "path_validate", "success", user_id=analyst.user.id, username=analyst.user.username,
          target_type="attack_path", target_id=path_id, ip=client_ip(request),
          detail={"score": path.score, "severity": path.severity})
    return path_view(path, full=True)


# ------------------------------------------------------------------ graph views (Cytoscape elements)
def _node(n: int, data: dict[str, Any]) -> dict[str, Any]:
    return {"data": {"id": str(n), "label": data["name"], "kind": data["kind"], "tier0": bool(data["tier0"]),
                     "placeholder": bool(data["placeholder"]), "enabled": data["enabled"]}}


def _edge(u: int, v: int, k: Any, data: dict[str, Any]) -> dict[str, Any]:
    return {"data": {"id": f"e{k}", "source": str(u), "target": str(v), "kind": data["kind"],
                     "traversable": bool(data["t"]), "conditional": bool(data["cond"])}}


@router.get("/snapshots/{snapshot_id}/graph/neighborhood")
def neighborhood(snapshot_id: int, request: Request, viewer: Viewer, node: int,
                 depth: Annotated[int, Query(ge=1, le=3)] = 1, traversable_only: bool = False) -> dict:
    """The objects around ``node`` (both directions), capped at AEGIS_UI_MAX_ELEMENTS for the browser."""
    state = request.app.state
    graph = state.graphs.get(snapshot_id)
    g = graph.g
    if node not in g:
        raise NotFoundError("Object not found in this snapshot.")
    cap = state.settings.ui_max_elements
    seen, queue, edges, truncated = {node}, deque([(node, 0)]), {}, False
    while queue and not truncated:
        current, dist = queue.popleft()
        if dist == depth:
            continue
        incident = [(current, v, k, d) for v, kd in g.succ[current].items() for k, d in kd.items()] + \
                   [(u, current, k, d) for u, kd in g.pred[current].items() for k, d in kd.items()]
        for u, v, k, d in incident:
            if traversable_only and not d["t"]:
                continue
            other = v if u == current else u
            cost = 1 + (other not in seen)  # the edge, plus its far node if new
            if len(seen) + len(edges) + cost > cap:
                truncated = True
                break
            edges[(u, v, k)] = d
            if other not in seen:
                seen.add(other)
                queue.append((other, dist + 1))
    return {"center": node, "truncated": truncated, "limit": cap,
            "elements": {"nodes": [_node(n, g.nodes[n]) for n in seen],
                         "edges": [_edge(u, v, k, d) for (u, v, k), d in edges.items() if u in seen and v in seen]}}


@router.get("/paths/{path_id}/graph")
def path_graph(path_id: int, viewer: Viewer) -> dict:
    """Path subgraph built from stored details, so it renders even if the graph is not in memory."""
    details = _get_path(viewer.db, path_id).details or {}
    nodes = details.get("nodes", [])
    objects = {o.id: o for o in viewer.db.scalars(select(AdObject).where(AdObject.id.in_([n["id"] for n in nodes])))}
    return {"elements": {
        "nodes": [{"data": {"id": str(n["id"]), "label": n["name"], "kind": n["kind"], "tier0": n["tier0"],
                            "placeholder": bool((objects[n["id"]].properties or {}).get("aegis_placeholder"))
                            if n["id"] in objects else False, "enabled": None, "position": i}}
                  for i, n in enumerate(nodes)],
        "edges": [{"data": {"id": f"s{i}", "source": str(s["src"]), "target": str(s["dst"]), "kind": s["kind"],
                            "traversable": True, "conditional": s["conditional"], "step": i + 1,
                            "alternatives": s["alternatives"]}} for i, s in enumerate(details.get("steps", []))]}}
