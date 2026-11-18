"""Analysis and risk configuration (read: analyst; change: administrator) and the dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import func, select

from app.api.common import Admin, Analyst, Viewer, analysis_view, snapshot_view
from app.core.errors import NotFoundError
from app.graph_engine.config import TIER0_CATEGORIES, AnalysisConfig, load_config, save_config
from app.models import AdObject, Analysis, AttackPath, Snapshot
from app.risk_engine.config import RiskConfig, load_risk_config, save_risk_config
from app.security.audit import audit
from app.security.deps import client_ip

router = APIRouter(prefix="/api", tags=["settings"])
HIGH_RISK_STEP_SEVERITY = 0.85


@router.get("/settings/analysis")
def get_analysis_settings(analyst: Analyst) -> dict:
    return {"config": load_config(analyst.db).model_dump(), "categories": TIER0_CATEGORIES}


@router.put("/settings/analysis")
def put_analysis_settings(body: AnalysisConfig, request: Request, admin: Admin) -> dict:
    save_config(admin.db, body, updated_by=admin.user.id)
    request.app.state.graphs.cache.invalidate()  # tier-0 and traversal depend on it
    audit(admin.db, "settings_update", "success", user_id=admin.user.id, username=admin.user.username,
          target_type="settings", target_id="analysis_config", ip=client_ip(request), detail=body.model_dump())
    return {"config": body.model_dump()}


@router.get("/settings/risk")
def get_risk_settings(analyst: Analyst) -> dict:
    return {"config": load_risk_config(analyst.db).model_dump()}


@router.put("/settings/risk")
def put_risk_settings(body: RiskConfig, request: Request, admin: Admin) -> dict:
    save_risk_config(admin.db, body, updated_by=admin.user.id)
    audit(admin.db, "settings_update", "success", user_id=admin.user.id, username=admin.user.username,
          target_type="settings", target_id="risk_config", ip=client_ip(request),
          detail={"weights": str(body.weights), "bands": str(body.bands)})
    return {"config": body.model_dump()}


@router.get("/dashboard")
def dashboard(viewer: Viewer, snapshot_id: int | None = None) -> dict[str, Any]:
    """Headline statistics, all computed from imported data and the latest successful analysis."""
    db = viewer.db
    snap = db.get(Snapshot, snapshot_id) if snapshot_id else db.scalars(
        select(Snapshot).where(Snapshot.status == "ready").order_by(Snapshot.id.desc())).first()
    if snapshot_id and snap is None:
        raise NotFoundError("Snapshot not found.")
    if snap is None:
        return {"snapshot": None, "stats": None, "analysis": None}

    by_kind = dict(db.execute(select(AdObject.kind, func.count()).where(AdObject.snapshot_id == snap.id)
                              .group_by(AdObject.kind)).all())
    privileged = db.scalar(select(func.count()).select_from(AdObject).where(
        AdObject.snapshot_id == snap.id, AdObject.is_tier0.is_(True),
        AdObject.kind.in_(["User", "ServiceAccount"])))
    users = by_kind.get("User", 0) + by_kind.get("ServiceAccount", 0)
    stats = {"identities": users + by_kind.get("Group", 0) + by_kind.get("Computer", 0), "users": users,
             "service_accounts": by_kind.get("ServiceAccount", 0), "groups": by_kind.get("Group", 0),
             "computers": by_kind.get("Computer", 0), "privileged_accounts": privileged, "objects_by_kind": by_kind}

    analysis = db.scalars(select(Analysis).where(Analysis.snapshot_id == snap.id, Analysis.status == "succeeded")
                          .order_by(Analysis.id.desc())).first()
    findings = None
    if analysis is not None:
        paths = db.scalars(select(AttackPath).where(AttackPath.analysis_id == analysis.id)).all()
        risky_steps = {(s["src"], s["dst"], str(s["edge_key"])) for p in paths
                       for s in (p.details or {}).get("steps", []) if s["severity"] >= HIGH_RISK_STEP_SEVERITY}
        findings = {
            "attack_paths": len(paths),
            "critical_paths": sum(p.severity == "Critical" for p in paths),
            "high_risk_relationships": len(risky_steps),
            "unresolved_findings": sum(p.severity in ("Critical", "High") for p in paths),
            "exposed_identities": (analysis.summary or {}).get("exposed_sources", 0),
        }
    return {"snapshot": snapshot_view(snap), "stats": stats,
            "analysis": analysis_view(analysis) if analysis else None, "findings": findings,
            "definitions": {
                "high_risk_relationships": f"distinct relationships on attack paths with rule severity >= "
                                           f"{HIGH_RISK_STEP_SEVERITY}",
                "unresolved_findings": "Critical and High attack paths in the latest analysis"}}
