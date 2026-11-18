"""Shared API helpers: role aliases, pagination parameters and serialisers."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, Query

from app.models import AdObject, Analysis, AttackPath, Snapshot
from app.security.deps import Principal, require_role

Viewer = Annotated[Principal, Depends(require_role("viewer"))]
Analyst = Annotated[Principal, Depends(require_role("analyst"))]
Admin = Annotated[Principal, Depends(require_role("admin"))]
Offset = Annotated[int, Query(ge=0, le=10_000_000)]
Limit = Annotated[int, Query(ge=1, le=500)]


def iso(value) -> str | None:
    return value.isoformat() if value else None


def snapshot_view(s: Snapshot) -> dict[str, Any]:
    return {"id": s.id, "name": s.name, "description": s.description, "status": s.status, "is_sample": s.is_sample,
            "source_kind": s.source_kind, "created_at": iso(s.created_at), "collected_at": iso(s.collected_at),
            "stats": s.stats or {}}


def object_view(o: AdObject, *, full: bool = False) -> dict[str, Any]:
    view = {"id": o.id, "object_id": o.object_id, "kind": o.kind, "name": o.name, "domain": o.domain,
            "enabled": o.enabled, "tier0": o.is_tier0, "tier0_reason": o.tier0_reason,
            "placeholder": bool((o.properties or {}).get("aegis_placeholder"))}
    if full:
        view["properties"] = {k: v for k, v in (o.properties or {}).items() if k != "aegis_placeholder"}
    return view


def analysis_view(a: Analysis, *, full: bool = False) -> dict[str, Any]:
    summary = a.summary or {}
    view = {"id": a.id, "snapshot_id": a.snapshot_id, "status": a.status, "error": a.error,
            "created_at": iso(a.created_at), "started_at": iso(a.started_at), "finished_at": iso(a.finished_at),
            "environment_risk": summary.get("environment_risk"), "paths_total": summary.get("paths_total"),
            "paths_by_severity": summary.get("paths_by_severity")}
    if full:
        view["params"] = a.params
        view["summary"] = summary
    return view


def path_view(p: AttackPath, *, full: bool = False) -> dict[str, Any]:
    details = p.details or {}
    nodes = details.get("nodes", [])
    view = {"id": p.id, "analysis_id": p.analysis_id, "score": p.score, "severity": p.severity, "hops": p.hops,
            "classification": p.classification, "confidence": p.confidence, "signature": p.signature,
            "source": nodes[0] if nodes else None, "target": nodes[-1] if nodes else None,
            "summary": details.get("summary"), "validated_at": iso(p.validated_at)}
    if full:
        view.update({"nodes": nodes, "steps": details.get("steps", []), "conditions": details.get("conditions", []),
                     "narrative": details.get("narrative", []), "target_reasons": details.get("target_reasons", []),
                     "score_breakdown": p.score_breakdown})
    return view
