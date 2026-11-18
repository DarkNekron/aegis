"""Builds the report data model (also the JSON export) from stored analysis results.

Every number in the report is computed from imported data and the stored analysis; nothing is
hard-coded. The renderers (HTML, PDF) only present this model.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.comparison.engine import SnapshotComparator
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.jobs import CancellationToken
from app.graph_engine.analysis import CONDITIONAL, DISCLAIMER, POTENTIAL, AnalysisParams
from app.graph_engine.model import ADGraph
from app.graph_engine.rules import rule_for
from app.models import AdEdge, AdObject, Analysis, AttackPath, ImportJob, Simulation, Snapshot
from app.risk_engine.config import SEVERITIES, load_risk_config
from app.risk_engine.scoring import VALIDATED, RiskScorer
from app.simulation.engine import SimulationRequest, Simulator

SECTIONS = ["executive_summary", "scope", "methodology", "environment", "directory_statistics", "privileged_exposure",
            "attack_paths", "critical_findings", "technical_evidence", "risk_assessment", "recommendations",
            "simulations", "conclusion"]
SECTION_TITLES = {
    "executive_summary": "Executive Summary", "scope": "Assessment Scope", "methodology": "Methodology",
    "environment": "Environment Overview", "directory_statistics": "Directory Statistics",
    "privileged_exposure": "Privileged Identity Exposure", "attack_paths": "Attack Path Analysis",
    "critical_findings": "Critical Findings", "technical_evidence": "Technical Evidence",
    "risk_assessment": "Risk Assessment", "recommendations": "Remediation Recommendations",
    "simulations": "Remediation Simulation Results", "conclusion": "Conclusion", "changes": "Changes Since the "
    "Previous Assessment",
}
CLASSIFICATION_LABELS = {POTENTIAL: "Potential privilege escalation", CONDITIONAL: "Conditional attack path",
                         VALIDATED: "Validated security exposure"}
MAX_OVERVIEW_PATHS = 100
MAX_FINDINGS = 15


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _pct(part: int, whole: int) -> str:
    return f"{(100.0 * part / whole):.1f}%" if whole else "0%"


class ReportBuilder:
    def __init__(self, session: Session):
        self.s = session

    def build(self, analysis_id: int, *, graph: ADGraph | None = None, simulation_ids: list[int] | None = None,
              previous_snapshot_id: int | None = None, generated_by: str | None = None,
              token: CancellationToken | None = None) -> dict[str, Any]:
        token = token or CancellationToken()
        analysis = self.s.get(Analysis, analysis_id)
        if analysis is None:
            raise NotFoundError("Analysis not found.")
        if analysis.status != "succeeded":
            raise ValidationFailedError("Reports can only be generated from a completed analysis.")
        snap = self.s.get(Snapshot, analysis.snapshot_id)
        summary = analysis.summary or {}
        paths = self.s.scalars(select(AttackPath).where(AttackPath.analysis_id == analysis_id)
                               .order_by(AttackPath.score.desc(), AttackPath.hops, AttackPath.id)).all()
        token.check()

        stats = self._directory(snap)
        privileged = self._privileged(snap, summary)
        findings = [p for p in paths if p.severity in ("Critical", "High")][:MAX_FINDINGS]
        evidence = self._evidence(findings, snap.id)
        recommendations = self._recommendations(summary, paths)
        simulations = self._simulations(analysis, graph, simulation_ids, token)
        report: dict[str, Any] = {
            "meta": {"title": "Active Directory Attack Path Assessment", "product": "AEGIS",
                     "product_version": __version__, "generated_at": datetime.now(UTC).isoformat(),
                     "generated_by": generated_by, "classification": "CONFIDENTIAL",
                     "sample_data": snap.is_sample, "snapshot": {"id": snap.id, "name": snap.name},
                     "analysis_id": analysis.id, "sections": SECTIONS, "section_titles": SECTION_TITLES,
                     "disclaimer": DISCLAIMER},
            "scope": self._scope(snap, analysis),
            "methodology": self._methodology(),
            "environment": {"domains": stats.pop("domains"), "objects_by_kind": stats["objects_by_kind"]},
            "directory_statistics": stats,
            "privileged_exposure": privileged,
            "attack_paths": self._overview(paths, summary),
            "critical_findings": [self._finding(p) for p in findings],
            "technical_evidence": evidence,
            "risk_assessment": self._risk(summary, paths),
            "recommendations": recommendations,
            "simulations": simulations,
        }
        if previous_snapshot_id is not None:
            report["changes"] = SnapshotComparator(self.s, limit=50).compare(previous_snapshot_id, snap.id)
            report["meta"]["sections"] = SECTIONS[:-1] + ["changes", "conclusion"]
        report["executive_summary"] = self._executive(report, summary)
        report["conclusion"] = self._conclusion(report, summary)
        return report

    # ------------------------------------------------------------------ sections
    def _scope(self, snap: Snapshot, analysis: Analysis) -> dict[str, Any]:
        imports = self.s.scalars(select(ImportJob).where(ImportJob.snapshot_id == snap.id)
                                 .order_by(ImportJob.id)).all()
        return {
            "snapshot": snap.name, "description": snap.description, "collected_at": _iso(snap.collected_at),
            "source_kind": snap.source_kind, "sample_data": snap.is_sample,
            "data_sources": [{"file": i.filename, "format": i.detected_format, "status": i.status,
                              "sha256": i.sha256, "size_bytes": i.size_bytes, "imported_at": _iso(i.created_at)}
                             for i in imports],
            "analysis": {"id": analysis.id, "completed_at": _iso(analysis.finished_at), "parameters": analysis.params},
            "out_of_scope": ["Live interaction with Active Directory (the assessment is offline and read-only)",
                             "Exploitation or validation of paths (unless an analyst recorded a validation)",
                             "Certificate Services (AD CS) escalation techniques"],
        }

    @staticmethod
    def _methodology() -> dict[str, Any]:
        return {
            "approach": [
                "Directory data collected by SharpHound / BloodHound CE (or supplied inventories) was imported, "
                "validated and normalised; nothing was executed and no system was contacted.",
                "AEGIS reconstructed the directory as a directed graph in which an edge means the source can affect "
                "the destination, and applied relationship-specific traversal rules (e.g. RDP access is not "
                "treated as administrative control; DCSync requires both replication rights).",
                "Tier-0 objects were identified from well-known identifiers, domain controllers, DCSync holders "
                "and transitive membership, each with a recorded reason.",
                "AEGIS's own algorithms computed the shortest path for every identity (multi-source Dijkstra), "
                "alternative routes (Yen's k-shortest paths), choke points, the minimum set of relationships "
                "disconnecting all identities from tier-0 (max-flow / min-cut) and betweenness centrality.",
                "Each path was scored with a transparent nine-factor model and remediation was tested in simulation.",
            ],
            "classifications": {
                CLASSIFICATION_LABELS[POTENTIAL]: "Every step is unconditionally abusable under the rules.",
                CLASSIFICATION_LABELS[CONDITIONAL]: "At least one step has conditions that must be validated "
                                                    "(e.g. a session that may have ended, delegation prerequisites).",
                CLASSIFICATION_LABELS[VALIDATED]: "An analyst confirmed the path in an authorised test.",
            },
            "limitations": [
                "Findings reflect the collected data at collection time; sessions in particular are point-in-time.",
                "Objects referenced but not collected appear as placeholders and may hide or create paths.",
                DISCLAIMER,
            ],
        }

    def _directory(self, snap: Snapshot) -> dict[str, Any]:
        kinds = dict(self.s.execute(select(AdObject.kind, func.count()).where(AdObject.snapshot_id == snap.id)
                                    .group_by(AdObject.kind)).all())
        enabled = dict(self.s.execute(select(AdObject.enabled, func.count()).where(
            AdObject.snapshot_id == snap.id, AdObject.kind.in_(["User", "ServiceAccount"])
        ).group_by(AdObject.enabled)).all())
        domains = sorted(self.s.scalars(select(AdObject.name).where(AdObject.snapshot_id == snap.id,
                                                                    AdObject.kind == "Domain")).all())
        placeholders = sum((i.summary or {}).get("placeholders_created", 0) for i in self.s.scalars(
            select(ImportJob).where(ImportJob.snapshot_id == snap.id)))
        relationships = (snap.stats or {}).get("relationships_by_kind", {})
        return {"domains": domains, "objects_by_kind": kinds, "objects_total": sum(kinds.values()),
                "accounts": {"enabled": enabled.get(True, 0), "disabled": enabled.get(False, 0),
                             "unknown_state": enabled.get(None, 0)},
                "service_accounts": kinds.get("ServiceAccount", 0),
                "relationships_total": sum(relationships.values()),
                "relationships_by_kind": dict(sorted(relationships.items(), key=lambda kv: -kv[1])),
                "collection_gaps": placeholders}

    def _privileged(self, snap: Snapshot, summary: dict[str, Any]) -> dict[str, Any]:
        rows = self.s.scalars(select(AdObject).where(AdObject.snapshot_id == snap.id, AdObject.is_tier0.is_(True))
                              .order_by(AdObject.kind, AdObject.name)).all()
        accounts = [r for r in rows if r.kind in ("User", "ServiceAccount")]
        return {
            "tier0_total": len(rows), "tier0_accounts": len(accounts),
            "objects": [{"name": r.name, "kind": r.kind, "enabled": r.enabled, "reason": r.tier0_reason}
                        for r in rows],
            "exposed_targets": [{"name": t["name"], "kind": t["kind"], "identities": t["sources"]}
                                for t in summary.get("targets", [])],
            "exposed_identities": summary.get("exposed_sources", 0),
            "starting_identities": summary.get("sources_total", 0),
        }

    @staticmethod
    def _brief(p: AttackPath) -> dict[str, Any]:
        nodes = (p.details or {}).get("nodes", [])
        return {"id": p.id, "score": p.score, "severity": p.severity, "hops": p.hops,
                "classification": CLASSIFICATION_LABELS.get(p.classification, p.classification),
                "source": nodes[0]["name"] if nodes else "", "target": nodes[-1]["name"] if nodes else "",
                "route": " → ".join(n["name"] for n in nodes)}

    def _overview(self, paths: list[AttackPath], summary: dict[str, Any]) -> dict[str, Any]:
        return {"total": len(paths), "by_severity": {s: sum(p.severity == s for p in paths) for s in SEVERITIES},
                "by_classification": {CLASSIFICATION_LABELS.get(k, k): v
                                      for k, v in Counter(p.classification for p in paths).items()},
                "hops_distribution": dict(sorted(Counter(p.hops for p in paths).items())),
                "beyond_depth": summary.get("beyond_depth", 0), "truncated": summary.get("truncated", False),
                "paths": [self._brief(p) for p in paths[:MAX_OVERVIEW_PATHS]],
                "listed": min(len(paths), MAX_OVERVIEW_PATHS)}

    def _finding(self, p: AttackPath) -> dict[str, Any]:
        details = p.details or {}
        factors = (p.score_breakdown or {}).get("factors", {})
        return self._brief(p) | {
            "summary": details.get("summary"), "narrative": details.get("narrative", []),
            "conditions": details.get("conditions", []), "target_reasons": details.get("target_reasons", []),
            "steps": [{"from": details["nodes"][i]["name"], "kind": s["kind"], "to": details["nodes"][i + 1]["name"],
                       "technique": s["technique"], "alternatives": s.get("alternatives", [])}
                      for i, s in enumerate(details.get("steps", []))],
            "score_breakdown": [{"factor": k.replace("_", " "), "value": v["value"], "points": v["points"],
                                 "why": v["why"]} for k, v in factors.items()],
            "validated": p.classification == VALIDATED,
        }

    def _evidence(self, findings: list[AttackPath], snapshot_id: int) -> list[dict[str, Any]]:
        out = []
        for p in findings:
            details = p.details or {}
            names = {n["id"]: n["name"] for n in details.get("nodes", [])}
            steps = []
            for s in details.get("steps", []):
                key = s["edge_key"]
                if isinstance(key, str):  # derived DCSync: show both replication rights
                    rows = self.s.scalars(select(AdEdge).where(
                        AdEdge.snapshot_id == snapshot_id, AdEdge.src_object_pk == s["src"],
                        AdEdge.dst_object_pk == s["dst"], AdEdge.kind.in_(["GetChanges", "GetChangesAll"]))).all()
                else:
                    rows = [e for e in [self.s.get(AdEdge, key)] if e is not None]
                steps.append({"relationship": f"{names.get(s['src'])} -[{s['kind']}]-> {names.get(s['dst'])}",
                              "records": [{"kind": e.kind, "data_source": e.data_source,
                                           "source_file": (e.evidence or {}).get("source_file"),
                                           "field": (e.evidence or {}).get("field"),
                                           "collected_at": _iso(e.collected_at), "inherited": e.is_inherited,
                                           "confidence": e.confidence} for e in rows]})
            out.append({"path_id": p.id, "route": self._brief(p)["route"], "steps": steps})
        return out

    def _risk(self, summary: dict[str, Any], paths: list[AttackPath]) -> dict[str, Any]:
        config = load_risk_config(self.s)
        return {"environment": summary.get("environment_risk", {}),
                "weights": summary.get("risk_weights") or RiskScorer(config).weights,
                "bands": config.bands, "conditional_cap": config.conditional_max_severity,
                "score_range": [min((p.score for p in paths), default=0), max((p.score for p in paths), default=0)],
                "choke_points": [{"from": c["src"]["name"], "kinds": c["kinds"], "to": c["dst"]["name"],
                                  "paths": c["paths"]} for c in summary.get("choke_points", [])[:10]],
                "central_objects": [{"name": c["name"], "betweenness": c["betweenness"], "tier0": c["tier0"]}
                                    for c in summary.get("centrality", [])[:10]]}

    def _recommendations(self, summary: dict[str, Any], paths: list[AttackPath]) -> dict[str, Any]:
        cut = summary.get("min_cut", {})
        priority = []
        for step in cut.get("steps", []):
            kind = step["kinds"][0]
            rule = rule_for(kind, step["dst"]["kind"])
            priority.append({"relationship": f"{step['src']['name']} -[{', '.join(step['kinds'])}]-> "
                                             f"{step['dst']['name']}",
                             "action": rule.remediate(step["src"]["name"], step["dst"]["name"], kind),
                             "technique": rule.technique})
        techniques: dict[str, dict[str, Any]] = {}
        for p in paths:
            for s in (p.details or {}).get("steps", []):
                entry = techniques.setdefault(s["technique"], {"technique": s["technique"], "paths": 0,
                                                               "relationship_kinds": set()})
                entry["paths"] += 1
                entry["relationship_kinds"].add(s["kind"])
        return {
            "minimum_cut_size": cut.get("size", 0),
            "priority_actions": priority,
            "by_technique": sorted(({**t, "relationship_kinds": sorted(t["relationship_kinds"])}
                                    for t in techniques.values()), key=lambda t: -t["paths"]),
            "general": [
                "Adopt a tiered administration model: tier-0 credentials must never be used on lower-tier systems.",
                "Review delegated ACLs on privileged groups, GPOs and OUs at least quarterly.",
                "Add privileged accounts to Protected Users and enable Credential Guard where supported.",
                "Deploy LAPS and remove broad local-administrator group memberships.",
                "Re-run collection and AEGIS after remediation to confirm the paths are gone.",
            ],
        }

    def _simulations(self, analysis: Analysis, graph: ADGraph | None, simulation_ids: list[int] | None,
                     token: CancellationToken) -> dict[str, Any]:
        query = select(Simulation).where(Simulation.analysis_id == analysis.id).order_by(Simulation.id.desc())
        if simulation_ids:
            query = query.where(Simulation.id.in_(simulation_ids))
        saved = self.s.scalars(query.limit(10)).all()
        out = {"saved": [self._sim_view(s.result or {}, f"Simulation #{s.id}") for s in saved], "minimum_cut": None}
        if graph is not None and (analysis.summary or {}).get("min_cut", {}).get("size"):
            scorer = RiskScorer(load_risk_config(self.s))
            request = SimulationRequest.model_validate({"actions": [{"type": "apply_min_cut"}]})
            result = Simulator(graph, scorer, AnalysisParams.model_validate(analysis.params)).run(request.actions,
                                                                                                  token=token)
            out["minimum_cut"] = self._sim_view(result, "Apply the minimum cut (computed for this report)")
        return out

    @staticmethod
    def _sim_view(r: dict[str, Any], title: str) -> dict[str, Any]:
        removed = [f"{rel['src']['name']} -[{rel['kind']}]-> {rel['dst']['name']}"
                   for a in r.get("actions", []) for rel in a.get("relationships", [])]
        disabled = [a["object"]["name"] for a in r.get("actions", []) if a.get("type") == "disable_identity"]
        return {"title": title, "removed": removed, "disabled": disabled,
                "paths_before": r.get("paths_before"), "paths_after": r.get("paths_after"),
                "exposed_before": r.get("exposed_before"), "exposed_after": r.get("exposed_after"),
                "risk_before": (r.get("environment_risk_before") or {}).get("score"),
                "risk_after": (r.get("environment_risk_after") or {}).get("score"),
                "secured": [o["name"] for o in r.get("identities_secured", [])][:50],
                "still_exposed": [o["name"] for o in r.get("identities_still_exposed", [])][:50]}

    @staticmethod
    def _executive(report: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
        priv, paths, rec = report["privileged_exposure"], report["attack_paths"], report["recommendations"]
        env = summary.get("environment_risk", {})
        exposed, total = priv["exposed_identities"], priv["starting_identities"]
        shortest = min(paths["hops_distribution"], default=None)  # over all paths, not only those listed
        messages = [f"{exposed} of {total} enabled identities ({_pct(exposed, total)}) can reach a tier-0 object."
                    if total else "No starting identities were found in the collected data."]
        if shortest is not None:
            messages.append(f"The shortest route to tier-0 takes {shortest} step{'s' if shortest != 1 else ''}.")
        sev = paths["by_severity"]
        messages.append(f"{paths['total']} attack path(s) were identified: {sev['Critical']} Critical, "
                        f"{sev['High']} High, {sev['Medium']} Medium and {sev['Low']} Low.")
        sim = report["simulations"]["minimum_cut"]
        if rec["minimum_cut_size"]:
            text = (f"Removing {rec['minimum_cut_size']} specific relationship(s) would disconnect every identified "
                    f"identity from tier-0")
            if sim:
                text += (f"; simulation confirms paths fall from {sim['paths_before']} to {sim['paths_after']} and the "
                         f"environment risk from {sim['risk_before']} to {sim['risk_after']}")
            messages.append(text + ".")
        return {"environment_risk": env, "messages": messages,
                "top_findings": [{"route": f["route"], "severity": f["severity"], "score": f["score"]}
                                 for f in report["critical_findings"][:3]]}

    @staticmethod
    def _conclusion(report: dict[str, Any], summary: dict[str, Any]) -> list[str]:
        env = summary.get("environment_risk", {})
        rec = report["recommendations"]
        lines = [f"The overall environment risk is {env.get('score', 0)} ({env.get('severity', 'Low')})."]
        if report["attack_paths"]["total"]:
            lines.append(f"Prioritise the {rec['minimum_cut_size']} relationship change(s) in the remediation "
                         "section: they break every identified route to tier-0, and should be followed by the "
                         "structural measures listed there.")
        else:
            lines.append("No attack paths to tier-0 were identified in the collected data.")
        lines.append("Re-collect and re-assess after remediation; AEGIS's historical comparison will confirm which "
                     "paths were eliminated and flag any new exposure.")
        return lines
