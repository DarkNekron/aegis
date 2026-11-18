"""Runs attack-path analyses, scores them and persists the results.

An ``analyses`` row is created first (status ``running``) so failures are recorded. Paths are written
in one transaction together with the final status: a crashed or cancelled analysis never leaves a
half-populated result.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from sqlalchemy import func, select

from app.core.config import Settings
from app.core.errors import AegisError, JobCancelledError, NotFoundError, ValidationFailedError
from app.core.jobs import CancellationToken
from app.db.base import utcnow
from app.db.session import Database
from app.graph_engine.analysis import AnalysisParams, AnalysisResult, PathAnalyzer
from app.graph_engine.model import ADGraph
from app.graph_engine.service import GraphService
from app.models import Analysis, AttackPath, Snapshot
from app.risk_engine.config import SEVERITIES, load_risk_config
from app.risk_engine.scoring import VALIDATED, PathScore, RiskScorer

logger = logging.getLogger(__name__)

MAX_PAGE = 500
INSERT_BATCH = 1000


class AnalysisStatus:
    RUNNING, SUCCEEDED, FAILED, CANCELLED = "running", "succeeded", "failed", "cancelled"


class AnalysisService:
    def __init__(self, db: Database, settings: Settings, graphs: GraphService):
        self.db = db
        self.settings = settings
        self.graphs = graphs

    # ------------------------------------------------------------------ run
    def run(self, snapshot_id: int, *, params: AnalysisParams | None = None, token: CancellationToken | None = None,
            created_by: int | None = None) -> int:
        params = params or AnalysisParams.from_settings(self.settings)
        token = token or CancellationToken(self.settings.job_timeout_seconds)
        with self.db.session() as s:
            if s.get(Snapshot, snapshot_id) is None:
                raise NotFoundError("Snapshot not found.")
            analysis = Analysis(snapshot_id=snapshot_id, params=params.model_dump(), status=AnalysisStatus.RUNNING,
                                started_at=utcnow(), created_by=created_by)
            s.add(analysis)
            s.commit()
            analysis_id = analysis.id
        try:
            graph = self.graphs.get(snapshot_id, token=token)
            result = PathAnalyzer(graph).run(params, token=token)
            self._persist(analysis_id, graph, result)
        except AegisError as exc:
            status = AnalysisStatus.CANCELLED if isinstance(exc, JobCancelledError) else AnalysisStatus.FAILED
            self._fail(analysis_id, status, exc.message)
            raise
        except Exception:
            self._fail(analysis_id, AnalysisStatus.FAILED, "Internal error during analysis.")
            raise
        return analysis_id

    def _persist(self, analysis_id: int, graph: ADGraph, result: AnalysisResult) -> None:
        g = graph.g
        with self.db.session() as s:
            scorer = RiskScorer(load_risk_config(s))
            scores = scorer.score_analysis(graph, result)
            environment = scorer.environment_risk(result, scores)
            rows = [self._row(analysis_id, graph, path, scores[path.signature]) for path in result.paths]
            for start in range(0, len(rows), INSERT_BATCH):
                s.execute(AttackPath.__table__.insert(), rows[start:start + INSERT_BATCH])

            def obj(n: int) -> dict[str, Any]:
                return {"id": n, "object_id": g.nodes[n]["oid"], "name": g.nodes[n]["name"], "kind": g.nodes[n]["kind"]}

            classification_counts: dict[str, int] = {}
            for p in result.paths:
                classification_counts[p.classification] = classification_counts.get(p.classification, 0) + 1
            analysis = s.get(Analysis, analysis_id)
            analysis.summary = {
                "environment_risk": environment,
                "paths_total": len(result.paths),
                "paths_by_severity": environment.get("paths_by_severity", dict.fromkeys(SEVERITIES, 0)),
                "paths_by_classification": classification_counts,
                "sources_total": result.sources_total,
                "exposed_sources": len(result.exposure),
                "beyond_depth": result.beyond_depth,
                "truncated": result.truncated,
                "targets": [obj(t["node"]) | {"sources": t["sources"]} for t in result.target_exposure],
                "choke_points": [{"src": obj(c["src"]), "dst": obj(c["dst"]), "kinds": c["kinds"],
                                  "edge_keys": c["edge_keys"], "paths": c["paths"]} for c in result.choke_steps],
                "choke_nodes": [obj(c["node"]) | {"paths": c["paths"]} for c in result.choke_nodes],
                "min_cut": {"size": result.min_cut.get("size", 0),
                            "steps": [{"src": obj(c["src"]), "dst": obj(c["dst"]), "kinds": c["kinds"],
                                       "edge_keys": c["edge_keys"]} for c in result.min_cut.get("steps", [])]},
                "centrality": [obj(c["node"]) | {"betweenness": c["betweenness"], "tier0": c["tier0"]}
                               for c in result.centrality],
                "centrality_sampled": result.centrality_sampled,
                "graph": asdict(graph.stats),
                "graph_version": graph.version,
                "timings": result.timings,
                "risk_weights": scorer.weights,
            }
            analysis.status = AnalysisStatus.SUCCEEDED
            analysis.finished_at = utcnow()
            s.commit()
        logger.info("Analysis %s: %s paths, environment risk %s", analysis_id, len(result.paths),
                    environment["score"])

    @staticmethod
    def _row(analysis_id: int, graph: ADGraph, path, score: PathScore) -> dict[str, Any]:
        g = graph.g
        return {
            "analysis_id": analysis_id, "source_pk": path.source, "target_pk": path.target, "hops": path.hops,
            "edge_ids": [s.key for s in path.steps], "classification": path.classification,
            "confidence": path.confidence, "score": score.score, "severity": score.severity,
            "score_breakdown": {"factors": score.breakdown, "capped_by_classification": score.capped},
            "signature": path.signature,
            "details": {
                "nodes": [{"id": n, "object_id": g.nodes[n]["oid"], "name": g.nodes[n]["name"],
                           "kind": g.nodes[n]["kind"], "tier0": n in graph.tier0} for n in path.nodes],
                "steps": [{"src": s.src, "dst": s.dst, "edge_key": s.key, "kind": s.kind,
                           "alternatives": s.alternatives, "conditional": s.conditional, "technique": s.technique,
                           "explanation": s.explanation, "severity": s.severity, "confidence": s.confidence}
                          for s in path.steps],
                "conditions": path.conditions, "summary": path.summary, "narrative": path.narrative,
                "cost": path.cost, "shortest_for_source": path.shortest_for_source,
                "target_reasons": graph.tier0_reasons.get(path.target, []),
            },
        }

    def _fail(self, analysis_id: int, status: str, message: str) -> None:
        try:
            with self.db.session() as s:
                analysis = s.get(Analysis, analysis_id)
                analysis.status, analysis.error, analysis.finished_at = status, message[:1000], utcnow()
                s.commit()
        except Exception:
            logger.exception("Could not record failure of analysis %s", analysis_id)

    # ------------------------------------------------------------------ queries
    def get(self, analysis_id: int) -> Analysis:
        with self.db.session() as s:
            analysis = s.get(Analysis, analysis_id)
            if analysis is None:
                raise NotFoundError("Analysis not found.")
            return analysis

    def list_paths(self, analysis_id: int, *, offset: int = 0, limit: int = 50, severity: str | None = None,
                   classification: str | None = None, source_pk: int | None = None,
                   target_pk: int | None = None) -> tuple[int, list[AttackPath]]:
        if not 1 <= limit <= MAX_PAGE or offset < 0:
            raise ValidationFailedError(f"limit must be 1-{MAX_PAGE} and offset >= 0.")
        if severity is not None and severity not in SEVERITIES:
            raise ValidationFailedError(f"severity must be one of {', '.join(SEVERITIES)}.")
        self.get(analysis_id)
        conditions = [AttackPath.analysis_id == analysis_id]
        if severity:
            conditions.append(AttackPath.severity == severity)
        if classification:
            conditions.append(AttackPath.classification == classification)
        if source_pk is not None:
            conditions.append(AttackPath.source_pk == source_pk)
        if target_pk is not None:
            conditions.append(AttackPath.target_pk == target_pk)
        with self.db.session() as s:
            total = s.scalar(select(func.count()).select_from(AttackPath).where(*conditions))
            rows = s.scalars(select(AttackPath).where(*conditions)
                             .order_by(AttackPath.score.desc(), AttackPath.hops, AttackPath.id)
                             .offset(offset).limit(limit)).all()
        return total, list(rows)

    def validate_path(self, path_id: int, user_id: int | None, note: str | None = None) -> AttackPath:
        """Analyst confirmed the path in an authorised test: mark it and rescore with the stored weights."""
        with self.db.session() as s:
            path = s.get(AttackPath, path_id)
            if path is None:
                raise NotFoundError("Attack path not found.")
            factors = path.score_breakdown["factors"]
            factors["exploitability"] = {**factors["exploitability"], "value": 1.0,
                                         "points": round(100 * factors["exploitability"]["weight"], 2),
                                         "why": "validated by an analyst"}
            score = round(sum(f["points"] for f in factors.values()), 2)
            scorer = RiskScorer(load_risk_config(s))
            path.classification = VALIDATED
            path.score, path.severity = score, scorer.band(score)
            path.score_breakdown = {"factors": factors, "capped_by_classification": False,
                                    "validation_note": (note or "")[:500]}
            path.validated_by, path.validated_at = user_id, utcnow()
            s.commit()
            s.refresh(path)
            return path
