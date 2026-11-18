"""Runs and stores remediation simulations against a baseline analysis."""

from __future__ import annotations

from sqlalchemy import func, select

from app.core.errors import NotFoundError, ValidationFailedError
from app.core.jobs import CancellationToken
from app.db.session import Database
from app.graph_engine.analysis import AnalysisParams
from app.graph_engine.service import GraphService
from app.models import Analysis, Simulation
from app.risk_engine.config import load_risk_config
from app.risk_engine.scoring import RiskScorer
from app.simulation.engine import SimulationRequest, Simulator


class SimulationService:
    def __init__(self, db: Database, graphs: GraphService):
        self.db = db
        self.graphs = graphs

    def baseline(self, analysis_id: int) -> Analysis:
        with self.db.session() as s:
            analysis = s.get(Analysis, analysis_id)
            if analysis is None:
                raise NotFoundError("Analysis not found.")
            if analysis.status != "succeeded":
                raise ValidationFailedError("Simulations need a successfully completed analysis as their baseline.")
            return analysis

    def run(self, analysis_id: int, request: SimulationRequest, *, token: CancellationToken | None = None,
            created_by: int | None = None) -> int:
        analysis = self.baseline(analysis_id)
        token = token or CancellationToken()
        graph = self.graphs.get(analysis.snapshot_id, token=token)
        with self.db.session() as s:
            scorer = RiskScorer(load_risk_config(s))
        params = AnalysisParams.model_validate(analysis.params)
        result = Simulator(graph, scorer, params).run(request.actions, token=token)
        result["baseline_graph_version"] = (analysis.summary or {}).get("graph_version")
        result["baseline_is_current"] = result["baseline_graph_version"] == graph.version
        with self.db.session() as s:
            sim = Simulation(analysis_id=analysis_id, actions=[a.model_dump() for a in request.actions],
                             result=result, created_by=created_by)
            s.add(sim)
            s.commit()
            return sim.id

    def get(self, simulation_id: int) -> Simulation:
        with self.db.session() as s:
            sim = s.get(Simulation, simulation_id)
            if sim is None:
                raise NotFoundError("Simulation not found.")
            return sim

    def list(self, analysis_id: int, *, offset: int = 0, limit: int = 50) -> tuple[int, list[Simulation]]:
        with self.db.session() as s:
            cond = Simulation.analysis_id == analysis_id
            total = s.scalar(select(func.count()).select_from(Simulation).where(cond))
            rows = s.scalars(select(Simulation).where(cond).order_by(Simulation.id.desc()).offset(offset).limit(limit))
            return total, list(rows)
