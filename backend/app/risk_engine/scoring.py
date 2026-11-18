"""Path and environment risk scoring.

    score = 100 * sum_i( w_i * f_i ) / sum_i( w_i )        each factor f_i in [0, 1]

Every score is returned with its full breakdown: for each factor the value, the normalised weight,
the points it contributed, and a one-line reason. The points sum to the score. The model and the
rationale for each factor are documented in docs/RISK_SCORING.md.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Any

from app.graph_engine.analysis import CONDITIONAL, AnalysisResult, PathResult
from app.graph_engine.model import ADGraph
from app.risk_engine.config import SEVERITIES, RiskConfig

VALIDATED = "validated_security_exposure"


@dataclass
class PathScore:
    score: float
    severity: str
    breakdown: dict[str, dict[str, Any]]
    capped: bool


class RiskScorer:
    def __init__(self, config: RiskConfig):
        self.config = config
        self.weights = config.normalised_weights()

    # ------------------------------------------------------------------ factors
    def factors(self, graph: ADGraph, path: PathResult, *, paths_for_source: int, sources_reaching_target: int,
                classification: str | None = None) -> dict[str, tuple[float, str]]:
        cfg = self.config
        g = graph.g
        target_name = g.nodes[path.target]["name"]
        categories = graph.tier0_categories.get(path.target, frozenset())
        if categories:
            best = max(categories, key=lambda c: cfg.category_privilege.get(c, cfg.default_privilege))
            privilege = cfg.category_privilege.get(best, cfg.default_privilege)
            privilege_why = f"{target_name} is tier-0 ({best.replace('_', ' ')})"
        else:
            privilege, privilege_why = cfg.default_privilege, f"{target_name} is a selected target"

        classification = classification or path.classification
        if classification == CONDITIONAL:
            exploit, exploit_why = cfg.conditional_factor, f"{len(path.conditions)} condition(s) must be validated"
        elif classification == VALIDATED:
            exploit, exploit_why = 1.0, "validated by an analyst"
        else:
            exploit, exploit_why = 1.0, "every step is unconditionally abusable"

        proximity = cfg.hop_decay ** (path.hops - 1)
        severity = sum(s.severity for s in path.steps) / len(path.steps)
        exposure = min(1.0, math.log1p(sources_reaching_target) / math.log1p(cfg.exposure_saturation))
        alternatives = min(1.0, (paths_for_source - 1) / (cfg.alternatives_saturation - 1))
        placeholders = sum(1 for n in path.nodes if g.nodes[n]["placeholder"])
        completeness = 1.0 - placeholders / len(path.nodes)
        crit = [(cfg.asset_criticality[g.nodes[n]["oid"]], g.nodes[n]["name"]) for n in path.nodes
                if g.nodes[n]["oid"] in cfg.asset_criticality]
        criticality = max(crit)[0] if crit else 0.0

        return {
            "destination_privilege": (privilege, privilege_why),
            "exploitability": (exploit, exploit_why),
            "proximity": (proximity, f"{path.hops} step(s) from the source"),
            "relationship_severity": (severity, "mean severity of the relationships used: "
                                      + ", ".join(sorted({s.kind for s in path.steps}))),
            "confidence": (path.confidence, "product of the evidence confidence of each step"),
            "exposure": (exposure, f"{sources_reaching_target} identit{'y' if sources_reaching_target == 1 else 'ies'}"
                                   f" reach {target_name}"),
            "alternatives": (alternatives, f"{paths_for_source} route(s) from this identity"),
            "evidence_completeness": (completeness, "all objects observed in the collection" if not placeholders
                                      else f"{placeholders} object(s) on the path were not collected"),
            "asset_criticality": (criticality, f"most critical asset: {max(crit)[1]}" if crit
                                  else "no business criticality configured"),
        }

    # ------------------------------------------------------------------ scores
    def score_factors(self, factors: dict[str, tuple[float, str]], classification: str) -> PathScore:
        breakdown: dict[str, dict[str, Any]] = {}
        total = 0.0
        for name, (value, why) in factors.items():
            value = min(1.0, max(0.0, float(value)))
            points = 100.0 * self.weights[name] * value
            total += points
            breakdown[name] = {"value": round(value, 4), "weight": round(self.weights[name], 4),
                               "points": round(points, 2), "why": why}
        score = round(min(100.0, total), 2)
        severity = self.band(score)
        capped = False
        if classification == CONDITIONAL:
            cap = self.config.conditional_max_severity
            if SEVERITIES.index(severity) < SEVERITIES.index(cap):
                severity, capped = cap, True
        return PathScore(score=score, severity=severity, breakdown=breakdown, capped=capped)

    def band(self, score: float) -> str:
        bands = self.config.bands
        for name in ("Critical", "High", "Medium"):
            if score >= bands[name]:
                return name
        return "Low"

    def score_analysis(self, graph: ADGraph, result: AnalysisResult) -> dict[str, PathScore]:
        """Score every path; returns {signature: PathScore} and re-sorts ``result.paths`` by risk."""
        per_source = Counter(p.source for p in result.paths)
        reaching = Counter(p.target for p in result.paths if p.shortest_for_source)
        scores: dict[str, PathScore] = {}
        for path in result.paths:
            factors = self.factors(graph, path, paths_for_source=per_source[path.source],
                                   sources_reaching_target=reaching.get(path.target, 1))
            scores[path.signature] = self.score_factors(factors, path.classification)
        result.paths.sort(key=lambda p: (-scores[p.signature].score, p.hops, p.cost, p.signature))
        return scores

    def environment_risk(self, result: AnalysisResult, scores: dict[str, PathScore]) -> dict[str, Any]:
        """Overall exposure, 0-100: 50% worst path, 30% mean of each exposed identity's worst path, 20% breadth."""
        if not result.paths:
            return {"score": 0.0, "severity": "Low", "components": {"worst_path": 0.0, "mean_identity": 0.0,
                                                                     "breadth": 0.0}}
        best_per_source: dict[int, float] = {}
        for p in result.paths:
            best_per_source[p.source] = max(best_per_source.get(p.source, 0.0), scores[p.signature].score)
        worst = max(best_per_source.values())
        mean = sum(best_per_source.values()) / len(best_per_source)
        fraction = len(best_per_source) / max(1, result.sources_total)
        breadth = 100.0 * min(1.0, fraction / 0.05)  # 5% of identities exposed counts as fully broad
        score = round(0.5 * worst + 0.3 * mean + 0.2 * breadth, 2)
        severity_counts = Counter(s.severity for s in scores.values())
        return {"score": score, "severity": self.band(score),
                "components": {"worst_path": round(worst, 2), "mean_identity": round(mean, 2),
                               "breadth": round(breadth, 2), "exposed_fraction": round(fraction, 4)},
                "paths_by_severity": {s: severity_counts.get(s, 0) for s in SEVERITIES}}
