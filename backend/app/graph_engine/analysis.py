"""Module 3 orchestration: from a graph to explained, de-duplicated, ranked attack paths.

AEGIS reports what the collected data *supports*, never that something was exploited:

* ``potential_privilege_escalation``: every step is unconditionally abusable under the rules;
* ``conditional_attack_path``: at least one step has conditions that must be validated;
* ``validated_security_exposure``: only ever set manually by an analyst (not here).
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from app.core.config import Settings
from app.core.jobs import CancellationToken
from app.graph_engine.algorithms.alternatives import enumerate_paths, k_shortest_paths
from app.graph_engine.algorithms.centrality import betweenness
from app.graph_engine.algorithms.flow import min_edge_cut
from app.graph_engine.algorithms.index import TraversalIndex
from app.graph_engine.algorithms.shortest import Distances, path_length, reverse_shortest
from app.graph_engine.model import ADGraph, EdgeRef
from app.graph_engine.rules import rule_for

POTENTIAL = "potential_privilege_escalation"
CONDITIONAL = "conditional_attack_path"
DISCLAIMER = ("Derived from collected directory data. It shows what the data supports; it has not been validated "
              "and does not prove the path is exploitable.")


class AnalysisParams(BaseModel):
    max_depth: int = Field(10, ge=1, le=25)
    alternatives_per_source: int = Field(3, ge=1, le=50)
    max_sources_with_alternatives: int = Field(500, ge=0, le=100_000)
    max_paths: int = Field(10_000, ge=1, le=1_000_000)
    centrality_sample_size: int = Field(256, ge=8, le=100_000)
    top_n: int = Field(25, ge=1, le=500)

    @classmethod
    def from_settings(cls, settings: Settings, **overrides: Any) -> AnalysisParams:
        base = {"max_depth": settings.max_path_depth, "alternatives_per_source": settings.max_alternative_paths,
                "centrality_sample_size": settings.centrality_sample_size}
        params = cls(**(base | overrides))
        # never exceed the administrator's configured ceilings
        params.max_depth = min(params.max_depth, settings.max_path_depth)
        params.alternatives_per_source = min(params.alternatives_per_source, settings.max_alternative_paths)
        return params


@dataclass
class PathStep:
    src: int
    dst: int
    key: Any
    kind: str
    alternatives: list[str]   # other relationship kinds that also link src -> dst
    conditional: bool
    cost: float
    severity: float
    confidence: float
    technique: str
    explanation: str


@dataclass
class PathResult:
    source: int
    target: int
    nodes: list[int]
    steps: list[PathStep]
    hops: int
    cost: float
    confidence: float
    classification: str
    conditions: list[str]
    signature: str
    summary: str
    narrative: list[str]
    shortest_for_source: bool = False

    def edge_refs(self) -> list[EdgeRef]:
        return [(s.src, s.dst, s.key) for s in self.steps]


@dataclass
class AnalysisResult:
    snapshot_id: int
    params: AnalysisParams
    paths: list[PathResult]
    exposure: dict[int, tuple[int, float]]          # source -> (hops, cost) of its shortest path
    sources_total: int
    beyond_depth: int
    truncated: bool
    choke_steps: list[dict[str, Any]]
    choke_nodes: list[dict[str, Any]]
    min_cut: dict[str, Any]
    centrality: list[dict[str, Any]]
    centrality_sampled: bool
    target_exposure: list[dict[str, Any]]
    timings: dict[str, float] = field(default_factory=dict)

    @property
    def exposed_sources(self) -> set[int]:
        return set(self.exposure)


class PathAnalyzer:
    def __init__(self, graph: ADGraph):
        self.graph = graph

    # ------------------------------------------------------------------ public API
    def run(self, params: AnalysisParams, *, token: CancellationToken,
            removed_edges: tuple[EdgeRef, ...] = (), disabled_nodes: tuple[int, ...] = (),
            include_insights: bool = True) -> AnalysisResult:
        timings: dict[str, float] = {}
        t0 = time.perf_counter()
        index = TraversalIndex(self.graph, removed_edges=removed_edges, disabled_nodes=disabled_nodes)
        timings["index"] = time.perf_counter() - t0
        t_short = time.perf_counter()
        dist = reverse_shortest(index, max_depth=params.max_depth, token=token)
        timings["shortest"] = time.perf_counter() - t_short

        exposed = sorted((s for s in index.sources if s in dist.length), key=lambda s: (dist.length[s], s))
        t1 = time.perf_counter()
        paths, truncated = self._collect_paths(index, dist, exposed, params, token)
        timings["alternatives"] = time.perf_counter() - t1

        paths.sort(key=lambda p: (p.hops, p.cost, -p.confidence, self.graph.name(p.source), p.signature))
        result = AnalysisResult(
            snapshot_id=self.graph.snapshot_id, params=params, paths=paths,
            exposure={s: dist.length[s] for s in exposed}, sources_total=len(index.sources),
            beyond_depth=dist.beyond_depth, truncated=truncated, choke_steps=[], choke_nodes=[], min_cut={},
            centrality=[], centrality_sampled=False, target_exposure=self._target_exposure(dist, exposed),
            timings=timings,
        )
        if include_insights:
            self._insights(result, index, dist, exposed, params, token)
        timings["total"] = time.perf_counter() - t0
        result.timings = {k: round(v, 4) for k, v in timings.items()}
        return result

    def paths_between(self, source: int, targets: set[int], *, max_depth: int, limit: int,
                      token: CancellationToken) -> tuple[list[PathResult], bool]:
        """Multi-hop discovery for one source and chosen targets (e.g. a specific server)."""
        index = TraversalIndex(self.graph)
        node_paths, truncated = enumerate_paths(index, source, targets, max_depth=max_depth, limit=limit,
                                                token=token)
        return [self._describe(index, nodes) for nodes in node_paths], truncated

    # ------------------------------------------------------------------ internals
    def _collect_paths(self, index: TraversalIndex, dist: Distances, exposed: list[int], params: AnalysisParams,
                       token: CancellationToken) -> tuple[list[PathResult], bool]:
        results: dict[str, PathResult] = {}
        truncated = False
        for rank, source in enumerate(exposed):
            token.check()
            shortest = dist.path(source)
            candidates = [shortest]
            if params.alternatives_per_source > 1 and rank < params.max_sources_with_alternatives:
                alternatives = [alt for alt in k_shortest_paths(index, source, k=params.alternatives_per_source,
                                                                max_depth=params.max_depth, token=token)
                                if alt != shortest]
                candidates.extend(alternatives[: params.alternatives_per_source - 1])
            for i, nodes in enumerate(candidates):
                path = self._describe(index, nodes)
                path.shortest_for_source = i == 0
                if path.signature not in results:
                    results[path.signature] = path
                if len(results) >= params.max_paths:
                    return list(results.values()), True
        return list(results.values()), truncated

    def _describe(self, index: TraversalIndex, nodes: list[int]) -> PathResult:
        g = self.graph.g
        steps: list[PathStep] = []
        conditions: list[str] = []
        confidence = 1.0
        for u, v in zip(nodes, nodes[1:], strict=False):
            step = index.step(u, v)
            data = g[u][v][step.key]
            src_name, dst_name = g.nodes[u]["name"], g.nodes[v]["name"]
            rule = rule_for(data["kind"], g.nodes[v]["kind"])
            alternatives = sorted({g[u][v][k]["kind"] for k in step.keys[1:]} - {data["kind"]})
            steps.append(PathStep(src=u, dst=v, key=step.key, kind=data["kind"], alternatives=alternatives,
                                  conditional=bool(data["cond"]), cost=data["w"], severity=data["sev"],
                                  confidence=float(data["conf"]), technique=rule.technique,
                                  explanation=rule.explain(src_name, dst_name)))
            confidence *= float(data["conf"])
            if data["cond"]:
                for text in rule.conditions or (f"Validate the {data['kind']} relationship.",):
                    text = text.format(src=src_name, dst=dst_name)
                    if text not in conditions:
                        conditions.append(text)
        source, target = nodes[0], nodes[-1]
        hops, cost = path_length(index, nodes)
        classification = CONDITIONAL if any(s.conditional for s in steps) else POTENTIAL
        signature = hashlib.sha256("|".join(
            f"{g.nodes[s.src]['oid']}>{s.kind}>{g.nodes[s.dst]['oid']}" for s in steps).encode()).hexdigest()
        reasons = self.graph.tier0_reasons.get(target)
        why = f"{g.nodes[target]['name']} is tier-0 ({'; '.join(reasons)})" if reasons else \
            f"{g.nodes[target]['name']} is a selected target"
        summary = (f"{g.nodes[source]['name']} can reach {g.nodes[target]['name']} in {hops} "
                   f"step{'s' if hops != 1 else ''}. {why}.")
        narrative = [f"{i}. {s.explanation}" + (f" (also via {', '.join(s.alternatives)})" if s.alternatives else "")
                     for i, s in enumerate(steps, 1)]
        narrative.append(f"Why it matters: control of a tier-0 object means control of the domain. {why}.")
        narrative.append(DISCLAIMER)
        return PathResult(source=source, target=target, nodes=nodes, steps=steps, hops=hops, cost=round(cost, 3),
                          confidence=round(confidence, 4), classification=classification, conditions=conditions,
                          signature=signature, summary=summary, narrative=narrative)

    def _target_exposure(self, dist: Distances, exposed: list[int]) -> list[dict[str, Any]]:
        counts: Counter[int] = Counter()
        for source in exposed:
            counts[dist.path(source)[-1]] += 1
        return [{"node": n, "name": self.graph.name(n), "sources": c} for n, c in counts.most_common()]

    def _insights(self, result: AnalysisResult, index: TraversalIndex, dist: Distances, exposed: list[int],
                  params: AnalysisParams, token: CancellationToken) -> None:
        t = time.perf_counter()
        step_use: Counter[tuple[int, int]] = Counter()
        node_use: Counter[int] = Counter()
        for path in result.paths:
            for s in path.steps:
                step_use[(s.src, s.dst)] += 1
            for n in path.nodes[1:-1]:
                node_use[n] += 1
        result.choke_steps = [self._step_info(index, u, v) | {"paths": c}
                              for (u, v), c in step_use.most_common(params.top_n)]
        result.choke_nodes = [{"node": n, "name": self.graph.name(n), "paths": c}
                              for n, c in node_use.most_common(params.top_n)]

        relevant = set(dist.length)
        cut = min_edge_cut(index, set(exposed), relevant, token=token)
        result.min_cut = {"size": cut.size, "sources": cut.sources_considered,
                          "steps": [self._step_info(index, u, v) for u, v in cut.steps]}
        result.timings["min_cut"] = time.perf_counter() - t

        t = time.perf_counter()
        scores, sampled = betweenness(index, relevant, sample_size=params.centrality_sample_size, token=token)
        ranked = sorted(((v, n) for n, v in scores.items() if v > 0), key=lambda x: (-x[0], x[1]))[: params.top_n]
        result.centrality = [{"node": n, "name": self.graph.name(n), "betweenness": round(v, 3),
                              "tier0": n in self.graph.tier0} for v, n in ranked]
        result.centrality_sampled = sampled
        result.timings["centrality"] = time.perf_counter() - t

    def _step_info(self, index: TraversalIndex, u: int, v: int) -> dict[str, Any]:
        g = self.graph.g
        step = index.step(u, v)
        return {"src": u, "dst": v, "src_name": g.nodes[u]["name"], "dst_name": g.nodes[v]["name"],
                "kinds": [g[u][v][k]["kind"] for k in step.keys], "edge_keys": list(step.keys)}
