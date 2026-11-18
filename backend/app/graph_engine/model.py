"""The in-memory attack graph for one snapshot.

Nodes are ``ad_objects.id`` integers. Attributes are kept deliberately small (evidence stays in the
database and is loaded on demand):

    node: oid (directory identifier, stable across snapshots), kind, name, enabled, placeholder, tier0
    edge (key = ad_edges.id, or "dcsync:<src>:<dst>" for derived edges):
          kind, t (traversable), cond (conditional), w (cost), sev (severity), conf (confidence)

The base graph is never mutated after construction. Analyses that need a modified graph
(remediation simulation) use ``view()``, a zero-copy filtered view.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.graph_engine.config import AnalysisConfig

EdgeRef = tuple[int, int, Any]  # (u, v, key)


@dataclass
class BuildStats:
    nodes: int = 0
    edges: int = 0
    traversable_edges: int = 0
    derived_edges: int = 0
    placeholders: int = 0
    tier0: int = 0
    sources: int = 0
    estimated_memory_mb: int = 0
    build_seconds: float = 0.0


@dataclass
class ADGraph:
    snapshot_id: int
    version: str
    config: AnalysisConfig
    g: nx.MultiDiGraph
    tier0: frozenset[int]
    tier0_reasons: dict[int, list[str]]
    sources: frozenset[int]
    derived_evidence: dict[str, list[int]] = field(default_factory=dict)
    tier0_categories: dict[int, frozenset[str]] = field(default_factory=dict)
    stats: BuildStats = field(default_factory=BuildStats)

    def view(self, *, removed_edges: Iterable[EdgeRef] = (), disabled_nodes: Iterable[int] = (),
             traversable_only: bool = True) -> nx.MultiDiGraph:
        """Read-only filtered view. ``disabled_nodes`` keep their node but lose all outgoing edges
        (a disabled account can no longer act), which is how "disable identity" is simulated."""
        removed = frozenset(removed_edges)
        disabled = frozenset(disabled_nodes)
        g = self.g

        def keep_edge(u: int, v: int, k: Any) -> bool:
            if traversable_only and not g[u][v][k]["t"]:
                return False
            return u not in disabled and (u, v, k) not in removed

        return nx.subgraph_view(g, filter_edge=keep_edge)

    def node(self, n: int) -> dict[str, Any]:
        return self.g.nodes[n]

    def edge(self, ref: EdgeRef) -> dict[str, Any]:
        u, v, k = ref
        return self.g[u][v][k]

    def name(self, n: int) -> str:
        return self.g.nodes[n]["name"]
