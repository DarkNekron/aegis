"""Compact traversal adjacency built from an ``ADGraph`` (plus optional what-if modifications).

* Only traversable edges are included.
* Edges leaving a tier-0 node are dropped: a path ends at the first tier-0 object it reaches.
* Parallel edges between the same pair of nodes are collapsed into one step. The cheapest edge
  (then the most severe, then the lowest key) represents the step and the others are kept as
  alternatives, so "A -GenericAll-> B" and "A -WriteDacl-> B" do not produce two near-identical paths.
* Removed edges and disabled identities (remediation simulation) are applied here, so the base
  graph is never modified. Building an index is O(E) and much smaller than the graph itself.

Iteration order follows the graph's edge order, which the builder makes deterministic (ORDER BY id),
so tie-breaking between equally good paths is reproducible.
"""

from __future__ import annotations

import gc
from collections import defaultdict
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from app.graph_engine.model import ADGraph, EdgeRef


@dataclass(frozen=True, slots=True)
class Step:
    """One collapsed hop u -> v."""

    key: Any                 # representative edge key
    w: float                 # cost of the representative edge
    keys: tuple[Any, ...]    # every parallel traversable edge key (representative first)


@contextmanager
def gc_paused() -> Iterator[None]:
    """Pause cyclic GC during bulk allocation of acyclic objects.

    Allocating ~10^5 small objects next to a large graph otherwise triggers repeated full-heap
    collections that cost more than the work itself (measured: 2.2 s -> 0.6 s for 114k edges).
    """
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _key_order(key: Any) -> tuple[int, Any]:
    # integer keys (database edges) sort before string keys (derived edges); never compare int with str
    return (1, key) if isinstance(key, str) else (0, key)


class TraversalIndex:
    def __init__(self, graph: ADGraph, *, removed_edges: Iterable[EdgeRef] = (),
                 disabled_nodes: Iterable[int] = ()):
        self.graph = graph
        removed = frozenset(removed_edges)
        self.disabled = frozenset(disabled_nodes)
        self.tier0 = graph.tier0
        self.sources = frozenset(graph.sources - self.disabled)
        tier0, disabled = self.tier0, self.disabled

        with gc_paused():
            best: dict[tuple[int, int], tuple[tuple, list]] = {}
            for u, v, k, d in graph.g.edges(keys=True, data=True):
                if not d["t"] or u in tier0 or u in disabled or (removed and (u, v, k) in removed):
                    continue
                rank = (d["w"], -d["sev"], _key_order(k))
                entry = best.get((u, v))
                if entry is None:
                    best[(u, v)] = (rank, [k])
                else:
                    entry[1].append(k)
                    if rank < entry[0]:
                        best[(u, v)] = (rank, entry[1])

            self.succ: dict[int, dict[int, Step]] = defaultdict(dict)
            self.pred: dict[int, dict[int, Step]] = defaultdict(dict)
            for (u, v), (rank, keys) in best.items():
                rep = rank[2][1]
                ordered = (rep,) if len(keys) == 1 else (rep, *sorted((k for k in keys if k != rep), key=_key_order))
                step = Step(key=rep, w=rank[0], keys=ordered)
                self.succ[u][v] = step
                self.pred[v][u] = step
        self.edge_count = len(best)

    def step(self, u: int, v: int) -> Step:
        return self.succ[u][v]
