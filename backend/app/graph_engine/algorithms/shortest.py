"""Shortest paths.

Path length is compared lexicographically as ``(hops, cost)``: fewest steps first, and among equally
short paths the one with the lowest summed rule cost (the "easiest"). Both searches are Dijkstra
with tuple weights; with uniform hop weights this is exact for the hop count and exact for cost as
a tie-breaker.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass

from app.core.jobs import CancellationToken
from app.graph_engine.algorithms.index import TraversalIndex

Length = tuple[int, float]


@dataclass
class Distances:
    """Result of the reverse search: every node's distance to its nearest tier-0 object."""

    length: dict[int, Length]      # node -> (hops, cost) to nearest tier-0
    next_hop: dict[int, int]       # node -> next node on its best path
    beyond_depth: int              # nodes that reach tier-0 only in more than max_depth hops

    def path(self, source: int) -> list[int] | None:
        if source not in self.length:
            return None
        nodes = [source]
        while nodes[-1] in self.next_hop:
            nodes.append(self.next_hop[nodes[-1]])
        return nodes


def reverse_shortest(index: TraversalIndex, *, max_depth: int, token: CancellationToken) -> Distances:
    """Multi-source Dijkstra from all tier-0 nodes over reversed edges: one pass serves every source."""
    length: dict[int, Length] = {t: (0, 0.0) for t in index.tier0}
    next_hop: dict[int, int] = {}
    heap = [(0, 0.0, t) for t in sorted(index.tier0)]
    heapq.heapify(heap)
    too_deep: set[int] = set()
    while heap:
        hops, cost, node = heapq.heappop(heap)
        if (hops, cost) > length[node]:
            continue
        token.checkpoint(256)
        for pred, step in index.pred.get(node, {}).items():
            candidate = (hops + 1, cost + step.w)
            if candidate[0] > max_depth:
                if pred not in length:
                    too_deep.add(pred)
                continue
            if pred not in length or candidate < length[pred]:
                length[pred] = candidate
                next_hop[pred] = node
                heapq.heappush(heap, (candidate[0], candidate[1], pred))
    return Distances(length=length, next_hop=next_hop, beyond_depth=len(too_deep - length.keys()))


def forward_shortest(index: TraversalIndex, source: int, *, max_hops: int, token: CancellationToken,
                     banned_nodes: frozenset[int] = frozenset(),
                     banned_edges: frozenset[tuple[int, int]] = frozenset()) -> tuple[Length, list[int]] | None:
    """Dijkstra from ``source`` to the nearest tier-0 node, avoiding banned nodes/edges (Yen spur search)."""
    if source in index.tier0:
        return (0, 0.0), [source]
    best: dict[int, Length] = {source: (0, 0.0)}
    parent: dict[int, int] = {}
    heap = [(0, 0.0, source)]
    while heap:
        hops, cost, node = heapq.heappop(heap)
        if (hops, cost) > best[node]:
            continue
        if node in index.tier0:
            path = [node]
            while path[-1] != source:
                path.append(parent[path[-1]])
            return (hops, cost), path[::-1]
        token.checkpoint(256)
        if hops >= max_hops:
            continue
        for nxt, step in index.succ.get(node, {}).items():
            if nxt in banned_nodes or (node, nxt) in banned_edges:
                continue
            candidate = (hops + 1, cost + step.w)
            if nxt not in best or candidate < best[nxt]:
                best[nxt] = candidate
                parent[nxt] = node
                heapq.heappush(heap, (candidate[0], candidate[1], nxt))
    return None


def path_length(index: TraversalIndex, nodes: list[int]) -> Length:
    return len(nodes) - 1, sum(index.succ[a][b].w for a, b in zip(nodes, nodes[1:], strict=False))
