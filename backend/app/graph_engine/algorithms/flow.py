"""Minimum edge cut between exposed identities and tier-0 (Edmonds-Karp max-flow).

Every collapsed step u -> v has capacity 1 (removing it means removing every parallel relationship
between u and v). A super-source feeds every exposed source and every tier-0 node drains into a
super-sink, both with unbounded capacity. By max-flow/min-cut, the number of edge-disjoint attack
routes equals the smallest number of steps whose removal disconnects *all* sources from tier-0;
the cut is read from the source side of the final residual graph.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from app.core.jobs import CancellationToken
from app.graph_engine.algorithms.index import TraversalIndex

_SOURCE, _SINK = -1, -2
_INF = 1 << 60


@dataclass
class MinCut:
    size: int
    steps: list[tuple[int, int]]   # (u, v) pairs to remove
    sources_considered: int


def min_edge_cut(index: TraversalIndex, sources: set[int], relevant: set[int], *,
                 token: CancellationToken) -> MinCut:
    """``relevant``: nodes that can reach tier-0 (others can never carry flow)."""
    capacity: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for u in relevant:
        if u in index.tier0:
            capacity[u][_SINK] = _INF
            continue
        for v in index.succ.get(u, {}):
            if v in relevant:
                capacity[u][v] += 1
    for s in sources:
        capacity[_SOURCE][s] = _INF
    neighbours: dict[int, set[int]] = defaultdict(set)
    for u, row in list(capacity.items()):
        for v in row:
            neighbours[u].add(v)
            neighbours[v].add(u)  # residual (reverse) direction

    flow = 0
    while True:
        token.check()
        parent = {_SOURCE: _SOURCE}
        queue = deque([_SOURCE])
        while queue and _SINK not in parent:
            node = queue.popleft()
            for nxt in neighbours[node]:
                if nxt not in parent and capacity[node][nxt] > 0:
                    parent[nxt] = node
                    queue.append(nxt)
        if _SINK not in parent:
            break
        bottleneck, node = _INF, _SINK
        while node != _SOURCE:
            bottleneck = min(bottleneck, capacity[parent[node]][node])
            node = parent[node]
        node = _SINK
        while node != _SOURCE:
            capacity[parent[node]][node] -= bottleneck
            capacity[node][parent[node]] += bottleneck
            node = parent[node]
        flow += bottleneck

    reachable = {_SOURCE}
    queue = deque([_SOURCE])
    while queue:
        node = queue.popleft()
        for nxt in neighbours[node]:
            if nxt not in reachable and capacity[node][nxt] > 0:
                reachable.add(nxt)
                queue.append(nxt)
    steps = sorted((u, v) for u in reachable if u >= 0 and u not in index.tier0
                   for v in index.succ.get(u, {}) if v in relevant and v not in reachable)
    return MinCut(size=flow, steps=steps, sources_considered=len(sources))
