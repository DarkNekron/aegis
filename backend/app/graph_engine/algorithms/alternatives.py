"""Alternative and exhaustive path discovery.

* ``k_shortest_paths``: Yen's algorithm for the k shortest *loopless* paths from one source to the
  tier-0 set (paths end at the first tier-0 node).
* ``enumerate_paths``: bounded depth-first enumeration of every simple path from a source to a chosen
  target set, pruned with exact hop distances so branches that cannot finish within the depth bound
  are never explored.
"""

from __future__ import annotations

import heapq
from collections import deque

from app.core.jobs import CancellationToken
from app.graph_engine.algorithms.index import TraversalIndex
from app.graph_engine.algorithms.shortest import forward_shortest, path_length


def k_shortest_paths(index: TraversalIndex, source: int, *, k: int, max_depth: int,
                     token: CancellationToken) -> list[list[int]]:
    first = forward_shortest(index, source, max_hops=max_depth, token=token)
    if first is None or len(first[1]) < 2:
        return []
    accepted: list[list[int]] = [first[1]]
    seen = {tuple(first[1])}
    candidates: list[tuple[int, float, tuple[int, ...]]] = []

    while len(accepted) < k:
        previous = accepted[-1]
        for j in range(len(previous) - 1):
            token.check()
            spur, root = previous[j], previous[: j + 1]
            banned_edges = frozenset((p[j], p[j + 1]) for p in accepted if len(p) > j + 1 and p[: j + 1] == root)
            banned_nodes = frozenset(root[:-1])
            found = forward_shortest(index, spur, max_hops=max_depth - j, token=token,
                                     banned_nodes=banned_nodes, banned_edges=banned_edges)
            if found is None:
                continue
            candidate = tuple(root[:-1]) + tuple(found[1])
            if candidate in seen or len(candidate) - 1 > max_depth:
                continue
            seen.add(candidate)
            hops, cost = path_length(index, list(candidate))
            heapq.heappush(candidates, (hops, cost, candidate))
        if not candidates:
            break
        accepted.append(list(heapq.heappop(candidates)[2]))
    return accepted


def hop_distances_to(index: TraversalIndex, targets: set[int], max_depth: int) -> dict[int, int]:
    """Exact hop distance from every node to the nearest node in ``targets`` (reverse BFS)."""
    dist = dict.fromkeys(targets, 0)
    queue = deque(targets)
    while queue:
        node = queue.popleft()
        if dist[node] >= max_depth:
            continue
        for pred in index.pred.get(node, {}):
            if pred not in dist:
                dist[pred] = dist[node] + 1
                queue.append(pred)
    return dist


def enumerate_paths(index: TraversalIndex, source: int, targets: set[int], *, max_depth: int, limit: int,
                    token: CancellationToken) -> tuple[list[list[int]], bool]:
    """All simple paths source -> targets with at most ``max_depth`` hops. Returns (paths, truncated).

    Targets may be any objects. Because the index has no edges leaving tier-0 nodes, a path never runs
    *through* a tier-0 object to reach a target beyond it.
    """
    dist = hop_distances_to(index, targets, max_depth)
    if source not in dist:
        return [], False
    found: list[list[int]] = []
    stack: list[tuple[int, list[int]]] = [(source, [source])]
    while stack:
        token.checkpoint(128)
        node, path = stack.pop()
        if node in targets and node != source:
            found.append(path)
            if len(found) >= limit:
                return sorted(found, key=lambda p: path_length(index, p)), True
            continue
        depth = len(path) - 1
        for nxt in sorted(index.succ.get(node, {}), reverse=True):
            if nxt in path or nxt not in dist or depth + 1 + dist[nxt] > max_depth:
                continue
            stack.append((nxt, path + [nxt]))
    return sorted(found, key=lambda p: path_length(index, p)), False
