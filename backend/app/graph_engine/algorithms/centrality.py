"""Betweenness centrality on the attack-relevant subgraph (Brandes, unweighted, directed).

Only nodes that can reach tier-0 are considered: centrality in the rest of the directory says
nothing about attack paths, and restricting the graph keeps this affordable. With more nodes than
``sample_size``, pivots are sampled uniformly (seeded, so results are reproducible) and the scores
are scaled by n / sample, an unbiased estimate of the exact value.
"""

from __future__ import annotations

import random
from collections import deque

from app.core.jobs import CancellationToken
from app.graph_engine.algorithms.index import TraversalIndex


def betweenness(index: TraversalIndex, nodes: set[int], *, sample_size: int, token: CancellationToken,
                seed: int = 1729) -> tuple[dict[int, float], bool]:
    """Returns (scores, sampled). Scores are un-normalised pair counts, like NetworkX normalized=False."""
    ordered = sorted(nodes)
    sampled = len(ordered) > sample_size
    pivots = random.Random(seed).sample(ordered, sample_size) if sampled else ordered  # noqa: S311
    score = dict.fromkeys(ordered, 0.0)
    for s in pivots:
        token.check()
        stack: list[int] = []
        preds: dict[int, list[int]] = {s: []}
        sigma = {s: 1.0}
        dist = {s: 0}
        queue = deque([s])
        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in index.succ.get(v, {}):
                if w not in nodes:
                    continue
                if w not in dist:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                    sigma[w] = 0.0
                    preds[w] = []
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    preds[w].append(v)
        delta = dict.fromkeys(stack, 0.0)
        while stack:
            w = stack.pop()
            for v in preds[w]:
                delta[v] += sigma[v] / sigma[w] * (1.0 + delta[w])
            if w != s:
                score[w] += delta[w]
    if sampled:
        factor = len(ordered) / len(pivots)
        score = {n: v * factor for n, v in score.items()}
    return score, sampled
