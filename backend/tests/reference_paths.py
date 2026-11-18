"""Deliberately simple REFERENCE implementation of the sample-data conventions (test-only).

It exists to check the hand-derived ground truth independently, and later as an oracle for the
real engine. It favours obviousness over speed: plain BFS/DFS over Python sets. It must never be
imported by application code.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from sqlalchemy import select

from app.models import AdEdge, AdObject

TIER0_GROUP_SUFFIXES = ("-512", "-516", "-518", "-519", "-S-1-5-32-544", "-S-1-5-32-548", "-S-1-5-32-549",
                        "-S-1-5-32-551")
TIER0_USER_SUFFIXES = ("-500", "-502")
CONDITIONAL_KINDS = {"HasSession", "AllowedToAct", "AllowedToDelegate", "AddKeyCredentialLink"}


@dataclass
class RefGraph:
    names: dict[int, str]
    kinds: dict[int, str]
    enabled: dict[int, bool | None]
    placeholder: set[int]
    edges: set[tuple[int, str, int]]
    traversable: frozenset[str]
    tier0: set[int] = field(default_factory=set)
    by_name: dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, session, snapshot_id: int, traversable: list[str]) -> RefGraph:
        objs = session.execute(select(AdObject).where(AdObject.snapshot_id == snapshot_id)).scalars().all()
        g = cls(
            names={o.id: o.name for o in objs}, kinds={o.id: o.kind for o in objs},
            enabled={o.id: o.enabled for o in objs},
            placeholder={o.id for o in objs if (o.properties or {}).get("aegis_placeholder")},
            edges={(e.src_object_pk, e.kind, e.dst_object_pk) for e in
                   session.execute(select(AdEdge).where(AdEdge.snapshot_id == snapshot_id)).scalars()},
            traversable=frozenset(traversable),
        )
        g.by_name = {v: k for k, v in g.names.items()}
        oid = {o.id: o.object_id for o in objs}
        props = {o.id: o.properties or {} for o in objs}

        seeds = set()
        for i, kind in g.kinds.items():
            if i in g.placeholder:
                continue
            is_seed = (
                kind == "Domain"
                or (kind == "Computer" and props[i].get("isdc"))
                or (kind == "Group" and oid[i].endswith(TIER0_GROUP_SUFFIXES))
                or (kind in ("User", "ServiceAccount") and oid[i].endswith(TIER0_USER_SUFFIXES))
            )
            if is_seed:
                seeds.add(i)
        domains = {i for i in seeds if g.kinds[i] == "Domain"}
        # DCSync = both GetChanges and GetChangesAll on a domain; derive the edge
        rights = defaultdict(set)
        for s, k, d in g.edges:
            if d in domains and k in ("GetChanges", "GetChangesAll"):
                rights[(s, d)].add(k)
        for (s, d), have in rights.items():
            if have == {"GetChanges", "GetChangesAll"}:
                g.edges.add((s, "DCSync", d))
                seeds.add(s)
        # transitive membership closure
        tier0 = set(seeds)
        changed = True
        while changed:
            changed = False
            for s, k, d in g.edges:
                if k == "MemberOf" and d in tier0 and s not in tier0:
                    tier0.add(s)
                    changed = True
        g.tier0 = tier0
        return g

    def sources(self) -> set[int]:
        return {i for i, k in self.kinds.items() if k in ("User", "ServiceAccount") and self.enabled.get(i) is True
                and i not in self.tier0 and i not in self.placeholder}

    def _adjacency(self, removed: set[tuple[int, str, int]] = frozenset()) -> dict[int, list[tuple[str, int]]]:
        adj = defaultdict(list)
        for s, k, d in sorted(self.edges):
            if k in self.traversable and (s, k, d) not in removed:
                adj[s].append((k, d))
        return adj

    def shortest_hops(self, removed=frozenset()) -> dict[int, int]:
        """Hop distance from each source to the nearest tier-0 node (reverse multi-source BFS)."""
        reverse = defaultdict(list)
        for s, targets in self._adjacency(removed).items():
            for _, d in targets:
                reverse[d].append(s)
        dist = {t: 0 for t in self.tier0}
        queue = deque(self.tier0)
        while queue:
            node = queue.popleft()
            for pred in reverse[node]:
                if pred not in dist:
                    dist[pred] = dist[node] + 1
                    queue.append(pred)
        return {s: dist[s] for s in self.sources() if s in dist}

    def all_paths(self, max_depth: int = 10, removed=frozenset()) -> list[list[tuple[int, str, int]]]:
        """Every simple path from a source that ends at its first tier-0 node."""
        adj = self._adjacency(removed)
        found = []

        def dfs(node: int, path: list, seen: set) -> None:
            if len(path) >= max_depth:
                return
            for kind, nxt in adj[node]:
                if nxt in seen:
                    continue
                step = path + [(node, kind, nxt)]
                if nxt in self.tier0:
                    found.append(step)
                else:
                    dfs(nxt, step, seen | {nxt})

        for src in sorted(self.sources()):
            dfs(src, [], {src})
        return found

    def named(self, path) -> list[list[str]]:
        return [[self.names[s], k, self.names[d]] for s, k, d in path]

    def edge_ids(self, named_edges) -> set[tuple[int, str, int]]:
        return {(self.by_name[a], k, self.by_name[b]) for a, k, b in named_edges}

    def classify(self, path) -> str:
        for _s, k, d in path:
            if k in CONDITIONAL_KINDS or (k == "GenericWrite" and self.kinds[d] in ("User", "ServiceAccount",
                                                                                    "Computer")):
                return "conditional_attack_path"
        return "potential_privilege_escalation"
