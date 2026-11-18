"""What-if remediation simulation.

Actions are resolved to concrete edges and identities of the in-memory graph, then the attack-path
analysis runs twice on the *same* graph with the *same* parameters and risk model: once as-is
(baseline) and once on a filtered traversal index that hides the removed relationships and the
outgoing edges of disabled identities. The base graph is never mutated (``TraversalIndex`` builds a
separate adjacency), and nothing is written to the directory data.
"""

from __future__ import annotations

from collections import Counter
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from app.core.errors import ValidationFailedError
from app.core.jobs import CancellationToken
from app.graph_engine.analysis import AnalysisParams, AnalysisResult, PathAnalyzer
from app.graph_engine.model import ADGraph, EdgeRef
from app.risk_engine.config import SEVERITIES
from app.risk_engine.scoring import RiskScorer

ACL_KINDS = frozenset({"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AddMember", "AddSelf",
                       "ForceChangePassword", "AllExtendedRights", "AddKeyCredentialLink", "ReadLAPSPassword",
                       "ReadGMSAPassword", "WriteSPN", "WriteAccountRestrictions", "AddAllowedToAct",
                       "GetChanges", "GetChangesAll"})
MAX_LISTED_PATHS = 200


class RemoveRelationship(BaseModel):
    type: Literal["remove_relationship"]
    edge_key: int | str = Field(description="ad_edges.id, or a derived key such as dcsync:<src>:<dst>")


class RemoveStep(BaseModel):
    type: Literal["remove_step"]
    src: int
    dst: int


class RemoveMembership(BaseModel):
    type: Literal["remove_membership"]
    member: int
    group: int


class RemoveAcl(BaseModel):
    type: Literal["remove_acl"]
    principal: int
    target: int
    kinds: list[str] | None = Field(default=None, description="default: every ACL-type relationship")


class RemoveAdmin(BaseModel):
    type: Literal["remove_admin"]
    principal: int
    computer: int


class RemoveSession(BaseModel):
    type: Literal["remove_session"]
    user: int
    computer: int | None = Field(default=None, description="omit to remove the user's sessions everywhere")


class DisableIdentity(BaseModel):
    type: Literal["disable_identity"]
    object: int


class ApplyMinCut(BaseModel):
    type: Literal["apply_min_cut"]


Action = Annotated[RemoveRelationship | RemoveStep | RemoveMembership | RemoveAcl | RemoveAdmin | RemoveSession
                   | DisableIdentity | ApplyMinCut, Field(discriminator="type")]


class SimulationRequest(BaseModel):
    actions: list[Action] = Field(min_length=1, max_length=100)


class Simulator:
    def __init__(self, graph: ADGraph, scorer: RiskScorer, params: AnalysisParams):
        self.graph = graph
        self.scorer = scorer
        self.params = params

    # ------------------------------------------------------------------ resolution
    def _node(self, n: int, what: str) -> int:
        if n not in self.graph.g:
            raise ValidationFailedError(f"{what} {n} does not exist in this snapshot.")
        return n

    def _edges(self, u: int, v: int, kinds: frozenset[str] | None, what: str) -> list[EdgeRef]:
        g = self.graph.g
        found = [(u, v, k) for k, d in (g[u][v].items() if g.has_edge(u, v) else [])
                 if kinds is None or d["kind"] in kinds]
        if not found:
            raise ValidationFailedError(f"No {what} relationship from {g.nodes[u]['name']} to {g.nodes[v]['name']}.")
        return found

    def resolve(self, actions: list[Any], baseline: AnalysisResult) -> tuple[set[EdgeRef], set[int], list[dict]]:
        g = self.graph.g
        removed: set[EdgeRef] = set()
        disabled: set[int] = set()
        described: list[dict] = []
        for action in actions:
            if isinstance(action, RemoveRelationship):
                ref = next(((u, v, k) for u, v, k in g.edges(keys=True) if k == action.edge_key), None)
                if ref is None:
                    raise ValidationFailedError(f"Relationship {action.edge_key} does not exist in this snapshot.")
                edges = [ref]
            elif isinstance(action, RemoveStep):
                edges = self._edges(self._node(action.src, "Object"), self._node(action.dst, "Object"), None, "any")
            elif isinstance(action, RemoveMembership):
                edges = self._edges(self._node(action.member, "Member"), self._node(action.group, "Group"),
                                    frozenset({"MemberOf"}), "MemberOf")
            elif isinstance(action, RemoveAcl):
                kinds = frozenset(action.kinds) if action.kinds else ACL_KINDS
                derived = {"DCSync"} if kinds & {"GetChanges", "GetChangesAll"} else set()
                edges = self._edges(self._node(action.principal, "Principal"), self._node(action.target, "Target"),
                                    kinds | derived, "ACL")
            elif isinstance(action, RemoveAdmin):
                edges = self._edges(self._node(action.principal, "Principal"),
                                    self._node(action.computer, "Computer"), frozenset({"AdminTo"}), "AdminTo")
            elif isinstance(action, RemoveSession):
                user = self._node(action.user, "User")
                computers = [self._node(action.computer, "Computer")] if action.computer is not None else \
                    [u for u in g.pred[user] if any(d["kind"] == "HasSession" for d in g[u][user].values())]
                if not computers:
                    raise ValidationFailedError(f"{g.nodes[user]['name']} has no recorded sessions.")
                edges = [e for c in computers for e in self._edges(c, user, frozenset({"HasSession"}), "HasSession")]
            elif isinstance(action, DisableIdentity):
                node = self._node(action.object, "Object")
                disabled.add(node)
                described.append({"type": action.type, "object": self._obj(node)})
                continue
            else:  # ApplyMinCut
                edges = [(s["src"], s["dst"], k) for s in baseline.min_cut.get("steps", []) for k in s["edge_keys"]]
            removed.update(edges)
            described.append({"type": action.type, "relationships": [self._edge(e) for e in edges]})
        return removed, disabled, described

    def _obj(self, n: int) -> dict[str, Any]:
        d = self.graph.g.nodes[n]
        return {"id": n, "object_id": d["oid"], "name": d["name"], "kind": d["kind"]}

    def _edge(self, ref: EdgeRef) -> dict[str, Any]:
        u, v, k = ref
        return {"src": self._obj(u), "dst": self._obj(v), "kind": self.graph.g[u][v][k]["kind"], "edge_key": k}

    # ------------------------------------------------------------------ run
    def run(self, actions: list[Any], *, token: CancellationToken) -> dict[str, Any]:
        analyzer = PathAnalyzer(self.graph)
        before = analyzer.run(self.params, token=token)
        removed, disabled, described = self.resolve(actions, before)
        after = analyzer.run(self.params, token=token, removed_edges=tuple(removed), disabled_nodes=tuple(disabled))

        scores_before = self.scorer.score_analysis(self.graph, before)
        scores_after = self.scorer.score_analysis(self.graph, after)
        env_before = self.scorer.environment_risk(before, scores_before)
        env_after = self.scorer.environment_risk(after, scores_after)

        after_signatures = {p.signature for p in after.paths}
        eliminated = [p for p in before.paths if p.signature not in after_signatures]
        exposed_before, exposed_after = set(before.exposure), set(after.exposure)

        def path_brief(p, scores) -> dict[str, Any]:
            s = scores[p.signature]
            return {"signature": p.signature, "summary": p.summary, "hops": p.hops, "score": s.score,
                    "severity": s.severity, "source": self._obj(p.source), "target": self._obj(p.target)}

        def severity_counts(scores) -> dict[str, int]:
            counts = Counter(s.severity for s in scores.values())
            return {s: counts.get(s, 0) for s in SEVERITIES}

        return {
            "actions": described,
            "removed_relationships": len(removed),
            "disabled_identities": len(disabled),
            "paths_before": len(before.paths),
            "paths_after": len(after.paths),
            "paths_eliminated": len(eliminated),
            "eliminated": [path_brief(p, scores_before) for p in eliminated[:MAX_LISTED_PATHS]],
            "remaining": [path_brief(p, scores_after) for p in after.paths[:MAX_LISTED_PATHS]],
            "exposed_before": len(exposed_before),
            "exposed_after": len(exposed_after),
            "identities_secured": sorted((self._obj(n) for n in exposed_before - exposed_after),
                                         key=lambda o: o["name"]),
            "identities_still_exposed": sorted((self._obj(n) for n in exposed_after), key=lambda o: o["name"]),
            "tier0_still_reachable": [self._obj(t["node"]) | {"sources": t["sources"]} for t in after.target_exposure],
            "severity_before": severity_counts(scores_before),
            "severity_after": severity_counts(scores_after),
            "environment_risk_before": env_before,
            "environment_risk_after": env_after,
            "environment_risk_change": round(env_after["score"] - env_before["score"], 2),
            "min_cut_after": after.min_cut.get("size", 0),
            "truncated": before.truncated or after.truncated,
            "graph_version": self.graph.version,
        }
