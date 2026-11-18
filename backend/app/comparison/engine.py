"""Snapshot comparison through stable keys, computed in SQL.

* Objects are matched on ``object_id`` (SID/GUID), which survives renames.
* Relationships are matched on ``(source object_id, kind, destination object_id)``. Set differences
  use ``EXCEPT`` in the database, so neither graph is loaded and only differences are returned.
* Attack paths are matched on their signature (ordered object ids and relationship kinds), which is
  identical across snapshots for the same route.

Membership changes caused purely by an account being created or deleted (its primary-group
membership) are not repeated under "memberships": they are implied by the account change.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, aliased

from app.core.errors import NotFoundError, ValidationFailedError
from app.models import AdEdge, AdObject, Analysis, AttackPath, Snapshot
from app.simulation.engine import ACL_KINDS

CATEGORIES: dict[str, frozenset[str]] = {
    "memberships": frozenset({"MemberOf"}),
    "admin_rights": frozenset({"AdminTo"}),
    "acl": ACL_KINDS,
    "delegation": frozenset({"AllowedToAct", "AllowedToDelegate", "HasSIDHistory"}),
    "sessions": frozenset({"HasSession"}),
}
PRINCIPAL_KINDS = ("User", "ServiceAccount")


def _category(kind: str) -> str:
    return next((name for name, kinds in CATEGORIES.items() if kind in kinds), "other")


def _edge_keys(snapshot_id: int):
    src, dst = aliased(AdObject), aliased(AdObject)
    return (select(src.object_id.label("src"), AdEdge.kind.label("kind"), dst.object_id.label("dst"))
            .join(src, AdEdge.src_object_pk == src.id).join(dst, AdEdge.dst_object_pk == dst.id)
            .where(AdEdge.snapshot_id == snapshot_id))


class SnapshotComparator:
    def __init__(self, session: Session, limit: int = 500):
        self.s = session
        self.limit = limit

    # ------------------------------------------------------------------ public
    def compare(self, old_id: int, new_id: int, *, old_analysis_id: int | None = None,
                new_analysis_id: int | None = None) -> dict[str, Any]:
        if old_id == new_id:
            raise ValidationFailedError("Choose two different snapshots to compare.")
        old, new = self._snapshot(old_id), self._snapshot(new_id)
        old_analysis = self._analysis(old_id, old_analysis_id)
        new_analysis = self._analysis(new_id, new_analysis_id)

        objects = self._objects(old_id, new_id)
        relationships = {"added": self._edges(new_id, old_id), "removed": self._edges(old_id, new_id)}
        self._drop_lifecycle_memberships(relationships, objects)
        paths = self._paths(old_analysis, new_analysis)
        risk = self._risk(old_analysis, new_analysis)
        report = {
            "old": self._snap_view(old, old_analysis), "new": self._snap_view(new, new_analysis),
            "objects": objects, "relationships": relationships,
            "privilege": {"newly_tier0": objects.pop("_newly_tier0"), "no_longer_tier0": objects.pop("_lost_tier0"),
                          "reliable": bool(old_analysis and new_analysis)},
            "attack_paths": paths, "risk": risk,
        }
        report["summary"] = self._summary(report)
        return report

    # ------------------------------------------------------------------ lookups
    def _snapshot(self, snapshot_id: int) -> Snapshot:
        snap = self.s.get(Snapshot, snapshot_id)
        if snap is None:
            raise NotFoundError(f"Snapshot {snapshot_id} not found.")
        return snap

    def _analysis(self, snapshot_id: int, analysis_id: int | None) -> Analysis | None:
        if analysis_id is not None:
            analysis = self.s.get(Analysis, analysis_id)
            if analysis is None or analysis.snapshot_id != snapshot_id or analysis.status != "succeeded":
                raise ValidationFailedError(f"Analysis {analysis_id} is not a completed analysis of snapshot "
                                            f"{snapshot_id}.")
            return analysis
        return self.s.scalars(select(Analysis).where(Analysis.snapshot_id == snapshot_id,
                                                     Analysis.status == "succeeded")
                              .order_by(Analysis.id.desc())).first()

    @staticmethod
    def _snap_view(snap: Snapshot, analysis: Analysis | None) -> dict[str, Any]:
        return {"id": snap.id, "name": snap.name, "collected_at": snap.collected_at.isoformat()
                if snap.collected_at else None, "is_sample": snap.is_sample,
                "analysis_id": analysis.id if analysis else None}

    # ------------------------------------------------------------------ objects
    def _objects(self, old_id: int, new_id: int) -> dict[str, Any]:
        def ids(snapshot_id: int):
            return select(AdObject.object_id).where(AdObject.snapshot_id == snapshot_id)

        out: dict[str, Any] = {}
        for label, (a, b) in {"added": (new_id, old_id), "removed": (old_id, new_id)}.items():
            diff = ids(a).except_(ids(b)).subquery()
            rows = self.s.execute(select(AdObject.object_id, AdObject.kind, AdObject.name)
                                  .where(AdObject.snapshot_id == a, AdObject.object_id.in_(select(diff.c.object_id)))
                                  .order_by(AdObject.kind, AdObject.name)).all()
            by_kind = Counter(kind for _, kind, _ in rows)
            out[label] = {"count": len(rows), "by_kind": dict(by_kind),
                          "items": [{"object_id": o, "kind": k, "name": n} for o, k, n in rows[: self.limit]]}
        out["users_added"] = sorted(i["name"] for i in out["added"]["items"] if i["kind"] in PRINCIPAL_KINDS)
        out["users_removed"] = sorted(i["name"] for i in out["removed"]["items"] if i["kind"] in PRINCIPAL_KINDS)
        out["groups_added"] = sorted(i["name"] for i in out["added"]["items"] if i["kind"] == "Group")
        out["groups_removed"] = sorted(i["name"] for i in out["removed"]["items"] if i["kind"] == "Group")

        o, n = aliased(AdObject), aliased(AdObject)
        pairs = self.s.execute(
            select(o.object_id, o.kind, n.kind, o.name, n.name, o.enabled, n.enabled, o.is_tier0, n.is_tier0)
            .join(n, and_(n.object_id == o.object_id, n.snapshot_id == new_id))
            .where(o.snapshot_id == old_id,
                   (o.kind != n.kind) | (o.name != n.name) | (o.enabled.is_distinct_from(n.enabled))
                   | (o.is_tier0 != n.is_tier0))
            .order_by(n.name)).all()
        changed, newly, lost = [], [], []
        for oid, k0, k1, n0, n1, e0, e1, t0, t1 in pairs:
            changes = {f: [a, b] for f, a, b in (("kind", k0, k1), ("name", n0, n1), ("enabled", e0, e1),
                                                 ("tier0", t0, t1)) if a != b}
            changed.append({"object_id": oid, "name": n1, "changes": changes})
            if t1 and not t0:
                newly.append(n1)
            elif t0 and not t1:
                lost.append(n1)
        out["changed"] = {"count": len(changed), "items": changed[: self.limit]}
        out["_newly_tier0"], out["_lost_tier0"] = sorted(newly), sorted(lost)
        return out

    # ------------------------------------------------------------------ relationships
    def _edges(self, present_in: int, absent_in: int) -> dict[str, Any]:
        diff = _edge_keys(present_in).except_(_edge_keys(absent_in)).subquery()
        by_kind = dict(self.s.execute(select(diff.c.kind, func.count()).group_by(diff.c.kind)).all())
        names = aliased(AdObject)
        categories: dict[str, Any] = {}
        for name in [*CATEGORIES, "other"]:
            kinds = [k for k in by_kind if _category(k) == name]
            if not kinds:
                continue
            rows = self.s.execute(select(diff.c.src, diff.c.kind, diff.c.dst).where(diff.c.kind.in_(kinds))
                                  .order_by(diff.c.kind, diff.c.src, diff.c.dst).limit(self.limit)).all()
            lookup = dict(self.s.execute(select(names.object_id, names.name).where(
                names.snapshot_id == present_in,
                names.object_id.in_({r[0] for r in rows} | {r[2] for r in rows}))).all())
            categories[name] = {"count": sum(by_kind[k] for k in kinds), "items": [
                {"src": {"object_id": s, "name": lookup.get(s, s)}, "kind": k,
                 "dst": {"object_id": d, "name": lookup.get(d, d)}} for s, k, d in rows]}
        return {"count": sum(by_kind.values()), "by_kind": by_kind, "categories": categories}

    def _drop_lifecycle_memberships(self, relationships: dict[str, Any], objects: dict[str, Any]) -> None:
        """Primary-group memberships of created/deleted accounts are implied by the account change."""
        for side, lifecycle in (("added", "added"), ("removed", "removed")):
            accounts = {i["object_id"] for i in objects[lifecycle]["items"]}
            memberships = relationships[side]["categories"].get("memberships")
            if not memberships or not accounts:
                continue
            primary = self._primary_groups(accounts)
            kept = [i for i in memberships["items"]
                    if not (i["src"]["object_id"] in accounts and i["dst"]["object_id"] in primary)]
            memberships["implied_by_account_changes"] = len(memberships["items"]) - len(kept)
            memberships["count"] -= memberships["implied_by_account_changes"]
            memberships["items"] = kept

    def _primary_groups(self, accounts: set[str]) -> set[str]:
        """Groups that are the primary group (evidence.primary_group) of any of the given accounts."""
        src, dst = aliased(AdObject), aliased(AdObject)
        rows = self.s.execute(select(dst.object_id, AdEdge.evidence)
                              .join(src, AdEdge.src_object_pk == src.id).join(dst, AdEdge.dst_object_pk == dst.id)
                              .where(AdEdge.kind == "MemberOf", src.object_id.in_(accounts))).all()
        return {oid for oid, evidence in rows if (evidence or {}).get("primary_group")}

    # ------------------------------------------------------------------ paths and risk
    def _paths(self, old: Analysis | None, new: Analysis | None) -> dict[str, Any]:
        if old is None or new is None:
            return {"available": False, "reason": "Both snapshots need a completed analysis to compare attack paths."}

        def load(analysis_id: int) -> dict[str, AttackPath]:
            rows = self.s.scalars(select(AttackPath).where(AttackPath.analysis_id == analysis_id)).all()
            return {p.signature: p for p in rows}

        before, after = load(old.id), load(new.id)

        def brief(p: AttackPath) -> dict[str, Any]:
            nodes = (p.details or {}).get("nodes", [])
            return {"signature": p.signature, "summary": (p.details or {}).get("summary"), "score": p.score,
                    "severity": p.severity, "hops": p.hops, "source": nodes[0] if nodes else None}

        appeared = sorted((after[s] for s in after.keys() - before.keys()), key=lambda p: -p.score)
        resolved = sorted((before[s] for s in before.keys() - after.keys()), key=lambda p: -p.score)
        changed = sorted(({"signature": s, "summary": (after[s].details or {}).get("summary"),
                           "old_score": before[s].score, "new_score": after[s].score,
                           "change": round(after[s].score - before[s].score, 2)}
                          for s in before.keys() & after.keys() if before[s].score != after[s].score),
                         key=lambda c: -abs(c["change"]))

        def exposed(paths: dict[str, AttackPath]) -> dict[str, str]:
            out = {}
            for p in paths.values():
                nodes = (p.details or {}).get("nodes", [])
                if nodes:
                    out[nodes[0]["object_id"]] = nodes[0]["name"]
            return out

        old_exposed, new_exposed = exposed(before), exposed(after)
        return {
            "available": True,
            "old_total": len(before), "new_total": len(after),
            "appeared": {"count": len(appeared), "items": [brief(p) for p in appeared[: self.limit]]},
            "resolved": {"count": len(resolved), "items": [brief(p) for p in resolved[: self.limit]]},
            "persisting": len(before.keys() & after.keys()),
            "score_changes": changed[: self.limit],
            "newly_exposed": sorted(new_exposed[o] for o in new_exposed.keys() - old_exposed.keys()),
            "no_longer_exposed": sorted(old_exposed[o] for o in old_exposed.keys() - new_exposed.keys()),
        }

    @staticmethod
    def _risk(old: Analysis | None, new: Analysis | None) -> dict[str, Any]:
        def env(a: Analysis | None) -> dict[str, Any] | None:
            return (a.summary or {}).get("environment_risk") if a else None

        old_env, new_env = env(old), env(new)
        change = round(new_env["score"] - old_env["score"], 2) if old_env and new_env else None
        return {"old": old_env, "new": new_env, "change": change}

    @staticmethod
    def _summary(r: dict[str, Any]) -> list[str]:
        o, rel, p, risk = r["objects"], r["relationships"], r["attack_paths"], r["risk"]
        lines = [f"{o['added']['count']} object(s) added and {o['removed']['count']} removed "
                 f"({len(o['users_added'])} new and {len(o['users_removed'])} removed user account(s)); "
                 f"{o['changed']['count']} object(s) changed."]
        for side in ("added", "removed"):
            parts = [f"{c['count']} {name.replace('_', ' ')}" for name, c in rel[side]["categories"].items()
                     if c["count"]]
            if parts:
                lines.append(f"Relationships {side}: " + ", ".join(parts) + ".")
        if r["privilege"]["newly_tier0"]:
            lines.append("Newly privileged (tier-0): " + ", ".join(r["privilege"]["newly_tier0"]) + ".")
        if p.get("available"):
            lines.append(f"Attack paths: {p['appeared']['count']} new, {p['resolved']['count']} resolved, "
                         f"{p['persisting']} unchanged routes ({p['old_total']} -> {p['new_total']}).")
            if p["newly_exposed"]:
                lines.append("Newly exposed identities: " + ", ".join(p["newly_exposed"]) + ".")
            if p["no_longer_exposed"]:
                lines.append("No longer exposed: " + ", ".join(p["no_longer_exposed"]) + ".")
        else:
            lines.append(p["reason"])
        if risk["change"] is not None:
            direction = "increased" if risk["change"] > 0 else "decreased" if risk["change"] < 0 else "did not change"
            lines.append(f"Environment risk {direction}: {risk['old']['score']} -> {risk['new']['score']} "
                         f"({risk['change']:+.2f}).")
        return lines

