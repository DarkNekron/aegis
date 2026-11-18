"""Tier-0 (privileged destination) classification.

1. Seeds from well-known identifiers and properties, by configurable category.
2. DCSync holders: principals with both GetChanges and GetChangesAll on a domain.
3. Analyst-defined custom objects.
4. Closure: transitive members of any tier-0 group become tier-0.

Every tier-0 object records *why* it is tier-0. Imported "highvalue" / "admin_tier_0" flags are
untrusted hints: they are recorded but only count if ``trust_input_hints`` is enabled.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from app.graph_engine.config import AnalysisConfig

GROUP_RID_CATEGORY = {"512": "domain_admins", "516": "domain_controllers", "518": "schema_admins",
                      "519": "enterprise_admins", "526": "key_admins", "527": "key_admins"}
BUILTIN_RID_CATEGORY = {"544": "administrators", "548": "operators", "549": "operators", "550": "operators",
                        "551": "operators"}
USER_RID_CATEGORY = {"500": "builtin_accounts", "502": "builtin_accounts"}


@dataclass(frozen=True, slots=True)
class NodeFacts:
    """What the classifier needs to know about one object (collected while streaming nodes)."""

    object_id: str
    kind: str
    name: str
    is_dc: bool
    placeholder: bool
    hinted: bool


def seed_category(f: NodeFacts) -> str | None:
    if f.placeholder:
        return None  # an object we never saw cannot be classified from its identifier alone
    oid = f.object_id
    if f.kind == "Domain":
        return "domain"
    if f.kind == "Computer" and f.is_dc:
        return "domain_controllers"
    rid = oid.rsplit("-", 1)[-1]
    if f.kind == "Group":
        if "-S-1-5-32-" in oid or oid.startswith("S-1-5-32-"):
            return BUILTIN_RID_CATEGORY.get(rid)
        if oid.startswith("S-1-5-21-") or "-S-1-5-21-" in oid:
            return GROUP_RID_CATEGORY.get(rid)
    if f.kind in ("User", "ServiceAccount") and (oid.startswith("S-1-5-21-") or "-S-1-5-21-" in oid):
        return USER_RID_CATEGORY.get(rid)
    return None


class Tier0Classifier:
    def __init__(self, config: AnalysisConfig):
        self.config = config
        self.enabled = set(config.tier0_categories)
        self.custom = set(config.custom_tier0_object_ids)
        self.reasons: dict[int, list[str]] = defaultdict(list)
        self.categories: dict[int, set[str]] = defaultdict(set)
        self.hints: set[int] = set()

    def observe(self, node: int, facts: NodeFacts) -> None:
        category = seed_category(facts)
        if category and category in self.enabled:
            self.reasons[node].append(f"{category.replace('_', ' ')}: {facts.name}")
            self.categories[node].add(category)
        if facts.object_id in self.custom:
            self.reasons[node].append("designated tier-0 by an administrator")
            self.categories[node].add("custom")
        if facts.hinted:
            self.hints.add(node)
            if self.config.trust_input_hints:
                self.reasons[node].append("marked high-value in the imported data")
                self.categories[node].add("hint")

    def add_dcsync(self, node: int, domain_name: str) -> None:
        if "dcsync" in self.enabled:
            self.reasons[node].append(f"holds DCSync rights on {domain_name}")
            self.categories[node].add("dcsync")

    def finish(self, member_of: dict[int, list[int]], names: dict[int, str]) -> dict[int, list[str]]:
        """Propagate tier-0 status to transitive members. ``member_of`` maps group -> direct members."""
        tier0 = set(self.reasons)
        queue = deque(tier0)
        while queue:
            group = queue.popleft()
            for member in member_of.get(group, ()):
                newly_tier0 = member not in tier0
                if newly_tier0:
                    tier0.add(member)
                    self.reasons[member].append(f"member of {names.get(group, group)}")
                # Inherit the group's privilege categories. Re-queue whenever a member gains a category,
                # so someone in both Backup Operators and Domain Admins ends up with both (fixpoint).
                gained = self.categories[group] - self.categories[member]
                if newly_tier0 or gained:
                    self.categories[member] |= self.categories[group]
                    queue.append(member)
        return {node: self.reasons[node] for node in tier0}
