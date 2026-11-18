"""Relationship traversal rules: the single source of truth for what an edge *means*.

Ingestion stores what was observed. These rules decide, per relationship type **and target kind**,
whether an attacker who controls the source can use the edge to gain control of the target, whether
that needs conditions to be validated, how costly it is, and how to explain and remediate it.

Anything not listed here is stored and displayed but **never traversed**. The rules implement the
conventions documented in ``sample_data/README.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PRINCIPALS = frozenset({"User", "ServiceAccount"})
CONTAINERS = frozenset({"OU", "Container", "Domain"})
CONTROLLABLE = PRINCIPALS | {"Group", "Computer", "GPO", "OU", "Container", "Domain"}


@dataclass(frozen=True)
class Rule:
    traversable: bool
    conditional: bool = False
    cost: float = 1.0          # relative effort/noise for path ranking (1.0 = trivial)
    severity: float = 0.5      # 0..1 how dangerous the relationship is when present
    technique: str = ""
    explanation: str = ""      # template: {src}, {dst}
    conditions: tuple[str, ...] = ()
    remediation: str = ""

    def explain(self, src: str, dst: str) -> str:
        return self.explanation.format(src=src, dst=dst)

    def remediate(self, src: str, dst: str, kind: str) -> str:
        return self.remediation.format(src=src, dst=dst, kind=kind)


NOT_TRAVERSABLE = Rule(traversable=False, severity=0.1, technique="Informational relationship",
                       explanation="{src} has a recorded relationship to {dst} that AEGIS does not treat as a "
                                   "privilege-escalation step.")


@dataclass(frozen=True)
class KindRules:
    default: Rule
    by_target: dict[str, Rule] = field(default_factory=dict)

    def for_target(self, target_kind: str) -> Rule:
        return self.by_target.get(target_kind, self.default)


def _each(kinds, rule: Rule) -> dict[str, Rule]:
    return dict.fromkeys(kinds, rule)


_TAKEOVER = "Grant itself full control, then take over the object"
_REMOVE_ACE = "Remove the {kind} access-control entry for {src} on {dst} (review delegated administration)."

RULES: dict[str, KindRules] = {
    "MemberOf": KindRules(Rule(
        True, cost=0.5, severity=0.6, technique="Group membership",
        explanation="{src} is a member of {dst} and inherits every right granted to it.",
        remediation="Remove {src} from {dst} if the membership is not required.")),
    "AdminTo": KindRules(NOT_TRAVERSABLE, _each({"Computer"}, Rule(
        True, cost=1.0, severity=0.9, technique="Local administrator",
        explanation="{src} is a local administrator on {dst} and can run code as SYSTEM there.",
        remediation="Remove {src} from the local Administrators group of {dst}; use tiered admin accounts / LAPS."))),
    "HasSession": KindRules(NOT_TRAVERSABLE, _each(PRINCIPALS, Rule(
        True, conditional=True, cost=2.0, severity=0.8, technique="Credential theft from a logon session",
        explanation="{dst} was logged on to {src}; an administrator of {src} can harvest those credentials.",
        conditions=("Sessions are point-in-time observations: confirm the session is still present or recurs.",
                    "Credential theft requires local administrator rights on the host and may be blocked by "
                    "Credential Guard / Protected Users."),
        remediation="Stop {dst} logging on to {src} (tiered administration, Protected Users, Authentication "
                    "Policy Silos)."))),
    "GenericAll": KindRules(NOT_TRAVERSABLE, {
        **_each(PRINCIPALS, Rule(True, cost=1.0, severity=0.95, technique="Full control of an account",
                                 explanation="{src} has full control of {dst} and can reset its password or add "
                                             "credentials.", remediation=_REMOVE_ACE)),
        "Group": Rule(True, cost=1.0, severity=0.95, technique="Full control of a group",
                      explanation="{src} has full control of {dst} and can add itself as a member.",
                      remediation=_REMOVE_ACE),
        "Computer": Rule(True, conditional=True, cost=1.5, severity=0.9, technique="Full control of a computer",
                         explanation="{src} has full control of {dst} (resource-based constrained delegation or "
                                     "LAPS password read).",
                         conditions=("RBCD needs control of an account with an SPN or the ability to create one "
                                     "(MachineAccountQuota), or LAPS must be deployed.",),
                         remediation=_REMOVE_ACE),
        "GPO": Rule(True, cost=1.5, severity=0.95, technique="GPO takeover",
                    explanation="{src} has full control of {dst} and can push code to every object it applies to.",
                    remediation=_REMOVE_ACE),
        **_each({"OU", "Container"}, Rule(True, cost=1.5, severity=0.85, technique="Container takeover",
                                          explanation="{src} has full control of {dst} and can grant itself "
                                                      "rights on the objects it contains (inheritance).",
                                          remediation=_REMOVE_ACE)),
        "Domain": Rule(True, cost=1.0, severity=1.0, technique="Full control of the domain",
                       explanation="{src} has full control of the domain object {dst} and can grant itself DCSync.",
                       remediation=_REMOVE_ACE),
    }),
    "GenericWrite": KindRules(NOT_TRAVERSABLE, {
        **_each(PRINCIPALS, Rule(True, conditional=True, cost=2.0, severity=0.8,
                                 technique="Shadow credentials / targeted Kerberoasting",
                                 explanation="{src} can write attributes of {dst} (msDS-KeyCredentialLink or SPN).",
                                 conditions=("Shadow credentials need PKINIT (AD CS or Windows Server 2016+ DC "
                                             "key trust); Kerberoasting needs a crackable password.",),
                                 remediation=_REMOVE_ACE)),
        "Group": Rule(True, cost=1.0, severity=0.9, technique="Write group membership",
                      explanation="{src} can write the member attribute of {dst} and add itself.",
                      remediation=_REMOVE_ACE),
        "Computer": Rule(True, conditional=True, cost=2.0, severity=0.8,
                         technique="Resource-based constrained delegation",
                         explanation="{src} can write msDS-AllowedToActOnBehalfOfOtherIdentity on {dst}.",
                         conditions=("Requires control of an account with an SPN or MachineAccountQuota > 0.",),
                         remediation=_REMOVE_ACE),
        "GPO": Rule(True, cost=1.5, severity=0.9, technique="GPO modification",
                    explanation="{src} can modify {dst} and push code to every object it applies to.",
                    remediation=_REMOVE_ACE),
        **_each({"OU", "Container"}, Rule(True, conditional=True, cost=2.0, severity=0.7,
                                          technique="GPO linking",
                                          explanation="{src} can write gPLink on {dst} and link a malicious GPO.",
                                          conditions=("Requires the ability to create or control a GPO.",),
                                          remediation=_REMOVE_ACE)),
    }),
    **{kind: KindRules(NOT_TRAVERSABLE, _each(CONTROLLABLE, Rule(
        True, cost=1.5, severity=severity, technique=_TAKEOVER,
        explanation="{src} can " + verb + " {dst} and grant itself full control.", remediation=_REMOVE_ACE)))
       for kind, verb, severity in (("WriteDacl", "modify the permissions of", 0.95),
                                    ("WriteOwner", "take ownership of", 0.95),
                                    ("Owns", "(as owner) change the permissions of", 0.9))},
    **{kind: KindRules(NOT_TRAVERSABLE, _each({"Group"}, Rule(
        True, cost=0.8, severity=0.9, technique="Add member",
        explanation="{src} can add " + ("itself" if kind == "AddSelf" else "any principal") + " to {dst}.",
        remediation=_REMOVE_ACE))) for kind in ("AddMember", "AddSelf")},
    "ForceChangePassword": KindRules(NOT_TRAVERSABLE, _each(PRINCIPALS, Rule(
        True, cost=1.5, severity=0.85, technique="Password reset",
        explanation="{src} can reset the password of {dst} without knowing the current one.",
        conditions=("Resetting a password is disruptive and visible to the account owner.",),
        remediation=_REMOVE_ACE))),
    "AllExtendedRights": KindRules(NOT_TRAVERSABLE, {
        **_each(PRINCIPALS, Rule(True, cost=1.5, severity=0.85, technique="Password reset (extended right)",
                                 explanation="{src} holds all extended rights on {dst}, including password reset.",
                                 remediation=_REMOVE_ACE)),
        "Computer": Rule(True, conditional=True, cost=1.5, severity=0.8, technique="LAPS password read",
                         explanation="{src} holds all extended rights on {dst}, including reading its LAPS password.",
                         conditions=("Only exploitable if LAPS is deployed on the computer.",),
                         remediation=_REMOVE_ACE),
        "Domain": Rule(True, cost=1.0, severity=1.0, technique="DCSync (extended rights)",
                       explanation="{src} holds all extended rights on {dst}, including directory replication.",
                       remediation=_REMOVE_ACE),
    }),
    "AddKeyCredentialLink": KindRules(NOT_TRAVERSABLE, _each(PRINCIPALS | {"Computer"}, Rule(
        True, conditional=True, cost=2.0, severity=0.8, technique="Shadow credentials",
        explanation="{src} can add a key credential to {dst} and authenticate as it.",
        conditions=("Requires PKINIT support (AD CS or a Windows Server 2016+ DC with key trust).",),
        remediation=_REMOVE_ACE))),
    "WriteSPN": KindRules(NOT_TRAVERSABLE, _each(PRINCIPALS, Rule(
        True, conditional=True, cost=2.5, severity=0.6, technique="Targeted Kerberoasting",
        explanation="{src} can set an SPN on {dst} and request a crackable service ticket.",
        conditions=("Only succeeds if the target's password can be cracked offline.",),
        remediation=_REMOVE_ACE))),
    "WriteAccountRestrictions": KindRules(NOT_TRAVERSABLE, _each({"Computer"}, Rule(
        True, conditional=True, cost=2.0, severity=0.8, technique="Resource-based constrained delegation",
        explanation="{src} can write delegation settings on {dst}.",
        conditions=("Requires control of an account with an SPN or MachineAccountQuota > 0.",),
        remediation=_REMOVE_ACE))),
    "ReadLAPSPassword": KindRules(NOT_TRAVERSABLE, _each({"Computer"}, Rule(
        True, cost=1.0, severity=0.9, technique="LAPS password read",
        explanation="{src} can read the local administrator password of {dst}.",
        remediation="Restrict LAPS password read access on {dst} to the appropriate admin tier."))),
    "ReadGMSAPassword": KindRules(NOT_TRAVERSABLE, _each(PRINCIPALS, Rule(
        True, cost=1.0, severity=0.9, technique="gMSA password read",
        explanation="{src} can retrieve the managed password of {dst}.",
        remediation="Limit PrincipalsAllowedToRetrieveManagedPassword on {dst}."))),
    **{kind: KindRules(NOT_TRAVERSABLE, _each({"Computer"}, Rule(
        True, conditional=True, cost=2.0, severity=0.85, technique=title,
        explanation=text, conditions=conds, remediation=fix)))
       for kind, title, text, conds, fix in (
           ("AllowedToAct", "Resource-based constrained delegation",
            "{src} is allowed to act on behalf of other identities to {dst} (RBCD) and can impersonate an "
            "administrator there.",
            ("S4U requires {src} to have an SPN (or a usable TGT for a user without one).",
             "Accounts in Protected Users or marked sensitive cannot be impersonated."),
            "Clear msDS-AllowedToActOnBehalfOfOtherIdentity on {dst} unless the delegation is required."),
           ("AddAllowedToAct", "Configure RBCD",
            "{src} can configure resource-based constrained delegation on {dst}.",
            ("Requires control of an account with an SPN or MachineAccountQuota > 0.",),
            "Remove the right to write msDS-AllowedToActOnBehalfOfOtherIdentity on {dst}."),
           ("AllowedToDelegate", "Constrained delegation",
            "{src} is trusted for constrained delegation to services on {dst} and can impersonate users to it.",
            ("Requires control of {src}'s credentials; protocol transition affects which users can be "
             "impersonated.",),
            "Review msDS-AllowedToDelegateTo on {src}; prefer RBCD scoped to specific accounts."),
       )},
    "HasSIDHistory": KindRules(Rule(
        True, cost=1.0, severity=0.9, technique="SID history",
        explanation="{src} carries the SID of {dst} in its SID history and is treated as {dst}.",
        remediation="Remove the stale SID history from {src}; enable SID filtering on trusts.")),
    "Contains": KindRules(Rule(
        True, cost=0.5, severity=0.5, technique="Inherited control (containment)",
        explanation="{src} contains {dst}; control of {src} propagates to {dst} through inherited permissions.",
        remediation="Block inheritance on {dst} or remove the control held over {src}.")),
    "GPLink": KindRules(NOT_TRAVERSABLE, _each(CONTAINERS, Rule(
        True, cost=1.0, severity=0.85, technique="Group Policy application",
        explanation="{src} is linked to {dst}; whoever controls {src} can execute code on the objects under {dst}.",
        remediation="Restrict who can edit {src} to the same tier as the objects under {dst}."))),
    "DCSync": KindRules(NOT_TRAVERSABLE, _each({"Domain"}, Rule(
        True, cost=1.0, severity=1.0, technique="DCSync",
        explanation="{src} holds both directory replication rights on {dst} and can extract every password hash, "
                    "including krbtgt.",
        remediation="Remove 'Replicating Directory Changes (All)' from {src} on {dst} unless it is a domain "
                    "controller or an approved sync service."))),
}

# Explicitly informational (documented reasons; kept for clarity in the UI and reports).
INFORMATIONAL = {
    "CanRDP": "Interactive logon only; credential theft from sessions requires local administrator rights.",
    "CanPSRemote": "Remote PowerShell logon only; not local administrator.",
    "ExecuteDCOM": "DCOM execution as the user; not local administrator.",
    "TrustedBy": "Cross-domain trust; abuse depends on SID filtering and is not traversed by default.",
    "GetChanges": "Half of DCSync; combined with GetChangesAll AEGIS derives a DCSync edge.",
    "GetChangesAll": "Half of DCSync; combined with GetChanges AEGIS derives a DCSync edge.",
    "GetChangesInFilteredSet": "Filtered replication; not sufficient for DCSync on its own.",
    "SQLAdmin": "Code execution as the SQL Server service account, not necessarily local administrator.",
}


def rule_for(kind: str, target_kind: str) -> Rule:
    """Resolve the rule for an edge. Unknown kinds and unsupported targets are never traversable."""
    kind_rules = RULES.get(kind)
    if kind_rules is None:
        if kind in INFORMATIONAL:
            return Rule(False, severity=0.2, technique="Informational relationship",
                        explanation="{src} -" + kind + "-> {dst}: " + INFORMATIONAL[kind])
        return NOT_TRAVERSABLE
    if target_kind == "Unknown":
        return NOT_TRAVERSABLE  # we cannot reason about control over an object of unknown type
    return kind_rules.for_target(target_kind)


def traversable_kinds() -> frozenset[str]:
    return frozenset(k for k, r in RULES.items()
                     if r.default.traversable or any(x.traversable for x in r.by_target.values()))
