"""Generate AEGIS's synthetic sample datasets and their ground truth.

    python scripts/generate_sample_data.py            # (re)writes sample_data/
    python scripts/generate_sample_data.py --out DIR  # write elsewhere (used by the drift test)

Every dataset is SYNTHETIC: the domain is AEGISLAB.LOCAL, every object description says
"AEGIS synthetic sample data", and ground_truth.json carries "synthetic": true.

Output is byte-for-byte deterministic (fixed seeds, fixed ZIP timestamps, sorted JSON), so the
committed files can be verified against the generator.

The conventions the ground truth assumes are in CONVENTIONS below and in sample_data/README.md;
they are the specification the graph engine (Module 2) and path engine (Module 3) must satisfy.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "AEGISLAB.LOCAL"
DOMAIN_SID = "S-1-5-21-4100000001-4100000002-4100000003"
ZIP_TIME = (2026, 11, 1, 9, 0, 0)
NOTE = "AEGIS synthetic sample data"

CONVENTIONS = {
    "tier0_seeds": [
        "the domain object", "domain controllers (isdc, or members of DOMAIN CONTROLLERS)",
        "groups RID 512 Domain Admins, 516 Domain Controllers, 518 Schema Admins, 519 Enterprise Admins, "
        "526 Key Admins, 527 Enterprise Key Admins",
        "BUILTIN 544 Administrators, 548 Account Operators, 549 Server Operators, 550 Print Operators, "
        "551 Backup Operators",
        "users RID 500 Administrator and 502 krbtgt",
    ],
    "tier0_dcsync": "a principal holding BOTH GetChanges and GetChangesAll on the domain is tier-0",
    "tier0_membership": "transitive members of any tier-0 group are tier-0",
    "sources": "enabled User/ServiceAccount objects that are not tier-0 and not placeholders",
    "path_end": "a path ends at the first tier-0 object it reaches",
    "traversable": [
        "MemberOf", "AdminTo", "HasSession", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
        "AddMember", "AddSelf", "ForceChangePassword", "AllExtendedRights", "AddKeyCredentialLink",
        "ReadLAPSPassword", "ReadGMSAPassword", "AllowedToAct", "AddAllowedToAct", "AllowedToDelegate",
        "HasSIDHistory", "Contains", "GPLink", "DCSync", "WriteSPN", "WriteAccountRestrictions",
    ],
    "not_traversable": {
        "CanRDP / CanPSRemote / ExecuteDCOM": "user-level logon only; harvesting credentials from sessions needs "
                                              "local admin, so these never chain into HasSession",
        "TrustedBy": "trust abuse depends on SID filtering and is informational by default",
        "GetChanges or GetChangesAll alone": "DCSync requires both rights",
        "any unknown relationship type": "stored and shown, never traversed",
    },
    "classification": {
        "potential_privilege_escalation": "every edge is unconditionally abusable",
        "conditional_attack_path": "at least one edge needs validation: HasSession (point-in-time), AllowedToAct / "
                                   "AddAllowedToAct / AllowedToDelegate (Kerberos delegation prerequisites), "
                                   "GenericWrite on a user, computer, OU or container, GenericAll on a computer, "
                                   "AllExtendedRights on a computer (LAPS), AddKeyCredentialLink, WriteSPN, "
                                   "WriteAccountRestrictions",
    },
}


# ----------------------------------------------------------------------------- domain builder
class Lab:
    """Builds a SharpHound v6-shaped dataset with name-based helpers."""

    def __init__(self, sid: str = DOMAIN_SID, name: str = DOMAIN):
        self.sid, self.name = sid, name
        self.objects: dict[str, dict[str, Any]] = {}
        self.kinds: dict[str, str] = {}
        self.by_name: dict[str, str] = {}
        self.order: dict[str, list[str]] = {t: [] for t in
                                            ("users", "groups", "computers", "domains", "ous", "gpos")}
        dom = self._add("domains", "Domain", sid, name, {"functionallevel": "2016", "domainsid": sid})
        dom.update({"Trusts": [], "Links": [], "ChildObjects": [], "GPOChanges": {}})

    # ids
    def rid(self, rid: int) -> str:
        return f"{self.sid}-{rid}"

    def builtin(self, rid: int) -> str:
        return f"{self.name}-S-1-5-32-{rid}"

    @staticmethod
    def guid(label: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"aegislab/{label}")).upper()

    def _add(self, ftype: str, kind: str, oid: str, name: str, props: dict[str, Any]) -> dict[str, Any]:
        if oid in self.objects:
            raise ValueError(f"duplicate object {oid}")
        obj = {"ObjectIdentifier": oid, "Properties": {"name": name, "domain": self.name, "description": NOTE,
                                                       **props},
               "Aces": [], "IsDeleted": False, "IsACLProtected": False}
        self.objects[oid], self.kinds[oid] = obj, kind
        self.by_name[name] = oid
        self.order[ftype].append(oid)
        return obj

    def __getitem__(self, short: str) -> str:
        """Look up an object id by short name ('ALICE', 'DOMAIN ADMINS', 'SRV-APP01', 'DOMAIN')."""
        if short == "DOMAIN":
            return self.sid
        for candidate in (f"{short}@{self.name}", f"{short}.{self.name}", short):
            if candidate in self.by_name:
                return self.by_name[candidate]
        raise KeyError(short)

    def full_name(self, oid: str) -> str:
        return self.objects[oid]["Properties"]["name"]

    # objects
    def user(self, rid: int, short: str, *, enabled: bool = True, spn: bool = False, **props) -> str:
        oid = self.rid(rid)
        extra = {"enabled": enabled, "samaccountname": short.lower(), **props}
        if spn:
            extra.update(hasspn=True, serviceprincipalnames=[f"MSSQLSvc/{short.lower()}.{self.name.lower()}:1433"])
        obj = self._add("users", "User", oid, f"{short}@{self.name}", extra)
        obj.update({"PrimaryGroupSID": self.rid(513), "AllowedToDelegate": [], "HasSIDHistory": [], "SPNTargets": []})
        return oid

    def group(self, rid_or_id: int | str, short: str, **props) -> str:
        oid = self.rid(rid_or_id) if isinstance(rid_or_id, int) else rid_or_id
        self._add("groups", "Group", oid, f"{short}@{self.name}", props)["Members"] = []
        return oid

    def computer(self, rid: int, short: str, *, dc: bool = False) -> str:
        oid = self.rid(rid)
        obj = self._add("computers", "Computer", oid, f"{short}.{self.name}",
                        {"enabled": True, "isdc": dc, "operatingsystem": "Windows Server 2022 Datacenter"})
        obj.update({
            "PrimaryGroupSID": self.rid(516 if dc else 515), "IsDC": dc, "AllowedToDelegate": [], "AllowedToAct": [],
            "HasSIDHistory": [], "Sessions": {"Results": [], "Collected": True, "FailureReason": None},
            "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
            "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
            "LocalGroups": [], "UserRights": [], "Status": None,
        })
        return oid

    def ou(self, short: str) -> str:
        oid = self.guid(f"ou/{short}")
        self._add("ous", "OU", oid, f"{short}@{self.name}", {"blocksinheritance": False}).update(
            {"Links": [], "ChildObjects": [], "GPOChanges": {}})
        return oid

    def gpo(self, short: str) -> str:
        oid = self.guid(f"gpo/{short}")
        self._add("gpos", "GPO", oid, f"{short}@{self.name}", {"gpcpath": f"\\\\{self.name}\\SYSVOL\\{oid}"})
        return oid

    # relationships
    def member(self, member: str, group: str) -> None:
        self.objects[group]["Members"].append({"ObjectIdentifier": member, "ObjectType": self.kinds[member]})

    def ace(self, principal: str, target: str, right: str, *, inherited: bool = False) -> None:
        self.objects[target]["Aces"].append({"PrincipalSID": principal, "PrincipalType": self.kinds[principal],
                                             "RightName": right, "IsInherited": inherited})

    def _local(self, computer: str, rid: int, label: str, principal: str) -> None:
        groups = self.objects[computer]["LocalGroups"]
        gid = f"{computer}-{rid}"
        entry = next((g for g in groups if g["ObjectIdentifier"] == gid), None)
        if entry is None:
            host = self.full_name(computer).split(".")[0]
            entry = {"ObjectIdentifier": gid, "Name": f"{label}@{host}", "Results": [], "LocalNames": [],
                     "Collected": True, "FailureReason": None}
            groups.append(entry)
        entry["Results"].append({"ObjectIdentifier": principal, "ObjectType": self.kinds[principal]})

    def admin(self, principal: str, computer: str) -> None:
        self._local(computer, 544, "ADMINISTRATORS", principal)

    def rdp(self, principal: str, computer: str) -> None:
        self._local(computer, 555, "REMOTE DESKTOP USERS", principal)

    def dcom(self, principal: str, computer: str) -> None:
        self._local(computer, 562, "DISTRIBUTED COM USERS", principal)

    def session(self, user: str, computer: str) -> None:
        self.objects[computer]["Sessions"]["Results"].append({"UserSID": user, "ComputerSID": computer})

    def allowed_to_act(self, principal: str, computer: str) -> None:
        self.objects[computer]["AllowedToAct"].append({"ObjectIdentifier": principal,
                                                       "ObjectType": self.kinds[principal]})

    def contains(self, parent: str, child: str) -> None:
        self.objects[parent]["ChildObjects"].append({"ObjectIdentifier": child, "ObjectType": self.kinds[child]})

    def gplink(self, gpo: str, target: str, enforced: bool = False) -> None:
        self.objects[target]["Links"].append({"IsEnforced": enforced, "GUID": gpo})

    def trust(self, target_sid: str, target_name: str, direction: int) -> None:
        self.objects[self.sid]["Trusts"].append({
            "TargetDomainSid": target_sid, "TargetDomainName": target_name, "IsTransitive": True,
            "SidFilteringEnabled": True, "TrustDirection": direction, "TrustType": "External"})

    def link(self, a: str, kind: str, b: str) -> None:
        """Create relationship ``a -kind-> b`` using the SharpHound field that expresses it."""
        if kind == "MemberOf":
            self.member(a, b)
        elif kind == "AdminTo":
            self.admin(a, b)
        elif kind == "HasSession":
            self.session(b, a)  # computer a holds a session of user b
        elif kind == "GPLink":
            self.gplink(a, b)
        elif kind == "Contains":
            self.contains(a, b)
        else:
            self.ace(a, b, kind)

    def remove_session(self, user: str, computer: str) -> None:
        res = self.objects[computer]["Sessions"]["Results"]
        res[:] = [r for r in res if r["UserSID"] != user]

    def remove_ace(self, principal: str, target: str, right: str) -> None:
        aces = self.objects[target]["Aces"]
        aces[:] = [a for a in aces if not (a["PrincipalSID"] == principal and a["RightName"] == right)]

    def remove_member(self, member: str, group: str) -> None:
        members = self.objects[group]["Members"]
        members[:] = [m for m in members if m["ObjectIdentifier"] != member]

    def delete(self, oid: str) -> None:
        for ids in self.order.values():
            if oid in ids:
                ids.remove(oid)
        name = self.full_name(oid)
        del self.objects[oid], self.kinds[oid], self.by_name[name]

    # standard well-known objects
    def well_known(self) -> None:
        self.user(500, "ADMINISTRATOR", admincount=True)
        self.user(501, "GUEST", enabled=False)
        self.user(502, "KRBTGT", enabled=False)
        for rid, short in [(512, "DOMAIN ADMINS"), (513, "DOMAIN USERS"), (515, "DOMAIN COMPUTERS"),
                           (516, "DOMAIN CONTROLLERS"), (518, "SCHEMA ADMINS"), (519, "ENTERPRISE ADMINS")]:
            self.group(rid, short, highvalue=rid in (512, 516, 518, 519))
        for rid, short in [(544, "ADMINISTRATORS"), (548, "ACCOUNT OPERATORS"), (551, "BACKUP OPERATORS")]:
            self.group(self.builtin(rid), short, highvalue=True)
        self.member(self.rid(500), self.rid(512))
        self.member(self.rid(512), self.builtin(544))
        self.member(self.rid(519), self.builtin(544))
        self.computer(1000, "DC01", dc=True)
        self.member(self.rid(1000), self.rid(516))
        for tier0_group in (self.rid(512), self.rid(519)):
            self.ace(tier0_group, self.sid, "GenericAll", inherited=False)
        self.ace(self.rid(512), self.rid(1000), "GenericAll", inherited=True)

    # output
    def files(self) -> dict[str, dict[str, Any]]:
        out = {}
        for ftype, ids in self.order.items():
            items = [self.objects[i] for i in ids]
            out[ftype] = {"data": items, "meta": {"methods": 521215, "type": ftype, "count": len(items),
                                                  "version": 6, "collectorversion": "aegis-synthetic"}}
        return out

    def write_zip(self, path: Path, prefix: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for ftype, content in self.files().items():
                info = zipfile.ZipInfo(f"{prefix}_{ftype}.json", date_time=ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, json.dumps(content, indent=1, sort_keys=True))


def p(lab: Lab, *steps: str) -> list[list[str]]:
    """Path helper: p(lab, 'ALICE', 'GenericAll', 'HELPDESK', ...) -> [[full_src, kind, full_dst], ...]."""
    names = [lab.full_name(lab[s]) if i % 2 == 0 else s for i, s in enumerate(steps)]
    return [[names[i], names[i + 1], names[i + 2]] for i in range(0, len(names) - 2, 2)]


# ----------------------------------------------------------------------------- corp-small
def build_corp_small(version: int = 1) -> tuple[Lab, dict[str, Any]]:
    lab = Lab()
    lab.well_known()
    users = {"ALICE": 1101, "BOB": 1102, "CAROL": 1103, "DAVE": 1104, "FRANK": 1106, "GRACE": 1108, "HENRY": 1109,
             "DA_JOHN": 1110, "IVAN": 1111}
    for short, rid in users.items():
        lab.user(rid, short)
    lab.user(1105, "ERIN", enabled=False)
    lab.user(1120, "SVC_SQL", spn=True)
    lab.user(1121, "SVC_BACKUP", spn=True)
    lab.user(1122, "SVC_REPL")
    for rid, short in [(1201, "HELPDESK"), (1202, "DEVOPS"), (1203, "IT-ADMINS"), (1204, "REPL-SVC"),
                       (1205, "HALF-REPL"), (1206, "RDP-USERS")]:
        lab.group(rid, short)
    srv_app, srv_sql = lab.computer(1301, "SRV-APP01"), lab.computer(1302, "SRV-SQL01")
    ws01 = lab.computer(1303, "WS01")
    ou_users, ou_servers, ou_ws = lab.ou("USERS"), lab.ou("SERVERS"), lab.ou("WORKSTATIONS")
    gpo_servers = lab.gpo("SERVERS-POLICY")

    for ou_id in (ou_users, ou_servers, ou_ws):
        lab.contains(lab.sid, ou_id)
    for short in [*users, "ERIN", "SVC_SQL", "SVC_BACKUP", "SVC_REPL"]:
        lab.contains(ou_users, lab[short])
    lab.contains(ou_servers, srv_app)
    lab.contains(ou_servers, srv_sql)
    lab.contains(ou_ws, ws01)
    lab.gplink(gpo_servers, ou_servers)

    lab.member(lab["BOB"], lab["HELPDESK"])
    lab.member(lab["CAROL"], lab["DEVOPS"])
    lab.member(lab["IVAN"], lab["IT-ADMINS"])
    lab.member(lab["DA_JOHN"], lab["DOMAIN ADMINS"])
    lab.member(lab["SVC_BACKUP"], lab["BACKUP OPERATORS"])
    lab.member(lab["SVC_REPL"], lab["REPL-SVC"])
    lab.member(lab["HENRY"], lab["HALF-REPL"])
    lab.member(lab["FRANK"], lab["RDP-USERS"])

    lab.ace(lab["ALICE"], lab["HELPDESK"], "GenericAll")
    lab.ace(lab["ALICE"], lab["SVC_BACKUP"], "ForceChangePassword")
    lab.ace(lab["DEVOPS"], lab["IT-ADMINS"], "AddMember")
    lab.ace(lab["IT-ADMINS"], lab["DOMAIN ADMINS"], "WriteDacl")
    lab.ace(lab["DEVOPS"], lab["SVC_SQL"], "GenericAll")
    lab.ace(lab["GRACE"], gpo_servers, "GenericWrite")
    lab.ace(lab["ERIN"], lab["DOMAIN ADMINS"], "GenericAll")
    lab.ace(lab["REPL-SVC"], lab.sid, "GetChanges")
    lab.ace(lab["REPL-SVC"], lab.sid, "GetChangesAll")
    lab.ace(lab["HALF-REPL"], lab.sid, "GetChanges")

    lab.admin(lab["HELPDESK"], srv_app)
    lab.admin(lab["SVC_SQL"], srv_sql)
    lab.session(lab["DA_JOHN"], srv_app)
    lab.rdp(lab["RDP-USERS"], ws01)
    lab.session(lab["CAROL"], ws01)
    lab.allowed_to_act(lab["SVC_SQL"], lab["DC01"])
    lab.trust("S-1-5-21-4200000001-4200000002-4200000003", "PARTNER.LOCAL", 2)

    if version == 1:
        return lab, corp_small_truth(lab)

    # ---- version 2: the same environment one month later
    lab.remove_session(lab["DA_JOHN"], srv_app)                       # remediated
    lab.remove_ace(lab["ALICE"], lab["SVC_BACKUP"], "ForceChangePassword")  # remediated
    lab.remove_member(lab["BOB"], lab["HELPDESK"])                    # BOB moved team...
    lab.member(lab["BOB"], lab["DEVOPS"])                             # ...and gained a path
    lab.user(1112, "KEVIN")
    lab.member(lab["KEVIN"], lab["HELPDESK"])
    lab.contains(ou_users, lab["KEVIN"])
    lab.ace(lab["DAVE"], lab["IT-ADMINS"], "GenericAll")              # new misconfiguration
    ou_users_obj = lab.objects[ou_users]
    ou_users_obj["ChildObjects"] = [c for c in ou_users_obj["ChildObjects"] if c["ObjectIdentifier"] != lab["FRANK"]]
    lab.remove_member(lab["FRANK"], lab["RDP-USERS"])
    lab.delete(lab["FRANK"])                                          # account removed
    return lab, corp_small_v2_truth(lab)


def _tier0_common(lab: Lab) -> list[str]:
    names = ["DOMAIN", "DC01", "DOMAIN ADMINS", "DOMAIN CONTROLLERS", "SCHEMA ADMINS", "ENTERPRISE ADMINS",
             "ADMINISTRATORS", "ACCOUNT OPERATORS", "BACKUP OPERATORS", "ADMINISTRATOR", "KRBTGT",
             "DA_JOHN", "SVC_BACKUP", "REPL-SVC", "SVC_REPL"]
    return sorted(lab.full_name(lab[n]) for n in names)


def corp_small_truth(lab: Lab) -> dict[str, Any]:
    n = lambda s: lab.full_name(lab[s])  # noqa: E731
    session_path = p(lab, "SRV-APP01", "HasSession", "DA_JOHN")
    return {
        "dataset": "corp-small",
        "synthetic": True,
        "description": "Hand-designed lab: six identities with paths to tier-0 (incl. alternatives, a conditional "
                       "session path, RBCD and a GPO chain) plus decoys that must NOT produce paths.",
        "conventions": CONVENTIONS,
        "tier0": _tier0_common(lab),
        "tier0_reasons": {
            n("DA_JOHN"): "member of DOMAIN ADMINS", n("SVC_BACKUP"): "member of BACKUP OPERATORS",
            n("REPL-SVC"): "holds GetChanges + GetChangesAll (DCSync) on the domain",
            n("SVC_REPL"): "member of REPL-SVC (DCSync)",
        },
        "not_tier0": [n("HALF-REPL"), n("IT-ADMINS"), n("ERIN")],
        "sources_with_paths": sorted(n(s) for s in ["ALICE", "BOB", "CAROL", "GRACE", "IVAN", "SVC_SQL"]),
        "sources_without_paths": sorted(n(s) for s in ["DAVE", "FRANK", "HENRY"]),
        "excluded_sources": {n("ERIN"): "disabled account (holds GenericAll on DOMAIN ADMINS)",
                             n("DA_JOHN"): "already tier-0", n("SVC_BACKUP"): "already tier-0",
                             n("SVC_REPL"): "already tier-0"},
        "shortest_hops": {n("ALICE"): 1, n("BOB"): 3, n("CAROL"): 3, n("GRACE"): 4, n("IVAN"): 2, n("SVC_SQL"): 1},
        "all_paths": [
            {"id": "P1", "source": n("ALICE"), "target": n("SVC_BACKUP"), "hops": 1,
             "classification": "potential_privilege_escalation",
             "edges": p(lab, "ALICE", "ForceChangePassword", "SVC_BACKUP"),
             "why": "Resetting SVC_BACKUP's password yields a Backup Operators member (tier-0)."},
            {"id": "P2", "source": n("ALICE"), "target": n("DA_JOHN"), "hops": 3,
             "classification": "conditional_attack_path",
             "edges": p(lab, "ALICE", "GenericAll", "HELPDESK", "AdminTo", "SRV-APP01") + session_path,
             "why": "ALICE can add herself to HELPDESK, which administers SRV-APP01 where DA_JOHN was logged on."},
            {"id": "P3", "source": n("BOB"), "target": n("DA_JOHN"), "hops": 3,
             "classification": "conditional_attack_path",
             "edges": p(lab, "BOB", "MemberOf", "HELPDESK", "AdminTo", "SRV-APP01") + session_path,
             "why": "Local admin on a server holding a Domain Admin session."},
            {"id": "P4", "source": n("CAROL"), "target": n("DOMAIN ADMINS"), "hops": 3,
             "classification": "potential_privilege_escalation",
             "edges": p(lab, "CAROL", "MemberOf", "DEVOPS", "AddMember", "IT-ADMINS", "WriteDacl", "DOMAIN ADMINS"),
             "why": "DEVOPS can add members to IT-ADMINS, which can rewrite the DOMAIN ADMINS ACL."},
            {"id": "P5", "source": n("CAROL"), "target": n("DC01"), "hops": 3,
             "classification": "conditional_attack_path",
             "edges": p(lab, "CAROL", "MemberOf", "DEVOPS", "GenericAll", "SVC_SQL", "AllowedToAct", "DC01"),
             "why": "Control of SVC_SQL (which has an SPN) allows resource-based constrained delegation to DC01."},
            {"id": "P6", "source": n("GRACE"), "target": n("DA_JOHN"), "hops": 4,
             "classification": "conditional_attack_path",
             "edges": p(lab, "GRACE", "GenericWrite", "SERVERS-POLICY", "GPLink", "SERVERS", "Contains",
                        "SRV-APP01") + session_path,
             "why": "Editing a GPO linked to the SERVERS OU gives code execution on SRV-APP01."},
            {"id": "P7", "source": n("IVAN"), "target": n("DOMAIN ADMINS"), "hops": 2,
             "classification": "potential_privilege_escalation",
             "edges": p(lab, "IVAN", "MemberOf", "IT-ADMINS", "WriteDacl", "DOMAIN ADMINS"),
             "why": "IT-ADMINS can grant itself full control of DOMAIN ADMINS."},
            {"id": "P8", "source": n("SVC_SQL"), "target": n("DC01"), "hops": 1,
             "classification": "conditional_attack_path",
             "edges": p(lab, "SVC_SQL", "AllowedToAct", "DC01"),
             "why": "SVC_SQL is trusted for RBCD to a domain controller."},
        ],
        "decoys": [
            {"source": n("FRANK"), "why": "RDP-USERS can only RDP to WS01 (CanRDP is user-level, not admin)."},
            {"source": n("HENRY"), "why": "HALF-REPL holds GetChanges but not GetChangesAll, so no DCSync."},
            {"source": n("DAVE"), "why": "Only a member of DOMAIN USERS, which holds no rights."},
            {"source": n("ERIN"), "why": "Disabled account: not a valid starting identity."},
            {"source": lab.full_name(lab["DOMAIN"]), "why": "Outbound trust to PARTNER.LOCAL is not traversed."},
        ],
        "choke_points": [
            {"edge": session_path[0], "paths_through": 3, "ids": ["P2", "P3", "P6"]},
        ],
        "min_cut": {
            "size": 4,
            "edges": sorted([p(lab, "ALICE", "ForceChangePassword", "SVC_BACKUP")[0], session_path[0],
                             p(lab, "IT-ADMINS", "WriteDacl", "DOMAIN ADMINS")[0],
                             p(lab, "SVC_SQL", "AllowedToAct", "DC01")[0]]),
            "unique": True,
            "edge_disjoint_witness_paths": ["P1", "P3", "P7", "P8"],
        },
        "simulations": [
            {"remove": [session_path[0]], "sources_losing_all_paths": sorted([n("BOB"), n("GRACE")]),
             "sources_still_exposed": sorted([n("ALICE"), n("CAROL"), n("IVAN"), n("SVC_SQL")]),
             "paths_before": 8, "paths_after": 5},
            {"remove": [p(lab, "IT-ADMINS", "WriteDacl", "DOMAIN ADMINS")[0]],
             "sources_losing_all_paths": [n("IVAN")],
             "sources_still_exposed": sorted([n("ALICE"), n("BOB"), n("CAROL"), n("GRACE"), n("SVC_SQL")]),
             "paths_before": 8, "paths_after": 6},
        ],
        "expected_placeholders": ["PARTNER.LOCAL"],
    }


def corp_small_v2_truth(lab: Lab) -> dict[str, Any]:
    n = lambda s: lab.full_name(lab[s])  # noqa: E731
    return {
        "dataset": "corp-small-v2",
        "synthetic": True,
        "description": "corp-small one month later: two paths remediated, one user moved team, one new "
                       "misconfiguration, one account created and one deleted. Use with corp-small for comparison.",
        "conventions": CONVENTIONS,
        "tier0": _tier0_common(lab),
        "sources_with_paths": sorted(n(s) for s in ["BOB", "CAROL", "DAVE", "IVAN", "SVC_SQL"]),
        "sources_without_paths": sorted(n(s) for s in ["ALICE", "GRACE", "HENRY", "KEVIN"]),
        "shortest_hops": {n("BOB"): 3, n("CAROL"): 3, n("DAVE"): 2, n("IVAN"): 2, n("SVC_SQL"): 1},
        "comparison_with": "corp-small",
        "changes": {
            "new_users": [n("KEVIN")],
            "removed_users": [f"FRANK@{DOMAIN}"],
            "membership_added": [[n("BOB"), n("DEVOPS")], [n("KEVIN"), n("HELPDESK")]],
            "membership_removed": [[n("BOB"), n("HELPDESK")], [f"FRANK@{DOMAIN}", n("RDP-USERS")]],
            "relationships_added": [p(lab, "DAVE", "GenericAll", "IT-ADMINS")[0]],
            "relationships_removed": [p(lab, "ALICE", "ForceChangePassword", "SVC_BACKUP")[0],
                                      p(lab, "SRV-APP01", "HasSession", "DA_JOHN")[0]],
            "sources_newly_exposed": [n("DAVE")],
            "sources_no_longer_exposed": sorted([n("ALICE"), n("GRACE")]),
        },
    }


# ----------------------------------------------------------------------------- corp-medium
PLANTED = [
    # (template id, hops, classification, steps). Steps use placeholders resolved per instance.
    ("T1", 1, "potential_privilege_escalation", ["U", "GenericAll", "@DOMAIN ADMINS"]),
    ("T2", 2, "potential_privilege_escalation", ["U", "MemberOf", "G1", "WriteOwner", "@DOMAIN ADMINS"]),
    ("T3", 3, "potential_privilege_escalation",
     ["U", "ForceChangePassword", "U2", "MemberOf", "G1", "AddMember", "@BACKUP OPERATORS"]),
    ("T4", 3, "conditional_attack_path", ["U", "MemberOf", "G1", "AdminTo", "C1", "HasSession", "DA"]),
    ("T5", 4, "conditional_attack_path", ["U", "GenericWrite", "GPO", "GPLink", "OU", "Contains", "C1",
                                          "HasSession", "DA"]),
    ("T6", 5, "potential_privilege_escalation",
     ["U", "MemberOf", "G0", "Owns", "G1", "GenericAll", "U2", "MemberOf", "G2", "AdminTo", "@DC01"]),
    ("T7", 5, "conditional_attack_path",
     ["U", "MemberOf", "G1", "WriteDacl", "U2", "MemberOf", "G2", "AdminTo", "C1", "HasSession", "RU"]),
    ("T8", 8, "potential_privilege_escalation",
     ["U", "MemberOf", "G1", "AddMember", "G2", "MemberOf", "G3", "AddMember", "G4", "MemberOf", "G5", "AddMember",
      "G6", "MemberOf", "G7", "WriteDacl", "@ENTERPRISE ADMINS"]),
]
DECOYS = [
    ("D1", "CanRDP to a server with a Domain Admin session (user-level access only)"),
    ("D2", "member of a group holding only GetChanges on the domain"),
    ("D3", "disabled account with GenericAll on DOMAIN ADMINS"),
    ("D4", "ExecuteDCOM to a server with a Domain Admin session (user-level access only)"),
]


def build_corp_medium(noise_users: int = 3000, instances: int = 3, seed: int = 20261118) -> tuple[Lab, dict]:
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data
    lab = Lab()
    lab.well_known()
    repl = lab.group(1990, "DIRSYNC-SERVICES")
    lab.ace(repl, lab.sid, "GetChanges")
    lab.ace(repl, lab.sid, "GetChangesAll")
    half = lab.group(1991, "SYNC-READERS")
    lab.ace(half, lab.sid, "GetChanges")

    # --- noise: an ordinary organisation that has no route to tier-0 by construction
    rid = 10_000
    n_users, n_groups, n_comps = noise_users, max(20, noise_users // 8), max(10, noise_users // 4)
    noise_users_ids = [lab.user(rid + i, f"USER{i:05d}", enabled=rng.random() > 0.05,
                                spn=rng.random() < 0.01) for i in range(n_users)]
    noise_groups = [lab.group(100_000 + i, f"TEAM{i:04d}") for i in range(n_groups)]
    noise_comps = [lab.computer(200_000 + i, f"HOST{i:05d}") for i in range(n_comps)]
    ou_staff, ou_hosts = lab.ou("STAFF"), lab.ou("HOSTS")
    lab.contains(lab.sid, ou_staff)
    lab.contains(lab.sid, ou_hosts)
    for u in noise_users_ids:
        lab.contains(ou_staff, u)
        for g in rng.sample(noise_groups, 2):
            lab.member(u, g)
    for i, g in enumerate(noise_groups):
        if i + 1 < n_groups and rng.random() < 0.3:
            lab.member(g, noise_groups[rng.randrange(i + 1, n_groups)])  # nesting
        for target in rng.sample(noise_users_ids, 2) + rng.sample(noise_groups, 1):
            if target != g:
                lab.ace(g, target, rng.choice(["GenericAll", "GenericWrite", "WriteDacl", "ForceChangePassword",
                                               "AddMember" if target in noise_groups else "GenericAll"]))
    for c in noise_comps:
        lab.contains(ou_hosts, c)
        lab.admin(rng.choice(noise_groups), c)
        for u in rng.sample(noise_users_ids, 2):
            lab.session(u, c)
        if rng.random() < 0.2:
            lab.rdp(rng.choice(noise_groups), c)

    # --- planted attack paths: private objects, no noise edge ever points into them
    planted, decoys = [], []
    shortest: dict[str, int] = {}
    next_rid = [50_000]

    def new_rid() -> int:
        next_rid[0] += 1
        return next_rid[0]

    for k in range(instances):
        for tid, hops, cls, steps in PLANTED:
            tag = f"{tid}_{k}"
            made: dict[str, str] = {}

            def obj(part: str, made: dict[str, str] = made, tag: str = tag) -> str:  # bind per-chain state
                if part.startswith("@"):
                    return lab[part[1:]]
                if part in made:
                    return made[part]
                short = f"{tag}_{part}"
                if part == "GPO":  # exact tokens first: "GPO" also starts with "G"
                    oid = lab.gpo(short)
                elif part == "OU":
                    oid = lab.ou(short)
                    lab.contains(lab.sid, oid)
                elif part == "DA":
                    oid = lab.user(new_rid(), short)
                    lab.member(oid, lab["DOMAIN ADMINS"])
                elif part.startswith(("U", "RU")):
                    oid = lab.user(new_rid(), short)
                elif part.startswith("G"):
                    oid = lab.group(new_rid(), short)
                elif part.startswith("C"):
                    oid = lab.computer(new_rid(), short)
                else:
                    raise ValueError(part)
                if part == "RU":
                    lab.member(oid, repl)  # DCSync-capable -> tier-0
                made[part] = oid
                return oid

            ids = [obj(t) if i % 2 == 0 else t for i, t in enumerate(steps)]
            edges = []
            for i in range(0, len(ids) - 2, 2):
                a, kind, b = ids[i], ids[i + 1], ids[i + 2]
                lab.link(a, kind, b)
                edges.append([lab.full_name(a), kind, lab.full_name(b)])
            planted.append({"id": tag, "template": tid, "source": edges[0][0], "target": edges[-1][2],
                            "hops": hops, "classification": cls, "edges": edges})
            for pos in range(0, len(steps) - 2, 2):  # intermediate users can also reach tier-0
                part = steps[pos]
                if part.startswith("U"):
                    shortest[lab.full_name(ids[pos])] = hops - pos // 2

        # decoys
        da = lab.user(new_rid(), f"D_{k}_DA")
        lab.member(da, lab["DOMAIN ADMINS"])
        srv = lab.computer(new_rid(), f"D_{k}_SRV")
        lab.session(da, srv)
        d1 = lab.user(new_rid(), f"D1_{k}_U")
        lab.rdp(d1, srv)
        d2 = lab.user(new_rid(), f"D2_{k}_U")
        lab.member(d2, half)
        d3 = lab.user(new_rid(), f"D3_{k}_U", enabled=False)
        lab.ace(d3, lab["DOMAIN ADMINS"], "GenericAll")
        d4 = lab.user(new_rid(), f"D4_{k}_U")
        lab.dcom(d4, srv)
        decoys += [{"id": f"{did}_{k}", "source": lab.full_name(oid), "why": why}
                   for (did, why), oid in zip(DECOYS, (d1, d2, d3, d4), strict=True)]

    truth = {
        "dataset": "corp-medium",
        "synthetic": True,
        "description": f"{n_users} ordinary users in {n_groups} groups on {n_comps} hosts with dense internal "
                       "ACLs, memberships, local admin rights and sessions that by construction never reach "
                       f"tier-0, plus {len(planted)} planted attack paths (templates T1-T8, 1-8 hops) and "
                       f"{len(decoys)} decoys.",
        "conventions": CONVENTIONS,
        "seed": seed,
        "planted_paths": planted,
        "decoys": decoys,
        "shortest_hops": dict(sorted(shortest.items())),
        "sources_with_paths_count": len(shortest),
        "claim": "Exactly the users listed in shortest_hops (chain starts and users inside planted chains) have a "
                 "path to tier-0; every other enabled non-tier-0 user has none.",
    }
    return lab, truth


# ----------------------------------------------------------------------------- inventory example
def inventory_example() -> dict[str, str]:
    objects = ("id,kind,name,domain,enabled,department\n"
               "INV-U-1,User,alice@example.test,EXAMPLE.TEST,true,Finance\n"
               "INV-U-2,User,bob@example.test,EXAMPLE.TEST,true,IT\n"
               "INV-G-1,Group,SERVER-ADMINS@example.test,EXAMPLE.TEST,,\n"
               "INV-C-1,Computer,FILESRV01.example.test,EXAMPLE.TEST,true,\n")
    relationships = ("source,target,kind,confidence,evidence\n"
                     "INV-U-2,INV-G-1,MemberOf,1.0,HR system group export\n"
                     "INV-G-1,INV-C-1,AdminTo,0.9,CMDB local administrators report\n"
                     "INV-C-1,INV-U-1,HasSession,0.6,EDR logon telemetry\n")
    inventory = {"format": "aegis-inventory", "version": 1, "collected_at": "2026-11-01T09:00:00Z",
                 "objects": [{"id": "INV-U-1", "kind": "User", "name": "alice@example.test", "domain": "EXAMPLE.TEST",
                              "enabled": True, "properties": {"department": "Finance", "note": NOTE}},
                             {"id": "INV-G-1", "kind": "Group", "name": "SERVER-ADMINS@example.test"}],
                 "relationships": [{"source": "INV-U-1", "target": "INV-G-1", "kind": "MemberOf",
                                    "confidence": 1.0, "evidence": "Synthetic example"}]}
    return {"objects.csv": objects, "relationships.csv": relationships,
            "inventory.json": json.dumps(inventory, indent=2, sort_keys=True) + "\n"}


# ----------------------------------------------------------------------------- main
def write_all(out: Path) -> list[Path]:
    written = []
    datasets = [("corp-small", *build_corp_small(1)), ("corp-small-v2", *build_corp_small(2)),
                ("corp-medium", *build_corp_medium())]
    for name, lab, truth in datasets:
        folder = out / name
        lab.write_zip(folder / f"{name}.zip", prefix="20261101090000" if name != "corp-small-v2" else "20261201090000")
        (folder / "ground_truth.json").write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n",
                                                  encoding="utf-8", newline="\n")
        written += [folder / f"{name}.zip", folder / "ground_truth.json"]
    inv = out / "inventory-example"
    inv.mkdir(parents=True, exist_ok=True)
    for fname, content in inventory_example().items():
        (inv / fname).write_text(content, encoding="utf-8", newline="\n")
        written.append(inv / fname)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "sample_data")
    args = parser.parse_args()
    for path in write_all(args.out):
        print(f"wrote {path} ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
