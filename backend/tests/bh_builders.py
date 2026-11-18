"""Builders for SharpHound/BloodHound CE-style test files (format v6 unless stated)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

DOM = "S-1-5-21-1000-2000-3000"
DOMAIN_NAME = "CORP.LOCAL"


def sid(rid: int | str) -> str:
    return f"{DOM}-{rid}"


def bh_file(data_type: str, items: list[dict[str, Any]], version: int = 6) -> dict[str, Any]:
    return {"data": items, "meta": {"methods": 46067, "type": data_type, "count": len(items), "version": version}}


def user(rid: int, name: str, **props) -> dict[str, Any]:
    return {
        "ObjectIdentifier": sid(rid),
        "Properties": {"name": f"{name}@{DOMAIN_NAME}", "domain": DOMAIN_NAME, "enabled": True, **props},
        "PrimaryGroupSID": sid(513), "AllowedToDelegate": [], "HasSIDHistory": [], "SPNTargets": [],
        "Aces": [], "IsDeleted": False, "IsACLProtected": False,
        "ContainedBy": {"ObjectIdentifier": "OU-USERS-GUID", "ObjectType": "OU"},
    }


def group(rid: int | str, name: str, members: list[tuple[str, str]] = (), aces: list[dict] = ()) -> dict[str, Any]:
    gid = rid if isinstance(rid, str) else sid(rid)
    return {
        "ObjectIdentifier": gid,
        "Properties": {"name": f"{name}@{DOMAIN_NAME}", "domain": DOMAIN_NAME, "highvalue": rid in (512, 519)},
        "Members": [{"ObjectIdentifier": m, "ObjectType": t} for m, t in members],
        "Aces": list(aces), "IsDeleted": False, "IsACLProtected": False,
    }


def ace(principal: str, right: str, ptype: str = "User", inherited: bool = False) -> dict[str, Any]:
    return {"PrincipalSID": principal, "PrincipalType": ptype, "RightName": right, "IsInherited": inherited}


def computer(rid: int, name: str, *, sessions: list[str] = (), admins: list[tuple[str, str]] = (),
             rdp: list[tuple[str, str]] = (), allowed_to_act: list[str] = (), is_dc: bool = False) -> dict[str, Any]:
    cid = sid(rid)
    return {
        "ObjectIdentifier": cid,
        "Properties": {"name": f"{name}.{DOMAIN_NAME}", "domain": DOMAIN_NAME, "enabled": True,
                       "operatingsystem": "Windows Server 2022", "isdc": is_dc},
        "PrimaryGroupSID": sid(516 if is_dc else 515),
        "AllowedToDelegate": [],
        "AllowedToAct": [{"ObjectIdentifier": p, "ObjectType": "User"} for p in allowed_to_act],
        "HasSIDHistory": [], "DumpSMSAPassword": [],
        "Sessions": {"Results": [{"UserSID": u, "ComputerSID": cid} for u in sessions], "Collected": True,
                     "FailureReason": None},
        "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
        "RegistrySessions": {"Results": [], "Collected": False, "FailureReason": "access denied"},
        "LocalGroups": [
            {"ObjectIdentifier": f"{cid}-544", "Name": f"ADMINISTRATORS@{name}",
             "Results": [{"ObjectIdentifier": m, "ObjectType": t} for m, t in admins], "Collected": True},
            {"ObjectIdentifier": f"{cid}-555", "Name": f"REMOTE DESKTOP USERS@{name}",
             "Results": [{"ObjectIdentifier": m, "ObjectType": t} for m, t in rdp], "Collected": True},
        ],
        "UserRights": [], "IsDC": is_dc, "Aces": [], "IsDeleted": False,
        "Status": None,
    }


def domain(trusts: list[dict] = (), aces: list[dict] = ()) -> dict[str, Any]:
    return {
        "ObjectIdentifier": DOM,
        "Properties": {"name": DOMAIN_NAME, "domain": DOMAIN_NAME, "functionallevel": "2016"},
        "Trusts": list(trusts),
        "Links": [{"IsEnforced": False, "GUID": "GPO-DEFAULT-GUID"}],
        "ChildObjects": [{"ObjectIdentifier": "OU-USERS-GUID", "ObjectType": "OU"}],
        "Aces": list(aces), "IsDeleted": False, "GPOChanges": {},
    }


def ou(guid: str, name: str, children: list[tuple[str, str]] = ()) -> dict[str, Any]:
    return {"ObjectIdentifier": guid, "Properties": {"name": f"{name}@{DOMAIN_NAME}", "domain": DOMAIN_NAME},
            "ChildObjects": [{"ObjectIdentifier": c, "ObjectType": t} for c, t in children], "Links": [],
            "Aces": [], "IsDeleted": False, "GPOChanges": {}}


def gpo(guid: str, name: str) -> dict[str, Any]:
    return {"ObjectIdentifier": guid, "Properties": {"name": f"{name}@{DOMAIN_NAME}", "domain": DOMAIN_NAME},
            "Aces": [], "IsDeleted": False}


def small_domain() -> dict[str, dict[str, Any]]:
    """A tiny domain with known ground truth.

    alice (1101) -GenericAll-> HELPDESK (1201) ; bob (1102) MemberOf HELPDESK
    HELPDESK -AdminTo-> SRV01 (1301) ; SRV01 -HasSession-> da_admin (1103)
    da_admin MemberOf Domain Admins (512) ; svc_sql (1104, SPN) -AllowedToAct-> SRV01
    """
    users = [user(1101, "ALICE"), user(1102, "BOB"), user(1103, "DA_ADMIN", admincount=True),
             user(1104, "SVC_SQL", hasspn=True, serviceprincipalnames=["MSSQLSvc/srv01.corp.local:1433"])]
    groups = [
        group(1201, "HELPDESK", members=[(sid(1102), "User")], aces=[ace(sid(1101), "GenericAll")]),
        group(512, "DOMAIN ADMINS", members=[(sid(1103), "User")]),
        group(513, "DOMAIN USERS", members=[]),
    ]
    computers = [computer(1301, "SRV01", sessions=[sid(1103)], admins=[(sid(1201), "Group")],
                          allowed_to_act=[sid(1104)]),
                 computer(1000, "DC01", is_dc=True)]
    trusts = [{"TargetDomainSid": "S-1-5-21-9-9-9", "TargetDomainName": "PARTNER.LOCAL", "IsTransitive": True,
               "SidFilteringEnabled": True, "TrustDirection": 2, "TrustType": "External"}]
    return {
        "users": bh_file("users", users),
        "groups": bh_file("groups", groups),
        "computers": bh_file("computers", computers),
        "domains": bh_file("domains", [domain(trusts=trusts)]),
        "ous": bh_file("ous", [ou("OU-USERS-GUID", "USERS", children=[(sid(1101), "User")])]),
        "gpos": bh_file("gpos", [gpo("GPO-DEFAULT-GUID", "DEFAULT DOMAIN POLICY")]),
    }


def write_json(path: Path, content: Any, *, bom: bool = False) -> Path:
    data = json.dumps(content).encode()
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + data)
    return path


def write_zip(path: Path, members: dict[str, bytes | str | dict]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in members.items():
            if isinstance(content, dict):
                content = json.dumps(content)
            zf.writestr(name, content)
    return path


def sharphound_zip(path: Path, files: dict[str, dict] | None = None) -> Path:
    files = files or small_domain()
    return write_zip(path, {f"20261101120000_{t}.json": c for t, c in files.items()})
