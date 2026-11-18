"""Parser for SharpHound / BloodHound CE JSON (format versions 4-6).

Every relationship is emitted in AEGIS's direction convention, "source can affect destination":

    ACE              principal       -[RightName]->        object
    Members          member          -[MemberOf]->         group
    PrimaryGroupSID  object          -[MemberOf]->         group
    Sessions         computer        -[HasSession]->       user      (credential exposure on the host)
    LocalGroups      principal       -[AdminTo|CanRDP|ExecuteDCOM|CanPSRemote]-> computer
    AllowedToDelegate object         -[AllowedToDelegate]-> computer
    AllowedToAct     principal       -[AllowedToAct]->     computer  (RBCD)
    HasSIDHistory    object          -[HasSIDHistory]->    principal
    ChildObjects / ContainedBy  container -[Contains]->    child
    Links            GPO             -[GPLink]->           OU/domain
    Trusts           trusted domain  -[TrustedBy]->        trusting domain

Ingestion records *what was observed*. Whether an edge is traversable, and under which
conditions, is decided later by the graph engine's rules table (Module 2).
"""

from __future__ import annotations

from typing import Any

import ijson

from app.core.jobs import CancellationToken
from app.ingestion.model import IngestSink, NormalizedEdge, NormalizedObject, canonical_kind
from app.ingestion.sanitize import (
    MAX_NAME,
    MalformedItem,
    clean_properties,
    clean_text,
    normalize_edge_kind,
    normalize_object_id,
    to_bool,
)

TYPE_TO_KIND = {
    "users": "User", "groups": "Group", "computers": "Computer", "domains": "Domain", "ous": "OU",
    "gpos": "GPO", "containers": "Container", "certtemplates": "CertTemplate", "enterprisecas": "EnterpriseCA",
    "rootcas": "RootCA", "aiacas": "AIACA", "ntauthstores": "NTAuthStore", "issuancepolicies": "IssuancePolicy",
}

KEEP_PROPERTIES = frozenset({
    "name", "domain", "domainsid", "distinguishedname", "samaccountname", "displayname", "description",
    "enabled", "admincount", "highvalue", "system_tags", "hasspn", "serviceprincipalnames",
    "unconstraineddelegation", "trustedtoauth", "dontreqpreauth", "passwordnotreqd", "pwdneverexpires",
    "sensitive", "lastlogon", "lastlogontimestamp", "pwdlastset", "whencreated", "operatingsystem", "haslaps",
    "isdc", "sidhistory", "functionallevel", "gmsa", "msa", "isaclprotected", "blocksinheritance", "gpcpath",
})

# Well-known local group RIDs on member servers/workstations -> relationship type
LOCAL_GROUP_RID = {"544": "AdminTo", "555": "CanRDP", "562": "ExecuteDCOM", "580": "CanPSRemote"}
LEGACY_LOCAL_FIELDS = {"LocalAdmins": "AdminTo", "RemoteDesktopUsers": "CanRDP", "DcomUsers": "ExecuteDCOM",
                       "PSRemoteUsers": "CanPSRemote"}
USER_RIGHTS = {"SeRemoteInteractiveLogonRight": "CanRDP"}
# Sessions are point-in-time observations, so confidence is lower than for ACLs/memberships.
SESSION_FIELDS = {"Sessions": 0.7, "PrivilegedSessions": 0.8, "RegistrySessions": 0.6}
TRUST_DIRECTIONS = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _results(block: Any) -> list:
    """SharpHound v4+ wraps API results as {"Results": [...], "Collected": bool}; v3 used a bare list."""
    if isinstance(block, dict):
        return _list(block.get("Results"))
    return _list(block)


def _ref(entry: Any, key: str = "ObjectIdentifier") -> tuple[Any, str | None]:
    if isinstance(entry, dict):
        return entry.get(key), entry.get("ObjectType")
    return entry, None


class _ItemContext:
    """Emits edges for one object while collecting per-edge problems instead of aborting the object."""

    def __init__(self, sink: IngestSink, source: str, location: str, version: int | None):
        self.sink = sink
        self.source = source
        self.location = location
        self.format = f"bloodhound-v{version}" if version else "bloodhound"

    def edge(self, src: Any, dst: Any, kind: str, data_source: str, confidence: float, *, field: str,
             src_kind: Any = None, dst_kind: Any = None, src_name: Any = None, dst_name: Any = None,
             inherited: Any = None, extra: dict[str, Any] | None = None) -> None:
        try:
            src_id = normalize_object_id(src)
            dst_id = normalize_object_id(dst)
            edge_kind = normalize_edge_kind(kind)
        except MalformedItem as exc:
            self.sink.item_error(self.source, f"{self.location}.{field}", str(exc))
            return
        if src_id == dst_id:
            self.sink.count("self_relationships_skipped")
            return
        evidence: dict[str, Any] = {"source_file": self.source, "format": self.format, "field": field}
        if extra:
            evidence.update(extra)
        self.sink.add_edge(NormalizedEdge(
            src_id=src_id, dst_id=dst_id, kind=edge_kind, data_source=data_source, confidence=confidence,
            evidence=evidence, is_inherited=to_bool(inherited),
            src_kind_hint=canonical_kind(src_kind), dst_kind_hint=canonical_kind(dst_kind),
            src_name_hint=clean_text(src_name, MAX_NAME), dst_name_hint=clean_text(dst_name, MAX_NAME),
        ))


def parse_bloodhound(stream, *, source_name: str, data_type: str, version: int | None, sink: IngestSink,
                     token: CancellationToken) -> int:
    """Stream ``data[]`` items into ``sink``. Returns the number of items seen."""
    base_kind = TYPE_TO_KIND[data_type]
    seen = 0
    for index, item in enumerate(ijson.items(stream, "data.item", use_float=True)):
        token.checkpoint(64)
        seen += 1
        location = f"data[{index}]"
        if not isinstance(item, dict):
            sink.item_error(source_name, location, "entry is not a JSON object")
            continue
        try:
            _parse_item(item, base_kind, _ItemContext(sink, source_name, location, version))
        except MalformedItem as exc:
            sink.item_error(source_name, location, str(exc))
    return seen


def _parse_item(item: dict[str, Any], base_kind: str, ctx: _ItemContext) -> None:
    oid = normalize_object_id(item.get("ObjectIdentifier"))
    if to_bool(item.get("IsDeleted")):
        ctx.sink.count("deleted_objects_skipped")
        return
    props = item.get("Properties") if isinstance(item.get("Properties"), dict) else {}

    kind = base_kind
    if base_kind == "User" and any(to_bool(props.get(k)) for k in ("hasspn", "gmsa", "msa")):
        kind = "ServiceAccount"
    name = clean_text(props.get("name") or props.get("samaccountname") or oid, MAX_NAME) or oid
    domain = clean_text(props.get("domain"), 255)
    properties = clean_properties(props, KEEP_PROPERTIES)
    if kind == "ServiceAccount":
        properties["base_kind"] = "User"
    if base_kind == "Computer" and to_bool(item.get("IsDC")) is not None:
        properties["isdc"] = to_bool(item.get("IsDC"))
    ctx.sink.add_object(NormalizedObject(object_id=oid, kind=kind, name=name,
                                         domain=domain.upper() if domain else None,
                                         enabled=to_bool(props.get("enabled")), properties=properties))

    # --- ACLs: principal -[right]-> this object
    for i, ace in enumerate(_list(item.get("Aces"))):
        if not isinstance(ace, dict):
            continue
        right = ace.get("RightName")
        ctx.edge(ace.get("PrincipalSID"), oid, right, "bloodhound:acl", 0.95, field=f"Aces[{i}]",
                 src_kind=ace.get("PrincipalType"), inherited=ace.get("IsInherited"),
                 extra={"right": clean_text(right, 64)})

    # --- Group membership
    for i, member in enumerate(_list(item.get("Members"))):
        mid, mkind = _ref(member)
        ctx.edge(mid, oid, "MemberOf", "bloodhound:membership", 1.0, field=f"Members[{i}]", src_kind=mkind,
                 dst_kind="Group")
    if item.get("PrimaryGroupSID"):
        ctx.edge(oid, item["PrimaryGroupSID"], "MemberOf", "bloodhound:primarygroup", 1.0,
                 field="PrimaryGroupSID", dst_kind="Group", extra={"primary_group": True})

    # --- Delegation, RBCD, SID history, SQL admin
    for i, target in enumerate(_list(item.get("AllowedToDelegate"))):
        tid, tkind = _ref(target)
        ctx.edge(oid, tid, "AllowedToDelegate", "bloodhound:delegation", 0.9, field=f"AllowedToDelegate[{i}]",
                 dst_kind=tkind or "Computer")
    for i, principal in enumerate(_list(item.get("AllowedToAct"))):
        pid, pkind = _ref(principal)
        ctx.edge(pid, oid, "AllowedToAct", "bloodhound:delegation", 0.9, field=f"AllowedToAct[{i}]", src_kind=pkind)
    for i, target in enumerate(_list(item.get("HasSIDHistory"))):
        tid, tkind = _ref(target)
        ctx.edge(oid, tid, "HasSIDHistory", "bloodhound:sidhistory", 0.9, field=f"HasSIDHistory[{i}]",
                 dst_kind=tkind)
    for i, target in enumerate(_list(item.get("SPNTargets"))):
        if isinstance(target, dict) and target.get("Service") == "SQLAdmin":
            ctx.edge(oid, target.get("ComputerSID"), "SQLAdmin", "bloodhound:spntargets", 0.8,
                     field=f"SPNTargets[{i}]", dst_kind="Computer", extra={"port": target.get("Port")})

    # --- Sessions: computer -[HasSession]-> user
    for field_name, confidence in SESSION_FIELDS.items():
        block = item.get(field_name)
        if isinstance(block, dict) and block.get("Collected") is False:
            ctx.sink.count("session_collections_failed")
        for i, result in enumerate(_results(block)):
            if not isinstance(result, dict):
                continue
            ctx.edge(result.get("ComputerSID") or oid, result.get("UserSID"), "HasSession",
                     f"bloodhound:{field_name.lower()}", confidence, field=f"{field_name}[{i}]",
                     src_kind="Computer", dst_kind="User", extra={"method": field_name})

    # --- Local group membership on computers
    for gi, group in enumerate(_list(item.get("LocalGroups"))):
        if not isinstance(group, dict):
            continue
        rid = str(group.get("ObjectIdentifier") or "").rsplit("-", 1)[-1]
        edge_kind = LOCAL_GROUP_RID.get(rid)
        if not edge_kind:
            continue
        for i, member in enumerate(_results(group)):
            mid, mkind = _ref(member)
            ctx.edge(mid, oid, edge_kind, "bloodhound:localgroups", 0.9, field=f"LocalGroups[{gi}].Results[{i}]",
                     src_kind=mkind, dst_kind="Computer", extra={"local_group": clean_text(group.get("Name"), 128)})
    for field_name, edge_kind in LEGACY_LOCAL_FIELDS.items():
        for i, member in enumerate(_results(item.get(field_name))):
            mid, mkind = _ref(member)
            ctx.edge(mid, oid, edge_kind, "bloodhound:localgroups", 0.9, field=f"{field_name}[{i}]", src_kind=mkind,
                     dst_kind="Computer")
    for ri, right in enumerate(_list(item.get("UserRights"))):
        if not isinstance(right, dict):
            continue
        edge_kind = USER_RIGHTS.get(str(right.get("Privilege")))
        if not edge_kind:
            continue
        for i, member in enumerate(_results(right)):
            mid, mkind = _ref(member)
            ctx.edge(mid, oid, edge_kind, "bloodhound:userrights", 0.85, field=f"UserRights[{ri}].Results[{i}]",
                     src_kind=mkind, dst_kind="Computer", extra={"privilege": right.get("Privilege")})

    # --- Containment and GPO links
    for i, child in enumerate(_list(item.get("ChildObjects"))):
        cid, ckind = _ref(child)
        ctx.edge(oid, cid, "Contains", "bloodhound:containment", 1.0, field=f"ChildObjects[{i}]", dst_kind=ckind)
    parent = item.get("ContainedBy")
    if isinstance(parent, dict) and parent.get("ObjectIdentifier"):
        ctx.edge(parent.get("ObjectIdentifier"), oid, "Contains", "bloodhound:containment", 1.0,
                 field="ContainedBy", src_kind=parent.get("ObjectType"))
    for i, link in enumerate(_list(item.get("Links"))):
        if isinstance(link, dict):
            ctx.edge(link.get("GUID"), oid, "GPLink", "bloodhound:gplink", 1.0, field=f"Links[{i}]", src_kind="GPO",
                     extra={"enforced": bool(to_bool(link.get("IsEnforced")))})

    # --- Domain trusts
    for i, trust in enumerate(_list(item.get("Trusts"))):
        if isinstance(trust, dict):
            _trust_edges(trust, oid, i, ctx)


def _trust_edges(trust: dict[str, Any], domain_id: str, index: int, ctx: _ItemContext) -> None:
    raw = trust.get("TrustDirection")
    direction = TRUST_DIRECTIONS.get(raw) if isinstance(raw, int) else str(raw or "").strip().lower()
    target, target_name = trust.get("TargetDomainSid"), trust.get("TargetDomainName")
    extra = {
        "transitive": to_bool(trust.get("IsTransitive")),
        "sid_filtering": to_bool(trust.get("SidFilteringEnabled")),
        "trust_type": clean_text(trust.get("TrustType"), 32),
        "direction": direction,
    }
    field = f"Trusts[{index}]"
    # Outbound: this domain trusts the target -> principals of the target can reach this domain.
    if direction in ("outbound", "bidirectional"):
        ctx.edge(target, domain_id, "TrustedBy", "bloodhound:trusts", 1.0, field=field, src_kind="Domain",
                 src_name=target_name, extra=extra)
    if direction in ("inbound", "bidirectional"):
        ctx.edge(domain_id, target, "TrustedBy", "bloodhound:trusts", 1.0, field=field, dst_kind="Domain",
                 dst_name=target_name, extra=extra)
