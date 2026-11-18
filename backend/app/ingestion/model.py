"""Normalised, source-independent representation of imported directory data."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

# Canonical object kinds. Keys are lower-case aliases seen in BloodHound/SharpHound and custom inventories.
OBJECT_KINDS: dict[str, str] = {
    "user": "User",
    "group": "Group",
    "computer": "Computer",
    "domain": "Domain",
    "ou": "OU",
    "organizationalunit": "OU",
    "gpo": "GPO",
    "grouppolicyobject": "GPO",
    "container": "Container",
    "serviceaccount": "ServiceAccount",
    "certtemplate": "CertTemplate",
    "enterpriseca": "EnterpriseCA",
    "rootca": "RootCA",
    "aiaca": "AIACA",
    "ntauthstore": "NTAuthStore",
    "issuancepolicy": "IssuancePolicy",
    "localuser": "LocalUser",
    "localgroup": "LocalGroup",
    "unknown": "Unknown",
    "base": "Unknown",
}
CANONICAL_KINDS = frozenset(OBJECT_KINDS.values())
UNKNOWN = "Unknown"


def canonical_kind(value: Any) -> str | None:
    """Map an alias to the canonical kind; ``None`` if unrecognised."""
    if value is None:
        return None
    key = "".join(ch for ch in str(value).lower() if ch.isalnum())
    return OBJECT_KINDS.get(key)


@dataclass(slots=True)
class NormalizedObject:
    object_id: str
    kind: str
    name: str
    domain: str | None = None
    enabled: bool | None = None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedEdge:
    """Directed relationship: ``src`` can affect ``dst``. Endpoints are directory identifiers."""

    src_id: str
    dst_id: str
    kind: str
    data_source: str
    confidence: float
    evidence: dict[str, Any] | None = None
    is_inherited: bool | None = None
    collected_at: datetime | None = None
    src_kind_hint: str | None = None
    dst_kind_hint: str | None = None
    src_name_hint: str | None = None
    dst_name_hint: str | None = None


class IngestSink(Protocol):
    """Where parsers send their output. Implemented by ``ImportSession``."""

    def add_object(self, obj: NormalizedObject) -> None: ...

    def add_edge(self, edge: NormalizedEdge) -> None: ...

    def item_error(self, source: str, location: str, message: str) -> None: ...

    def count(self, counter: str, amount: int = 1) -> None: ...
