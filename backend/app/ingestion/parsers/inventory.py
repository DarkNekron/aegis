"""Parsers for AEGIS custom inventories: JSON (``"format": "aegis-inventory"``) and CSV.

JSON schema (version 1)::

    {
      "format": "aegis-inventory", "version": 1, "collected_at": "2026-11-01T10:00:00Z",
      "objects": [
        {"id": "S-1-5-21-...-1105", "kind": "User", "name": "SVC_SQL@CORP.LOCAL",
         "domain": "CORP.LOCAL", "enabled": true, "properties": {"hasspn": true}}
      ],
      "relationships": [
        {"source": "S-1-5-21-...-1105", "target": "S-1-5-21-...-1201", "kind": "AdminTo",
         "confidence": 0.9, "evidence": "Local admin per CMDB export", "collected_at": "...", "inherited": false}
      ]
    }

CSV: one file of objects (``id,kind,name[,domain,enabled,<extra property columns>]``) and/or one
file of relationships (``source,target,kind[,confidence,evidence,collected_at,data_source]``).
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import ijson
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.jobs import CancellationToken
from app.ingestion.model import CANONICAL_KINDS, IngestSink, NormalizedEdge, NormalizedObject, canonical_kind
from app.ingestion.sanitize import (
    MAX_NAME,
    MalformedItem,
    clean_properties,
    clean_text,
    normalize_edge_kind,
    normalize_object_id,
    to_bool,
)

DEFAULT_CONFIDENCE = 0.8
_ALLOWED_KINDS_TEXT = ", ".join(sorted(CANONICAL_KINDS - {"Unknown"}))


class InventoryObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(max_length=200)
    kind: str = Field(max_length=40)
    name: str | None = Field(default=None, max_length=2000)
    domain: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class InventoryRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(max_length=200)
    target: str = Field(max_length=200)
    kind: str = Field(max_length=64)
    confidence: float = Field(default=DEFAULT_CONFIDENCE, ge=0.0, le=1.0)
    evidence: str | dict[str, Any] | None = None
    collected_at: datetime | None = None
    inherited: bool | None = None
    data_source: str | None = Field(default=None, max_length=64)

    @field_validator("collected_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def _object(record: InventoryObject) -> NormalizedObject:
    oid = normalize_object_id(record.id)
    kind = canonical_kind(record.kind)
    if kind is None or kind == "Unknown":
        raise MalformedItem(f"unknown object kind {record.kind[:40]!r} (allowed: {_ALLOWED_KINDS_TEXT})")
    domain = clean_text(record.domain, 255)
    return NormalizedObject(object_id=oid, kind=kind, name=clean_text(record.name, MAX_NAME) or oid,
                            domain=domain.upper() if domain else None, enabled=record.enabled,
                            properties=clean_properties(record.properties))


def _edge(record: InventoryRelationship, fmt: str, source: str, default_time: datetime | None) -> NormalizedEdge:
    src, dst = normalize_object_id(record.source), normalize_object_id(record.target)
    if src == dst:
        raise MalformedItem("source and target are the same object")
    evidence: dict[str, Any] = {"source_file": source, "format": fmt}
    if isinstance(record.evidence, dict):
        evidence["details"] = clean_properties(record.evidence)
    elif record.evidence:
        evidence["note"] = clean_text(record.evidence)
    data_source = clean_text(record.data_source, 64) or fmt
    return NormalizedEdge(src_id=src, dst_id=dst, kind=normalize_edge_kind(record.kind),
                          data_source=f"inventory:{data_source}", confidence=record.confidence, evidence=evidence,
                          is_inherited=record.inherited, collected_at=record.collected_at or default_time)


def _validation_message(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:3]:
        loc = ".".join(str(p) for p in err.get("loc", ())) or "record"
        parts.append(f"{loc}: {err.get('msg', 'invalid')}")
    return "; ".join(parts)


def parse_inventory_json(opener: Callable[[], Any], *, source_name: str, collected_at: Any, sink: IngestSink,
                         token: CancellationToken) -> int:
    default_time = _parse_time(collected_at)
    seen = 0
    with opener() as stream:
        for index, raw in enumerate(ijson.items(stream, "objects.item", use_float=True)):
            token.checkpoint(64)
            seen += 1
            _handle(sink, source_name, f"objects[{index}]",
                    lambda raw=raw: sink.add_object(_object(InventoryObject.model_validate(raw))))
    with opener() as stream:  # second pass: relationships (may reference objects defined anywhere)
        for index, raw in enumerate(ijson.items(stream, "relationships.item", use_float=True)):
            token.checkpoint(64)
            seen += 1
            _handle(sink, source_name, f"relationships[{index}]",
                    lambda raw=raw: sink.add_edge(_edge(InventoryRelationship.model_validate(raw), "aegis-json",
                                                        source_name, default_time)))
    return seen


def parse_inventory_csv(opener: Callable[[], Any], *, source_name: str, family: str, sink: IngestSink,
                        token: CancellationToken) -> int:
    seen = 0
    with opener() as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
        reader = csv.DictReader(text)
        reader.fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
        for index, row in enumerate(reader, start=2):  # row 1 is the header
            token.checkpoint(64)
            seen += 1
            values = {k: (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k}
            if None in row:
                sink.item_error(source_name, f"row {index}", "row has more columns than the header")
                continue
            if family == "csv-objects":
                _handle(sink, source_name, f"row {index}", lambda v=values: sink.add_object(_csv_object(v)))
            else:
                _handle(sink, source_name, f"row {index}", lambda v=values: sink.add_edge(_csv_edge(v, source_name)))
    return seen


def _csv_object(values: dict[str, str]) -> NormalizedObject:
    core = {"id", "kind", "name", "domain", "enabled"}
    record = InventoryObject(
        id=values.get("id", ""), kind=values.get("kind", ""), name=values.get("name") or None,
        domain=values.get("domain") or None,
        enabled=to_bool(values["enabled"]) if values.get("enabled") else None,
        properties={k: _csv_value(v) for k, v in values.items() if k not in core and v not in ("", None)},
    )
    return _object(record)


def _csv_edge(values: dict[str, str], source_name: str) -> NormalizedEdge:
    record = InventoryRelationship(
        source=values.get("source", ""), target=values.get("target", ""), kind=values.get("kind", ""),
        confidence=float(values["confidence"]) if values.get("confidence") else DEFAULT_CONFIDENCE,
        evidence=values.get("evidence") or None,
        collected_at=values.get("collected_at") or None,
        inherited=to_bool(values["inherited"]) if values.get("inherited") else None,
        data_source=values.get("data_source") or None,
    )
    return _edge(record, "csv", source_name, None)


def _csv_value(value: str) -> Any:
    as_bool = to_bool(value)
    if as_bool is not None and value.lower() in {"true", "false", "yes", "no"}:
        return as_bool
    try:
        return int(value)
    except ValueError:
        return value


def _handle(sink: IngestSink, source: str, location: str, action: Callable[[], None]) -> None:
    try:
        action()
    except ValidationError as exc:
        sink.item_error(source, location, _validation_message(exc))
    except (MalformedItem, ValueError) as exc:
        sink.item_error(source, location, str(exc)[:300])


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
