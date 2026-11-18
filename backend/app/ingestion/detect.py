"""Format detection for a single data file.

JSON files are scanned once with a streaming parser that records only the top-level keys and a
few small scalar values (``meta.type``, ``meta.version``, ``format`` ...). SharpHound writes
``meta`` *after* the ``data`` array, so the whole file must be scanned; the C parser does this
quickly with flat memory.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from typing import Any

import ijson

from app.core.errors import MalformedInputError, UnsupportedFormatError
from app.ingestion.sources import SourceFile

BLOODHOUND_TYPES = {
    "users", "groups", "computers", "domains", "ous", "gpos", "containers",
    "certtemplates", "enterprisecas", "rootcas", "aiacas", "ntauthstores", "issuancepolicies",
}
_FILENAME_TYPE = re.compile(r"(?:^|[_\-.])(" + "|".join(sorted(BLOODHOUND_TYPES)) + r")\.json$", re.IGNORECASE)
_CAPTURE = {"meta.type", "meta.version", "meta.count", "meta.methods", "meta.collectorversion",
            "format", "version", "collected_at"}


@dataclass
class DetectedFormat:
    family: str  # bloodhound | aegis-json | csv-objects | csv-relationships
    data_type: str | None = None  # bloodhound file type (users, groups, ...)
    version: int | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.family == "bloodhound":
            return f"bloodhound-v{self.version or '?'}:{self.data_type}"
        return self.family


def detect(source: SourceFile) -> DetectedFormat:
    if source.extension == ".csv":
        return _detect_csv(source)
    return _detect_json(source)


def _detect_json(source: SourceFile) -> DetectedFormat:
    keys: list[str] = []
    captured: dict[str, Any] = {}
    top_is_array = False
    try:
        with source.open() as stream:
            for prefix, event, value in ijson.parse(stream, use_float=True):
                if prefix == "" and event == "start_array":
                    top_is_array = True
                    break
                if prefix == "" and event == "map_key":
                    keys.append(value)
                elif prefix in _CAPTURE and event in ("string", "number", "boolean"):
                    captured[prefix] = value
    except ijson.JSONError as exc:
        raise MalformedInputError(f"{source.name}: invalid or truncated JSON ({_short(exc)}).") from exc

    if top_is_array:
        raise UnsupportedFormatError(f"{source.name}: a top-level JSON array is not a supported format.")

    if captured.get("format") == "aegis-inventory":
        return DetectedFormat("aegis-json", version=_int(captured.get("version")),
                              meta={"collected_at": captured.get("collected_at")})

    if "data" in keys:
        data_type = str(captured.get("meta.type", "")).lower() or None
        version = _int(captured.get("meta.version"))
        notes: list[str] = []
        if data_type is None:
            match = _FILENAME_TYPE.search(source.name)
            if match:
                data_type = match.group(1).lower()
                notes.append(f"{source.name}: 'meta' block missing; file type '{data_type}' inferred from the name.")
        if data_type not in BLOODHOUND_TYPES:
            raise UnsupportedFormatError(
                f"{source.name}: unrecognised BloodHound data type {data_type!r}."
                if data_type else f"{source.name}: has a 'data' array but no 'meta.type'; cannot tell what it contains."
            )
        if version is not None and version not in (4, 5, 6):
            notes.append(f"{source.name}: BloodHound format version {version} has not been tested; parsed best-effort.")
        meta = {k.split(".", 1)[1]: v for k, v in captured.items() if k.startswith("meta.")}
        return DetectedFormat("bloodhound", data_type=data_type, version=version, meta=meta, notes=notes)

    if "graph" in keys:
        raise UnsupportedFormatError(f"{source.name}: BloodHound OpenGraph exports are not supported yet.")
    raise UnsupportedFormatError(
        f"{source.name}: not a recognised format (expected SharpHound/BloodHound JSON with 'data' and 'meta', "
        "or an AEGIS inventory with \"format\": \"aegis-inventory\")."
    )


def _detect_csv(source: SourceFile) -> DetectedFormat:
    try:
        with source.open() as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
            header = next(csv.reader(text), None)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise MalformedInputError(f"{source.name}: not a readable UTF-8 CSV file.") from exc
    columns = {h.strip().lower() for h in (header or [])}
    if {"id", "kind", "name"} <= columns:
        return DetectedFormat("csv-objects")
    if {"source", "target", "kind"} <= columns:
        return DetectedFormat("csv-relationships")
    raise UnsupportedFormatError(
        f"{source.name}: CSV header must contain either id,kind,name (objects) or source,target,kind (relationships)."
    )


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _short(exc: Exception) -> str:
    return str(exc).splitlines()[0][:120] if str(exc) else exc.__class__.__name__
