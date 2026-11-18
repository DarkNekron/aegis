"""Sanitisation of untrusted imported values.

Imported data is never trusted. Text is stripped of control characters and of invisible or
bidirectional-override code points (which can disguise names in the UI, "Trojan Source" style),
and capped in length. Identifiers must match a strict pattern.
"""

from __future__ import annotations

import math
import re
from typing import Any

_UNSAFE_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁠-⁩﻿]")
_WHITESPACE = re.compile(r"[\t\r\n]+")
_OBJECT_ID = re.compile(r"^[A-Za-z0-9{][A-Za-z0-9._@{}:\-]{0,127}$")  # "{" allows braced GUIDs
_EDGE_KIND = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
_PROPERTY_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

MAX_NAME = 512
MAX_TEXT = 1024
MAX_LIST_ITEMS = 50
MAX_PROPERTIES = 60


class MalformedItem(Exception):
    """A single record is invalid. It is skipped and reported; the rest of the file still imports."""


def clean_text(value: Any, max_len: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = _UNSAFE_CHARS.sub("", str(value))
    text = _WHITESPACE.sub(" ", text).strip()
    return text[:max_len] if text else None


def normalize_object_id(value: Any) -> str:
    """SIDs and GUIDs are case-insensitive in AD; AEGIS stores them upper-case."""
    text = clean_text(value, 200)
    if not text or not _OBJECT_ID.match(text):
        shown = (text or "")[:40]
        raise MalformedItem(f"invalid object identifier {shown!r}")
    return text.upper()


def normalize_edge_kind(value: Any) -> str:
    text = clean_text(value, 64)
    if not text or not _EDGE_KIND.match(text):
        raise MalformedItem(f"invalid relationship type {(text or '')[:40]!r}")
    return text


def to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "yes", "y", "1"}:
            return True
        if v in {"false", "no", "n", "0"}:
            return False
    return None


def _clean_scalar(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if hasattr(value, "is_finite"):  # decimal.Decimal from a JSON parser
        return float(value) if value.is_finite() else None
    return clean_text(value)


def clean_properties(props: Any, allowed: frozenset[str] | None = None) -> dict[str, Any]:
    """Keep a bounded, JSON-safe subset of properties.

    ``allowed`` restricts keys to a whitelist (BloodHound); otherwise any key matching
    ``[a-z][a-z0-9_]*`` is accepted (custom inventories), up to ``MAX_PROPERTIES`` keys.
    """
    if not isinstance(props, dict):
        return {}
    out: dict[str, Any] = {}
    for raw_key, raw_value in props.items():
        key = str(raw_key).strip().lower()
        if allowed is not None:
            if key not in allowed:
                continue
        elif not _PROPERTY_KEY.match(key):
            continue
        if isinstance(raw_value, list):
            items = [_clean_scalar(v) for v in raw_value[:MAX_LIST_ITEMS] if not isinstance(v, (dict, list))]
            value: Any = [v for v in items if v is not None]
        elif isinstance(raw_value, dict):
            continue
        else:
            value = _clean_scalar(raw_value)
        if value is None or value == []:
            continue
        out[key] = value
        if len(out) >= MAX_PROPERTIES:
            break
    return out
