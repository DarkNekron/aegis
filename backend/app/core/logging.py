"""Logging setup with secret redaction.

A filter masks values that look like credentials (``password=...``, ``token: ...``, bearer tokens,
the configured secret key) before records reach any handler, so secrets never land in logs even
if a developer logs a request body by mistake.
"""

from __future__ import annotations

import logging
import re

_SENSITIVE_KV = re.compile(
    r"(?i)(\"?\b(?:password|passwd|pwd|secret|secret_key|token|api[_-]?key|authorization|cookie|csrf[_-]?token)\b\"?"
    r"\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}&]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
REDACTED = "[REDACTED]"


class RedactingFilter(logging.Filter):
    def __init__(self, extra_secrets: list[str] | None = None):
        super().__init__()
        self._literals = [s for s in (extra_secrets or []) if s and len(s) >= 8]

    def redact(self, text: str) -> str:
        for literal in self._literals:
            text = text.replace(literal, REDACTED)
        # Bearer tokens first: otherwise "Authorization: Bearer <tok>" would only redact the word "Bearer".
        text = _BEARER.sub("Bearer " + REDACTED, text)
        return _SENSITIVE_KV.sub(lambda m: m.group(1) + REDACTED, text)

    def filter(self, record: logging.LogRecord) -> bool:
        # Render the message once, redact it, and freeze it so handlers cannot re-expand args.
        try:
            message = record.getMessage()
        except Exception:  # malformed format args: keep the raw template
            message = str(record.msg)
        record.msg = self.redact(message)
        record.args = None
        if record.exc_text:
            record.exc_text = self.redact(record.exc_text)
        return True


def configure_logging(level: str, extra_secrets: list[str] | None = None) -> None:
    root = logging.getLogger()
    root.setLevel(level)
    redactor = RedactingFilter(extra_secrets)
    if not any(getattr(h, "_aegis", False) for h in root.handlers):
        handler = logging.StreamHandler()
        handler._aegis = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        root.addHandler(handler)
    for handler in root.handlers:
        for f in list(handler.filters):
            if isinstance(f, RedactingFilter):
                handler.removeFilter(f)
        handler.addFilter(redactor)
