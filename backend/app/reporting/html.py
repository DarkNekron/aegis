"""HTML renderer: Jinja2 with autoescaping on and StrictUndefined (a missing field is an error, not blank)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(report: dict[str, Any]) -> str:
    return _env.get_template("report.html.j2").render(**report)
