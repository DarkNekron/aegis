"""Generates, stores and serves report files (JSON, HTML, PDF).

Files are written under ``<data_dir>/reports`` with random names. Each is recorded in the ``reports``
table with its SHA-256, so a downloaded report can be verified later.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from app.core.config import Settings
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.jobs import CancellationToken
from app.db.session import Database
from app.graph_engine.service import GraphService
from app.models import Analysis, Report
from app.reporting.html import render_html
from app.reporting.model import ReportBuilder
from app.reporting.pdf import render_pdf

FORMATS = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}


def safe_download_name(snapshot_name: str, analysis_id: int, fmt: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", snapshot_name).strip("-.")[:60] or "snapshot"
    return f"aegis-report-{slug}-analysis{analysis_id}.{fmt}"


class ReportService:
    def __init__(self, db: Database, settings: Settings, graphs: GraphService):
        self.db = db
        self.graphs = graphs
        self.directory = settings.data_dir / "reports"

    def generate(self, analysis_id: int, formats: list[str], *, simulation_ids: list[int] | None = None,
                 previous_snapshot_id: int | None = None, generated_by: str | None = None,
                 created_by: int | None = None, token: CancellationToken | None = None) -> list[int]:
        formats = list(dict.fromkeys(formats))
        if not formats or any(f not in FORMATS for f in formats):
            raise ValidationFailedError(f"formats must be a non-empty subset of {', '.join(FORMATS)}.")
        token = token or CancellationToken()
        with self.db.session() as s:
            analysis = s.get(Analysis, analysis_id)
            if analysis is None:
                raise NotFoundError("Analysis not found.")
            snapshot_id = analysis.snapshot_id
        graph = self.graphs.get(snapshot_id, token=token)  # for the minimum-cut simulation
        with self.db.session() as s:
            report = ReportBuilder(s).build(analysis_id, graph=graph, simulation_ids=simulation_ids,
                                            previous_snapshot_id=previous_snapshot_id, generated_by=generated_by,
                                            token=token)
        self.directory.mkdir(parents=True, exist_ok=True)
        ids = []
        for fmt in formats:
            token.check()
            content = self._render(report, fmt)
            path = self.directory / f"{secrets.token_hex(16)}.{fmt}"
            path.write_bytes(content)
            with self.db.session() as s:
                row = Report(snapshot_id=snapshot_id, analysis_id=analysis_id, format=fmt, path=path.name,
                             sha256=hashlib.sha256(content).hexdigest(), created_by=created_by)
                s.add(row)
                s.commit()
                ids.append(row.id)
        return ids

    @staticmethod
    def _render(report: dict[str, Any], fmt: str) -> bytes:
        if fmt == "json":
            return json.dumps(report, indent=2, default=str, ensure_ascii=False).encode("utf-8")
        if fmt == "html":
            return render_html(report).encode("utf-8")
        return render_pdf(report)

    def get(self, report_id: int) -> Report:
        with self.db.session() as s:
            row = s.get(Report, report_id)
            if row is None:
                raise NotFoundError("Report not found.")
            return row

    def file(self, report: Report) -> Path:
        """Resolve the stored file, refusing anything outside the reports directory."""
        path = (self.directory / report.path).resolve()
        if path.parent != self.directory.resolve() or not path.is_file():
            raise NotFoundError("Report file is missing.")
        return path

    def list(self, *, snapshot_id: int | None = None, offset: int = 0, limit: int = 50) -> tuple[int, list[Report]]:
        cond = [Report.snapshot_id == snapshot_id] if snapshot_id is not None else []
        with self.db.session() as s:
            total = s.scalar(select(func.count()).select_from(Report).where(*cond))
            rows = s.scalars(select(Report).where(*cond).order_by(Report.id.desc()).offset(offset).limit(limit))
            return total, list(rows)
