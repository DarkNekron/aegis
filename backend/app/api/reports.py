"""Report generation and download."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.api.common import Analyst, Limit, Offset, Viewer, iso
from app.core.jobs import JobContext, JobKind
from app.models import Snapshot
from app.reporting.service import FORMATS, safe_download_name
from app.security.audit import audit
from app.security.deps import client_ip

router = APIRouter(prefix="/api", tags=["reports"])


class ReportRequest(BaseModel):
    formats: list[Literal["pdf", "html", "json"]] = Field(default_factory=lambda: ["pdf", "html", "json"],
                                                          min_length=1, max_length=3)
    simulation_ids: list[int] | None = Field(default=None, max_length=50)
    previous_snapshot_id: int | None = None


@router.post("/analyses/{analysis_id}/reports", status_code=202)
def generate_report(analysis_id: int, body: ReportRequest, request: Request, analyst: Analyst) -> dict:
    state = request.app.state
    state.analyses.get(analysis_id)  # 404 before queueing
    user_id, username = analyst.user.id, analyst.user.username

    def run(ctx: JobContext) -> dict:
        ids = state.reports.generate(analysis_id, list(body.formats), simulation_ids=body.simulation_ids,
                                     previous_snapshot_id=body.previous_snapshot_id, generated_by=username,
                                     created_by=user_id, token=ctx.token)
        return {"report_ids": ids}

    job = state.jobs.submit(f"Report for analysis {analysis_id}", run, kind=JobKind.HEAVY)
    audit(analyst.db, "report_generate", "success", user_id=user_id, username=username, target_type="analysis",
          target_id=analysis_id, ip=client_ip(request), detail={"job": job.id, "formats": ",".join(body.formats)})
    return {"job": job.public_view()}


@router.get("/reports")
def list_reports(request: Request, viewer: Viewer, snapshot_id: int | None = None, offset: Offset = 0,
                 limit: Limit = 50) -> dict:
    total, rows = request.app.state.reports.list(snapshot_id=snapshot_id, offset=offset, limit=limit)
    return {"total": total, "items": [{"id": r.id, "snapshot_id": r.snapshot_id, "analysis_id": r.analysis_id,
                                       "format": r.format, "sha256": r.sha256, "created_at": iso(r.created_at)}
                                      for r in rows]}


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, request: Request, viewer: Viewer) -> FileResponse:
    service = request.app.state.reports
    report = service.get(report_id)
    path = service.file(report)
    snapshot = viewer.db.get(Snapshot, report.snapshot_id)
    audit(viewer.db, "report_download", "success", user_id=viewer.user.id, username=viewer.user.username,
          target_type="report", target_id=report_id, ip=client_ip(request))
    # Always an attachment: the HTML report is never rendered inside the AEGIS origin.
    return FileResponse(path, media_type=FORMATS[report.format],
                        filename=safe_download_name(snapshot.name if snapshot else "snapshot", report.analysis_id or 0,
                                                    report.format),
                        content_disposition_type="attachment",
                        headers={"X-Report-SHA256": report.sha256})
