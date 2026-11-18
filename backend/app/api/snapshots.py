"""Snapshots, uploads/imports and the identity explorer."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from starlette.concurrency import run_in_threadpool

from app.api.common import Admin, Analyst, Limit, Offset, Viewer, iso, object_view, snapshot_view
from app.core.errors import ConflictError, LimitExceededError, NotFoundError, ValidationFailedError
from app.core.jobs import JobContext, JobKind
from app.ingestion.uploads import UploadWriter
from app.models import AdEdge, AdObject, ImportJob, Snapshot
from app.security.audit import audit
from app.security.deps import client_ip

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["snapshots"])


class SnapshotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    is_sample: bool = False


def _get_snapshot(db, snapshot_id: int) -> Snapshot:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise NotFoundError("Snapshot not found.")
    return snap


@router.get("/snapshots")
def list_snapshots(viewer: Viewer, offset: Offset = 0, limit: Limit = 50) -> dict:
    db = viewer.db
    total = db.scalar(select(func.count()).select_from(Snapshot))
    rows = db.scalars(select(Snapshot).order_by(Snapshot.id.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [snapshot_view(s) for s in rows]}


@router.post("/snapshots", status_code=201)
def create_snapshot(body: SnapshotCreate, request: Request, analyst: Analyst) -> dict:
    sid = request.app.state.imports.create_snapshot(body.name, description=body.description,
                                                    is_sample=body.is_sample, created_by=analyst.user.id)
    audit(analyst.db, "snapshot_create", "success", user_id=analyst.user.id, username=analyst.user.username,
          target_type="snapshot", target_id=sid, ip=client_ip(request), detail={"name": body.name})
    return snapshot_view(_get_snapshot(analyst.db, sid))


@router.get("/snapshots/{snapshot_id}")
def get_snapshot(snapshot_id: int, viewer: Viewer) -> dict:
    snap = _get_snapshot(viewer.db, snapshot_id)
    imports = viewer.db.scalars(select(ImportJob).where(ImportJob.snapshot_id == snapshot_id)
                                .order_by(ImportJob.id.desc()).limit(100)).all()
    return snapshot_view(snap) | {"imports": [
        {"id": i.id, "filename": i.filename, "size_bytes": i.size_bytes, "sha256": i.sha256, "status": i.status,
         "format": i.detected_format, "created_at": iso(i.created_at), "finished_at": iso(i.finished_at),
         "summary": i.summary, "errors": i.errors} for i in imports]}


@router.delete("/snapshots/{snapshot_id}")
def delete_snapshot(snapshot_id: int, request: Request, admin: Admin) -> dict:
    snap = _get_snapshot(admin.db, snapshot_id)
    if snap.status == "importing":
        raise ConflictError("Wait for the running import to finish before deleting this snapshot.")
    name = snap.name
    admin.db.delete(snap)
    admin.db.commit()
    request.app.state.graphs.cache.invalidate(snapshot_id)
    audit(admin.db, "snapshot_delete", "success", user_id=admin.user.id, username=admin.user.username,
          target_type="snapshot", target_id=snapshot_id, ip=client_ip(request), detail={"name": name})
    return {"status": "deleted"}


@router.post("/snapshots/{snapshot_id}/imports", status_code=202)
async def upload(snapshot_id: int, request: Request, analyst: Analyst,
                 filename: Annotated[str, Query(min_length=1, max_length=255)]) -> dict:
    """Upload one .zip/.json/.csv file as the raw request body (application/octet-stream).

    The size limit is enforced while streaming, before anything is parsed. The import then runs as a
    background job; poll ``GET /api/jobs/{id}``.
    """
    settings = request.app.state.settings
    _get_snapshot(analyst.db, snapshot_id)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_upload_bytes:
        raise LimitExceededError(f"The file exceeds the maximum upload size of {settings.max_upload_mb} MB.")
    request.app.state.resources.ensure_disk_space()

    writer = UploadWriter(settings.data_dir / "uploads", filename, settings.max_upload_bytes)
    try:
        async for chunk in request.stream():
            # file I/O off the event loop; raises (and deletes the partial file) when the limit is crossed
            await run_in_threadpool(writer.write, chunk)
        saved = await run_in_threadpool(writer.finish)
    except Exception:
        writer.abort()
        raise
    if saved.size == 0:
        saved.path.unlink(missing_ok=True)
        raise ValidationFailedError("The uploaded file is empty.")

    imports, graphs = request.app.state.imports, request.app.state.graphs
    user_id = analyst.user.id

    def run(ctx: JobContext) -> dict:
        try:
            result = imports.import_file(snapshot_id, saved.path, saved.original_name, token=ctx.token,
                                         progress=ctx.report_progress, sha256=saved.sha256, created_by=user_id)
            return {"import_job_id": result.import_job_id, "status": result.status}
        finally:
            saved.path.unlink(missing_ok=True)  # raw directory data is not retained after import
            graphs.cache.invalidate(snapshot_id)

    try:
        job = request.app.state.jobs.submit(f"Import {saved.original_name}", run, kind=JobKind.LIGHT)
    except Exception:
        saved.path.unlink(missing_ok=True)
        raise
    audit(analyst.db, "import_submit", "success", user_id=analyst.user.id, username=analyst.user.username,
          target_type="snapshot", target_id=snapshot_id, ip=client_ip(request),
          detail={"file": saved.original_name, "size": saved.size, "sha256": saved.sha256, "job": job.id})
    return {"job": job.public_view()}


@router.get("/snapshots/{snapshot_id}/objects")
def search_objects(snapshot_id: int, viewer: Viewer, offset: Offset = 0, limit: Limit = 50,
                   q: Annotated[str | None, Query(max_length=200)] = None,
                   kind: Annotated[str | None, Query(max_length=32)] = None,
                   tier0: bool | None = None) -> dict:
    _get_snapshot(viewer.db, snapshot_id)
    conditions = [AdObject.snapshot_id == snapshot_id]
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        conditions.append(or_(AdObject.name.ilike(pattern, escape="\\"),
                              AdObject.object_id.ilike(pattern, escape="\\")))
    if kind:
        conditions.append(AdObject.kind == kind)
    if tier0 is not None:
        conditions.append(AdObject.is_tier0.is_(tier0))
    total = viewer.db.scalar(select(func.count()).select_from(AdObject).where(*conditions))
    rows = viewer.db.scalars(select(AdObject).where(*conditions).order_by(AdObject.name, AdObject.id)
                             .offset(offset).limit(limit)).all()
    return {"total": total, "items": [object_view(o) for o in rows]}


@router.get("/objects/{object_pk}")
def get_object(object_pk: int, viewer: Viewer) -> dict:
    obj = viewer.db.get(AdObject, object_pk)
    if obj is None:
        raise NotFoundError("Object not found.")
    outgoing = viewer.db.scalar(select(func.count()).select_from(AdEdge).where(AdEdge.src_object_pk == object_pk))
    incoming = viewer.db.scalar(select(func.count()).select_from(AdEdge).where(AdEdge.dst_object_pk == object_pk))
    return object_view(obj, full=True) | {"snapshot_id": obj.snapshot_id,
                                          "relationship_counts": {"outgoing": outgoing, "incoming": incoming}}


@router.get("/objects/{object_pk}/relationships")
def object_relationships(object_pk: int, viewer: Viewer, offset: Offset = 0, limit: Limit = 50,
                         direction: Annotated[str, Query(pattern="^(in|out)$")] = "out") -> dict:
    if viewer.db.get(AdObject, object_pk) is None:
        raise NotFoundError("Object not found.")
    mine, other = ((AdEdge.src_object_pk, AdEdge.dst_object_pk) if direction == "out"
                   else (AdEdge.dst_object_pk, AdEdge.src_object_pk))
    total = viewer.db.scalar(select(func.count()).select_from(AdEdge).where(mine == object_pk))
    rows = viewer.db.execute(select(AdEdge, AdObject).join(AdObject, AdObject.id == other).where(mine == object_pk)
                             .order_by(AdEdge.kind, AdObject.name).offset(offset).limit(limit)).all()
    return {"total": total, "direction": direction, "items": [
        {"id": e.id, "kind": e.kind, "other": object_view(o), "data_source": e.data_source,
         "collected_at": iso(e.collected_at), "is_inherited": e.is_inherited, "confidence": e.confidence,
         "evidence": e.evidence} for e, o in rows]}
