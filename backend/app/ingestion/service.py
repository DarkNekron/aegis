"""Import orchestration: snapshot lifecycle, atomic import, failure recording.

An import is all-or-nothing at the database level: data is written in one transaction and only
committed when every file has been processed. Problems inside individual records or files are
reported in the summary (status ``partial``) rather than aborting everything; unsafe archives,
limit violations and cancellations abort and roll back.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ijson
from sqlalchemy import func, select

from app.core.config import Settings
from app.core.errors import (
    AegisError,
    ConflictError,
    JobCancelledError,
    MalformedInputError,
    NotFoundError,
    UnsupportedFormatError,
)
from app.core.jobs import CancellationToken
from app.core.resources import MB, ResourceManager
from app.db.base import utcnow
from app.db.session import Database
from app.ingestion.detect import DetectedFormat, detect
from app.ingestion.parsers.bloodhound import parse_bloodhound
from app.ingestion.parsers.inventory import parse_inventory_csv, parse_inventory_json
from app.ingestion.sources import OpenedUpload, SourceFile, open_upload
from app.ingestion.store import ImportSummary, SnapshotStore
from app.models import AdEdge, AdObject, ImportJob, Snapshot, SnapshotStatus

logger = logging.getLogger(__name__)

ProgressFn = Callable[[float, str], None]


class ImportStatus:
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ImportResult:
    import_job_id: int
    snapshot_id: int
    status: str
    summary: dict[str, Any]


def sha256_file(path: Path, token: CancellationToken | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            if token:
                token.check()
            digest.update(chunk)
    return digest.hexdigest()


class ImportService:
    def __init__(self, db: Database, settings: Settings, resources: ResourceManager):
        self.db = db
        self.settings = settings
        self.resources = resources

    # ------------------------------------------------------------------ snapshots
    def create_snapshot(self, name: str, *, description: str | None = None, is_sample: bool = False,
                        created_by: int | None = None) -> int:
        name = (name or "").strip()
        if not name:
            raise MalformedInputError("A snapshot name is required.")
        with self.db.session() as s:
            snap = Snapshot(name=name[:200], description=description, is_sample=is_sample, created_by=created_by,
                            status=SnapshotStatus.EMPTY.value)
            s.add(snap)
            s.commit()
            return snap.id

    # ------------------------------------------------------------------ import
    def import_file(self, snapshot_id: int, path: Path, original_name: str, *,
                    token: CancellationToken | None = None, progress: ProgressFn | None = None,
                    sha256: str | None = None, created_by: int | None = None) -> ImportResult:
        token = token or CancellationToken(self.settings.job_timeout_seconds)
        size = path.stat().st_size
        self.resources.ensure_upload_size(size)
        self.resources.ensure_disk_space(required_mb=(size * 3) // MB)  # staging + final rows + WAL
        digest = sha256 or sha256_file(path, token)
        job_id = self._begin(snapshot_id, original_name, digest, size)

        summary = ImportSummary()
        opened: OpenedUpload | None = None
        try:
            read = [0]
            total = [max(size, 1)]

            def on_read(n: int) -> None:
                read[0] += n
                if progress:
                    # each JSON file is read twice (detect + parse); cap below 100% until committed
                    progress(min(0.95, read[0] / (2 * total[0])), "Reading data")

            opened = open_upload(path, original_name, self.settings, on_read=on_read)
            total[0] = max(opened.total_bytes, 1)
            for warning in opened.warnings:
                summary.warn(warning)
            status = self._run(snapshot_id, job_id, opened, summary, token)
        except AegisError as exc:
            outcome = ImportStatus.CANCELLED if isinstance(exc, JobCancelledError) else ImportStatus.FAILED
            self._record_failure(snapshot_id, job_id, summary, exc.message, outcome)
            raise
        except Exception:
            self._record_failure(snapshot_id, job_id, summary, "Internal error during import.", ImportStatus.FAILED)
            raise
        finally:
            if opened is not None:
                opened.close()
        if progress:
            progress(1.0, "Import complete")
        return ImportResult(job_id, snapshot_id, status, summary.to_dict())

    def _begin(self, snapshot_id: int, filename: str, digest: str, size: int) -> int:
        with self.db.session() as s:
            snap = s.get(Snapshot, snapshot_id, with_for_update=True)
            if snap is None:
                raise NotFoundError("Snapshot not found.")
            if snap.status == SnapshotStatus.IMPORTING.value:
                raise ConflictError("Another import into this snapshot is already running.")
            duplicate = s.scalar(select(ImportJob.id).where(
                ImportJob.snapshot_id == snapshot_id, ImportJob.sha256 == digest,
                ImportJob.status.in_([ImportStatus.SUCCEEDED, ImportStatus.PARTIAL])).limit(1))
            if duplicate:
                raise ConflictError("This exact file has already been imported into this snapshot.")
            job = ImportJob(snapshot_id=snapshot_id, filename=Path(filename).name[:255], sha256=digest,
                            size_bytes=size, status=ImportStatus.RUNNING)
            s.add(job)
            snap.status = SnapshotStatus.IMPORTING.value
            s.commit()
            return job.id

    def _run(self, snapshot_id: int, job_id: int, opened: OpenedUpload, summary: ImportSummary,
             token: CancellationToken) -> str:
        formats: set[str] = set()
        newest: datetime | None = None
        with self.db.session() as s:
            store = SnapshotStore(s, self.settings, snapshot_id, job_id, summary, token)
            for source in opened.sources:
                token.check()
                entry: dict[str, Any] = {"name": source.name[:200], "size_bytes": source.size}
                summary.files.append(entry)
                try:
                    fmt = detect(source)
                    entry["format"] = fmt.label
                    for note in fmt.notes:
                        summary.warn(note)
                    entry["records"] = self._parse(source, fmt, store, token)
                    formats.add(fmt.family)
                    if opened.kind == "zip" and source.modified:
                        newest = max(newest, source.modified) if newest else source.modified
                    if fmt.family == "aegis-json" and fmt.meta.get("collected_at"):
                        newest = _parse_iso(fmt.meta["collected_at"]) or newest
                except (MalformedInputError, UnsupportedFormatError) as exc:
                    entry["error"] = exc.message
                except ijson.JSONError as exc:
                    entry["error"] = f"invalid or truncated JSON; records before the fault were kept ({_short(exc)})"
            store.finalize()

            received = summary.counters["objects_received"] + summary.counters["edges_staged"]
            if received == 0:
                status = ImportStatus.FAILED
            elif summary.file_errors or summary.counters["item_errors"]:
                status = ImportStatus.PARTIAL
            else:
                status = ImportStatus.SUCCEEDED

            stats = self.snapshot_stats(s, snapshot_id)
            result = summary.to_dict()
            result["snapshot_objects_by_kind"] = stats["objects_by_kind"]
            result.pop("objects_by_kind", None)

            job = s.get(ImportJob, job_id)
            job.detected_format = ",".join(sorted(formats))[:48] or None
            job.status = status
            job.summary = result
            job.errors = [f["error"] for f in summary.files if f.get("error")] or None
            job.finished_at = utcnow()
            snap = s.get(Snapshot, snapshot_id)
            snap.stats = stats
            snap.status = SnapshotStatus.READY.value if stats["objects_total"] else SnapshotStatus.FAILED.value
            if formats:
                snap.source_kind = ("mixed" if len(formats) > 1 else next(iter(formats)))[:32]
            if newest and (snap.collected_at is None or newest > _aware(snap.collected_at)):
                snap.collected_at = newest
            s.commit()
        logger.info("Import %s into snapshot %s finished: %s", job_id, snapshot_id, status)
        return status

    def _parse(self, source: SourceFile, fmt: DetectedFormat, store: SnapshotStore, token: CancellationToken) -> int:
        if fmt.family == "bloodhound":
            with source.open() as stream:
                return parse_bloodhound(stream, source_name=source.name, data_type=fmt.data_type or "",
                                        version=fmt.version, sink=store, token=token)
        if fmt.family == "aegis-json":
            return parse_inventory_json(source.open, source_name=source.name,
                                        collected_at=fmt.meta.get("collected_at"), sink=store, token=token)
        return parse_inventory_csv(source.open, source_name=source.name, family=fmt.family, sink=store, token=token)

    def _record_failure(self, snapshot_id: int, job_id: int, summary: ImportSummary, message: str,
                        status: str) -> None:
        """Runs after the import transaction rolled back; records why, in a fresh transaction."""
        try:
            with self.db.session() as s:
                job = s.get(ImportJob, job_id)
                if job is not None:
                    job.status = status
                    job.errors = [message[:500]]
                    job.summary = summary.to_dict()
                    job.finished_at = utcnow()
                snap = s.get(Snapshot, snapshot_id)
                if snap is not None:
                    has_data = s.scalar(select(AdObject.id).where(AdObject.snapshot_id == snapshot_id).limit(1))
                    snap.status = SnapshotStatus.READY.value if has_data else SnapshotStatus.FAILED.value
                s.commit()
        except Exception:
            logger.exception("Could not record failure of import %s", job_id)

    # ------------------------------------------------------------------ statistics
    @staticmethod
    def snapshot_stats(session, snapshot_id: int) -> dict[str, Any]:
        by_kind = dict(session.execute(
            select(AdObject.kind, func.count()).where(AdObject.snapshot_id == snapshot_id).group_by(AdObject.kind)
        ).all())
        edges_by_kind = dict(session.execute(
            select(AdEdge.kind, func.count()).where(AdEdge.snapshot_id == snapshot_id).group_by(AdEdge.kind)
        ).all())
        return {
            "objects_total": sum(by_kind.values()),
            "objects_by_kind": by_kind,
            "relationships_total": sum(edges_by_kind.values()),
            "relationships_by_kind": edges_by_kind,
            "computed_at": datetime.now(UTC).isoformat(),
        }


def _parse_iso(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return _aware(parsed)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _short(exc: Exception) -> str:
    return str(exc).splitlines()[0][:120] if str(exc) else exc.__class__.__name__
