"""Bounded, cancellable in-process job runner.

Design (see docs/ARCHITECTURE.md §6):

* Two thread pools: a *heavy* pool (graph analysis; default 1 worker so only one expensive
  computation runs at a time) and a *light* pool (imports, small reports).
* Threads rather than processes: a process pool would need its own copy of the in-memory graph,
  doubling RAM use on a memory-constrained laptop.
* Cancellation and timeouts are cooperative. Long-running code receives a ``JobContext`` and calls
  ``ctx.token.checkpoint()`` inside its loops; the token raises ``JobCancelledError`` or
  ``JobTimeoutError`` and the runner records the outcome. Python cannot safely kill a thread, so
  every AEGIS algorithm is written to check its token regularly.
* Back-pressure: at most ``max_pending_jobs`` jobs may be queued or running.
* Heavy jobs re-check free RAM when they actually start, since conditions change while queued.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import CancelledError as FutureCancelled
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.core.config import Settings
from app.core.errors import (
    AegisError,
    JobCancelledError,
    JobQueueFullError,
    JobTimeoutError,
    NotFoundError,
)
from app.core.resources import ResourceManager

logger = logging.getLogger(__name__)


class JobKind(StrEnum):
    HEAVY = "heavy"
    LIGHT = "light"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"

    @property
    def is_active(self) -> bool:
        return self in (JobStatus.QUEUED, JobStatus.RUNNING)


class CancellationToken:
    """Cooperative cancellation + deadline. Cheap enough to call inside hot loops via ``checkpoint``."""

    __slots__ = ("_event", "_deadline", "_counter")

    def __init__(self, timeout_seconds: float | None = None):
        self._event = threading.Event()
        self._deadline: float | None = None
        self._counter = 0
        if timeout_seconds:
            self.start_deadline(timeout_seconds)

    def start_deadline(self, timeout_seconds: float | None) -> None:
        self._deadline = time.monotonic() + timeout_seconds if timeout_seconds else None

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def expired(self) -> bool:
        return self._deadline is not None and time.monotonic() > self._deadline

    def check(self) -> None:
        if self._event.is_set():
            raise JobCancelledError("The operation was cancelled.")
        if self.expired:
            raise JobTimeoutError("The operation exceeded its time limit and was stopped.")

    def checkpoint(self, every: int = 512) -> None:
        """Call from tight loops; performs a full ``check`` once every ``every`` calls."""
        self._counter += 1
        if self._counter >= every:
            self._counter = 0
            self.check()


@dataclass
class Job:
    id: str
    name: str
    kind: JobKind
    timeout_seconds: float | None
    estimated_memory_mb: int
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress: float = 0.0
    message: str = ""
    error: str | None = None
    error_code: str | None = None
    result: Any = None
    token: CancellationToken = field(default_factory=CancellationToken)
    future: Future | None = field(default=None, repr=False)

    def public_view(self) -> dict[str, Any]:
        """JSON-safe description for the API (never includes the raw result object)."""
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind.value,
            "status": self.status.value,
            "progress": round(self.progress, 4),
            "message": self.message,
            "error": self.error,
            "error_code": self.error_code,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


class JobContext:
    """Handed to job functions: progress reporting plus the cancellation token."""

    def __init__(self, job: Job):
        self._job = job
        self.token = job.token

    def report_progress(self, fraction: float, message: str | None = None) -> None:
        self._job.progress = min(1.0, max(0.0, float(fraction)))
        if message is not None:
            self._job.message = message[:500]
        self.token.check()


JobFn = Callable[[JobContext], Any]


class JobRunner:
    def __init__(self, settings: Settings, resources: ResourceManager, *, retention: int = 200):
        self.settings = settings
        self.resources = resources
        self._retention = retention
        self._lock = threading.RLock()  # re-entrant: _finish may run while _run already holds it
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._pools = {
            JobKind.HEAVY: ThreadPoolExecutor(settings.max_analysis_workers, thread_name_prefix="aegis-heavy"),
            JobKind.LIGHT: ThreadPoolExecutor(settings.max_light_workers, thread_name_prefix="aegis-light"),
        }
        self._closed = False

    # ------------------------------------------------------------------ submission
    def submit(
        self,
        name: str,
        fn: JobFn,
        *,
        kind: JobKind = JobKind.LIGHT,
        timeout_seconds: float | None = None,
        estimated_memory_mb: int = 0,
    ) -> Job:
        if self._closed:
            raise JobQueueFullError("The job runner is shutting down.")
        if kind is JobKind.HEAVY:
            # Fail fast at submit time; re-checked when the job actually starts.
            self.resources.ensure_can_start_heavy_job(estimated_memory_mb)

        timeout = self.settings.job_timeout_seconds if timeout_seconds is None else timeout_seconds
        job = Job(
            id=uuid.uuid4().hex,
            name=name[:200],
            kind=kind,
            timeout_seconds=timeout,
            estimated_memory_mb=estimated_memory_mb,
        )
        with self._lock:
            active = sum(1 for j in self._jobs.values() if j.status.is_active)
            if active >= self.settings.max_pending_jobs:
                raise JobQueueFullError(
                    f"{active} jobs are already queued or running (limit {self.settings.max_pending_jobs}). "
                    "Wait for them to finish or cancel one."
                )
            self._jobs[job.id] = job
            job.future = self._pools[kind].submit(self._run, job, fn)
        return job

    # ------------------------------------------------------------------ execution
    def _run(self, job: Job, fn: JobFn) -> None:
        with self._lock:
            if job.token.cancelled:
                self._finish(job, JobStatus.CANCELLED, error="Cancelled before it started.",
                             code=JobCancelledError.code)
                return
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(UTC)
            job.token.start_deadline(job.timeout_seconds)
        try:
            if job.kind is JobKind.HEAVY:
                self.resources.ensure_can_start_heavy_job(job.estimated_memory_mb)
            result = fn(JobContext(job))
        except JobCancelledError as exc:
            self._finish(job, JobStatus.CANCELLED, error=exc.message, code=exc.code)
        except JobTimeoutError as exc:
            self._finish(job, JobStatus.TIMED_OUT, error=exc.message, code=exc.code)
        except AegisError as exc:
            self._finish(job, JobStatus.FAILED, error=exc.message, code=exc.code)
        except Exception:
            ref = uuid.uuid4().hex[:12]
            logger.exception("Job %s (%s) failed [ref %s]", job.id, job.name, ref)
            self._finish(job, JobStatus.FAILED, error=f"Internal error (reference {ref}).", code="internal_error")
        else:
            job.result = result
            job.progress = 1.0
            self._finish(job, JobStatus.SUCCEEDED)

    def _finish(self, job: Job, status: JobStatus, *, error: str | None = None, code: str | None = None) -> None:
        with self._lock:
            job.status = status
            job.error = error
            job.error_code = code
            job.finished_at = datetime.now(UTC)
            self._prune()

    def _prune(self) -> None:
        """Forget the oldest finished jobs beyond the retention limit (bounded memory)."""
        finished = [jid for jid, j in self._jobs.items() if not j.status.is_active]
        for jid in finished[: max(0, len(finished) - self._retention)]:
            self._jobs.pop(jid, None)

    # ------------------------------------------------------------------ queries & control
    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise NotFoundError("Job not found.")
        return job

    def list(self) -> list[Job]:
        with self._lock:
            return list(reversed(self._jobs.values()))

    def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        with self._lock:
            if not job.status.is_active:
                return job
            job.token.cancel()
            # A job still waiting in the pool queue can be withdrawn immediately.
            if job.status is JobStatus.QUEUED and job.future is not None and job.future.cancel():
                self._finish(job, JobStatus.CANCELLED, error="Cancelled before it started.",
                             code=JobCancelledError.code)
        return job

    def wait(self, job_id: str, timeout: float | None = None) -> Job:
        """Block until the job finishes (used by tests and synchronous callers)."""
        job = self.get(job_id)
        if job.future is not None:
            try:
                job.future.result(timeout=timeout)
            except FutureCancelled:
                pass  # withdrawn from the queue; status already recorded by cancel()
            except FutureTimeout as exc:
                raise JobTimeoutError("Timed out waiting for the job to finish.") from exc
        return job

    def stats(self) -> dict[str, int]:
        with self._lock:
            jobs = list(self._jobs.values())
        counts = {status.value: 0 for status in JobStatus}
        for j in jobs:
            counts[j.status.value] += 1
        counts["heavy_running"] = sum(1 for j in jobs if j.kind is JobKind.HEAVY and j.status is JobStatus.RUNNING)
        return counts

    def shutdown(self, *, wait: bool = True) -> None:
        self._closed = True
        with self._lock:
            for job in self._jobs.values():
                if job.status.is_active:
                    job.token.cancel()
        for pool in self._pools.values():
            pool.shutdown(wait=wait, cancel_futures=False)
