"""Typed application errors.

Every error carries a stable machine-readable ``code`` and a message that is safe to show to
users. Internal details (stack traces, file paths, SQL) are never placed in ``message``.
"""

from __future__ import annotations


class AegisError(Exception):
    code = "aegis_error"
    http_status = 400

    def __init__(self, message: str, *, code: str | None = None, http_status: int | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if http_status:
            self.http_status = http_status


class NotFoundError(AegisError):
    code = "not_found"
    http_status = 404


class ValidationFailedError(AegisError):
    code = "validation_failed"
    http_status = 422


class LimitExceededError(AegisError):
    """A configured size/count limit would be exceeded (graph size, upload size, ...)."""

    code = "limit_exceeded"
    http_status = 413


class InsufficientResourcesError(AegisError):
    """The machine currently lacks the free RAM/disk needed to start the operation safely."""

    code = "insufficient_resources"
    http_status = 503


class JobQueueFullError(AegisError):
    code = "job_queue_full"
    http_status = 503


class JobCancelledError(AegisError):
    code = "job_cancelled"
    http_status = 409


class JobTimeoutError(AegisError):
    code = "job_timeout"
    http_status = 504
