"""Streaming upload persistence with the size limit enforced while writing.

The upload API (added with authentication in roadmap stage 5.0) streams request chunks through
``UploadWriter``; nothing is buffered whole in memory, the size cap is enforced before the limit
is exceeded on disk, and partial files are deleted on any failure. Stored names are random, so a
client-supplied filename never touches the filesystem.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from app.core.errors import LimitExceededError, UnsupportedFormatError
from app.ingestion.sources import ALLOWED_EXTENSIONS


@dataclass(frozen=True)
class SavedUpload:
    path: Path
    original_name: str
    size: int
    sha256: str


class UploadWriter:
    def __init__(self, upload_dir: Path, original_name: str, max_bytes: int):
        safe_name = PurePosixPath(original_name.replace("\\", "/")).name[:255]
        ext = PurePosixPath(safe_name).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise UnsupportedFormatError(f"Unsupported file type {ext or '(none)'!r}.")
        upload_dir.mkdir(parents=True, exist_ok=True)
        self.original_name = safe_name
        self.max_bytes = max_bytes
        self.path = upload_dir / f"{secrets.token_hex(16)}{ext}"
        self._fh = self.path.open("xb")  # exclusive create: never overwrite
        self._digest = hashlib.sha256()
        self._size = 0

    def write(self, chunk: bytes) -> None:
        if self._size + len(chunk) > self.max_bytes:
            self.abort()
            limit_mb = self.max_bytes // (1024 * 1024)
            raise LimitExceededError(f"The file exceeds the maximum upload size of {limit_mb} MB.")
        self._fh.write(chunk)
        self._digest.update(chunk)
        self._size += len(chunk)

    def finish(self) -> SavedUpload:
        self._fh.close()
        return SavedUpload(self.path, self.original_name, self._size, self._digest.hexdigest())

    def abort(self) -> None:
        if not self._fh.closed:
            self._fh.close()
        self.path.unlink(missing_ok=True)
