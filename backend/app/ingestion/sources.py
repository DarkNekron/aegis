"""Safe access to uploaded files and ZIP archives.

Nothing is ever extracted to disk. ZIP members are validated up front (names, symlinks,
encryption, counts, sizes, compression ratio) and then streamed through ``GuardedStream``, which
enforces the byte limits *while reading*, so a forged size header cannot bypass them.
"""

from __future__ import annotations

import io
import stat
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from app.core.config import Settings
from app.core.errors import MalformedInputError, UnsafeArchiveError, UnsupportedFormatError

ALLOWED_EXTENSIONS = {".zip", ".json", ".csv"}
DATA_MEMBER_EXTENSIONS = {".json", ".csv"}
ZIP_MAGIC = b"PK\x03\x04"
EMPTY_ZIP_MAGIC = b"PK\x05\x06"
UTF8_BOM = b"\xef\xbb\xbf"
RATIO_CHECK_MIN_BYTES = 1024 * 1024  # small, highly compressible JSON files are normal


class ByteBudget:
    """Total decompressed bytes allowed for one upload (shared by all members)."""

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def consume(self, n: int) -> None:
        self.used += n
        if self.used > self.limit:
            raise UnsafeArchiveError(
                "The archive expands beyond the configured limit (AEGIS_MAX_ZIP_UNCOMPRESSED_MB); import stopped."
            )


class GuardedStream(io.RawIOBase):
    """Read-only stream that enforces a per-member byte limit and a shared budget, and drops a UTF-8 BOM."""

    def __init__(self, raw: BinaryIO, *, member_limit: int | None, budget: ByteBudget | None,
                 on_read: Callable[[int], None] | None = None):
        super().__init__()
        self._raw = raw
        self._member_limit = member_limit
        self._budget = budget
        self._on_read = on_read
        self._count = 0
        self._first = True

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        data = self._raw.read(len(buffer))
        if not data:
            return 0
        n = len(data)
        self._count += n
        if self._member_limit is not None and self._count > self._member_limit:
            raise UnsafeArchiveError("An archive member is larger than its declared size; import stopped.")
        if self._budget is not None:
            self._budget.consume(n)
        if self._on_read is not None:
            self._on_read(n)
        if self._first:
            self._first = False
            if data.startswith(UTF8_BOM):
                data = data[len(UTF8_BOM):]
                n = len(data)
        buffer[:n] = data
        return n

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


@dataclass
class SourceFile:
    """One data file: a plain upload or a validated ZIP member."""

    name: str
    size: int
    modified: datetime | None
    _opener: Callable[[], BinaryIO]

    def open(self) -> io.BufferedReader:
        return io.BufferedReader(self._opener(), buffer_size=256 * 1024)

    @property
    def extension(self) -> str:
        return PurePosixPath(self.name).suffix.lower()


@dataclass
class OpenedUpload:
    kind: str  # "zip" | "json" | "csv"
    sources: list[SourceFile]
    warnings: list[str]
    total_bytes: int
    _zip: zipfile.ZipFile | None = None

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()


def _sniff(path: Path) -> bytes:
    with path.open("rb") as fh:
        return fh.read(64)


def _check_member_name(name: str) -> None:
    if not name or "\x00" in name:
        raise UnsafeArchiveError("The archive contains an entry with an empty or invalid name.")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise UnsafeArchiveError(f"The archive contains an absolute path ({name[:80]!r}); refusing to process it.")
    if ".." in PurePosixPath(normalized).parts:
        raise UnsafeArchiveError(
            f"The archive contains a path-traversal entry ({name[:80]!r}); refusing to process it."
        )


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return info.create_system == 3 and stat.S_ISLNK(mode)


def open_upload(path: Path, original_name: str, settings: Settings,
                on_read: Callable[[int], None] | None = None) -> OpenedUpload:
    """Validate an uploaded file and return its data sources. Raises on anything unsafe."""
    ext = PurePosixPath(original_name.replace("\\", "/")).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"Unsupported file type {ext or '(none)'!r}. Upload a SharpHound/BloodHound .zip or .json, "
            "an AEGIS inventory .json, or a .csv inventory."
        )
    size = path.stat().st_size
    if size == 0:
        raise MalformedInputError("The uploaded file is empty.")
    head = _sniff(path)

    if ext == ".zip":
        if not (head.startswith(ZIP_MAGIC) or head.startswith(EMPTY_ZIP_MAGIC)):
            raise UnsupportedFormatError("The file has a .zip extension but is not a ZIP archive.")
        return _open_zip(path, settings, on_read)

    if head.startswith(ZIP_MAGIC):
        raise UnsupportedFormatError(f"The file is a ZIP archive but has a {ext} extension; rename it to .zip.")
    stripped = head[len(UTF8_BOM):] if head.startswith(UTF8_BOM) else head
    if ext == ".json" and stripped.lstrip()[:1] not in (b"{", b"["):
        raise UnsupportedFormatError("The file has a .json extension but does not contain JSON.")
    if b"\x00" in stripped:
        raise UnsupportedFormatError("The file appears to be binary, not text.")

    modified = datetime.fromtimestamp(path.stat().st_mtime).astimezone()
    source = SourceFile(
        name=PurePosixPath(original_name.replace("\\", "/")).name,
        size=size,
        modified=modified,
        _opener=lambda: GuardedStream(path.open("rb"), member_limit=None, budget=None, on_read=on_read),
    )
    return OpenedUpload(kind=ext.lstrip("."), sources=[source], warnings=[], total_bytes=size)


def _open_zip(path: Path, settings: Settings, on_read: Callable[[int], None] | None) -> OpenedUpload:
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise MalformedInputError("The ZIP archive is corrupt or truncated.") from exc

    try:
        infos = archive.infolist()
        if len(infos) > settings.max_zip_members:
            raise UnsafeArchiveError(
                f"The archive has {len(infos)} entries; the limit is {settings.max_zip_members} "
                "(AEGIS_MAX_ZIP_MEMBERS)."
            )
        declared_total = 0
        sources: list[SourceFile] = []
        warnings: list[str] = []
        budget = ByteBudget(settings.max_zip_uncompressed_bytes)

        for info in infos:
            _check_member_name(info.filename)
            if _is_symlink(info):
                raise UnsafeArchiveError(f"The archive contains a symbolic link ({info.filename[:80]!r}).")
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise UnsafeArchiveError(
                    "The archive is password-protected. Extract it with the password and upload the JSON files "
                    "(or re-zip them without a password)."
                )
            declared_total += info.file_size
            if declared_total > settings.max_zip_uncompressed_bytes:
                raise UnsafeArchiveError(
                    "The archive's uncompressed size exceeds the configured limit (AEGIS_MAX_ZIP_UNCOMPRESSED_MB)."
                )
            if info.file_size >= RATIO_CHECK_MIN_BYTES:
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > settings.max_zip_ratio:
                    raise UnsafeArchiveError(
                        f"Archive entry {info.filename[:80]!r} has a suspicious compression ratio ({ratio:,.0f}:1); "
                        "possible ZIP bomb."
                    )
            suffix = PurePosixPath(info.filename).suffix.lower()
            if suffix not in DATA_MEMBER_EXTENSIONS:
                warnings.append(f"Skipped {info.filename[:120]!r}: only .json and .csv files are imported.")
                continue

            def opener(info: zipfile.ZipInfo = info) -> BinaryIO:
                return GuardedStream(archive.open(info), member_limit=info.file_size, budget=budget,
                                     on_read=on_read)

            sources.append(SourceFile(name=info.filename, size=info.file_size,
                                      modified=_zip_time(info), _opener=opener))

        if not sources:
            raise UnsupportedFormatError("The archive contains no .json or .csv files to import.")
        return OpenedUpload(kind="zip", sources=sources, warnings=warnings, total_bytes=declared_total,
                            _zip=archive)
    except Exception:
        archive.close()
        raise


def _zip_time(info: zipfile.ZipInfo) -> datetime | None:
    try:
        return datetime(*info.date_time).astimezone()
    except (TypeError, ValueError):
        return None
