"""Assessment snapshots and the directory data (objects + relationships) imported into them."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class SnapshotStatus(StrEnum):
    EMPTY = "empty"
    IMPORTING = "importing"
    READY = "ready"
    FAILED = "failed"


class Snapshot(TimestampMixin, Base):
    """One point-in-time assessment of a directory. All imported data belongs to a snapshot."""

    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_kind: Mapped[str | None] = mapped_column(String(32))
    is_sample: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=SnapshotStatus.EMPTY.value)
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    imports: Mapped[list[ImportJob]] = relationship(back_populates="snapshot", cascade="all, delete-orphan",
                                                    passive_deletes=True)


class ImportJob(TimestampMixin, Base):
    __tablename__ = "import_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="CASCADE"), index=True,
                                             nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detected_format: Mapped[str | None] = mapped_column(String(48))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    errors: Mapped[list[Any] | None] = mapped_column(JSON)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    snapshot: Mapped[Snapshot] = relationship(back_populates="imports")


class AdObject(Base):
    """A directory object (user, group, computer, domain, OU, GPO, ...).

    ``id`` is a compact integer that doubles as the node key in the in-memory graph.
    ``object_id`` is the directory identifier (SID or GUID) and is stable across snapshots.
    """

    __tablename__ = "ad_objects"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "object_id", name="uq_ad_objects_snapshot_object"),
        Index("ix_ad_objects_snapshot_kind", "snapshot_id", "kind"),
        Index("ix_ad_objects_snapshot_name", "snapshot_id", "name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False)
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    is_tier0: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tier0_reason: Mapped[str | None] = mapped_column(String(255))
    properties: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class AdEdge(Base):
    """A relationship between two objects. Direction always means "source can affect destination"."""

    __tablename__ = "ad_edges"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "src_object_pk", "dst_object_pk", "kind", name="uq_ad_edges_identity"),
        Index("ix_ad_edges_snapshot_kind", "snapshot_id", "kind"),
        Index("ix_ad_edges_src", "src_object_pk"),
        Index("ix_ad_edges_dst", "dst_object_pk"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False)
    src_object_pk: Mapped[int] = mapped_column(ForeignKey("ad_objects.id", ondelete="CASCADE"), nullable=False)
    dst_object_pk: Mapped[int] = mapped_column(ForeignKey("ad_objects.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    data_source: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_inherited: Mapped[bool | None] = mapped_column(Boolean)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    conditions: Mapped[list[Any] | None] = mapped_column(JSON)
