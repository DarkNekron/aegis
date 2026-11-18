"""Analysis runs, discovered attack paths, simulations, reports and editable settings."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, utcnow


class PathClassification(StrEnum):
    """How strongly a path is supported. AEGIS never claims a path *was* exploited."""

    OBSERVED = "observed_relationship"
    POTENTIAL = "potential_privilege_escalation"
    CONDITIONAL = "conditional_attack_path"
    VALIDATED = "validated_security_exposure"  # set only by an analyst


class Analysis(TimestampMixin, Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="CASCADE"), index=True,
                                             nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class AttackPath(Base):
    __tablename__ = "attack_paths"
    __table_args__ = (
        Index("ix_attack_paths_analysis_score", "analysis_id", "score"),
        Index("ix_attack_paths_signature", "signature"),
        Index("ix_attack_paths_analysis_severity", "analysis_id", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    source_pk: Mapped[int] = mapped_column(ForeignKey("ad_objects.id", ondelete="CASCADE"), nullable=False)
    target_pk: Mapped[int] = mapped_column(ForeignKey("ad_objects.id", ondelete="CASCADE"), nullable=False)
    hops: Mapped[int] = mapped_column(Integer, nullable=False)
    edge_ids: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    classification: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    score_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    # Self-contained explanation (nodes, steps, conditions, narrative) so reports and the UI do not
    # need the in-memory graph.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    # Stable across snapshots: hash of the ordered (object_id, edge kind) sequence.
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    validated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Simulation(TimestampMixin, Base):
    __tablename__ = "simulations"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True,
                                             nullable=False)
    actions: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Report(TimestampMixin, Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id", ondelete="CASCADE"), index=True,
                                             nullable=False)
    analysis_id: Mapped[int | None] = mapped_column(ForeignKey("analyses.id", ondelete="SET NULL"))
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class SettingEntry(Base):
    """Administrator-editable settings (scoring weights, target categories)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow,
                                                 nullable=False)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
