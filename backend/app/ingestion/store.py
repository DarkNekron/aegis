"""Writes normalised data into a snapshot within one database transaction.

* Objects are buffered and upserted in batches with SQLAlchemy Core (no ORM identity map, so memory
  stays flat). Duplicates (same directory identifier) are merged, not duplicated.
* Relationships are staged by identifier and resolved at ``finalize()`` with set-based SQL:
  missing endpoints become *placeholder* objects (often a sign of incomplete collection), duplicate
  relationships collapse to one row, and relationships already present in the snapshot are kept.
* Graph-size limits are enforced as data arrives, so an oversized import fails early and rolls back.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import Integer, bindparam, func, literal, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, aliased

from app.core.config import Settings
from app.core.errors import LimitExceededError
from app.core.jobs import CancellationToken
from app.ingestion.model import UNKNOWN, NormalizedEdge, NormalizedObject
from app.models import AdEdge, AdObject, IngestStagedEdge

PLACEHOLDER_FLAG = "aegis_placeholder"
MAX_REPORTED_ERRORS = 200
MAX_REPORTED_WARNINGS = 100


class ImportSummary:
    """Counters and capped error/warning lists describing one import."""

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self.objects_by_kind: Counter[str] = Counter()
        self.edges_by_kind: Counter[str] = Counter()
        self.files: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self.warnings: list[str] = []

    def item_error(self, source: str, location: str, message: str) -> None:
        self.counters["item_errors"] += 1
        if len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append({"file": source[:200], "location": location[:120], "message": message[:300]})

    def warn(self, message: str) -> None:
        self.counters["warnings"] += 1
        if len(self.warnings) < MAX_REPORTED_WARNINGS:
            self.warnings.append(message[:400])

    @property
    def file_errors(self) -> int:
        return sum(1 for f in self.files if f.get("error"))

    def to_dict(self) -> dict[str, Any]:
        c = self.counters
        return {
            "files": self.files,
            "objects_received": c["objects_received"],
            "objects_inserted": c["objects_inserted"],
            "objects_merged_duplicates": c["objects_merged_duplicates"],
            "placeholders_created": c["placeholders_created"],
            "placeholders_resolved": c["placeholders_resolved"],
            "objects_by_kind": dict(self.objects_by_kind),
            "relationships_received": c["edges_staged"],
            "relationships_inserted": c["edges_inserted"],
            "relationships_duplicate_in_upload": c["edges_duplicate_in_upload"],
            "relationships_already_present": c["edges_already_present"],
            "relationships_by_kind": dict(self.edges_by_kind),
            "deleted_objects_skipped": c["deleted_objects_skipped"],
            "self_relationships_skipped": c["self_relationships_skipped"],
            "session_collections_failed": c["session_collections_failed"],
            "item_errors": c["item_errors"],
            "errors": self.errors,
            "errors_truncated": max(0, c["item_errors"] - len(self.errors)),
            "warnings": self.warnings,
        }


def _dialect_insert(session: Session):
    return pg_insert if session.get_bind().dialect.name == "postgresql" else sqlite_insert


def _merge(existing: dict[str, Any], new: NormalizedObject) -> tuple[dict[str, Any], str]:
    """Merge ``new`` into ``existing`` (row values). Returns (values, outcome)."""
    props = existing.get("properties") or {}
    if props.get(PLACEHOLDER_FLAG):
        return ({"kind": new.kind, "name": new.name, "domain": new.domain, "enabled": new.enabled,
                 "properties": new.properties}, "placeholder_resolved")
    kind = existing["kind"]
    if kind == UNKNOWN or {kind, new.kind} == {"User", "ServiceAccount"}:
        kind = new.kind if kind == UNKNOWN or new.kind == "ServiceAccount" else kind
    name = existing["name"] if existing["name"] and existing["name"] != existing["object_id"] else new.name
    merged_props = {**props, **new.properties}
    return ({"kind": kind, "name": name, "domain": existing["domain"] or new.domain,
             "enabled": new.enabled if new.enabled is not None else existing["enabled"],
             "properties": merged_props}, "duplicate")


class SnapshotStore:
    """Implements ``IngestSink`` for one import into one snapshot."""

    def __init__(self, session: Session, settings: Settings, snapshot_id: int, import_job_id: int,
                 summary: ImportSummary, token: CancellationToken):
        self.session = session
        self.settings = settings
        self.snapshot_id = snapshot_id
        self.import_job_id = import_job_id
        self.summary = summary
        self.token = token
        self._batch = settings.ingest_batch_size
        self._objects: dict[str, NormalizedObject] = {}
        self._edges: list[dict[str, Any]] = []
        self._insert = _dialect_insert(session)
        self._object_count = session.scalar(
            select(func.count()).select_from(AdObject).where(AdObject.snapshot_id == snapshot_id)) or 0
        self._kind_conflicts_reported = 0

    # ------------------------------------------------------------------ sink interface
    def add_object(self, obj: NormalizedObject) -> None:
        self.summary.counters["objects_received"] += 1
        buffered = self._objects.get(obj.object_id)
        if buffered is None:
            self._objects[obj.object_id] = obj
        else:
            values, _ = _merge({"object_id": buffered.object_id, "kind": buffered.kind, "name": buffered.name,
                                "domain": buffered.domain, "enabled": buffered.enabled,
                                "properties": buffered.properties}, obj)
            self._note_kind_conflict(obj.object_id, buffered.kind, obj.kind)
            self._objects[obj.object_id] = NormalizedObject(object_id=obj.object_id, **values)
            self.summary.counters["objects_merged_duplicates"] += 1
        if len(self._objects) >= self._batch:
            self._flush_objects()

    def add_edge(self, edge: NormalizedEdge) -> None:
        self.summary.counters["edges_staged"] += 1
        self.summary.edges_by_kind[edge.kind] += 1
        if self.summary.counters["edges_staged"] > self.settings.max_graph_edges * 2:
            raise LimitExceededError(
                "The upload contains far more relationships than AEGIS_MAX_GRAPH_EDGES allows; import stopped."
            )
        self._edges.append({
            "import_job_id": self.import_job_id, "src_object_id": edge.src_id, "dst_object_id": edge.dst_id,
            "src_kind_hint": edge.src_kind_hint, "dst_kind_hint": edge.dst_kind_hint,
            "src_name_hint": edge.src_name_hint, "dst_name_hint": edge.dst_name_hint, "kind": edge.kind,
            "data_source": edge.data_source, "collected_at": edge.collected_at, "is_inherited": edge.is_inherited,
            "confidence": edge.confidence, "evidence": edge.evidence,
        })
        if len(self._edges) >= self._batch:
            self._flush_edges()

    def item_error(self, source: str, location: str, message: str) -> None:
        self.summary.item_error(source, location, message)

    def count(self, counter: str, amount: int = 1) -> None:
        self.summary.counters[counter] += amount

    # ------------------------------------------------------------------ flushing
    def _note_kind_conflict(self, object_id: str, old: str, new: str) -> None:
        if old != new and UNKNOWN not in (old, new) and {old, new} != {"User", "ServiceAccount"}:
            self._kind_conflicts_reported += 1
            if self._kind_conflicts_reported <= 20:
                self.summary.warn(f"Object {object_id} appears as both {old} and {new}; kept {old}.")

    def _check_node_limit(self, adding: int) -> None:
        if self._object_count + adding > self.settings.max_graph_nodes:
            raise LimitExceededError(
                f"This import would exceed the configured maximum of {self.settings.max_graph_nodes:,} objects per "
                "snapshot (AEGIS_MAX_GRAPH_NODES). Nothing was imported."
            )

    def _flush_objects(self) -> None:
        if not self._objects:
            return
        self.token.check()
        table = AdObject.__table__
        ids = list(self._objects)
        rows = self.session.execute(
            select(table.c.id, table.c.object_id, table.c.kind, table.c.name, table.c.domain, table.c.enabled,
                   table.c.properties)
            .where(table.c.snapshot_id == self.snapshot_id, table.c.object_id.in_(ids))
        ).mappings().all()

        updates = []
        for row in rows:
            new = self._objects.pop(row["object_id"])
            values, outcome = _merge(dict(row), new)
            if outcome == "duplicate":
                self._note_kind_conflict(row["object_id"], row["kind"], new.kind)
                self.summary.counters["objects_merged_duplicates"] += 1
            else:
                self.summary.counters["placeholders_resolved"] += 1
            updates.append({"b_id": row["id"], **{f"b_{k}": v for k, v in values.items()}})

        inserts = [
            {"snapshot_id": self.snapshot_id, "object_id": o.object_id, "kind": o.kind, "name": o.name,
             "domain": o.domain, "enabled": o.enabled, "is_tier0": False, "properties": o.properties}
            for o in self._objects.values()
        ]
        self._check_node_limit(len(inserts))
        if inserts:
            self.session.execute(table.insert(), inserts)
            self._object_count += len(inserts)
            self.summary.counters["objects_inserted"] += len(inserts)
        if updates:
            self.session.execute(
                update(table).where(table.c.id == bindparam("b_id")).values(
                    kind=bindparam("b_kind"), name=bindparam("b_name"), domain=bindparam("b_domain"),
                    enabled=bindparam("b_enabled"), properties=bindparam("b_properties")),
                updates,
                execution_options={"synchronize_session": False},
            )
        self._objects.clear()

    def _flush_edges(self) -> None:
        if self._edges:
            self.token.check()
            self.session.execute(IngestStagedEdge.__table__.insert(), self._edges)
            self._edges.clear()

    # ------------------------------------------------------------------ finalisation
    def finalize(self) -> None:
        self._flush_objects()
        self._flush_edges()
        self._create_placeholders()
        self._insert_edges()
        self.session.execute(IngestStagedEdge.__table__.delete().where(
            IngestStagedEdge.import_job_id == self.import_job_id))

    def _create_placeholders(self) -> None:
        staged = IngestStagedEdge.__table__
        objects = AdObject.__table__
        missing: dict[str, tuple[str | None, str | None]] = {}
        for id_col, kind_col, name_col in ((staged.c.src_object_id, staged.c.src_kind_hint, staged.c.src_name_hint),
                                           (staged.c.dst_object_id, staged.c.dst_kind_hint, staged.c.dst_name_hint)):
            exists = select(objects.c.id).where(objects.c.snapshot_id == self.snapshot_id,
                                                objects.c.object_id == id_col).exists()
            query = (select(id_col, func.max(kind_col), func.max(name_col))
                     .where(staged.c.import_job_id == self.import_job_id, ~exists).group_by(id_col))
            for object_id, kind, name in self.session.execute(query):
                prev_kind, prev_name = missing.get(object_id, (None, None))
                missing[object_id] = (prev_kind or kind, prev_name or name)

        if not missing:
            return
        self._check_node_limit(len(missing))
        rows = [{"snapshot_id": self.snapshot_id, "object_id": oid, "kind": kind or UNKNOWN, "name": name or oid,
                 "domain": None, "enabled": None, "is_tier0": False, "properties": {PLACEHOLDER_FLAG: True}}
                for oid, (kind, name) in missing.items()]
        for start in range(0, len(rows), self._batch):
            self.token.check()
            self.session.execute(objects.insert(), rows[start:start + self._batch])
        self._object_count += len(rows)
        self.summary.counters["placeholders_created"] += len(rows)
        self.summary.warn(
            f"{len(rows)} referenced object(s) were not present in the upload and were added as placeholders "
            "(this usually means the collection was partial)."
        )

    def _insert_edges(self) -> None:
        staged = IngestStagedEdge.__table__
        edges = AdEdge.__table__
        src, dst = aliased(AdObject.__table__), aliased(AdObject.__table__)

        first_ids = (select(func.min(staged.c.id)).where(staged.c.import_job_id == self.import_job_id)
                     .group_by(staged.c.src_object_id, staged.c.dst_object_id, staged.c.kind))
        unique_count = self.session.scalar(select(func.count()).select_from(first_ids.subquery())) or 0
        existing = self.session.scalar(
            select(func.count()).select_from(edges).where(edges.c.snapshot_id == self.snapshot_id)) or 0
        if existing + unique_count > self.settings.max_graph_edges:
            raise LimitExceededError(
                f"This import would exceed the configured maximum of {self.settings.max_graph_edges:,} relationships "
                "per snapshot (AEGIS_MAX_GRAPH_EDGES). Nothing was imported."
            )
        self.token.check()

        selection = (
            select(literal(self.snapshot_id, Integer), src.c.id, dst.c.id, staged.c.kind,
                   staged.c.data_source, staged.c.collected_at, staged.c.is_inherited, staged.c.confidence,
                   staged.c.evidence)
            .join(src, (src.c.snapshot_id == self.snapshot_id) & (src.c.object_id == staged.c.src_object_id))
            .join(dst, (dst.c.snapshot_id == self.snapshot_id) & (dst.c.object_id == staged.c.dst_object_id))
            .where(staged.c.id.in_(first_ids))
        )
        stmt = self._insert(edges).from_select(
            ["snapshot_id", "src_object_pk", "dst_object_pk", "kind", "data_source", "collected_at", "is_inherited",
             "confidence", "evidence"],
            selection,
        ).on_conflict_do_nothing(index_elements=["snapshot_id", "src_object_pk", "dst_object_pk", "kind"])
        inserted = self.session.execute(stmt).rowcount or 0

        staged_total = self.summary.counters["edges_staged"]
        self.summary.counters["edges_inserted"] += inserted
        self.summary.counters["edges_duplicate_in_upload"] += staged_total - unique_count
        self.summary.counters["edges_already_present"] += unique_count - inserted
