"""Builds an ``ADGraph`` for a snapshot from the database.

Resource discipline (docs/ARCHITECTURE.md §6):
* counts are checked against AEGIS_MAX_GRAPH_NODES / _EDGES and free RAM *before* loading anything;
* rows are streamed with SQLAlchemy Core (``yield_per``); no ORM objects, no duplicate copies;
* the cancellation token is checked while streaming.
"""

from __future__ import annotations

import logging
import sys
import time
from collections import defaultdict

import networkx as nx
from sqlalchemy import bindparam, func, select, update

from app.core.errors import NotFoundError, ValidationFailedError
from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.algorithms.index import gc_paused
from app.graph_engine.config import AnalysisConfig, load_config
from app.graph_engine.model import ADGraph, BuildStats
from app.graph_engine.rules import rule_for
from app.graph_engine.tier0 import NodeFacts, Tier0Classifier
from app.models import AdEdge, AdObject, ImportJob, Snapshot

logger = logging.getLogger(__name__)

STREAM_BATCH = 5000
SOURCE_KINDS = ("User", "ServiceAccount")
_HINT_TAGS = ("admin_tier_0",)


def snapshot_version(session, snapshot_id: int, config: AnalysisConfig) -> str:
    """Changes whenever the snapshot's data or the analysis configuration changes."""
    last_import = session.scalar(select(func.max(ImportJob.id)).where(ImportJob.snapshot_id == snapshot_id)) or 0
    return f"{last_import}:{config.fingerprint()}"


def _is_hinted(props: dict) -> bool:
    tags = props.get("system_tags") or ""
    tags = " ".join(tags) if isinstance(tags, list) else str(tags)
    return bool(props.get("highvalue")) or any(t in tags for t in _HINT_TAGS)


class GraphBuilder:
    def __init__(self, db: Database, resources: ResourceManager):
        self.db = db
        self.resources = resources

    def build(self, snapshot_id: int, *, token: CancellationToken | None = None,
              config: AnalysisConfig | None = None, persist_tier0: bool = True) -> ADGraph:
        token = token or CancellationToken()
        started = time.perf_counter()
        objects, edges = AdObject.__table__, AdEdge.__table__

        with self.db.session() as s:
            snap = s.get(Snapshot, snapshot_id)
            if snap is None:
                raise NotFoundError("Snapshot not found.")
            if snap.status == "importing":
                raise ValidationFailedError("The snapshot is still importing; try again when the import finishes.")
            config = config or load_config(s)
            version = snapshot_version(s, snapshot_id, config)
            n_nodes = s.scalar(select(func.count()).select_from(objects).where(objects.c.snapshot_id == snapshot_id))
            n_edges = s.scalar(select(func.count()).select_from(edges).where(edges.c.snapshot_id == snapshot_id))

        self.resources.ensure_graph_within_limits(n_nodes, n_edges)
        estimate = self.resources.estimate_graph_memory_mb(n_nodes, n_edges)
        self.resources.ensure_can_start_heavy_job(estimate)

        g = nx.MultiDiGraph()
        classifier = Tier0Classifier(config)
        names: dict[int, str] = {}
        kinds: dict[int, str] = {}
        domains: set[int] = set()
        stats = BuildStats(estimated_memory_mb=estimate)
        intern = sys.intern

        with self.db.engine.connect() as conn, gc_paused():  # bulk, acyclic allocation (see gc_paused)
            node_rows = conn.execution_options(yield_per=STREAM_BATCH).execute(
                select(objects.c.id, objects.c.object_id, objects.c.kind, objects.c.name, objects.c.enabled,
                       objects.c.properties)
                .where(objects.c.snapshot_id == snapshot_id).order_by(objects.c.id))
            for pk, object_id, kind, name, enabled, props in node_rows:
                token.checkpoint(1024)
                props = props or {}
                placeholder = bool(props.get("aegis_placeholder"))
                kind = intern(kind)
                g.add_node(pk, oid=object_id, kind=kind, name=name, enabled=enabled, placeholder=placeholder,
                           tier0=False)
                names[pk], kinds[pk] = name, kind
                stats.placeholders += placeholder
                if kind == "Domain" and not placeholder:
                    domains.add(pk)
                classifier.observe(pk, NodeFacts(object_id=object_id, kind=kind, name=name,
                                                 is_dc=bool(props.get("isdc")), placeholder=placeholder,
                                                 hinted=_is_hinted(props)))

            replication: dict[tuple[int, int], dict[str, int]] = defaultdict(dict)
            member_of: dict[int, list[int]] = defaultdict(list)  # group -> direct members
            edge_rows = conn.execution_options(yield_per=STREAM_BATCH).execute(
                select(edges.c.id, edges.c.src_object_pk, edges.c.dst_object_pk, edges.c.kind, edges.c.confidence)
                .where(edges.c.snapshot_id == snapshot_id).order_by(edges.c.id))
            for eid, src, dst, kind, confidence in edge_rows:
                token.checkpoint(1024)
                kind = intern(kind)
                rule = rule_for(kind, kinds.get(dst, "Unknown"))
                traversable = rule.traversable or (kind == "TrustedBy" and config.traverse_trusts)
                g.add_edge(src, dst, key=eid, kind=kind, t=traversable, cond=rule.conditional or kind == "TrustedBy",
                           w=rule.cost if rule.traversable else 3.0, sev=rule.severity, conf=confidence)
                stats.traversable_edges += traversable
                if kind == "MemberOf":
                    member_of[dst].append(src)
                elif kind in ("GetChanges", "GetChangesAll") and dst in domains:
                    replication[(src, dst)][kind] = eid

        # Derived DCSync edges: both replication rights on the same domain.
        derived_evidence: dict[str, list[int]] = {}
        dcsync_rule = rule_for("DCSync", "Domain")
        for (src, dst), rights in replication.items():
            if len(rights) == 2:
                key = f"dcsync:{src}:{dst}"
                g.add_edge(src, dst, key=key, kind="DCSync", t=True, cond=False, w=dcsync_rule.cost,
                           sev=dcsync_rule.severity, conf=1.0, derived=True)
                derived_evidence[key] = sorted(rights.values())
                classifier.add_dcsync(src, names[dst])
                stats.derived_edges += 1
                stats.traversable_edges += 1
        token.check()

        reasons = classifier.finish(member_of, names)
        tier0 = frozenset(reasons)
        for node in tier0:
            g.nodes[node]["tier0"] = True
        sources = frozenset(
            n for n, data in g.nodes(data=True)
            if data["kind"] in SOURCE_KINDS and data["enabled"] is True and not data["placeholder"] and n not in tier0
        )

        stats.nodes, stats.edges = g.number_of_nodes(), g.number_of_edges()
        stats.tier0, stats.sources = len(tier0), len(sources)
        if persist_tier0:
            self._persist_tier0(snapshot_id, reasons)
        stats.build_seconds = round(time.perf_counter() - started, 3)
        logger.info("Built graph for snapshot %s: %s nodes, %s edges (%s traversable), %s tier-0, %.2fs",
                    snapshot_id, stats.nodes, stats.edges, stats.traversable_edges, stats.tier0, stats.build_seconds)
        return ADGraph(snapshot_id=snapshot_id, version=version, config=config, g=g, tier0=tier0,
                       tier0_reasons=reasons, sources=sources, derived_evidence=derived_evidence, stats=stats,
                       tier0_categories={n: frozenset(classifier.categories[n]) for n in tier0})

    def _persist_tier0(self, snapshot_id: int, reasons: dict[int, list[str]]) -> None:
        """Store the classification so list views and reports can filter on it without the graph."""
        objects = AdObject.__table__
        with self.db.session() as s:
            s.execute(update(objects).where(objects.c.snapshot_id == snapshot_id, objects.c.is_tier0.is_(True))
                      .values(is_tier0=False, tier0_reason=None))
            rows = [{"b_id": node, "b_reason": "; ".join(r)[:255]} for node, r in reasons.items()]
            if rows:
                s.execute(update(objects).where(objects.c.id == bindparam("b_id"))
                          .values(is_tier0=True, tier0_reason=bindparam("b_reason")), rows,
                          execution_options={"synchronize_session": False})
            s.commit()
