"""Entry point used by analyses and the API: returns a cached or freshly built graph."""

from __future__ import annotations

from app.core.jobs import CancellationToken
from app.core.resources import ResourceManager
from app.db.session import Database
from app.graph_engine.builder import GraphBuilder, snapshot_version
from app.graph_engine.cache import GraphCache
from app.graph_engine.config import load_config
from app.graph_engine.model import ADGraph


class GraphService:
    def __init__(self, db: Database, resources: ResourceManager, cache: GraphCache):
        self.db = db
        self.cache = cache
        self.builder = GraphBuilder(db, resources)

    def get(self, snapshot_id: int, token: CancellationToken | None = None) -> ADGraph:
        with self.db.session() as s:
            config = load_config(s)
            version = snapshot_version(s, snapshot_id, config)
        return self.cache.get_or_build(
            snapshot_id, version, lambda: self.builder.build(snapshot_id, token=token, config=config))
