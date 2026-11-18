"""Bounded LRU cache of built graphs (default capacity 1, see AEGIS_GRAPH_CACHE_SIZE).

* An entry is reused only while its version matches (same last import, same analysis config).
* Concurrent requests for the same snapshot wait for a single build instead of building twice.
* Evicted graphs are dropped and garbage-collected so their memory is returned promptly.
"""

from __future__ import annotations

import gc
import threading
from collections import OrderedDict
from collections.abc import Callable

from app.graph_engine.model import ADGraph


class GraphCache:
    def __init__(self, capacity: int):
        self.capacity = max(1, capacity)
        # snapshot id -> (version the entry was requested for, graph)
        self._entries: OrderedDict[int, tuple[str, ADGraph]] = OrderedDict()
        self._lock = threading.Lock()
        self._build_locks: dict[int, threading.Lock] = {}
        self.builds = 0
        self.hits = 0

    def get_or_build(self, snapshot_id: int, current_version: str, build: Callable[[], ADGraph]) -> ADGraph:
        cached = self._lookup(snapshot_id, current_version)
        if cached is not None:
            return cached
        with self._lock:
            build_lock = self._build_locks.setdefault(snapshot_id, threading.Lock())
        with build_lock:
            cached = self._lookup(snapshot_id, current_version)  # another thread may have built it
            if cached is not None:
                return cached
            graph = build()
            with self._lock:
                self.builds += 1
                self._entries[snapshot_id] = (current_version, graph)
                self._entries.move_to_end(snapshot_id)
                evicted = False
                while len(self._entries) > self.capacity:
                    self._entries.popitem(last=False)
                    evicted = True
            if evicted:
                gc.collect()
            return graph

    def _lookup(self, snapshot_id: int, version: str) -> ADGraph | None:
        with self._lock:
            entry = self._entries.get(snapshot_id)
            if entry is not None and entry[0] == version:
                self._entries.move_to_end(snapshot_id)
                self.hits += 1
                return entry[1]
            return None

    def invalidate(self, snapshot_id: int | None = None) -> None:
        with self._lock:
            if snapshot_id is None:
                self._entries.clear()
            else:
                self._entries.pop(snapshot_id, None)
        gc.collect()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"entries": len(self._entries), "capacity": self.capacity, "builds": self.builds,
                    "hits": self.hits}
