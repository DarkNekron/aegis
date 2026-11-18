"""Resource-aware guards for expensive operations.

Before a heavy job (graph build, path analysis, report generation) starts, AEGIS checks that the
machine has enough free RAM and disk, and that the requested work is within configured size
limits. Failing a check raises a typed error with a human-readable reason instead of letting the
laptop swap or the process be killed.
"""

from __future__ import annotations

import os
import platform
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

import psutil

from app.core.config import Settings
from app.core.errors import InsufficientResourcesError, LimitExceededError

MB = 1024 * 1024

# Planning estimates for an in-memory NetworkX MultiDiGraph with AEGIS's slim attributes
# (integer node keys, ~5 small attributes per node, ~3 per edge). Calibrated in Phase 6
# benchmarks; deliberately on the high side.
EST_BYTES_PER_NODE = 700
EST_BYTES_PER_EDGE = 500


@dataclass(frozen=True)
class ResourceSnapshot:
    timestamp: float
    total_ram_mb: int
    available_ram_mb: int
    ram_percent: float
    cpu_percent: float
    cpu_logical: int
    cpu_physical: int
    process_rss_mb: int
    disk_total_mb: int
    disk_free_mb: int

    def to_dict(self) -> dict:
        return asdict(self)


def _psutil_probe(disk_path: Path) -> Callable[[], ResourceSnapshot]:
    process = psutil.Process(os.getpid())
    psutil.cpu_percent(interval=None)  # prime the counter; the first reading is always 0.0

    def probe() -> ResourceSnapshot:
        vm = psutil.virtual_memory()
        target = disk_path if disk_path.exists() else disk_path.anchor or "/"
        disk = psutil.disk_usage(str(target))
        return ResourceSnapshot(
            timestamp=time.time(),
            total_ram_mb=vm.total // MB,
            available_ram_mb=vm.available // MB,
            ram_percent=vm.percent,
            cpu_percent=psutil.cpu_percent(interval=None),
            cpu_logical=psutil.cpu_count(logical=True) or 1,
            cpu_physical=psutil.cpu_count(logical=False) or 1,
            process_rss_mb=process.memory_info().rss // MB,
            disk_total_mb=disk.total // MB,
            disk_free_mb=disk.free // MB,
        )

    return probe


class ResourceManager:
    def __init__(self, settings: Settings, probe: Callable[[], ResourceSnapshot] | None = None):
        self.settings = settings
        self._probe = probe or _psutil_probe(settings.data_dir)

    def snapshot(self) -> ResourceSnapshot:
        return self._probe()

    @staticmethod
    def estimate_graph_memory_mb(nodes: int, edges: int) -> int:
        return max(1, (nodes * EST_BYTES_PER_NODE + edges * EST_BYTES_PER_EDGE) // MB)

    def ensure_can_start_heavy_job(self, estimated_memory_mb: int = 0) -> ResourceSnapshot:
        """Raise ``InsufficientResourcesError`` if starting the job would leave too little free RAM."""
        snap = self.snapshot()
        needed = self.settings.min_free_ram_mb + max(0, estimated_memory_mb)
        if snap.available_ram_mb < needed:
            raise InsufficientResourcesError(
                f"Not enough free memory to start this analysis safely: {snap.available_ram_mb} MB available, "
                f"{needed} MB required ({self.settings.min_free_ram_mb} MB safety reserve + "
                f"{max(0, estimated_memory_mb)} MB estimated for the job). Close other applications or "
                "narrow the analysis scope and try again."
            )
        return snap

    def ensure_disk_space(self, required_mb: int = 0) -> ResourceSnapshot:
        snap = self.snapshot()
        needed = self.settings.min_free_disk_mb + max(0, required_mb)
        if snap.disk_free_mb < needed:
            raise InsufficientResourcesError(
                f"Not enough free disk space: {snap.disk_free_mb} MB free, {needed} MB required."
            )
        return snap

    def ensure_graph_within_limits(self, nodes: int, edges: int) -> None:
        s = self.settings
        if nodes > s.max_graph_nodes:
            raise LimitExceededError(
                f"Graph has {nodes:,} nodes; the configured limit is {s.max_graph_nodes:,} (AEGIS_MAX_GRAPH_NODES)."
            )
        if edges > s.max_graph_edges:
            raise LimitExceededError(
                f"Graph has {edges:,} relationships; the configured limit is {s.max_graph_edges:,} "
                "(AEGIS_MAX_GRAPH_EDGES)."
            )

    def ensure_upload_size(self, size_bytes: int) -> None:
        if size_bytes > self.settings.max_upload_bytes:
            raise LimitExceededError(
                f"File is {size_bytes / MB:,.1f} MB; the maximum upload size is {self.settings.max_upload_mb} MB."
            )

    @staticmethod
    def platform_info() -> dict[str, str]:
        return {
            "python": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        }
