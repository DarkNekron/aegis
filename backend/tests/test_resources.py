import pytest

from app.core.errors import InsufficientResourcesError, LimitExceededError
from app.core.resources import ResourceManager
from tests.conftest import FakeProbe, make_settings


def test_heavy_job_allowed_when_ram_is_available(resources):
    snap = resources.ensure_can_start_heavy_job(estimated_memory_mb=500)
    assert snap.available_ram_mb == 4096


def test_heavy_job_refused_below_reserve(tmp_path):
    rm = ResourceManager(make_settings(tmp_path, min_free_ram_mb=768), probe=FakeProbe(available_ram_mb=700))
    with pytest.raises(InsufficientResourcesError) as exc:
        rm.ensure_can_start_heavy_job()
    assert "700 MB available" in exc.value.message
    assert exc.value.http_status == 503


def test_estimated_job_memory_counts_against_reserve(tmp_path):
    rm = ResourceManager(make_settings(tmp_path, min_free_ram_mb=768), probe=FakeProbe(available_ram_mb=1000))
    rm.ensure_can_start_heavy_job(estimated_memory_mb=200)  # 968 needed, 1000 available
    with pytest.raises(InsufficientResourcesError):
        rm.ensure_can_start_heavy_job(estimated_memory_mb=300)  # 1068 needed


def test_disk_space_guard(tmp_path):
    rm = ResourceManager(make_settings(tmp_path, min_free_disk_mb=1024), probe=FakeProbe(disk_free_mb=1500))
    rm.ensure_disk_space(required_mb=400)
    with pytest.raises(InsufficientResourcesError):
        rm.ensure_disk_space(required_mb=600)


def test_graph_limits(tmp_path):
    rm = ResourceManager(make_settings(tmp_path, max_graph_nodes=100, max_graph_edges=500), probe=FakeProbe())
    rm.ensure_graph_within_limits(100, 500)
    with pytest.raises(LimitExceededError, match="AEGIS_MAX_GRAPH_NODES"):
        rm.ensure_graph_within_limits(101, 10)
    with pytest.raises(LimitExceededError, match="AEGIS_MAX_GRAPH_EDGES"):
        rm.ensure_graph_within_limits(10, 501)


def test_upload_limit(tmp_path):
    rm = ResourceManager(make_settings(tmp_path, max_upload_mb=1), probe=FakeProbe())
    rm.ensure_upload_size(1024 * 1024)
    with pytest.raises(LimitExceededError):
        rm.ensure_upload_size(1024 * 1024 + 1)


def test_memory_estimate_scales_with_graph_size():
    small = ResourceManager.estimate_graph_memory_mb(1_000, 5_000)
    large = ResourceManager.estimate_graph_memory_mb(100_000, 1_000_000)
    assert 1 <= small < large
    assert 400 <= large <= 1000  # planning range from docs/SYSTEM_ASSESSMENT.md


def test_real_psutil_probe_returns_sane_values(settings):
    snap = ResourceManager(settings).snapshot()
    assert snap.total_ram_mb > 0
    assert 0 < snap.available_ram_mb <= snap.total_ram_mb
    assert snap.cpu_logical >= snap.cpu_physical >= 1
    assert snap.process_rss_mb > 0
    assert snap.disk_free_mb > 0
