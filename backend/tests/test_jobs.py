import threading
import time

import pytest

from app.core.errors import AegisError, InsufficientResourcesError, JobQueueFullError, NotFoundError
from app.core.jobs import CancellationToken, JobKind, JobRunner, JobStatus
from app.core.resources import ResourceManager
from tests.conftest import FakeProbe, make_settings

WAIT = 10  # seconds; generous so slow CI machines don't flake


@pytest.fixture
def runner(settings, resources):
    r = JobRunner(settings, resources)
    yield r
    r.shutdown(wait=True)


def wait_until(predicate, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    raise AssertionError("condition not met in time")


def test_successful_job_records_result_and_progress(runner):
    def work(ctx):
        ctx.report_progress(0.5, "halfway")
        return 42

    job = runner.wait(runner.submit("answer", work).id, timeout=WAIT)
    assert job.status is JobStatus.SUCCEEDED
    assert job.result == 42
    assert job.progress == 1.0
    assert job.started_at and job.finished_at and job.finished_at >= job.started_at


def test_unexpected_exception_is_reported_without_internal_details(runner):
    def boom(ctx):
        raise RuntimeError("C:\\secret\\path leaked?")

    job = runner.wait(runner.submit("boom", boom).id, timeout=WAIT)
    assert job.status is JobStatus.FAILED
    assert job.error_code == "internal_error"
    assert "secret" not in job.error and "reference" in job.error


def test_aegis_error_message_is_kept(runner):
    def fail(ctx):
        raise AegisError("Snapshot has no data.", code="empty_snapshot")

    job = runner.wait(runner.submit("fail", fail).id, timeout=WAIT)
    assert (job.status, job.error, job.error_code) == (JobStatus.FAILED, "Snapshot has no data.", "empty_snapshot")


def test_running_job_cancels_cooperatively(runner):
    started = threading.Event()

    def loop(ctx):
        started.set()
        while True:
            ctx.token.checkpoint(every=1)
            time.sleep(0.005)

    job = runner.submit("loop", loop)
    assert started.wait(WAIT)
    runner.cancel(job.id)
    runner.wait(job.id, timeout=WAIT)
    assert job.status is JobStatus.CANCELLED


def test_timeout_stops_job(runner):
    def loop(ctx):
        while True:
            ctx.token.checkpoint(every=1)
            time.sleep(0.005)

    job = runner.wait(runner.submit("slow", loop, timeout_seconds=0.2).id, timeout=WAIT)
    assert job.status is JobStatus.TIMED_OUT
    assert job.error_code == "job_timeout"


def test_only_one_heavy_job_runs_at_a_time(runner):
    release = threading.Event()
    running = []
    lock = threading.Lock()
    max_seen = [0]

    def heavy(ctx):
        with lock:
            running.append(1)
            max_seen[0] = max(max_seen[0], len(running))
        release.wait(WAIT)
        with lock:
            running.pop()

    first = runner.submit("h1", heavy, kind=JobKind.HEAVY)
    second = runner.submit("h2", heavy, kind=JobKind.HEAVY)
    wait_until(lambda: first.status is JobStatus.RUNNING)
    time.sleep(0.1)
    assert second.status is JobStatus.QUEUED  # waiting for the single heavy worker
    release.set()
    runner.wait(first.id, WAIT)
    runner.wait(second.id, WAIT)
    assert max_seen[0] == 1
    assert first.status is second.status is JobStatus.SUCCEEDED


def test_queued_job_can_be_cancelled_before_it_starts(runner):
    release = threading.Event()
    ran = []
    blocker = runner.submit("blocker", lambda ctx: release.wait(WAIT), kind=JobKind.HEAVY)
    wait_until(lambda: blocker.status is JobStatus.RUNNING)
    queued = runner.submit("queued", lambda ctx: ran.append(1), kind=JobKind.HEAVY)

    runner.cancel(queued.id)
    assert queued.status is JobStatus.CANCELLED  # immediate, without waiting for the worker
    release.set()
    runner.wait(blocker.id, WAIT)
    runner.wait(queued.id, WAIT)
    assert ran == []


def test_pending_job_limit_applies_backpressure(tmp_path):
    settings = make_settings(tmp_path, max_pending_jobs=2, max_light_workers=1)
    runner = JobRunner(settings, ResourceManager(settings, probe=FakeProbe()))
    release = threading.Event()
    try:
        runner.submit("a", lambda ctx: release.wait(WAIT))
        runner.submit("b", lambda ctx: release.wait(WAIT))
        with pytest.raises(JobQueueFullError):
            runner.submit("c", lambda ctx: None)
    finally:
        release.set()
        runner.shutdown(wait=True)


def test_heavy_job_refused_when_ram_is_low(tmp_path):
    settings = make_settings(tmp_path, min_free_ram_mb=768)
    probe = FakeProbe(available_ram_mb=500)
    runner = JobRunner(settings, ResourceManager(settings, probe=probe))
    try:
        with pytest.raises(InsufficientResourcesError):
            runner.submit("big", lambda ctx: None, kind=JobKind.HEAVY)
        # light jobs are not gated on the RAM reserve
        light = runner.wait(runner.submit("small", lambda ctx: 1).id, WAIT)
        assert light.status is JobStatus.SUCCEEDED
    finally:
        runner.shutdown(wait=True)


def test_ram_is_rechecked_when_queued_heavy_job_starts(tmp_path):
    settings = make_settings(tmp_path, min_free_ram_mb=768)
    probe = FakeProbe(available_ram_mb=4000)
    runner = JobRunner(settings, ResourceManager(settings, probe=probe))
    release = threading.Event()
    try:
        first = runner.submit("first", lambda ctx: release.wait(WAIT), kind=JobKind.HEAVY)
        wait_until(lambda: first.status is JobStatus.RUNNING)
        second = runner.submit("second", lambda ctx: None, kind=JobKind.HEAVY)
        probe.available_ram_mb = 300  # memory pressure appears while second is queued
        release.set()
        runner.wait(second.id, WAIT)
        assert second.status is JobStatus.FAILED
        assert second.error_code == "insufficient_resources"
    finally:
        runner.shutdown(wait=True)


def test_finished_jobs_are_pruned(settings, resources):
    runner = JobRunner(settings, resources, retention=3)
    try:
        jobs = [runner.submit(f"j{i}", lambda ctx: None) for i in range(6)]
        for job in jobs:  # wait on the futures directly: finished jobs may already be pruned
            job.future.result(timeout=WAIT)
        wait_until(lambda: all(not j.status.is_active for j in jobs))
        assert len(runner.list()) == 3
        with pytest.raises(NotFoundError):
            runner.get(jobs[0].id)
    finally:
        runner.shutdown(wait=True)


def test_stats_and_public_view(runner):
    job = runner.wait(runner.submit("x", lambda ctx: {"big": "object"}).id, WAIT)
    view = job.public_view()
    assert view["status"] == "succeeded" and "result" not in view
    assert runner.stats()["succeeded"] == 1


def test_cancellation_token_standalone():
    token = CancellationToken(timeout_seconds=None)
    token.check()
    token.cancel()
    with pytest.raises(AegisError, match="cancelled"):
        token.check()
    expiring = CancellationToken(timeout_seconds=0.01)
    time.sleep(0.03)
    with pytest.raises(AegisError, match="time limit"):
        expiring.check()


def test_checkpoint_only_checks_every_n_calls():
    token = CancellationToken()
    token.cancel()
    for _ in range(9):
        token.checkpoint(every=10)  # no raise yet
    with pytest.raises(AegisError):
        token.checkpoint(every=10)
