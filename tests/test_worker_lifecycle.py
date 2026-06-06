"""Unit tests for ida_pro_mcp.worker_lifecycle.WorkerLifecycle.

These run outside IDA: the module imports nothing IDA-specific.
"""

import threading
import time

from ida_pro_mcp.worker_lifecycle import WorkerLifecycle


def test_check_returns_none_while_under_ttl():
    lc = WorkerLifecycle(idle_ttl_sec=60.0, poll_interval_sec=0.05)
    assert lc.check_shutdown_reason() is None


def test_check_fires_after_idle_ttl():
    lc = WorkerLifecycle(idle_ttl_sec=0.05, poll_interval_sec=0.05)
    time.sleep(0.10)
    reason = lc.check_shutdown_reason()
    assert reason is not None and "no requests" in reason


def test_touch_resets_idle_ttl():
    lc = WorkerLifecycle(idle_ttl_sec=0.10, poll_interval_sec=0.05)
    time.sleep(0.06)
    lc.touch()
    time.sleep(0.06)
    assert lc.check_shutdown_reason() is None
    time.sleep(0.10)
    assert lc.check_shutdown_reason() is not None


def test_watchdog_fires_callback_and_exits():
    fired: list[str] = []
    done = threading.Event()

    def on_shutdown(reason: str) -> None:
        fired.append(reason)
        done.set()

    lc = WorkerLifecycle(idle_ttl_sec=0.05, poll_interval_sec=0.02)
    lc.start(on_shutdown=on_shutdown)
    try:
        assert done.wait(timeout=2.0), "watchdog did not fire"
        assert fired and "no requests" in fired[0]
    finally:
        lc.stop()


def test_watchdog_does_not_fire_while_touched():
    fired: list[str] = []
    lc = WorkerLifecycle(idle_ttl_sec=0.10, poll_interval_sec=0.02)
    lc.start(on_shutdown=lambda reason: fired.append(reason))
    try:
        deadline = time.monotonic() + 0.30
        while time.monotonic() < deadline:
            lc.touch()
            time.sleep(0.03)
        assert fired == []
    finally:
        lc.stop()


def test_snapshot_exposes_idle_ttl():
    lc = WorkerLifecycle(idle_ttl_sec=42.0)
    snap = lc.snapshot()
    assert snap["idle_ttl_sec"] == 42.0
    assert isinstance(snap["last_request_age_sec"], float)


def test_set_idle_ttl_uses_request_when_above_min():
    lc = WorkerLifecycle(idle_ttl_sec=10.0)
    lc.set_idle_ttl(1800.0)
    assert lc.idle_ttl_sec == 1800.0


def test_set_idle_ttl_clamps_to_min():
    lc = WorkerLifecycle(idle_ttl_sec=1000.0)
    lc.set_idle_ttl(0)
    assert lc.idle_ttl_sec == WorkerLifecycle.MIN_IDLE_TTL_SEC
    lc.set_idle_ttl(-50.0)
    assert lc.idle_ttl_sec == WorkerLifecycle.MIN_IDLE_TTL_SEC
    lc.set_idle_ttl(3.0)
    assert lc.idle_ttl_sec == WorkerLifecycle.MIN_IDLE_TTL_SEC


def test_set_idle_ttl_adds_load_time():
    lc = WorkerLifecycle(idle_ttl_sec=10.0)
    lc.set_idle_ttl(600.0, load_time_sec=45.0)
    assert lc.idle_ttl_sec == 645.0


def test_set_idle_ttl_clamps_user_then_adds_load_time():
    lc = WorkerLifecycle(idle_ttl_sec=10.0)
    lc.set_idle_ttl(0.0, load_time_sec=120.0)
    assert lc.idle_ttl_sec == WorkerLifecycle.MIN_IDLE_TTL_SEC + 120.0


def test_set_idle_ttl_ignores_negative_load_time():
    lc = WorkerLifecycle(idle_ttl_sec=10.0)
    lc.set_idle_ttl(600.0, load_time_sec=-5.0)
    assert lc.idle_ttl_sec == 600.0
