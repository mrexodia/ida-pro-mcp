"""Main-thread job pump tests (no IDA required)."""

import importlib.util
import threading
import time
from pathlib import Path

import pytest

# Import by path: ida_mcp/__init__.py pulls in IDA, which is absent here.
_spec = importlib.util.spec_from_file_location(
    "ida_mcp_mainthread",
    Path(__file__).resolve().parents[1] / "src/ida_pro_mcp/ida_mcp/mainthread.py",
)
assert _spec is not None and _spec.loader is not None
_mainthread = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mainthread)
MainThreadPump = _mainthread.MainThreadPump
PumpBusyError = _mainthread.PumpBusyError


def _run_pump(pump: MainThreadPump) -> threading.Thread:
    thread = threading.Thread(target=pump.run, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    for _ in range(200):
        if pump.active:
            return thread
        time.sleep(0.01)
    raise AssertionError("pump did not start")


def test_submit_runs_job_on_pump_thread():
    pump = MainThreadPump()
    thread = _run_pump(pump)
    try:
        assert pump.submit(lambda: threading.get_ident(), timeout=5) == thread.ident
    finally:
        pump.stop()


def test_submit_propagates_exception():
    pump = MainThreadPump()
    _run_pump(pump)
    try:
        with pytest.raises(ValueError, match="boom"):
            pump.submit(lambda: (_ for _ in ()).throw(ValueError("boom")), timeout=5)
    finally:
        pump.stop()


def test_submit_on_pump_thread_runs_inline():
    pump = MainThreadPump()
    _run_pump(pump)
    try:
        nested = pump.submit(lambda: pump.submit(lambda: "inner", timeout=5), timeout=5)
        assert nested == "inner"
    finally:
        pump.stop()


def test_busy_status_reports_running_job():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    try:
        blocker = threading.Thread(
            target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
        )
        blocker.start()
        for _ in range(200):
            if pump.busy_status() is not None:
                break
            time.sleep(0.01)
        busy = pump.busy_status()
        assert busy is not None and busy["tool"] == "slow"
        assert busy["elapsed_sec"] >= 0
    finally:
        release.set()
        pump.stop()


def test_submit_times_out_while_pump_is_busy():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    try:
        blocker = threading.Thread(
            target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
        )
        blocker.start()
        time.sleep(0.05)
        with pytest.raises(PumpBusyError, match="slow"):
            pump.submit(lambda: "never", label="quick", timeout=0.2)
    finally:
        release.set()
        pump.stop()


def test_queued_job_is_dropped_after_its_waiter_gives_up():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    ran = []
    try:
        blocker = threading.Thread(
            target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
        )
        blocker.start()
        time.sleep(0.05)
        with pytest.raises(PumpBusyError):
            pump.submit(lambda: ran.append("late"), label="abandoned", timeout=0.2)
        release.set()
        time.sleep(0.2)
        assert ran == []
    finally:
        release.set()
        pump.stop()


def test_submit_without_running_pump_raises():
    pump = MainThreadPump()
    with pytest.raises(RuntimeError, match="not running"):
        pump.submit(lambda: None, timeout=1)


def test_stop_fails_pending_jobs():
    pump = MainThreadPump()
    _run_pump(pump)
    release = threading.Event()
    blocker = threading.Thread(
        target=lambda: pump.submit(release.wait, label="slow", timeout=10), daemon=True
    )
    blocker.start()
    time.sleep(0.05)

    errors = []

    def pending():
        try:
            pump.submit(lambda: "never", label="pending", timeout=10)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    waiter = threading.Thread(target=pending, daemon=True)
    waiter.start()
    time.sleep(0.05)
    pump.stop()
    release.set()
    waiter.join(timeout=5)

    assert errors and "shutting down" in str(errors[0])


def test_job_submitted_before_run_is_queued_not_rejected():
    """Arming closes the window between serve() and run()."""
    pump = MainThreadPump()
    pump.arm()
    results: list = []
    submitter = threading.Thread(
        target=lambda: results.append(pump.submit(lambda: "late", timeout=5)),
        daemon=True,
    )
    submitter.start()
    time.sleep(0.05)
    assert results == []
    runner = threading.Thread(target=pump.run, kwargs={"poll_interval": 0.01}, daemon=True)
    runner.start()
    submitter.join(timeout=5)
    pump.stop()
    assert results == ["late"]
