"""Regression tests for discovery of live instances with transient probe errors.

A single failed TCP probe must not delete a registration whose PID is alive;
the registration is pruned only after repeated failures.
"""

import importlib.util
import json
import pathlib

import pytest

_DISCOVERY_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "discovery.py"
)
_SPEC = importlib.util.spec_from_file_location("discovery_prune_race_test", _DISCOVERY_PATH)
assert _SPEC is not None and _SPEC.loader is not None
discovery = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(discovery)
_PROBE_FAILURES_BEFORE_PRUNE = getattr(discovery, "_PROBE_FAILURES_BEFORE_PRUNE", 3)


@pytest.fixture(autouse=True)
def _reset_probe_failures():
    failures = getattr(discovery, "_probe_failures", {})
    failures.clear()
    try:
        yield
    finally:
        failures.clear()


@pytest.fixture
def instances_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "get_instances_dir", lambda: str(tmp_path))
    monkeypatch.setattr(discovery, "is_pid_alive", lambda _pid: True)
    return tmp_path


def _register(directory, port, *, pid=4242, **extra):
    info = {
        "host": "127.0.0.1",
        "port": port,
        "pid": pid,
        "binary": f"bin_{port}",
        "idb_path": f"/tmp/{port}.idb",
        "started_at": f"2026-01-01T00:00:{port % 60:02d}+00:00",
    }
    info.update(extra)
    path = directory / f"instance_{port}.json"
    path.write_text(json.dumps(info), encoding="utf-8")
    return path


def test_transient_probe_failure_keeps_live_registration(instances_dir, monkeypatch):
    path = _register(instances_dir, 56000)
    monkeypatch.setattr(discovery, "probe_instance", lambda *_args, **_kwargs: False)

    for _ in range(_PROBE_FAILURES_BEFORE_PRUNE - 1):
        assert discovery.discover_instances() == []
        assert path.exists(), "a transient probe failure deleted a live registration"

    monkeypatch.setattr(discovery, "probe_instance", lambda *_args, **_kwargs: True)
    assert [inst["port"] for inst in discovery.discover_instances()] == [56000]
    assert path.exists()

    # The successful probe resets the debounce, so a new streak is tolerated.
    monkeypatch.setattr(discovery, "probe_instance", lambda *_args, **_kwargs: False)
    for _ in range(_PROBE_FAILURES_BEFORE_PRUNE - 1):
        assert discovery.discover_instances() == []
        assert path.exists()


def test_persistent_probe_failure_prunes_registration(instances_dir, monkeypatch):
    path = _register(instances_dir, 56001)
    monkeypatch.setattr(discovery, "probe_instance", lambda *_args, **_kwargs: False)

    for _ in range(_PROBE_FAILURES_BEFORE_PRUNE - 1):
        assert discovery.discover_instances() == []
        assert path.exists()

    assert discovery.discover_instances() == []
    assert not path.exists(), "a permanently unreachable registration was never pruned"


def test_failure_streaks_are_tracked_per_instance(instances_dir, monkeypatch):
    transient = _register(instances_dir, 56010)
    stale = _register(instances_dir, 56011)
    transient_calls = 0

    def probe(_host, port, timeout=2.0):
        nonlocal transient_calls
        if port == 56010:
            transient_calls += 1
            return transient_calls > 1
        return False

    monkeypatch.setattr(discovery, "probe_instance", probe)

    assert discovery.discover_instances() == []
    assert transient.exists() and stale.exists()

    found = discovery.discover_instances()
    assert [inst["port"] for inst in found] == [56010]
    assert transient.exists()
    assert stale.exists()

    found = discovery.discover_instances()
    assert [inst["port"] for inst in found] == [56010]
    assert transient.exists()
    assert not stale.exists()


def test_dead_pid_is_still_pruned_immediately(instances_dir, monkeypatch):
    path = _register(instances_dir, 56002)
    monkeypatch.setattr(discovery, "is_pid_alive", lambda _pid: False)
    monkeypatch.setattr(discovery, "probe_instance", lambda *_args, **_kwargs: True)

    assert discovery.discover_instances() == []
    assert not path.exists()


def test_unlink_failure_keeps_file_and_does_not_abort_discovery(
    instances_dir, monkeypatch
):
    path = _register(instances_dir, 56003)
    healthy = _register(instances_dir, 56004)
    monkeypatch.setattr(
        discovery, "probe_instance", lambda _host, port, timeout=2.0: port == 56004
    )

    def deny_unlink(_path):
        raise PermissionError("registration directory is read-only")

    monkeypatch.setattr(discovery.os, "unlink", deny_unlink)

    for _ in range(_PROBE_FAILURES_BEFORE_PRUNE):
        found = discovery.discover_instances()
        assert [inst["port"] for inst in found] == [56004]
        assert path.exists()

    assert healthy.exists()

