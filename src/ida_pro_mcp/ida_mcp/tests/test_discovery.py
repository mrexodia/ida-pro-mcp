"""Tests for the instance discovery module (discovery.py).

Exercises registration/unregistration round-trips, the multi-stage staleness
pipeline in discover_instances, and sort-order guarantees that server.py
relies on for auto-selection.
"""

import contextlib
import json
import os
import tempfile

from ..framework import test
from .. import discovery


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _tmp_instances_dir():
    """Redirect discovery.get_instances_dir to a temp directory, then restore."""
    with tempfile.TemporaryDirectory() as tmp:
        original = discovery.get_instances_dir
        discovery.get_instances_dir = lambda: tmp
        try:
            yield tmp
        finally:
            discovery.get_instances_dir = original


@contextlib.contextmanager
def _patched_instances_dir(path):
    """Redirect discovery.get_instances_dir to an arbitrary path, then restore."""
    original = discovery.get_instances_dir
    discovery.get_instances_dir = lambda: path
    try:
        yield
    finally:
        discovery.get_instances_dir = original


# ---------------------------------------------------------------------------
# Registration / unregistration round-trips
# ---------------------------------------------------------------------------


@test()
def test_register_unregister_roundtrip():
    """register_instance creates a file that unregister_instance removes."""
    with _tmp_instances_dir():
        path = discovery.register_instance("127.0.0.1", 55000, os.getpid(), "test.exe", "/tmp/test.idb")
        assert os.path.isfile(path)
        assert discovery.unregister_instance(55000) is True
        assert not os.path.isfile(path)


@test()
def test_unregister_nonexistent_returns_false():
    """unregister_instance returns False when no registration exists."""
    with _tmp_instances_dir():
        assert discovery.unregister_instance(99999) is False


@test()
def test_register_overwrites_existing():
    """Re-registering the same port atomically replaces the previous entry."""
    with _tmp_instances_dir() as tmp:
        discovery.register_instance("127.0.0.1", 55005, os.getpid(), "first.bin", "first.idb")
        discovery.register_instance("127.0.0.1", 55005, os.getpid(), "second.bin", "second.idb")
        with open(os.path.join(tmp, "instance_55005.json"), "r") as f:
            data = json.load(f)
        assert data["binary"] == "second.bin"


# ---------------------------------------------------------------------------
# PID liveness
# ---------------------------------------------------------------------------


@test()
def test_is_pid_alive_current_process():
    """is_pid_alive returns True for the current (known-alive) process."""
    assert discovery.is_pid_alive(os.getpid()) is True


@test()
def test_is_pid_alive_bogus_pid():
    """is_pid_alive returns False for a PID that cannot exist."""
    assert discovery.is_pid_alive(4_000_000) is False


# ---------------------------------------------------------------------------
# TCP probe
# ---------------------------------------------------------------------------


@test()
def test_probe_instance_unreachable():
    """probe_instance returns False for a port nothing listens on."""
    assert discovery.probe_instance("127.0.0.1", 1, timeout=0.5) is False


# ---------------------------------------------------------------------------
# discover_instances staleness pipeline
# ---------------------------------------------------------------------------


@test()
def test_discover_cleans_up_dead_pid():
    """discover_instances removes registrations whose PID is dead."""
    with _tmp_instances_dir() as tmp:
        discovery.register_instance("127.0.0.1", 55002, 4_000_000, "dead.bin", "dead.idb")
        assert discovery.discover_instances() == []
        assert not os.path.isfile(os.path.join(tmp, "instance_55002.json"))


@test()
def test_discover_cleans_up_corrupt_json():
    """discover_instances removes files with invalid JSON."""
    with _tmp_instances_dir() as tmp:
        corrupt_path = os.path.join(tmp, "instance_55003.json")
        with open(corrupt_path, "w") as f:
            f.write("not json{{{")
        assert discovery.discover_instances() == []
        assert not os.path.isfile(corrupt_path)


@test()
def test_discover_cleans_up_missing_required_keys():
    """discover_instances removes registrations missing host/port/pid."""
    with _tmp_instances_dir() as tmp:
        path = os.path.join(tmp, "instance_55004.json")
        with open(path, "w") as f:
            json.dump({"host": "127.0.0.1"}, f)
        assert discovery.discover_instances() == []
        assert not os.path.isfile(path)


@test()
def test_discover_skips_alive_pid_unreachable_port():
    """discover_instances removes entries with alive PID but no listening server."""
    with _tmp_instances_dir():
        discovery.register_instance("127.0.0.1", 1, os.getpid(), "no_server.bin", "no.idb")
        assert discovery.discover_instances() == []


@test()
def test_discover_returns_empty_when_dir_missing():
    """discover_instances returns [] when the instances directory doesn't exist."""
    with _patched_instances_dir("/nonexistent/path/that/does/not/exist"):
        assert discovery.discover_instances() == []


# ---------------------------------------------------------------------------
# Sort order — server.py picks instances[0], so order matters
# ---------------------------------------------------------------------------


@test()
def test_discover_sorts_by_started_at():
    """discover_instances returns results sorted by started_at (oldest first).

    server.py auto-selects instances[0], so this order determines which
    instance gets auto-connected when multiple are running.
    """
    with _tmp_instances_dir() as tmp:
        for port, ts in [(55010, "2025-01-01T00:00:02+00:00"),
                         (55011, "2025-01-01T00:00:01+00:00")]:
            info = {
                "host": "127.0.0.1", "port": port,
                "pid": os.getpid(), "binary": f"bin_{port}",
                "idb_path": f"/tmp/{port}.idb", "started_at": ts,
            }
            path = os.path.join(tmp, f"instance_{port}.json")
            with open(path, "w") as f:
                json.dump(info, f)

        orig_pid = discovery.is_pid_alive
        orig_probe = discovery.probe_instance
        discovery.is_pid_alive = lambda pid: True
        discovery.probe_instance = lambda h, p, timeout=2.0: True
        try:
            results = discovery.discover_instances()
            assert len(results) == 2
            assert results[0]["port"] == 55011
            assert results[1]["port"] == 55010
        finally:
            discovery.is_pid_alive = orig_pid
            discovery.probe_instance = orig_probe
