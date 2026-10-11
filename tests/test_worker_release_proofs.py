"""Worker release-proof regression tests; no licensed IDA engine required."""

import json
import subprocess
import sys
from itertools import count
from threading import Event, Thread

import pytest

from ida_pro_mcp import idalib_supervisor as m

_ids = count(12001)


class FakeProcess:
    def __init__(self, exit_code=None):
        self.pid = next(_ids)
        self.returncode = exit_code

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class FakeSupervisor(m.IdalibSupervisor):
    def __init__(self):
        super().__init__(m.McpServer("test-release"), max_workers=3)
        self.saved = []

    def _spawn_worker(self):
        return m.WorkerSession(
            session_id="__schema__", input_path="", filename="",
            process=FakeProcess(), owned=True,
        )

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        if name == "idb_open":
            return {
                "success": True,
                "session": {
                    "session_id": arguments["preferred_session_id"],
                    "input_path": arguments["input_path"],
                    "filename": "input.bin",
                },
            }
        if name == "idb_save":
            self.saved.append(worker.session_id)
            return {"ok": True}
        raise AssertionError(name)

    def _probe_session_health(self, session, **kwargs):
        alive = session.is_alive()
        return {"state": "ok" if alive else "dead", "reachable": alive}


@pytest.fixture
def fixture(monkeypatch, tmp_path):
    monkeypatch.setattr(m._discovery, "discover_instances", list)
    sup = FakeSupervisor()
    target = tmp_path / "input.bin"
    target.write_bytes(b"original private input")
    return sup, target


def open_owned(sup, target, name="owned"):
    return sup.open_session(str(target), session_id=name, mode="force_headless")


def check_proof(proof, session, path):
    assert proof["verified"] is True
    assert proof["status"] == "terminated"
    assert proof["session_id"] == session.session_id
    assert proof["release_id"] == session.release_id
    assert proof["input_path"] == str(path)
    assert proof["owned"] is True
    assert proof["backend"] == "worker"
    assert proof["worker_pid"] == session.process.pid
    assert proof["exit_code"] is not None


def test_live_close_proves_termination_then_repeat_is_idempotent(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    for idx in range(2):
        result = sup.close_session(
            "owned", save=False, expected_input_path=str(target),
            release_id=session.release_id,
        )
        assert result["success"] is True
        assert result["saved"] is None
        check_proof(result["release"], session, target)
    assert session.process.poll() is not None
    assert sup.sessions == {}
    assert sup.path_to_session == {}
    assert sup.saved == []
    assert target.read_bytes() == b"original private input"


def test_reaped_exited_worker_releases_by_exact_generation(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    session.process.returncode = 9
    with pytest.raises(RuntimeError, match="not reachable"):
        sup.resolve_session("owned")
    assert "owned" not in sup.sessions
    for _ in range(2):
        result = sup.close_session(
            "owned", save=False, expected_input_path=str(target),
            release_id=session.release_id,
        )
        check_proof(result["release"], session, target)


def test_idb_open_exposes_token_but_idb_list_does_not(fixture, monkeypatch):
    sup, target = fixture
    monkeypatch.setattr(m, "supervisor", sup)
    result = m.idb_open(str(target), mode="force_headless")
    assert result["success"] is True
    session_id = result["session"]["session_id"]
    token = result["session"]["release_id"]
    session = sup.sessions[session_id]
    assert token == sup.sessions[session_id].release_id
    assert "release_id" not in m.idb_list()["sessions"][0]
    closed = m.idb_close(
        session_id, save=False, expected_input_path=str(target), release_id=token,
    )
    check_proof(closed["release"], session, target)


def test_wrong_session_path_or_generation_cannot_claim_release(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    with pytest.raises(RuntimeError, match="identity mismatch"):
        sup.close_session("owned", save=False, release_id="different")
    with pytest.raises(RuntimeError, match="identity mismatch"):
        sup.close_session("owned", save=False, expected_input_path=str(target) + ".other")
    assert session.process.poll() is None
    sup.close_session("owned", save=False)
    with pytest.raises(RuntimeError):
        sup.close_session("wrong", save=False, expected_input_path=str(target),
                          release_id=session.release_id)
    with pytest.raises(RuntimeError, match="identity mismatch"):
        sup.close_session("owned", save=False, expected_input_path=str(target) + ".wrong",
                          release_id=session.release_id)
    with pytest.raises(RuntimeError, match="unknown"):
        sup.close_session("owned", save=False, expected_input_path=str(target),
                          release_id="not-the-generation")


def test_unregistered_live_worker_is_not_a_successful_empty_inventory(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    with sup._lock:
        sup._unregister_session_locked("owned")
    assert sup.list_sessions() == []
    assert session.process.poll() is None
    with pytest.raises(RuntimeError, match="unknown"):
        sup.close_session("owned", save=False, expected_input_path=str(target),
                          release_id=session.release_id)
    assert (session.session_id, session.release_id) in sup._pending_releases
    assert not sup._release_receipts
    # Only after the *same* process object exits may its receipt become valid.
    session.process.returncode = -9
    done = sup.close_session("owned", save=False, expected_input_path=str(target),
                             release_id=session.release_id)
    check_proof(done["release"], session, target)


def test_missing_process_handle_never_proves_owned_release(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    session.process = None
    with pytest.raises(RuntimeError, match="unconfirmed"):
        sup.close_session("owned", save=False)
    assert sup.sessions["owned"] is session
    assert not sup._release_receipts


def test_termination_timeout_preserves_registry_and_refuses_proof(fixture):
    sup, target = fixture
    session = open_owned(sup, target)

    class Stuck(FakeProcess):
        def terminate(self):
            raise TimeoutError("timeout")

        def kill(self):
            raise TimeoutError("still alive")

    session.process = Stuck()
    with pytest.raises(TimeoutError, match="still alive"):
        sup.close_session("owned", save=False, expected_input_path=str(target),
                          release_id=session.release_id)
    assert sup.sessions["owned"] is session
    assert session.closing is False
    assert sup._release_receipts == {}


def test_cancel_during_termination_keeps_owner_and_unlocks(fixture, monkeypatch):
    sup, target = fixture
    session = open_owned(sup, target)

    def interrupted(_):
        raise KeyboardInterrupt()

    monkeypatch.setattr(sup, "_terminate_worker", interrupted)
    with pytest.raises(KeyboardInterrupt):
        sup.close_session("owned", save=False)
    assert sup.sessions["owned"] is session
    assert session.closing is False


def test_concurrent_close_never_forges_premature_receipt(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    entered, proceed = Event(), Event()
    original = sup._terminate_worker
    results = []

    def blocked(worker):
        entered.set()
        assert proceed.wait(5)
        return original(worker)

    sup._terminate_worker = blocked

    def run_close():
        results.append(sup.close_session("owned", save=False))

    t = Thread(target=run_close)
    t.start()
    try:
        assert entered.wait(5)
        with pytest.raises(RuntimeError, match="in progress"):
            sup.close_session("owned", save=False)
        assert "owned" in sup.sessions
        assert not sup._release_receipts
    finally:
        proceed.set()
        t.join(timeout=5)
    assert not t.is_alive()
    assert results[0]["success"] is True
    check_proof(results[0]["release"], session, target)


def test_other_workers_and_adopted_processes_are_not_terminated(fixture, tmp_path):
    sup, target = fixture
    other = tmp_path / "other.bin"
    other.write_bytes(b"other")
    first = open_owned(sup, target, "first")
    second = open_owned(sup, other, "second")
    sup.close_session("first", save=False)
    assert first.process.poll() is not None
    assert second.process.poll() is None
    adopted = m.WorkerSession(
        session_id="adopted", input_path=str(target), filename="input.bin",
        process=FakeProcess(), owned=False,
    )
    with sup._lock:
        sup._register_session_locked(adopted, str(target))
    result = sup.close_session("adopted", save=False)
    assert result["success"] is True
    assert "release" not in result
    assert adopted.process.poll() is None


def test_discovery_failure_is_explicit_not_empty_inventory(fixture, monkeypatch):
    sup, _ = fixture
    monkeypatch.setattr(m, "supervisor", sup)

    def fail():
        raise RuntimeError("enumeration failed")

    monkeypatch.setattr(m._discovery, "discover_instances", fail)
    result = m.idb_list()
    assert "enumeration failed" in result["error"]
    assert "sessions" not in result


def test_receipt_expiry_is_unknown_and_does_not_invent_success(fixture):
    sup, target = fixture
    session = open_owned(sup, target)
    sup.close_session("owned", save=False)
    key = (session.session_id, session.release_id)
    timestamp, proof = sup._release_receipts[key]
    sup._release_receipts[key] = (timestamp - m.RELEASE_RECEIPT_TTL_SEC - 1, proof)
    with pytest.raises(RuntimeError, match="unknown"):
        sup.close_session("owned", save=False, expected_input_path=str(target),
                          release_id=session.release_id)


def test_real_os_process_termination_and_no_leak(fixture):
    sup, target = fixture
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    session = m.WorkerSession(
        session_id="real", input_path=str(target), filename="input.bin",
        process=proc, owned=True,
    )
    with sup._lock:
        sup._register_session_locked(session, str(target))
    try:
        closed = sup.close_session("real", save=False)
        assert closed["success"] is True
        check_proof(closed["release"], session, target)
        assert proc.poll() is not None
        assert target.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def test_prior_release_survives_reused_session_id_for_other_input(fixture, tmp_path):
    sup, first = fixture
    older = open_owned(sup, first, "reused-id")
    sup.close_session("reused-id", save=False)
    second_input = tmp_path / "different.bin"
    second_input.write_bytes(b"different private input")
    newer = open_owned(sup, second_input, "reused-id")

    result = sup.close_session(
        "reused-id", save=False, expected_input_path=str(first),
        release_id=older.release_id,
    )
    check_proof(result["release"], older, first)
    assert sup.sessions["reused-id"] is newer
    assert newer.process.poll() is None
    assert first.read_bytes() == b"original private input"
    assert second_input.read_bytes() == b"different private input"
    sup.close_session("reused-id", save=False)


def test_prior_release_rejected_while_another_session_uses_same_input(fixture):
    sup, target = fixture
    older = open_owned(sup, target, "original")
    sup.close_session("original", save=False)
    newer = open_owned(sup, target, "new-owner")

    with pytest.raises(RuntimeError, match="input still in use"):
        sup.close_session(
            "original", save=False, expected_input_path=str(target),
            release_id=older.release_id,
        )
    assert newer.process.poll() is None
    assert sup.sessions["new-owner"] is newer

    sup.close_session("new-owner", save=False)
    proof = sup.close_session(
        "original", save=False, expected_input_path=str(target),
        release_id=older.release_id,
    )
    check_proof(proof["release"], older, target)


def test_prior_release_rejected_while_unregistered_live_worker_uses_input(fixture):
    sup, target = fixture
    older = open_owned(sup, target, "original")
    sup.close_session("original", save=False)
    newer = open_owned(sup, target, "unregistered")
    with sup._lock:
        sup._unregister_session_locked("unregistered")
    assert newer.process.poll() is None
    assert sup.sessions == {}

    with pytest.raises(RuntimeError, match="input still in use"):
        sup.close_session(
            "original", save=False, expected_input_path=str(target),
            release_id=older.release_id,
        )
    assert newer.process.poll() is None
    assert target.read_bytes() == b"original private input"
    newer.process.terminate()
    proof = sup.close_session(
        "original", save=False, expected_input_path=str(target),
        release_id=older.release_id,
    )
    check_proof(proof["release"], older, target)


def _strict_discovery_fixture(monkeypatch, tmp_path):
    discovery = m._import_discovery()
    directory = tmp_path / "registrations"
    directory.mkdir()
    monkeypatch.setattr(discovery, "get_instances_dir", lambda: str(directory))
    monkeypatch.setattr(m._discovery, "discover_instances", discovery.discover_instances)
    monkeypatch.setattr(m, "supervisor", FakeSupervisor())
    return discovery, directory


def test_strict_inventory_completed_empty_scan(monkeypatch, tmp_path):
    _, directory = _strict_discovery_fixture(monkeypatch, tmp_path)
    assert m.idb_list(strict_discovery=True) == {
        "sessions": [], "count": 0, "registry_scan_complete": True,
    }
    directory.rmdir()
    assert m.idb_list(strict_discovery=True)["registry_scan_complete"] is True


def test_strict_inventory_rejects_corrupt_registration(monkeypatch, tmp_path):
    _, directory = _strict_discovery_fixture(monkeypatch, tmp_path)
    registration = directory / "instance_12345.json"
    registration.write_text("{broken json", encoding="utf-8")
    result = m.idb_list(strict_discovery=True)
    assert "error" in result and "incomplete" in result["error"].lower()
    assert "sessions" not in result and "registry_scan_complete" not in result
    assert registration.exists()


def test_strict_inventory_rejects_unreachable_registration(monkeypatch, tmp_path):
    discovery, directory = _strict_discovery_fixture(monkeypatch, tmp_path)
    registration = directory / "instance_43210.json"
    registration.write_text(json.dumps({
        "host": "127.0.0.1", "port": 43210, "pid": 424242,
    }), encoding="utf-8")
    monkeypatch.setattr(discovery, "is_pid_alive", lambda _pid: True)
    monkeypatch.setattr(discovery, "probe_instance", lambda *_a, **_k: False)
    result = m.idb_list(strict_discovery=True)
    assert "error" in result and "incomplete" in result["error"].lower()
    assert "sessions" not in result and "registry_scan_complete" not in result
    assert registration.exists()


def test_strict_inventory_rejects_directory_read_error(monkeypatch, tmp_path):
    discovery, directory = _strict_discovery_fixture(monkeypatch, tmp_path)
    directory.rmdir()
    nondir = tmp_path / "plain-file"
    nondir.write_bytes(b"not a directory")
    monkeypatch.setattr(discovery, "get_instances_dir", lambda: str(nondir))
    result = m.idb_list(strict_discovery=True)
    assert "error" in result and "incomplete" in result["error"].lower()
    assert "sessions" not in result and "registry_scan_complete" not in result


def test_open_session_does_not_return_a_worker_already_closing(fixture):
    sup, target = fixture
    existing = open_owned(sup, target, "owned")
    existing.closing = True
    try:
        with pytest.raises(RuntimeError, match="release in progress"):
            open_owned(sup, target, "new")
        assert sup.sessions["owned"] is existing
        assert existing.process.poll() is None
    finally:
        existing.closing = False
    sup.close_session("owned", save=False)


def test_saved_cleanup_holds_registration_lock_until_complete(fixture):
    sup, target = fixture
    session = open_owned(sup, target, "owned")
    sidecar = target.with_name(target.name + ".id0")
    sidecar.write_bytes(b"disposable unpacked database")
    entered, resume = Event(), Event()
    previous_cleanup = sup._cleanup_partial_database
    outcomes = []

    def paused_cleanup(path):
        entered.set()
        assert resume.wait(5)
        previous_cleanup(path)

    sup._cleanup_partial_database = paused_cleanup

    def close():
        outcomes.append(sup.close_session("owned", save=True))

    closer = Thread(target=close)
    closer.start()
    acquired = False
    try:
        assert entered.wait(5)
        # Registration uses this exact lock. Cleanup may not race with an
        # incoming open_session after the terminating worker is unregistered.
        acquired = sup._lock.acquire(blocking=False)
        assert not acquired, "A new worker could register during IDA sidecar cleanup"
    finally:
        if acquired:
            sup._lock.release()
        resume.set()
        closer.join(timeout=5)
    assert not closer.is_alive()
    assert outcomes[0]["success"] is True
    assert session.process.poll() is not None
    assert not sidecar.exists()
    assert target.read_bytes() == b"original private input"
