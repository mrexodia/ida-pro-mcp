"""idb_close against a real supervisor, worker and idalib.

These tests need a licensed IDA with idalib and skip when it is unavailable.
They only ever touch temporary copies of tests/crackme03.elf and only signal
the worker processes their own supervisor started.
"""

import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

# find_spec, not importorskip: importing idapro here would leak IDA modules into
# the other tests of this pytest process.
if importlib.util.find_spec("idapro") is None:
    pytest.skip("idapro is not installed", allow_module_level=True)

FIXTURE = Path(__file__).parent / "crackme03.elf"
MARKER = "renamed_by_close_test"
OTHER_MARKER = "renamed_after_save_test"


class _Supervisor:
    """Minimal line-delimited JSON-RPC client for `idalib-mcp --stdio`."""

    def __init__(self, cwd: Path, *extra_args: str):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "ida_pro_mcp.idalib_supervisor", "--stdio",
             "--max-workers", "1", *extra_args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
        )
        self.worker_pids: set[int] = set()
        self.exited_pids: set[int] = set()
        self._next_id = 0
        self._rpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test_idalib_close", "version": "0"},
        })

    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def call(self, name: str, **arguments):
        response = self._rpc("tools/call", {"name": name, "arguments": arguments})
        return response["result"].get("structuredContent", response["result"])

    def open(self, path: Path) -> str:
        opened = self.call("idb_open", input_path=str(path))
        # Record the worker before asserting so teardown can always stop it.
        for listed in self.call("idb_list").get("sessions", []):
            if Path(listed["input_path"]).samefile(path):
                self.worker_pids.add(listed["worker_pid"])
        assert opened.get("success"), opened
        return opened["session"]["session_id"]

    def close(self, database: str, **flags) -> dict:
        return self.call("idb_close", database=database, **flags)

    def function_addr(self, database: str, name: str) -> str | None:
        function = self.lookup(database, name)
        return function["addr"] if function else None

    def lookup(self, database: str, query: str) -> dict | None:
        return self.call("lookup_funcs", database=database, queries=query)["result"][0]["fn"]

    def rename(self, database: str, addr: str, name: str) -> None:
        result = self.call("rename", database=database, batch={"func": [{"addr": addr, "name": name}]})
        assert result["summary"]["ok"] == 1, result

    def shutdown(self) -> None:
        # Only workers this supervisor reported and that are still running are
        # signalled; the supervisor does not stop database workers on exit.
        for pid in self.worker_pids - self.exited_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            _wait_gone(pid)
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.proc.stdout is not None:
            self.proc.stdout.close()


def _assert_worker_exited(sup: "_Supervisor") -> None:
    running = sup.worker_pids - sup.exited_pids
    assert len(running) == 1, running
    for pid in running:
        assert _wait_gone(pid), f"worker {pid} is still running"
        sup.exited_pids.add(pid)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_gone(pid: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.2)
    return False


@pytest.fixture
def workdir(tmp_path):
    """A temp copy of the fixture binary with no database next to it."""
    shutil.copy(FIXTURE, tmp_path / FIXTURE.name)
    return tmp_path


@pytest.fixture
def supervisor(workdir):
    sup = _Supervisor(workdir)
    yield sup
    sup.shutdown()


@pytest.fixture
def profiled_supervisor(workdir):
    # A profile whitelists tools and would drop idb_discard from the worker
    # unless it is protected like the other management tools.
    profile = workdir / "profile.txt"
    profile.write_text("lookup_funcs\nrename\n")
    sup = _Supervisor(workdir, "--profile", str(profile))
    yield sup
    sup.shutdown()


def _reopened_name(sup: _Supervisor, workdir: Path, addr: str) -> str:
    """Open the database again in a fresh worker and return the function name at addr."""
    session_id = sup.open(workdir / FIXTURE.name)
    function = sup.lookup(session_id, addr)
    sup.close(session_id, save=False)
    _assert_worker_exited(sup)
    assert function is not None
    return function["name"]


def test_close_without_save_discards_unsaved_rename(supervisor, workdir):
    session_id = supervisor.open(workdir / FIXTURE.name)
    addr = supervisor.function_addr(session_id, "main")
    assert addr is not None
    supervisor.rename(session_id, addr, MARKER)
    assert supervisor.function_addr(session_id, MARKER) == addr

    result = supervisor.close(session_id, save=False)

    assert result["success"] is True and result["saved"] is None, result
    _assert_worker_exited(supervisor)
    assert not (workdir / "crackme03.elf.i64").exists(), "discard must not write a database"
    assert _reopened_name(supervisor, workdir, addr) == "main"


def test_close_without_save_keeps_earlier_saved_state(supervisor, workdir):
    session_id = supervisor.open(workdir / FIXTURE.name)
    addr = supervisor.function_addr(session_id, "main")
    assert addr is not None
    supervisor.rename(session_id, addr, MARKER)
    assert supervisor.call("idb_save", database=session_id)["ok"] is True
    supervisor.rename(session_id, addr, OTHER_MARKER)

    supervisor.close(session_id, save=False)

    _assert_worker_exited(supervisor)
    assert _reopened_name(supervisor, workdir, addr) == MARKER


@pytest.mark.parametrize("flags", [{"save": True}, {}], ids=["save-true", "default"])
def test_close_with_save_persists_rename(supervisor, workdir, flags):
    session_id = supervisor.open(workdir / FIXTURE.name)
    addr = supervisor.function_addr(session_id, "main")
    assert addr is not None
    supervisor.rename(session_id, addr, MARKER)

    result = supervisor.close(session_id, **flags)

    assert result["success"] is True and result["saved"] is True, result
    _assert_worker_exited(supervisor)
    assert _reopened_name(supervisor, workdir, addr) == MARKER


def test_close_without_save_discards_with_tool_profile(profiled_supervisor, workdir):
    session_id = profiled_supervisor.open(workdir / FIXTURE.name)
    addr = profiled_supervisor.function_addr(session_id, "main")
    assert addr is not None
    profiled_supervisor.rename(session_id, addr, MARKER)

    result = profiled_supervisor.close(session_id, save=False)

    assert result["success"] is True and "discard_error" not in result, result
    _assert_worker_exited(profiled_supervisor)
    assert not (workdir / "crackme03.elf.i64").exists(), "discard must not write a database"
