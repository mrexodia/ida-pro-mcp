"""idalib supervisor tests that do not require IDA/idalib."""

import sys
from pathlib import Path

from ida_pro_mcp import idalib_supervisor as supmod


class _FakeProcess:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _DeadProcess(_FakeProcess):
    returncode = 1


class _FakeSupervisor(supmod.IdalibSupervisor):
    def __init__(self):
        super().__init__(supmod.McpServer("test"), max_workers=4)
        self.forwarded: list[dict] = []
        self.opened: list[tuple[str, dict]] = []
        self.tool_calls: list[tuple[str, dict | None]] = []

    def _spawn_worker(self):
        return supmod.WorkerSession(
            session_id="__schema__",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=1,
            process=_FakeProcess(),
        )

    def _worker_rpc(self, worker, payload, *, timeout=None):
        method = payload.get("method")
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": "decompile",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"addr": {"type": "string"}},
                                "required": ["addr"],
                            },
                        },
                        {"name": "idb_open", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resources": []}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resourceTemplates": []}}
        self.forwarded.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        self.tool_calls.append((name, arguments))
        if name == "idb_open":
            assert arguments is not None
            self.opened.append((name, arguments))
            warmup = None
            if arguments.get("build_caches") or arguments.get("init_hexrays"):
                warmup = {"ok": True, "steps": [], "health": {"status": "ok"}}
            return {
                "success": True,
                "session": {
                    "session_id": arguments["preferred_session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
                "warmup": warmup,
            }
        return {"ok": True, "error": None}

    def _session_is_reachable(self, session):
        return session.is_alive()

    def _probe_session_health(self, session):
        reachable = self._session_is_reachable(session)
        return {
            "backend": session.backend,
            "process_alive": session.is_alive(),
            "tcp_connect": reachable if session.backend == "worker" else None,
            "rpc_ping": reachable if session.backend == "worker" else None,
            "reachable": reachable,
            "failed_probe": None if reachable else "tcp_connect",
            "error": None if reachable else "unreachable",
        }


def _patch_discovery(*, instances, probe):
    old_discover = supmod._discovery.discover_instances
    old_probe = supmod._discovery.probe_instance
    supmod._discovery.discover_instances = lambda: instances
    supmod._discovery.probe_instance = lambda *_args, **_kwargs: probe

    def restore():
        supmod._discovery.discover_instances = old_discover
        supmod._discovery.probe_instance = old_probe

    return restore


def test_supervisor_import_does_not_import_ida_modules():
    assert "idapro" not in sys.modules
    assert "idaapi" not in sys.modules


def test_worker_rpc_default_has_no_socket_timeout(monkeypatch):
    class _FakeResponse:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'

    class _FakeConnection:
        instances = []

        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
            type(self).instances.append(self)

        def request(self, method, path, body, headers):
            pass

        def getresponse(self):
            return _FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(supmod.http.client, "HTTPConnection", _FakeConnection)
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="",
        filename="",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    sup._worker_rpc(worker, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, timeout=2.0)

    assert _FakeConnection.instances[0].timeout is None
    assert _FakeConnection.instances[1].timeout == 2.0

def test_worker_tools_inject_database_and_filter_management_tools():
    sup = _FakeSupervisor()
    tools = sup.worker_tools()
    names = [tool["name"] for tool in tools]
    assert names == ["decompile"]
    schema = tools[0]["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" in schema.get("required", [])


def test_inject_database_arg_marks_required():
    sup = _FakeSupervisor()
    injected = sup._inject_database_arg(
        {
            "name": "decompile",
            "inputSchema": {
                "type": "object",
                "properties": {"addr": {"type": "string"}},
                "required": ["addr"],
            },
        }
    )
    schema = injected["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" in schema["required"]


def test_inject_database_arg_is_idempotent_in_required_list():
    sup = _FakeSupervisor()
    injected = sup._inject_database_arg(
        {
            "name": "decompile",
            "inputSchema": {
                "type": "object",
                "properties": {"addr": {"type": "string"}},
                "required": ["addr", "database"],
            },
        }
    )
    required = injected["inputSchema"]["required"]
    assert required.count("database") == 1


def test_handle_tools_call_errors_when_database_missing():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "decompile", "arguments": {"addr": "0x1000"}},
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        text = result["result"]["content"][0]["text"]
        assert "database is required" in text
        assert not supmod.supervisor.forwarded
    finally:
        supmod.supervisor = old_supervisor


def test_handle_tools_call_errors_when_database_empty():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "decompile",
                    "arguments": {"addr": "0x1000", "database": ""},
                },
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        assert "database is required" in result["result"]["content"][0]["text"]
    finally:
        supmod.supervisor = old_supervisor


def test_open_session_rejects_unknown_mode(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    try:
        sup.open_session(str(sample), session_id="sample", mode="bogus")
    except ValueError as e:
        assert "Unknown mode" in str(e)
    else:
        raise AssertionError("expected ValueError for unknown mode")


def test_open_session_prefer_headless_skips_gui_discovery(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="prefer_headless")
        assert session.backend == "worker"
        assert sup.opened, "expected the worker to be invoked despite a running GUI"
    finally:
        restore()


def test_open_session_force_headless_ignores_running_gui(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="force_headless")
        assert session.backend == "worker"
    finally:
        restore()


def test_open_session_force_gui_launches_when_no_gui_found(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    calls = []

    def fake_launch(file_path, **kwargs):
        calls.append(file_path)
        return {
            "success": True,
            "host": "127.0.0.1",
            "port": 31337,
            "pid": 4242,
            "binary": "sample.bin",
        }

    monkeypatch.setattr(supmod._discovery, "launch_gui_instance", fake_launch)
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="force_gui")
        assert session.backend == "gui"
        assert session.port == 31337
        assert calls == [str(sample.resolve())] or calls == [str(sample)]
    finally:
        restore()


def test_idb_list_includes_unadopted_gui_instances(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")

    extra_idb = tmp_path / "other.bin.i64"
    extra_idb.write_bytes(b"idb")
    monkeypatch.setattr(
        supmod._discovery,
        "discover_instances",
        lambda: [
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 1234,
                "binary": "other.bin",
                "idb_path": str(extra_idb),
                "started_at": "now",
            }
        ],
    )
    monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)

    listed = sup.list_sessions()
    by_id = {entry["session_id"]: entry for entry in listed}
    assert "sample" in by_id and by_id["sample"]["adopted"] is True
    unadopted = [entry for entry in listed if not entry["adopted"]]
    assert len(unadopted) == 1
    assert unadopted[0]["backend"] == "gui"
    assert unadopted[0]["input_path"] == str(extra_idb)
    assert unadopted[0]["pid"] == 1234


def test_idb_list_reports_unadopted_worker_instances_as_workers(tmp_path, monkeypatch):
    extra_idb = tmp_path / "worker.bin"
    extra_idb.write_bytes(b"idb")
    monkeypatch.setattr(
        supmod._discovery,
        "discover_instances",
        lambda: [
            {
                "host": "127.0.0.1",
                "port": 31338,
                "pid": 4321,
                "binary": "worker.bin",
                "idb_path": str(extra_idb),
                "started_at": "now",
                "backend": "worker",
            }
        ],
    )
    monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)

    listed = _FakeSupervisor().list_sessions()

    assert len(listed) == 1
    assert listed[0]["backend"] == "worker"
    assert listed[0]["metadata"]["backend"] == "worker"
    assert listed[0]["worker_pid"] == 4321
    assert listed[0]["adopted"] is False


def test_prefer_headless_adopts_only_registered_worker_backend(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="sample", mode="prefer_headless")
        assert session.backend == "worker"
        assert session.owned is True
        assert sup.opened, "legacy GUI registration should not be adopted as a worker"
    finally:
        restore()


def test_idb_list_omits_unadopted_when_already_adopted(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    idb = tmp_path / "sample.bin.i64"
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 1234,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        monkeypatch.setattr(supmod._discovery, "probe_instance", lambda *_args, **_kwargs: True)
        listed = sup.list_sessions()
        assert all(entry["adopted"] for entry in listed)
        assert len(listed) == 1
    finally:
        restore()


def test_open_session_forwards_warmup_flags_and_captures_result(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(
        str(sample),
        session_id="sample",
        run_auto_analysis=False,
        build_caches=True,
        init_hexrays=True,
    )
    args = sup.opened[0][1]
    assert args["build_caches"] is True
    assert args["init_hexrays"] is True
    assert args["run_auto_analysis"] is False
    assert session.last_warmup is not None
    assert session.last_warmup["ok"] is True


def test_open_session_forwards_idle_ttl_sec(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample", idle_ttl_sec=1800)
    args = sup.opened[0][1]
    assert args["idle_ttl_sec"] == 1800


def test_open_session_defaults_idle_ttl_sec_to_baseline(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")
    args = sup.opened[0][1]
    assert args["idle_ttl_sec"] == 600


def test_open_session_skips_warmup_when_flags_disabled(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(
        str(sample),
        session_id="sample",
        build_caches=False,
        init_hexrays=False,
    )
    args = sup.opened[0][1]
    assert args["build_caches"] is False
    assert args["init_hexrays"] is False
    assert session.last_warmup is None


def test_resolve_session_requires_database():
    sup = _FakeSupervisor()
    for value in (None, ""):
        try:
            sup.resolve_session(value)
        except RuntimeError as e:
            assert "database is required" in str(e)
        else:
            raise AssertionError(f"expected RuntimeError for database={value!r}")


def test_tool_error_result_omits_structured_content():
    result = supmod._call_tool_result({"error": "no database"}, is_error=True)
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_open_session_reuses_schema_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.worker_tools()  # creates the idle/schema worker
    session = sup.open_session(str(sample), session_id="sample")
    assert session.session_id == "sample"
    assert sup.opened[0][1]["preferred_session_id"] == "sample"


def test_resolve_session_only_accepts_session_id(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample")

    assert sup.resolve_session("sample").session_id == "sample"

    for selector in ("sample.bin", str(sample), str(sample.resolve())):
        try:
            sup.resolve_session(selector)
        except RuntimeError as e:
            assert "not found" in str(e)
        else:
            raise AssertionError(f"expected RuntimeError for selector={selector!r}")


def test_open_session_uses_matching_gui_instance(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        assert session.host == "127.0.0.1"
        assert session.port == 31337
        assert session.pid == 999
        assert sup.resolve_session("gui").session_id == "gui"
        assert sup.opened == []
    finally:
        restore()


def test_open_session_removes_stale_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()))
        session = sup.open_session(str(sample), session_id="new")
        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_open_session_ignores_dead_workers_for_max_worker_limit(tmp_path):
    stale_path = tmp_path / "stale.bin"
    new_path = tmp_path / "new.bin"
    stale_path.write_bytes(b"stale")
    new_path.write_bytes(b"new")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        sup.max_workers = 1
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(stale_path.resolve()),
            filename="stale.bin",
            process=_DeadProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(stale_path.resolve()))

        session = sup.open_session(str(new_path), session_id="new")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_resolve_session_removes_unreachable_worker(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    session = sup.open_session(str(sample), session_id="sample")
    unreachable = {session.session_id}

    def fake_reachable(candidate):
        if candidate.session_id in unreachable:
            return False
        return candidate.is_alive()

    sup._session_is_reachable = fake_reachable

    try:
        sup.resolve_session("sample")
    except RuntimeError as e:
        assert "not reachable" in str(e)
    else:
        raise AssertionError("expected RuntimeError")

    assert "sample" not in sup.sessions
    assert session.process.returncode == 0


def test_open_session_prunes_unreachable_existing_mapping(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _FakeSupervisor()
        stale = supmod.WorkerSession(
            session_id="stale",
            input_path=str(sample.resolve()),
            filename="sample.bin",
            process=_FakeProcess(),
        )
        with sup._lock:
            sup._register_session_locked(stale, str(sample.resolve()))

        sup._session_is_reachable = lambda session: session.session_id != "stale" and session.is_alive()

        session = sup.open_session(str(sample), session_id="new")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
    finally:
        restore()


def test_probe_session_health_reports_tcp_connect_failure(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    def fail_connect(*_args, **_kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(supmod.socket, "create_connection", fail_connect)

    health = sup._probe_session_health(worker)

    assert health["reachable"] is False
    assert health["tcp_connect"] is False
    assert health["rpc_ping"] is None
    assert health["failed_probe"] == "tcp_connect"
    assert "refused" in health["error"]


def test_probe_session_health_reports_rpc_ping_failure(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"))
    worker = supmod.WorkerSession(
        session_id="worker",
        input_path="sample.bin",
        filename="sample.bin",
        host="127.0.0.1",
        port=12345,
        process=_FakeProcess(),
    )

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(supmod.socket, "create_connection", lambda *_args, **_kwargs: _FakeSocket())
    sup._worker_rpc = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("rpc timeout"))

    health = sup._probe_session_health(worker)

    assert health["reachable"] is False
    assert health["tcp_connect"] is True
    assert health["rpc_ping"] is False
    assert health["failed_probe"] == "rpc_ping"
    assert "rpc timeout" in health["error"]


def test_list_sessions_reports_is_active_from_health_probe(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")
    sup = _FakeSupervisor()
    sup.open_session(str(first), session_id="first")
    sup.open_session(str(second), session_id="second")

    sup._session_is_reachable = lambda session: session.session_id == "first"
    supmod._discovery.discover_instances = lambda: []

    listed = {s["session_id"]: s["is_active"] for s in sup.list_sessions()}
    assert listed == {"first": True, "second": False}


def test_supervisor_uses_idb_prefixed_management_tools_only():
    """No legacy names should leak into IDB_MANAGEMENT_TOOLS or module symbols."""
    legacy = {
        "open_database",
        "idalib_close",
        "idalib_list",
        "idalib_save",
        "idb_close",
        "idalib_switch",
        "idalib_unbind",
        "idalib_current",
        "idalib_warmup",
        "idalib_health",
    }
    assert supmod.IDB_MANAGEMENT_TOOLS == {"idb_open", "idb_list"}
    for name in legacy:
        assert not hasattr(supmod, name), f"{name} should have been deleted"
    for typename in ("IdalibWarmupResult", "IdalibHealthResult"):
        assert not hasattr(supmod, typename), f"{typename} should have been deleted"
    # --stdio-shared and its support code should be gone.
    for name in (
        "_stdio_proxy",
        "_open_stdio_initial_database",
        "_ensure_shared_http_supervisor",
        "_spawn_shared_http_supervisor",
        "_probe_http_supervisor",
        "_http_jsonrpc",
        "_stdio_shared_session_id",
    ):
        assert not hasattr(supmod, name), f"{name} should have been deleted"


def test_open_session_race_discards_losing_worker_for_existing_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample))
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
        assert sup.opened[0][1]["preferred_session_id"] != "winner"
    finally:
        restore()


def test_open_session_race_returns_existing_when_preferred_id_differs(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="loser")
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
    finally:
        restore()


def test_open_session_returns_existing_session_when_path_already_open(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    first = sup.open_session(str(sample), session_id="alpha")
    again = sup.open_session(str(sample), session_id="beta")
    assert again is first
    assert again.session_id == "alpha"
    assert set(sup.sessions) == {"alpha"}


def test_open_session_race_rejects_duplicate_session_id_for_different_path(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"1")
    second.write_bytes(b"2")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                existing = supmod.WorkerSession(
                    session_id=arguments["preferred_session_id"],
                    input_path=str(first.resolve()),
                    filename="first.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(first.resolve()))
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(second), session_id="shared")
        except ValueError as e:
            assert "Session already exists: shared" in str(e)
        else:
            raise AssertionError("expected ValueError")

        assert set(sup.sessions) == {"shared"}
        assert sup.sessions["shared"].input_path == str(first.resolve())
        assert sup.path_to_session.get(sup._path_key(str(second.resolve()))) is None
        assert sup.spawned[0].process.returncode == 0
    finally:
        restore()


def test_closed_gui_session_reopens_headless(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(idb.resolve())
    finally:
        restore()


def test_closed_gui_session_falls_back_to_requested_binary_if_idb_is_stale(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        idb.unlink()
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False
        reopened = sup.resolve_session("gui")
        assert reopened.backend == "worker"
        assert reopened.session_id == "gui"
        assert sup.opened[-1][1]["input_path"] == str(sample.resolve())
    finally:
        restore()


def test_closed_gui_session_does_not_reappear_if_closed_during_headless_fallback(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")

    class _RaceSupervisor(_FakeSupervisor):
        def __init__(self):
            super().__init__()
            self.spawned = []

        def _spawn_worker(self):
            worker = super()._spawn_worker()
            self.spawned.append(worker)
            return worker

        def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idb_open":
                # Simulate: the session disappears while the reopen worker
                # is doing the open. Drop it from the supervisor's registry
                # and tear down the spawning worker.
                sid = arguments["preferred_session_id"]
                with self._lock:
                    stale = self._unregister_session_locked(sid)
                if stale is not None:
                    self._terminate_worker(stale)
            return result

    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample), session_id="gui", mode="prefer_gui")
        assert session.backend == "gui"
        supmod._discovery.probe_instance = lambda *_args, **_kwargs: False

        try:
            sup.resolve_session("gui")
        except RuntimeError as e:
            assert "was closed or replaced" in str(e)
        else:
            raise AssertionError("expected RuntimeError")

        assert "gui" not in sup.sessions
        assert sup.spawned[-1].process.returncode == 0
    finally:
        restore()
