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
                        {"name": "idalib_open", "inputSchema": {"type": "object"}},
                        {"name": "list_instances", "inputSchema": {"type": "object"}},
                        {"name": "select_instance", "inputSchema": {"type": "object"}},
                    ]
                },
            }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resources": []}}
        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"resourceTemplates": []}}
        self.forwarded.append(payload)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"ok": True}}

    def call_worker_tool(self, worker, name, arguments=None):
        if name == "idalib_open":
            assert arguments is not None
            self.opened.append((name, arguments))
            return {
                "success": True,
                "session": {
                    "session_id": arguments["session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
            }
        return {"ok": True, "error": None}


class _TransportMcp:
    def __init__(self, session_id="stdio:default"):
        self.session_id = session_id

    def get_current_transport_session_id(self):
        return self.session_id


class _MainExit(Exception):
    pass


class _FakeInputBuffer:
    def __init__(self, lines):
        self.lines = list(lines)

    def readline(self):
        if not self.lines:
            return b""
        return self.lines.pop(0)


class _FakeStdin:
    def __init__(self, lines):
        self.buffer = _FakeInputBuffer(lines)


class _RecordingOutputBuffer:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        pass


class _FakeStdout:
    def __init__(self):
        self.buffer = _RecordingOutputBuffer()


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


def test_stdio_shared_supervisor_spawn_uses_http_daemon_command(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    captured = {}

    class _FakePopen:
        returncode = None

        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs

        def poll(self):
            return None

    monkeypatch.setattr(supmod.subprocess, "Popen", _FakePopen)

    proc = supmod._spawn_shared_http_supervisor(
        host="127.0.0.1",
        port=9876,
        worker_args=["--unsafe", "--max-workers", "8"],
    )

    assert isinstance(proc, _FakePopen)
    assert captured["cmd"][:3] == [
        sys.executable,
        "-m",
        "ida_pro_mcp.idalib_supervisor",
    ]
    assert "--stdio" not in captured["cmd"]
    assert "--stdio-shared" not in captured["cmd"]
    assert "--unsafe" in captured["cmd"]
    assert "--max-workers" in captured["cmd"]
    assert str(sample) not in captured["cmd"]
    assert captured["kwargs"]["stdin"] is supmod.subprocess.DEVNULL
    assert captured["kwargs"]["stdout"] is supmod.subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] is supmod.subprocess.DEVNULL
    assert "start_new_session" in captured["kwargs"]


def test_open_stdio_initial_database_forwards_transport_session(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    captured = {}

    def fake_http_jsonrpc(**kwargs):
        captured.update(kwargs)
        return (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [],
                    "structuredContent": {
                        "success": True,
                        "session": {"session_id": "sample"},
                    },
                },
            },
            kwargs["session_id"],
        )

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)

    supmod._open_stdio_initial_database(
        host="127.0.0.1",
        port=9876,
        input_path=sample,
        session_id="http-session",
    )

    assert captured["session_id"] == "http-session"
    payload = supmod.json.loads(captured["body"])
    assert payload["params"]["name"] == "idalib_open"
    assert payload["params"]["arguments"]["input_path"] == str(sample)


def test_probe_http_supervisor_uses_stable_session_header(monkeypatch):
    captured = {}

    def fake_http_jsonrpc(**kwargs):
        captured.update(kwargs)
        return (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"serverInfo": {"name": supmod.mcp.name}},
            },
            kwargs["session_id"],
        )

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)

    assert supmod._probe_http_supervisor("127.0.0.1", 9876) is True
    assert captured["session_id"] == supmod.STDIO_PROXY_PROBE_SESSION_ID
    assert supmod.json.loads(captured["body"])["method"] == "initialize"


def test_probe_http_supervisor_rejects_unexpected_server(monkeypatch):
    def fake_http_jsonrpc(**kwargs):
        return (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"serverInfo": {"name": "other-server"}},
            },
            kwargs["session_id"],
        )

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)

    assert supmod._probe_http_supervisor("127.0.0.1", 9876) is False


def test_stdio_proxy_opens_initial_database_after_initialize(monkeypatch, tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    forwarded = []
    opened = []

    def fake_http_jsonrpc(**kwargs):
        forwarded.append(kwargs)
        return ({"jsonrpc": "2.0", "id": 1, "result": {}}, "http-session")

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)
    monkeypatch.setattr(
        supmod,
        "_open_stdio_initial_database",
        lambda **kwargs: opened.append(kwargs),
    )
    monkeypatch.setattr(
        supmod.sys,
        "stdin",
        _FakeStdin(
            [
                b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
                b"",
            ]
        ),
    )
    stdout = _FakeStdout()
    monkeypatch.setattr(supmod.sys, "stdout", stdout)

    supmod._stdio_proxy("127.0.0.1", 9876, input_path=sample)

    assert forwarded[0]["session_id"] is None
    assert opened == [
        {
            "host": "127.0.0.1",
            "port": 9876,
            "input_path": sample,
            "session_id": "http-session",
        }
    ]
    assert stdout.buffer.writes


def test_stdio_proxy_does_not_open_initial_database_when_initialize_fails(
    monkeypatch, tmp_path
):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    opened = []

    def fake_http_jsonrpc(**_kwargs):
        return ({"jsonrpc": "2.0", "id": 1, "error": {"message": "bad"}}, None)

    monkeypatch.setattr(supmod, "_http_jsonrpc", fake_http_jsonrpc)
    monkeypatch.setattr(
        supmod,
        "_open_stdio_initial_database",
        lambda **kwargs: opened.append(kwargs),
    )
    monkeypatch.setattr(
        supmod.sys,
        "stdin",
        _FakeStdin(
            [
                b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
                b"",
            ]
        ),
    )
    monkeypatch.setattr(supmod.sys, "stdout", _FakeStdout())

    supmod._stdio_proxy("127.0.0.1", 9876, input_path=sample)

    assert opened == []


def test_jsonrpc_proxy_error_omits_notification_response():
    result = supmod._jsonrpc_proxy_error(
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
        "boom",
    )

    assert result is None


def test_stdio_flag_uses_direct_stdio_not_shared_proxy(monkeypatch):
    calls = []
    old_supervisor = supmod.supervisor
    old_dispatch = supmod.mcp.registry.dispatch
    old_require_session = supmod.mcp.require_streamable_http_session

    monkeypatch.setattr(supmod.sys, "argv", ["idalib-mcp", "--stdio"])
    monkeypatch.setattr(
        supmod,
        "_ensure_shared_http_supervisor",
        lambda **_kwargs: calls.append("shared"),
    )
    monkeypatch.setattr(supmod.signal, "signal", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(supmod.mcp, "stdio", lambda: (_ for _ in ()).throw(_MainExit))

    try:
        try:
            supmod.main()
        except _MainExit:
            pass
        else:
            raise AssertionError("expected direct stdio path")
    finally:
        supmod.supervisor = old_supervisor
        supmod.mcp.registry.dispatch = old_dispatch
        supmod.mcp.require_streamable_http_session = old_require_session

    assert calls == []


def test_stdio_shared_flag_uses_shared_proxy(monkeypatch):
    calls = []

    monkeypatch.setattr(supmod.sys, "argv", ["idalib-mcp", "--stdio-shared"])
    monkeypatch.setattr(
        supmod,
        "_ensure_shared_http_supervisor",
        lambda **kwargs: calls.append(("ensure", kwargs)),
    )
    monkeypatch.setattr(
        supmod,
        "_stdio_proxy",
        lambda host, port, input_path=None: calls.append(
            ("proxy", host, port, input_path)
        ),
    )

    supmod.main()

    assert calls[0][0] == "ensure"
    assert calls[1] == ("proxy", "127.0.0.1", 8745, None)


def test_stdio_flags_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(
        supmod.sys,
        "argv",
        ["idalib-mcp", "--stdio", "--stdio-shared"],
    )

    try:
        supmod.main()
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("expected argparse conflict")


def test_worker_tools_inject_database_and_filter_management_tools():
    sup = _FakeSupervisor()
    tools = sup.worker_tools()
    names = [tool["name"] for tool in tools]
    assert names == ["decompile"]
    schema = tools[0]["inputSchema"]
    assert "database" in schema["properties"]
    assert "database" not in schema.get("required", [])


def test_tool_error_result_omits_structured_content():
    result = supmod._call_tool_result({"error": "no database"}, is_error=True)
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_supervisor_blocks_gui_plugin_routing_tools():
    old_supervisor = supmod.supervisor
    supmod.supervisor = _FakeSupervisor()
    try:
        result = supmod._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "select_instance", "arguments": {"port": 13337}},
            }
        )
        assert result is not None
        assert result["result"]["isError"] is True
        text = result["result"]["content"][0]["text"]
        assert "GUI-plugin routing tool" in text
        assert not supmod.supervisor.forwarded
    finally:
        supmod.supervisor = old_supervisor


def test_open_session_reuses_schema_worker_and_binds_context(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.worker_tools()  # creates the idle/schema worker
    session = sup.open_session(str(sample), session_id="sample", context_id="ctx")
    assert session.session_id == "sample"
    assert sup.context_bindings["ctx"] == "sample"
    assert sup.opened[0][1]["session_id"] == "sample"


def test_resolve_session_accepts_session_id_filename_and_context(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="sample", context_id="ctx")
    sup.mcp = _TransportMcp()
    sup.context_bindings[supmod.SHARED_FALLBACK_CONTEXT_ID] = "sample"

    assert sup.resolve_session("sample").session_id == "sample"
    assert sup.resolve_session("sample.bin").session_id == "sample"
    assert sup.resolve_session(None).session_id == "sample"


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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
        assert session.backend == "gui"
        assert session.host == "127.0.0.1"
        assert session.port == 31337
        assert session.pid == 999
        assert sup.resolve_session(str(sample)).session_id == "gui"
        assert sup.resolve_session(str(idb)).session_id == "gui"
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
            sup._register_session_locked(stale, str(sample.resolve()), "ctx")
        session = sup.open_session(str(sample), session_id="new", context_id="ctx")
        assert session.session_id == "new"
        assert "stale" not in sup.sessions
        assert sup.context_bindings["ctx"] == "new"
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
            sup._register_session_locked(stale, str(stale_path.resolve()), "ctx")

        session = sup.open_session(str(new_path), session_id="new", context_id="ctx")

        assert session.session_id == "new"
        assert "stale" not in sup.sessions
        assert sup.context_bindings["ctx"] == "new"
    finally:
        restore()


def test_open_session_race_discards_losing_worker_for_existing_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        session = sup.open_session(str(sample))
        assert session.session_id == "winner"
        assert set(sup.sessions) == {"winner"}
        assert sup.opened[0][1]["session_id"] != "winner"
    finally:
        restore()


def test_open_session_race_rejects_different_requested_session_id(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    class _RaceSupervisor(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id="winner",
                    input_path=str(sample.resolve()),
                    filename="sample.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(sample.resolve()), None)
            return result

    restore = _patch_discovery(instances=[], probe=False)
    try:
        sup = _RaceSupervisor()
        try:
            sup.open_session(str(sample), session_id="loser")
        except ValueError as e:
            assert "already open as session 'winner'" in str(e)
        else:
            raise AssertionError("expected ValueError")
        assert set(sup.sessions) == {"winner"}
    finally:
        restore()


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

        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                existing = supmod.WorkerSession(
                    session_id=arguments["session_id"],
                    input_path=str(first.resolve()),
                    filename="first.bin",
                    process=_FakeProcess(),
                )
                with self._lock:
                    self._register_session_locked(existing, str(first.resolve()), None)
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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
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

        def call_worker_tool(self, worker, name, arguments=None):
            result = super().call_worker_tool(worker, name, arguments)
            if name == "idalib_open":
                self.close_session(arguments["session_id"])
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
        session = sup.open_session(str(sample), session_id="gui", context_id="ctx")
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
