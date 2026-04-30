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

    def _worker_rpc(self, worker, payload, *, timeout=300.0):
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
