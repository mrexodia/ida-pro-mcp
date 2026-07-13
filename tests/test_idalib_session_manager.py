"""Tests for IDASessionManager, run without IDA by stubbing idapro/ida_auto.

Regression coverage for #476: the process-global strings cache must be dropped
whenever the active database is torn down or replaced, otherwise a switched-to
binary serves the previous one's strings.
"""

import sys
import types
import importlib

import pytest


class _FakeIdapro(types.ModuleType):
    """Records open/close_database calls in order."""

    def __init__(self):
        super().__init__("idapro")
        self.events: list[tuple] = []

    def open_database(self, path, run_auto_analysis=False):
        self.events.append(("open", path))
        return 0  # 0 == success; the manager treats a truthy return as failure

    def close_database(self, *args, **kwargs):
        self.events.append(("close",))


class _FakeIdaAuto(types.ModuleType):
    def __init__(self):
        super().__init__("ida_auto")

    def auto_wait(self):
        return True


class _CacheSpy:
    def __init__(self):
        self.invalidations = 0

    def invalidate_strings_cache(self):
        self.invalidations += 1


@pytest.fixture
def session_env(monkeypatch):
    """Import a fresh IDASessionManager wired to fake IDA dependencies."""
    fake_idapro = _FakeIdapro()
    fake_ida_auto = _FakeIdaAuto()
    spy = _CacheSpy()

    fake_api_core = types.ModuleType("ida_pro_mcp.ida_mcp.api_core")
    fake_api_core.invalidate_strings_cache = spy.invalidate_strings_cache
    fake_ida_mcp = types.ModuleType("ida_pro_mcp.ida_mcp")
    fake_ida_mcp.api_core = fake_api_core

    monkeypatch.setitem(sys.modules, "idapro", fake_idapro)
    monkeypatch.setitem(sys.modules, "ida_auto", fake_ida_auto)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp", fake_ida_mcp)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.api_core", fake_api_core)
    # Re-import against the stubs, not any real copy left by another test.
    monkeypatch.delitem(sys.modules, "ida_pro_mcp.idalib_session_manager", raising=False)

    module = importlib.import_module("ida_pro_mcp.idalib_session_manager")
    manager = module.IDASessionManager()

    yield types.SimpleNamespace(manager=manager, idapro=fake_idapro, spy=spy)

    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)


def _make_binary(tmp_path, name):
    path = tmp_path / name
    path.write_bytes(b"\x7fELF" + name.encode())
    return path


def test_switching_binaries_invalidates_strings_cache(session_env, tmp_path):
    a = _make_binary(tmp_path, "a.bin")
    b = _make_binary(tmp_path, "b.bin")

    session_env.manager.open_binary(a, run_auto_analysis=False)
    session_env.spy.invalidations = 0
    session_env.idapro.events.clear()

    session_env.manager.open_binary(b, run_auto_analysis=False)

    assert session_env.spy.invalidations >= 1, "cache not invalidated on binary switch"
    # The previous database is closed before the new one is opened.
    assert session_env.idapro.events == [("close",), ("open", str(b))]


def test_activate_session_invalidates_strings_cache(session_env, tmp_path):
    a = _make_binary(tmp_path, "a.bin")
    b = _make_binary(tmp_path, "b.bin")

    sid_a = session_env.manager.open_binary(a, run_auto_analysis=False)
    session_env.manager.open_binary(b, run_auto_analysis=False)  # b is now active
    session_env.spy.invalidations = 0

    session_env.manager.activate_session(sid_a)

    assert session_env.spy.invalidations >= 1, "cache not invalidated on re-activation"


def test_reactivating_already_active_session_does_not_invalidate(session_env, tmp_path):
    a = _make_binary(tmp_path, "a.bin")
    sid_a = session_env.manager.open_binary(a, run_auto_analysis=False)
    session_env.spy.invalidations = 0

    session_env.manager.activate_session(sid_a)  # already active: no DB change

    assert session_env.spy.invalidations == 0


def test_closing_active_session_invalidates_strings_cache(session_env, tmp_path):
    a = _make_binary(tmp_path, "a.bin")
    sid_a = session_env.manager.open_binary(a, run_auto_analysis=False)
    session_env.spy.invalidations = 0

    session_env.manager.close_session(sid_a)

    assert session_env.spy.invalidations >= 1, "cache not invalidated when active DB closed"


def test_closing_inactive_session_preserves_active_cache(session_env, tmp_path):
    a = _make_binary(tmp_path, "a.bin")
    b = _make_binary(tmp_path, "b.bin")
    sid_a = session_env.manager.open_binary(a, run_auto_analysis=False)
    session_env.manager.open_binary(b, run_auto_analysis=False)  # b is now active
    session_env.spy.invalidations = 0

    session_env.manager.close_session(sid_a)  # a is not active; b stays loaded

    assert session_env.spy.invalidations == 0, "must not clear cache for the still-active DB"


def test_close_all_sessions_invalidates_strings_cache(session_env, tmp_path):
    a = _make_binary(tmp_path, "a.bin")
    session_env.manager.open_binary(a, run_auto_analysis=False)
    session_env.spy.invalidations = 0

    session_env.manager.close_all_sessions()

    assert session_env.spy.invalidations >= 1
