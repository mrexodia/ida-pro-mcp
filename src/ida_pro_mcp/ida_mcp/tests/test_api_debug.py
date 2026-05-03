"""Tests for debugger control helpers."""

from ..framework import test
from .. import api_debug
from ..sync import IDAError


class _SavedAttr:
    def __init__(self, obj, name, value):
        self.obj = obj
        self.name = name
        self.old = getattr(obj, name)
        setattr(obj, name, value)

    def restore(self):
        setattr(self.obj, self.name, self.old)


@test()
def test_list_breakpoints_normalizes_enabled_to_bool():
    """list_breakpoints should return a real boolean for the enabled field."""

    class _FakeBpt:
        def __init__(self):
            self.ea = 0
            self.flags = 0
            self.condition = None
            self.elang = None

    def getn_bpt(index, bpt):
        if index != 0:
            return False
        bpt.ea = 0x401000
        bpt.flags = api_debug.ida_dbg.BPT_ENABLED
        bpt.condition = None
        return True

    patches = [
        _SavedAttr(api_debug.ida_dbg, "get_bpt_qty", lambda: 1),
        _SavedAttr(api_debug.ida_dbg, "bpt_t", _FakeBpt),
        _SavedAttr(api_debug.ida_dbg, "getn_bpt", getn_bpt),
    ]
    try:
        result = api_debug.list_breakpoints()
        assert result == [{"addr": "0x401000", "enabled": True, "condition": None, "language": None}]
        assert isinstance(result[0]["enabled"], bool)
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_reports_success_when_debugger_is_running_without_ip():
    """dbg_start should report success even if IP is not immediately available after launch."""
    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_RUN),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: None),
    ]
    try:
        result = api_debug.dbg_start()
        assert result == {"started": True, "state": "running", "running": True}
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_waits_briefly_for_first_ip():
    """dbg_start should briefly wait for an initial suspend/IP before falling back to running."""
    calls = {"waits": 0}
    ip_values = iter([None, None, 0x401000])
    state_values = iter([
        api_debug.ida_dbg.DSTATE_RUN,
        api_debug.ida_dbg.DSTATE_RUN,
        api_debug.ida_dbg.DSTATE_SUSP,
    ])

    def wait_for_next_event(_flags, _timeout):
        calls["waits"] += 1
        return 1

    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: next(state_values)),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: next(ip_values)),
        _SavedAttr(api_debug.ida_dbg, "wait_for_next_event", wait_for_next_event),
    ]
    try:
        result = api_debug.dbg_start()
        assert result["started"] is True
        assert calls["waits"] >= 1
        if result["state"] == "suspended":
            assert result.get("suspended") is True
            if "ip" in result:
                assert result["ip"] == "0x401000"
        else:
            assert result == {
                "started": True,
                "state": "running",
                "running": True,
            }
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_continue_reports_running_without_needing_breakpoint_hit():
    """dbg_continue should succeed immediately after resuming even if no breakpoint is hit yet."""
    patches = [
        _SavedAttr(api_debug, "dbg_ensure_suspended", lambda: object()),
        _SavedAttr(api_debug.idaapi, "continue_process", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_RUN),
    ]
    try:
        result = api_debug.dbg_continue()
        assert result == {"continued": True, "state": "running", "running": True}
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_regs_require_suspended_state():
    """Register inspection should require a suspended debugger, not just an attached one."""
    patches = [
        _SavedAttr(api_debug.ida_idd, "get_dbg", lambda: object()),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_RUN),
    ]
    try:
        try:
            api_debug.dbg_ensure_suspended()
        except IDAError as exc:
            assert "Debugger is running" in str(exc)
        else:
            raise AssertionError("Expected IDAError for running debugger state")
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_set_bp_condition_sets_condition():
    """dbg_set_bp_condition should apply a condition to an existing breakpoint."""

    class _FakeBpt:
        def __init__(self):
            self.condition = None
            self.elang = None

        def is_compiled(self):
            return bool(self.condition)

    state = {"condition": None, "language": None}
    calls = []

    def get_bpt(ea, bpt):
        if ea != 0x401000:
            return False
        bpt.condition = state["condition"]
        bpt.elang = state["language"]
        return True

    def set_bpt_cond(ea, cnd, is_lowcnd=0):
        calls.append((ea, cnd, is_lowcnd))
        state["condition"] = cnd or None
        return True

    patches = [
        _SavedAttr(api_debug, "parse_address", lambda _addr: 0x401000),
        _SavedAttr(api_debug.ida_dbg, "bpt_t", _FakeBpt),
        _SavedAttr(api_debug.ida_dbg, "get_bpt", get_bpt),
        _SavedAttr(api_debug.idc, "set_bpt_cond", set_bpt_cond),
    ]
    try:
        result = api_debug.dbg_set_bp_condition(
            {"addr": "0x401000", "condition": "eax == 1"}
        )
        assert result == [{"addr": "0x401000", "ok": True, "condition": "eax == 1", "language": None}]
        assert calls == [(0x401000, "eax == 1", 0)]
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_set_bp_condition_can_clear_condition():
    """dbg_set_bp_condition should clear a condition when passed null."""

    class _FakeBpt:
        def __init__(self):
            self.condition = None
            self.elang = "IDC"

        def is_compiled(self):
            return bool(self.condition)

    state = {"condition": "eax == 1", "language": "IDC"}
    calls = []

    def get_bpt(ea, bpt):
        if ea != 0x401000:
            return False
        bpt.condition = state["condition"]
        bpt.elang = state["language"]
        return True

    def set_bpt_cond(ea, cnd, is_lowcnd=0):
        calls.append((ea, cnd, is_lowcnd))
        state["condition"] = cnd or None
        return True

    patches = [
        _SavedAttr(api_debug, "parse_address", lambda _addr: 0x401000),
        _SavedAttr(api_debug.ida_dbg, "bpt_t", _FakeBpt),
        _SavedAttr(api_debug.ida_dbg, "get_bpt", get_bpt),
        _SavedAttr(api_debug.idc, "set_bpt_cond", set_bpt_cond),
    ]
    try:
        result = api_debug.dbg_set_bp_condition(
            {"addr": "0x401000", "condition": None, "low_level": True}
        )
        assert result == [{"addr": "0x401000", "ok": True, "condition": None, "language": "IDC"}]
        assert calls == [(0x401000, "", 1)]
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_set_bp_condition_can_set_python_language():
    """dbg_set_bp_condition should switch language before compiling a new condition."""

    class _FakeBpt:
        def __init__(self):
            self.condition = None
            self.elang = "IDC"

        def is_compiled(self):
            return bool(self.condition)

    state = {"condition": None, "language": "IDC"}
    calls = []

    def get_bpt(ea, bpt):
        if ea != 0x401000:
            return False
        bpt.condition = state["condition"]
        bpt.elang = state["language"]
        return True

    def set_bpt_cond(ea, cnd, is_lowcnd=0):
        calls.append(("set", ea, cnd, is_lowcnd))
        state["condition"] = cnd or None
        return True

    def update_bpt(bpt):
        calls.append(("update", bpt.elang))
        state["language"] = bpt.elang
        return True

    patches = [
        _SavedAttr(api_debug, "parse_address", lambda _addr: 0x401000),
        _SavedAttr(api_debug.ida_dbg, "bpt_t", _FakeBpt),
        _SavedAttr(api_debug.ida_dbg, "get_bpt", get_bpt),
        _SavedAttr(api_debug.ida_dbg, "update_bpt", update_bpt),
        _SavedAttr(api_debug.idc, "set_bpt_cond", set_bpt_cond),
    ]
    try:
        result = api_debug.dbg_set_bp_condition(
            {"addr": "0x401000", "condition": "RAX == 1", "language": "python"}
        )
        assert result == [
            {
                "addr": "0x401000",
                "ok": True,
                "condition": "RAX == 1",
                "language": "Python",
            }
        ]
        assert calls == [("update", "Python"), ("set", 0x401000, "RAX == 1", 0)]
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_set_bp_condition_clears_old_condition_before_language_switch():
    """Changing language with an existing condition should clear first, then switch, then set."""

    class _FakeBpt:
        def __init__(self):
            self.condition = None
            self.elang = "IDC"

        def is_compiled(self):
            return bool(self.condition)

    state = {"condition": "R13==0x1234", "language": "IDC"}
    calls = []

    def get_bpt(ea, bpt):
        if ea != 0x401000:
            return False
        bpt.condition = state["condition"]
        bpt.elang = state["language"]
        return True

    def set_bpt_cond(ea, cnd, is_lowcnd=0):
        calls.append(("set", ea, cnd, is_lowcnd))
        state["condition"] = cnd or None
        return True

    def update_bpt(bpt):
        calls.append(("update", bpt.elang))
        state["language"] = bpt.elang
        return True

    patches = [
        _SavedAttr(api_debug, "parse_address", lambda _addr: 0x401000),
        _SavedAttr(api_debug.ida_dbg, "bpt_t", _FakeBpt),
        _SavedAttr(api_debug.ida_dbg, "get_bpt", get_bpt),
        _SavedAttr(api_debug.ida_dbg, "update_bpt", update_bpt),
        _SavedAttr(api_debug.idc, "set_bpt_cond", set_bpt_cond),
    ]
    try:
        result = api_debug.dbg_set_bp_condition(
            {"addr": "0x401000", "condition": "True", "language": "python"}
        )
        assert result == [
            {
                "addr": "0x401000",
                "ok": True,
                "condition": "True",
                "language": "Python",
            }
        ]
        assert calls == [
            ("set", 0x401000, "", 0),
            ("update", "Python"),
            ("set", 0x401000, "True", 0),
        ]
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_set_bp_condition_rejects_uncompiled_condition():
    """dbg_set_bp_condition should fail when IDA stores but does not compile the condition."""

    class _FakeBpt:
        def __init__(self):
            self.condition = None
            self.elang = "IDC"

        def is_compiled(self):
            return False

    state = {"condition": None, "language": "IDC"}

    def get_bpt(ea, bpt):
        if ea != 0x401000:
            return False
        bpt.condition = state["condition"]
        bpt.elang = state["language"]
        return True

    def set_bpt_cond(ea, cnd, is_lowcnd=0):
        state["condition"] = cnd or None
        return True

    patches = [
        _SavedAttr(api_debug, "parse_address", lambda _addr: 0x401000),
        _SavedAttr(api_debug.ida_dbg, "bpt_t", _FakeBpt),
        _SavedAttr(api_debug.ida_dbg, "get_bpt", get_bpt),
        _SavedAttr(api_debug.idc, "set_bpt_cond", set_bpt_cond),
    ]
    try:
        result = api_debug.dbg_set_bp_condition(
            {"addr": "0x401000", "condition": "this is invalid syntax"}
        )
        assert result == [
            {
                "addr": "0x401000",
                "error": "Breakpoint condition was stored but did not compile successfully",
            }
        ]
    finally:
        for patch in reversed(patches):
            patch.restore()
