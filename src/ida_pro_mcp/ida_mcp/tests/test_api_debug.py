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
def test_dbg_start_trusts_debugger_state_over_start_process_return():
    """start_process is asynchronous and may return -1 from inside execute_sync
    even when the process actually started; outcome must be decided by the
    actual debugger state, not the return code."""
    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: -1),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_SUSP),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: 0x401000),
    ]
    try:
        result = api_debug.dbg_start()
        assert result == {
            "started": True,
            "state": "suspended",
            "suspended": True,
            "ip": "0x401000",
        }
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_arms_batch_restore_hook_before_start_process():
    """dbg_start must arm the batch-mode restore hook BEFORE invoking
    start_process, so dialogs that fire on the main thread after we exit
    execute_sync are still suppressed by batch mode. The hook then turns
    batch mode back off via dbg_process_start / dbg_process_attach /
    dbg_process_exit / dbg_process_detach."""

    sequence = []

    def fake_arm(restore_batch=0):
        sequence.append(("arm", restore_batch))

    def fake_start_process(*_args):
        sequence.append(("start_process",))
        return 1

    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug, "_arm_dbg_start_batch_hook", fake_arm),
        _SavedAttr(api_debug.idaapi, "start_process", fake_start_process),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_SUSP),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: 0x401000),
    ]
    try:
        api_debug.dbg_start()
        assert sequence[0][0] == "arm", f"hook must arm first, got {sequence}"
        assert sequence[1] == ("start_process",), (
            f"start_process must run after the hook is armed, got {sequence}"
        )
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_arms_batch_restore_hook_with_pre_call_batch_value():
    """The batch-restore hook must capture the *pre-call* batch state
    (what the caller had before the sync wrapper bumped it to 1), so
    headless / batch-mode workflows aren't silently flipped to
    interactive after dbg_start. Hard-coding 0 would regress that."""

    captured = []

    def fake_arm(restore_batch=0):
        captured.append(restore_batch)

    for pre_call in [0, 1]:
        captured.clear()

        def fake_get_pre_call_batch(_v=pre_call):
            return _v

        patches = [
            _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
            _SavedAttr(api_debug, "_arm_dbg_start_batch_hook", fake_arm),
            _SavedAttr(api_debug, "get_pre_call_batch", fake_get_pre_call_batch),
            _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
            _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
            _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_SUSP),
            _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: 0x401000),
        ]
        try:
            api_debug.dbg_start()
            assert captured == [pre_call], (
                f"expected hook armed with pre-call batch {pre_call}, got {captured}"
            )
        finally:
            for patch in reversed(patches):
                patch.restore()


@test()
def test_dbg_start_batch_hook_restores_at_end_of_startup_only():
    """Batch mode must be restored as soon as the debugger has started up
    (dbg_process_start / dbg_process_attach) and on cleanup paths
    (dbg_process_exit / dbg_process_detach), but NOT on later events like
    dbg_suspend_process — those happen mid-session, after startup, where
    the user expects normal dialog behavior again."""

    # First, verify dbg_suspend_process does NOT restore batch (would be a
    # regression: it would keep batch on across the entire debug session).
    hook = api_debug._DbgStartBatchHook(restore_batch=0)
    suspend_calls = []

    def fake_batch_no_call(value, _calls=suspend_calls):
        _calls.append(value)
        return 1

    patch = _SavedAttr(api_debug.idc, "batch", fake_batch_no_call)
    try:
        hook.dbg_suspend_process()
        assert suspend_calls == [], (
            "dbg_suspend_process must not restore batch (it fires mid-session)"
        )
        assert hook._done is False
    finally:
        patch.restore()

    for callback_name, args in [
        ("dbg_process_start", (1234, 5678, 0x401000, "name", 0x400000, 0x1000)),
        ("dbg_process_attach", (1234, 5678, 0x401000, "name", 0x400000, 0x1000)),
        ("dbg_process_exit", (1234, 5678, 0x401000, 0)),
        ("dbg_process_detach", (1234, 5678, 0x401000)),
    ]:
        calls = []
        unhooked = []

        def fake_batch(value, _calls=calls):
            _calls.append(("batch", value))
            return 1

        hook = api_debug._DbgStartBatchHook(restore_batch=0)
        hook.unhook = lambda _u=unhooked: _u.append(True) or True

        patch = _SavedAttr(api_debug.idc, "batch", fake_batch)
        try:
            getattr(hook, callback_name)(*args)
            assert calls == [("batch", 0)], (
                f"{callback_name}: expected batch(0), got {calls}"
            )
            assert unhooked == [True], (
                f"{callback_name}: hook should unhook itself"
            )
            assert hook._done is True

            # Second invocation must be a no-op (idempotent).
            calls.clear()
            unhooked.clear()
            getattr(hook, callback_name)(*args)
            assert calls == []
            assert unhooked == []
        finally:
            patch.restore()


@test()
def test_dbg_start_reports_cancelled_when_start_process_returns_zero_and_state_never_comes_up():
    """When the debugger never comes up and start_process reported a
    cancellation, dbg_start should surface that specific error."""
    waits = {"count": 0}

    def wait_for_next_event(_flags, _timeout):
        waits["count"] += 1
        return 1

    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 0),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: False),
        _SavedAttr(api_debug.ida_dbg, "wait_for_next_event", wait_for_next_event),
    ]
    try:
        try:
            api_debug.dbg_start()
        except IDAError as exc:
            assert "cancelled" in str(exc).lower()
        else:
            raise AssertionError("Expected IDAError when debugger never starts")
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_briefly_waits_for_ip_but_still_succeeds_without_it():
    """dbg_start may wait briefly for an initial IP/suspend, but must still succeed without it."""
    calls = {"waits": 0}

    def wait_for_next_event(_flags, timeout):
        calls["waits"] += 1
        assert timeout == int(api_debug._DBG_START_WAIT_POLL_MS)
        return 1

    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_RUN),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: None),
        _SavedAttr(api_debug.ida_dbg, "wait_for_next_event", wait_for_next_event),
    ]
    try:
        result = api_debug.dbg_start()
        assert result == {
            "started": True,
            "state": "running",
            "running": True,
        }
        assert calls["waits"] == api_debug._DBG_START_IP_GRACE_POLL_COUNT
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_briefly_waits_for_ip_and_returns_it_if_it_appears():
    """dbg_start should report IP if it becomes available during the grace period."""
    calls = {"waits": 0}
    ip_values = iter([0x401000])
    state_values = iter([
        api_debug.ida_dbg.DSTATE_RUN,
        api_debug.ida_dbg.DSTATE_RUN,
        api_debug.ida_dbg.DSTATE_SUSP,
    ])

    def wait_for_next_event(_flags, timeout):
        calls["waits"] += 1
        assert timeout == int(api_debug._DBG_START_WAIT_POLL_MS)
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
        assert result == {
            "started": True,
            "state": "suspended",
            "suspended": True,
            "ip": "0x401000",
        }
        assert calls["waits"] == 2
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_waits_up_to_timeout_for_debugger_to_come_up():
    """dbg_start should tolerate a debugger that only becomes active after several polls."""
    calls = {"waits": 0}
    on_values = iter([False, False, False, False, False, False, True, True])

    def wait_for_next_event(_flags, timeout):
        calls["waits"] += 1
        assert timeout == int(api_debug._DBG_START_WAIT_POLL_MS)
        return 1

    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: next(on_values)),
        _SavedAttr(api_debug.ida_dbg, "get_process_state", lambda: api_debug.ida_dbg.DSTATE_SUSP),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: 0x401000),
        _SavedAttr(api_debug.ida_dbg, "wait_for_next_event", wait_for_next_event),
    ]
    try:
        result = api_debug.dbg_start()
        assert result == {
            "started": True,
            "state": "suspended",
            "suspended": True,
            "ip": "0x401000",
        }
        assert calls["waits"] == 6
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
