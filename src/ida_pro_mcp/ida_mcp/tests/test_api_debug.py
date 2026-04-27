"""Tests for debugger control helpers."""

from ..framework import test
from .. import api_debug


class _SavedAttr:
    def __init__(self, obj, name, value):
        self.obj = obj
        self.name = name
        self.old = getattr(obj, name)
        setattr(obj, name, value)

    def restore(self):
        setattr(self.obj, self.name, self.old)


@test()
def test_dbg_start_reports_success_when_debugger_is_running_without_ip():
    """dbg_start should report success even if IP is not immediately available after launch."""
    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: None),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: True),
    ]
    try:
        result = api_debug.dbg_start()
        assert result == {"started": True}
    finally:
        for patch in reversed(patches):
            patch.restore()


@test()
def test_dbg_start_waits_briefly_for_first_ip():
    """dbg_start should wait for the first suspend event before giving up on IP reporting."""
    calls = {"waits": 0}
    ip_values = iter([None, None, 0x401000])

    def wait_for_next_event(_flags, _timeout):
        calls["waits"] += 1
        return 1

    patches = [
        _SavedAttr(api_debug, "list_breakpoints", lambda: [object()]),
        _SavedAttr(api_debug.idaapi, "start_process", lambda *_args: 1),
        _SavedAttr(api_debug.ida_dbg, "get_ip_val", lambda: next(ip_values)),
        _SavedAttr(api_debug.ida_dbg, "is_debugger_on", lambda: False),
        _SavedAttr(api_debug.ida_dbg, "wait_for_next_event", wait_for_next_event),
    ]
    try:
        result = api_debug.dbg_start()
        assert result == {"started": True, "ip": "0x401000"}
        assert calls["waits"] >= 1
    finally:
        for patch in reversed(patches):
            patch.restore()
