import logging
import queue
import functools
import os
import sys
import time
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
from .rpc import McpToolError
from .zeromcp.jsonrpc import get_current_cancel_event, RequestCancelledError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


class CancelledError(RequestCancelledError):
    """Raised when a request is cancelled via notifications/cancelled."""
    pass


logger = logging.getLogger(__name__)
_TOOL_TIMEOUT_ENV = "IDA_MCP_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 15.0


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC



call_stack = queue.LifoQueue()


def _sync_wrapper(ff):
    """Call a function ff with a specific IDA safety_mode."""

    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()

    idaapi.execute_sync(runned, idaapi.MFF_WRITE)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def _normalize_timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sync_wrapper(ff, timeout_override: float | None = None):
    """Wrapper to enable batch mode during IDA synchronization."""
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    old_batch = idc.batch(1)
    try:
        timeout = timeout_override
        if timeout is None:
            timeout = _get_tool_timeout_seconds()
        if timeout > 0 or cancel_event is not None:
            def timed_ff():
                # Calculate deadline when execution starts on IDA main thread,
                # not when the request was queued (avoids stale deadlines)
                deadline = time.monotonic() + timeout if timeout > 0 else None

                def profilefunc(frame, event, arg):
                    # Check cancellation first (higher priority)
                    if cancel_event is not None and cancel_event.is_set():
                        raise CancelledError("Request was cancelled")
                    if deadline is not None and time.monotonic() >= deadline:
                        raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

                old_profile = sys.getprofile()
                sys.setprofile(profilefunc)
                try:
                    return ff()
                finally:
                    sys.setprofile(old_profile)

            timed_ff.__name__ = ff.__name__
            return _sync_wrapper(timed_ff)
        return _sync_wrapper(ff)
    finally:
        idc.batch(old_batch)


def idasync(f):
    """Run the function on the IDA main thread in write mode.
    
    This is the unified decorator for all IDA synchronization.
    Previously there were separate @idaread and @idawrite decorators,
    but since read-only operations in IDA might actually require write
    access (e.g., decompilation), we now use a single decorator.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, timeout_override)

    return wrapper


# Backwards compatibility aliases
idaread = idasync
idawrite = idasync


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds).

    IMPORTANT: Must be applied BEFORE @idasync (i.e., listed AFTER it)
    so the attribute exists when it captures the function in closure.

    Correct order:
        @tool
        @idasync
        @tool_timeout(90.0)  # innermost
        def my_func(...):
    """
    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func
    return decorator


def is_window_active():
    """Returns whether IDA is currently active."""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)
    
    if using_pyside6:
        from PySide6 import QtWidgets
    else:
        from PyQt5 import QtWidgets
    
    app = QtWidgets.QApplication.instance()
    if app is None:
        return False
    return app.activeWindow() is not None
