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


class IDASafety(IntEnum):
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


call_stack = queue.LifoQueue()


def _sync_wrapper(ff, safety_mode: IDASafety):
    """Call a function ff with a specific IDA safety_mode."""
    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = f"Invalid safety mode {safety_mode} over function {ff.__name__}"
        logger.error(error_str)
        raise IDASyncError(error_str)

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

    idaapi.execute_sync(runned, safety_mode)
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


def sync_wrapper(ff, safety_mode: IDASafety, timeout_override: float | None = None):
    """Wrapper to enable batch mode during IDA synchronization."""
    old_batch = idc.batch(1)
    try:
        timeout = timeout_override
        if timeout is None:
            timeout = _get_tool_timeout_seconds()
        if timeout > 0:
            deadline = time.monotonic() + timeout

            def timed_ff():
                def tracefunc(frame, event, arg):
                    if time.monotonic() >= deadline:
                        raise IDASyncError(f"Tool timed out after {timeout:.2f}s")
                    return tracefunc

                old_trace = sys.gettrace()
                sys.settrace(tracefunc)
                try:
                    return ff()
                finally:
                    sys.settrace(old_trace)

            timed_ff.__name__ = ff.__name__
            return _sync_wrapper(timed_ff, safety_mode)
        return _sync_wrapper(ff, safety_mode)
    finally:
        idc.batch(old_batch)

def idawrite(f):
    """Decorator for marking a function as modifying the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, idaapi.MFF_WRITE, timeout_override)

    return wrapper


def idaread(f):
    """Decorator for marking a function as reading from the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        timeout_override = _normalize_timeout(
            getattr(f, "__ida_mcp_timeout_sec__", None)
        )
        return sync_wrapper(ff, idaapi.MFF_READ, timeout_override)

    return wrapper


def tool_timeout(seconds: float):
    """Decorator to override per-tool timeout (seconds)."""
    def decorator(func):
        setattr(func, "__ida_mcp_timeout_sec__", seconds)
        return func
    return decorator


def is_window_active():
    """Returns whether IDA is currently active"""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    try:
        if using_pyside6:
            import PySide6.QtWidgets as QApplication
        else:
            import PyQt5.QtWidgets as QApplication

        app = QApplication.instance()
        if app is None:
            return False

        for widget in app.topLevelWidgets():
            if widget.isActiveWindow():
                return True
    except Exception:
        # Headless mode or other error (this is not a critical feature)
        pass
    return False
