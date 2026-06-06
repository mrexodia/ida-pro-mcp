import logging
import queue
import functools
import os
import sys
import threading
import time
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
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0


# Thread-local: while a synchronized tool body is running, holds the monotonic
# deadline (or None if no timeout). Tools can read this to self-monitor and
# return partial results gracefully — useful when sync.py's Timer-fired
# set_cancelled mechanism races with GIL contention on tight loops.
_deadline_state = threading.local()


def get_tool_deadline() -> float | None:
    """Return the monotonic deadline for the current tool call, or None.

    Only meaningful inside an @idasync function body. Tools that walk
    large structures can check `time.monotonic() >= get_tool_deadline()`
    to bail cleanly without depending on the global cancel flag.
    """
    return getattr(_deadline_state, "deadline", None)


def _get_tool_timeout_seconds() -> float:
    value = os.getenv(_TOOL_TIMEOUT_ENV, "").strip()
    if value == "":
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        return float(value)
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


call_stack = queue.LifoQueue()

# Thread-local: while a synchronized tool body is running, holds the batch
# value that was in effect *before* the sync wrapper bumped it to 1. Tools
# decorated with @keep_batch read this via get_pre_call_batch() so they can
# restore the caller's original state — not assume a hard-coded default.
_sync_state = threading.local()


def get_pre_call_batch() -> int | None:
    """Return the pre-call batch state, or None if not inside a sync body.

    Only meaningful inside a @idasync function body — outside of that the
    sync wrapper isn't tracking anything. Tools using @keep_batch should
    read this and pass it to whatever asynchronous restorer they install,
    so the original batch state is preserved across the deferred work.
    """
    return getattr(_sync_state, "pre_call_batch", None)


def _sync_wrapper(ff, keep_batch=False):
    """Call a function ff with a specific IDA safety_mode.

    If keep_batch=True and ff() returns successfully, batch mode is left on
    after the wrapper exits. The decorated function is responsible for
    arranging restoration (typically via a DBG_Hooks callback) so that any
    asynchronous work scheduled by ff() — e.g. start_process triggering a
    "matching executable names" dialog after we exit execute_sync — runs
    while batch mode is still on. On exception, batch mode is always
    restored before re-raising.

    The pre-call batch state is exposed to ff() via get_pre_call_batch()
    so tools can capture it (typically at hook-install time) and restore
    the caller's original state instead of hard-coding a default.
    """

    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            # Non-blocking: a concurrent reentrant @idasync call from
            # within another tool's ff() on the same main thread may
            # have drained the queue between empty() and get().
            try:
                last_func_name = call_stack.get_nowait()
            except queue.Empty:
                last_func_name = "<empty>"
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        # Enable batch mode for all synchronized operations
        old_batch = idc.batch(1)
        prev_pre_call = getattr(_sync_state, "pre_call_batch", None)
        _sync_state.pre_call_batch = old_batch
        completed = False
        try:
            res_container.put(ff())
            completed = True
        except Exception as x:
            res_container.put(x)
        finally:
            if not (completed and keep_batch):
                idc.batch(old_batch)
            _sync_state.pre_call_batch = prev_pre_call
            # Non-blocking: a reentrant @idasync invoked synchronously
            # inside ff() may have already popped our entry. Default
            # block=True would freeze the IDA main thread on an empty
            # queue and hang every subsequent @idasync call.
            try:
                call_stack.get_nowait()
            except queue.Empty:
                pass

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


def sync_wrapper(
    ff, timeout_override: float | None = None, keep_batch: bool = False
):
    """Wrapper to enable timeout and cancellation during IDA synchronization.

    Note: Batch mode is now handled in _sync_wrapper to ensure it's always
    applied consistently for all synchronized operations. Pass keep_batch=True
    to opt out of the post-call batch restore (see _sync_wrapper docstring).
    """
    # Capture cancel event from thread-local before execute_sync
    cancel_event = get_current_cancel_event()

    timeout = timeout_override
    if timeout is None:
        timeout = _get_tool_timeout_seconds()
    if timeout > 0 or cancel_event is not None:

        def timed_ff():
            # Calculate deadline when execution starts on IDA main thread,
            # not when the request was queued (avoids stale deadlines)
            deadline = time.monotonic() + timeout if timeout > 0 else None

            # Native cancellation: clear any stale flag and schedule a
            # set_cancelled() at the deadline. Many IDA SDK calls
            # (ida_search.find_*, ida_bytes.find_bytes/bin_search,
            # ida_hexrays.decompile*, ida_strlist.build_strlist,
            # ida_auto.auto_wait) poll user_cancelled() and bail with
            # BADADDR / MERR_CANCELED within one poll cycle, freeing the
            # main thread instead of running to natural completion.
            # set_cancelled() is THREAD_SAFE so firing it from a Timer
            # thread is safe.
            ida_kernwin.clr_cancelled()
            cancel_fired_at: list[float | None] = [None]
            native_timer: threading.Timer | None = None
            if deadline is not None:
                def _fire_native_cancel():
                    cancel_fired_at[0] = time.monotonic()
                    ida_kernwin.set_cancelled()
                native_timer = threading.Timer(timeout, _fire_native_cancel)
                native_timer.daemon = True
                native_timer.start()

            def profilefunc(frame, event, arg):
                # Check request-level cancellation first (higher priority)
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("Request was cancelled")
                # If native cancel just fired, give the tool a short grace
                # period to format a partial response rather than racing the
                # IDASyncError. Beyond that we still raise to bound the
                # response time.
                fired_at = cancel_fired_at[0]
                if fired_at is not None and time.monotonic() < fired_at + 5.0:
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    raise IDASyncError(f"Tool timed out after {timeout:.2f}s")

            # Expose the deadline so tool bodies can self-monitor and
            # return partial results gracefully (independent of the Timer).
            _deadline_state.deadline = deadline
            old_profile = sys.getprofile()
            sys.setprofile(profilefunc)
            try:
                return ff()
            finally:
                sys.setprofile(old_profile)
                if native_timer is not None:
                    native_timer.cancel()
                # Sticky flag: clear unconditionally so the next tool starts
                # with a clean state. Without this, every subsequent
                # user_cancelled() returns True forever.
                ida_kernwin.clr_cancelled()
                _deadline_state.deadline = None

        timed_ff.__name__ = ff.__name__
        return _sync_wrapper(timed_ff, keep_batch=keep_batch)
    return _sync_wrapper(ff, keep_batch=keep_batch)


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
        keep_batch = bool(getattr(f, "__ida_mcp_keep_batch__", False))
        return sync_wrapper(ff, timeout_override, keep_batch=keep_batch)

    return wrapper


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


def keep_batch(func):
    """Decorator to skip the sync wrapper's post-call batch-mode restore.

    Apply when the tool schedules asynchronous work that runs on the IDA
    main thread *after* execute_sync exits (e.g. start_process, which
    triggers the "matching executable names" dialog later). The decorated
    function MUST arrange batch-mode restoration itself, typically via a
    DBG_Hooks callback that fires once the asynchronous work has completed,
    so batch mode is not left on indefinitely.

    Same ordering rule as tool_timeout: place AFTER @idasync (innermost).

        @tool
        @idasync
        @keep_batch
        def my_func(...):
    """

    setattr(func, "__ida_mcp_keep_batch__", True)
    return func


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
