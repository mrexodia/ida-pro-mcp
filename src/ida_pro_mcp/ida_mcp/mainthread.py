"""Main-thread job pump for headless (idalib) workers.

idalib has no UI event loop, so execute_sync posted from a secondary thread is
never dispatched. IDA work must run on the thread that owns the database, so
the main thread parks here draining jobs while HTTP is served on background
threads. No IDA imports, so this is unit-testable outside IDA.
"""

import logging
import queue
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class PumpBusyError(RuntimeError):
    """A job did not reach the main thread before its deadline."""


class _Job:
    __slots__ = ("fn", "label", "done", "result", "error", "cancelled", "started_at")

    def __init__(self, fn: Callable[[], Any], label: str):
        self.fn = fn
        self.label = label
        self.done = threading.Event()
        self.result: Any = None
        self.error: BaseException | None = None
        self.cancelled = False
        self.started_at: float | None = None

    def run(self) -> None:
        self.started_at = time.monotonic()
        try:
            self.result = self.fn()
        except BaseException as e:  # noqa: BLE001 - handed to the waiter
            self.error = e
        finally:
            self.done.set()


class MainThreadPump:
    """Queue of callables executed on the thread that calls :meth:`run`."""

    def __init__(self):
        self._queue: queue.Queue[_Job] = queue.Queue()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread_id: int | None = None
        self._current: _Job | None = None
        self._running = False

    # -- state -------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._running

    def on_main_thread(self) -> bool:
        return self._thread_id == threading.get_ident()

    def busy_status(self) -> dict[str, Any] | None:
        """Describe the job occupying the main thread, or None if idle."""
        job = self._current
        if job is None:
            return None
        started = job.started_at
        return {
            "tool": job.label,
            "elapsed_sec": round(time.monotonic() - started, 3) if started else 0.0,
            "queued": self._queue.qsize(),
        }

    # -- lifecycle ---------------------------------------------------------

    def arm(self) -> None:
        """Claim the calling thread as the pump thread, before run().

        HTTP starts first, and a request landing in that gap would otherwise
        call execute_sync on its handler thread and hang there forever.
        """
        self._thread_id = threading.get_ident()
        self._running = True

    def run(self, poll_interval: float = 0.25) -> None:
        """Drain jobs until :meth:`stop`. Call from the IDA main thread."""
        self.arm()
        try:
            while not self._stop.is_set():
                try:
                    job = self._queue.get(timeout=poll_interval)
                except queue.Empty:
                    continue
                if job.cancelled:
                    job.done.set()
                    continue
                self._current = job
                try:
                    job.run()
                finally:
                    self._current = None
        finally:
            self._running = False
            self._drain_pending()

    def stop(self) -> None:
        self._stop.set()

    def _drain_pending(self) -> None:
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                return
            job.error = RuntimeError("worker is shutting down")
            job.done.set()

    # -- submission --------------------------------------------------------

    def submit(
        self,
        fn: Callable[[], Any],
        *,
        label: str = "",
        timeout: float | None = None,
    ) -> Any:
        """Run `fn` on the main thread and return its result.

        Raises PumpBusyError past `timeout`. The job is dropped if it never
        started, else left running: IDA cannot be interrupted from here.
        """
        if not self._running:
            raise RuntimeError("main-thread pump is not running")
        if self.on_main_thread():
            return fn()

        job = _Job(fn, label)
        self._queue.put(job)
        if job.done.wait(timeout):
            if job.error is not None:
                raise job.error
            return job.result

        if job.started_at is None:
            job.cancelled = True
        busy = self.busy_status()
        raise PumpBusyError(
            f"worker did not run '{label or 'tool'}' within {timeout:.1f}s; "
            f"the IDA main thread is busy"
            + (f" with '{busy['tool']}' ({busy['elapsed_sec']:.1f}s)" if busy else "")
        )


_pump = MainThreadPump()


def get_pump() -> MainThreadPump:
    return _pump
