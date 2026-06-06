"""Worker self-shutdown bookkeeping.

A spawned idalib worker exits cleanly when no JSON-RPC request has hit its
dispatcher for `idle_ttl_sec` seconds. There is no per-supervisor refcount;
every callable client keeps the worker alive simply by issuing requests
through `idb_open`, `idb_list`, or any forwarded tool.

This module has no IDA dependencies on purpose so it can be unit-tested
outside of IDA.
"""

import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class WorkerLifecycle:
    """Idle-timeout watchdog for an idalib worker process."""

    IDLE_TTL_SEC = 600.0
    POLL_INTERVAL_SEC = 5.0
    MIN_IDLE_TTL_SEC = 10.0

    def __init__(
        self,
        *,
        idle_ttl_sec: float | None = None,
        poll_interval_sec: float | None = None,
    ):
        self.idle_ttl_sec: float = (
            idle_ttl_sec if idle_ttl_sec is not None else self.IDLE_TTL_SEC
        )
        self.poll_interval_sec = (
            poll_interval_sec if poll_interval_sec is not None else self.POLL_INTERVAL_SEC
        )
        self._lock = threading.Lock()
        self._last_request_at = time.monotonic()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._on_shutdown: Callable[[str], None] | None = None

    def start(self, on_shutdown: Callable[[str], None]) -> None:
        if self._thread is not None:
            return
        self._on_shutdown = on_shutdown
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="idalib-watchdog"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=5.0)

    def touch(self) -> None:
        with self._lock:
            self._last_request_at = time.monotonic()

    def set_idle_ttl(self, user_ttl_sec: float, load_time_sec: float = 0.0) -> None:
        with self._lock:
            self.idle_ttl_sec = (
                max(self.MIN_IDLE_TTL_SEC, user_ttl_sec) + max(0.0, load_time_sec)
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            return {
                "last_request_age_sec": round(now - self._last_request_at, 2),
                "idle_ttl_sec": self.idle_ttl_sec,
            }

    def check_shutdown_reason(self) -> str | None:
        with self._lock:
            last_req = self._last_request_at
            ttl = self.idle_ttl_sec
        now = time.monotonic()
        if (now - last_req) > ttl:
            return f"no requests for {now - last_req:.1f}s"
        return None

    def _run(self) -> None:
        while not self._stop_event.wait(self.poll_interval_sec):
            reason = self.check_shutdown_reason()
            if reason is None:
                continue
            self._fire_shutdown(reason)
            return

    def _fire_shutdown(self, reason: str) -> None:
        if self._on_shutdown is None:
            return
        try:
            self._on_shutdown(reason)
        except Exception:
            logger.exception("Lifecycle on_shutdown handler raised")
