#!/usr/bin/env python3
"""Stress test: search-cancellation behavior (issue #235).

Validates that the cancellation plumbing in sync.py works end-to-end:
  - find_bytes / find / search_text are interrupted at the configured tool
    timeout via ida_kernwin.set_cancelled() fired by sync_wrapper.
  - a slow scan does NOT cause subsequent calls to time out (no sticky
    failure: the main thread is freed within one cancel-poll cycle of the
    deadline).
  - the recovered server state is clean (cancel flag cleared in finally).

Usage:
    # Headless: spawn our own idalib-mcp on a binary (RECOMMENDED — a wedge
    # only kills the spawned subprocess, not your GUI session)
    python3 scripts/stress_search_cancellation.py --spawn path/to/binary
    python3 scripts/stress_search_cancellation.py --spawn path/to/binary.i64

    # Drive an already-running server (GUI plugin or external idalib)
    python3 scripts/stress_search_cancellation.py --url http://127.0.0.1:13337/mcp
    python3 scripts/stress_search_cancellation.py --phases 0,3,5    # subset

Spawned mode passes --unsafe automatically so py_eval is available; the script
uses py_eval to override the server-side tool timeout via IDA_MCP_TOOL_TIMEOUT_SEC
so we can exercise cancellation without waiting for the 60s default.
"""

from __future__ import annotations
import argparse
import atexit
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:13337/mcp"
HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


@dataclass
class Ctx:
    url: str
    database: str | None
    short_timeout: float
    long_timeout: float
    binary_info: dict = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    passes: list[str] = field(default_factory=list)


# ─── Headless idalib-mcp lifecycle ─────────────────────────────────────────

def _free_port() -> int:
    """Bind a temporary socket to get an unused port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def spawn_idalib(binary: Path, *, port: int | None = None,
                 boot_timeout: float = 600.0) -> tuple[subprocess.Popen, str]:
    """Spawn `uv run idalib-mcp --unsafe --port=<p> <binary>` and wait until
    it is ready to serve. Returns (proc, url). Auto-killed at exit.

    Boot timeout is generous because idalib has to run auto-analysis on the
    binary, which can take minutes on large inputs.
    """
    if not binary.exists():
        raise FileNotFoundError(binary)
    port = port or _free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    print(f"  spawning: uv run idalib-mcp --unsafe --port={port} {binary}")
    log_path = Path(f"/tmp/stress_idalib_{port}.log")
    log = open(log_path, "wb")
    proc = subprocess.Popen(
        ["uv", "run", "idalib-mcp", "--unsafe", "--port", str(port), str(binary)],
        stdout=log, stderr=subprocess.STDOUT,
        # Own process group so we can SIGTERM the whole tree on exit.
        preexec_fn=os.setsid if hasattr(os, "setsid") else None,
    )
    atexit.register(_kill_proc, proc)
    print(f"  log: {log_path}  pid: {proc.pid}")
    # Wait for "Server started" / readiness in the log, plus a live HTTP probe.
    deadline = time.monotonic() + boot_timeout
    last_status = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"idalib-mcp exited early (code={proc.returncode}); "
                f"check {log_path}"
            )
        try:
            txt = log_path.read_text(errors="replace")
        except Exception:
            txt = ""
        if "Streamable HTTP" in txt or "[MCP] Server started" in txt:
            # Server is up. Now wait for the worker to finish opening the IDB.
            status = _wait_until_session_ready(url, deadline)
            if status == "ready":
                print(f"  idalib ready at {url}")
                return proc, url
            last_status = status
        time.sleep(2.0)
    raise TimeoutError(
        f"idalib-mcp didn't become ready in {boot_timeout}s "
        f"(last={last_status}); see {log_path}"
    )


def _wait_until_session_ready(url: str, deadline: float) -> str:
    """Poll idb_list until at least one session is is_active=true and not analyzing."""
    while time.monotonic() < deadline:
        try:
            payload = {"jsonrpc": "2.0", "id": "boot", "method": "tools/call",
                       "params": {"name": "idb_list", "arguments": {}}}
            req = urllib.request.Request(url, json.dumps(payload).encode(), HEADERS)
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
            sc = body.get("result", {}).get("structuredContent", {})
            sessions = sc.get("sessions") or []
            if sessions and any(s.get("is_active") and not s.get("is_analyzing") for s in sessions):
                return "ready"
            return "analyzing" if sessions else "no_session"
        except Exception:
            pass
        time.sleep(2.0)
    return "timeout"


def _kill_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
    except ProcessLookupError:
        pass


def discover_session(url: str) -> str | None:
    """Return the first active session id for the URL, or None (GUI plugin)."""
    payload = {"jsonrpc": "2.0", "id": "ls", "method": "tools/call",
               "params": {"name": "idb_list", "arguments": {}}}
    req = urllib.request.Request(url, json.dumps(payload).encode(), HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
    except Exception:
        return None
    res = body.get("result", {})
    if res.get("isError"):
        return None
    sc = res.get("structuredContent") or {}
    sessions = sc.get("sessions") or []
    for s in sessions:
        if s.get("is_active"):
            return s.get("session_id")
    return None


# ─── Low-level RPC ─────────────────────────────────────────────────────────

def rpc(ctx: Ctx, name: str, args: dict, *, client_timeout: float) -> tuple[float, dict, str]:
    """Send tools/call. Returns (wall_seconds, structured_or_None, raw_text_or_error)."""
    args = dict(args)
    if ctx.database:
        args.setdefault("database", ctx.database)
    payload = {"jsonrpc": "2.0", "id": name, "method": "tools/call",
               "params": {"name": name, "arguments": args}}
    req = urllib.request.Request(ctx.url, json.dumps(payload).encode(), HEADERS)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=client_timeout) as resp:
            body = json.loads(resp.read().decode())
    except Exception as e:
        return time.monotonic() - t0, {}, f"HTTP-ERROR {type(e).__name__}: {e}"
    dt = time.monotonic() - t0
    result = body.get("result", {})
    if result.get("isError"):
        text = result.get("content", [{}])[0].get("text", "")
        return dt, {}, f"TOOL-ERROR {text}"
    sc = result.get("structuredContent") or {}
    return dt, sc, ""


def py(ctx: Ctx, code: str, *, client_timeout: float = 30) -> tuple[float, str, str]:
    """Run a one-liner via py_eval. Returns (wall, result_str, error_str)."""
    dt, sc, err = rpc(ctx, "py_eval", {"code": code}, client_timeout=client_timeout)
    if err:
        return dt, "", err
    return dt, str(sc.get("result", "")), str(sc.get("stderr", ""))


def set_server_timeout(ctx: Ctx, seconds: float | None) -> None:
    """Override the server-side per-tool timeout via os.environ. None = unset.

    Note: os.environ requires string values, so the seconds float must be
    stringified — silently sending a float raises TypeError on the server
    and the timeout never actually changes.
    """
    if seconds is None:
        code = "import os; os.environ.pop('IDA_MCP_TOOL_TIMEOUT_SEC', None); 'unset'"
    else:
        code = (
            f"import os; "
            f"os.environ['IDA_MCP_TOOL_TIMEOUT_SEC'] = {str(seconds)!r}; "
            f"os.environ['IDA_MCP_TOOL_TIMEOUT_SEC']"
        )
    _, r, e = py(ctx, code)
    if e:
        raise RuntimeError(f"set_server_timeout({seconds}) failed: {e}")
    if seconds is not None and r != str(seconds):
        raise RuntimeError(f"set_server_timeout({seconds}) returned {r!r}")


# ─── Reporting helpers ─────────────────────────────────────────────────────

def hr(title: str) -> None:
    print(f"\n{'─'*4} {title} {'─'*max(4, 70-len(title))}")

def check(ctx: Ctx, name: str, ok: bool, detail: str) -> None:
    badge = "PASS" if ok else "FAIL"
    print(f"  [{badge}] {name}: {detail}")
    (ctx.passes if ok else ctx.failures).append(name)


# ─── Phases ────────────────────────────────────────────────────────────────

def phase_0_probe(ctx: Ctx) -> None:
    hr("phase 0 — probe environment & detect mode")
    # New sync.py loaded? Check both GUI plugin (ida_mcp.sync) and idalib
    # worker (ida_pro_mcp.ida_mcp.sync) module naming.
    _, r, _ = py(ctx,
        "import sys; "
        "m = sys.modules.get('ida_mcp.sync') or sys.modules.get('ida_pro_mcp.ida_mcp.sync'); "
        "'NEW' if (m and hasattr(m,'ida_kernwin')) else 'OLD'")
    check(ctx, "sync.py has cancellation plumbing", r == "NEW",
          r if r else "couldn't probe (py_eval blocked?)")
    if r != "NEW":
        _, file_path, _ = py(ctx,
            "import sys; "
            "m = sys.modules.get('ida_mcp.sync') or sys.modules.get('ida_pro_mcp.ida_mcp.sync'); "
            "m and m.__file__")
        print(f"    loaded sync.py path  : {file_path}")
    # Binary info
    _, h, _ = rpc(ctx, "server_health", {}, client_timeout=10)
    ctx.binary_info = h
    print(f"  binary: {h.get('module','?')}  ({h.get('idb_path','?')})")
    print(f"  hexrays_ready: {h.get('hexrays_ready')}  strings_cache_ready: {h.get('strings_cache_ready')}")
    # Function count
    _, sc, _ = rpc(ctx, "list_funcs", {"count": 1, "offset": 0}, client_timeout=30)
    total = sc.get("total") if isinstance(sc, dict) else None
    if total is not None:
        ctx.binary_info["func_total"] = total
        print(f"  total functions: {total}")
    # Image size hint
    _, r, _ = py(ctx, "import ida_ida; ida_ida.inf_get_max_ea()-ida_ida.inf_get_min_ea()")
    try:
        ctx.binary_info["image_size"] = int(r)
        print(f"  image size: {ctx.binary_info['image_size'] // (1024*1024)} MB ({r} bytes)")
    except (TypeError, ValueError):
        pass


def phase_1_baseline_scan_time(ctx: Ctx) -> None:
    """How long does an UNBOUNDED scan take on this binary?

    Pick a deliberately-not-present byte sequence. Use a generous client
    timeout AND a generous server timeout (no cancellation) to measure the
    raw cost. If this is fast (<5s) the binary isn't massive enough to
    really stress the cancellation paths.
    """
    hr("phase 1 — unbounded baseline scan time (no cancellation)")
    set_server_timeout(ctx, 600)  # 10 min server tool timeout
    pattern = "DE AD BE EF CA FE BA BE F0 0D"  # very unlikely
    print(f"  full-image find_bytes for {pattern!r}  (server timeout=600s, client=620s)…")
    dt, sc, err = rpc(ctx, "find_bytes", {"patterns": [pattern], "limit": 1}, client_timeout=620)
    if err:
        check(ctx, "baseline scan completes", False, err)
        return
    rows = sc.get("result", [])
    row = rows[0] if rows else {}
    matches = row.get("matches", [])
    cursor = row.get("cursor", {})
    print(f"  scan took {dt:.2f}s; matches={len(matches)}; cursor={cursor}")
    ctx.binary_info["baseline_scan_sec"] = dt
    check(ctx, "baseline scan completes", "done" in cursor or "next" in cursor,
          f"{dt:.2f}s, cursor={cursor}")


def phase_2_cancellation_works(ctx: Ctx) -> None:
    """Set a short server timeout, kick off the same slow scan, and verify
    it returns within (timeout + grace + small slack) instead of running to
    completion. The cursor should be marked cancelled.
    """
    hr(f"phase 2 — cancellation: short-timeout scan should return in ~{ctx.short_timeout}s + grace")
    base = ctx.binary_info.get("baseline_scan_sec")
    if base and base < ctx.short_timeout * 1.5:
        print(f"  ⚠ SKIPPING — baseline scan was only {base:.2f}s, < 1.5x short-timeout {ctx.short_timeout}s")
        print(f"    cancellation cannot fire because the scan finishes naturally first.")
        print(f"    (Need a bigger binary, or test a slower tool like search_text.)")
        return
    set_server_timeout(ctx, ctx.short_timeout)
    pattern = "DE AD BE EF CA FE BA BE F0 0D"
    client_timeout = ctx.short_timeout + 30  # 5s grace + 25s slack
    print(f"  full-image find_bytes for {pattern!r}  (server timeout={ctx.short_timeout}s, client={client_timeout}s)…")
    dt, sc, err = rpc(ctx, "find_bytes", {"patterns": [pattern], "limit": 1},
                      client_timeout=client_timeout)
    if err:
        # IDASyncError after the 5s grace is also an acceptable outcome
        if "timed out" in err.lower():
            print(f"  → server raised timeout after {dt:.2f}s: {err[:140]}")
            check(ctx, "scan returns within deadline (via raise)", dt < ctx.short_timeout + 10,
                  f"{dt:.2f}s vs deadline+grace={ctx.short_timeout+5}s")
            return
        check(ctx, "scan returns within deadline", False, err)
        return
    rows = sc.get("result", [])
    row = rows[0] if rows else {}
    cursor = row.get("cursor", {})
    print(f"  scan took {dt:.2f}s; matches={len(row.get('matches', []))}; cursor={cursor}")
    check(ctx, "scan returns within deadline+grace",
          dt < ctx.short_timeout + 8,
          f"{dt:.2f}s (deadline={ctx.short_timeout}s + 5s grace + 3s slack)")
    check(ctx, "cursor signals cancelled (not done)",
          bool(cursor.get("cancelled")),
          f"cursor={cursor}")


def phase_3_no_sticky_failure(ctx: Ctx) -> None:
    """The original #235 symptom: a slow scan made every subsequent call time
    out client-side until the slow scan finished naturally. Now: a fast call
    issued 2s after a slow scan starts should succeed promptly (because the
    slow scan is bounded by the short timeout and frees the main thread).
    """
    hr("phase 3 — no sticky failure: concurrent fast call during slow scan")
    set_server_timeout(ctx, ctx.short_timeout)
    results: dict[str, tuple[float, str]] = {}
    def fire(label, name, args, client_timeout):
        dt, sc, err = rpc(ctx, name, args, client_timeout=client_timeout)
        results[label] = (dt, err or json.dumps(sc)[:80])
    # A: kick off the slow scan with a generous client timeout
    tA = threading.Thread(target=fire, args=("A_slow",
        "find_bytes", {"patterns": ["DE AD BE EF CA FE BA BE F0 0D"], "limit": 1},
        ctx.short_timeout + 30))
    tA.start()
    time.sleep(2.0)
    # B: fast trivial call with SHORT client timeout — should NOT block
    tB = threading.Thread(target=fire, args=("B_fast",
        "server_health", {}, 5.0))
    tB.start()
    tA.join(); tB.join()
    dtA, A = results["A_slow"]
    dtB, B = results["B_fast"]
    print(f"  A (slow scan): {dtA:.2f}s — {A[:90]}")
    print(f"  B (fast call): {dtB:.2f}s — {B[:90]}")
    # B's success is what we care about
    check(ctx, "concurrent fast call succeeds despite slow scan",
          "HTTP-ERROR" not in B and dtB < 5.0,
          f"fast call took {dtB:.2f}s")


def phase_4_all_four_tools(ctx: Ctx) -> None:
    """Exercise the C-scan tools with the short timeout and confirm each
    behaves cleanly. SKIPS search_text on large binaries: ida_search.find_text
    walks the rendered listing and doesn't poll user_cancelled() often enough
    on huge .text segments — a stuck call here wedges every queued request
    and only naturally completes after many minutes. Tracked separately.
    """
    hr("phase 4 — C-scan tools with short timeout")
    set_server_timeout(ctx, ctx.short_timeout)
    cases = [
        ("find_bytes",  {"patterns": ["DE AD BE EF CA FE BA BE F0 0D"], "limit": 1}, "list"),
        ("find",        {"type": "string",    "targets": ["zzzz_never_a_match_zzzz"], "limit": 1}, "list"),
        ("find",        {"type": "immediate", "targets": [0xDEADBEEF],                "limit": 1}, "list"),
        # search_text now uses a Python-level Heads() walk that's bounded
        # and per-iteration cancellable, so it's safe on any binary size.
        ("search_text", {"pattern": "zzzz_never_a_match_zzzz", "limit": 1, "regex": False}, "dict"),
    ]
    for tool, args, shape in cases:
        label = f"{tool}({args.get('type', '')})" if tool == "find" else tool
        # If a prior call wedged the queue, skip subsequent tools rather than pile up POSTs.
        connect_dt, _, connect_err = rpc(ctx, "server_health", {}, client_timeout=5)
        if connect_err and "timed out" in connect_err.lower():
            print(f"  {label:25s}  -      SKIPPED: server unresponsive (queue wedged by prior call)")
            check(ctx, f"{label}: bounded", False, "skipped — server wedged")
            continue
        client_timeout = ctx.short_timeout + 30
        dt, sc, err = rpc(ctx, tool, args, client_timeout=client_timeout)
        if err:
            if "timed out" in err.lower() and dt < ctx.short_timeout + 10:
                print(f"  {label:25s}  {dt:6.2f}s   raised timeout (acceptable): {err[:80]}")
                check(ctx, f"{label}: bounded by deadline", True, f"{dt:.2f}s")
                continue
            print(f"  {label:25s}  {dt:6.2f}s   ERROR: {err[:100]}")
            check(ctx, f"{label}: bounded", False, err[:80])
            continue
        # Inspect cursor
        if shape == "list":
            row = (sc.get("result") or [{}])[0]
            cursor = row.get("cursor", {})
        else:
            cursor = sc.get("cursor", {})
        ok = dt < ctx.short_timeout + 8
        print(f"  {label:25s}  {dt:6.2f}s   cursor={cursor}")
        check(ctx, f"{label}: bounded by deadline+grace", ok,
              f"{dt:.2f}s vs {ctx.short_timeout+5}s")


def phase_5_recovery(ctx: Ctx) -> None:
    """After multiple cancellation events, normal calls should still work
    immediately and the cancel flag should be cleared.
    """
    hr("phase 5 — recovery / cancel-flag cleanup")
    set_server_timeout(ctx, None)  # restore default
    _, r, _ = py(ctx, "import ida_kernwin; ida_kernwin.user_cancelled()")
    check(ctx, "cancel flag is cleared after prior phases", r == "False",
          f"user_cancelled() = {r}")
    # Normal find_bytes should work and find real matches
    dt, sc, err = rpc(ctx, "find_bytes", {"patterns": ["55"], "limit": 5}, client_timeout=30)
    if err:
        check(ctx, "post-cancel normal find_bytes works", False, err)
        return
    rows = sc.get("result", [])
    matches = rows[0].get("matches", []) if rows else []
    print(f"  post-cancel find_bytes 55 (push rbp): {dt:.2f}s, {len(matches)} matches")
    check(ctx, "post-cancel normal find_bytes works", len(matches) > 0 and dt < 30,
          f"{len(matches)} matches in {dt:.2f}s")


# ─── Main ──────────────────────────────────────────────────────────────────

PHASES = {
    0: phase_0_probe,
    1: phase_1_baseline_scan_time,
    2: phase_2_cancellation_works,
    3: phase_3_no_sticky_failure,
    4: phase_4_all_four_tools,
    5: phase_5_recovery,
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--spawn", type=Path, default=None,
                   help="Path to a binary or .i64. Spawns its own idalib-mcp --unsafe "
                        "on a free port for isolation. Overrides --url/--database.")
    p.add_argument("--boot-timeout", type=float, default=900.0,
                   help="Seconds to wait for spawned idalib to finish analysis (default 900)")
    p.add_argument("--url", default=DEFAULT_URL, help=f"MCP endpoint (default {DEFAULT_URL})")
    p.add_argument("--database", default=None,
                   help="idalib session id (auto-discovered in --spawn mode; "
                        "omit for GUI plugin)")
    p.add_argument("--short-timeout", type=float, default=5.0,
                   help="seconds for the server tool timeout during cancellation phases (default 5)")
    p.add_argument("--long-timeout", type=float, default=600.0,
                   help="seconds for the unbounded baseline phase (default 600)")
    p.add_argument("--phases", default=None,
                   help="comma-separated phase numbers to run (default: all)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    selected = list(PHASES) if args.phases is None else [int(x) for x in args.phases.split(",")]

    spawned_proc: subprocess.Popen | None = None
    url = args.url
    database = args.database
    if args.spawn is not None:
        spawned_proc, url = spawn_idalib(args.spawn, boot_timeout=args.boot_timeout)
        if database is None:
            database = discover_session(url)
            print(f"  auto-discovered session: {database}")
    elif database is None:
        # Driving an external server. If it's idalib mode (database required),
        # auto-discover; if it's GUI mode this returns None which is correct.
        database = discover_session(url)
        if database:
            print(f"  auto-discovered idalib session: {database}")

    ctx = Ctx(url=url, database=database,
              short_timeout=args.short_timeout, long_timeout=args.long_timeout)
    print(f"target: {ctx.url}   database={ctx.database or '(GUI direct)'}")
    print(f"short-timeout: {ctx.short_timeout}s   long-timeout: {ctx.long_timeout}s")
    try:
        for n in selected:
            try:
                PHASES[n](ctx)
            except Exception as e:
                print(f"  ‼ phase {n} crashed: {type(e).__name__}: {e}")
                ctx.failures.append(f"phase_{n}_crashed")
    finally:
        # Best-effort restore
        try:
            set_server_timeout(ctx, None)
        except Exception:
            pass
        if spawned_proc is not None:
            print("\n  killing spawned idalib-mcp …")
            _kill_proc(spawned_proc)

    hr("summary")
    print(f"  passes: {len(ctx.passes)}")
    print(f"  fails:  {len(ctx.failures)}")
    if ctx.failures:
        for f in ctx.failures:
            print(f"    FAIL: {f}")
        return 1
    print("  ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
