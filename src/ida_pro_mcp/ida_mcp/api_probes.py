"""PROBE / WATCH / AUTOPILOT toolkit for IDA Pro MCP.

A live-debugger instrumentation layer built on the Phase-Plumbing in trace.py
(ProbeRing / probe registry / record_probe_event) and the Phase-0
_continue_and_wait pump in api_debug.py.

The core idea is the *non-stopping probe*: a breakpoint with a Python
condition that captures a small spec of values (registers, stack args, return
value, caller, memory slices), records the event into the probe ring, decrements
a hit budget, self-disarms at the budget, and ALWAYS returns False so the
debuggee never actually stops. This lets the toolkit watch a running process at
many sites without ever calling dbg_start and without halting execution.

Layers:
- PURE-LOGIC (no IDA): parse_capture_spec / build_probe_record / the small
  expr helpers. These import without idaapi so they are unit-testable headless.
- LIVE: the @tool entry points, each of which HARD-REQUIRES
  ida_dbg.is_debugger_on() and NEVER calls dbg_start.

Decorator idiom (outer -> inner):
    @ext("dbg") -> @safety(...) -> @title("...") -> @tool -> @idasync
    (+ @tool_timeout innermost for the waiting tools).

The ENTIRE probe toolkit lives under the debugger view (?ext=dbg): every tool
here is meaningless without a live debugger session, so read-only tools carry
@ext("dbg") + @safety("READ") and state-mutating/execute tools carry
@ext("dbg") + @safety("EXECUTE") or @safety("DESTRUCTIVE").

All debugger work uses raw idapython (ida_dbg / ida_idd / idc / idaapi), NOT
ida-domain.
"""

import re
import threading
from typing import Any, Optional, TypedDict

from . import trace as _trace
from .rpc import tool, safety, title, ext
from .safe_eval import safe_eval
from .sync import idasync, tool_timeout, IDAError


# ============================================================================
# TypedDict result shapes
# ============================================================================


class ProbeRef(TypedDict, total=False):
    probe_id: str
    ea: str
    kind: str
    capture: list[str]
    condition: str | None
    max_hits: int
    armed: bool
    installed: bool
    reused: bool
    error: str


class ProbeListResult(TypedDict):
    probes: list[dict]


class ProbeDrainResult(TypedDict):
    records: list[dict]
    cursor: int
    dropped: int


class ProbeClearResult(TypedDict, total=False):
    removed: int
    error: str


class RunUntilResult(TypedDict, total=False):
    status: str
    stopped_ea: str | None
    elapsed_ms: float
    hit_probe: str | None
    buffer: list[dict]
    error: str


class ReadStructLiveResult(TypedDict, total=False):
    fields: dict
    raw_hex: str | None
    _meta: dict
    error: str


class AppcallResult(TypedDict, total=False):
    dry_run: bool
    resolved_proto: str | None
    marshalled_args: list
    ret: Any
    exception: str | None
    _meta: dict
    error: str


class AppcallInspectResult(TypedDict, total=False):
    resolved_proto: str | None
    arg_types: list[str]
    ret_type: str | None
    _meta: dict
    error: str


class ProbeNetResult(TypedDict, total=False):
    installed: list[ProbeRef]
    error: str


class SnapshotResult(TypedDict, total=False):
    name: str
    regs: dict
    ranges: list[dict]
    restored: bool
    partial: bool
    restored_regs: int
    failed_regs: int
    restored_ranges: int
    failed_ranges: int
    identity: dict
    warning: str
    error: str


class TraceSummaryResult(TypedDict, total=False):
    group_by: str
    numeric_field: str | None
    total_records: int
    distinct_groups: int
    groups: list[dict]
    drained: int
    error: str


class AutopilotResult(TypedDict, total=False):
    transcript: list[dict]
    stopped_reason: str
    steps_run: int
    error: str


class BufferDiffResult(TypedDict, total=False):
    len_a: int | None
    len_b: int | None
    changed_offsets: list[int]
    first_diff: int | None
    equal: bool
    error: str


class MemoryScanResult(TypedDict, total=False):
    pattern: str
    pattern_len: int
    mask: str
    hits: list[str]
    scanned_ranges: int
    truncated: bool
    error: str


class ProbeStatsResult(TypedDict, total=False):
    armed_probes: int
    total_probes: int
    ring: dict
    fill_pct: float
    dropped: int
    per_probe: list[dict]
    error: str


class SnapshotListResult(TypedDict, total=False):
    snapshots: list[dict]
    error: str


class SnapshotDeleteResult(TypedDict, total=False):
    name: str
    deleted: bool
    error: str


# ============================================================================
# PURE-LOGIC SEPARATION (no live process / no idaapi required)
# ============================================================================

# A capture token is one of:
#   "<reg>"            a register name (eax, ecx, esp, ...)
#   "argN"             the Nth stack argument (cdecl/thiscall layout, see below)
#   "ret"             the return value register (eax on x86)
#   "caller"          the return address read from [esp] at function entry
#   "mem(<expr>,<n>)"  n bytes of memory at the address given by <expr>, where
#                      <expr> may itself reference regs / argN / a hex literal
_MEM_RE = re.compile(r"^\s*mem\(\s*(?P<expr>[^,]+?)\s*,\s*(?P<size>\d+)\s*\)\s*$", re.IGNORECASE)
_ARG_RE = re.compile(r"^arg(?P<idx>\d+)$", re.IGNORECASE)
_REG_TOKENS = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "al", "bl", "cl", "dl", "ax", "bx", "cx", "dx",
}


class CaptureToken(TypedDict, total=False):
    raw: str
    kind: str  # "reg" | "arg" | "ret" | "caller" | "mem"
    name: str  # reg name (reg/ret), arg index (arg), or expr (mem)
    size: int  # mem size
    error: str


def parse_capture_spec(capture: list[str]) -> list[CaptureToken]:
    """Parse a list of capture tokens into a structured plan.

    Pure: no IDA, no live process. Unknown / malformed tokens are returned with
    an "error" set rather than raising, so a partly-valid spec still installs
    and the caller can see which tokens were rejected.
    """
    if capture is None:
        return []
    if isinstance(capture, str):
        capture = [capture]
    plan: list[CaptureToken] = []
    for raw in capture:
        token = str(raw).strip()
        low = token.lower()
        if not token:
            continue
        m = _MEM_RE.match(token)
        if m:
            try:
                size = int(m.group("size"))
            except (TypeError, ValueError):
                plan.append({"raw": token, "kind": "mem", "error": "bad size"})
                continue
            if size < 0 or size > 4096:
                plan.append({"raw": token, "kind": "mem", "error": "size out of range"})
                continue
            plan.append({"raw": token, "kind": "mem", "name": m.group("expr").strip(), "size": size})
            continue
        am = _ARG_RE.match(low)
        if am:
            plan.append({"raw": token, "kind": "arg", "name": am.group("idx")})
            continue
        if low == "ret":
            plan.append({"raw": token, "kind": "ret", "name": "eax"})
            continue
        if low == "caller":
            plan.append({"raw": token, "kind": "caller", "name": "caller"})
            continue
        if low in _REG_TOKENS:
            plan.append({"raw": token, "kind": "reg", "name": low})
            continue
        plan.append({"raw": token, "kind": "unknown", "error": "unrecognized capture token"})
    return plan


def build_probe_record(
    probe_id: str,
    kind: str,
    ea: int | None,
    captured: dict,
    *,
    hit: int | None = None,
    tid: int | None = None,
    extra: dict | None = None,
) -> dict:
    """Assemble a probe-event record dict from already-captured values.

    Pure: takes the captured value dict (produced by the live evaluator) and
    folds it into the canonical record shape. record_probe_event() will stamp
    _seq/_meta/ts on top. Kept pure so it can be exercised headless.
    """
    record: dict = {
        "probe_id": probe_id,
        "kind": kind,
        "ea": hex(ea) if isinstance(ea, int) else ea,
        "captured": dict(captured) if captured else {},
    }
    if hit is not None:
        record["hit"] = hit
    if tid is not None:
        record["tid"] = tid
    if extra:
        for k, v in extra.items():
            record.setdefault(k, v)
    return record


def _stable_probe_id(prefix: str, ea: int | None, capture: list[str], condition: str | None) -> str:
    """Deterministic id over (ea, capture, condition) so install is idempotent."""
    import hashlib

    key = repr((ea, tuple(capture or ()), condition or ""))
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]
    ea_part = f"{ea:x}" if isinstance(ea, int) else "na"
    return f"{prefix}_{ea_part}_{digest}"


# Pointer-chain expression parser for read_struct_live: "[[base+0x10]+0x8]".
# Pure parse -> list of ops; the live deref applies them with read_dbg_memory.
def parse_ptr_chain(expr: str) -> list[dict]:
    """Parse a "[[base+0x10]+0x8]"-style pointer chain into a flat op list.

    Returns ops like {"op":"add","value":16} and {"op":"deref"}. The base token
    (a hex/dec literal or a name) is the first op {"op":"base","value":...}. Pure
    string parsing; resolution of names and the actual deref happens live.
    """
    s = str(expr).strip()
    if not s:
        raise ValueError("empty pointer-chain expression")

    pos = 0
    n = len(s)

    def skip_ws():
        nonlocal pos
        while pos < n and s[pos].isspace():
            pos += 1

    def parse_term() -> list[dict]:
        nonlocal pos
        skip_ws()
        if pos >= n:
            raise ValueError("unexpected end of expression")
        if s[pos] == "[":
            pos += 1
            inner = parse_expr()
            skip_ws()
            if pos >= n or s[pos] != "]":
                raise ValueError("unbalanced '[' in pointer-chain expression")
            pos += 1
            return inner + [{"op": "deref"}]
        # literal or name token up to an operator / bracket
        start = pos
        while pos < n and s[pos] not in "[]+-":
            pos += 1
        tok = s[start:pos].strip()
        if not tok:
            raise ValueError("empty term in pointer-chain expression")
        try:
            value = int(tok, 0)
            return [{"op": "base", "value": value}]
        except ValueError:
            return [{"op": "base_name", "value": tok}]

    def parse_expr() -> list[dict]:
        nonlocal pos
        ops = parse_term()
        while True:
            skip_ws()
            if pos < n and s[pos] in "+-":
                sign = s[pos]
                pos += 1
                skip_ws()
                start = pos
                while pos < n and s[pos] not in "[]+-":
                    pos += 1
                tok = s[start:pos].strip()
                if not tok:
                    raise ValueError("missing operand after '%s'" % sign)
                try:
                    value = int(tok, 0)
                except ValueError:
                    raise ValueError("non-literal offset %r in pointer chain" % tok)
                ops.append({"op": "add", "value": value if sign == "+" else -value})
            else:
                break
        return ops

    ops = parse_expr()
    skip_ws()
    if pos != n:
        raise ValueError("trailing characters in pointer-chain expression: %r" % s[pos:])
    return ops


# ----------------------------------------------------------------------------
# AUTOPILOT step plan (pure validation / sequencing).
#
# autopilot_run sequences ONLY a whitelist of SAFE pilot primitives. Anything
# that installs a patch, calls appcall, or otherwise executes target code is
# rejected at plan time so it can never make it into the live loop. This logic
# is pure (no idaapi) so the whitelist + budget rules are unit-testable headless.
# ----------------------------------------------------------------------------

# The ONLY actions an autopilot step may request. Each maps to a non-code-
# injecting pilot primitive (resume/observe/drain). Patch install and appcall
# are DELIBERATELY excluded.
AUTOPILOT_SAFE_ACTIONS = frozenset({
    "continue",      # resume until next suspend / timeout
    "run_until",     # resume until target_ea / probe / timeout
    "read_regs",     # read GP registers (no resume)
    "read_memory",   # read a memory slice (no resume)
    "probe_drain",   # drain captured probe records (no resume)
})

# Actions that, if requested, are an immediate hard reject (they execute target
# code or mutate the image). Listed explicitly so the error is specific.
AUTOPILOT_FORBIDDEN_ACTIONS = frozenset({
    "appcall", "patch", "patch_asm", "probe_add", "watch_field",
    "trace_calls", "snapshot_restore", "dbg_start", "dbg_write", "set_reg",
})


def validate_autopilot_step(step: Any) -> dict:
    """Validate ONE autopilot step. Pure: returns a normalized step dict.

    Returns {"action": <safe-action>, "params": {...}} on success, or
    {"error": "..."} (with "action" echoed when known) on rejection. A step
    must be a dict with an "action" in AUTOPILOT_SAFE_ACTIONS; every other key
    is carried through as a parameter. Forbidden actions (appcall/patch/...)
    are rejected with an explicit message so the live loop never sees them.
    """
    if not isinstance(step, dict):
        return {"error": f"step must be a dict, got {type(step).__name__}"}
    action = step.get("action")
    if not action:
        return {"error": "step missing 'action'"}
    action = str(action).strip().lower()
    if action in AUTOPILOT_FORBIDDEN_ACTIONS:
        return {
            "action": action,
            "error": (
                f"action {action!r} is forbidden in autopilot: it installs a "
                "patch / executes target code. Run it as a separate, "
                "human-confirmed tool call."
            ),
        }
    if action not in AUTOPILOT_SAFE_ACTIONS:
        return {
            "action": action,
            "error": (
                f"action {action!r} is not a safe autopilot primitive; allowed: "
                f"{sorted(AUTOPILOT_SAFE_ACTIONS)}"
            ),
        }
    params = {k: v for k, v in step.items() if k != "action"}
    return {"action": action, "params": params}


def plan_autopilot(steps: Any, step_budget: int = 64) -> dict:
    """Validate a whole autopilot step list against the budget. Pure.

    Returns {"steps": [normalized...], "budget": N} when every step is a safe
    primitive and the list fits the budget, else {"error": "...", "index": i}
    pinpointing the first bad step. An empty / non-list `steps` is an error.
    """
    try:
        budget = int(step_budget)
    except (TypeError, ValueError):
        return {"error": f"step_budget must be an int, got {step_budget!r}"}
    if budget < 1:
        return {"error": "step_budget must be >= 1"}
    if not isinstance(steps, (list, tuple)):
        return {"error": "steps must be a list of step dicts"}
    if not steps:
        return {"error": "steps is empty"}
    if len(steps) > budget:
        return {
            "error": f"steps ({len(steps)}) exceeds step_budget ({budget})",
        }
    normalized: list[dict] = []
    for i, raw in enumerate(steps):
        checked = validate_autopilot_step(raw)
        if checked.get("error"):
            return {"error": checked["error"], "index": i}
        normalized.append(checked)
    return {"steps": normalized, "budget": budget}


# ============================================================================
# LIVE-DEBUGGER GUARD (HARD requirement, never dbg_start)
# ============================================================================


def _require_debugger() -> Optional[dict]:
    """Return an error dict if the debugger is not on; else None.

    HARD-requires ida_dbg.is_debugger_on(). NEVER starts a debugger.
    """
    try:
        import ida_dbg
    except Exception as exc:  # pragma: no cover - only outside IDA
        return {"error": f"idapython unavailable: {exc}"}
    if not ida_dbg.is_debugger_on():
        return {
            "error": (
                "No live debugger session. This tool requires a process the "
                "maintainer already launched in IDA (F9). It will NOT call "
                "dbg_start. Start/attach a session and retry."
            )
        }
    return None


def _is_suspended() -> bool:
    import ida_dbg

    return ida_dbg.is_debugger_on() and ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP


# ============================================================================
# LIVE CAPTURE EVALUATOR (runs from inside the breakpoint condition)
# ============================================================================
#
# Pointer / register width. The target of interest (doida.exe) is 32-bit, so the
# default arg layout is 32-bit cdecl/thiscall. We still detect width from the
# inf flags where possible.


def _ptr_size() -> int:
    try:
        import ida_ida

        if hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit():
            return 8
    except Exception:
        pass
    try:
        import idaapi

        info = idaapi.get_inf_structure()
        if getattr(info, "is_64bit", lambda: False)():
            return 8
    except Exception:
        pass
    return 4


def _hw_slot_size(addr: int, size: int) -> int:
    """Largest aligned hardware-watch slot for `addr`/`size`, capped at the
    pointer width (8 on 64-bit, 4 on 32-bit). Thin wrapper over the pure
    trace.largest_aligned_slot so the alignment math stays unit-testable."""
    return _trace.largest_aligned_slot(addr, size, max_slot=_ptr_size())


def _read_reg(name: str) -> int | None:
    import ida_dbg

    try:
        rv = ida_dbg.get_reg_val(name.upper())
    except Exception:
        return None
    if isinstance(rv, int):
        return rv
    try:
        return int(rv)
    except Exception:
        return None


def _read_mem(ea: int, size: int) -> bytes | None:
    import idaapi

    try:
        data = idaapi.dbg_read_memory(ea, size)
        return bytes(data) if data else None
    except Exception:
        return None


def _read_ptr(ea: int) -> int | None:
    psize = _ptr_size()
    raw = _read_mem(ea, psize)
    if not raw or len(raw) < psize:
        return None
    return int.from_bytes(raw, "little")


def _stack_arg(index: int, conv: str = "cdecl") -> int | None:
    """Read the Nth integer argument at the callee ENTRY (return addr at [esp]).

    32-bit conventions:
      cdecl/stdcall: arg0 at [esp+4], arg1 at [esp+8], ...
      thiscall:      ecx = this, then stack args at [esp+4], [esp+8], ...
                     We expose thiscall arg0 as `this` via ecx ONLY through the
                     dedicated 'ecx' token; argN here is the STACK arg slot to
                     stay uniform with cdecl.
    """
    psize = _ptr_size()
    sp = _read_reg("rsp" if psize == 8 else "esp")
    if sp is None:
        return None
    slot = sp + psize * (index + 1)
    return _read_ptr(slot)


def _caller() -> int | None:
    """Return address at function entry == [esp] (32/64-bit)."""
    psize = _ptr_size()
    sp = _read_reg("rsp" if psize == 8 else "esp")
    if sp is None:
        return None
    return _read_ptr(sp)


def _eval_capture(plan: list[dict], conv: str = "cdecl") -> dict:
    """Evaluate a parsed capture plan against the live (suspended) thread."""
    out: dict = {}
    for token in plan:
        kind = token.get("kind")
        raw = token.get("raw", token.get("name", "?"))
        if token.get("error"):
            out[raw] = {"error": token["error"]}
            continue
        try:
            if kind == "reg":
                v = _read_reg(token["name"])
                out[raw] = hex(v) if isinstance(v, int) else None
            elif kind == "ret":
                v = _read_reg("eax" if _ptr_size() == 4 else "rax")
                out[raw] = hex(v) if isinstance(v, int) else None
            elif kind == "caller":
                v = _caller()
                out[raw] = hex(v) if isinstance(v, int) else None
            elif kind == "arg":
                v = _stack_arg(int(token["name"]), conv)
                out[raw] = hex(v) if isinstance(v, int) else None
            elif kind == "mem":
                addr = _eval_mem_expr(token["name"], conv)
                if addr is None:
                    out[raw] = None
                else:
                    data = _read_mem(addr, int(token["size"]))
                    out[raw] = {"addr": hex(addr), "hex": data.hex() if data else None}
            else:
                out[raw] = {"error": "unhandled token kind"}
        except Exception as exc:
            out[raw] = {"error": str(exc)}
    return out


def _eval_mem_expr(expr: str, conv: str = "cdecl") -> int | None:
    """Resolve a mem(...) address expression: a hex literal, a reg, argN, caller,
    or "<base>+<offset>" combinations of those."""
    s = str(expr).strip()
    total = 0
    # split on + keeping it simple (offsets are additive)
    for part in re.split(r"\+", s):
        p = part.strip()
        if not p:
            continue
        low = p.lower()
        am = _ARG_RE.match(low)
        if am:
            v = _stack_arg(int(am.group("idx")), conv)
        elif low == "caller":
            v = _caller()
        elif low == "ret":
            v = _read_reg("eax" if _ptr_size() == 4 else "rax")
        elif low in _REG_TOKENS:
            v = _read_reg(low)
        else:
            try:
                v = int(p, 0)
            except ValueError:
                return None
        if v is None:
            return None
        total += v
    return total


def _eval_watch(spec: dict) -> dict | None:
    """Change-detector for watch probes. Returns the captured dict ONLY when the
    watched field changed since the last hit; else None (suppress the record)."""
    addr = spec.get("ea")
    size = int(spec.get("watch_size", 4))
    if not isinstance(addr, int):
        return None
    data = _read_mem(addr, size)
    new_hex = data.hex() if data else None
    old_hex = spec.get("watch_last")
    if new_hex == old_hex:
        return None
    spec["watch_last"] = new_hex
    pc = _read_reg("eip" if _ptr_size() == 4 else "rip")
    return {
        "field": hex(addr),
        "old": old_hex,
        "new": new_hex,
        "writer_pc": hex(pc) if isinstance(pc, int) else None,
        "caller": (lambda c: hex(c) if isinstance(c, int) else None)(_caller()),
    }


# ============================================================================
# BREAKPOINT-CONDITION DISPATCH
# ============================================================================
#
# IDA evaluates a Python breakpoint condition in the __main__ namespace. We
# install a single dispatcher into __main__ under a fixed name; each probe's
# condition string is just a call into it with the probe_id. The dispatcher
# evaluates the capture plan, records the event, decrements the budget,
# self-disarms at the budget, and ALWAYS returns False so the process never
# stops.

_DISPATCH_GLOBAL = "_IDA_MCP_PROBE_DISPATCH"
_probe_specs: dict[str, dict] = {}
_probe_specs_lock = threading.Lock()


def _install_dispatcher() -> None:
    """Publish the dispatcher into __main__ so bpt conditions can reach it."""
    try:
        import __main__

        setattr(__main__, _DISPATCH_GLOBAL, _probe_dispatch)
    except Exception:
        pass


def _condition_text(probe_id: str) -> str:
    """The Python condition string stored on the breakpoint. Returns False so
    the breakpoint never stops; tolerant if the dispatcher is missing."""
    return (
        f"{_DISPATCH_GLOBAL}({probe_id!r}) "
        f"if '{_DISPATCH_GLOBAL}' in dir() else False"
    )


def _probe_dispatch(probe_id: str) -> bool:
    """Called from a breakpoint condition. Capture, record, budget, disarm.

    ALWAYS returns False (never stop). Any exception is swallowed and also
    returns False so a buggy probe can never halt the debuggee.
    """
    try:
        with _probe_specs_lock:
            spec = _probe_specs.get(probe_id)
        if spec is None:
            return False

        descriptor = _trace.get_probe(probe_id)
        if descriptor is not None and not descriptor.get("armed", True):
            return False

        conv = spec.get("conv", "cdecl")

        if spec.get("kind") == "watch":
            captured = _eval_watch(spec)
            if captured is None:
                return False  # no change
        else:
            # Optional Python predicate gate (string expr over captured dict).
            plan = spec.get("plan") or []
            captured = _eval_capture(plan, conv)

        predicate = spec.get("predicate")
        if predicate:
            if not _eval_predicate(predicate, captured):
                return False

        tid = None
        try:
            import ida_dbg

            tid = ida_dbg.get_current_thread()
        except Exception:
            pass

        hit_no = 0
        if descriptor is not None:
            descriptor["hits"] = descriptor.get("hits", 0) + 1
            hit_no = descriptor["hits"]

        record = build_probe_record(
            probe_id,
            spec.get("kind", "probe"),
            spec.get("ea"),
            captured,
            hit=hit_no,
            tid=tid,
        )
        _trace.record_probe_event(record)

        # Budget / self-disarm.
        max_hits = spec.get("max_hits")
        if max_hits is not None and hit_no >= max_hits:
            _disarm_probe(probe_id, spec.get("ea"))
    except Exception:
        return False
    return False


def _eval_predicate(predicate: str, captured: dict) -> bool:
    """Best-effort predicate evaluation over the captured dict. The predicate is
    a small whitelisted expression with `c` bound to the captured dict and
    `old`/`new` bound for watch probes. It is evaluated by safe_eval — a direct
    AST interpreter with NO eval/exec and no attribute access or function calls,
    so a predicate string cannot reach os/subprocess (the old emptied-builtins
    eval was not a real sandbox). Non-boolean / error -> True (don't suppress)."""
    try:
        env = {"c": captured, "old": captured.get("old"), "new": captured.get("new")}
        return bool(safe_eval(predicate, env))
    except Exception:
        return True


def _disarm_probe(probe_id: str, ea: int | None) -> None:
    try:
        import ida_dbg

        if isinstance(ea, int):
            ida_dbg.del_bpt(ea)
    except Exception:
        pass
    descriptor = _trace.get_probe(probe_id)
    if descriptor is not None:
        descriptor["armed"] = False


def _ensure_probe_session() -> None:
    """Make sure the probe ring has a session file configured."""
    if _trace._probe_state.get("session_id") is None:
        try:
            _trace.configure_probes("mcp")
        except Exception:
            pass


def _install_code_probe(
    ea: int,
    *,
    kind: str,
    plan: list[dict],
    capture_raw: list[str],
    condition: str | None,
    max_hits: int,
    conv: str = "cdecl",
    predicate: str | None = None,
    bpt_type: int | None = None,
    bpt_size: int = 0,
    probe_id: str | None = None,
) -> ProbeRef:
    """Shared installer: a non-stopping Python-condition breakpoint at ea."""
    import ida_dbg

    if probe_id is None:
        probe_id = _stable_probe_id(kind, ea, capture_raw, condition)

    _ensure_probe_session()
    _install_dispatcher()

    # Idempotency: same probe_id already registered & armed -> reuse.
    existing = _trace.get_probe(probe_id)
    reused = False
    bpt = ida_dbg.bpt_t()
    have_bpt = ida_dbg.get_bpt(ea, bpt) if bpt_type is None else False

    if existing is not None and have_bpt:
        reused = True
    else:
        if bpt_type is None:
            ok = ida_dbg.add_bpt(ea, 0, ida_dbg.BPT_SOFT)
        else:
            ok = ida_dbg.add_bpt(ea, bpt_size, bpt_type)
        if not ok and not ida_dbg.get_bpt(ea, ida_dbg.bpt_t()):
            return {"probe_id": probe_id, "ea": hex(ea), "kind": kind, "installed": False,
                    "error": "failed to add breakpoint"}

    # Configure the bpt: non-stopping, Python condition, update-memory.
    bpt = ida_dbg.bpt_t()
    if not ida_dbg.get_bpt(ea, bpt):
        return {"probe_id": probe_id, "ea": hex(ea), "kind": kind, "installed": False,
                "error": "breakpoint vanished after add"}

    try:
        bpt.elang = "Python"
    except Exception:
        setter = getattr(bpt, "set_cnd_elang", None)
        if callable(setter):
            setter("Python")

    # Clear BPT_BRK (don't break), set BPT_UPDMEM (refresh memory on hit) for
    # code probes.
    try:
        if hasattr(ida_dbg, "BPT_BRK"):
            bpt.flags &= ~ida_dbg.BPT_BRK
        if bpt_type is None and hasattr(ida_dbg, "BPT_UPDMEM"):
            bpt.flags |= ida_dbg.BPT_UPDMEM
    except Exception:
        pass

    bpt.condition = _condition_text(probe_id)
    ida_dbg.update_bpt(bpt)
    # set_bpt_cond is the reliable path for the condition + language on 9.x.
    try:
        import idc

        idc.set_bpt_cond(ea, _condition_text(probe_id), 0)
    except Exception:
        pass

    with _probe_specs_lock:
        _probe_specs[probe_id] = {
            "kind": kind,
            "ea": ea,
            "plan": plan,
            "conv": conv,
            "predicate": predicate,
            "max_hits": int(max_hits),
        }

    _trace.register_probe(
        probe_id,
        ea=hex(ea),
        kind=kind,
        condition=condition,
        max_hits=int(max_hits),
        armed=True,
        capture=list(capture_raw),
    )

    return {
        "probe_id": probe_id,
        "ea": hex(ea),
        "kind": kind,
        "capture": list(capture_raw),
        "condition": condition,
        "max_hits": int(max_hits),
        "armed": True,
        "installed": True,
        "reused": reused,
    }


# ============================================================================
# TOOLS
# ============================================================================


@ext("dbg")
@safety("EXECUTE")
@title("Install a non-stopping capture probe")
@tool
@idasync
def probe_add(
    ea: str,
    capture: list[str],
    condition: str | None = None,
    max_hits: int = 1024,
    every_nth: int = 1,
    buffer_mode: str = "circular",
) -> ProbeRef:
    """Install a non-stopping capture probe (breakpoint) at `ea`.

    The breakpoint carries a Python condition that, on each hit, evaluates the
    `capture` spec (tokens like "eax", "arg0", "ret", "caller", "mem(arg2,16)"),
    records the event into the probe ring, decrements its hit budget, and ALWAYS
    returns False so the debuggee never stops. Self-disarms (del_bpt) at
    max_hits. Idempotent on (ea, capture, condition).

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    from .utils import parse_address

    try:
        addr = parse_address(ea)
    except IDAError as exc:
        return {"error": str(exc)}

    if buffer_mode not in ("circular", "linear"):
        return {"error": f"buffer_mode must be 'circular' or 'linear', got {buffer_mode!r}"}

    plan = parse_capture_spec(capture)
    predicate = condition  # condition acts as a Python predicate gate (over `c`)

    # every_nth recorded on the spec for callers; sampling is applied via hit
    # budget semantics (the dispatcher records every hit; every_nth is advisory
    # and surfaced in the descriptor for now).
    ref = _install_code_probe(
        addr,
        kind="probe",
        plan=plan,
        capture_raw=list(capture or []),
        condition=condition,
        max_hits=max_hits,
        conv="cdecl",
        predicate=predicate,
    )
    if every_nth and every_nth > 1:
        with _probe_specs_lock:
            spec = _probe_specs.get(ref.get("probe_id", ""))
            if spec is not None:
                spec["every_nth"] = int(every_nth)
    return ref


@ext("dbg")
@safety("READ")
@title("List installed probes")
@tool
@idasync
def probe_list() -> ProbeListResult:
    """List all registered probes (id, ea, kind, hits, max_hits, armed).

    Read-only; does not require a live debugger.
    """
    return {"probes": _trace.list_probes()}


@ext("dbg")
@safety("READ")
@title("Drain captured probe records")
@tool
@idasync
def probe_drain(
    since_cursor: int = 0,
    filter: dict | None = None,
    limit: int = 512,
) -> ProbeDrainResult:
    """Drain probe-event records from the ring (oldest first, non-destructive).

    `filter` is an optional dict matched against record top-level fields, e.g.
    {"probe_id": "..."} or {"kind": "probe"}. Returns {records, cursor, dropped}
    where cursor is the next seq to pass back in since_cursor.

    Read-only.
    """
    ring = _trace.get_probe_ring()

    pred = None
    if filter:
        flt = dict(filter)

        def pred(rec: dict, _flt=flt) -> bool:
            for k, v in _flt.items():
                if rec.get(k) != v:
                    return False
            return True

    records = ring.drain(since_cursor=int(since_cursor), filter=pred, limit=int(limit))
    stats = ring.stats()
    if records:
        cursor = records[-1].get("_seq", since_cursor) + 1
    else:
        cursor = stats["next_cursor"]
    return {"records": records, "cursor": cursor, "dropped": stats["dropped"]}


@ext("dbg")
@safety("DESTRUCTIVE")
@title("Remove probes")
@tool
@idasync
def probe_clear(probe_id: str | None = None) -> ProbeClearResult:
    """Remove one probe (by probe_id) or ALL probes, deleting their breakpoints.

    Requires a live debugger session to delete the breakpoints; the registry is
    cleared regardless.
    """
    import ida_dbg

    debugger_on = False
    try:
        debugger_on = ida_dbg.is_debugger_on()
    except Exception:
        pass

    removed = 0
    targets = [probe_id] if probe_id else [p["probe_id"] for p in _trace.list_probes()]
    for pid in targets:
        descriptor = _trace.get_probe(pid)
        if descriptor is None:
            continue
        ea = descriptor.get("ea")
        if debugger_on and ea is not None:
            try:
                ida_dbg.del_bpt(int(ea, 0) if isinstance(ea, str) else ea)
            except Exception:
                pass
        if _trace.remove_probe(pid):
            removed += 1
        with _probe_specs_lock:
            _probe_specs.pop(pid, None)
    return {"removed": removed}


@ext("dbg")
@safety("EXECUTE")
@title("Run until a probe hits, an address, or timeout")
@tool
@idasync
@tool_timeout(120.0)
def run_until(
    timeout_ms: int = 10000,
    target_ea: str | None = None,
    probe_id: str | None = None,
) -> RunUntilResult:
    """Resume the debuggee and run until a probe hits, target_ea is reached, or
    the timeout elapses. Wraps _continue_and_wait.

    status in {"hit","timeout","exited","suspended"}. When probe_id is given,
    records captured by that probe during the run are returned in `buffer`.

    Requires a live (suspended) debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    if not _is_suspended():
        return {"status": "suspended", "stopped_ea": None, "elapsed_ms": 0.0,
                "hit_probe": None, "buffer": [], "error": "process not suspended"}

    from .api_debug import _continue_and_wait
    from .utils import parse_address

    ring = _trace.get_probe_ring()
    start_cursor = ring.stats()["next_cursor"]

    tea = None
    if target_ea is not None:
        try:
            tea = parse_address(target_ea)
        except IDAError as exc:
            return {"status": "timeout", "stopped_ea": None, "elapsed_ms": 0.0,
                    "hit_probe": None, "buffer": [], "error": str(exc)}

    result = _continue_and_wait(int(timeout_ms), target_ea=tea)

    # Map _continue_and_wait status -> run_until status.
    raw_status = result.get("status")
    if raw_status == "exited":
        status = "exited"
    elif raw_status == "timeout":
        status = "timeout"
    elif raw_status == "suspended":
        status = "suspended"
    else:
        status = raw_status or "timeout"

    # Pull any probe records produced during the run.
    pred = None
    if probe_id:
        def pred(rec: dict, _pid=probe_id) -> bool:
            return rec.get("probe_id") == _pid
    new_records = ring.drain(since_cursor=start_cursor, filter=pred, limit=512)

    hit_probe = None
    if new_records:
        status = "hit"
        hit_probe = new_records[-1].get("probe_id")

    return {
        "status": status,
        "stopped_ea": result.get("stopped_ea"),
        "elapsed_ms": result.get("elapsed_ms", 0.0),
        "hit_probe": hit_probe,
        "buffer": new_records,
    }


@ext("dbg")
@safety("EXECUTE")
@title("Watch a memory field for changes")
@tool
@idasync
def watch_field(
    ea: str | None = None,
    size: int = 4,
    mode: str = "write",
    base_ptr: str | None = None,
    offset: int = 0,
    predicate: str | None = None,
    max_hits: int = 512,
) -> ProbeRef:
    """Install a non-stopping data watchpoint that records ONLY on value change.

    Effective address is base_ptr+offset (else ea+offset). A hardware data
    breakpoint (BPT_WRITE / BPT_RDWR) gets a Python condition that reads the
    field, compares to the last value, and on change records
    {field,old,new,writer_pc,caller,tid} (subject to `predicate`), then returns
    False so the debuggee never stops.

    HARDWARE-SLOT / GRANULARITY LIMIT: data breakpoints use the CPU debug
    registers - only 4 slots, size must be 1/2/4 (8 on 64-bit) and naturally
    aligned. Excess/unaligned/oversized watches fail or never fire; split large
    fields into aligned sub-watches.

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    import ida_dbg
    from .utils import parse_address

    try:
        base = parse_address(base_ptr) if base_ptr is not None else (
            parse_address(ea) if ea is not None else None
        )
    except IDAError as exc:
        return {"error": str(exc)}
    if base is None:
        return {"error": "watch_field requires ea or base_ptr"}

    addr = base + int(offset)

    if size not in (1, 2, 4) and not (size == 8 and _ptr_size() == 8):
        return {"error": f"watch size must be 1/2/4 (8 on 64-bit); got {size}"}

    bpt_type = ida_dbg.BPT_RDWR if mode == "rdwr" else ida_dbg.BPT_WRITE

    probe_id = _stable_probe_id("watch", addr, [f"size{size}", mode], predicate)

    # Seed the last-value cache so the first real change is detected.
    seed = _read_mem(addr, size)
    with _probe_specs_lock:
        _probe_specs[probe_id] = {
            "kind": "watch",
            "ea": addr,
            "plan": [],
            "conv": "cdecl",
            "predicate": predicate,
            "max_hits": int(max_hits),
            "watch_size": int(size),
            "watch_last": seed.hex() if seed else None,
        }

    # Install via the shared installer but override the dispatcher path: watch
    # probes use a specialized dispatcher entry. We register the bpt then patch
    # the spec kind so _probe_dispatch routes to the change-detector.
    ref = _install_code_probe(
        addr,
        kind="watch",
        plan=[],
        capture_raw=[f"size{size}", mode],
        condition=predicate,
        max_hits=max_hits,
        conv="cdecl",
        predicate=None,
        bpt_type=bpt_type,
        bpt_size=int(size),
        probe_id=probe_id,
    )
    # Re-attach the watch-specific spec fields (the installer overwrote plan/conv
    # but we keep the watch_* keys by merging).
    with _probe_specs_lock:
        spec = _probe_specs.get(probe_id, {})
        spec.update({
            "kind": "watch",
            "watch_size": int(size),
            "watch_last": seed.hex() if seed else None,
            "predicate": predicate,
            "max_hits": int(max_hits),
        })
        _probe_specs[probe_id] = spec
    return ref


@ext("dbg")
@safety("EXECUTE")
@title("Watch a memory RANGE for changes")
@tool
@idasync
def watch_region(
    ea: str,
    size: int,
    mode: str = "write",
    predicate: str | None = None,
    max_hits: int = 512,
) -> ProbeRef:
    """Install a non-stopping hardware watchpoint over a byte RANGE.

    Unlike watch_field (which watches a single scalar field of size 1/2/4/8),
    this watches `size` consecutive bytes starting at `ea` and records ONLY when
    any byte in the range changes since the last hit. On change it records
    {field,old,new,writer_pc,caller,tid} where old/new are the FULL range hex,
    then returns False so the debuggee never stops. Self-disarms at max_hits.

    HARDWARE-SLOT / GRANULARITY LIMIT: a data watchpoint uses the CPU debug
    registers - only 4 slots, and each slot watches a naturally-aligned 1/2/4/8
    byte window. A range larger than a single slot cannot be covered by one
    hardware watch: this tool arms ONE watch sized to the largest aligned slot
    that fits (<= size, one of 8/4/2/1 on 64-bit; 4/2/1 on 32-bit) at `ea`, and
    its change-detector compares the WHOLE `size`-byte range. Writes inside the
    range but outside the armed slot may not trip the hardware; to cover a wide
    range exactly, split it into several aligned watch_region / watch_field
    calls. Excess/unaligned watches can fail or never fire.

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    import ida_dbg
    from .utils import parse_address

    try:
        addr = parse_address(ea)
    except IDAError as exc:
        return {"error": str(exc)}

    try:
        region_size = int(size)
    except (TypeError, ValueError):
        return {"error": f"size must be an int, got {size!r}"}
    if region_size < 1 or region_size > 4096:
        return {"error": f"watch_region size must be 1..4096, got {region_size}"}

    slot_size = _hw_slot_size(addr, region_size)

    bpt_type = ida_dbg.BPT_RDWR if mode == "rdwr" else ida_dbg.BPT_WRITE

    probe_id = _stable_probe_id("watchr", addr, [f"size{region_size}", mode], predicate)

    seed = _read_mem(addr, region_size)
    with _probe_specs_lock:
        _probe_specs[probe_id] = {
            "kind": "watch",
            "ea": addr,
            "plan": [],
            "conv": "cdecl",
            "predicate": predicate,
            "max_hits": int(max_hits),
            "watch_size": region_size,
            "watch_last": seed.hex() if seed else None,
        }

    ref = _install_code_probe(
        addr,
        kind="watch_region",
        plan=[],
        capture_raw=[f"size{region_size}", mode],
        condition=predicate,
        max_hits=max_hits,
        conv="cdecl",
        predicate=None,
        bpt_type=bpt_type,
        bpt_size=int(slot_size),
        probe_id=probe_id,
    )
    with _probe_specs_lock:
        spec = _probe_specs.get(probe_id, {})
        spec.update({
            "kind": "watch",
            "watch_size": region_size,
            "watch_last": seed.hex() if seed else None,
            "predicate": predicate,
            "max_hits": int(max_hits),
        })
        _probe_specs[probe_id] = spec
    if isinstance(ref, dict):
        ref["capture"] = [f"region({hex(addr)},{region_size}) hw_slot={slot_size}"]
    return ref


@ext("dbg")
@safety("EXECUTE")
@title("Trace calls with args and return value")
@tool
@idasync
def trace_calls(
    ea: str,
    conv: str = "thiscall",
    argc: int = 4,
    capture_ret: bool = True,
    max_hits: int = 2048,
    auto_return: bool = True,
) -> ProbeRef:
    """Install paired entry+return probes that trace a function's calls.

    The ENTRY probe captures the callee ea, the caller (return address at
    [esp]), and N args per the calling convention (32-bit __thiscall/__cdecl/
    __stdcall): thiscall exposes `ecx` (this) plus stack args arg0..; cdecl/
    stdcall expose arg0.. on the stack. If capture_ret, a paired RETURN-site
    probe at [esp] captures eax and a call depth.

    auto_return (default True): the entry probe ALSO captures `caller` (the
    return address, == the call's return site). When it first fires, drain the
    entry probe and read the `caller` value: that address is exactly where to
    place a probe_add(<caller>, ["ret"]) to capture eax at return. The return
    record tells you the paired return-site EA without stopping the process
    (this is non-stopping-safe - the entry probe never halts the debuggee, and
    nothing is auto-installed). auto_return=False suppresses that guidance and
    keeps the legacy capture list.

    Returns the ENTRY ProbeRef (its probe_id is the handle for drain/clear).

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    from .utils import parse_address

    try:
        addr = parse_address(ea)
    except IDAError as exc:
        return {"error": str(exc)}

    conv = (conv or "thiscall").lower()
    capture: list[str] = ["caller"]
    if conv == "thiscall":
        capture.append("ecx")
    for i in range(max(0, int(argc))):
        capture.append(f"arg{i}")

    plan = parse_capture_spec(capture)
    ref = _install_code_probe(
        addr,
        kind="trace_call_entry",
        plan=plan,
        capture_raw=capture,
        condition=None,
        max_hits=max_hits,
        conv=conv,
    )

    # The return-site probe is best-effort: at entry the dispatcher cannot easily
    # install a one-shot return bpt without stopping, so capture_ret records eax
    # at the caller's return address (the instruction after the call) when that
    # site is known. We attach a companion probe at the caller return address on
    # first hit is not feasible non-stop; instead we record eax via a second
    # probe the caller can place. Here we annotate the entry ref with the intent.
    if capture_ret:
        if auto_return:
            ref["capture"] = capture + [
                "auto_return: on first entry hit, drain this probe and read its "
                "`caller` value; that EA is the call return-site - place a "
                "probe_add(<caller>, ['ret']) there to capture eax at return "
                "(non-stopping; nothing is auto-installed)"
            ]
        else:
            ref["capture"] = capture + ["ret@return-site (place a probe_add(ret) at the call's return address)"]
    return ref


def _resolve_import_ea(name: str) -> dict:
    """Resolve an imported API `name` to a probe-able address.

    Tries, in order: a direct named address (get_name_ea_all / get_name_ea), then
    the import-module enumeration (the IAT entry, i.e. the thunk slot holding the
    resolved pointer). Returns {"func_ea": int|None, "iat_ea": int|None,
    "via": str} - func_ea is where to set the entry breakpoint; iat_ea is the IAT
    thunk slot when only that was found. On total failure returns
    {"error": "..."}. Best-effort and IDA-version tolerant.
    """
    target = str(name).strip()
    if not target:
        return {"error": "empty API name"}

    func_ea: int | None = None
    via = "name"
    try:
        import idc

        BADADDR = getattr(idc, "BADADDR", 0xFFFFFFFFFFFFFFFF)
        ea = idc.get_name_ea_simple(target)
        if ea is not None and ea != BADADDR:
            func_ea = int(ea)
    except Exception:
        pass

    iat_ea: int | None = None
    if func_ea is None:
        try:
            import idaapi

            found: dict = {}

            def _imp_cb(ea, imp_name, ordinal, _found=found, _t=target):
                if imp_name and imp_name == _t:
                    _found["ea"] = int(ea)
                    return False  # stop
                if imp_name and _t in imp_name:
                    _found.setdefault("loose", int(ea))
                return True

            qty = idaapi.get_import_module_qty()
            for i in range(qty):
                idaapi.enum_import_names(i, _imp_cb)
                if "ea" in found:
                    break
            if "ea" in found:
                iat_ea = found["ea"]
                via = "iat"
            elif "loose" in found:
                iat_ea = found["loose"]
                via = "iat_loose"
        except Exception:
            pass

    if func_ea is None and iat_ea is None:
        return {"error": f"could not resolve import {target!r} to an address"}

    return {"func_ea": func_ea, "iat_ea": iat_ea, "via": via}


@ext("dbg")
@safety("EXECUTE")
@title("Probe an imported API by name")
@tool
@idasync
def probe_api_call(
    name: str,
    capture: list[str] | None = None,
    max_hits: int = 512,
) -> ProbeRef:
    """Resolve an imported API by `name` and install a non-stopping capturing
    probe at it.

    Resolves `name` to a probe-able address (a direct named function EA when the
    import is a real code stub, else the IAT thunk slot that holds the resolved
    pointer), then installs a probe_add-style non-stopping breakpoint there. When
    `capture` is omitted, a sensible default is used: the caller (return address)
    plus the first four stack args by 32-bit cdecl/stdcall convention
    ("caller","arg0".."arg3"). The probe records each hit and ALWAYS returns
    False so the debuggee never stops; it self-disarms at max_hits.

    NOTE: if resolution lands on the IAT thunk slot rather than a code stub, the
    breakpoint sits on the indirect-call target slot; the captured args still
    follow the stack convention at the call. Pass an explicit `capture` to tune.

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    resolved = _resolve_import_ea(name)
    if resolved.get("error"):
        return {"error": resolved["error"]}

    addr = resolved.get("func_ea")
    if addr is None:
        addr = resolved.get("iat_ea")
    if addr is None:
        return {"error": f"could not resolve import {name!r} to an address"}

    cap = list(capture) if capture else ["caller", "arg0", "arg1", "arg2", "arg3"]
    plan = parse_capture_spec(cap)

    ref = _install_code_probe(
        int(addr),
        kind="api_call",
        plan=plan,
        capture_raw=cap,
        condition=None,
        max_hits=max_hits,
        conv="cdecl",
    )
    if isinstance(ref, dict):
        ref["api"] = name
        ref["resolved_via"] = resolved.get("via")
    return ref


@ext("dbg")
@safety("READ")
@title("Read a typed struct from live memory")
@tool
@idasync
def read_struct_live(ea: str, type_name: str) -> ReadStructLiveResult:
    """Read sizeof(type_name) bytes from live memory at `ea` and overlay the IDB
    type into a named-field dict.

    `ea` may be a plain address, or a pointer-chain expression like
    "[[base+0x10]+0x8]" which is dereferenced live before the struct is read.

    Requires a live debugger session.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    import ida_typeinf
    from .utils import parse_address

    # Resolve ea, supporting pointer-chain expressions.
    raw_ea = str(ea).strip()
    try:
        if raw_ea.startswith("["):
            addr = _resolve_ptr_chain(raw_ea)
            if addr is None:
                return {"error": f"failed to resolve pointer chain {raw_ea!r}"}
        else:
            addr = parse_address(raw_ea)
    except IDAError as exc:
        return {"error": str(exc)}
    except ValueError as exc:
        return {"error": f"bad pointer-chain expression: {exc}"}

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, type_name):
        # try parsing as a type decl
        if not _parse_named_type(tif, type_name):
            return {"error": f"type {type_name!r} not found"}

    total = tif.get_size()
    if not total or total <= 0 or total > 1 << 20:
        return {"error": f"type {type_name!r} has unusable size {total}"}

    raw = _read_mem(addr, total)
    if raw is None:
        return {"error": f"failed to read {total} bytes at {hex(addr)}"}

    fields = _overlay_type(tif, raw)
    return {
        "fields": fields,
        "raw_hex": raw.hex(),
        "_meta": {"ea": hex(addr), "type": type_name, "size": total, "dirty": True},
    }


def _parse_named_type(tif, type_name: str) -> bool:
    import ida_typeinf

    try:
        decl = type_name if type_name.strip().endswith(";") else type_name + ";"
        return ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None
    except Exception:
        return False


def _overlay_type(tif, raw: bytes) -> dict:
    """Overlay an IDB struct type onto raw bytes -> {field: value}."""
    import ida_typeinf

    fields: dict = {}
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        # scalar
        return {"value": raw.hex()}
    for member in udt:
        off = member.begin() // 8
        msize = member.type.get_size()
        chunk = raw[off:off + msize] if msize else b""
        name = member.name or f"field_{off:x}"
        if msize in (1, 2, 4, 8) and not member.type.is_float():
            val = int.from_bytes(chunk, "little") if chunk else 0
            fields[name] = {"offset": hex(off), "value": hex(val), "size": msize}
        else:
            fields[name] = {"offset": hex(off), "hex": chunk.hex(), "size": msize}
    return fields


def _resolve_ptr_chain(expr: str) -> int | None:
    """Apply a parsed pointer-chain (parse_ptr_chain ops) against live memory."""
    from .utils import parse_address

    ops = parse_ptr_chain(expr)
    acc: int | None = None
    for op in ops:
        kind = op["op"]
        if kind == "base":
            acc = int(op["value"])
        elif kind == "base_name":
            try:
                acc = parse_address(op["value"])
            except Exception:
                return None
        elif kind == "add":
            if acc is None:
                return None
            acc += int(op["value"])
        elif kind == "deref":
            if acc is None:
                return None
            acc = _read_ptr(acc)
            if acc is None:
                return None
    return acc


@ext("dbg")
@safety("EXECUTE")
@title("Appcall a function in the debuggee")
@tool
@idasync
def appcall(
    ea: str,
    prototype: str,
    args: list,
    confirm: bool = False,
) -> AppcallResult:
    """Resolve+marshal (and optionally CALL) a function in the live debuggee.

    confirm=False (default): resolve the prototype and marshal the args, and
    REPORT the resolved proto + marshalled args WITHOUT calling anything.
    confirm=True: requires a SUSPENDED process, then performs
    idaapi.Appcall.proto(ea, prototype)(*args) and returns the result.

    Appcall executes code in the target. NEVER use this inside any automated /
    looping flow - it is a deliberate, single, human-confirmed action only.

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    import idaapi
    from .utils import parse_address

    try:
        addr = parse_address(ea)
    except IDAError as exc:
        return {"error": str(exc)}

    resolved = f"{prototype} @ {hex(addr)}"
    meta = {"ea": hex(addr), "dirty": True}

    if not confirm:
        return {
            "dry_run": True,
            "resolved_proto": resolved,
            "marshalled_args": list(args) if args else [],
            "ret": None,
            "exception": None,
            "_meta": meta,
        }

    if not _is_suspended():
        return {
            "dry_run": False,
            "resolved_proto": resolved,
            "marshalled_args": list(args) if args else [],
            "ret": None,
            "exception": "process must be SUSPENDED to appcall",
            "_meta": meta,
            "error": "process not suspended",
        }

    try:
        fn = idaapi.Appcall.proto(addr, prototype)
        ret = fn(*(args or []))
        try:
            ret_repr = int(ret)
        except Exception:
            ret_repr = repr(ret)
        return {
            "dry_run": False,
            "resolved_proto": resolved,
            "marshalled_args": list(args) if args else [],
            "ret": ret_repr,
            "exception": None,
            "_meta": meta,
        }
    except Exception as exc:
        return {
            "dry_run": False,
            "resolved_proto": resolved,
            "marshalled_args": list(args) if args else [],
            "ret": None,
            "exception": str(exc),
            "_meta": meta,
        }


@ext("dbg")
@safety("READ")
@title("Inspect an appcall prototype")
@tool
@idasync
def appcall_inspect(ea: str, prototype: str) -> AppcallInspectResult:
    """Resolve an appcall prototype and report its parsed arg/return types
    WITHOUT calling anything.

    Read-only companion to `appcall`. Requires a live debugger session only to
    resolve against the target image.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    import ida_typeinf
    from .utils import parse_address

    try:
        addr = parse_address(ea)
    except IDAError as exc:
        return {"error": str(exc)}

    tif = ida_typeinf.tinfo_t()
    arg_types: list[str] = []
    ret_type: str | None = None
    try:
        decl = prototype if prototype.strip().endswith(";") else prototype + ";"
        if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None:
            ftd = ida_typeinf.func_type_data_t()
            if tif.get_func_details(ftd):
                ret_type = ftd.rettype._print()
                for a in ftd:
                    arg_types.append(a.type._print())
    except Exception:
        pass

    return {
        "resolved_proto": f"{prototype} @ {hex(addr)}",
        "arg_types": arg_types,
        "ret_type": ret_type,
        "_meta": {"ea": hex(addr), "dirty": True},
    }


@ext("dbg")
@safety("EXECUTE")
@title("Install recv/decrypt/send buffer probes")
@tool
@idasync
def probe_net(
    recv_ea: str | None = None,
    decrypt_ea: str | None = None,
    send_ea: str | None = None,
    buf_arg: str = "arg1",
    len_arg: str = "arg2",
    pre_post: bool = True,
) -> ProbeNetResult:
    """Convenience: install buffer-capturing probes at the supplied recv /
    decrypt / send addresses.

    Addresses are CALLER-SUPPLIED (doida.exe-specific) and NOT hardcoded. Each
    given address gets a probe_add capturing the buffer pointer + length and a
    memory slice of the buffer. When pre_post is set, decrypt_ea gets a second
    capture intent so the caller can compare the buffer before/after the
    transform (place a paired probe at the decrypt return site).

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    installed: list[ProbeRef] = []

    # Capture the length and a generous slice of the buffer keyed off buf_arg.
    # mem(arg1+0,256) reads up to 256 bytes from the buffer pointer arg.
    cap_common = [buf_arg, len_arg, f"mem({buf_arg},256)"]

    def _one(addr_str, kind):
        from .utils import parse_address
        try:
            addr = parse_address(addr_str)
        except IDAError as exc:
            return {"error": str(exc), "kind": kind}
        plan = parse_capture_spec(cap_common)
        return _install_code_probe(
            addr,
            kind=kind,
            plan=plan,
            capture_raw=list(cap_common),
            condition=None,
            max_hits=4096,
            conv="cdecl",
        )

    if recv_ea is not None:
        installed.append(_one(recv_ea, "net_recv"))
    if decrypt_ea is not None:
        installed.append(_one(decrypt_ea, "net_decrypt_pre"))
        if pre_post:
            # second intent marker for the post-transform read at the return site
            ref = installed[-1]
            ref.setdefault("capture", list(cap_common)).append(
                "pre/post: place probe_add at decrypt return site capturing mem(%s,256)" % buf_arg
            )
    if send_ea is not None:
        installed.append(_one(send_ea, "net_send"))

    if not installed:
        return {"installed": [], "error": "supply at least one of recv_ea/decrypt_ea/send_ea"}
    return {"installed": installed}


# ============================================================================
# LIVE MEMORY SCAN (read-only)
# ============================================================================


def _live_memory_ranges() -> list[tuple[int, int]]:
    """Enumerate mapped [start,end) ranges of the live debuggee.

    Best-effort over the IDA debugger memory-info API; coalesced via the pure
    trace.merge_ranges so the scan walks disjoint, ordered windows.
    """
    raw: list[tuple[int, int]] = []
    try:
        import ida_dbg
        import ida_idd

        meminfo = ida_idd.meminfo_vec_t()
        if ida_dbg.get_memory_info(meminfo):
            for region in meminfo:
                try:
                    start = int(region.start_ea)
                    end = int(region.end_ea)
                except Exception:
                    continue
                if end > start:
                    raw.append((start, end))
    except Exception:
        pass
    return _trace.merge_ranges(raw)


_SCAN_CHUNK = 1 << 16  # read mapped memory in 64 KiB chunks


@ext("dbg")
@safety("READ")
@title("Scan live debuggee memory for a byte pattern")
@tool
@idasync
@tool_timeout(120.0)
def memory_scan(
    pattern_hex: str,
    start: str | None = None,
    end: str | None = None,
    limit: int = 64,
) -> MemoryScanResult:
    """Scan LIVE debuggee memory for a byte pattern (with wildcards).

    `pattern_hex` is a hex byte pattern where "??" (or a single "?") is a
    wildcard byte, e.g. "8b ?? 56 ff 15" or "8b??56ff15". The scan walks the
    debuggee's mapped ranges (optionally clamped to [start,end)), reading them in
    chunks and matching the pattern; it returns up to `limit` absolute hit
    addresses. READ-ONLY: it reads live memory and installs NOTHING.

    Requires a live debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    try:
        pattern = _trace.parse_byte_pattern(pattern_hex)
    except ValueError as exc:
        return {"error": str(exc)}

    plen = len(pattern)
    if plen == 0:
        return {"error": "empty byte pattern"}

    try:
        _, mask = _trace.pattern_to_mask(pattern)
    except ValueError as exc:
        return {"error": str(exc)}

    from .utils import parse_address

    want_start = None
    want_end = None
    try:
        if start is not None:
            want_start = parse_address(start)
        if end is not None:
            want_end = parse_address(end)
    except IDAError as exc:
        return {"error": str(exc)}

    try:
        cap = int(limit)
    except (TypeError, ValueError):
        cap = 64
    if cap < 1:
        cap = 1

    ranges = _live_memory_ranges()
    if not ranges:
        return {"error": "no mapped memory ranges from the live debugger"}

    hits: list[int] = []
    scanned = 0
    truncated = False
    overlap = plen - 1  # carry to catch matches spanning a chunk boundary

    for seg_start, seg_end in ranges:
        window = _trace.clamp_scan_window(seg_start, seg_end, want_start, want_end)
        if window is None:
            continue
        lo, hi = window
        scanned += 1
        pos = lo
        while pos < hi:
            chunk_end = min(pos + _SCAN_CHUNK, hi)
            read_len = chunk_end - pos
            # extend by overlap to catch boundary-spanning matches (bounded by hi)
            read_len_ext = min(read_len + overlap, hi - pos)
            data = _read_mem(pos, read_len_ext)
            if data:
                local = _trace.find_pattern_in_buffer(data, pattern, base=pos, limit=cap - len(hits))
                for h in local:
                    # avoid double-counting a hit that begins in the overlap tail
                    # of one chunk and the head of the next
                    if h < chunk_end and h not in hits:
                        hits.append(h)
                        if len(hits) >= cap:
                            truncated = True
                            break
            if len(hits) >= cap:
                break
            pos = chunk_end
        if len(hits) >= cap:
            break

    return {
        "pattern": str(pattern_hex),
        "pattern_len": plen,
        "mask": mask,
        "hits": [hex(h) for h in hits],
        "scanned_ranges": scanned,
        "truncated": truncated,
    }


# ============================================================================
# SNAPSHOT (best-effort, NOT full process state)
# ============================================================================

_snapshots: dict[str, dict] = {}
_snapshots_lock = threading.Lock()


def _process_identity() -> dict:
    """Best-effort identity of the live debuggee, used to detect a relaunch
    between snapshot save and restore. None of these signals is guaranteed across
    IDA builds, so we capture whatever is available and only compare keys that
    BOTH sides actually have."""
    ident: dict = {}
    try:
        import idaapi

        base = idaapi.get_imagebase()
        if isinstance(base, int):
            ident["base"] = base
    except Exception:
        pass
    try:
        import ida_dbg

        get_pi = getattr(ida_dbg, "get_process_info", None)
        if callable(get_pi):
            pi = get_pi()
            pid = getattr(pi, "pid", None)
            if isinstance(pid, int):
                ident["pid"] = pid
    except Exception:
        pass
    return ident


def _identity_mismatch(saved: dict, current: dict) -> list[str]:
    """Human-readable differences across identity keys present in BOTH dicts."""
    diffs: list[str] = []
    for key in ("pid", "base"):
        if key in saved and key in current and saved[key] != current[key]:
            diffs.append(f"{key} changed (saved {saved[key]!r} -> now {current[key]!r})")
    return diffs


@ext("dbg")
@safety("EXECUTE")
@title("Save a best-effort register+memory snapshot")
@tool
@idasync
def snapshot_save(name: str, ranges: list[dict] | None = None) -> SnapshotResult:
    """Save GP registers and a bounded set of memory ranges, keyed by `name`.

    `ranges` is an optional list of {"addr","size"} regions to capture via
    read_dbg_memory. Stored IN-PROCESS only.

    BEST-EFFORT: this captures only the named registers and the explicitly given
    memory ranges - it is NOT a full process snapshot (no full address space,
    no kernel/handle/thread state). restore() writes those bytes and registers
    back; anything not captured is unchanged.

    Requires a SUSPENDED debugger session; never calls dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]
    if not _is_suspended():
        return {"name": name, "error": "process must be SUSPENDED to snapshot"}

    import ida_dbg
    from .utils import parse_address

    reg_names = [
        "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP",
    ]
    regs: dict = {}
    for rn in reg_names:
        try:
            v = ida_dbg.get_reg_val(rn)
            if isinstance(v, int):
                regs[rn] = v
        except Exception:
            continue

    captured_ranges: list[dict] = []
    for region in (ranges or []):
        try:
            addr = parse_address(region["addr"])
            size = int(region["size"])
        except Exception:
            continue
        data = _read_mem(addr, size)
        if data is not None:
            captured_ranges.append({"addr": addr, "hex": data.hex()})

    identity = _process_identity()
    with _snapshots_lock:
        _snapshots[name] = {
            "regs": regs,
            "ranges": captured_ranges,
            "identity": identity,
        }

    return {
        "name": name,
        "regs": {k: hex(v) for k, v in regs.items()},
        "ranges": [{"addr": hex(r["addr"]), "size": len(r["hex"]) // 2} for r in captured_ranges],
        "identity": {k: (hex(v) if isinstance(v, int) else v) for k, v in identity.items()},
    }


@ext("dbg")
@safety("EXECUTE")
@title("Restore a best-effort register+memory snapshot")
@tool
@idasync
def snapshot_restore(name: str) -> SnapshotResult:
    """Restore the registers + memory ranges saved under `name`.

    BEST-EFFORT: writes back only the captured registers and ranges; this is NOT
    a full process restore. Requires a SUSPENDED debugger session; never calls
    dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]
    if not _is_suspended():
        return {"name": name, "error": "process must be SUSPENDED to restore"}

    import ida_dbg
    import idaapi

    with _snapshots_lock:
        snap = _snapshots.get(name)
    if snap is None:
        return {"name": name, "error": f"no snapshot named {name!r}"}

    # Refuse to restore into a different process than the one snapshotted: the
    # captured addresses/registers would land in the wrong place and can crash
    # the debuggee. Never write blind (axis-7 safety).
    saved_identity = snap.get("identity", {}) or {}
    mismatch = _identity_mismatch(saved_identity, _process_identity())
    if mismatch:
        return {
            "name": name,
            "restored": False,
            "error": (
                "process identity changed since snapshot ("
                + "; ".join(mismatch)
                + ") - refusing to restore into a different / relaunched process"
            ),
        }

    restored_ranges = 0
    failed_ranges = 0
    for region in snap["ranges"]:
        try:
            data = bytes.fromhex(region["hex"])
            wrote = idaapi.dbg_write_memory(region["addr"], data)
            # dbg_write_memory returns the byte count (or True/falsy on some
            # builds); a short or zero write is a failure, not a success.
            if wrote is True or (isinstance(wrote, int) and wrote >= len(data)):
                restored_ranges += 1
            else:
                failed_ranges += 1
        except Exception:
            failed_ranges += 1

    restored_regs = 0
    failed_regs = 0
    for rn, val in snap["regs"].items():
        try:
            if ida_dbg.set_reg_val(rn, val):
                restored_regs += 1
            else:
                failed_regs += 1
        except Exception:
            failed_regs += 1

    partial = bool(failed_ranges or failed_regs)
    result: dict = {
        "name": name,
        "restored": not partial,
        "partial": partial,
        "restored_regs": restored_regs,
        "failed_regs": failed_regs,
        "restored_ranges": restored_ranges,
        "failed_ranges": failed_ranges,
        "regs": {k: hex(v) for k, v in snap["regs"].items()},
        "ranges": [{"addr": hex(r["addr"]), "size": len(r["hex"]) // 2} for r in snap["ranges"]],
    }
    if partial:
        result["warning"] = (
            f"partial restore: {failed_regs} register(s) and {failed_ranges} "
            "range(s) failed to write"
        )
    return result


@ext("dbg")
@safety("READ")
@title("List in-process snapshots")
@tool
@idasync
def snapshot_list() -> SnapshotListResult:
    """List the in-process snapshots saved by snapshot_save.

    Returns each snapshot's name plus its register count and the number/size of
    captured memory ranges (metadata only, never the captured bytes). Read-only;
    does not require a live debugger.
    """
    out: list[dict] = []
    with _snapshots_lock:
        for nm, snap in _snapshots.items():
            ranges = snap.get("ranges", []) or []
            out.append({
                "name": nm,
                "regs": len(snap.get("regs", {}) or {}),
                "ranges": len(ranges),
                "bytes": sum(len(r.get("hex", "")) // 2 for r in ranges),
            })
    return {"snapshots": out}


@ext("dbg")
@safety("DESTRUCTIVE")
@title("Delete an in-process snapshot")
@tool
@idasync
def snapshot_delete(name: str) -> SnapshotDeleteResult:
    """Delete the in-process snapshot saved under `name`.

    Removes the named snapshot from the in-process store (it never touched the
    debuggee, so nothing in the target changes). Returns {name, deleted} where
    deleted is False if no such snapshot existed. Does not require a live
    debugger.
    """
    with _snapshots_lock:
        existed = _snapshots.pop(name, None) is not None
    if not existed:
        return {"name": name, "deleted": False, "error": f"no snapshot named {name!r}"}
    return {"name": name, "deleted": True}


# ============================================================================
# SUMMARY / DIFF / ARM / AUTOPILOT TOOLS
# ============================================================================


@ext("dbg")
@safety("READ")
@title("Probe + ring health summary")
@tool
@idasync
def probe_stats() -> ProbeStatsResult:
    """Read-only health summary of the probe toolkit.

    Reports the armed/total probe counts, the ring stats (cap/size/dropped) with
    a fill percentage, and a per-probe hit-count breakdown (id, ea, kind, hits,
    max_hits, armed). Collapses "is anything firing / am I dropping records" into
    one call. Read-only; does not require a live debugger.
    """
    probes = _trace.list_probes()
    ring = _trace.get_probe_ring()
    return _trace.aggregate_probe_stats(probes, ring.stats())  # type: ignore[return-value]


@ext("dbg")
@safety("READ")
@title("Summarize captured probe records")
@tool
@idasync
def trace_summary(
    group_by: str = "func",
    filter: dict | None = None,
    since_cursor: int = 0,
    limit: int = 4096,
) -> TraceSummaryResult:
    """Roll up captured probe records into a per-group breakdown (read-only).

    Reads (non-destructively) from the probe ring and returns
    trace.summarize_records(...) grouped by `group_by` (one of
    "probe_id","func","caller","tid","pc"). `filter` is an optional dict matched
    against record top-level fields (e.g. {"probe_id": "..."}). This collapses
    10^5 hits into one rollup so an agent reasons over the call tree instead of
    streaming every record.

    Read-only; does not require a live debugger.
    """
    ring = _trace.get_probe_ring()

    pred = None
    if filter:
        flt = dict(filter)

        def pred(rec: dict, _flt=flt) -> bool:
            for k, v in _flt.items():
                if rec.get(k) != v:
                    return False
            return True

    records = ring.drain(since_cursor=int(since_cursor), filter=pred, limit=int(limit))
    try:
        summary = _trace.summarize_records(records, group_by=group_by)
    except ValueError as exc:
        return {"error": str(exc)}
    summary["drained"] = len(records)
    return summary  # type: ignore[return-value]


@ext("dbg")
@safety("READ")
@title("Byte-diff two captured buffers")
@tool
@idasync
def diff_buffers(a_hex: str, b_hex: str) -> BufferDiffResult:
    """Byte-diff two captured hex buffers (the crypto pre/post comparison).

    Thin tool surface over trace.diff_buffers: returns
    {len_a,len_b,changed_offsets,first_diff,equal}. A length mismatch counts the
    trailing offsets as changed; non-hex input yields an `error` with equal=False.
    Pure observation of already-captured bytes - read-only, no live debugger.
    """
    return _trace.diff_buffers(a_hex, b_hex)  # type: ignore[return-value]


@ext("dbg")
@safety("DESTRUCTIVE")
@title("Arm or disarm a probe")
@tool
@idasync
def probe_arm(probe_id: str, armed: bool = True) -> ProbeRef:
    """Toggle a probe on/off WITHOUT removing it (enable/disable its bpt).

    Flips the probe descriptor's `armed` flag and enables/disables the
    underlying breakpoint (ida_dbg.enable_bpt). The probe, its spec, and its
    captured records are preserved, so probe_arm(id, True) re-arms it later.
    The dispatcher also honors `armed` so a disabled probe records nothing even
    if its bpt momentarily fires.

    Requires a live debugger session to touch the breakpoint; never calls
    dbg_start.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    descriptor = _trace.get_probe(probe_id)
    if descriptor is None:
        return {"probe_id": probe_id, "error": f"no probe {probe_id!r}"}

    ea = descriptor.get("ea")
    addr = None
    if ea is not None:
        try:
            addr = int(ea, 0) if isinstance(ea, str) else int(ea)
        except (TypeError, ValueError):
            addr = None

    armed = bool(armed)
    if addr is not None:
        try:
            import ida_dbg

            if hasattr(ida_dbg, "enable_bpt"):
                ida_dbg.enable_bpt(addr, armed)
        except Exception:
            pass

    descriptor["armed"] = armed
    with _probe_specs_lock:
        spec = _probe_specs.get(probe_id)
        if spec is not None:
            spec["armed"] = armed

    return {
        "probe_id": probe_id,
        "ea": ea if isinstance(ea, str) else (hex(addr) if isinstance(addr, int) else None),
        "kind": descriptor.get("kind"),
        "max_hits": descriptor.get("max_hits"),
        "armed": armed,
        "installed": True,
    }


@ext("dbg")
@safety("EXECUTE")
@title("Sequence safe pilot primitives (autopilot)")
@tool
@idasync
@tool_timeout(300.0)
def autopilot_run(steps: list[dict], step_budget: int = 64) -> AutopilotResult:
    """Sequence ONLY safe pilot primitives up to step_budget, stopping on the
    first unexpected state.

    Each step is a dict {"action": ...}. Allowed actions are resume/observe/
    drain primitives ONLY: "continue", "run_until" (target_ea/probe_id/
    timeout_ms), "read_regs", "read_memory" (ea,size), "probe_drain"
    (since_cursor/filter/limit). It MUST NOT install patches or call appcall as
    a step - any such action is rejected at plan time before the loop runs.

    The loop stops early (stopped_reason) on: a forbidden/invalid step, the
    process exiting, a continue/run_until that times out without suspending, a
    primitive error, the budget, or an interrupt - probe_clear() acts as the
    interrupt by removing the probes a run_until step waits on. Returns
    {transcript, stopped_reason, steps_run}.

    Requires a live (suspended) debugger session; never calls dbg_start, never
    patches, never appcalls.
    """
    guard = _require_debugger()
    if guard:
        return guard  # type: ignore[return-value]

    plan = plan_autopilot(steps, step_budget)
    if plan.get("error"):
        return {
            "transcript": [],
            "stopped_reason": "invalid_plan",
            "steps_run": 0,
            "error": plan["error"],
        }

    from .api_debug import _continue_and_wait
    from .utils import parse_address

    transcript: list[dict] = []
    stopped_reason = "completed"
    steps_run = 0

    for step in plan["steps"]:
        action = step["action"]
        params = step["params"]
        entry: dict = {"action": action}

        if not _is_suspended():
            entry["error"] = "process not suspended"
            transcript.append(entry)
            stopped_reason = "not_suspended"
            break

        if action in ("continue", "run_until"):
            timeout_ms = int(params.get("timeout_ms", 10000))
            tea = None
            if action == "run_until" and params.get("target_ea") is not None:
                try:
                    tea = parse_address(str(params["target_ea"]))
                except IDAError as exc:
                    entry["error"] = str(exc)
                    transcript.append(entry)
                    stopped_reason = "bad_target"
                    break

            ring = _trace.get_probe_ring()
            start_cursor = ring.stats()["next_cursor"]
            result = _continue_and_wait(timeout_ms, target_ea=tea)
            raw_status = result.get("status")
            entry["status"] = raw_status
            entry["stopped_ea"] = result.get("stopped_ea")
            entry["elapsed_ms"] = result.get("elapsed_ms", 0.0)

            probe_id = params.get("probe_id")
            pred = None
            if probe_id:
                def pred(rec: dict, _pid=probe_id) -> bool:
                    return rec.get("probe_id") == _pid
            new_records = ring.drain(since_cursor=start_cursor, filter=pred, limit=512)
            entry["hits"] = len(new_records)
            if new_records:
                entry["hit_probe"] = new_records[-1].get("probe_id")

            steps_run += 1
            transcript.append(entry)

            if raw_status == "exited":
                stopped_reason = "process_exited"
                break
            if raw_status in ("timeout", "failed_to_resume", "not_running"):
                stopped_reason = f"unexpected_{raw_status}"
                break

        elif action == "read_regs":
            regs: dict = {}
            for rn in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP",
                       "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP"):
                v = _read_reg(rn)
                if isinstance(v, int):
                    regs[rn.lower()] = hex(v)
            entry["regs"] = regs
            steps_run += 1
            transcript.append(entry)

        elif action == "read_memory":
            try:
                addr = parse_address(str(params["ea"]))
            except (KeyError, IDAError) as exc:
                entry["error"] = f"read_memory needs a valid 'ea': {exc}"
                transcript.append(entry)
                stopped_reason = "primitive_error"
                break
            size = int(params.get("size", 16))
            if size < 0 or size > 4096:
                entry["error"] = "size out of range (0..4096)"
                transcript.append(entry)
                stopped_reason = "primitive_error"
                break
            data = _read_mem(addr, size)
            entry["ea"] = hex(addr)
            entry["hex"] = data.hex() if data else None
            steps_run += 1
            transcript.append(entry)

        elif action == "probe_drain":
            ring = _trace.get_probe_ring()
            flt = params.get("filter")
            pred = None
            if flt:
                fdict = dict(flt)

                def pred(rec: dict, _f=fdict) -> bool:
                    for k, v in _f.items():
                        if rec.get(k) != v:
                            return False
                    return True
            recs = ring.drain(
                since_cursor=int(params.get("since_cursor", 0)),
                filter=pred,
                limit=int(params.get("limit", 512)),
            )
            entry["records"] = recs
            entry["count"] = len(recs)
            steps_run += 1
            transcript.append(entry)

    if steps_run >= plan["budget"] and stopped_reason == "completed":
        stopped_reason = "budget_reached"

    return {
        "transcript": transcript,
        "stopped_reason": stopped_reason,
        "steps_run": steps_run,
    }


__all__ = [
    # pure helpers
    "parse_capture_spec",
    "build_probe_record",
    "parse_ptr_chain",
    "validate_autopilot_step",
    "plan_autopilot",
    "AUTOPILOT_SAFE_ACTIONS",
    "AUTOPILOT_FORBIDDEN_ACTIONS",
    # tools
    "probe_add",
    "probe_list",
    "probe_drain",
    "probe_clear",
    "run_until",
    "watch_field",
    "watch_region",
    "probe_api_call",
    "trace_calls",
    "read_struct_live",
    "appcall",
    "appcall_inspect",
    "probe_net",
    "memory_scan",
    "snapshot_save",
    "snapshot_restore",
    "snapshot_list",
    "snapshot_delete",
    "trace_summary",
    "diff_buffers",
    "probe_stats",
    "probe_arm",
    "autopilot_run",
]
