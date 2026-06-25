"""SEAM helpers shared by the debugger / probe toolkit.

This module is the PURE, IDA-free SEAM between live-debugger glue (api_debug.py,
api_probes.py) and the unit-testable logic that decides WHERE an argument lives,
WHAT a pointer points at, and HOW two captured snapshots differ. The valuable
reasoning lives here as argument-driven functions (readers are INJECTED), so the
headless idalib test runner -- which cannot launch a live process -- can exercise
every calling-convention / classification / diff path with plain fakes.

Layering:
- PURE (no idaapi at module top): detect_abi / int_arg_location / resolve_int_arg
  (ABI tables), classify_pointer (region lookup), diff_snapshots (snapshot delta),
  and CallPairing (entry<->return matching). None of these import IDA; they take
  small inputs and return plain dicts.
- LIVE: enumerate_memory_regions() is the ONLY function that touches IDA, and it
  imports ida_dbg / ida_idd LAZILY inside the body. It refactors the region walk
  behind api_probes._live_memory_ranges into the richer
  {start,end,perm,module,kind} shape that classify_pointer consumes, so memory_map
  and pointer classification share one enumerator.

Calling-convention reference (integer / pointer arguments only), implemented by
int_arg_location below. At the callee ENTRY the return address sits at [SP]:
- x86 cdecl / stdcall / thiscall: all stack args follow the retaddr.
    arg i (0-based) -> [SP + 4 + i*4]. thiscall additionally passes `this` in ECX
    (exposed via the dedicated 'ecx' token, not as a numbered arg here, to stay
    uniform with cdecl -- matching api_probes._stack_arg).
- Win64 (ms x64): integer args 0..3 -> RCX, RDX, R8, R9; arg i>=4 -> stack at
    [RSP + 0x28 + (i-4)*8] (8 retaddr + 0x20 shadow space the caller reserved).
- SysV AMD64 (linux / mac): integer args 0..5 -> RDI, RSI, RDX, RCX, R8, R9;
    arg i>=6 -> stack at [RSP + 8 + (i-6)*8] (no shadow space).
- Return value: EAX (x86) / RAX (x64).
"""

from typing import Any, Callable, Optional


# ============================================================================
# PURE: ABI / argument resolution
# ============================================================================

# Integer/pointer argument register order per convention (index -> reg name).
# cdecl has NO register args (everything spills to the stack at entry).
_REG_ARGS: dict[str, list[str]] = {
    "cdecl": [],
    "win64": ["rcx", "rdx", "r8", "r9"],
    "sysv": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
}

# Per-convention stack geometry at callee ENTRY (SP points at the retaddr):
#   first_stack_index : the 0-based arg index that is the FIRST one on the stack
#   base_disp         : bytes from SP to that first stack arg's slot
#   slot              : bytes per stack slot
# So stack arg i (i >= first_stack_index) sits at
#   SP + base_disp + (i - first_stack_index) * slot.
_STACK_GEOM: dict[str, dict[str, int]] = {
    # cdecl/stdcall/thiscall: arg0 at [esp+4], 4-byte slots.
    "cdecl": {"first_stack_index": 0, "base_disp": 4, "slot": 4},
    # win64: args 0..3 in regs; arg4 at [rsp+0x28] (8 retaddr + 0x20 shadow).
    "win64": {"first_stack_index": 4, "base_disp": 0x28, "slot": 8},
    # sysv: args 0..5 in regs; arg6 at [rsp+8] (no shadow space).
    "sysv": {"first_stack_index": 6, "base_disp": 8, "slot": 8},
}

# Return-value register per pointer width.
_RET_REG = {4: "eax", 8: "rax"}


def detect_abi(ptr_size: int, is_windows: bool) -> str:
    """Pick the integer-arg calling convention from pointer width + OS. Pure.

    WHAT: 32-bit (ptr_size==4) -> "cdecl" (the uniform stack layout shared by
    cdecl/stdcall/thiscall stack args). 64-bit (ptr_size==8) -> "win64" when
    is_windows else "sysv" (System V AMD64, used on linux/mac).
    WHEN-TO-USE: A live tool reads ptr width + target OS once, calls this, and
    threads the result into int_arg_location / resolve_int_arg.
    RETURNS: One of "cdecl" | "win64" | "sysv".
    PITFALL: This is the INTEGER/pointer-arg ABI only -- floating-point args use
    a different register file (XMM) not modelled here.
    """
    if int(ptr_size) == 8:
        return "win64" if is_windows else "sysv"
    return "cdecl"


def int_arg_location(index: int, conv: str) -> dict:
    """Where integer arg `index` lives at callee ENTRY under `conv`. Pure.

    WHAT: Returns either {"kind":"reg","reg":<name>} when the arg is passed in a
    register, or {"kind":"stack","disp":<bytes_from_sp_at_entry>} when it is on
    the stack (disp is measured from SP at the instant of entry, where [SP] is the
    return address). Uses the cdecl / win64 / sysv tables documented at module top.
    WHEN-TO-USE: To plan a single argument read without touching the process;
    resolve_int_arg layers the injected readers on top of this.
    RETURNS: dict with kind=="reg" (+reg) or kind=="stack" (+disp), or
    {"error":...} for a negative index / unknown convention.
    PITFALL: `disp` for stack args already accounts for the retaddr slot (and the
    win64 shadow space); add it directly to SP-at-entry, do not add 4/8 again.
    """
    try:
        idx = int(index)
    except (TypeError, ValueError):
        return {"error": f"index must be an int, got {index!r}"}
    if idx < 0:
        return {"error": f"arg index must be >= 0, got {idx}"}
    conv = str(conv).strip().lower()
    if conv not in _STACK_GEOM:
        return {"error": f"unknown calling convention {conv!r}"}

    reg_args = _REG_ARGS[conv]
    if idx < len(reg_args):
        return {"kind": "reg", "reg": reg_args[idx]}

    geom = _STACK_GEOM[conv]
    disp = geom["base_disp"] + (idx - geom["first_stack_index"]) * geom["slot"]
    return {"kind": "stack", "disp": disp}


def resolve_int_arg(
    index: int,
    conv: str,
    *,
    read_reg: Callable[[str], Optional[int]],
    read_stack_at_sp_disp: Callable[[int], Optional[int]],
) -> Optional[int]:
    """Resolve integer arg `index` to a value via INJECTED readers. Pure.

    WHAT: Looks up int_arg_location(index, conv); for a register arg it calls
    read_reg(<name>), for a stack arg it calls read_stack_at_sp_disp(<disp>) where
    disp is the byte offset from SP-at-entry. The readers are injected so this is
    unit-testable headless with fakes (a dict-backed read_reg, a list-backed
    stack reader); live callers pass thin lambdas over ida_dbg.
    WHEN-TO-USE: The single entry point a live wrapper uses to read one arg after
    detecting the ABI.
    RETURNS: The integer value, or None if the location is unknown/erroring or the
    injected reader returns None.
    PRO-TIP: read_stack_at_sp_disp receives the FULL displacement from SP (already
    includes retaddr + any shadow space) -- it should read a pointer-sized word at
    SP+disp.
    """
    loc = int_arg_location(index, conv)
    if loc.get("error"):
        return None
    if loc.get("kind") == "reg":
        return read_reg(loc["reg"])
    if loc.get("kind") == "stack":
        return read_stack_at_sp_disp(loc["disp"])
    return None


# ============================================================================
# PURE: pointer / memory classification
# ============================================================================


def classify_pointer(addr: int, regions: list[dict]) -> dict:
    """Classify `addr` against an enumerated region list. Pure.

    WHAT: Finds the region (each {start,end,perm,module,kind}) whose
    [start,end) contains `addr` and reports where the pointer lands. `kind` is
    taken from the matched region when present, else inferred: a region named
    like a stack/heap maps to "stack"/"heap", a module-backed region to "image",
    any other mapped region to "mapped"; no match -> "unmapped".
    WHEN-TO-USE: Turn a raw register/arg value into a human-meaningful location
    (which module/segment, what permissions, offset within the region) without a
    live read -- the region list comes from enumerate_memory_regions().
    RETURNS: {region, module, perm, offset_in_region, kind} where kind is one of
    "image"|"stack"|"heap"|"mapped"|"unmapped". For unmapped addresses module/
    perm/region are None and offset_in_region is None.
    PITFALL: If regions overlap, the FIRST containing region (input order) wins;
    pass a coalesced/ordered list for deterministic results.
    """
    try:
        a = int(addr)
    except (TypeError, ValueError):
        return {
            "region": None, "module": None, "perm": None,
            "offset_in_region": None, "kind": "unmapped",
        }

    for region in regions or []:
        try:
            start = int(region.get("start"))
            end = int(region.get("end"))
        except (TypeError, ValueError):
            continue
        if start <= a < end:
            module = region.get("module")
            kind = region.get("kind") or _infer_region_kind(region)
            return {
                "region": [start, end],
                "module": module,
                "perm": region.get("perm"),
                "offset_in_region": a - start,
                "kind": kind,
            }

    return {
        "region": None, "module": None, "perm": None,
        "offset_in_region": None, "kind": "unmapped",
    }


def _infer_region_kind(region: dict) -> str:
    """Infer a coarse region kind from its name/module when not pre-tagged."""
    name = str(region.get("module") or region.get("name") or "").lower()
    if "stack" in name:
        return "stack"
    if "heap" in name:
        return "heap"
    if region.get("module"):
        return "image"
    return "mapped"


# ============================================================================
# PURE: snapshot diff
# ============================================================================


def diff_snapshots(a: dict, b: dict) -> dict:
    """Diff two captured debugger snapshots. Pure.

    WHAT: Compares snapshot `a` (the BEFORE) against `b` (the AFTER). A snapshot
    is {"regs": {name: value}, "ranges": [{"addr": <int|hex-str>, "hex": <hexstr>}]}.
    Registers present in both with differing values yield {name, old, new};
    same-addr ranges whose hex differs yield, for each differing byte, {addr,
    offset, old, new} (old/new are the single-byte hex pair). Byte-level diffing
    pinpoints exactly which bytes moved between snapshots.
    WHEN-TO-USE: After capturing two snapshots around an operation (e.g. before/
    after a step or appcall) to report exactly which registers and which bytes of
    which watched ranges changed -- entirely offline, no live read.
    RETURNS: {"regs": [{name, old, new}], "ranges": [{addr, offset, old, new}]}.
    Registers only in one snapshot, and ranges with mismatched/odd-length hex, are
    skipped rather than raising.
    PITFALL: Range entries are paired by their `addr` key, not list position; an
    addr present in only one snapshot is ignored.
    """
    out_regs: list[dict] = []
    out_ranges: list[dict] = []

    regs_a = (a or {}).get("regs") or {}
    regs_b = (b or {}).get("regs") or {}
    for name, old in regs_a.items():
        if name in regs_b:
            new = regs_b[name]
            if old != new:
                out_regs.append({"name": name, "old": old, "new": new})

    by_addr_a = _index_ranges_by_addr((a or {}).get("ranges") or [])
    by_addr_b = _index_ranges_by_addr((b or {}).get("ranges") or [])
    for addr, hex_a in by_addr_a.items():
        if addr not in by_addr_b:
            continue
        hex_b = by_addr_b[addr]
        out_ranges.extend(_diff_hex(addr, hex_a, hex_b))

    return {"regs": out_regs, "ranges": out_ranges}


def _index_ranges_by_addr(ranges: list[dict]) -> dict:
    """Index a snapshot's range list by its normalized integer addr -> hex str."""
    out: dict[int, Optional[str]] = {}
    for entry in ranges:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("addr")
        try:
            if isinstance(raw, str):
                addr = int(raw, 0)
            else:
                addr = int(raw)
        except (TypeError, ValueError):
            continue
        out[addr] = entry.get("hex")
    return out


def _diff_hex(addr: int, hex_a: Optional[str], hex_b: Optional[str]) -> list[dict]:
    """Per-byte diff of two equal-length hex strings -> list of byte deltas."""
    if not isinstance(hex_a, str) or not isinstance(hex_b, str):
        return []
    if len(hex_a) != len(hex_b) or len(hex_a) % 2 != 0:
        return []
    out: list[dict] = []
    for i in range(0, len(hex_a), 2):
        ba = hex_a[i:i + 2]
        bb = hex_b[i:i + 2]
        if ba.lower() != bb.lower():
            out.append({"addr": addr + i // 2, "offset": i // 2, "old": ba, "new": bb})
    return out


# ============================================================================
# PURE: entry <-> return pairing
# ============================================================================


class CallPairing:
    """Match function-entry events to their later return events. Pure.

    Keyed by (tid, sp_at_entry): at a callee's entry the stack pointer is unique
    per in-flight invocation on a thread, so it identifies that frame until the
    matching return (when SP has been restored to the same value). record_entry()
    stashes an entry payload; match_return() consumes it and joins the two into a
    single record. No IDA -- this is a plain data structure exercised headless.
    """

    def __init__(self) -> None:
        self._pending: dict[tuple, dict] = {}

    @staticmethod
    def _key(tid: Any, sp_at_entry: Any) -> tuple:
        return (tid, int(sp_at_entry))

    def record_entry(self, tid: Any, sp_at_entry: int, payload: dict) -> tuple:
        """Record an entry event; returns the (tid, sp) key it was stored under.

        A later entry with the SAME key (e.g. unbalanced recursion / a missed
        return) overwrites the pending entry -- last-in wins so we always pair the
        innermost outstanding frame.
        """
        key = self._key(tid, sp_at_entry)
        self._pending[key] = dict(payload or {})
        return key

    def match_return(self, tid: Any, sp_at_return: int, payload: dict) -> Optional[dict]:
        """Match a return event to its pending entry; returns the joined record.

        The return SP must equal the entry SP (the frame is identified by the SP
        value at entry, which the epilogue restores). On a hit the pending entry
        is consumed (popped) and a joined record is returned; on no match returns
        None so unbalanced returns are simply ignored.
        """
        key = self._key(tid, sp_at_return)
        entry = self._pending.pop(key, None)
        if entry is None:
            return None
        return {
            "tid": tid,
            "sp": int(sp_at_return),
            "entry": entry,
            "return": dict(payload or {}),
        }

    def pending_count(self) -> int:
        """Number of entries still awaiting a matching return."""
        return len(self._pending)

    def drop(self, tid: Any, sp_at_entry: int) -> bool:
        """Discard a pending entry (e.g. on probe teardown). Returns True if one
        was removed."""
        return self._pending.pop(self._key(tid, sp_at_entry), None) is not None


# ============================================================================
# LIVE: memory-region enumerator (lazy IDA import inside the body)
# ============================================================================


def enumerate_memory_regions() -> list[dict]:
    """Enumerate the live debuggee's mapped regions in classify_pointer shape.

    WHAT: Walks ida_dbg.get_memory_info() and returns one dict per mapped region:
    {start, end, perm, module, kind}. `perm` is the SEGPERM-style "rwx" string
    (missing bits shown as "-"); `module` is the owning module basename when the
    region carries a name; `kind` is "image" for module-backed regions, "stack"/
    "heap" for regions whose name says so, else "mapped". This is the richer
    refactor of api_probes._live_memory_ranges, sharing one region walk with
    classify_pointer and memory_map.
    WHEN-TO-USE: As the live input to classify_pointer, and to back a memory_map
    tool. The result is plain data, so the classification logic stays headless-
    testable.
    RETURNS: list of {start,end,perm,module,kind}; empty list if no debugger / no
    info (never raises).
    PITFALL: Only meaningful with a live session; addresses/permissions reflect
    the process at the moment of the call.
    """
    out: list[dict] = []
    try:
        import os
        import ida_dbg
        import ida_idd
    except Exception:  # pragma: no cover - only outside IDA
        return out

    try:
        meminfo = ida_idd.meminfo_vec_t()
        if not ida_dbg.get_memory_info(meminfo):
            return out
    except Exception:
        return out

    for region in meminfo:
        try:
            start = int(region.start_ea)
            end = int(region.end_ea)
        except Exception:
            continue
        if end <= start:
            continue

        name = ""
        try:
            name = str(getattr(region, "name", "") or "")
        except Exception:
            name = ""
        module = os.path.basename(name) if name else None

        perm = _perm_to_str(getattr(region, "perm", None))

        out.append({
            "start": start,
            "end": end,
            "perm": perm,
            "module": module,
            "kind": _infer_region_kind({"module": module, "name": name}),
        })
    return out


def _perm_to_str(perm: Any) -> Optional[str]:
    """Render an ida_idd SEGPERM bitmask as an "rwx" string ("-" for absent)."""
    if perm is None:
        return None
    try:
        bits = int(perm)
    except (TypeError, ValueError):
        return None
    # ida_idd SEGPERM_EXEC=1, SEGPERM_WRITE=2, SEGPERM_READ=4.
    r = "r" if bits & 4 else "-"
    w = "w" if bits & 2 else "-"
    x = "x" if bits & 1 else "-"
    return r + w + x
