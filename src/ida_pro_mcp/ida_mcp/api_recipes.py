"""High-level composite, read-only static-analysis recipes.

Each tool here chains several low-level capabilities (decompile, xrefs, callers,
callees, strings, imports, switch tables, instruction scanning) into a single
one-shot report that an LLM can consume without orchestrating five separate
calls. Nothing in here mutates the IDB.

The IDA-touching work is delegated to the shared helpers in ``utils`` and the
sibling ``api_composite`` module wherever a clean helper already exists; only
the parsing/aggregation/ranking logic is implemented locally, and that logic is
kept in idaapi-free pure functions (``_rank_candidates``, ``_merge_report``,
``_score_crypto_loop`` ...) so it can be unit-tested headless.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any, TypedDict

from ._kernel.rpc import safety, title, tool
from ._kernel.sync import idasync, tool_timeout, IDAError
from ._kernel.utils import (
    parse_address,
    get_prototype,
    get_callees,
    get_callers,
    decompile_function_safe,
    extract_function_strings,
)
from .api_composite import (
    _resolve_addr,
    _cap_decompile,
    _compact_strings,
    _compact_callees,
)

# Default head cap for pseudocode in the function dossier.
_PSEUDOCODE_HEAD_LINES = 60
# Default number of crypto candidates returned.
_DEFAULT_CRYPTO_TOP = 20
# Default minimum case count for a construct to count as a "dispatcher".
_DEFAULT_DISPATCH_MIN_CASES = 8
# Cap on the number of string matches walked in recipe_string_to_code.
_MAX_STRING_MATCHES = 200
# Cap on enclosing-function fan-out per matched string / call site.
_MAX_ENCLOSING = 500


# ---------------------------------------------------------------------------
# TypedDict results
# ---------------------------------------------------------------------------


class FunctionReport(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    pseudocode_head: str | None
    pseudocode_truncated: int
    decompile_error: str | None
    callers: list[str]
    callees: list[str]
    strings: list[str]
    xref_count: int
    error: str


class StringSite(TypedDict, total=False):
    string_addr: str
    string: str
    ref_addr: str
    func_addr: str | None
    func_name: str | None


class StringToCodeResult(TypedDict, total=False):
    query: str
    match_count: int
    sites: list[StringSite]
    functions: list[str]
    error: str


class ImportSite(TypedDict, total=False):
    call_addr: str
    func_addr: str | None
    func_name: str | None


class ImportUsageResult(TypedDict, total=False):
    name: str
    import_addr: str | None
    call_site_count: int
    sites: list[ImportSite]
    functions: list[str]
    error: str


class DispatchCandidate(TypedDict, total=False):
    addr: str
    func_addr: str | None
    func_name: str | None
    case_count: int
    kind: str


class DispatchScanResult(TypedDict, total=False):
    min_cases: int
    candidate_count: int
    candidates: list[DispatchCandidate]
    error: str


class CryptoCandidate(TypedDict, total=False):
    addr: str
    name: str
    score: int
    ops: list[str]
    loop_count: int
    reasons: list[str]


class CryptoCandidatesResult(TypedDict, total=False):
    top: int
    candidate_count: int
    candidates: list[CryptoCandidate]
    error: str


# ---------------------------------------------------------------------------
# Pure helpers (idaapi-free -- unit-testable headless)
# ---------------------------------------------------------------------------

# Mnemonics that look like a crypto inner loop when they operate on a buffer.
_CRYPTO_BITOPS = frozenset({"xor", "rol", "ror", "shl", "shr", "sar", "not", "rcl", "rcr"})
# A pure xor of a register with itself (`xor eax, eax`) is just a zero idiom, not
# crypto; the caller is responsible for filtering those before scoring, but we
# also discount when ops are dominated by it.


def _rank_candidates(
    candidates: list[dict[str, Any]],
    *,
    score_key: str = "score",
    top: int | None = None,
) -> list[dict[str, Any]]:
    """Sort *candidates* by their ``score_key`` descending and return the top N.

    Pure: takes and returns plain dicts so it can be exercised without IDA. Ties
    are broken by the ``addr`` field (lexical) so the order is deterministic.
    Items missing the score key sort as score 0. ``top`` of None or <=0 returns
    all of them.
    """
    def _key(item: dict[str, Any]) -> tuple[int, str]:
        raw = item.get(score_key, 0)
        score = raw if isinstance(raw, int) else 0
        return (score, str(item.get("addr", "")))

    ordered = sorted(candidates, key=_key, reverse=True)
    if top is not None and top > 0:
        return ordered[:top]
    return ordered


def _merge_report(*parts: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge several partial report dicts into one.

    Later parts override earlier ones for scalar keys; lists with the same key
    are concatenated (preserving order, de-duplicating while keeping first-seen
    order); None values never overwrite an already-present value. Pure and
    side-effect free so report assembly can be unit-tested.
    """
    out: dict[str, Any] = {}
    for part in parts:
        if not part:
            continue
        for key, value in part.items():
            if value is None and key in out:
                continue
            if isinstance(value, list) and isinstance(out.get(key), list):
                merged = list(out[key])
                seen = set()
                for item in merged:
                    try:
                        seen.add(item)
                    except TypeError:
                        pass
                for item in value:
                    try:
                        if item in seen:
                            continue
                        seen.add(item)
                    except TypeError:
                        pass
                    merged.append(item)
                out[key] = merged
            else:
                out[key] = value
    return out


def _dedup_preserve(values: list[Any]) -> list[Any]:
    """Return *values* with duplicates removed, first occurrence kept. Pure."""
    seen: set = set()
    out: list[Any] = []
    for v in values:
        try:
            if v in seen:
                continue
            seen.add(v)
        except TypeError:
            pass
        out.append(v)
    return out


def _score_crypto_loop(ops: list[str], loop_count: int) -> tuple[int, list[str]]:
    """Score a function's crypto-likeness from its bit-op mnemonics + loop count.

    Pure heuristic over already-extracted mnemonics (lower-cased) and the number
    of detected loops/back-edges. Returns (score, reasons). Neutral: a high score
    means "looks crypto-shaped", never "is crypto".

    Heuristic:
      * +3 per distinct bit-op family present (xor/rol/ror/shl/...),
      * +2 if a rotate (rol/ror/rcl/rcr) is present (rotates are a strong tell),
      * +2 if at least one loop is present (tight transform over a buffer),
      * +1 per additional loop beyond the first, capped,
      * a function with only a single `xor` and no loop scores 0.
    """
    lowered = [o.lower() for o in ops]
    present = {o for o in lowered if o in _CRYPTO_BITOPS}
    reasons: list[str] = []
    score = 0

    if not present:
        return 0, reasons

    distinct = len(present)
    score += 3 * distinct
    reasons.append(f"{distinct} distinct bit-op families: {sorted(present)}")

    if present & {"rol", "ror", "rcl", "rcr"}:
        score += 2
        reasons.append("rotate present")

    if loop_count >= 1:
        score += 2
        reasons.append(f"{loop_count} loop(s)")
        score += min(loop_count - 1, 3)
    else:
        # No loop at all: a lone bit-op is rarely a cipher.
        if distinct <= 1:
            return 0, ["single bit-op, no loop"]
        reasons.append("no loop detected (weak)")

    return score, reasons


def _classify_dispatch(case_count: int, min_cases: int) -> str:
    """Classify a switch construct by size. Pure."""
    if case_count >= max(min_cases * 4, 32):
        return "large_dispatcher"
    if case_count >= min_cases:
        return "dispatcher"
    return "small_switch"


# ---------------------------------------------------------------------------
# Tool 1 -- recipe_function_report
# ---------------------------------------------------------------------------


@safety("READ")
@title("Function First-Look Dossier")
@tool
@idasync
@tool_timeout(120.0)
def recipe_function_report(
    ea: Annotated[str, "Function address (hex like '0x401000') or symbol name to profile"],
    pseudocode_lines: Annotated[int, "How many leading pseudocode lines to include; clamped to 1..400 (default 60)"] = _PSEUDOCODE_HEAD_LINES,
) -> FunctionReport:
    """WHAT: One call that returns a complete first-look dossier on a single
    function -- its name, recovered prototype/signature, the head of its
    decompiled pseudocode, its callers and callees, the strings it references, and
    a total cross-reference count -- by chaining the individual decompile / proto
    / callers / callees / strings / xref capabilities into one response.

    WHEN TO USE: As the very first call when you land on an unknown function and
    want the whole picture cheaply, before deciding whether to read it in full.
    Prefer this over issuing the five underlying calls yourself; the pseudocode is
    head-capped (default 60 lines) to stay token-cheap.

    RETURNS: FunctionReport with addr, name, prototype, pseudocode_head
    (pseudocode_truncated holds the true total line count when capped),
    decompile_error if Hex-Rays could not decompile it, callers and callees
    (names only), strings (deduped values), and xref_count (number of code/data
    references pointing AT this function). On bad input only addr+error are set.

    PRO-TIP: A high xref_count with a tiny body usually means a hot utility
    (allocator, logger, string helper) -- skip reading it. PITFALL: if
    decompile_error is present the function could not be decompiled; the
    name/prototype/callers/callees/strings fields are still populated from
    disassembly-level data, so the dossier is still useful."""

    import idaapi
    import idautils

    try:
        func_ea = _resolve_addr(ea)
    except IDAError as exc:
        return {"addr": ea, "error": str(exc)}

    func = idaapi.get_func(func_ea)
    if func is None:
        return {"addr": hex(func_ea), "error": f"No function at {hex(func_ea)}"}

    start = func.start_ea

    if pseudocode_lines < 1:
        pseudocode_lines = 1
    if pseudocode_lines > 400:
        pseudocode_lines = 400

    report: FunctionReport = {
        "addr": hex(start),
        "name": idaapi.get_func_name(start) or "",
        "prototype": get_prototype(func),
    }

    raw_code, decompile_err = decompile_function_safe(start)
    if raw_code is None:
        report["pseudocode_head"] = None
        if decompile_err:
            report["decompile_error"] = decompile_err
    else:
        lines = raw_code.split("\n")
        total = len(lines)
        if total > pseudocode_lines:
            report["pseudocode_head"] = "\n".join(lines[:pseudocode_lines])
            report["pseudocode_truncated"] = total
        else:
            report["pseudocode_head"] = raw_code

    report["callers"] = _compact_callees(get_callers(hex(start)))
    report["callees"] = _compact_callees(get_callees(hex(start)))
    report["strings"] = _compact_strings(extract_function_strings(start))

    xref_count = 0
    for _ in idautils.XrefsTo(start, 0):
        xref_count += 1
    report["xref_count"] = xref_count

    return report


# ---------------------------------------------------------------------------
# Tool 2 -- recipe_string_to_code
# ---------------------------------------------------------------------------


@safety("READ")
@title("Find Code That Uses A String")
@tool
@idasync
@tool_timeout(120.0)
def recipe_string_to_code(
    text: Annotated[str, "Substring to search for inside the binary's string literals (case-sensitive)"],
    max_matches: Annotated[int, "Cap on the number of matching strings to walk; clamped to 1..200 (default 50)"] = 50,
) -> StringToCodeResult:
    """WHAT: Answer "where is this message produced?" in one call. Finds every
    string literal containing *text*, follows each one's cross-references back to
    the code that uses it, and resolves the enclosing function of each reference --
    so a user-visible message, log line, or format string becomes a short list of
    the functions that emit it.

    WHEN TO USE: When you have a piece of on-screen / logged / protocol text and
    want to jump straight to the code that produces it, without manually listing
    strings then chasing xrefs then mapping each to its function.

    RETURNS: StringToCodeResult with query, match_count (number of matching
    string literals), sites (per-reference: string_addr, string, ref_addr,
    func_addr, func_name), and functions (the deduped list of enclosing function
    addresses -- your shortlist). On bad input only error is set.

    PRO-TIP: Make *text* as specific as possible (a distinctive word from the
    message) -- a common substring matches hundreds of strings and the walk gets
    capped. PITFALL: a string with NO xrefs produces no sites (it may be reached
    via a computed pointer, or be dead data); and a reference outside any defined
    function yields func_addr=None. Matching is a plain case-sensitive substring,
    not a regex."""

    import idaapi
    import idautils
    import idc

    if not text:
        return {"error": "text must be a non-empty substring"}

    if max_matches < 1:
        max_matches = 1
    if max_matches > _MAX_STRING_MATCHES:
        max_matches = _MAX_STRING_MATCHES

    matched_strings: list[tuple[int, str]] = []
    qty = idaapi.get_strlist_qty()
    for i in range(qty):
        if len(matched_strings) >= max_matches:
            break
        si = idaapi.string_info_t()
        if not idaapi.get_strlist_item(si, i):
            continue
        raw = idc.get_strlit_contents(si.ea, -1, 0)
        if not raw:
            continue
        try:
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        if text in decoded:
            matched_strings.append((si.ea, decoded))

    sites: list[StringSite] = []
    func_addrs: list[str] = []
    for str_ea, decoded in matched_strings:
        for xref in idautils.XrefsTo(str_ea, 0):
            if len(sites) >= _MAX_ENCLOSING:
                break
            ref_ea = xref.frm
            func = idaapi.get_func(ref_ea)
            func_addr = hex(func.start_ea) if func else None
            func_name = idaapi.get_func_name(func.start_ea) if func else None
            sites.append({
                "string_addr": hex(str_ea),
                "string": decoded,
                "ref_addr": hex(ref_ea),
                "func_addr": func_addr,
                "func_name": func_name,
            })
            if func_addr is not None:
                func_addrs.append(func_addr)

    return {
        "query": text,
        "match_count": len(matched_strings),
        "sites": sites,
        "functions": _dedup_preserve(func_addrs),
    }


# ---------------------------------------------------------------------------
# Tool 3 -- recipe_import_usage
# ---------------------------------------------------------------------------


@safety("READ")
@title("Map An Imported API's Usage")
@tool
@idasync
@tool_timeout(120.0)
def recipe_import_usage(
    name: Annotated[str, "Imported API name to resolve, e.g. 'recv', 'CreateFileA', 'malloc'"],
) -> ImportUsageResult:
    """WHAT: Build a usage map for a single imported API. Resolves *name* to the
    import thunk / IAT entry, finds every call site that reaches it, and resolves
    each call site's enclosing function -- one call instead of "list imports" then
    "xrefs to the import" then "function at each xref".

    WHEN TO USE: When you want to know who in the binary calls a particular OS /
    CRT / library function (e.g. every caller of recv to find the network read
    path, or every caller of a decrypt/alloc routine). The functions list is the
    fast lead into the subsystem that depends on that API.

    RETURNS: ImportUsageResult with name, import_addr (the resolved import EA, or
    None if it could not be resolved by name), call_site_count, sites (per call:
    call_addr, func_addr, func_name) and functions (the deduped enclosing-function
    addresses). On bad input only name+error are set; an unknown name returns a
    clean empty result with import_addr=None rather than an error.

    PRO-TIP: If the result is empty, try the decorated form the linker actually
    used (e.g. 'recv' vs '__imp_recv', 'CreateFileA' vs 'CreateFile') -- name
    resolution is exact. PITFALL: APIs reached only through a vtable or a
    runtime-resolved pointer (GetProcAddress) will show few or no direct call
    sites; the static xref view cannot see those indirect dispatches."""

    import idaapi
    import idautils

    if not name:
        return {"name": name, "error": "name must be a non-empty import name"}

    import_ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if import_ea == idaapi.BADADDR:
        return {
            "name": name,
            "import_addr": None,
            "call_site_count": 0,
            "sites": [],
            "functions": [],
        }

    sites: list[ImportSite] = []
    func_addrs: list[str] = []
    for xref in idautils.XrefsTo(import_ea, 0):
        if len(sites) >= _MAX_ENCLOSING:
            break
        ref_ea = xref.frm
        func = idaapi.get_func(ref_ea)
        func_addr = hex(func.start_ea) if func else None
        func_name = idaapi.get_func_name(func.start_ea) if func else None
        sites.append({
            "call_addr": hex(ref_ea),
            "func_addr": func_addr,
            "func_name": func_name,
        })
        if func_addr is not None:
            func_addrs.append(func_addr)

    return {
        "name": name,
        "import_addr": hex(import_ea),
        "call_site_count": len(sites),
        "sites": sites,
        "functions": _dedup_preserve(func_addrs),
    }


# ---------------------------------------------------------------------------
# Tool 4 -- recipe_dispatch_scan
# ---------------------------------------------------------------------------


@safety("READ")
@title("Find Opcode/Command Dispatchers")
@tool
@idasync
@tool_timeout(300.0)
def recipe_dispatch_scan(
    min_cases: Annotated[int, "Minimum number of switch cases for a construct to count as a candidate dispatcher; clamped to 2..1024 (default 8)"] = _DEFAULT_DISPATCH_MIN_CASES,
) -> DispatchScanResult:
    """WHAT: Scan the whole database for large switch / jump-table constructs --
    the classic shape of an opcode or command dispatcher -- and rank them by
    approximate case count. Uses IDA's recovered switch metadata for every
    instruction that drives a switch, so you don't have to eyeball every indirect
    jmp by hand.

    WHEN TO USE: As the opening move when hunting a packet/opcode dispatcher,
    a command router, or a state machine: run this, take the top candidates, then
    decompile each to read the case-to-handler mapping.

    RETURNS: DispatchScanResult with min_cases (the threshold used),
    candidate_count, and candidates ranked by case_count descending. Each
    candidate has addr (the switch/indirect-jump instruction), func_addr +
    func_name (the enclosing function), case_count (approximate number of cases),
    and kind ('large_dispatcher' / 'dispatcher' / 'small_switch'). On failure only
    error is set.

    PRO-TIP: The single largest case_count is very often the main message
    dispatcher; start there. PITFALL: case_count is the size IDA recovered for the
    jump table -- compiler-collapsed sparse tables (an index byte table feeding a
    smaller jump table) can under-report the true opcode range, and a dispatch
    built as an if/else chain or a function-pointer array has NO switch metadata
    and will not appear here at all."""

    import idaapi
    import idautils
    import ida_nalt

    if min_cases < 2:
        min_cases = 2
    if min_cases > 1024:
        min_cases = 1024

    raw_candidates: list[dict[str, Any]] = []
    seen: set[int] = set()

    try:
        for func_ea in idautils.Functions():
            func = idaapi.get_func(func_ea)
            if func is None:
                continue
            for head in idautils.Heads(func.start_ea, func.end_ea):
                si = idaapi.get_switch_info(head)
                if si is None:
                    continue
                try:
                    case_count = int(si.get_jtable_size())
                except Exception:
                    try:
                        case_count = int(si.ncases)
                    except Exception:
                        case_count = 0
                if case_count < min_cases:
                    continue
                if head in seen:
                    continue
                seen.add(head)
                raw_candidates.append({
                    "addr": hex(head),
                    "func_addr": hex(func.start_ea),
                    "func_name": idaapi.get_func_name(func.start_ea) or "",
                    "case_count": case_count,
                    "score": case_count,
                    "kind": _classify_dispatch(case_count, min_cases),
                })
    except Exception as exc:
        return {"error": f"dispatch scan failed: {exc}"}

    ranked = _rank_candidates(raw_candidates, score_key="score")
    candidates: list[DispatchCandidate] = [
        {
            "addr": c["addr"],
            "func_addr": c["func_addr"],
            "func_name": c["func_name"],
            "case_count": c["case_count"],
            "kind": c["kind"],
        }
        for c in ranked
    ]

    return {
        "min_cases": min_cases,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


# ---------------------------------------------------------------------------
# Tool 5 -- recipe_crypto_candidates
# ---------------------------------------------------------------------------


def _collect_function_bitops(func_ea: int) -> tuple[list[str], int]:
    """Return (bit-op mnemonics, loop_count) for the function at *func_ea*.

    A "loop" is counted as a backward intra-function control-flow edge (a branch
    whose target is at or before its own address but still inside the function).
    Touches IDA, so it is kept tiny and out of the pure-helper set.
    """
    import idaapi
    import idautils
    import idc

    func = idaapi.get_func(func_ea)
    if func is None:
        return [], 0

    ops: list[str] = []
    loop_count = 0
    self_xor_skips = 0

    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = (idc.print_insn_mnem(head) or "").lower()
        if mnem in _CRYPTO_BITOPS:
            if mnem == "xor":
                op0 = idc.print_operand(head, 0)
                op1 = idc.print_operand(head, 1)
                if op0 and op0 == op1:
                    self_xor_skips += 1
                    continue
            ops.append(mnem)

        for xref in idautils.XrefsFrom(head, 0):
            if not xref.iscode:
                continue
            target = xref.to
            if func.start_ea <= target <= head and target != head + idc.get_item_size(head):
                if target <= head:
                    loop_count += 1
                    break

    return ops, loop_count


@safety("READ")
@title("Rank Crypto-Shaped Functions")
@tool
@idasync
@tool_timeout(300.0)
def recipe_crypto_candidates(
    top: Annotated[int, "How many top-ranked candidates to return; clamped to 1..200 (default 20)"] = _DEFAULT_CRYPTO_TOP,
) -> CryptoCandidatesResult:
    """WHAT: Statically rank the database's functions by how crypto-shaped they
    look -- functions whose body is a tight loop dominated by XOR / ROL / ROR /
    SHL / SHR bit-operations over a buffer. This is a NEUTRAL heuristic that
    surfaces candidates; it never claims a function IS a cipher.

    WHEN TO USE: As the first sweep when hunting a packet cipher, checksum, hash,
    or obfuscation routine, before reading any function. Take the top candidates
    and confirm each by decompiling it (and, for the wire cipher, by the live
    debugger).

    RETURNS: CryptoCandidatesResult with top (the cap used), candidate_count, and
    candidates ranked by score descending. Each candidate has addr, name, score
    (the heuristic weight), ops (the bit-op mnemonics seen), loop_count, and
    reasons (a short, human-readable explanation of why it scored). On failure
    only error is set.

    PRO-TIP: A rotate (rol/ror) inside a loop is the strongest tell and is
    weighted accordingly -- start at the top. The score is comparative, not
    absolute. PITFALL: this only sees integer bit-ops -- table-driven ciphers
    (AES S-box lookups), SSE/AVX vectorized crypto, and big-integer modular
    arithmetic may score low or not appear; a plain `xor reg,reg` zero idiom is
    deliberately discounted so it does not inflate the score."""

    import idaapi
    import idautils

    if top < 1:
        top = 1
    if top > 200:
        top = 200

    raw_candidates: list[dict[str, Any]] = []

    try:
        for func_ea in idautils.Functions():
            ops, loop_count = _collect_function_bitops(func_ea)
            if not ops:
                continue
            score, reasons = _score_crypto_loop(ops, loop_count)
            if score <= 0:
                continue
            raw_candidates.append({
                "addr": hex(func_ea),
                "name": idaapi.get_func_name(func_ea) or "",
                "score": score,
                "ops": _dedup_preserve(ops),
                "loop_count": loop_count,
                "reasons": reasons,
            })
    except Exception as exc:
        return {"error": f"crypto scan failed: {exc}"}

    ranked = _rank_candidates(raw_candidates, score_key="score", top=top)
    candidates: list[CryptoCandidate] = [
        {
            "addr": c["addr"],
            "name": c["name"],
            "score": c["score"],
            "ops": c["ops"],
            "loop_count": c["loop_count"],
            "reasons": c["reasons"],
        }
        for c in ranked
    ]

    return {
        "top": top,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


__all__ = [
    "recipe_function_report",
    "recipe_string_to_code",
    "recipe_import_usage",
    "recipe_dispatch_scan",
    "recipe_crypto_candidates",
    # Pure helpers (exported for unit tests)
    "_rank_candidates",
    "_merge_report",
    "_dedup_preserve",
    "_score_crypto_loop",
    "_classify_dispatch",
]
