"""High-level static-analysis tools backed by the ida-domain SDK.

These tools wrap the official ida-domain Python SDK (the ``ida_domain``
package) to expose ergonomic, read-only views of the open database that
genuinely reduce boilerplate versus raw IDAPython: function listings with
sizes, decompiler pseudocode, cross-references in either direction, the
string table, segment layout, named types, and entry points.

The SDK is imported softly: if ``ida_domain`` is not installed the module
still imports cleanly and every tool returns a structured error dict rather
than raising, so the MCP server never crashes on a host that lacks the SDK.

All tools are part of the base ``/mcp`` view (no extension gate) and
classified READ. They open the *currently loaded* database with the in-GUI
``Database.open()`` form (no path), since this code runs inside IDA.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

from .rpc import safety, title, tool
from .sync import idasync

_UNLOADED = object()

ida_domain = _UNLOADED
Database = _UNLOADED


def _ensure_sdk() -> None:
    """Lazily import the ida-domain SDK on first tool use.

    The SDK is imported on demand rather than at module-import time: importing
    ``ida_domain`` initializes native IDA bindings, which is only valid inside a
    live IDA process. Deferring keeps this module importable everywhere (the MCP
    server registry, headless test harnesses) and lets the per-tool guard return
    a structured error instead of crashing the host.

    Idempotent: once resolved (to the SDK module or to ``None`` when it is not
    importable) the module globals are left untouched, so a caller that has
    pinned ``ida_domain`` (e.g. a test) is never overwritten.
    """
    global ida_domain, Database
    if ida_domain is not _UNLOADED:
        return
    try:
        import ida_domain as _sdk
        from ida_domain import Database as _Database
    except Exception:  # pragma: no cover - exercised only when SDK is absent
        ida_domain = None
        Database = None
        return
    ida_domain = _sdk
    Database = _Database


# ============================================================================
# TypedDict return shapes
# ============================================================================


class DomainError(TypedDict):
    error: str
    detail: str


class DomainFunctionInfo(TypedDict):
    addr: str
    name: str
    start: str
    end: str
    size: int


class DomainFunctionsResult(TypedDict, total=False):
    count: int
    functions: list[DomainFunctionInfo]
    truncated: bool
    error: str
    detail: str


class DomainPseudocodeResult(TypedDict, total=False):
    addr: str
    name: str
    pseudocode: str
    error: str
    detail: str


class DomainXrefInfo(TypedDict):
    from_addr: str
    to_addr: str
    type: str


class DomainXrefsResult(TypedDict, total=False):
    addr: str
    direction: str
    count: int
    xrefs: list[DomainXrefInfo]
    truncated: bool
    error: str
    detail: str


class DomainStringInfo(TypedDict):
    addr: str
    value: str
    length: int


class DomainStringsResult(TypedDict, total=False):
    count: int
    strings: list[DomainStringInfo]
    truncated: bool
    error: str
    detail: str


class DomainSegmentInfo(TypedDict):
    name: str
    start: str
    end: str
    size: int


class DomainSegmentsResult(TypedDict, total=False):
    count: int
    segments: list[DomainSegmentInfo]
    error: str
    detail: str


class DomainTypeInfo(TypedDict):
    name: str
    tid: str


class DomainTypesResult(TypedDict, total=False):
    count: int
    types: list[DomainTypeInfo]
    truncated: bool
    error: str
    detail: str


class DomainEntryInfo(TypedDict):
    addr: str
    name: str
    ordinal: int


class DomainEntryPointsResult(TypedDict, total=False):
    count: int
    entry_points: list[DomainEntryInfo]
    error: str
    detail: str


# ============================================================================
# Internal helpers
# ============================================================================

# Result caps so a huge database never returns an unbounded payload.
_MAX_FUNCTIONS = 5_000
_MAX_XREFS = 1_000
_MAX_STRINGS = 5_000
_MAX_TYPES = 5_000


def _sdk_unavailable() -> DomainError:
    """Uniform error dict when the ida-domain SDK is not importable."""
    return {
        "error": "ida_domain_unavailable",
        "detail": (
            "The ida-domain SDK is not installed in this IDA Python "
            "environment; install the 'ida-domain' package to use the "
            "domain_* tools."
        ),
    }


def _exc_error(kind: str, exc: Exception) -> DomainError:
    """Uniform error dict for an SDK/runtime failure."""
    return {"error": kind, "detail": f"{type(exc).__name__}: {exc}"}


def _parse_ea(value: str) -> int:
    """Parse an address string (decimal or 0x-prefixed hex) to an int."""
    text = value.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    try:
        return int(text, 10)
    except ValueError:
        return int(text, 16)


def _xref_type_name(xref) -> str:
    """Best-effort human name for an SDK xref's reference type."""
    try:
        t = xref.type
        name = getattr(t, "name", None)
        if name is not None:
            return str(name)
        return str(t)
    except Exception:
        return "unknown"


# ============================================================================
# Tools
# ============================================================================


@safety("READ")
@title("Domain: List Functions")
@tool
@idasync
def domain_functions(
    name_filter: Annotated[
        str,
        "Optional case-insensitive substring to match against function names; "
        "empty string returns all functions (up to the internal cap).",
    ] = "",
) -> DomainFunctionsResult:
    """WHAT: List the database's functions via the ida-domain SDK, each with its
    name, start/end address, and byte size. An optional case-insensitive
    substring filter narrows the result by function name.

    WHEN TO USE: When you want a clean, high-level function inventory without
    hand-rolling idautils.Functions + per-function name/size lookups. Pair the
    returned addresses with domain_function_pseudocode or domain_xrefs.

    RETURNS: a DomainFunctionsResult with 'count', a 'functions' list (addr,
    name, start, end, size), and 'truncated' when the cap was hit. On a host
    without the ida-domain SDK, returns {'error', 'detail'} instead and never
    raises."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    needle = name_filter.strip().lower()
    try:
        with Database.open() as db:
            out: list[DomainFunctionInfo] = []
            truncated = False
            for func in db.functions:
                fname = db.functions.get_name(func) or ""
                if needle and needle not in fname.lower():
                    continue
                start = int(func.start_ea)
                end = int(func.end_ea)
                try:
                    size = int(func.size)
                except Exception:
                    size = end - start
                out.append(
                    {
                        "addr": hex(start),
                        "name": fname,
                        "start": hex(start),
                        "end": hex(end),
                        "size": size,
                    }
                )
                if len(out) >= _MAX_FUNCTIONS:
                    truncated = True
                    break
            return {"count": len(out), "functions": out, "truncated": truncated}
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_functions_failed", exc)


@safety("READ")
@title("Domain: Function Pseudocode")
@tool
@idasync
def domain_function_pseudocode(
    ea: Annotated[
        str,
        "Address inside the target function (decimal or 0x-prefixed hex).",
    ],
) -> DomainPseudocodeResult:
    """WHAT: Decompile one function to Hex-Rays pseudocode via the ida-domain
    SDK and return it as a single text blob, along with the function's name.

    WHEN TO USE: When you want the decompiler output for a specific function
    address without driving the Hex-Rays API directly. The address may be the
    function start or any address within it.

    RETURNS: a DomainPseudocodeResult with 'addr', 'name', and 'pseudocode'.
    If the SDK is missing, the address is invalid, or no function/decompiler
    output exists there, returns {'error', 'detail'} and never raises.

    PITFALL: this returns raw decompiler text; in a clean-room workflow that
    output is dirty-room only — never paste it into committed specs or C#."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    try:
        addr = _parse_ea(ea)
    except Exception as exc:
        return _exc_error("invalid_address", exc)

    try:
        with Database.open() as db:
            func = None
            for candidate in db.functions:
                start = int(candidate.start_ea)
                end = int(candidate.end_ea)
                if start <= addr < end:
                    func = candidate
                    break
            if func is None:
                return {
                    "error": "no_function",
                    "detail": f"No function contains address {hex(addr)}.",
                }
            fname = db.functions.get_name(func) or ""
            pseudocode = db.functions.get_pseudocode(func)
            if pseudocode is None:
                return {
                    "error": "no_pseudocode",
                    "detail": f"Decompiler produced no output for {fname or hex(addr)}.",
                }
            try:
                lines = list(pseudocode.to_text())
            except Exception:
                lines = [str(pseudocode)]
            return {
                "addr": hex(int(func.start_ea)),
                "name": fname,
                "pseudocode": "\n".join(str(line) for line in lines),
            }
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_function_pseudocode_failed", exc)


@safety("READ")
@title("Domain: Cross-References")
@tool
@idasync
def domain_xrefs(
    ea: Annotated[
        str,
        "Target address (decimal or 0x-prefixed hex) whose cross-references to "
        "enumerate.",
    ],
    direction: Annotated[
        str,
        "Which references to return: 'to' (references that point AT this "
        "address) or 'from' (references originating FROM this address). "
        "Defaults to 'to'.",
    ] = "to",
) -> DomainXrefsResult:
    """WHAT: Enumerate cross-references for an address via the ida-domain SDK,
    in either direction. 'to' lists every reference whose target is the given
    address (who reaches it); 'from' lists every reference originating from it
    (what it reaches).

    WHEN TO USE: To answer "who calls / reads / jumps to this function or
    global" ('to') or "what does this instruction reference" ('from') without
    hand-walking idautils.XrefsTo / XrefsFrom.

    RETURNS: a DomainXrefsResult with 'addr', 'direction', 'count', an 'xrefs'
    list (from_addr, to_addr, type), and 'truncated' when the cap is hit. On a
    missing SDK or invalid address, returns {'error', 'detail'} and never
    raises."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    dir_norm = direction.strip().lower()
    if dir_norm not in ("to", "from"):
        return {
            "error": "invalid_direction",
            "detail": "direction must be 'to' or 'from'.",
        }

    try:
        addr = _parse_ea(ea)
    except Exception as exc:
        return _exc_error("invalid_address", exc)

    try:
        with Database.open() as db:
            iterator = (
                db.xrefs.to_ea(addr) if dir_norm == "to" else db.xrefs.from_ea(addr)
            )
            out: list[DomainXrefInfo] = []
            truncated = False
            for xref in iterator:
                out.append(
                    {
                        "from_addr": hex(int(xref.from_ea)),
                        "to_addr": hex(int(xref.to_ea)),
                        "type": _xref_type_name(xref),
                    }
                )
                if len(out) >= _MAX_XREFS:
                    truncated = True
                    break
            return {
                "addr": hex(addr),
                "direction": dir_norm,
                "count": len(out),
                "xrefs": out,
                "truncated": truncated,
            }
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_xrefs_failed", exc)


@safety("READ")
@title("Domain: List Strings")
@tool
@idasync
def domain_strings(
    filter: Annotated[
        str,
        "Optional case-insensitive substring; only strings containing it are "
        "returned. Empty string returns all strings (up to the internal cap).",
    ] = "",
) -> DomainStringsResult:
    """WHAT: List the database's recovered strings via the ida-domain SDK, each
    with its address, value, and length. An optional case-insensitive
    substring filter narrows the result by content.

    WHEN TO USE: To census or grep the string table for a subsystem marker
    (a path, a format token, an error message) without driving the string-list
    API by hand.

    RETURNS: a DomainStringsResult with 'count', a 'strings' list (addr, value,
    length), and 'truncated' when the cap is hit. On a missing SDK, returns
    {'error', 'detail'} and never raises."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    needle = filter.strip().lower()
    try:
        with Database.open() as db:
            out: list[DomainStringInfo] = []
            truncated = False
            for item in db.strings:
                value = str(item)
                if needle and needle not in value.lower():
                    continue
                try:
                    length = int(item.length)
                except Exception:
                    length = len(value)
                out.append(
                    {
                        "addr": hex(int(item.address)),
                        "value": value,
                        "length": length,
                    }
                )
                if len(out) >= _MAX_STRINGS:
                    truncated = True
                    break
            return {"count": len(out), "strings": out, "truncated": truncated}
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_strings_failed", exc)


@safety("READ")
@title("Domain: List Segments")
@tool
@idasync
def domain_segments() -> DomainSegmentsResult:
    """WHAT: List the database's segments via the ida-domain SDK, each with its
    name, start/end address, and byte size.

    WHEN TO USE: For a quick high-level memory map of the binary (where code,
    data, and import segments live) without hand-walking idautils.Segments.

    RETURNS: a DomainSegmentsResult with 'count' and a 'segments' list (name,
    start, end, size). On a missing SDK, returns {'error', 'detail'} and never
    raises."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    try:
        with Database.open() as db:
            out: list[DomainSegmentInfo] = []
            for seg in db.segments:
                start = int(seg.start_ea)
                end = int(seg.end_ea)
                try:
                    size = int(seg.size)
                except Exception:
                    size = end - start
                out.append(
                    {
                        "name": str(seg.name),
                        "start": hex(start),
                        "end": hex(end),
                        "size": size,
                    }
                )
            return {"count": len(out), "segments": out}
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_segments_failed", exc)


@safety("READ")
@title("Domain: List Types")
@tool
@idasync
def domain_types(
    filter: Annotated[
        str,
        "Optional case-insensitive substring to match against type names; "
        "empty string returns all named types (up to the internal cap).",
    ] = "",
) -> DomainTypesResult:
    """WHAT: List the named types in the database's type system via the
    ida-domain SDK, each with its name and type id. An optional
    case-insensitive substring filter narrows the result by name.

    WHEN TO USE: To discover which structs/enums/typedefs are already declared
    in the IDB (e.g. before recovering a struct layout) without driving the
    type-info API by hand.

    RETURNS: a DomainTypesResult with 'count', a 'types' list (name, tid), and
    'truncated' when the cap is hit. On a missing SDK, returns {'error',
    'detail'} and never raises."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    needle = filter.strip().lower()
    try:
        with Database.open() as db:
            out: list[DomainTypeInfo] = []
            truncated = False
            for type_def in db.types:
                try:
                    type_name = type_def.get_type_name()
                except Exception:
                    type_name = str(type_def)
                type_name = type_name or ""
                if needle and needle not in type_name.lower():
                    continue
                try:
                    tid = str(type_def.get_tid())
                except Exception:
                    tid = ""
                out.append({"name": type_name, "tid": tid})
                if len(out) >= _MAX_TYPES:
                    truncated = True
                    break
            return {"count": len(out), "types": out, "truncated": truncated}
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_types_failed", exc)


@safety("READ")
@title("Domain: Entry Points")
@tool
@idasync
def domain_entry_points() -> DomainEntryPointsResult:
    """WHAT: List the binary's entry points via the ida-domain SDK, each with
    its address, name, and ordinal.

    WHEN TO USE: To find the program's start address(es) and exported ordinals
    as an orientation step, without hand-walking the entry table.

    RETURNS: a DomainEntryPointsResult with 'count' and an 'entry_points' list
    (addr, name, ordinal). On a missing SDK, returns {'error', 'detail'} and
    never raises."""
    _ensure_sdk()
    if ida_domain is None:
        return _sdk_unavailable()

    try:
        with Database.open() as db:
            out: list[DomainEntryInfo] = []
            for entry in db.entries:
                try:
                    ordinal = int(entry.ordinal)
                except Exception:
                    ordinal = 0
                out.append(
                    {
                        "addr": hex(int(entry.address)),
                        "name": str(entry.name),
                        "ordinal": ordinal,
                    }
                )
            return {"count": len(out), "entry_points": out}
    except Exception as exc:  # pragma: no cover - runtime/SDK failure path
        return _exc_error("domain_entry_points_failed", exc)


__all__ = [
    "domain_functions",
    "domain_function_pseudocode",
    "domain_xrefs",
    "domain_strings",
    "domain_segments",
    "domain_types",
    "domain_entry_points",
]
