"""Core API Functions - IDB metadata and basic queries"""

import logging
import os
import re
import threading
import time
from typing import Annotated, Any, NotRequired, TypedDict

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

from .rpc import tool, safety, title
from .sync import idasync, get_tool_deadline
from .utils import (
    ConvertedNumber,
    EntityQuery,
    Function,
    FunctionQuery,
    Global,
    Import,
    ListQuery,
    NumberConversion,
    Page,
    ImportQuery,
    get_function,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    paginate,
    pattern_filter,
)

logger = logging.getLogger(__name__)


class ServerHealthResult(TypedDict):
    status: str
    uptime_sec: float
    idb_path: str | None
    module: str
    input_path: str
    imagebase: str
    auto_analysis_ready: bool | None
    hexrays_ready: bool
    strings_cache_ready: bool
    strings_cache_size: int


class ServerWarmupStep(TypedDict, total=False):
    step: str
    ok: bool
    ms: float
    error: str


class ServerWarmupResult(TypedDict):
    ok: bool
    steps: list[ServerWarmupStep]
    health: ServerHealthResult


class LookupFuncResult(TypedDict):
    query: str
    fn: Function | None
    error: str | None


class IntConvertResult(TypedDict):
    input: str
    result: ConvertedNumber | None
    error: str | None


class FunctionQueryRow(Function, total=False):
    has_type: bool
    size_int: int


class FunctionQueryPage(TypedDict, total=False):
    data: list[FunctionQueryRow]
    next_offset: int | None
    error: str | None


class EntityQueryPage(TypedDict, total=False):
    kind: str
    data: list[dict[str, Any]]
    next_offset: int | None
    total: int
    error: str | None


class ImportsQueryPage(TypedDict):
    data: list[Import]
    next_offset: int | None


class IdbSaveResult(TypedDict):
    ok: bool
    path: str | None
    error: NotRequired[str]


class FindRegexResult(TypedDict, total=False):
    n: int
    matches: list[dict[str, Any]]
    cursor: dict[str, Any]
    error: str | None


class SearchTextLine(TypedDict, total=False):
    kind: str  # "disasm" | "comment"
    text: str


class SearchTextHit(TypedDict, total=False):
    addr: str
    function: str
    segment: str
    matches: list[SearchTextLine]


class SearchTextResult(TypedDict, total=False):
    n: int
    hits: list[SearchTextHit]
    cursor: dict[str, Any]
    error: str


# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_strings_cache_lock = threading.Lock()
_server_started_at = time.time()


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    with _strings_cache_lock:
        if _strings_cache is None:
            _strings_cache = [
                (s.ea, str(s)) for s in idautils.Strings() if s is not None
            ]
        return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    with _strings_cache_lock:
        _strings_cache = None


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    logger.info("[MCP] Cached %d strings in %.0fms", len(strings), (t1 - t0) * 1000)


# ============================================================================
# Core API Functions
# ============================================================================


def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()

    # 0x<hex> - direct address
    if q.startswith("0x") or q.startswith("0X"):
        try:
            return int(q, 16)
        except ValueError:
            pass

    # sub_<hex> - IDA auto-named function
    if q.startswith("sub_"):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass

    return idaapi.BADADDR


def _coerce_sort_number(value, default: int = 0) -> int:
    """Parse decimal or prefixed string numbers used by generic entity rows."""
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _collect_imports() -> list[Import]:
    """Collect all imports in the current database."""
    all_imports: list[Import] = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, all_imports)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return all_imports


def _segment_name_for_ea(ea: int) -> str | None:
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        return idaapi.get_segm_name(seg)
    except Exception:
        return None


def _primary_text_key(kind: str) -> str:
    if kind == "strings":
        return "text"
    return "name"


def _collect_entities(kind: str) -> list[dict]:
    if kind == "functions":
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append(
                {
                    "kind": "function",
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                    "segment": _segment_name_for_ea(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    if kind == "globals":
        rows = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "imports":
        rows = []
        for imp in _collect_imports():
            rows.append(
                {
                    "kind": "import",
                    "addr": imp["addr"],
                    "name": imp["imported_name"],
                    "module": imp["module"],
                }
            )
        return rows

    if kind == "strings":
        rows = []
        for ea, text in _get_strings_cache():
            rows.append(
                {
                    "kind": "string",
                    "addr": hex(ea),
                    "text": text,
                    "length": len(text),
                    "segment": _segment_name_for_ea(ea),
                }
            )
        return rows

    if kind == "names":
        rows = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(idaapi.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": _segment_name_for_ea(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    return []


def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add("kind")
    projected = []
    for item in items:
        projected.append({k: v for k, v in item.items() if k in keep})
    return projected


def _build_health_payload() -> dict:
    auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
    auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None

    hexrays_ready = False
    try:
        hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ready = False

    idb_path = None
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = None

    return {
        "status": "ok",
        "uptime_sec": round(time.time() - _server_started_at, 3),
        "idb_path": idb_path,
        "module": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "auto_analysis_ready": auto_analysis_ready,
        "hexrays_ready": hexrays_ready,
        "strings_cache_ready": _strings_cache is not None,
        "strings_cache_size": len(_strings_cache) if _strings_cache is not None else 0,
    }


@safety("READ")
@title("Server Health Probe")
@tool
@idasync
def server_health() -> ServerHealthResult:
    """WHAT: Liveness/readiness probe for the MCP server and the database it has open.

    WHEN TO USE: Call first in any session to confirm the server is reachable and an
    IDB is actually loaded before issuing real analysis tools; also use to check whether
    auto-analysis has finished, whether Hex-Rays is available (gates decompile), and
    whether the strings cache is warm.

    RETURNS: status, server uptime_sec, idb_path, module/input_path, imagebase,
    auto_analysis_ready, hexrays_ready, and strings_cache_ready/size.

    PITFALL: hexrays_ready may be False on the very first probe even when Hex-Rays is
    installed; it initializes lazily, so a follow-up server_warmup (run by idb_open)
    or a first decompile call flips it true. auto_analysis_ready is None when the
    auto_is_ok API is unavailable, which is NOT the same as "not ready".
    """
    return _build_health_payload()


@idasync
def server_warmup(
    wait_auto_analysis: bool = True,
    build_caches: bool = True,
    init_hexrays: bool = True,
) -> ServerWarmupResult:
    """Warm up IDA subsystems. Called by idb_open; no longer exposed as an MCP tool."""
    steps = []

    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append(
            {
                "step": "auto_wait",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append(
            {
                "step": "init_caches",
                "ok": True,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )

    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step = {
            "step": "init_hexrays",
            "ok": ok,
            "ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        if not ok:
            step["error"] = "Hex-Rays unavailable"
        steps.append(step)

    return {
        "ok": all(bool(step.get("ok")) for step in steps),
        "steps": steps,
        "health": _build_health_payload(),
    }


@safety("READ")
@title("Look Up Functions by Address or Name")
@tool
@idasync
def lookup_funcs(
    queries: Annotated[
        list[str] | str,
        "One or more function references, each either an address (0x401000 or sub_401000) or a symbol name (e.g. 'main'). Pass '*' or an empty value to fetch the first 1000 functions.",
    ],
) -> list[LookupFuncResult]:
    """WHAT: Resolve each query to a function and return its descriptor, auto-detecting
    whether the query is an address (0x.. / sub_..) or a name.

    WHEN TO USE: The fast lookup when you already know exactly which function(s) you
    want by address or name and need their metadata; prefer list_funcs/func_query when
    you need to FILTER or paginate across the whole image.

    RETURNS: One row per query, each {query, fn, error}; fn is None and error is set
    ("Not found" / "Not a function") when the query does not resolve to a function.

    PRO-TIP: Results are aligned 1:1 and in order with the input queries, so you can zip
    them back to your inputs. The bulk '*' mode caps at 1000 functions — use func_query
    with pagination for full enumeration of large binaries.
    """
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions" - but add limit
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in queries:
        try:
            # Fast path: 0x<ea> or sub_<ea>
            ea = _parse_func_query(query)

            # Slow path: name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)

            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({"query": query, "fn": func, "error": None})
                else:
                    results.append(
                        {"query": query, "fn": None, "error": "Not a function"}
                    )
            else:
                results.append({"query": query, "fn": None, "error": "Not found"})
        except Exception as e:
            results.append({"query": query, "fn": None, "error": str(e)})

    return results


@safety("READ")
@title("Convert Integers Between Representations")
@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "One or more {text, size} items: text is a number in any base (0x.., 0b.., decimal); size is the byte width to encode it in (omit/0 = smallest width that fits). A bare string is accepted and treated as 64-bit.",
    ],
) -> list[IntConvertResult]:
    """WHAT: Convert each input number into all common representations at once: decimal,
    hexadecimal, little-endian byte string, ASCII (if printable), and binary.

    WHEN TO USE: When eyeballing a constant, flag value, or magic number found in the
    listing and you want every view (e.g. is this 0x6F6C6C65H actually the ASCII tag
    'ello'?). Pure arithmetic — does not touch the IDB and works without a database.

    RETURNS: One row per input {input, result, error}; result is None and error is set
    on an unparseable number or when the value overflows the requested size.

    PITFALL: bytes/ascii are LITTLE-ENDIAN encodings, so the byte order is reversed
    versus how the hex literal reads left-to-right; ascii is null only when a byte is
    outside the printable range 32..126.
    """
    inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

    results = []
    for item in inputs:
        text = item.get("text", "")
        size = item.get("size")

        try:
            value = int(text, 0)
        except ValueError:
            results.append(
                {"input": text, "result": None, "error": f"Invalid number: {text}"}
            )
            continue

        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        try:
            bytes_data = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            results.append(
                {
                    "input": text,
                    "result": None,
                    "error": f"Number {text} is too big for {size} bytes",
                }
            )
            continue

        ascii_str = ""
        for byte in bytes_data.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break

        results.append(
            {
                "input": text,
                "result": ConvertedNumber(
                    decimal=str(value),
                    hexadecimal=hex(value),
                    bytes=bytes_data.hex(" "),
                    ascii=ascii_str,
                    binary=bin(value),
                ),
                "error": None,
            }
        )

    return results


@safety("READ")
@title("List Functions")
@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery,
        "One or more {filter, offset, count} pages. filter is a substring/glob matched against the function name ('' or '*' = all); offset/count drive offset/count pagination (count defaults to 100).",
    ],
) -> list[Page[Function]]:
    """WHAT: Enumerate functions, name-filtered and paginated, returning one page per query.

    WHEN TO USE: The simple "what functions exist / find functions whose name contains X"
    listing. Reach for func_query instead when you need size/type filters, regex name
    matching, or sorting; use lookup_funcs when you already know the exact address/name.

    RETURNS: One Page[Function] per query: {data: [{addr, name, ...}], next_offset};
    next_offset is the value to pass as the next page's offset, or None when exhausted.

    PRO-TIP: Batch several {filter,offset,count} queries in a single call to fetch
    multiple name slices in one round-trip instead of issuing the tool repeatedly.
    """
    queries = normalize_dict_list(queries)
    all_functions = [get_function(addr) for addr in idautils.Functions()]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_functions, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@safety("READ")
@title("Query Functions With Filters and Sorting")
@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery,
        "One or more query objects supporting: filter (name substring), name_regex (Python regex on name), min_size/max_size (bytes), has_type (true/false on whether a tinfo is set), sort_by ('addr'|'name'|'size'), descending, and offset/count pagination.",
    ],
) -> list[FunctionQueryPage]:
    """WHAT: Richer function search than list_funcs — filter by name substring or regex,
    by byte-size bounds, by whether a type is set, then sort and paginate.

    WHEN TO USE: To hunt for candidates by shape, e.g. "large untyped functions"
    (max_size off, has_type=false, sort_by=size descending) when triaging a binary, or
    a regex name sweep that plain substring filter can't express.

    RETURNS: One FunctionQueryPage per query {data, next_offset, error}; each row is
    {addr, name, size, has_type}. An invalid name_regex yields an empty page, not an error.

    PRO-TIP: sort_by/min_size/max_size combine, so you can rank the biggest functions in
    a size band; the internal size_int helper field is stripped from the output, so sort
    on 'size' rather than expecting a numeric size in the rows.
    """
    queries = normalize_dict_list(queries)

    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
        has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
        all_functions.append(
            {
                "addr": hex(fn.start_ea),
                "name": fn_name,
                "size": hex(size_int),
                "size_int": size_int,
                "has_type": has_type,
            }
        )

    def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
        if not expr:
            return items
        try:
            compiled = re.compile(expr)
        except re.error:
            return []
        return [item for item in items if compiled.search(item["name"])]

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        filtered = list(all_functions)
        name_filter = query.get("filter", "")
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "name")

        name_regex = query.get("name_regex", "")
        if name_regex:
            filtered = apply_name_regex(filtered, name_regex)

        min_size = query.get("min_size")
        if min_size is not None:
            filtered = [f for f in filtered if f["size_int"] >= int(min_size)]

        max_size = query.get("max_size")
        if max_size is not None:
            filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

        if "has_type" in query:
            require_type = bool(query.get("has_type"))
            filtered = [f for f in filtered if bool(f["has_type"]) is require_type]

        if sort_by == "name":
            filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
        elif sort_by == "size":
            filtered.sort(key=lambda f: f["size_int"], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

        page = paginate(filtered, offset, count)
        page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
        results.append(page)

    return results


@safety("READ")
@title("List Global Symbols")
@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery,
        "One or more {filter, offset, count} pages. filter is a substring/glob on the symbol name ('' or '*' = all); offset/count drive offset/count pagination (count defaults to 100).",
    ],
) -> list[Page[Global]]:
    """WHAT: Enumerate named non-function symbols (data globals), name-filtered and paginated.

    WHEN TO USE: To find global variables / data labels by name when chasing a referenced
    datum (e.g. a config table or string pointer). For imports use imports/imports_query;
    for functions use list_funcs/func_query.

    RETURNS: One Page[Global] per query {data: [{addr, name}], next_offset}; next_offset
    feeds the following page's offset, or is None when exhausted.

    PITFALL: This lists only NAMED addresses that are not functions — unnamed data and
    function entry points are excluded; if a global is missing, it likely has no name yet.
    For a cross-kind sweep (globals + strings + imports + names) use entity_query.
    """
    queries = normalize_dict_list(queries)
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@safety("READ")
@title("Query IDB Entities (Functions/Globals/Imports/Strings/Names)")
@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery,
        "One or more query objects. kind selects the entity set ('functions'|'globals'|'imports'|'strings'|'names', default 'functions'); then filter (substring on name/text), regex, segment (not for imports), module (imports only), min_addr/max_addr bounds, sort_by ('addr'|'size'|'length'|'name'|...), descending, fields (projection list of columns to keep), and offset/count pagination.",
    ],
) -> list[EntityQueryPage]:
    """WHAT: One unified, filterable, projectable, paginated query over five entity kinds
    — functions, globals, imports, strings, and all named addresses.

    WHEN TO USE: The general-purpose explorer when you want to slice across a kind with
    address bounds, segment/module scoping, regex, custom sort, and a trimmed column set,
    or when you don't know yet which specialized lister (list_funcs/list_globals/imports/
    find_regex) fits — entity_query subsumes them with one schema.

    RETURNS: One EntityQueryPage per query {kind, data, next_offset, total, error}; total
    is the full filtered count (pre-pagination), useful for sizing further pages.

    PRO-TIP: Use fields to project just the columns you need (e.g. ['addr','name']) to
    shrink payloads on big result sets; an unsupported kind returns an error row rather
    than throwing, and 'strings' is served from the warm strings cache.
    """
    queries = normalize_dict_list(queries)
    results: list[dict] = []

    for query in queries:
        kind = str(query.get("kind", "functions") or "functions").lower()
        if kind not in {"functions", "globals", "imports", "strings", "names"}:
            results.append(
                {
                    "kind": kind,
                    "data": [],
                    "next_offset": None,
                    "total": 0,
                    "error": f"Unsupported kind: {kind}",
                }
            )
            continue

        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get("filter", "") or "")
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)

        regex = str(query.get("regex", "") or "")
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
            except re.error:
                rows = []

        segment_filter = str(query.get("segment", "") or "")
        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
            except Exception:
                rows = []

        sort_by = str(query.get("sort_by", "addr") or "addr")
        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: row.get("size_int", _coerce_sort_number(row.get(sort_by, 0))),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query.get("count", 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)

        results.append(
            {
                "kind": kind,
                "data": data,
                "next_offset": page["next_offset"],
                "total": len(rows),
                "error": None,
            }
        )

    return results


@safety("READ")
@title("List Imports")
@tool
@idasync
def imports(
    offset: Annotated[int, "Zero-based index of the first import row to return (pass 0 to start)."],
    count: Annotated[int, "Maximum number of rows to return; pass 0 to return ALL imports in one page."],
) -> Page[Import]:
    """WHAT: List the binary's imported symbols with their resolving module names, paginated.

    WHEN TO USE: Quick "what does this binary import" census, or to confirm a specific API
    (e.g. recv/CreateFileW) is imported before xref'ing it. For name/module FILTERING use
    imports_query instead of paging through everything here.

    RETURNS: A Page[Import] {data: [{addr, imported_name, module}], next_offset}; ordinal-only
    imports surface as imported_name '#<ordinal>' and modules with no name as '<unnamed>'.

    PRO-TIP: count=0 dumps the entire import table in a single page — convenient on small
    binaries, but prefer paging (or imports_query with a filter) on large ones.
    """
    return paginate(_collect_imports(), offset, count)


@safety("READ")
@title("Query Imports With Filters")
@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery,
        "One or more query objects: filter (substring on the imported symbol name), module (substring on the resolving DLL/module name), and offset/count pagination (count defaults to 100).",
    ],
) -> list[ImportsQueryPage]:
    """WHAT: Filterable, paginated import lookup — richer than imports(offset, count).

    WHEN TO USE: To find imports by symbol substring (e.g. all 'Crypt*' APIs) and/or by
    module (e.g. everything from ws2_32.dll) without paging the whole table. Plain
    enumeration with no filtering is fine via imports.

    RETURNS: One ImportsQueryPage per query {data: [{addr, imported_name, module}],
    next_offset}; next_offset feeds the following page's offset, or is None when exhausted.

    PRO-TIP: filter and module are combined with AND, so {filter:'recv', module:'ws2_32'}
    narrows to socket-recv APIs in one go; both are case-insensitive substring matches.
    """
    queries = normalize_dict_list(queries)
    all_imports = _collect_imports()
    results = []

    for query in queries:
        filtered = all_imports
        name_filter = query.get("filter", "")
        module_filter = query.get("module", "")

        if name_filter:
            filtered = pattern_filter(filtered, name_filter, "imported_name")
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, "module")

        results.append(
            paginate(filtered, query.get("offset", 0), query.get("count", 100))
        )

    return results


@safety("WRITE")
@title("Save IDB to Disk")
@tool
@idasync
def idb_save(
    path: Annotated[
        str,
        "Optional destination path for the saved database; empty means save in place to the currently open IDB path.",
    ] = "",
    overwrite: Annotated[
        bool,
        "Guard against clobbering an existing different file. When path resolves to an existing file that differs from the currently open IDB, the save is refused unless this is True.",
    ] = False,
) -> IdbSaveResult:
    """WHAT: Persist the active IDB (all renames, comments, types, patches) to disk,
    either in place or as a copy at a new path.

    WHEN TO USE: After a batch of IDB-mutating tools to durably checkpoint your work, or to
    snapshot the database to a new file. Read-only analysis tools do not need this.

    RETURNS: {ok, path, error?}; ok is False with an error string when the path can't be
    resolved, save_database reports failure, or the destination would overwrite an
    existing different file while overwrite is False.

    PARAMS: overwrite (default False) is a safety guard: when path resolves to an already
    existing file that differs from the currently open IDB, the save is refused unless
    overwrite=True, so an explicit save-as cannot silently clobber an unrelated database.

    PITFALL: In the GUI this performs a native in-place save (Ctrl+W) and, for a different
    path, a compressed snapshot — it deliberately never kills the live loose working files
    (.id0/.id1/.nam/...), which would corrupt the open database (issue #446). Only headless
    idalib packs into a single compressed .i64/.idb and removes the loose files.

    Original behavioral notes:
    In the GUI (idaq) the open database is backed by loose working files
    (.id0/.id1/.id2/.nam/.til) that IDA actively manages; packing+killing them
    out from under the running GUI corrupts the database on the next reopen
    (issue #446). So in GUI mode this uses IDA's native in-place save
    (equivalent to Ctrl+W / save_database(None, 0)), and for an explicit
    different destination writes a compressed copy WITHOUT killing the live
    working files.

    Only headless idalib — which has no live loose files to clobber — packs into
    a single compressed .i64/.idb, removing the loose working files.
    """
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        try:
            is_gui = bool(ida_kernwin.is_idaq())
        except Exception:
            # Bias to the SAFE branch on an unknown environment: assume GUI so we use the
            # native in-place save and never DBFL_KILL loose working files. A false headless
            # assumption here would pack+kill a live GUI database and corrupt it (issue #446).
            is_gui = True

        current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if (
            path
            and save_path != current
            and os.path.exists(save_path)
            and not overwrite
        ):
            return {
                "ok": False,
                "path": save_path,
                "error": f"Refusing to overwrite existing file {save_path}; pass overwrite=true to allow",
            }

        if is_gui:
            # GUI: never DBFL_KILL the loose files of the open database.
            if path and save_path != current:
                # Save-as a compressed snapshot to a new path; leaves the live
                # working files intact.
                ok = bool(ida_loader.save_database(save_path, ida_loader.DBFL_COMP))
            else:
                # Native in-place save (Ctrl+W).
                ok = bool(ida_loader.save_database(None, 0))
        else:
            # Headless idalib: safe to pack into a single compressed file.
            flags = ida_loader.DBFL_KILL | ida_loader.DBFL_COMP
            ok = bool(ida_loader.save_database(save_path, flags))

        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}


@safety("READ")
@title("Find Strings by Regex")
@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Python regular expression matched (case-insensitively) against each extracted string's text."],
    limit: Annotated[int, "Maximum matches to return per page; clamped to 1..500 (default 30)."] = 30,
    offset: Annotated[int, "Number of leading matches to skip for pagination (default 0)."] = 0,
) -> FindRegexResult:
    """WHAT: Search the binary's extracted string literals by case-insensitive Python regex,
    with offset/limit pagination.

    WHEN TO USE: To locate strings by pattern (URLs, format specifiers, error messages,
    file extensions) as a fast entry point into a subsystem. For the rendered LISTING
    (disassembly text + comments) rather than string literals, use search_text instead.

    RETURNS: {n, matches: [{addr, string}], cursor}; cursor is {next: <offset>} when more
    results remain, else {done: true}.

    PRO-TIP: Strings come from a warm cache built once per session, so repeated regex
    searches are cheap; the match is always case-insensitive, so don't add inline (?i).
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    regex = re.compile(pattern, re.IGNORECASE)
    strings = _get_strings_cache()

    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({"addr": hex(ea), "string": text})

    return {
        "n": len(matches),
        "matches": matches,
        "cursor": {"next": offset + limit} if more else {"done": True},
    }


_COMMENT_SCOLORS = (
    ida_lines.SCOLOR_REGCMT,
    ida_lines.SCOLOR_RPTCMT,
    ida_lines.SCOLOR_AUTOCMT,
    ida_lines.SCOLOR_COLLAPSED,
)


def _line_is_comment(tagged: str) -> bool:
    """A rendered listing line is a comment if it carries any comment SCOLOR tag."""
    if not tagged:
        return False
    for sc in _COMMENT_SCOLORS:
        if ida_lines.COLOR_ON + sc in tagged:
            return True
    return False


def _classify_hit_lines(
    ea: int,
    matcher,
    want_disasm: bool,
    want_comments: bool,
    max_lines: int = 32,
) -> list[SearchTextLine]:
    """Render the listing for `ea` once, classify each line, return matching lines."""
    out: list[SearchTextLine] = []
    try:
        result = ida_lines.generate_disassembly(ea, max_lines, False, False)
    except Exception:
        return out
    # Bindings vary: (n, lineno, lines) or (lines, lineno).
    lines = None
    if isinstance(result, tuple):
        for item in result:
            if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                lines = list(item)
                break
    if lines is None:
        return out

    for tagged in lines:
        text = ida_lines.tag_remove(tagged) or ""
        if not text or not matcher(text):
            continue
        is_cmt = _line_is_comment(tagged)
        kind = "comment" if is_cmt else "disasm"
        if kind == "disasm" and not want_disasm:
            continue
        if kind == "comment" and not want_comments:
            continue
        out.append({"kind": kind, "text": text})
    return out


def _exec_segments() -> list[tuple[int, int]]:
    """Return [(start, end)] for executable segments in address order."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if not (seg.perm & idaapi.SEGPERM_EXEC):
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges


def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges


@safety("READ")
@title("Search Disassembly Listing Text")
@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to find in the rendered listing; a literal substring by default, or a Python regex when regex=True."],
    limit: Annotated[int, "Maximum hits per page; clamped to 1..500 (default 30)."] = 30,
    start: Annotated[str, "Inclusive lower address bound, hex or symbol; empty = start of the first (in-scope) segment."] = "",
    end: Annotated[str, "Exclusive upper address bound, hex or symbol; empty = end of the last (in-scope) segment."] = "",
    regex: Annotated[bool, "Treat pattern as a Python regular expression instead of a literal substring."] = False,
    case_sensitive: Annotated[bool, "Match case-sensitively (default False = case-insensitive)."] = False,
    include: Annotated[str, "Which listing lines to match: 'disasm', 'comments', or 'all' (default 'all')."] = "all",
    code_only: Annotated[bool, "Restrict the scan to executable segments (default True); set False to also scan data segments."] = True,
) -> SearchTextResult:
    """WHAT: Search the RENDERED disassembly listing (instruction text and/or comments) for
    a substring or regex over an address range, returning located hits.

    WHEN TO USE: To find text that only exists in the rendered view — an operand mnemonic,
    an immediate, an auto/repeatable comment, an analyst note — which a raw string search
    (find_regex) can't see. Use include='comments' to grep your own annotations.

    RETURNS: {n, hits: [{addr, function?, segment?, matches:[{kind, text}]}], cursor};
    cursor is {done:true}, {next:<ea>} for the next page, or {next:<ea>, cancelled:true}
    when the per-tool deadline or UI Cancel interrupted a long scan (resume from next).

    PRO-TIP: ALWAYS scope big binaries with start/end (and keep code_only=True) — the scan
    walks heads in pure Python so it's interruptible, but unscoped it covers the whole image
    and is slow. A cursor with cancelled=true is a partial result, not a failure.

    Iterates `idautils.Heads()` in pure Python and renders each via
    `ida_lines.generate_disassembly()`. Per-head iteration is cheap and
    yields between heads, so the per-tool deadline (sync_wrapper) and the
    UI Cancel button both interrupt the walk reliably — unlike the C-level
    `ida_search.find_text()` it replaced, which on huge .text segments
    could run for minutes without polling `user_cancelled()`.

    Use `start`/`end` to scope the work for predictable performance on
    large binaries; without them the scan covers the whole image.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    include = (include or "all").lower()
    if include not in ("disasm", "comments", "all"):
        return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid include: {include!r}"}

    want_disasm = include in ("disasm", "all")
    want_comments = include in ("comments", "all")

    # Per-line matcher (Python re or substring; case folding done here).
    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid regex: {e}"}
        matcher = lambda s: bool(rx.search(s))
    elif case_sensitive:
        needle = pattern
        matcher = lambda s: needle in s
    else:
        needle = pattern.lower()
        matcher = lambda s: needle in s.lower()

    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    if start:
        try:
            start_ea = parse_address(start)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid start: {e}"}
    else:
        start_ea = segments[0][0]

    if end:
        try:
            end_ea = parse_address(end)
        except Exception as e:
            return {"n": 0, "hits": [], "cursor": {"done": True}, "error": f"invalid end: {e}"}
    else:
        end_ea = segments[-1][1]

    if end_ea <= start_ea:
        return {"n": 0, "hits": [], "cursor": {"done": True}}

    hits: list[SearchTextHit] = []
    next_cursor: int | None = None
    cancelled = False
    # Chunk the address space into fixed-size windows and call Heads() per
    # chunk. This bounds each Heads()/next_head() C call to one CHUNK_BYTES
    # scan — without it, a single next_head over a huge undefined gap can
    # run for tens of seconds without yielding to Python, so neither the
    # tool deadline nor the cancel flag can interrupt it.
    #
    # Between chunks we check (a) our own monotonic deadline directly
    # (independent of sync.py's Timer, which can be starved by GIL contention
    # on big binaries), and (b) the global cancel flag for UI-driven cancels.
    # Either path returns a partial result with cursor.cancelled=True.
    CHUNK_BYTES = 65536
    deadline = get_tool_deadline()

    for seg_start, seg_end in segments:
        if cancelled or len(hits) >= limit:
            break
        if seg_end <= start_ea:
            continue
        if seg_start >= end_ea:
            break
        walk_start = max(seg_start, start_ea)
        walk_end = min(seg_end, end_ea)
        chunk_ea = walk_start
        while chunk_ea < walk_end:
            if cancelled or len(hits) >= limit:
                break
            if (deadline is not None and time.monotonic() >= deadline) \
                or ida_kernwin.user_cancelled():
                cancelled = True
                next_cursor = chunk_ea
                break
            chunk_end = min(chunk_ea + CHUNK_BYTES, walk_end)
            for head_ea in idautils.Heads(chunk_ea, chunk_end):
                lines = _classify_hit_lines(head_ea, matcher, want_disasm, want_comments)
                if not lines:
                    continue
                entry: SearchTextHit = {"addr": hex(head_ea), "matches": lines}
                func = idaapi.get_func(head_ea)
                if func is not None:
                    fname = ida_funcs.get_func_name(func.start_ea)
                    if fname:
                        entry["function"] = fname
                seg = idaapi.getseg(head_ea)
                if seg is not None:
                    sname = ida_segment.get_segm_name(seg)
                    if sname:
                        entry["segment"] = sname
                hits.append(entry)
                if len(hits) >= limit:
                    size = max(1, idaapi.get_item_size(head_ea))
                    next_cursor = head_ea + size
                    break
            chunk_ea = chunk_end

    cursor: dict[str, Any]
    if cancelled:
        cursor = {"next": hex(next_cursor), "cancelled": True}
    elif next_cursor is not None:
        cursor = {"next": hex(next_cursor)}
    else:
        cursor = {"done": True}

    return {"n": len(hits), "hits": hits, "cursor": cursor}
