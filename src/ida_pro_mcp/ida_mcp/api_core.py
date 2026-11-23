"""Core API Functions - IDB metadata and basic queries"""

import logging
import re
import sys
import time
from typing import Annotated, Any, NotRequired, TypedDict

import ida_auto
import ida_bytes
import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_search
import ida_segment
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import idc

from .mainthread import get_pump
from .rpc import tool
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


class ServerHealthResult(TypedDict, total=False):
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
    busy_tool: str
    busy_sec: float
    queued_calls: int


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
_server_started_at = time.time()


def _get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access.

    Both ASCII (C-style) and UTF-16 (wide) strings are scanned so that
    ``find_regex`` can locate wide-char strings, which are common in Unreal
    Engine and Windows binaries. ``idautils.Strings()`` defaults to
    ``strtypes=[0]`` (C strings only), missing UTF-16 content — see #263.
    """
    global _strings_cache
    if _strings_cache is None:
        strings = idautils.Strings()
        # strtype 0 = C (ASCII/UTF-8), strtype 1 = Unicode C-Style (UTF-16).
        strings.setup(strtypes=[0, 1])
        _strings_cache = [(s.ea, str(s)) for s in strings if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None
    http_mod = sys.modules.get(f"{__package__}.http")
    if http_mod is not None and hasattr(http_mod, "invalidate_cors_policy_cache"):
        http_mod.invalidate_cors_policy_cache()


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = _get_strings_cache()
    t1 = time.perf_counter()
    logger.info("[MCP] Cached %d strings in %.0fms", len(strings), (t1 - t0) * 1000)
    http_mod = sys.modules.get(f"{__package__}.http")
    if http_mod is not None and hasattr(http_mod, "refresh_cors_policy_on_main_thread"):
        http_mod.refresh_cors_policy_on_main_thread()


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


@idasync
def _server_health_full() -> ServerHealthResult:
    return _build_health_payload()


@tool
def server_health() -> ServerHealthResult:
    """Health/ready probe for MCP server and current IDB state."""
    # Every field below needs the IDA main thread. Report the busy state
    # rather than queueing behind the very call we are meant to observe.
    busy = get_pump().busy_status()
    if busy is not None:
        return {
            "status": "busy",
            "uptime_sec": round(time.time() - _server_started_at, 3),
            "busy_tool": busy["tool"],
            "busy_sec": busy["elapsed_sec"],
            "queued_calls": busy["queued"],
        }
    return _server_health_full()


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


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[LookupFuncResult]:
    """Get functions by address or name (auto-detects)"""
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


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[IntConvertResult]:
    """Convert numbers to different formats"""
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


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(queries)
    remaining_unfiltered = sum(
        1 for q in queries if q.get("filter", "") in ("", "*")
    )
    remaining_filtered = len(queries) - remaining_unfiltered
    reuse_across_queries = len(queries) > 1
    func_eas: list[int] | None = None
    func_cache: dict[int, Function] | None = (
        {} if reuse_across_queries and remaining_unfiltered > 0 else None
    )
    all_functions: list[Function] | None = None

    def get_func_entry(addr: int) -> Function:
        if func_cache is not None and remaining_filtered == 0:
            fn = func_cache.get(addr)
            if fn is None:
                fn = get_function(addr)
                func_cache[addr] = fn
            return fn
        return get_function(addr)

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            remaining_unfiltered -= 1
            eas = func_eas if func_eas is not None else list(idautils.Functions())
            if reuse_across_queries and (remaining_unfiltered > 0 or remaining_filtered > 0):
                func_eas = eas
            else:
                func_eas = None
            total = len(eas)
            eff_count = total if count == 0 else count
            next_offset = offset + eff_count
            if next_offset >= total:
                next_offset = None
            results.append(
                {
                    "data": [
                        get_func_entry(addr)
                        for addr in eas[offset : offset + eff_count]
                    ],
                    "next_offset": next_offset,
                }
            )
            if remaining_unfiltered == 0 and func_cache is not None:
                func_cache.clear()
            continue

        remaining_filtered -= 1
        if all_functions is None:
            eas_iter = func_eas if func_eas is not None else idautils.Functions()
            if remaining_filtered > 0:
                all_functions = [get_function(addr) for addr in eas_iter]
                rows_source = all_functions
            else:
                rows_source = [get_function(addr) for addr in eas_iter]
        else:
            rows_source = all_functions
            if remaining_filtered == 0:
                all_functions = None

        if remaining_unfiltered == 0 and remaining_filtered == 0:
            func_eas = None

        filtered = pattern_filter(rows_source, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery,
        "Richer function query (size/type/name filters + pagination)",
    ],
) -> list[FunctionQueryPage]:
    """Query functions with richer filtering than list_funcs."""
    queries = normalize_dict_list(queries)

    raw_funcs: list[tuple[int, int]] | None = None
    name_cache: dict[int, str] = {}
    tinfo_cache: dict[int, bool] = {}

    def get_raw_funcs() -> list[tuple[int, int]]:
        nonlocal raw_funcs
        if raw_funcs is None:
            collected: list[tuple[int, int]] = []
            for addr in idautils.Functions():
                fn = idaapi.get_func(addr)
                if not fn:
                    continue
                collected.append((fn.start_ea, fn.end_ea - fn.start_ea))
            raw_funcs = collected
        return raw_funcs

    def get_name(ea: int) -> str:
        name = name_cache.get(ea)
        if name is None:
            name = ida_funcs.get_func_name(ea) or "<unnamed>"
            name_cache[ea] = name
        return name

    def get_has_type(ea: int) -> bool:
        has_type = tinfo_cache.get(ea)
        if has_type is None:
            has_type = bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), ea))
            tinfo_cache[ea] = has_type
        return has_type

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 50)
        sort_by = query.get("sort_by", "addr")
        descending = bool(query.get("descending", False))
        if sort_by not in ("addr", "name", "size"):
            sort_by = "addr"

        name_regex = query.get("name_regex", "")
        compiled_regex = None
        if name_regex:
            try:
                compiled_regex = re.compile(name_regex)
            except re.error:
                results.append(paginate([], offset, count))
                continue

        candidates = get_raw_funcs()

        min_size = query.get("min_size")
        if min_size is not None:
            min_size_int = int(min_size)
            candidates = [(ea, sz) for ea, sz in candidates if sz >= min_size_int]

        max_size = query.get("max_size")
        if max_size is not None:
            max_size_int = int(max_size)
            candidates = [(ea, sz) for ea, sz in candidates if sz <= max_size_int]

        name_filter = query.get("filter", "")
        if name_filter:
            named_items = [
                {"ea": ea, "size_int": sz, "name": get_name(ea)}
                for ea, sz in candidates
            ]
            filtered_dicts = pattern_filter(named_items, name_filter, "name")
            candidates = [(d["ea"], d["size_int"]) for d in filtered_dicts]

        if compiled_regex is not None:
            candidates = [
                (ea, sz) for ea, sz in candidates if compiled_regex.search(get_name(ea))
            ]

        if "has_type" in query:
            require_type = bool(query.get("has_type"))
            candidates = [
                (ea, sz) for ea, sz in candidates if get_has_type(ea) is require_type
            ]

        if sort_by == "name":
            candidates = sorted(
                candidates, key=lambda item: get_name(item[0]).lower(), reverse=descending
            )
        elif sort_by == "size":
            candidates = sorted(
                candidates, key=lambda item: item[1], reverse=descending
            )
        else:
            candidates = sorted(
                candidates, key=lambda item: item[0], reverse=descending
            )

        page = paginate(candidates, offset, count)
        page["data"] = [
            {
                "addr": hex(ea),
                "name": get_name(ea),
                "size": hex(sz),
                "has_type": get_has_type(ea),
            }
            for ea, sz in page["data"]
        ]
        results.append(page)

    return results


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(queries)
    raw_globals: list[tuple[int, str]] | None = None
    all_globals: list[Global] | None = None

    def get_raw_globals() -> list[tuple[int, str]]:
        nonlocal raw_globals
        if raw_globals is None:
            raw_globals = [
                (addr, name)
                for addr, name in idautils.Names()
                if not idaapi.get_func(addr) and name is not None
            ]
        return raw_globals

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            items = get_raw_globals()
            total = len(items)
            eff_count = total if count == 0 else count
            next_offset = offset + eff_count
            if next_offset >= total:
                next_offset = None
            results.append(
                {
                    "data": [
                        Global(addr=hex(addr), name=name)
                        for addr, name in items[offset : offset + eff_count]
                    ],
                    "next_offset": next_offset,
                }
            )
            continue

        if all_globals is None:
            all_globals = [
                Global(addr=hex(addr), name=name) for addr, name in get_raw_globals()
            ]
        filtered = pattern_filter(all_globals, filter_pattern, "name")
        results.append(paginate(filtered, offset, count))

    return results


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[EntityQueryPage]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(queries)
    results: list[dict] = []
    entity_cache: dict[str, list[dict]] = {}
    func_rows_base: list[dict] | None = None
    kind_remaining: dict[str, int] = {}
    for q in queries:
        k = str(q.get("kind", "functions") or "functions").lower()
        if k in {"functions", "globals", "imports", "strings", "names"}:
            kind_remaining[k] = kind_remaining.get(k, 0) + 1

    def _collect_func_rows_base() -> list[dict]:
        collected: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            collected.append(
                {
                    "kind": "function",
                    "_ea": fn.start_ea,
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                }
            )
        return collected

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

        kind_remaining[kind] -= 1
        keep_cached = kind_remaining[kind] > 0

        segment_filter = str(query.get("segment", "") or "")
        sort_by = str(query.get("sort_by", "addr") or "addr")
        fields_raw = query.get("fields")
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]

        if kind == "functions":
            if keep_cached:
                if func_rows_base is None:
                    func_rows_base = _collect_func_rows_base()
                rows = list(func_rows_base)
            elif func_rows_base is not None:
                rows = func_rows_base
                func_rows_base = None
            else:
                rows = _collect_func_rows_base()
            need_seg_early = bool(segment_filter) or sort_by == "segment"
            need_type_early = sort_by == "has_type"
            if need_seg_early or need_type_early:
                enriched_rows: list[dict] = []
                for row in rows:
                    if need_seg_early and "segment" not in row:
                        row["segment"] = _segment_name_for_ea(row["_ea"])
                    if need_type_early and "has_type" not in row:
                        row["has_type"] = bool(
                            ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), row["_ea"])
                        )
                    enriched_rows.append(row)
                rows = enriched_rows
        else:
            if keep_cached:
                if kind not in entity_cache:
                    entity_cache[kind] = _collect_entities(kind)
                rows = list(entity_cache[kind])
            else:
                cached_rows = entity_cache.pop(kind, None)
                rows = (
                    cached_rows
                    if cached_rows is not None
                    else _collect_entities(kind)
                )

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

        if segment_filter and kind in {"functions", "globals", "strings", "names"}:
            rows = pattern_filter(rows, segment_filter, "segment")

        module_filter = str(query.get("module", "") or "")
        if module_filter and kind == "imports":
            rows = pattern_filter(rows, module_filter, "module")

        def _row_ea(row: dict) -> int:
            ea = row.get("_ea")
            if ea is not None:
                return ea
            return int(str(row.get("addr", "0x0")), 16)

        min_addr = query.get("min_addr")
        if min_addr not in (None, ""):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if _row_ea(row) >= min_ea]
            except Exception:
                rows = []

        max_addr = query.get("max_addr")
        if max_addr not in (None, ""):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if _row_ea(row) <= max_ea]
            except Exception:
                rows = []

        descending = bool(query.get("descending", False))
        if sort_by == "addr":
            rows.sort(key=_row_ea, reverse=descending)
        elif sort_by in {"size", "length"}:
            rows.sort(
                key=lambda row: (
                    row["size_int"]
                    if "size_int" in row
                    else _coerce_sort_number(row.get(sort_by, 0))
                ),
                reverse=descending,
            )
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

        offset = int(query.get("offset", 0) or 0)
        count = int(query["count"]) if query.get("count") is not None else 100
        page = paginate(rows, offset, count)

        keep_fields: set[str] | None = None
        if fields is not None:
            normalized_fields = {str(f).strip() for f in fields if str(f).strip()}
            if normalized_fields:
                keep_fields = normalized_fields
        data: list[dict] = []
        for item in page["data"]:
            ea_val = item.get("_ea")
            out = {k: v for k, v in item.items() if k not in ("size_int", "_ea")}
            if kind == "functions" and ea_val is not None:
                if (keep_fields is None or "segment" in keep_fields) and "segment" not in out:
                    out["segment"] = _segment_name_for_ea(ea_val)
                if (keep_fields is None or "has_type" in keep_fields) and "has_type" not in out:
                    out["has_type"] = bool(
                        ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), ea_val)
                    )
            data.append(out)

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


@tool
@idasync
def imports(
    offset: Annotated[int, "Starting pagination index (default: 0)"],
    count: Annotated[int, "Maximum rows (0 returns all imports)"],
) -> Page[Import]:
    """List imports with module names using offset/count pagination."""
    return paginate(_collect_imports(), offset, count)


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery,
        "Import query with import/module filters and pagination",
    ],
) -> list[ImportsQueryPage]:
    """Query imports with richer filtering than imports(offset,count)."""
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


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> IdbSaveResult:
    """Save active IDB to disk, optionally to a provided path.

    The open database is backed by loose working files (.id0/.id1/.id2/.nam/.til)
    that IDA actively manages, headless included. Killing them out from under the
    open database corrupts it (issues #446, #498), so DBFL_KILL is never used
    here: an in-place save uses IDA's native save (Ctrl+W), and an explicit
    different destination gets a compressed copy while the working files stay.
    """
    try:
        save_path = path.strip() if path else ""
        current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            save_path = current
        if not save_path:
            return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

        if save_path != current:
            ok = bool(ida_loader.save_database(save_path, ida_loader.DBFL_COMP))
        else:
            ok = bool(ida_loader.save_database(None, 0))

        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return result
    except Exception as e:
        return {"ok": False, "path": path or None, "error": str(e)}


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> FindRegexResult:
    """Search strings by case-insensitive regex with offset/limit pagination."""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500

    matches = []
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {
            "n": 0,
            "matches": [],
            "cursor": {"done": True},
            "error": f"Invalid regex: {e}",
        }
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


@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to search for in the rendered listing (literal substring by default)"],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Lower bound (hex or symbol). Empty = first segment."] = "",
    end: Annotated[str, "Upper bound (hex or symbol, exclusive). Empty = last segment."] = "",
    regex: Annotated[bool, "Treat pattern as a Python regex"] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match (default: false)"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments (default: true)"] = True,
) -> SearchTextResult:
    """Search the rendered listing for `pattern` over [start, end).

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
