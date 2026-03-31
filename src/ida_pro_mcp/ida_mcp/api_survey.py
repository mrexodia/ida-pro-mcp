"""Binary survey tool -- complete triage in one call."""

from __future__ import annotations

import hashlib
import re
from itertools import islice
from typing import Annotated, TypedDict

from .rpc import tool
from .sync import idasync, tool_timeout
from . import compat
from .api_core import _get_strings_cache
from .utils import get_image_size


class SurveyMetadata(TypedDict):
    path: str
    module: str
    arch: str
    base_address: str
    image_size: str
    md5: str
    sha256: str


class SurveySegmentInfo(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


class SurveyEntrypoint(TypedDict):
    addr: str
    name: str
    ordinal: int


class SurveyStatistics(TypedDict):
    total_functions: int
    named_functions: int
    library_functions: int
    unnamed_functions: int
    total_strings: int
    total_segments: int


class SurveyInterestingString(TypedDict):
    addr: str
    string: str
    xref_count: int


class SurveyInterestingFunction(TypedDict):
    addr: str
    name: str
    size: int
    xref_count: int
    callee_count: int
    type: str


class SurveyImportEntry(TypedDict):
    addr: str
    name: str
    module: str


class SurveyImportsByCategory(TypedDict):
    crypto: list[SurveyImportEntry]
    network: list[SurveyImportEntry]
    file_io: list[SurveyImportEntry]
    process: list[SurveyImportEntry]
    registry: list[SurveyImportEntry]
    other: list[SurveyImportEntry]


class SurveyCallGraphSummary(TypedDict):
    total_edges: int
    max_depth_estimate: None
    root_functions: list[str]
    leaf_functions_count: int


class SurveyBinaryResult(TypedDict, total=False):
    metadata: SurveyMetadata
    statistics: SurveyStatistics
    segments: list[SurveySegmentInfo]
    entrypoints: list[SurveyEntrypoint]
    interesting_strings: list[SurveyInterestingString]
    interesting_functions: list[SurveyInterestingFunction]
    imports_by_category: SurveyImportsByCategory
    call_graph_summary: SurveyCallGraphSummary
    _note: str

# Max functions to iterate for xref counting on large binaries.
_MAX_FUNC_ITER = 10_000

# Max strings to process in _build_interesting_strings (perf cap).
_MAX_STRING_ITER = 5_000

# Max xrefs to materialize per string.
_MAX_XREFS_PER_STRING = 200

# Import category rules: keyword -> category name.
# Order matters: first match wins.
_IMPORT_CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    ("crypto", re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|\bssl\b|\btls\b|\bcert", re.IGNORECASE)),
    ("network", re.compile(r"socket|connect|send|recv|http|url|internet|ws2|winsock", re.IGNORECASE)),
    ("process", re.compile(r"process|thread|terminate|execute|shell|pipe|virtual", re.IGNORECASE)),
    ("registry", re.compile(r"reg|registry|hkey", re.IGNORECASE)),
    ("file_io", re.compile(r"file|path|directory|fopen|fclose|fread|fwrite|readfile|writefile|deletefile|createfile", re.IGNORECASE)),
]


def _classify_import(name: str) -> str:
    for category, pattern in _IMPORT_CATEGORIES:
        if pattern.search(name):
            return category
    return "other"


def _build_metadata() -> dict:
    import idaapi
    import idc
    import ida_nalt

    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())
    is_64 = compat.inf_is_64bit()

    input_path = ida_nalt.get_input_file_path()
    try:
        with open(input_path, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
    except Exception:
        md5 = sha256 = "unavailable"

    return {
        "path": path,
        "module": module,
        "arch": "64" if is_64 else "32",
        "base_address": base,
        "image_size": size,
        "md5": md5,
        "sha256": sha256,
    }


def _build_segments() -> list[dict]:
    import idaapi
    import idautils
    import ida_segment

    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        perms = []
        if seg.perm & idaapi.SEGPERM_READ:
            perms.append("r")
        if seg.perm & idaapi.SEGPERM_WRITE:
            perms.append("w")
        if seg.perm & idaapi.SEGPERM_EXEC:
            perms.append("x")
        segments.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.size()),
            "permissions": "".join(perms) or "---",
        })
    return segments


def _build_entrypoints() -> list[dict]:
    entrypoints = []
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        name = compat.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


def _build_statistics(func_eas: list[int], string_count: int, segment_count: int) -> dict:
    import idaapi
    import idc

    total = len(func_eas)
    named = 0
    library = 0
    unnamed = 0

    for ea in func_eas:
        name = idc.get_name(ea, 0) or ""
        func = idaapi.get_func(ea)
        flags = func.flags if func else 0

        if name.startswith("sub_"):
            unnamed += 1
        elif flags & idaapi.FUNC_LIB:
            library += 1
        else:
            named += 1

    return {
        "total_functions": total,
        "named_functions": named,
        "library_functions": library,
        "unnamed_functions": unnamed,
        "total_strings": string_count,
        "total_segments": segment_count,
    }


def _build_interesting_strings() -> list[dict]:
    import idautils

    strings = _get_strings_cache()

    if len(strings) > _MAX_STRING_ITER:
        strings = strings[:_MAX_STRING_ITER]

    scored: list[tuple[int, int, str]] = []

    for ea, s in strings:
        count = sum(1 for _ in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_STRING))
        if count == 0:
            continue
        scored.append((count, ea, s))

    scored.sort(key=lambda t: t[0], reverse=True)
    # Top 15 only — compact: string value + xref count, no referencing function lists.
    return [
        {"addr": hex(ea), "string": s, "xref_count": xref_count}
        for xref_count, ea, s in scored[:15]
    ]


def _is_library_func(ea: int, name: str, flags: int) -> bool:
    """A function is 'library' if it has a FLIRT signature."""
    import idaapi

    return bool(flags & idaapi.FUNC_LIB)


def _classify_func(ea: int, func, name: str, callee_count: int) -> str:
    """Classify function as thunk/wrapper/leaf/dispatcher/complex."""
    import idaapi

    flags = func.flags
    size = func.end_ea - func.start_ea
    if flags & idaapi.FUNC_THUNK or size <= 8:
        return "thunk"
    if callee_count == 1 and size < 100:
        return "wrapper"
    if callee_count == 0:
        return "leaf"
    if callee_count > 10:
        return "dispatcher"
    return "complex"


def _build_interesting_functions(func_eas: list[int], truncated: bool) -> list[dict]:
    import idaapi
    import idautils
    import idc

    candidates: list[tuple[int, int, str, int, int]] = []

    for ea in func_eas:
        func = idaapi.get_func(ea)
        if not func:
            continue
        name = idc.get_name(ea, 0) or ""
        flags = func.flags

        if _is_library_func(ea, name, flags):
            continue

        xref_count = len(list(idautils.XrefsTo(ea, 0)))
        size = func.size()
        candidates.append((xref_count, ea, name, size, flags))

    candidates.sort(key=lambda t: t[0], reverse=True)
    # Top 15 with classification hints.
    top = candidates[:15]

    result = []
    for xref_count, ea, name, size, _flags in top:
        func = idaapi.get_func(ea)
        callee_count = 0
        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    callee_count += 1

        classification = _classify_func(ea, func, name, callee_count)
        result.append({
            "addr": hex(ea),
            "name": name,
            "size": size,
            "xref_count": xref_count,
            "callee_count": callee_count,
            "type": classification,
        })
    return result


def _build_imports_by_category() -> dict[str, list[dict]]:
    import ida_nalt

    categories: dict[str, list[dict]] = {
        "crypto": [],
        "network": [],
        "file_io": [],
        "process": [],
        "registry": [],
        "other": [],
    }

    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

        collected: list[tuple[int, str]] = []

        def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
            name = symbol_name if symbol_name else f"#{ordinal}"
            collected.append((ea, name))
            return True

        ida_nalt.enum_import_names(i, imp_cb)

        for ea, name in collected:
            cat = _classify_import(name)
            categories[cat].append({
                "addr": hex(ea),
                "name": name,
                "module": module_name,
            })

    return categories


def _build_call_graph_summary(func_eas: list[int]) -> dict:
    import idaapi
    import idautils

    total_edges = 0
    root_functions: list[str] = []
    leaf_count = 0

    for ea in func_eas:
        has_callers = False
        has_callees = False

        # Check incoming xrefs (callers)
        for xref in idautils.XrefsTo(ea, 0):
            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                has_callers = True
                break

        # Check outgoing code refs (callees)
        for item_ea in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    total_edges += 1
                    has_callees = True

        if not has_callers:
            name = idaapi.get_name(ea) or hex(ea)
            root_functions.append(name)
        if not has_callees:
            leaf_count += 1

    return {
        "total_edges": total_edges,
        "max_depth_estimate": None,  # would require full DFS; omitted for performance
        "root_functions": root_functions[:100],  # cap to avoid massive output
        "leaf_functions_count": leaf_count,
    }



@tool
@idasync
@tool_timeout(120.0)
def survey_binary(
    detail_level: Annotated[str, "Detail level: 'standard' or 'minimal'"] = "standard",
) -> SurveyBinaryResult:
    """Get a compact overview of the binary in one call. Returns file metadata,
    segment layout, entry points, statistics, top 15 strings and functions ranked
    by xref count (functions include classification: thunk/wrapper/leaf/dispatcher/
    complex), imports by category, and call graph summary. Use this as your FIRST
    tool call when starting analysis. Do not call list_funcs, imports, or find_regex
    separately for triage — this returns all of that. Use detail_level='minimal'
    for binaries with >10k functions."""
    import idautils

    minimal = detail_level == "minimal"

    # Collect all function addresses once, cap at _MAX_FUNC_ITER for large binaries.
    all_func_eas = list(idautils.Functions())
    truncated = len(all_func_eas) > _MAX_FUNC_ITER
    if truncated:
        func_eas = all_func_eas[:_MAX_FUNC_ITER]
    else:
        func_eas = all_func_eas

    strings = _get_strings_cache()
    segments = _build_segments()

    result: dict = {
        "metadata": _build_metadata(),
        "statistics": _build_statistics(
            all_func_eas, len(strings), len(segments)
        ),
        "segments": segments,
        "entrypoints": _build_entrypoints(),
    }

    if not minimal:
        result["interesting_strings"] = _build_interesting_strings()
        result["interesting_functions"] = _build_interesting_functions(func_eas, truncated)
        result["imports_by_category"] = _build_imports_by_category()
        result["call_graph_summary"] = _build_call_graph_summary(func_eas)

    if truncated:
        result["_note"] = (
            f"Binary has {len(all_func_eas)} functions; "
            f"xref analysis was limited to the first {_MAX_FUNC_ITER} for performance."
        )

    return result
