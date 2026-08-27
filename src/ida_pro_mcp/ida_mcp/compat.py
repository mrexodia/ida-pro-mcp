"""
IDA Pro API Compatibility Layer

This module wraps IDA APIs that differ between IDA 9.0+ and older versions,
providing a unified interface.

Compatibility notes:
- IDA 9.0: some idaapi methods removed, uses ida_entry, ida_ida
- IDA 8.5: idaapi.get_inf_structure methods removed, ida_funcs.func_t api update
- IDA 8.4: uses ida_typeinf.get_ordinal_limit
- IDA <8.4: uses idaapi.get_inf_structure, ida_typeinf.get_ordinal_qty, etc.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable, cast

import idaapi
import ida_bytes
import ida_frame
import ida_funcs
import ida_nalt
import ida_segment
import ida_typeinf
import idc

# ============================================================================
# Version resolution
# ============================================================================


def _parse_kernel_version(v: str) -> tuple[int, int, int]:
    # Parse formats like "9.2", "9.2.0", "9.2sp1"
    nums = [int(x) for x in re.findall(r"\d+", v)]
    major = nums[0] if len(nums) > 0 else 0
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    return (major, minor, patch)


def _check_required_apis(version: tuple[int, int, int]) -> None:
    """
    Check that required Python APIs are available.

    IDA 9.0 initial release (build 240925) is missing several Python API methods
    that were added in 8.5 and later reinstated in 9.0 SP1 (build 241217).
    Rather than adding compatibility hacks, we explicitly reject this version.

    Older IDA versions (<8.5) legitimately lack these methods; the wrappers in
    this module (get_func_name, get_func_prototype, tinfo_get_udm) provide
    fallbacks, so we only enforce the check on IDA 9.0+.
    """
    # Only IDA 9.0+ is expected to have these methods natively. Pre-8.5 versions
    # are handled via fallback wrappers in this module.
    if version < (9, 0, 0):
        return

    missing = []

    # Check func_t methods (added in 8.5, missing in 9.0 SP0)
    func = ida_funcs.func_t()
    if not hasattr(func, "get_name"):
        missing.append("func_t.get_name")
    if not hasattr(func, "get_prototype"):
        missing.append("func_t.get_prototype")

    # Check tinfo_t methods (added in 8.5, missing in 9.0 SP0)
    tif = ida_typeinf.tinfo_t()
    if not hasattr(tif, "get_udm"):
        missing.append("tinfo_t.get_udm")

    if missing:
        ver_str = idaapi.get_kernel_version()
        raise RuntimeError(
            f"IDA Pro {ver_str} is missing required Python API methods: "
            f"{', '.join(missing)}. "
            f"If using IDA 9.0, please upgrade to IDA 9.0 SP1 or later."
        )


if TYPE_CHECKING:
    import ida_entry
    import ida_ida
    import ida_hexrays

    IDA_VERSION: tuple[int, int, int] = cast(tuple[int, int, int], (9, 2, 0))
else:
    IDA_VERSION = _parse_kernel_version(idaapi.get_kernel_version())

IDA_GE_90 = IDA_VERSION >= (9, 0, 0)
IDA_GE_85 = IDA_VERSION >= (8, 5, 0)
IDA_GE_84 = IDA_VERSION >= (8, 4, 0)

# ============================================================================
# Version-gated imports
# ============================================================================

if IDA_GE_90:
    import ida_ida

if IDA_GE_84:
    import ida_entry

if not IDA_GE_84:
    import ida_hexrays

# ============================================================================
# Entry point compatibility
# ============================================================================

# Entry-point APIs have moved between modules across IDA versions:
#   - IDA 9.0+:    ida_entry.*
#   - IDA 8.4-8.x: ida_entry.* (also still in ida_nalt in some builds)
#   - IDA <8.4:    idaapi.* / ida_nalt.* depending on build
# Resolve them once at import time by probing the candidate modules.


def _resolve_entry_api(name: str) -> Callable:
    candidates = []
    if IDA_GE_84:
        # ida_entry was imported above when IDA_GE_84
        candidates.append(ida_entry)
    candidates.append(ida_nalt)
    candidates.append(idaapi)
    for mod in candidates:
        fn = getattr(mod, name, None)
        if fn is not None:
            return fn
    raise AttributeError(
        f"IDA Pro {idaapi.get_kernel_version()} does not expose '{name}' "
        f"in ida_entry, ida_nalt, or idaapi"
    )


_get_entry_qty = _resolve_entry_api("get_entry_qty")
_get_entry_ordinal = _resolve_entry_api("get_entry_ordinal")
_get_entry = _resolve_entry_api("get_entry")
_get_entry_name = _resolve_entry_api("get_entry_name")


def get_entry_qty() -> int:
    return _get_entry_qty()


def get_entry_ordinal(idx: int) -> int:
    return _get_entry_ordinal(idx)


def get_entry(ordinal: int) -> int:
    return _get_entry(ordinal)


def get_entry_name(ordinal: int) -> str | None:
    return _get_entry_name(ordinal)


# ============================================================================
# Type ordinal compatibility
# ============================================================================


def get_ordinal_limit(til: ida_typeinf.til_t | None = None) -> int:
    if IDA_GE_84:
        return (
            ida_typeinf.get_ordinal_limit(til)
            if til is not None
            else ida_typeinf.get_ordinal_limit()
        )
    return (
        ida_typeinf.get_ordinal_qty(til)
        if til is not None
        else ida_typeinf.get_ordinal_qty()
    )


# ============================================================================
# inf structure compatibility
# ============================================================================


def inf_get_min_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea


def inf_get_max_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea


def inf_get_omin_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_omin_ea()
    return idaapi.get_inf_structure().omin_ea


def inf_get_omax_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_omax_ea()
    return idaapi.get_inf_structure().omax_ea


def inf_is_64bit() -> bool:
    if IDA_GE_85:
        return ida_ida.inf_is_64bit()
    return idaapi.get_inf_structure().is_64bit()


# ============================================================================
# Function info compatibility
# ============================================================================


def _resolve_func_entry_info_api() -> tuple[Callable, Callable] | None:
    getter = getattr(ida_funcs, "get_func_entry_info", None)
    info_type = getattr(ida_funcs, "func_entry_info_t", None)
    if getter is None or info_type is None:
        return None
    return getter, info_type


_FUNC_ENTRY_INFO_API = _resolve_func_entry_info_api()
HAS_FUNC_ENTRY_INFO = _FUNC_ENTRY_INFO_API is not None


def get_func_info(ea: int, flags: int = 0):
    """Return function entry information for any address in a function.

    IDA 9.4 deprecated ``get_func()`` because it exposes a borrowed ``func_t``
    pointer.  The replacement is an output-parameter API that returns a stable
    copy of the function entry information.  Older IDA versions are kept on
    their original API behind this compatibility boundary.

    ``flags`` is a combination of ``GFI_*``.  It defaults to 0 (no optional
    string field is fetched): every caller in this project reads the name or
    comments through :func:`get_func_name` / :func:`get_func_comment`, which do
    not depend on the entry-info string fields.  Requesting ``GFI_NAME`` here
    would copy a qstring on every call, and these calls happen per-address in
    several loops.
    """
    if _FUNC_ENTRY_INFO_API is not None:
        get_entry_info, entry_info_type = _FUNC_ENTRY_INFO_API
        info = entry_info_type()
        if get_entry_info(info, ea, flags):
            return info
        return None

    # IDA versions predating func_entry_info_t do not emit the 9.4 warning.
    return ida_funcs.get_func(ea)


def func_start_ea(ea: int) -> int:
    """Start EA of the function containing *ea*, or ``BADADDR``.

    Cheap replacement for ``get_func(ea)`` at call sites that only need to know
    whether *ea* belongs to a function, or the entry address of that function.
    Tail chunks resolve to their owning function, exactly like ``get_func()``.
    """
    get_start = getattr(ida_funcs, "get_func_start", None)
    if get_start is not None:
        return get_start(ea)
    func = get_func_info(ea)
    return func.start_ea if func is not None else idaapi.BADADDR


def in_function(ea: int) -> bool:
    """Is *ea* inside a function (entry or tail chunk)?"""
    return func_start_ea(ea) != idaapi.BADADDR


def func_flags_at(ea: int) -> int:
    """Function chunk flags at *ea*, or 0 when there is no chunk.

    ``ida_funcs.get_func_flags()`` reports the flags of the *chunk* at *ea*, so
    only pass a chunk start (a function entry EA in practice); for an arbitrary
    interior address use ``get_func_flags(get_func_info(ea))`` instead.
    """
    get_flags = getattr(ida_funcs, "get_func_flags", None)
    if get_flags is not None:
        try:
            return int(get_flags(ea))
        except TypeError:
            # Very old builds exported get_func_flags(func_t *).
            pass
    func = get_func_info(ea)
    return get_func_flags(func) if func is not None else 0


def get_func_flags(func) -> int:
    """Read function flags from either func_t or func_entry_info_t."""
    get_flags = getattr(func, "get_flags", None)
    return int(get_flags() if get_flags is not None else func.flags)


def get_func_frame_id(func):
    """Read the frame structure id from either function representation."""
    get_frame_id = getattr(func, "get_frame_id", None)
    return get_frame_id() if get_frame_id is not None else func.frame


def get_func_comment(ea: int, repeatable: bool) -> str:
    """Read a function comment without materializing a deprecated func_t."""
    get_cmt_ea = getattr(ida_funcs, "get_func_cmt_ea", None)
    if get_cmt_ea is not None:
        return get_cmt_ea(ea, repeatable) or ""

    if _FUNC_ENTRY_INFO_API is not None:
        get_entry_info, entry_info_type = _FUNC_ENTRY_INFO_API
        info = entry_info_type()
        flag = getattr(ida_funcs, "GFI_CMT_RPT" if repeatable else "GFI_CMT")
        if get_entry_info(info, ea, flag):
            return (info.get_cmt_rpt() if repeatable else info.get_cmt()) or ""
        return ""

    return idc.get_func_cmt(ea, repeatable) or ""


def set_func_comment(ea: int, comment: str, repeatable: bool) -> bool | None:
    """Write a function comment through the address-based IDA API."""
    set_comment = getattr(ida_funcs, "set_func_cmt_ea", None)
    if set_comment is not None:
        return bool(set_comment(ea, comment, repeatable))
    return idc.set_func_cmt(ea, comment, repeatable)


def function_eas(start: int | None = None, end: int | None = None):
    """Iterate function entry addresses using the EA-based function API.

    Mirrors ``idautils.Functions()`` exactly (which still routes through the
    deprecated ``get_fchunk()`` / ``get_next_func()`` in IDA 9.4): start at the
    chunk containing *start* (or the next one), skip leading tail chunks, then
    walk function entries while they start below *end*.  As in ``Functions()``,
    the first yielded entry may start before *start* and the last one may extend
    past *end*.
    """
    get_fchunk_start = getattr(ida_funcs, "get_fchunk_start", None)
    get_next_fchunk_ea = getattr(ida_funcs, "get_next_fchunk_ea", None)
    is_tail = getattr(ida_funcs, "is_function_tail", None)
    get_next_func_ea = getattr(ida_funcs, "get_next_func_ea", None)
    if (
        get_fchunk_start is None
        or get_next_fchunk_ea is None
        or is_tail is None
        or get_next_func_ea is None
    ):
        import idautils

        yield from idautils.Functions(start, end)
        return

    if start is None:
        start = inf_get_min_ea()
    if end is None:
        end = inf_get_max_ea()

    chunk_ea = get_fchunk_start(start)
    if chunk_ea == idaapi.BADADDR:
        chunk_ea = get_next_fchunk_ea(start)

    # Skip leading tail chunks: they are not function entries.
    while chunk_ea != idaapi.BADADDR and chunk_ea < end and is_tail(chunk_ea):
        chunk_ea = get_next_fchunk_ea(chunk_ea)

    func_ea = chunk_ea
    while func_ea != idaapi.BADADDR and func_ea < end:
        yield func_ea
        func_ea = get_next_func_ea(func_ea)


def function_items(func_ea: int):
    """Iterate the code items of a function through function_item_iterator_t.

    ``idautils.FuncItems()`` iterates ``first()`` / ``next_code()`` (see the
    ``__iter__`` generator installed on ``func_item_iterator_t``), i.e. code
    items, not every address in the function.  ``next_addr()`` would walk the
    function byte by byte and is *not* the same generator, so the EA-based
    iterator has to be driven with ``next_code()`` to keep the item counts and
    the disassembly listings identical.
    """
    iterator_type = getattr(ida_funcs, "function_item_iterator_t", None)
    if iterator_type is None:
        import idautils

        yield from idautils.FuncItems(func_ea)
        return

    iterator = iterator_type(func_ea)
    ok = iterator.first()
    while ok:
        yield iterator.current()
        ok = iterator.next_code()


def get_func_name(func) -> str | None:
    """Resolve the function name for either function representation.

    ``func_t.get_name()`` is implemented as ``get_func_name(start_ea)``, so this
    is behaviour-preserving for the old representation.  It must *not* be routed
    through ``func_entry_info_t.get_name()``: that returns the raw ``name_``
    field, which is only populated when ``get_func_entry_info()`` was called
    with ``GFI_NAME``, and it yields an empty string (never the generated
    ``sub_...`` name) instead of ``None`` for unnamed functions.
    """
    return ida_funcs.get_func_name(func.start_ea)


def get_func_prototype(func) -> ida_typeinf.tinfo_t | None:
    """Return the prototype tinfo_t of *func*, or None.

    ``func_entry_info_t`` has no ``get_prototype()``, so on IDA 9.4 this always
    takes the ``ida_nalt.get_tinfo()`` branch below -- which is what
    ``func_t.get_prototype()`` does internally, plus an ``is_func()`` guard.
    """
    # func_t.get_prototype() introduced in 8.5, but missing in early 9.0 builds (build 240925)
    # Use hasattr() to handle early IDA 9.0 builds that lack the method
    if IDA_GE_85 and hasattr(func, "get_prototype"):
        return func.get_prototype()

    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        return tif
    return None


# ============================================================================
# Segment info compatibility
# ============================================================================


def get_segment_info(ea: int):
    """Return segment information for *ea* without using the legacy segment API."""
    get_info = getattr(ida_segment, "get_segment_info", None)
    info_type = getattr(ida_segment, "segment_info_t", None)
    if get_info is not None and info_type is not None:
        info = info_type()
        if get_info(info, ea):
            return info
        return None

    # IDA versions predating segment_info_t do not emit the 9.4 warning.
    return idaapi.getseg(ea)


def get_segment_name(ea: int) -> str | None:
    """Return the segment name using an address-based lookup."""
    get_name = getattr(ida_segment, "get_segment_name", None)
    if get_name is not None:
        return get_name(ea) or None

    seg = get_segment_info(ea)
    if seg is None:
        return None
    return idaapi.get_segm_name(seg)


def segment_eas():
    """Iterate segment start addresses without the legacy segment pointers."""
    get_first = getattr(ida_segment, "get_first_segment_ea", None)
    get_next = getattr(ida_segment, "get_next_segment_ea", None)
    if get_first is not None and get_next is not None:
        seg_ea = get_first()
        while seg_ea != idaapi.BADADDR:
            yield seg_ea
            seg_ea = get_next(seg_ea)
        return

    import idautils

    yield from idautils.Segments()


def get_segment_perm(segment) -> int:
    get_perm = getattr(segment, "get_perm", None)
    return int(get_perm() if get_perm is not None else segment.perm)


def get_segment_type(segment) -> int:
    get_type = getattr(segment, "get_type", None)
    return int(get_type() if get_type is not None else segment.type)


def get_segment_size(segment) -> int:
    return int(segment.end_ea - segment.start_ea)


# ============================================================================
# EA-based flow charts
# ============================================================================


class _FunctionFlowBlock:
    """Adapter exposing ``ida_gdl.BasicBlock``'s interface over qflow_chart_ea_t.

    ``id`` / ``start_ea`` / ``end_ea`` / ``type`` and the ``succs()`` /
    ``preds()`` generators match ``ida_gdl.BasicBlock``.  Like ``BasicBlock``,
    the generators yield the chart's own block objects, so only ``start_ea`` and
    ``end_ea`` are guaranteed on the yielded neighbours.  The chart is kept alive
    by the reference held here: objects returned by ``chart[i]`` point into the
    chart's block vector.
    """

    def __init__(self, chart, index: int):
        block = chart[index]
        self.id = index
        self.start_ea = block.start_ea
        self.end_ea = block.end_ea
        self.type = chart.calc_block_type(index)
        self._chart = chart
        self._index = index

    def succs(self):
        return (
            self._chart[self._chart.succ(self._index, i)]
            for i in range(self._chart.nsucc(self._index))
        )

    def preds(self):
        return (
            self._chart[self._chart.pred(self._index, i)]
            for i in range(self._chart.npred(self._index))
        )


def function_flow_blocks(func_ea: int) -> list:
    """Return the basic blocks of a function using the EA-based flow API.

    ``ida_gdl.FlowChart(func)`` builds ``qflow_chart_t("", func, BADADDR,
    BADADDR, 0)``; the bounds only matter for range-based charts, so the
    EA-based chart is built with the same ``(BADADDR, BADADDR)`` sentinel bounds
    instead of ``(0, 0)``.
    """
    import ida_gdl

    func_start = func_start_ea(func_ea)
    if func_start == idaapi.BADADDR:
        return []

    chart_type = getattr(ida_gdl, "qflow_chart_ea_t", None)
    if chart_type is not None:
        chart = chart_type("", func_start, idaapi.BADADDR, idaapi.BADADDR, 0)
        return [_FunctionFlowBlock(chart, i) for i in range(chart.size())]

    # Older IDA versions lack the EA-based chart and the deprecated API is
    # still the native API there.
    func = get_func_info(func_start)
    return list(idaapi.FlowChart(func)) if func is not None else []


# ============================================================================
# Stack frame compatibility
# ============================================================================

# IDA 9.4 deprecated every ida_frame entry point that takes a func_t* in favour
# of an "_ea" variant.  The wrappers below accept the function object returned by
# get_func_info() so a single call site works on both API generations: on 9.4
# they forward the start EA, on older builds they forward the func_t itself.


def get_func_frame(tif, func) -> bool:
    """Fetch the frame type of *func* into *tif*."""
    fn = getattr(ida_frame, "get_func_frame_ea", None)
    if fn is not None:
        return bool(fn(tif, func.start_ea))
    return bool(ida_frame.get_func_frame(tif, func))


def soff_to_fpoff(func, soff: int) -> int:
    """Convert a frame-structure offset into an fp-relative offset."""
    fn = getattr(ida_frame, "soff_to_fpoff_ea", None)
    if fn is not None:
        return fn(func.start_ea, soff)
    return ida_frame.soff_to_fpoff(func, soff)


def define_stkvar(func, name: str, off: int, tif) -> bool:
    """Define or redefine a stack variable in *func*'s frame."""
    fn = getattr(ida_frame, "define_stkvar_ea", None)
    if fn is not None:
        return bool(fn(func.start_ea, name, off, tif))
    return bool(ida_frame.define_stkvar(func, name, off, tif))


def is_funcarg_off(func, frameoff: int) -> bool:
    """Does *frameoff* lie in *func*'s argument area?"""
    fn = getattr(ida_frame, "is_funcarg_off_ea", None)
    if fn is not None:
        return bool(fn(func.start_ea, frameoff))
    return bool(ida_frame.is_funcarg_off(func, frameoff))


def delete_frame_members(func, start_offset: int, end_offset: int) -> bool:
    """Delete the frame members in ``[start_offset, end_offset)``."""
    fn = getattr(ida_frame, "delete_frame_members_ea", None)
    if fn is not None:
        return bool(fn(func.start_ea, start_offset, end_offset))
    return bool(ida_frame.delete_frame_members(func, start_offset, end_offset))


def set_frame_member_type(func, offset: int, tif) -> bool:
    """Change the type of the frame member at *offset*."""
    fn = getattr(ida_frame, "set_frame_member_type_ea", None)
    if fn is not None:
        return bool(fn(func.start_ea, offset, tif))
    return bool(ida_frame.set_frame_member_type(func, offset, tif))


# ============================================================================
# Snippet (range-based) decompilation
# ============================================================================

# IDA 9.4 has no *public* Python route to the range-based decompiler:
#   * ida_hexrays.decompile() is a hand-written pycode wrapper (see
#     sdk/plugins/idapython/pywraps/py_hexrays.py) that shadows the SWIG
#     overload set and unconditionally forwards to decompile_function(ea) --
#     it is kept that way on purpose, so scripts calling decompile(ea=...,
#     hf=...) by keyword keep working;
#   * decompile_snippet() is %ignore'd in sdk/plugins/idapython/swig/hexrays.i.
# The compiled SWIG entry point in _ida_hexrays still accepts decomp_ranges_t,
# so that is what we use, behind the usual capability probe. Everything returns
# None when the route is unavailable so callers fall back to whole-function
# decompilation instead of failing.

# Hard caps: a runaway range list would be handed straight to Hex-Rays.
MAX_DECOMP_RANGES = 64
MAX_DECOMP_BYTES = 0x40000


def _hexrays():
    import ida_hexrays

    return ida_hexrays


def _raw_range_decompiler():
    if getattr(_hexrays(), "decomp_ranges_t", None) is None:
        return None
    try:
        import _ida_hexrays
    except ImportError:
        return None
    return getattr(_ida_hexrays, "decompile", None)


def can_decompile_ranges() -> bool:
    """Is range-based (snippet) decompilation reachable on this build?"""
    return _raw_range_decompiler() is not None


def normalize_code_ranges(
    ranges, *, max_ranges: int = MAX_DECOMP_RANGES, max_bytes: int = MAX_DECOMP_BYTES
) -> tuple[list[tuple[int, int]], str | None]:
    """Validate/normalize ``[(start, end), ...]`` for the snippet decompiler.

    Garbage ranges go straight into Hex-Rays, so everything is checked here
    rather than relying on the decompiler to reject it: each bound is snapped to
    an item boundary, unmapped or non-code starts are rejected, and overlapping
    or adjacent ranges are merged. Returns ``(ranges, error)`` with exactly one
    of the two meaningful.
    """
    import ida_bytes

    cleaned: list[tuple[int, int]] = []
    for item in ranges:
        try:
            start, end = int(item[0]), int(item[1])
        except (TypeError, ValueError, IndexError):
            return [], f"Invalid range: {item!r}"
        if start == idaapi.BADADDR or end == idaapi.BADADDR:
            return [], "Range bound is BADADDR"
        if end <= start:
            return [], f"Empty or reversed range: {hex(start)}-{hex(end)}"
        if not ida_bytes.is_loaded(start):
            return [], f"Range start {hex(start)} is not mapped"

        # Snap to item boundaries: a range starting mid-instruction is the most
        # likely caller mistake and the decompiler should never see one.
        head = ida_bytes.get_item_head(start)
        if head != idaapi.BADADDR:
            start = head
        if not ida_bytes.is_code(ida_bytes.get_flags(start)):
            return [], f"Range start {hex(start)} is not code"
        last_head = ida_bytes.get_item_head(end - 1)
        if last_head != idaapi.BADADDR:
            item_end = ida_bytes.get_item_end(last_head)
            if item_end != idaapi.BADADDR and item_end > end:
                end = item_end
        cleaned.append((start, end))

    if not cleaned:
        return [], "No ranges given"

    cleaned.sort()
    merged: list[tuple[int, int]] = [cleaned[0]]
    for start, end in cleaned[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:  # overlapping or adjacent
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    if len(merged) > max_ranges:
        return [], f"Too many ranges: {len(merged)} (max {max_ranges})"
    total = sum(end - start for start, end in merged)
    if total > max_bytes:
        return [], f"Ranges cover {hex(total)} bytes (max {hex(max_bytes)})"
    return merged, None


def decompile_ranges(ranges, flags: int = 0):
    """Decompile a snippet spanning *ranges* (already normalized).

    The lowest address becomes the snippet entry point; code outside the ranges
    shows up as ``JUMPOUT``. Ranges unreachable from the entry are silently
    dropped by the decompiler, so callers should report back which ranges were
    actually submitted. Returns ``(cfunc, error)``.
    """
    import ida_range

    ida_hexrays = _hexrays()
    raw = _raw_range_decompiler()
    if raw is None:
        return None, "Range-based decompilation is not available on this IDA build"
    if not ida_hexrays.init_hexrays_plugin():
        return None, "Hex-Rays decompiler is not available"

    dcr = ida_hexrays.decomp_ranges_t()
    for start, end in ranges:
        dcr.ranges.push_back(ida_range.range_t(start, end))
    if dcr.empty():
        return None, "No ranges given"

    hf = ida_hexrays.hexrays_failure_t()
    try:
        cfunc = raw(dcr, hf, flags)
    except Exception as exc:  # the private entry point is not contract-bound
        return None, f"Range decompilation failed: {exc}"
    if not cfunc:
        if hf.code == ida_hexrays.MERR_LICENSE:
            return None, "Decompiler license is not available"
        message = "Snippet decompilation failed"
        if hf.str:
            message += f": {hf.str}"
        if hf.errea != idaapi.BADADDR:
            message += f" (address: {hex(hf.errea)})"
        return None, message
    return cfunc, None


def submitted_decomp_ranges(cfunc, fallback) -> list[tuple[int, int]]:
    """Ranges the decompiler actually received, as it merged them.

    ``mba_t.get_decomp_ranges()`` reports the submitted (merged) set. Note it is
    *not* a coverage report -- and neither is ``cfunc.get_eamap()``, which on a
    snippet also lists addresses outside the ranges.
    """
    try:
        dr = cfunc.mba.get_decomp_ranges()
        out = [(r.start_ea, r.end_ea) for r in dr.ranges]
        if out:
            return out
    except Exception:
        pass
    return list(fallback)


# ============================================================================
# Binary search compatibility
# ============================================================================


def raw_bin_search(
    ea: int,
    max_ea: int,
    data: bytes,
    mask: bytes,
    flags: int = 0,
) -> int:
    # 9.0+ find_bytes natively supports bytes+mask search
    if IDA_GE_90:
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)


def make_bytes_searcher(
    pattern: str,
) -> tuple[Callable[[int, int], int] | None, str | None]:
    tokens = pattern.strip().split()
    if not tokens:
        return None, "Empty pattern"

    # 9.0+ search closure
    if IDA_GE_90:
        normalized = " ".join("?" if t in ("??", "?") else t for t in tokens)

        def _search_modern(ea: int, max_ea: int) -> int:
            return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)

        return _search_modern, None

    # Legacy search closure
    pat = bytearray()
    msk = bytearray()
    for t in tokens:
        if t in ("??", "?"):
            pat.append(0)
            msk.append(0)
        else:
            pat.append(int(t, 16))
            msk.append(0xFF)

    data = bytes(pat)
    mask = bytes(msk)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW

    def _search_legacy(ea: int, max_ea: int) -> int:
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)

    return _search_legacy, None


# ============================================================================
# Type inference compatibility
# ============================================================================


def guess_tinfo(tif: ida_typeinf.tinfo_t, ea: int) -> bool:
    # Prefer modern API first
    try:
        rc = ida_typeinf.guess_tinfo(tif, ea)
        if isinstance(rc, bool):
            if rc:
                return True
        elif int(rc) > 0:
            return True
    except Exception:
        pass

    # Fallback to ida_hexrays for very old IDA
    if not IDA_GE_84 and ida_hexrays is not None:
        try:
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                return True
        except Exception:
            pass

    return False


# ============================================================================
# UDM (struct/union member) compatibility
# ============================================================================


def tinfo_get_udm(
    tif: ida_typeinf.tinfo_t, name: str
) -> tuple[int, ida_typeinf.udm_t | None]:
    """
    Get a UDM (user-defined member) from a tinfo_t by name.

    tinfo_t.get_udm() was introduced in IDA 8.5 but is missing in early
    IDA 9.0 builds (build 240925). This wrapper provides a fallback using
    the older find_udm() + get_udm_by_tid() APIs.

    Returns:
        tuple of (index, udm) where udm is None if not found
    """
    # Try modern API first (available in 8.5+ but not early 9.0 builds)
    if hasattr(tif, "get_udm"):
        return tif.get_udm(name)

    # Fallback for early 9.0 builds using find_udm + get_udm_by_tid
    idx = tif.find_udm(name)
    if idx == -1:
        return -1, None

    udm = ida_typeinf.udm_t()
    tid = tif.get_udm_tid(idx)
    # get_udm_by_tid returns 0 on success (C convention), check if udm.name is populated
    tif.get_udm_by_tid(udm, tid)
    if udm.name:
        return idx, udm
    return -1, None
