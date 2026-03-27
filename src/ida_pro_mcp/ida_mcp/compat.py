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
import ida_funcs
import ida_nalt
import ida_typeinf

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


def _check_required_apis() -> None:
    """
    Check that required Python APIs are available.

    IDA 9.0 initial release (build 240925) is missing several Python API methods
    that were added in 8.5 and later reinstated in 9.0 SP1 (build 241217).
    Rather than adding compatibility hacks, we explicitly reject this version.
    """
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
        version = idaapi.get_kernel_version()
        raise RuntimeError(
            f"IDA Pro {version} is missing required Python API methods: "
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
    _check_required_apis()

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


def get_entry_qty() -> int:
    if IDA_GE_90:
        return ida_entry.get_entry_qty()
    return ida_nalt.get_entry_qty()


def get_entry_ordinal(idx: int) -> int:
    if IDA_GE_90:
        return ida_entry.get_entry_ordinal(idx)
    return ida_nalt.get_entry_ordinal(idx)


def get_entry(ordinal: int) -> int:
    if IDA_GE_90:
        return ida_entry.get_entry(ordinal)
    return ida_nalt.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str | None:
    if IDA_GE_90:
        return ida_entry.get_entry_name(ordinal)
    return ida_nalt.get_entry_name(ordinal)


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


def get_func_name(func: ida_funcs.func_t) -> str | None:
    # func_t.get_name() introduced in 8.5
    if IDA_GE_85:
        return func.get_name()
    return ida_funcs.get_func_name(func.start_ea)


def get_func_prototype(func: ida_funcs.func_t) -> ida_typeinf.tinfo_t | None:
    # func_t.get_prototype() introduced in 8.5
    if IDA_GE_85:
        return func.get_prototype()

    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        return tif
    return None


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
