"""
IDA Pro API Compatibility Layer

This module wraps IDA APIs that differ between IDA 9.0+ and older versions,
providing a unified interface.

Compatibility notes:
- IDA 9.0+: new modules ida_entry, ida_ida; some idaapi methods removed
- IDA <9.0: uses ida_nalt, idaapi.get_inf_structure(), etc.
"""

import ida_nalt
import ida_typeinf
import idaapi
import ida_funcs
import ida_name
import ida_bytes

try:
    import ida_entry
except ImportError:
    ida_entry = None

try:
    import ida_ida
except ImportError:
    ida_ida = None


# ============================================================================
# Entry Point Functions (IDA 9.0+ moved to ida_entry)
# ============================================================================

def get_entry_qty() -> int:
    """Get number of entry points."""
    if ida_entry and hasattr(ida_entry, "get_entry_qty"):
        return ida_entry.get_entry_qty()
    return ida_nalt.get_entry_qty()


def get_entry_ordinal(idx: int) -> int:
    """Get entry point ordinal by index."""
    if ida_entry and hasattr(ida_entry, "get_entry_ordinal"):
        return ida_entry.get_entry_ordinal(idx)
    return ida_nalt.get_entry_ordinal(idx)


def get_entry(ordinal: int) -> int:
    """Get entry point address by ordinal."""
    if ida_entry and hasattr(ida_entry, "get_entry"):
        return ida_entry.get_entry(ordinal)
    return ida_nalt.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str | None:
    """Get entry point name by ordinal."""
    if ida_entry and hasattr(ida_entry, "get_entry_name"):
        return ida_entry.get_entry_name(ordinal)
    return ida_nalt.get_entry_name(ordinal)


# ============================================================================
# Type Information Functions
# ============================================================================

def get_ordinal_limit(til=None) -> int:
    """Get the ordinal limit for type library (max ordinal + 1).
    
    IDA 9.0+: ida_typeinf.get_ordinal_limit() or get_ordinal_qty()
    Older: ida_typeinf.get_ordinal_qty()
    """
    if hasattr(ida_typeinf, "get_ordinal_limit"):
        try:
            return ida_typeinf.get_ordinal_limit(til)
        except TypeError:
            return ida_typeinf.get_ordinal_limit()
    if hasattr(ida_typeinf, "get_ordinal_qty"):
        try:
            return ida_typeinf.get_ordinal_qty(til)
        except TypeError:
            return ida_typeinf.get_ordinal_qty()
    return 0


# ============================================================================
# Database Info Functions (IDA 9.0+ uses ida_ida.inf_* instead of get_inf_structure)
# ============================================================================

def inf_get_min_ea() -> int:
    """Get minimum address in the database."""
    if ida_ida and hasattr(ida_ida, "inf_get_min_ea"):
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea


def inf_get_max_ea() -> int:
    """Get maximum address in the database."""
    if ida_ida and hasattr(ida_ida, "inf_get_max_ea"):
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea


def inf_get_omin_ea() -> int:
    """Get original minimum address (before rebasing)."""
    if ida_ida and hasattr(ida_ida, "inf_get_omin_ea"):
        return ida_ida.inf_get_omin_ea()
    return idaapi.get_inf_structure().omin_ea


def inf_get_omax_ea() -> int:
    """Get original maximum address (before rebasing)."""
    if ida_ida and hasattr(ida_ida, "inf_get_omax_ea"):
        return ida_ida.inf_get_omax_ea()
    return idaapi.get_inf_structure().omax_ea


def inf_is_64bit() -> bool:
    """Check if the database is 64-bit."""
    if ida_ida and hasattr(ida_ida, "inf_is_64bit"):
        return ida_ida.inf_is_64bit()
    return idaapi.get_inf_structure().is_64bit()


# ============================================================================
# Function Info Functions (IDA 9.0+ has func_t methods)
# ============================================================================

def get_func_name(func: 'ida_funcs.func_t') -> str | None:
    """Get function name.
    
    IDA 9.0+: func_t.get_name()
    Older: ida_funcs.get_func_name(start_ea)
    """
    if hasattr(func, "get_name"):
        return func.get_name()
    return ida_funcs.get_func_name(func.start_ea)


def get_func_prototype(func: 'ida_funcs.func_t') -> 'ida_typeinf.tinfo_t | None':
    """Get function prototype as tinfo_t.
    
    IDA 9.0+: func_t.get_prototype()
    Older: ida_nalt.get_tinfo()
    """
    if hasattr(func, "get_prototype"):
        return func.get_prototype()
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea):
        return tif
    return None


# ============================================================================
# Binary Search Functions
# ============================================================================

def raw_bin_search(
    ea: int, 
    max_ea: int, 
    data: bytes, 
    mask: bytes, 
    flags: int = 0
) -> int:
    """Search for raw bytes with mask, compatible across IDA versions.

    Returns the match address, or idaapi.BADADDR if not found.
    
    IDA 9.0+: ida_bytes.find_bytes() with bytes + mask
    Older: ida_bytes.bin_search() with 6 parameters
    """
    if hasattr(ida_bytes, "find_bytes"):
        # IDA 9.0+: high-level API accepting bytes + mask directly
        return ida_bytes.find_bytes(
            data, ea, range_end=max_ea, mask=mask, flags=flags
        )
    if hasattr(ida_bytes, "bin_search"):
        # Older IDA: low-level 6-param API
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)
    raise RuntimeError(
        "No binary search API available (tried ida_bytes.find_bytes, ida_bytes.bin_search)"
    )


def find_bytes_pattern(pattern: str, ea: int, max_ea: int) -> int:
    """Search for byte pattern string (e.g., '48 8B ?? ??').
    
    Returns match address or BADADDR.
    
    IDA 9.0+: ida_bytes.find_bytes() with pattern string
    Older: ida_bytes.bin_search() with bytes + mask
    """
    tokens = pattern.strip().split()
    if not tokens:
        return idaapi.BADADDR

    if hasattr(ida_bytes, "find_bytes"):
        # IDA 9.0+: high-level API accepts pattern string directly
        # Normalize "??" to "?" (IDA uses single ? per wildcard byte)
        normalized = " ".join("?" if t in ("??", "?") else t for t in tokens)
        return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)
    
    if hasattr(ida_bytes, "bin_search"):
        # Older IDA: manual parse into bytes + mask
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
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)
    
    raise RuntimeError(
        "No binary search API available (tried ida_bytes.find_bytes, ida_bytes.bin_search)"
    )


def make_bytes_searcher(pattern: str):
    """Create a reusable searcher function for a byte pattern.
    
    Returns (searcher_fn, error_str|None) where:
    - searcher_fn(ea, max_ea) -> int (BADADDR if not found)
    - error_str is None on success
    
    This is useful when searching for the same pattern multiple times.
    """
    tokens = pattern.strip().split()
    if not tokens:
        return None, "Empty pattern"

    if hasattr(ida_bytes, "find_bytes"):
        # IDA 9.0+ high-level API: accepts pattern string directly.
        # Normalize "??" to "?" (IDA uses single ? per wildcard byte).
        normalized = " ".join("?" if t in ("??", "?") else t for t in tokens)

        def _search(ea, max_ea):
            return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)

        return _search, None

    if hasattr(ida_bytes, "bin_search"):
        # Older IDA: manual parse into bytes + mask
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

        def _search(ea, max_ea):
            return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)

        return _search, None

    return (
        None,
        "No binary search API available (tried ida_bytes.find_bytes, ida_bytes.bin_search)",
    )


# ============================================================================
# Type Inference Functions (IDA Hex-Rays compatibility)
# ============================================================================

def guess_tinfo(tif: 'ida_typeinf.tinfo_t', ea: int) -> bool:
    """Guess type information for an address.
    
    Tries multiple methods across IDA versions to infer type info:
    1. ida_hexrays.guess_tinfo (IDA 8.x and older)
    2. ida_typeinf.guess_tinfo (some IDA 9.x builds)
    3. tinfo_t.guess_type (alternative method)
    4. ida_typeinf.idc_get_type (fallback)
    
    Args:
        tif: tinfo_t object to receive the guessed type
        ea: Address to guess type for
        
    Returns:
        True if type was successfully guessed, False otherwise
        
    IDA 9.0+: guess_tinfo may be in ida_typeinf or use tinfo_t method
    IDA <9.0: guess_tinfo is in ida_hexrays module
    """
    import ida_hexrays
    
    # Method 1: ida_hexrays.guess_tinfo (classic location, IDA < 9.0)
    if hasattr(ida_hexrays, 'guess_tinfo'):
        try:
            if ida_hexrays.init_hexrays_plugin():
                if ida_hexrays.guess_tinfo(tif, ea):
                    return True
        except Exception:
            pass
    
    # Method 2: ida_typeinf.guess_tinfo (IDA 9.0+ moved location)
    if hasattr(ida_typeinf, 'guess_tinfo'):
        try:
            if ida_typeinf.guess_tinfo(tif, ea):
                return True
        except Exception:
            pass
    
    # Method 3: tinfo_t.guess_type (alternative API in some versions)
    if hasattr(tif, 'guess_type'):
        try:
            if tif.guess_type(ea):
                return True
        except Exception:
            pass
    
    # Method 4: ida_typeinf.idc_get_type (fallback using IDC bridge)
    try:
        type_str = ida_typeinf.idc_get_type(ea)
        if type_str:
            parsed = tif.parse(type_str, None, ida_typeinf.PT_SIL)
            if parsed:
                return True
    except Exception:
        pass
    
    return False


def guess_tinfo_ex(ea: int) -> tuple[bool, 'ida_typeinf.tinfo_t']:
    """Convenience wrapper that creates and returns a tinfo_t.
    
    Args:
        ea: Address to guess type for
        
    Returns:
        Tuple of (success, tinfo_t) where success indicates if type was guessed
    """
    tif = ida_typeinf.tinfo_t()
    success = guess_tinfo(tif, ea)
    return success, tif
