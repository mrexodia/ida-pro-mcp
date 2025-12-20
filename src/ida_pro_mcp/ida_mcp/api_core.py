"""Core API Functions - IDB metadata and basic queries"""

from typing import Annotated, Optional

import ida_hexrays
import idaapi
import idautils
import ida_nalt
import ida_typeinf
import ida_segment

from .rpc import tool
from .sync import idasync
from .utils import (
    Metadata,
    Function,
    ConvertedNumber,
    Global,
    Import,
    String,
    Segment,
    Page,
    NumberConversion,
    ListQuery,
    get_image_size,
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    looks_like_address,
    get_function,
    create_demangled_to_ea_map,
    paginate,
    pattern_filter,
    DEMANGLED_TO_EA,
)
from .sync import IDAError
from .tests import (
    test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    get_any_function,
)


# ============================================================================
# String Cache
# ============================================================================

# Cache for idautils.Strings() to avoid rebuilding on every call
_strings_cache: Optional[list[String]] = None
_strings_cache_md5: Optional[str] = None


def _get_cached_strings() -> list[String]:
    """Get cached strings, rebuilding if IDB changed"""
    global _strings_cache, _strings_cache_md5

    # Get current IDB modification hash
    current_md5 = ida_nalt.retrieve_input_file_md5()

    # Rebuild cache if needed
    if _strings_cache is None or _strings_cache_md5 != current_md5:
        _strings_cache = []
        for item in idautils.Strings():
            if item is None:
                continue
            try:
                string = str(item)
                if string:
                    _strings_cache.append(
                        String(addr=hex(item.ea), length=item.length, string=string)
                    )
            except Exception:
                continue
        _strings_cache_md5 = current_md5

    return _strings_cache


# ============================================================================
# Core API Functions
# ============================================================================


@tool
@idasync
def idb_meta() -> Metadata:
    """Get IDB metadata"""

    def hash(f):
        try:
            return f().hex()
        except Exception:
            return ""

    return Metadata(
        path=idaapi.get_input_file_path(),
        module=idaapi.get_root_filename(),
        base=hex(idaapi.get_imagebase()),
        size=hex(get_image_size()),
        md5=hash(ida_nalt.retrieve_input_file_md5),
        sha256=hash(ida_nalt.retrieve_input_file_sha256),
        crc32=hex(ida_nalt.retrieve_input_file_crc32()),
        filesize=hex(ida_nalt.retrieve_input_file_size()),
    )


@test()
def test_idb_meta():
    """idb_meta returns valid metadata with all required fields"""
    meta = idb_meta()
    assert_has_keys(
        meta, "path", "module", "base", "size", "md5", "sha256", "crc32", "filesize"
    )
    assert_non_empty(meta["path"])
    assert_non_empty(meta["module"])
    assert_valid_address(meta["base"])
    assert_valid_address(meta["size"])


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)

    # Treat empty/"*" as "all functions"
    if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
        all_funcs = [get_function(addr) for addr in idautils.Functions()]
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    if len(DEMANGLED_TO_EA) == 0:
        create_demangled_to_ea_map()

    results = []
    for query in queries:
        try:
            ea = idaapi.BADADDR

            # Try as address first if it looks like one
            if looks_like_address(query):
                try:
                    ea = parse_address(query)
                except Exception:
                    ea = idaapi.BADADDR

            # Fall back to name lookup
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)
                if ea == idaapi.BADADDR and query in DEMANGLED_TO_EA:
                    ea = DEMANGLED_TO_EA[query]

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


@test()
def test_lookup_funcs_by_address():
    """lookup_funcs can find function by address"""
    fn_addr = get_any_function()
    if not fn_addr:
        return  # Skip if no functions

    result = lookup_funcs(fn_addr)
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is not None
    assert result[0]["error"] is None
    assert_has_keys(result[0]["fn"], "addr", "name", "size")


@test()
def test_lookup_funcs_invalid():
    """lookup_funcs returns error for invalid address"""
    # Use an address that's unlikely to be a valid function
    result = lookup_funcs("0xDEADBEEFDEADBEEF")
    assert_is_list(result, min_length=1)
    assert result[0]["fn"] is None
    assert result[0]["error"] is not None


@test()
def test_lookup_funcs_wildcard():
    """lookup_funcs with '*' returns all functions (covers lines 132-134)"""
    result = lookup_funcs("*")
    assert_is_list(result, min_length=1)
    # All results should have query="*" and a function
    for r in result:
        assert r["query"] == "*"
        assert r["fn"] is not None


@test()
def test_lookup_funcs_empty():
    """lookup_funcs with empty string returns all functions (covers lines 132-134)"""
    result = lookup_funcs("")
    assert_is_list(result, min_length=1)
    assert result[0]["query"] == "*"


@test()
def test_lookup_funcs_malformed_hex():
    """lookup_funcs handles malformed hex address (covers lines 148-149)"""
    # This looks like an address but isn't valid hex
    result = lookup_funcs("0xZZZZ")
    assert_is_list(result, min_length=1)
    # Should return error since it's not a valid address or name
    assert result[0]["error"] is not None


@test()
def test_lookup_funcs_data_address():
    """lookup_funcs with valid address but not a function (covers lines 162-164)"""
    from .tests import get_data_address

    data_addr = get_data_address()
    if not data_addr:
        return  # Skip if no data segments

    result = lookup_funcs(data_addr)
    assert_is_list(result, min_length=1)
    # Should return "Not a function" error
    assert result[0]["fn"] is None
    assert "Not a function" in str(result[0]["error"]) or "Not found" in str(
        result[0]["error"]
    )


@tool
@idasync
def cursor_addr() -> str:
    """Get current address"""
    return hex(idaapi.get_screen_ea())


@test()
def test_cursor_addr():
    """cursor_addr returns valid address or handles headless mode"""
    try:
        result = cursor_addr()
        # If it succeeds, verify it's a valid hex address
        assert_valid_address(result)
    except IDAError:
        pass  # Expected in headless mode without GUI


@tool
@idasync
def cursor_func() -> Optional[Function]:
    """Get current function"""
    return get_function(idaapi.get_screen_ea())


@test()
def test_cursor_func():
    """cursor_func returns function info or handles headless mode"""
    try:
        result = cursor_func()
        # Result can be None if cursor is not in a function
        if result is not None:
            assert_has_keys(result, "addr", "name", "size")
            assert_valid_address(result["addr"])
    except IDAError:
        pass  # Expected in headless mode or if cursor not in function


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
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


@test()
def test_int_convert():
    """int_convert properly converts numbers"""
    result = int_convert({"text": "0x41"})
    assert_is_list(result, min_length=1)
    assert result[0]["error"] is None
    assert result[0]["result"] is not None
    conv = result[0]["result"]
    assert_has_keys(conv, "decimal", "hexadecimal", "bytes", "binary")
    assert conv["decimal"] == "65"
    assert conv["hexadecimal"] == "0x41"
    assert conv["ascii"] == "A"


@test()
def test_int_convert_invalid_text():
    """int_convert handles invalid number text (covers lines 252-256)"""
    result = int_convert({"text": "not_a_number"})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert result[0]["error"] is not None
    assert "Invalid number" in result[0]["error"]


@test()
def test_int_convert_overflow():
    """int_convert handles overflow with small size (covers lines 269-277)"""
    # Try to fit a large number into 1 byte
    result = int_convert({"text": "0xFFFF", "size": 1})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert result[0]["error"] is not None
    assert "too big" in result[0]["error"]


@test()
def test_int_convert_non_ascii():
    """int_convert handles non-ASCII bytes (covers lines 283-285)"""
    # 0x01 is not a printable ASCII character (control char)
    result = int_convert({"text": "0x01"})
    assert_is_list(result, min_length=1)
    assert result[0]["error"] is None
    # ascii should be None for non-printable bytes
    assert result[0]["result"]["ascii"] is None


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
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


@test()
def test_list_funcs():
    """list_funcs returns functions with proper structure"""
    result = list_funcs({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    assert_is_list(page["data"], min_length=1)
    # Check first function has required keys
    fn = page["data"][0]
    assert_has_keys(fn, "addr", "name", "size")
    assert_valid_address(fn["addr"])


@test()
def test_list_funcs_pagination():
    """list_funcs pagination works correctly"""
    # Get first 2 functions
    result1 = list_funcs({"offset": 0, "count": 2})
    assert_is_list(result1, min_length=1)
    page1 = result1[0]
    assert len(page1["data"]) <= 2

    # Get next 2 functions
    if page1["next_offset"] is not None:
        result2 = list_funcs({"offset": page1["next_offset"], "count": 2})
        page2 = result2[0]
        # Verify we got different functions (if there are enough)
        if page2["data"]:
            assert page1["data"][0]["addr"] != page2["data"][0]["addr"]


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
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


@test()
def test_list_globals():
    """list_globals returns global variables with proper structure"""
    result = list_globals({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    # Globals list may be empty for some binaries
    if page["data"]:
        glob = page["data"][0]
        assert_has_keys(glob, "addr", "name")
        assert_valid_address(glob["addr"])


@test()
def test_list_globals_pagination():
    """list_globals pagination works correctly"""
    # Get first 2 globals
    result1 = list_globals({"offset": 0, "count": 2})
    assert_is_list(result1, min_length=1)
    page1 = result1[0]
    assert len(page1["data"]) <= 2

    # Get next 2 globals if available
    if page1["next_offset"] is not None and page1["data"]:
        result2 = list_globals({"offset": page1["next_offset"], "count": 2})
        page2 = result2[0]
        # Verify we got different globals (if there are enough)
        if page2["data"]:
            assert page1["data"][0]["addr"] != page2["data"][0]["addr"]


@tool
@idasync
def imports(
    offset: Annotated[int, "Offset"],
    count: Annotated[int, "Count (0=all)"],
) -> Page[Import]:
    """List imports"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
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
            return imp_cb(ea, symbol_name, ordinal, rv)

        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


@test()
def test_imports():
    """imports returns list of imported functions"""
    result = imports(0, 50)
    assert_has_keys(result, "data", "next_offset")
    # Imports may be empty for some binaries (static linking)
    if result["data"]:
        imp = result["data"][0]
        assert_has_keys(imp, "addr", "imported_name", "module")
        assert_valid_address(imp["addr"])


@test()
def test_imports_pagination():
    """imports pagination works correctly"""
    # Get first 2 imports
    result1 = imports(0, 2)
    assert_has_keys(result1, "data", "next_offset")
    assert len(result1["data"]) <= 2

    # Get next 2 imports if available
    if result1["next_offset"] is not None and result1["data"]:
        result2 = imports(result1["next_offset"], 2)
        # Verify we got different imports (if there are enough)
        if result2["data"]:
            assert result1["data"][0]["addr"] != result2["data"][0]["addr"]


@tool
@idasync
def strings(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List strings with optional filtering and pagination",
    ],
) -> list[Page[String]]:
    """List strings"""
    queries = normalize_dict_list(
        queries, lambda s: {"offset": 0, "count": 50, "filter": s}
    )
    # Use cached strings instead of rebuilding every time
    all_strings = _get_cached_strings()

    results = []
    for query in queries:
        offset = query.get("offset", 0)
        count = query.get("count", 100)
        filter_pattern = query.get("filter", "")

        # Treat empty/"*" filter as "all"
        if filter_pattern in ("", "*"):
            filter_pattern = ""

        filtered = pattern_filter(all_strings, filter_pattern, "string")
        results.append(paginate(filtered, offset, count))

    return results


@test()
def test_strings():
    """strings returns string list with proper structure"""
    result = strings({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    # If there are strings, check structure
    if page["data"]:
        string_item = page["data"][0]
        assert_has_keys(string_item, "addr", "length", "string")
        assert_valid_address(string_item["addr"])


def ida_segment_perm2str(perm: int) -> str:
    perms = []
    if perm & ida_segment.SEGPERM_READ:
        perms.append("r")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_WRITE:
        perms.append("w")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_EXEC:
        perms.append("x")
    else:
        perms.append("-")
    return "".join(perms)


@tool
@idasync
def segments() -> list[Segment]:
    """List all segments"""
    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        segments.append(
            Segment(
                name=seg_name,
                start=hex(seg.start_ea),
                end=hex(seg.end_ea),
                size=hex(seg.end_ea - seg.start_ea),
                permissions=ida_segment_perm2str(seg.perm),
            )
        )
    return segments


@test()
def test_segments():
    """segments returns list of memory segments"""
    result = segments()
    assert_is_list(result, min_length=1)
    seg = result[0]
    assert_has_keys(seg, "name", "start", "end", "size", "permissions")
    assert_valid_address(seg["start"])
    assert_valid_address(seg["end"])


@tool
@idasync
def local_types():
    """List local types"""
    error = ida_hexrays.hexrays_failure_t()
    locals = []
    idati = ida_typeinf.get_idati()
    type_count = ida_typeinf.get_ordinal_limit(idati)
    for ordinal in range(1, type_count):
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(idati, ordinal):
                type_name = tif.get_type_name()
                if not type_name:
                    type_name = f"<Anonymous Type #{ordinal}>"
                locals.append(f"\nType #{ordinal}: {type_name}")
                if tif.is_udt():
                    c_decl_flags = (
                        ida_typeinf.PRTYPE_MULTI
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI
                        | ida_typeinf.PRTYPE_DEF
                        | ida_typeinf.PRTYPE_METHODS
                        | ida_typeinf.PRTYPE_OFFSETS
                    )
                    c_decl_output = tif._print(None, c_decl_flags)
                    if c_decl_output:
                        locals.append(f"  C declaration:\n{c_decl_output}")
                else:
                    simple_decl = tif._print(
                        None,
                        ida_typeinf.PRTYPE_1LINE
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI,
                    )
                    if simple_decl:
                        locals.append(f"  Simple declaration:\n{simple_decl}")
            else:
                message = f"\nType #{ordinal}: Failed to retrieve information."
                if error.str:
                    message += f": {error.str}"
                if error.errea != idaapi.BADADDR:
                    message += f"from (address: {hex(error.errea)})"
                raise IDAError(message)
        except Exception:
            continue
    return locals


@test()
def test_local_types():
    """local_types returns list of local types"""
    result = local_types()
    # Result is a list of strings describing local types
    assert isinstance(result, list), f"Expected list, got {type(result).__name__}"
    # Local types may be empty for some binaries
    if result:
        # Each item should be a string describing a type
        assert isinstance(result[0], str), (
            f"Expected string items, got {type(result[0]).__name__}"
        )
