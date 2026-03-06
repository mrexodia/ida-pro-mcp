"""Tests for api_core API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    assert_all_have_keys,
    get_any_function,
    get_data_address,
)

# Import functions under test
from ..api_core import (
    lookup_funcs,
    int_convert,
    list_funcs,
    list_globals,
    imports,
    find_regex,
)

# Import sync module for IDAError


# ============================================================================
# Tests for lookup_funcs
# ============================================================================


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
    """lookup_funcs with '*' returns all functions"""
    result = lookup_funcs("*")
    assert_is_list(result, min_length=1)
    # All results should have query="*" and a function
    for r in result:
        assert r["query"] == "*"
        assert r["fn"] is not None


@test()
def test_lookup_funcs_empty():
    """lookup_funcs with empty string returns all functions"""
    result = lookup_funcs("")
    assert_is_list(result, min_length=1)
    assert result[0]["query"] == "*"


@test()
def test_lookup_funcs_malformed_hex():
    """lookup_funcs handles malformed hex address"""
    # This looks like an address but isn't valid hex
    result = lookup_funcs("0xZZZZ")
    assert_is_list(result, min_length=1)
    # Should return error since it's not a valid address or name
    assert result[0]["error"] is not None


@test()
def test_lookup_funcs_data_address():
    """lookup_funcs with valid address but not a function"""
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


# ============================================================================
# Tests for lookup_funcs: interior address → entry point
# ============================================================================


@test()
def test_lookup_funcs_interior_address():
    """lookup_funcs returns function entry point when queried with interior address"""
    import idc
    import idaapi

    fn_addr = get_any_function()
    if not fn_addr:
        return

    ea = int(fn_addr, 16)
    func = idaapi.get_func(ea)
    if not func:
        return

    # Get second instruction inside the function
    interior = idc.next_head(func.start_ea, func.end_ea)
    if interior == idaapi.BADADDR or interior == func.start_ea:
        return

    result = lookup_funcs(hex(interior))
    assert len(result) == 1
    assert result[0]["fn"] is not None
    assert result[0]["fn"]["addr"] == hex(func.start_ea)
    assert result[0]["fn"]["addr"] != hex(interior)


# ============================================================================
# Tests for int_convert
# ============================================================================


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
    """int_convert handles invalid number text"""
    result = int_convert({"text": "not_a_number"})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert result[0]["error"] is not None
    assert "Invalid number" in result[0]["error"]


@test()
def test_int_convert_overflow():
    """int_convert handles overflow with small size"""
    # Try to fit a large number into 1 byte
    result = int_convert({"text": "0xFFFF", "size": 1})
    assert_is_list(result, min_length=1)
    assert result[0]["result"] is None
    assert result[0]["error"] is not None
    assert "too big" in result[0]["error"]


@test()
def test_int_convert_non_ascii():
    """int_convert handles non-ASCII bytes"""
    # 0x01 is not a printable ASCII character (control char)
    result = int_convert({"text": "0x01"})
    assert_is_list(result, min_length=1)
    assert result[0]["error"] is None
    # ascii should be None for non-printable bytes
    assert result[0]["result"]["ascii"] is None


# ============================================================================
# Tests for list_funcs
# ============================================================================


@test()
def test_list_funcs():
    """list_funcs returns functions with proper structure"""
    result = list_funcs({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")
    if page["data"]:
        assert_all_have_keys(page["data"], "addr", "name", "size")


@test()
def test_list_funcs_pagination():
    """list_funcs respects pagination parameters"""
    result = list_funcs({"offset": 0, "count": 5})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert len(page["data"]) <= 5
    assert "next_offset" in page


# ============================================================================
# Tests for list_globals
# ============================================================================


@test()
def test_list_globals():
    """list_globals returns globals with proper structure"""
    result = list_globals({})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset")


@test()
def test_list_globals_pagination():
    """list_globals respects pagination parameters"""
    result = list_globals({"offset": 0, "count": 5})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert len(page["data"]) <= 5
    assert "next_offset" in page


# ============================================================================
# Tests for imports
# ============================================================================


@test()
def test_imports():
    """imports returns import list with proper structure"""
    page = imports(0, 50)
    assert isinstance(page, dict)
    assert_has_keys(page, "data", "next_offset")


@test()
def test_imports_pagination():
    """imports respects pagination parameters"""
    page = imports(0, 5)
    assert isinstance(page, dict)
    assert len(page["data"]) <= 5
    assert "next_offset" in page


# ============================================================================
# Tests for find_regex
# ============================================================================


@test()
def test_find_regex():
    """find_regex can search for patterns"""
    # Search for a common pattern that should exist in most binaries
    result = find_regex(".*")
    assert isinstance(result, dict)
    # Result structure should have matches
    assert_has_keys(result, "matches", "n", "cursor")
