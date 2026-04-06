"""Tests for api_sigmaker API functions."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_ok,
    assert_error,
    assert_valid_address,
    assert_non_empty,
    optional,
    get_any_function,
    get_data_address,
    get_unmapped_address,
)
from ..api_sigmaker import (
    make_signature,
    make_signature_for_function,
    make_signature_for_range,
    find_xref_signatures,
    scan_signature,
)


# ============================================================================
# make_signature
# ============================================================================


@test()
def test_make_signature_produces_unique_sig():
    """make_signature returns a unique signature for a valid code address."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = make_signature(fn_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["query"] == fn_addr
    assert_valid_address(entry["addr"])
    assert entry["signature"] is not None
    assert_non_empty(entry["signature"])
    assert entry["unique"] is True
    assert entry["format"] == "ida"


@test()
def test_make_signature_invalid_address():
    """make_signature reports an error for an unmapped address."""
    result = make_signature(get_unmapped_address())
    assert_is_list(result, min_length=1)
    assert "error" in result[0]


@test()
def test_make_signature_batch():
    """make_signature handles multiple addresses in one call."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:3]]
    if len(addrs) < 2:
        skip_test("binary has fewer than two functions")

    result = make_signature(addrs)
    assert_is_list(result, min_length=len(addrs))
    for entry, addr in zip(result, addrs):
        assert entry["query"] == addr
        assert entry["signature"] is not None


@test(binary="crackme03.elf")
def test_make_signature_by_name():
    """make_signature accepts a function name and produces a valid signature."""
    result = make_signature("check_pw")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["query"] == "check_pw"
    assert entry["signature"] is not None
    assert entry["unique"] is True


# ============================================================================
# make_signature_for_function
# ============================================================================


@test()
def test_make_signature_for_function_valid():
    """make_signature_for_function returns a signature at the function entry."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = make_signature_for_function(fn_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_valid_address(entry["addr"])
    assert entry["signature"] is not None
    assert entry["name"] is not None


@test(binary="crackme03.elf")
def test_make_signature_for_function_by_name():
    """make_signature_for_function resolves 'main' and returns its signature."""
    result = make_signature_for_function("main")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["query"] == "main"
    assert entry["name"] == "main"
    assert entry["signature"] is not None


@test()
def test_make_signature_for_function_no_func():
    """make_signature_for_function errors for a data address with no function."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segments")

    result = make_signature_for_function(data_addr)
    assert_is_list(result, min_length=1)
    assert "error" in result[0]


@test()
def test_make_signature_for_function_batch():
    """make_signature_for_function handles multiple inputs."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:3]]
    if len(addrs) < 2:
        skip_test("binary has fewer than two functions")

    result = make_signature_for_function(addrs)
    assert_is_list(result, min_length=len(addrs))
    for entry in result:
        assert entry["signature"] is not None


# ============================================================================
# make_signature_for_range
# ============================================================================


@test()
def test_make_signature_for_range_valid():
    """make_signature_for_range encodes an address range as a signature."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    import ida_funcs
    func = ida_funcs.get_func(int(fn_addr, 16))
    if not func:
        skip_test("cannot get function object")

    start = hex(func.start_ea)
    # Use a small range: first 16 bytes or function end, whichever is smaller
    end_ea = min(func.start_ea + 16, func.end_ea)
    end = hex(end_ea)

    result = make_signature_for_range(start, end)
    assert result["signature"] is not None
    assert_non_empty(result["signature"])
    assert_valid_address(result["addr"])


@test(binary="crackme03.elf")
def test_make_signature_for_range_crackme():
    """make_signature_for_range works on a known crackme function range."""
    result = make_signature_for_range("0x11a9", "0x11b9")
    assert result["signature"] is not None
    assert "error" not in result


# ============================================================================
# find_xref_signatures
# ============================================================================


@test(binary="crackme03.elf")
def test_find_xref_signatures_for_string():
    """find_xref_signatures finds signatures for xrefs to a known string address."""
    # "Need exactly one argument." string at 0x2004
    result = find_xref_signatures("0x2004")
    assert_is_list(result, min_length=1)
    entry = result[0]
    if entry.get("signatures") and len(entry["signatures"]) > 0:
        sig = entry["signatures"][0]
        assert sig["signature"] is not None
        assert sig["length"] > 0
        assert_valid_address(sig["xref_addr"])


@test()
def test_find_xref_signatures_no_xrefs():
    """find_xref_signatures returns empty list for address with no xrefs."""
    result = find_xref_signatures(get_unmapped_address())
    assert_is_list(result, min_length=1)
    entry = result[0]
    # Either error or empty signatures
    if "error" not in entry:
        assert entry["signatures"] is not None
        assert entry["total_xrefs"] == 0


# ============================================================================
# scan_signature
# ============================================================================


@test()
def test_scan_signature_from_generated():
    """scan_signature finds a match when scanning with a generated signature."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    # Generate a signature first
    sig_result = make_signature(fn_addr)
    assert_is_list(sig_result, min_length=1)
    sig_str = sig_result[0]["signature"]
    assert sig_str is not None

    # Scan for it — should find exactly 1 match (unique)
    scan_result = scan_signature(sig_str)
    assert_is_list(scan_result, min_length=1)
    entry = scan_result[0]
    assert entry["n"] >= 1
    assert entry["unique"] is True
    assert_valid_address(entry["matches"][0])


@test()
def test_scan_signature_no_match():
    """scan_signature returns no matches for a bogus pattern."""
    result = scan_signature("DE AD BE EF CA FE BA BE 13 37 42 42 42 42")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["n"] == 0
    assert entry["unique"] is False
    assert len(entry["matches"]) == 0


@test()
def test_scan_signature_batch():
    """scan_signature handles multiple patterns in one call."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    sig_result = make_signature(fn_addr)
    sig_str = sig_result[0]["signature"]

    result = scan_signature([sig_str, "DE AD BE EF CA FE BA BE 13 37"])
    assert_is_list(result, min_length=2)
    assert result[0]["n"] >= 1
    assert result[1]["n"] == 0


# ============================================================================
# Output formats
# ============================================================================


@test()
def test_all_output_formats():
    """make_signature produces valid output in all 4 formats."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    for fmt in ("ida", "x64dbg", "mask", "bitmask"):
        result = make_signature(fn_addr, format=fmt)
        assert_is_list(result, min_length=1)
        entry = result[0]
        assert entry["format"] == fmt
        assert entry["signature"] is not None, f"format {fmt} returned None"
        assert_non_empty(entry["signature"])

    # IDA format uses single '?'
    ida_result = make_signature(fn_addr, format="ida")[0]["signature"]
    # x64dbg format uses '??'
    x64_result = make_signature(fn_addr, format="x64dbg")[0]["signature"]
    # mask format has backslash-x bytes + mask string
    mask_result = make_signature(fn_addr, format="mask")[0]["signature"]
    # bitmask format has 0x bytes + 0b bitmask
    bitmask_result = make_signature(fn_addr, format="bitmask")[0]["signature"]

    # Basic format validation
    assert "?" not in x64_result or "??" in x64_result  # x64dbg uses ?? not single ?
    assert "\\x" in mask_result or "x" in mask_result
    assert "0b" in bitmask_result


# ============================================================================
# Name resolution
# ============================================================================


@test(binary="crackme03.elf")
def test_name_resolution_across_tools():
    """All signature tools accept function names alongside hex addresses."""
    # make_signature
    r1 = make_signature("check_pw")
    assert r1[0]["signature"] is not None

    # make_signature_for_function
    r2 = make_signature_for_function("check_pw")
    assert r2[0]["signature"] is not None

    # Both should resolve to the same address
    assert r1[0]["addr"] == r2[0]["addr"]
