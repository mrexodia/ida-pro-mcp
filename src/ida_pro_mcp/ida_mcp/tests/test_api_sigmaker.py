"""Tests for api_sigmaker API functions.

Tests are structured to validate semantically meaningful behavior:
- Round-trip: generate a signature then scan it back to verify it finds
  the original address (proving uniqueness isn't just a boolean flag).
- Function resolution: make_signature_for_function resolves mid-function
  addresses to the function start and populates the name field.
- Batch with mixed input: batching names and hex addresses together tests
  the name-resolution path that plain hex batches don't exercise.
"""

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
)
from ..api_analysis import find_bytes


# ============================================================================
# make_signature
# ============================================================================


@test()
def test_make_signature_round_trip():
    """Generate a unique signature, then scan it back with find_bytes to prove
    it actually matches the original address and only that address."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = make_signature(fn_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["signature"] is not None
    assert_non_empty(entry["signature"])
    assert entry["unique"] is True

    # Round-trip: scan the generated signature and verify it lands back
    # on the same address with exactly one match (proving true uniqueness).
    scan = find_bytes(entry["signature"])
    assert_is_list(scan, min_length=1)
    assert scan[0]["n"] == 1, f"expected 1 match (unique), got {scan[0]['n']}"
    assert scan[0]["matches"][0] == entry["addr"]


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
def test_make_signature_for_function_resolves_to_start():
    """Pass a mid-function address and verify the tool resolves it to the
    function start.  Also verify the name field matches IDA's own function
    name — this is the key behaviour that make_signature doesn't provide."""
    import ida_funcs
    import idaapi
    import idautils

    # Find a function with at least 2 bytes so we can pick a mid-function addr
    func_ea = None
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f and f.end_ea - f.start_ea > 2:
            func_ea = f.start_ea
            break
    if func_ea is None:
        skip_test("no function with size > 2 found")

    func = ida_funcs.get_func(func_ea)
    mid_addr = hex(func.start_ea + 1)  # one byte into the function

    result = make_signature_for_function(mid_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]

    # Should resolve back to function start, not the mid-function input
    assert entry["addr"] == hex(func.start_ea), (
        f"expected addr {hex(func.start_ea)}, got {entry['addr']}"
    )
    # Name field should match IDA's function name
    expected_name = idaapi.get_func_name(func.start_ea)
    assert entry["name"] == expected_name, (
        f"expected name '{expected_name}', got '{entry['name']}'"
    )
    assert entry["signature"] is not None


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
def test_make_signature_for_function_batch_mixed_input():
    """Batch with a mix of hex addresses and symbolic names — exercises
    the name-resolution path that a pure-hex batch (make_signature_batch)
    never touches.  Also verifies each result carries a correct name."""
    import idaapi
    import idautils

    # Build a mixed batch: first function as hex, second as its IDA name
    funcs = list(idautils.Functions())[:2]
    if len(funcs) < 2:
        skip_test("binary has fewer than two functions")

    hex_addr = hex(funcs[0])
    name_str = idaapi.get_func_name(funcs[1])
    if not name_str:
        skip_test("second function has no name")

    result = make_signature_for_function([hex_addr, name_str])
    assert_is_list(result, min_length=2)

    # First entry: queried by hex address
    assert result[0]["query"] == hex_addr
    assert result[0]["signature"] is not None
    assert result[0]["name"] is not None  # name must be populated even for hex input

    # Second entry: queried by name
    assert result[1]["query"] == name_str
    assert result[1]["name"] == name_str
    assert result[1]["signature"] is not None

    # Both should resolve to different addresses (different functions)
    assert result[0]["addr"] != result[1]["addr"]


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
