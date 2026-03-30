"""Tests for api_security API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_shape,
    assert_ok,
    assert_is_list,
    optional,
    list_of,
    get_any_function,
    get_unmapped_address,
)
from ..api_security import (
    detect_vulns,
    find_crypto,
    find_dangerous_callers,
    detect_stack_strings,
    trace_source_to_sink,
)


# ============================================================================
# detect_vulns
# ============================================================================


@test()
def test_detect_vulns_full_scan():
    """detect_vulns scans all functions and returns structured report."""
    result = detect_vulns()
    assert_has_keys(result, "scanned", "total_findings", "by_type", "by_severity", "findings")
    assert isinstance(result["scanned"], int)
    assert result["scanned"] > 0
    assert isinstance(result["total_findings"], int)
    assert isinstance(result["by_type"], dict)
    assert isinstance(result["by_severity"], dict)
    assert isinstance(result["findings"], list)


@test()
def test_detect_vulns_single_function():
    """detect_vulns accepts a single function address."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = detect_vulns(addrs=fn_addr)
    assert_has_keys(result, "scanned", "total_findings", "findings")
    assert result["scanned"] == 1


@test()
def test_detect_vulns_severity_filter():
    """detect_vulns respects severity filter."""
    result = detect_vulns(severity="critical")
    assert_has_keys(result, "findings")
    for finding in result["findings"]:
        assert finding["severity"] == "critical"


@test()
def test_detect_vulns_type_filter():
    """detect_vulns respects vuln type filter."""
    result = detect_vulns(vuln_types="buffer_overflow")
    assert_has_keys(result, "findings")
    for finding in result["findings"]:
        assert finding["vuln"] == "buffer_overflow"


@test()
def test_detect_vulns_pagination():
    """detect_vulns respects offset and count parameters."""
    full = detect_vulns(count=0)
    total = full["total_findings"]

    if total == 0:
        skip_test("no vulnerabilities found to paginate")

    page1 = detect_vulns(offset=0, count=2)
    assert len(page1["findings"]) <= 2
    assert page1["offset"] == 0

    if total > 2:
        page2 = detect_vulns(offset=2, count=2)
        assert page2["offset"] == 2
        assert page1["findings"][0] != page2["findings"][0]


@test()
def test_detect_vulns_finding_shape():
    """detect_vulns findings have the expected structure."""
    result = detect_vulns()
    if not result["findings"]:
        skip_test("no findings to validate")

    finding = result["findings"][0]
    assert_has_keys(finding, "func", "func_addr", "call_site", "sink", "vuln", "severity", "note")
    assert finding["severity"] in ("critical", "high", "medium", "low")


# ============================================================================
# find_crypto
# ============================================================================


@test()
def test_find_crypto_full_scan():
    """find_crypto scans for constants and tables."""
    result = find_crypto()
    assert_has_keys(result, "total_findings", "algorithms_found", "by_algorithm")
    assert isinstance(result["total_findings"], int)
    assert isinstance(result["algorithms_found"], list)
    assert isinstance(result["by_algorithm"], dict)


@test()
def test_find_crypto_constants_only():
    """find_crypto can scan constants without tables."""
    result = find_crypto(scan_constants=True, scan_tables=False)
    assert_has_keys(result, "total_findings", "by_algorithm")


@test()
def test_find_crypto_tables_only():
    """find_crypto can scan tables without constants."""
    result = find_crypto(scan_constants=False, scan_tables=True)
    assert_has_keys(result, "total_findings", "by_algorithm")


@test()
def test_find_crypto_pagination():
    """find_crypto respects offset and count parameters."""
    result = find_crypto(count=1)
    assert_has_keys(result, "by_algorithm")
    for algo, hits in result["by_algorithm"].items():
        assert len(hits) <= 1


# ============================================================================
# find_dangerous_callers
# ============================================================================


@test()
def test_find_dangerous_callers_by_name():
    """find_dangerous_callers traces callers of a named function."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    # Use any function as a "sink" - we just test the mechanics
    result = find_dangerous_callers(sink=fn_addr, max_depth=1)
    assert_has_keys(result, "sink", "sink_addr", "total_callers", "edges", "root_entry_points")
    assert isinstance(result["edges"], list)
    assert isinstance(result["total_callers"], int)


@test()
def test_find_dangerous_callers_pagination():
    """find_dangerous_callers respects offset and count."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = find_dangerous_callers(sink=fn_addr, max_depth=2, offset=0, count=5)
    assert_has_keys(result, "edges", "offset", "count", "next_offset")
    assert result["offset"] == 0
    assert len(result["edges"]) <= 5


@test()
def test_find_dangerous_callers_bad_sink():
    """find_dangerous_callers raises on invalid sink."""
    try:
        find_dangerous_callers(sink="nonexistent_function_xyz_12345")
        assert False, "Expected IDAError"
    except Exception as e:
        assert "not find" in str(e).lower() or "not found" in str(e).lower()


@test()
def test_find_dangerous_callers_edge_shape():
    """find_dangerous_callers edges have expected structure."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = find_dangerous_callers(sink=fn_addr, max_depth=2)
    if not result["edges"]:
        skip_test("function has no callers")

    edge = result["edges"][0]
    assert_has_keys(edge, "caller", "caller_addr", "call_site", "target", "target_addr", "depth")


# ============================================================================
# detect_stack_strings
# ============================================================================


@test()
def test_detect_stack_strings_full_scan():
    """detect_stack_strings scans all functions."""
    result = detect_stack_strings()
    assert_has_keys(result, "total", "results", "offset", "count", "next_offset")
    assert isinstance(result["total"], int)
    assert isinstance(result["results"], list)


@test()
def test_detect_stack_strings_single_function():
    """detect_stack_strings accepts a single function address."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = detect_stack_strings(addrs=fn_addr)
    assert_has_keys(result, "total", "results")
    # Results may be empty - that's fine, just check structure
    for item in result["results"]:
        assert_has_keys(item, "func", "func_addr", "string", "length", "first_insn")
        assert item["length"] >= 4  # default min_length


@test()
def test_detect_stack_strings_min_length():
    """detect_stack_strings respects min_length parameter."""
    result = detect_stack_strings(min_length=8)
    for item in result["results"]:
        assert item["length"] >= 8


@test()
def test_detect_stack_strings_pagination():
    """detect_stack_strings respects offset and count."""
    result = detect_stack_strings(offset=0, count=3)
    assert_has_keys(result, "offset", "count", "next_offset")
    assert result["offset"] == 0
    assert len(result["results"]) <= 3


# ============================================================================
# trace_source_to_sink
# ============================================================================


@test()
def test_trace_source_to_sink_basic():
    """trace_source_to_sink finds paths between two functions."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    # Use any two functions as source/sink - tests mechanics not accuracy
    import idautils
    funcs = list(idautils.Functions())
    if len(funcs) < 2:
        skip_test("need at least 2 functions")

    import idc
    src = idc.get_name(funcs[0], 0) or hex(funcs[0])
    sink = idc.get_name(funcs[-1], 0) or hex(funcs[-1])

    result = trace_source_to_sink(sources=src, sinks=sink, max_depth=2)
    assert_has_keys(result, "sources", "sinks", "forward_reachable_count",
                    "backward_reachable_count", "intersection_count", "paths")
    assert isinstance(result["paths"], list)


@test()
def test_trace_source_to_sink_no_source():
    """trace_source_to_sink raises on missing source."""
    try:
        trace_source_to_sink(sources="nonexistent_xyz", sinks="also_nonexistent")
        assert False, "Expected IDAError"
    except Exception as e:
        assert "not found" in str(e).lower() or "no source" in str(e).lower()


@test()
def test_trace_source_to_sink_pagination():
    """trace_source_to_sink respects offset and count."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    import idautils
    import idc
    funcs = list(idautils.Functions())
    if len(funcs) < 2:
        skip_test("need at least 2 functions")

    src = idc.get_name(funcs[0], 0) or hex(funcs[0])
    sink = idc.get_name(funcs[-1], 0) or hex(funcs[-1])

    result = trace_source_to_sink(sources=src, sinks=sink, max_depth=2, offset=0, count=5)
    assert_has_keys(result, "offset", "count", "next_offset")
    assert result["offset"] == 0
    assert len(result["paths"]) <= 5
