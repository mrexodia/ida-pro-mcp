"""Tests for api_analysis API functions."""

from ..framework import (
    test,
    skip_test,
    assert_has_keys,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_shape,
    assert_ok,
    assert_error,
    is_hex_address,
    optional,
    get_any_function,
    get_data_address,
    get_unmapped_address,
)
from ..api_analysis import (
    decompile,
    disasm,
    func_profile,
    analyze_batch,
    xrefs_to,
    xref_query,
    insn_query,
    xrefs_to_field,
    callees,
    find_bytes,
    basic_blocks,
    find,
    export_funcs,
    callgraph,
)


CRACKME_CHECK_PW = "0x11a9"
CRACKME_MAIN = "0x123e"
CRACKME_CALL_TO_CHECK_PW = "0x12d3"
CRACKME_USAGE_STRING = "0x2004"


@test()
def test_decompile_valid_function():
    """decompile returns non-empty pseudocode for a valid function."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = decompile(fn_addr)
    assert_shape(result, {"addr": str, "code": optional(str), "error": optional(str)})
    assert_ok(result, "code")
    assert_non_empty(result["code"])


@test(binary="crackme03.elf")
def test_decompile_main_contains_expected_logic():
    """decompile(main) exposes the core crackme logic in pseudocode."""
    result = decompile("main")
    assert_ok(result, "code")
    code = result["code"]
    assert "check_pw" in code
    assert "Need exactly one argument." in code
    assert "Yes, %s is correct!" in code


@test()
def test_decompile_invalid_address():
    """decompile reports an error for an unmapped address."""
    result = decompile(get_unmapped_address())
    assert result["code"] is None
    assert_error(result)


@test()
def test_decompile_batch_addresses():
    """multiple valid function addresses can all be decompiled individually."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:3]]
    if len(addrs) < 2:
        skip_test("binary has fewer than two functions")

    results = [decompile(addr) for addr in addrs]
    assert len(results) == len(addrs)
    for result, addr in zip(results, addrs):
        assert result["addr"] == addr
        assert_ok(result, "code")


@test(binary="crackme03.elf")
def test_decompile_by_name():
    """decompile accepts a function name and returns crackme pseudocode."""
    result = decompile("check_pw")
    assert_ok(result, "code")
    assert "return" in result["code"]


@test()
def test_decompile_unknown_name():
    """decompile returns a specific error for an unknown function name."""
    result = decompile("nonexistent_function_xyz")
    assert result["code"] is None
    assert_error(result, contains="Not found")


@test(binary="crackme03.elf")
def test_decompile_default_includes_address_markers():
    """Default output carries /*0xNNNN*/ markers on at least one line."""
    result = decompile("main")
    assert_ok(result, "code")
    assert "/*0x" in result["code"]


@test(binary="crackme03.elf")
def test_decompile_include_addresses_false_strips_markers():
    """include_addresses=False drops all /*0xNNNN*/ markers."""
    result = decompile("main", include_addresses=False)
    assert_ok(result, "code")
    assert "/*0x" not in result["code"]


@test()
def test_disasm_valid_function():
    """disasm returns non-empty assembly for a valid function."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = disasm(fn_addr)
    assert_shape(
        result,
        {
            "addr": str,
            "asm": optional(
                {
                    "name": str,
                    "start_ea": is_hex_address,
                    "lines": list,
                }
            ),
            "instruction_count": int,
            "total_instructions": optional(int),
            "cursor": dict,
            "error": optional(str),
        },
    )
    assert_ok(result, "asm")
    assert_non_empty(result["asm"]["lines"])


@test(binary="crackme03.elf")
def test_disasm_main_contains_expected_calls():
    """disasm(main) contains the expected crackme call sites and metadata."""
    result = disasm(CRACKME_MAIN, max_instructions=64)
    assert_ok(result, "asm")
    asm = result["asm"]
    assert asm["name"] == "main"
    assert asm["start_ea"] == CRACKME_MAIN
    lines_text = " ".join(item["instruction"] for item in asm["lines"])
    assert "check_pw" in lines_text
    assert "_puts" in lines_text
    assert result["instruction_count"] > 0


@test()
def test_disasm_pagination():
    """disasm enforces max_instructions and advances the cursor."""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    page1 = disasm(fn_addr, max_instructions=5)
    assert_ok(page1, "asm")
    assert page1["instruction_count"] <= 5
    if "next" in page1["cursor"]:
        page2 = disasm(fn_addr, max_instructions=5, offset=page1["cursor"]["next"])
        assert_ok(page2, "asm")
        assert page2["asm"]["lines"] != page1["asm"]["lines"]


@test()
def test_disasm_unmapped_address():
    """disasm reports an error for an unmapped address."""
    result = disasm(get_unmapped_address())
    assert result["asm"] is None
    assert_error(result)


@test()
def test_disasm_data_segment():
    """disasm can still produce a structured response for a data-segment address."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = disasm(data_addr, max_instructions=4)
    assert result["addr"] == data_addr
    assert "cursor" in result


@test(binary="crackme03.elf")
def test_disasm_by_name():
    """disasm accepts a function name and returns the correct symbol metadata."""
    result = disasm("check_pw", max_instructions=8)
    assert_ok(result, "asm")
    assert result["asm"]["name"] == "check_pw"
    assert result["asm"]["start_ea"] == CRACKME_CHECK_PW


@test()
def test_disasm_unknown_name():
    """disasm returns a specific error for an unknown function name."""
    result = disasm("nonexistent_function_xyz")
    assert result["asm"] is None
    assert_error(result, contains="Not found")


@test()
def test_disasm_interior_address_preserves_cursor():
    """disasm preserves the queried interior address as start_ea for pagination."""
    import idaapi
    import idc

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    func = idaapi.get_func(int(fn_addr, 16))
    if not func:
        skip_test("IDA could not resolve function object")

    interior = idc.next_head(func.start_ea, func.end_ea)
    if interior == idaapi.BADADDR or interior == func.start_ea:
        skip_test("function has no interior instruction")

    result = disasm(hex(interior), max_instructions=4)
    assert_ok(result, "asm")
    assert result["asm"]["start_ea"] == hex(interior)


@test(binary="crackme03.elf")
def test_decompile_refs_include_check_pw():
    """decompile surfaces cot_obj refs, including the check_pw call target."""
    result = decompile(CRACKME_MAIN)
    assert_ok(result, "code")
    refs = result.get("refs", [])
    hit = next((r for r in refs if r["name"] == "check_pw"), None)
    assert hit is not None, f"check_pw not in decompile refs: {refs}"
    assert hit["addr"] == CRACKME_CHECK_PW


@test(binary="crackme03.elf")
def test_decompile_refs_decode_usage_string():
    """decompile refs carry decoded bytes for string-literal data targets."""
    result = decompile(CRACKME_MAIN)
    assert_ok(result, "code")
    refs = result.get("refs", [])
    hit = next((r for r in refs if r["addr"] == CRACKME_USAGE_STRING), None)
    assert hit is not None, f"usage-string ref missing: {refs}"
    assert "string" in hit, f"decoded string missing on ref: {hit}"
    assert "Need exactly" in hit["string"]


@test(binary="crackme03.elf")
def test_disasm_labels_populated():
    """disasm populates `label` on the function head and on branch targets."""
    result = disasm(CRACKME_MAIN, max_instructions=200)
    assert_ok(result, "asm")
    lines = result["asm"]["lines"]
    first = lines[0]
    assert first["addr"] == CRACKME_MAIN.removeprefix("0x")
    assert first.get("label") == "main"
    # At least one interior branch-target label should be present
    interior_labels = [ln["label"] for ln in lines[1:] if "label" in ln]
    assert interior_labels, "expected at least one interior label (e.g. loc_...)"


@test(binary="crackme03.elf")
def test_disasm_resolves_call_target():
    """disasm resolves `call check_pw` to a ref pointing at CRACKME_CHECK_PW."""
    result = disasm(CRACKME_MAIN, max_instructions=200)
    assert_ok(result, "asm")
    call_line = next(
        (ln for ln in result["asm"]["lines"] if ln["addr"] == CRACKME_CALL_TO_CHECK_PW.removeprefix("0x")),
        None,
    )
    assert call_line is not None, "missing expected call-to-check_pw line"
    refs = call_line.get("refs", [])
    hit = next((r for r in refs if r["name"] == "check_pw"), None)
    assert hit is not None, f"check_pw not in refs: {refs}"
    assert hit["addr"] == CRACKME_CHECK_PW


@test(binary="crackme03.elf")
def test_disasm_branch_ref_uses_local_label():
    """A branch to an in-function label must resolve to the label, not `main`."""
    result = disasm(CRACKME_MAIN, max_instructions=200)
    assert_ok(result, "asm")
    branch_refs = [
        r
        for ln in result["asm"]["lines"]
        for r in ln.get("refs", [])
        if r["name"].startswith("loc_")
    ]
    assert branch_refs, "expected at least one loc_* branch ref inside main"
    for ref in branch_refs:
        assert ref["name"] != "main", f"containing function leaked into ref: {ref}"


@test(binary="crackme03.elf")
def test_disasm_resolves_data_ref():
    """disasm resolves a load of the usage string to a data ref with its symbol."""
    result = disasm(CRACKME_MAIN, max_instructions=200)
    assert_ok(result, "asm")
    hits = [
        r
        for ln in result["asm"]["lines"]
        for r in ln.get("refs", [])
        if r["addr"] == CRACKME_USAGE_STRING
    ]
    assert hits, "expected a data ref to the usage string"


@test(binary="crackme03.elf")
def test_disasm_captures_comments():
    """disasm surfaces a user-set comment on an instruction line."""
    import ida_bytes

    ea = int(CRACKME_CALL_TO_CHECK_PW, 16)
    marker = "mcp-test-comment"
    prev = ida_bytes.get_cmt(ea, False)
    try:
        ida_bytes.set_cmt(ea, marker, False)
        result = disasm(CRACKME_MAIN, max_instructions=200)
        assert_ok(result, "asm")
        line = next(
            (ln for ln in result["asm"]["lines"] if ln["addr"] == CRACKME_CALL_TO_CHECK_PW.removeprefix("0x")),
            None,
        )
        assert line is not None
        assert marker in line.get("comments", []), f"comment missing: {line}"
    finally:
        ida_bytes.set_cmt(ea, prev or "", False)


@test(binary="crackme03.elf")
def test_disasm_captures_repeatable_and_extra_comments():
    """disasm surfaces repeatable comments and anterior/posterior extra comments."""
    import ida_bytes
    import ida_lines

    ea = int(CRACKME_CALL_TO_CHECK_PW, 16)
    prev_rep = ida_bytes.get_cmt(ea, True)
    try:
        ida_bytes.set_cmt(ea, "rep-marker", True)
        ida_lines.update_extra_cmt(ea, ida_lines.E_PREV, "ante-marker-0")
        ida_lines.update_extra_cmt(ea, ida_lines.E_PREV + 1, "ante-marker-1")
        ida_lines.update_extra_cmt(ea, ida_lines.E_NEXT, "post-marker")

        result = disasm(CRACKME_MAIN, max_instructions=200)
        assert_ok(result, "asm")
        line = next(
            (
                ln
                for ln in result["asm"]["lines"]
                if ln["addr"] == CRACKME_CALL_TO_CHECK_PW.removeprefix("0x")
            ),
            None,
        )
        assert line is not None
        comments = line.get("comments", [])
        for marker in ("rep-marker", "ante-marker-0", "ante-marker-1", "post-marker"):
            assert marker in comments, f"{marker} missing: {comments}"
        # Ordering contract: anterior (multi-line, in order) -> inline -> posterior
        assert (
            comments.index("ante-marker-0")
            < comments.index("ante-marker-1")
            < comments.index("rep-marker")
            < comments.index("post-marker")
        )
    finally:
        ida_bytes.set_cmt(ea, prev_rep or "", True)
        ida_lines.del_extra_cmt(ea, ida_lines.E_PREV)
        ida_lines.del_extra_cmt(ea, ida_lines.E_PREV + 1)
        ida_lines.del_extra_cmt(ea, ida_lines.E_NEXT)


@test(binary="crackme03.elf")
def test_disasm_ref_decodes_string_literal():
    """A data ref targeting a string literal carries the decoded bytes."""
    result = disasm(CRACKME_MAIN, max_instructions=200)
    assert_ok(result, "asm")
    usage_refs = [
        r
        for ln in result["asm"]["lines"]
        for r in ln.get("refs", [])
        if r["addr"] == CRACKME_USAGE_STRING
    ]
    assert usage_refs, "expected a ref to the usage string"
    with_string = [r for r in usage_refs if "string" in r]
    assert with_string, f"no ref carried a decoded string: {usage_refs}"
    assert "Need exactly" in with_string[0]["string"]


@test(binary="crackme03.elf")
def test_xrefs_to_check_pw_from_main():
    """xrefs_to(check_pw) includes the known call from main."""
    result = xrefs_to(CRACKME_CHECK_PW)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["addr"] == CRACKME_CHECK_PW
    assert_is_list(entry["xrefs"], min_length=1)
    hit = next(
        (xref for xref in entry["xrefs"] if xref["addr"] == CRACKME_CALL_TO_CHECK_PW),
        None,
    )
    assert hit is not None, "expected call site 0x12d3 -> check_pw"
    assert hit["type"] == "code"
    assert hit["fn"]["name"] == "main"


@test(binary="crackme03.elf")
def test_xrefs_to_by_name():
    """xrefs_to accepts a function name and returns the same xrefs as by address."""
    result = xrefs_to("check_pw")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_is_list(entry["xrefs"], min_length=1)
    hit = next(
        (xref for xref in entry["xrefs"] if xref["addr"] == CRACKME_CALL_TO_CHECK_PW),
        None,
    )
    assert hit is not None, "expected call site 0x12d3 -> check_pw via name"
    assert hit["fn"]["name"] == "main"


@test()
def test_xrefs_to_invalid():
    """xrefs_to reports an error or empty xrefs for an invalid address."""
    result = xrefs_to(get_unmapped_address())
    assert_is_list(result, min_length=1)
    assert result[0]["addr"] == get_unmapped_address()
    if result[0].get("xrefs") is None:
        assert_error(result[0])


@test()
def test_xref_query():
    """xref_query returns paged xref results for a function"""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = xref_query(
        {
            "addr": fn_addr,
            "direction": "both",
            "xref_type": "any",
            "offset": 0,
            "count": 10,
            "include_fn": True,
        }
    )
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "target", "resolved_addr", "data", "next_offset", "total", "error")
    if page["data"]:
        assert_has_keys(page["data"][0], "direction", "addr", "from", "to", "type")


@test()
def test_insn_query_function_scope():
    """insn_query supports scoped instruction search with pagination"""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = insn_query({"func": fn_addr, "count": 8, "include_disasm": True})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "query", "matches", "count", "scanned", "cursor", "error")
    assert page.get("error") is None
    if page["matches"]:
        assert_has_keys(page["matches"][0], "addr", "disasm")


@test()
def test_insn_query_requires_scope_by_default():
    """insn_query rejects broad scans unless allow_broad is set"""
    result = insn_query({"mnem": "call"})
    assert_is_list(result, min_length=1)
    assert result[0].get("error") is not None


# ============================================================================
# Tests for xrefs_to_field
# ============================================================================


@test()
def test_xrefs_to_field_nonexistent_struct():
    """xrefs_to_field reports a missing-struct error."""
    result = xrefs_to_field({"struct": "NonExistentStruct", "field": "nonexistent"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test()
def test_xrefs_to_field_batch():
    """xrefs_to_field accepts batch input and returns one result per query."""
    result = xrefs_to_field(
        [
            {"struct": "Struct1", "field": "field1"},
            {"struct": "Struct2", "field": "field2"},
        ]
    )
    assert_is_list(result, min_length=2)


@test(binary="crackme03.elf")
def test_callees_main_contains_expected_targets():
    """callees(main) returns the expected crackme callees."""
    result = callees(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_is_list(entry["callees"], min_length=1)
    by_name = {callee["name"]: callee for callee in entry["callees"]}
    assert "check_pw" in by_name
    assert ".printf" in by_name
    assert by_name["check_pw"]["addr"] == CRACKME_CHECK_PW


@test(binary="crackme03.elf")
def test_callees_by_name():
    """callees accepts a function name and returns the same callees as by address."""
    result = callees("main")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_is_list(entry["callees"], min_length=1)
    by_name = {callee["name"]: callee for callee in entry["callees"]}
    assert "check_pw" in by_name


@test()
def test_callees_multiple():
    """callees accepts multiple addresses and returns one result per input."""
    import idautils

    addrs = [hex(ea) for ea in list(idautils.Functions())[:3]]
    if len(addrs) < 2:
        skip_test("binary has fewer than two functions")

    result = callees(addrs)
    assert len(result) == len(addrs)


@test()
def test_callees_invalid_address():
    """callees reports a useful error for an invalid address."""
    result = callees(get_unmapped_address())
    assert_is_list(result, min_length=1)
    assert result[0]["callees"] is None
    assert_error(result[0])


@test(binary="crackme03.elf")
def test_find_bytes_matches_known_call_opcode_sequence():
    """find_bytes can locate a known call opcode sequence in the crackme text section."""
    result = find_bytes("E8", limit=20)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["n"] > 0
    assert_is_list(entry["matches"], min_length=1)
    for addr in entry["matches"]:
        assert_valid_address(addr)


@test(binary="crackme03.elf")
def test_basic_blocks_main_matches_known_cfg_shape():
    """basic_blocks(main) returns the known crackme CFG entry block and block count."""
    result = basic_blocks(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "blocks")
    assert entry["total_blocks"] == 9
    assert entry["blocks"][0]["start"] == CRACKME_MAIN
    assert entry["blocks"][0]["end"] == "0x1266"
    for block in entry["blocks"]:
        assert_valid_address(block["start"])
        assert_valid_address(block["end"])
        assert int(block["end"], 16) > int(block["start"], 16)


@test()
def test_basic_blocks_invalid_address():
    """basic_blocks reports a function-not-found error for unmapped roots."""
    result = basic_blocks(get_unmapped_address())
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Function not found")


@test(binary="crackme03.elf")
def test_find_string_known_usage_literal():
    """find(string, ...) locates the known crackme usage string."""
    result = find("string", "Need exactly one argument.")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["error"] is None
    assert CRACKME_USAGE_STRING in entry["matches"]


@test(binary="crackme03.elf")
def test_find_code_ref_to_check_pw():
    """find(code_ref, check_pw) finds the known call site inside main."""
    result = find("code_ref", CRACKME_CHECK_PW)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["error"] is None
    assert CRACKME_CALL_TO_CHECK_PW in entry["matches"]


@test()
def test_find_invalid_type():
    """find reports an unknown search type as an error."""
    result = find("invalid_type", "test")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Unknown search type")


@test()
def test_find_immediate_out_of_range():
    """find(immediate, ...) reports out-of-range immediates explicitly."""
    result = find("immediate", str(1 << 80))
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Immediate out of range")


@test()
def test_find_data_ref_invalid_target():
    """find(data_ref, ...) reports invalid target address parsing errors."""
    result = find("data_ref", "definitely_not_an_address")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not found")


@test()
def test_find_string_empty_pattern():
    """find(string, '') reports an empty-pattern error rather than silently succeeding."""
    result = find("string", "")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Empty pattern")


@test(binary="crackme03.elf")
def test_export_funcs_json_contains_expected_content():
    """export_funcs(json) returns prototype, asm, code and xrefs for main."""
    result = export_funcs(CRACKME_MAIN, format="json")
    assert result["format"] == "json"
    assert_is_list(result["functions"], min_length=1)
    fn = result["functions"][0]
    assert fn["name"] == "main"
    assert "prototype" in fn and "int __fastcall" in fn["prototype"]
    assert "check_pw" in fn["asm"]
    assert "Need exactly one argument." in fn["code"]
    assert isinstance(fn["xrefs"], dict)


@test(binary="crackme03.elf")
def test_export_funcs_c_header_contains_main_prototype():
    """export_funcs(c_header) emits a declaration-like header containing main."""
    result = export_funcs(CRACKME_MAIN, format="c_header")
    assert result["format"] == "c_header"
    assert "__fastcall" in result["content"]
    assert "Auto-generated by IDA Pro MCP" in result["content"]


@test(binary="typed_fixture.elf")
def test_export_funcs_prototypes_format():
    """export_funcs(prototypes) returns a compact prototype list for typed_fixture."""
    result = export_funcs("0x1013dc0", format="prototypes")
    assert result["format"] == "prototypes"
    assert_is_list(result["functions"], min_length=1)
    assert result["functions"][0]["name"] == "use_wrapper"
    assert "__cdecl" in result["functions"][0]["prototype"]


@test()
def test_export_funcs_invalid_address():
    """export_funcs(json) reports an error for an invalid function address."""
    result = export_funcs(get_unmapped_address(), format="json")
    assert result["format"] == "json"
    assert_is_list(result["functions"], min_length=1)
    assert_error(result["functions"][0])


@test(binary="crackme03.elf")
def test_callgraph_main_contains_expected_nodes():
    """callgraph(main) includes the local crackme call edge to check_pw."""
    result = callgraph(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_is_list(entry["nodes"], min_length=1)
    assert_is_list(entry["edges"], min_length=1)
    names = {node["name"] for node in entry["nodes"]}
    assert {"main", "check_pw"}.issubset(names)
    assert any(edge["from"] == CRACKME_MAIN and edge["to"] == CRACKME_CHECK_PW for edge in entry["edges"])
    for node in entry["nodes"]:
        assert_valid_address(node["addr"])
        assert node["depth"] >= 0
    for edge in entry["edges"]:
        assert_valid_address(edge["from"])
        assert_valid_address(edge["to"])
        assert edge["type"] == "call"


@test(binary="typed_fixture.elf")
def test_callgraph_depth_zero_keeps_only_root_node():
    """callgraph(max_depth=0) still returns the root node deterministically."""
    result = callgraph("0x1013dc0", max_depth=0)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert len(entry["nodes"]) == 1
    assert entry["nodes"][0]["name"] == "use_wrapper"
    assert entry["nodes"][0]["depth"] == 0


@test()
def test_callgraph_invalid_root():
    """callgraph reports an error for an invalid root function."""
    result = callgraph(get_unmapped_address())
    assert_is_list(result, min_length=1)
    assert_error(result[0])


# ============================================================================
# Tests for func_profile / analyze_batch
# ============================================================================


@test()
def test_func_profile():
    """func_profile returns function profile metrics"""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = func_profile({"addr": fn_addr, "include_lists": False})
    assert_is_list(result, min_length=1)
    page = result[0]
    assert_has_keys(page, "data", "next_offset", "error")
    if page["data"]:
        r = page["data"][0]
        assert_has_keys(
            r,
            "addr",
            "name",
            "size",
            "instruction_count",
            "basic_block_count",
            "caller_count",
            "callee_count",
            "has_type",
            "error",
        )


@test()
def test_analyze_batch():
    """analyze_batch returns structured analysis for a function"""
    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    result = analyze_batch(
        {
            "addr": fn_addr,
            "include_disasm": True,
            "max_disasm_insns": 16,
            "include_strings": True,
            "max_strings": 16,
            "include_constants": True,
            "max_constants": 16,
            "include_basic_blocks": True,
            "max_blocks": 16,
        }
    )
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "target", "addr", "name", "analysis", "error")
    if r["analysis"] is not None:
        a = r["analysis"]
        assert_has_keys(
            a,
            "size",
            "decompile",
            "disasm",
            "xrefs",
            "caller_count",
            "callee_count",
            "string_ref_count",
            "constant_count",
            "basic_block_count",
        )
