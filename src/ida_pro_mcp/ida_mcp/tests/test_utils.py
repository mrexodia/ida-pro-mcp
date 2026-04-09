"""Tests for IDA-facing helper functions in utils.py."""

from ..framework import test
from ..sync import IDAError
from ..utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    looks_like_address,
    get_function,
    get_prototype,
    get_type_by_name,
    paginate,
    pattern_filter,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    get_callees,
    get_callers,
    get_xrefs_from_internal,
    extract_function_strings,
    extract_function_constants,
    handle_large_output,
)


@test(binary="crackme03.elf")
def test_utils_parse_address_and_detection():
    """Address parsing helpers accept canonical inputs and reject malformed ones."""
    assert parse_address("0x123e") == 0x123E
    assert parse_address(0x123E) == 0x123E
    assert looks_like_address("0x123e") is True
    assert looks_like_address("123e") is True
    assert looks_like_address("main") is False
    try:
        parse_address("xyz")
        assert False, "expected parse_address to fail"
    except IDAError as e:
        assert "Not found" in str(e)


@test(binary="crackme03.elf")
def test_utils_parse_address_resolves_names():
    """parse_address resolves known symbol names to their addresses."""
    assert parse_address("main") == 0x123E
    assert parse_address("check_pw") == 0x11A9


@test()
def test_utils_parse_address_unknown_name():
    """parse_address raises IDAError for names that don't exist in the IDB."""
    try:
        parse_address("nonexistent_symbol_xyz_42")
        assert False, "expected parse_address to fail on unknown name"
    except IDAError as e:
        assert "Not found" in str(e)


@test(binary="crackme03.elf")
def test_utils_normalize_helpers():
    """Input normalization helpers handle strings, lists and JSON payloads."""
    assert normalize_list_input("a, b, c") == ["a", "b", "c"]
    assert normalize_list_input(["a", "b"]) == ["a", "b"]
    assert normalize_dict_list({"x": 1}) == [{"x": 1}]
    assert normalize_dict_list("a,b", lambda s: {"v": s}) == [{"v": "a"}, {"v": "b"}]
    assert normalize_dict_list('[{"x":1}]') == [{"x": 1}]


@test(binary="crackme03.elf")
def test_utils_get_function_and_prototype():
    """get_function and get_prototype resolve structured function metadata."""
    import idaapi

    fn = get_function(0x123E)
    assert fn["addr"] == "0x123e"
    assert fn["name"] == "main"
    assert fn["size"] == "0x104"
    assert get_function(0xDEADBEEF, raise_error=False) is None

    proto = get_prototype(idaapi.get_func(0x123E))
    assert proto is not None
    assert "int __fastcall" in proto


@test(binary="typed_fixture.elf")
def test_utils_get_type_by_name_named_and_builtin():
    """get_type_by_name resolves builtin and named types from the typed fixture."""
    assert str(get_type_by_name("int"))
    point = get_type_by_name("Point")
    assert point.get_type_name() == "Point"
    assert "Point" in str(point)


@test(binary="crackme03.elf")
def test_utils_paginate_and_pattern_filter():
    """Pagination and pattern filtering helpers behave deterministically."""
    data = [{"name": "main"}, {"name": "check_pw"}, {"name": "puts"}]
    page = paginate(data, 0, 2)
    assert len(page["data"]) == 2
    assert page["next_offset"] == 2
    assert [x["name"] for x in pattern_filter(data, "*pw", "name")] == ["check_pw"]
    assert [x["name"] for x in pattern_filter(data, "/MAIN/i", "name")] == ["main"]
    assert [x["name"] for x in pattern_filter(data, "put", "name")] == ["puts"]


@test(binary="typed_fixture.elf")
def test_utils_stack_frame_and_decompile_helpers():
    """Stack-frame and decompilation helpers expose typed_fixture details."""
    vars_ = get_stack_frame_variables_internal(0x1013DC0, True)
    names = {v["name"] for v in vars_}
    assert {"rhs_handle", "lhs_handle"}.issubset(names)

    code = decompile_function_safe(0x1013DC0)
    assert code is not None
    assert "sum_point" in code
    # Address annotations (/*0x....*/) are added via get_line_item; passing None
    # for the phead/ptail output params could crash IDA via null-pointer write.
    assert any("/*0x" in line for line in code.splitlines())


@test(binary="typed_fixture.elf")
def test_utils_assembly_xrefs_and_comments_helpers():
    """Assembly/xref/comment helpers produce structured views of the function."""
    asm = get_assembly_lines(0x1013DC0)
    assert "sum_point" in asm
    assert "g_numbers" in asm

    xrefs = get_all_xrefs(0x1013DC0)
    assert any(item["addr"] == "0x1013f1b" for item in xrefs["to"])

    comments = get_all_comments(0x1013DC0)
    assert isinstance(comments, dict)


@test(binary="typed_fixture.elf")
def test_utils_callees_callers_and_xrefs_from_helpers():
    """Call graph related utility helpers resolve deterministic relationships."""
    callees = get_callees("0x1013dc0")
    callee_names = {c["name"] for c in callees}
    assert "sum_point" in callee_names

    callers = get_callers("0x1013dc0")
    assert isinstance(callers, list)

    xrefs_from = get_xrefs_from_internal(0x1013F1B)
    assert any(x["addr"] == "0x1013dc0" for x in xrefs_from)


@test(binary="crackme03.elf")
def test_utils_extract_strings_and_constants():
    """Utility extractors find referenced strings and immediate constants."""
    strings = extract_function_strings(0x123E)
    assert any("Need exactly one argument." in s["string"] for s in strings)

    constants = extract_function_constants(0x11A9)
    values = {c["decimal"] for c in constants}
    assert any(v != 0 for v in values)


@test(binary="crackme03.elf")
def test_utils_handle_large_output():
    """Large output helper leaves small payloads inline and spills large payloads to a file reference."""
    small = handle_large_output({"x": 1}, line_threshold=100)
    assert small == {"x": 1}

    big = handle_large_output({"lines": [str(i) for i in range(100)]}, line_threshold=3)
    assert big["type"] == "file_reference"
    assert "path" in big
    assert big["line_count"] > 3
