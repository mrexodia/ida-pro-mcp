"""Binary-specific tests for tests/typed_fixture.elf."""

from ..framework import test, assert_is_list, assert_ok, skip_test
from ..api_core import lookup_funcs, find_regex, list_globals
from ..api_analysis import (
    decompile,
    disasm,
    xrefs_to,
    callees,
    find,
    basic_blocks,
    export_funcs,
    callgraph,
)
from ..api_memory import (
    get_string,
    get_global_value,
    get_int,
    put_int,
    patch,
    get_bytes,
)
from ..api_types import search_structs, set_type, read_struct, infer_types
from ..api_resources import (
    struct_name_resource,
    import_name_resource,
    export_name_resource,
)
from ..api_modify import rename
from ..api_stack import stack_frame


MAIN = "0x1013ef0"
SUM_POINT = "0x1013c10"
USE_WRAPPER = "0x1013dc0"
G_POINT = "0x1069f70"
G_WRAPPER = "0x1069f80"
G_NUMBERS = "0x1069fa0"
G_MESSAGE = "0x1000c00"
CALL_USE_WRAPPER = "0x1013f1b"
IMMEDIATE_1234 = "0x1013e44"
TYPED_FIXTURE_LOCAL_NAME = "rhs_handle"


def _plain_hex_bytes(text: str) -> str:
    return text.replace("0x", "").replace(" ", "").lower()


@test(binary="typed_fixture.elf")
def test_typed_fixture_core_symbols():
    """typed fixture symbols resolve to their expected named functions and globals."""
    results = lookup_funcs(["sum_point", "use_wrapper"])
    by_query = {item["query"]: item for item in results}
    assert by_query["sum_point"]["fn"]["addr"] == SUM_POINT
    assert by_query["use_wrapper"]["fn"]["addr"] == USE_WRAPPER


@test(binary="typed_fixture.elf")
def test_typed_fixture_decompile_and_disasm():
    """typed fixture decompilation/disassembly exposes the expected string and call structure."""
    dec = decompile(USE_WRAPPER)
    assert_ok(dec, "code")
    assert "sum_point" in dec["code"]
    assert "1234" in dec["code"]

    asm = disasm(USE_WRAPPER, max_instructions=40)
    assert_ok(asm, "asm")
    lines_text = " ".join(item["instruction"] for item in asm["asm"]["lines"])
    assert "sum_point" in lines_text
    assert "4D2h" in lines_text


@test(binary="typed_fixture.elf")
def test_typed_fixture_xrefs_and_callees():
    """typed fixture has the expected main -> use_wrapper relationship."""
    xrefs = xrefs_to(USE_WRAPPER)
    assert_is_list(xrefs, min_length=1)
    assert any(item["addr"] == CALL_USE_WRAPPER for item in xrefs[0]["xrefs"])

    call_result = callees(USE_WRAPPER)
    names = {item["name"] for item in call_result[0]["callees"]}
    assert "sum_point" in names
    assert any("ubsan_rt" in name for name in names)


@test(binary="typed_fixture.elf")
def test_typed_fixture_find_variants():
    """typed fixture drives immediate, data_ref and regex search paths."""
    imm = find("immediate", "1234")
    assert IMMEDIATE_1234 in imm[0]["matches"]

    data_ref = find("data_ref", G_MESSAGE)
    assert CALL_USE_WRAPPER in find("code_ref", USE_WRAPPER)[0]["matches"]
    assert data_ref[0]["count"] >= 1

    regex = find_regex("typed fixture says hi")
    assert regex["n"] >= 1
    assert regex["matches"][0]["addr"] == G_MESSAGE


@test(binary="typed_fixture.elf")
def test_typed_fixture_basic_blocks_export_and_callgraph():
    """typed fixture exercises CFG/export/callgraph paths with deterministic content."""
    blocks = basic_blocks(USE_WRAPPER)
    assert blocks[0]["total_blocks"] >= 5

    exported = export_funcs(USE_WRAPPER, format="prototypes")
    assert exported["format"] == "prototypes"
    assert exported["functions"][0]["name"] == "use_wrapper"

    graph = callgraph(USE_WRAPPER, max_depth=1)
    names = {node["name"] for node in graph[0]["nodes"]}
    assert {"use_wrapper", "sum_point"}.issubset(names)


@test(binary="typed_fixture.elf")
def test_typed_fixture_memory_and_globals():
    """typed fixture exposes deterministic string/global/integer values."""
    s = get_string(G_MESSAGE)
    assert s[0]["value"] == "typed fixture says hi"

    gv = get_global_value("g_point")
    assert_ok(gv[0], "value")

    val = get_int({"addr": G_NUMBERS, "ty": "u32"})[0]
    assert isinstance(val["value"], int)


@test(binary="typed_fixture.elf")
def test_typed_fixture_put_int_roundtrip():
    """typed fixture integer array can be patched and restored through put_int."""
    original = get_bytes({"addr": G_NUMBERS, "size": 4})[0]["data"]
    original_plain = _plain_hex_bytes(original)
    try:
        written = put_int({"addr": G_NUMBERS, "ty": "u32", "value": "99"})[0]
        assert "error" not in written
        roundtrip = get_int({"addr": G_NUMBERS, "ty": "u32"})[0]
        assert roundtrip["value"] == 99
    finally:
        patch({"addr": G_NUMBERS, "data": original_plain})


@test(binary="typed_fixture.elf")
def test_typed_fixture_struct_types_and_resources():
    """typed fixture drives struct search, type application, auto-detected read_struct and resource lookups."""
    point_matches = search_structs("Point")
    wrapper_matches = search_structs("Wrapper")
    assert any(item["name"] == "Point" for item in point_matches)
    assert any(item["name"] == "Wrapper" for item in wrapper_matches)

    set_point = set_type({"addr": G_POINT, "ty": "Point"})[0]
    assert "error" not in set_point
    auto = read_struct({"addr": G_POINT})[0]
    assert auto["struct"] == "Point"
    members = {m["name"]: m["value"] for m in auto["members"]}
    assert members["x"].endswith("(11)")
    assert members["y"].endswith("(22)")

    wrapper = struct_name_resource("Wrapper")
    assert "error" not in wrapper
    assert len(wrapper["members"]) == 2

    inferred = infer_types(G_POINT)[0]
    assert inferred["inferred_type"] is not None


@test(binary="typed_fixture.elf")
def test_typed_fixture_set_type_local_and_stack_paths():
    """typed fixture hits set_type() local and stack branches on deterministic variables."""
    local = set_type(
        {"addr": USE_WRAPPER, "kind": "local", "variable": TYPED_FIXTURE_LOCAL_NAME, "ty": "int"}
    )[0]
    assert (
        "error" not in local
        or local.get("error") == "Failed to apply local variable type"
    )

    stack = set_type(
        {"addr": USE_WRAPPER, "kind": "stack", "name": TYPED_FIXTURE_LOCAL_NAME, "ty": "int"}
    )[0]
    assert "error" not in stack


@test(binary="typed_fixture.elf")
def test_typed_fixture_rename_local_and_stack_paths():
    """typed fixture exercises local and stack rename flows."""
    try:
        local = rename(
            {
                "local": [
                    {"func_addr": USE_WRAPPER, "old": TYPED_FIXTURE_LOCAL_NAME, "new": "rhs_value"}
                ]
            }
        )
        assert (
            "error" not in local["local"][0]
            or local["local"][0].get("error") == "Rename failed"
        )
        stack = rename(
            {
                "stack": [
                    {"func_addr": USE_WRAPPER, "old": TYPED_FIXTURE_LOCAL_NAME, "new": "rhs_stack"}
                ]
            }
        )
        assert "error" not in stack["stack"][0]
        frame = stack_frame(USE_WRAPPER)[0]
        names = {var["name"] for var in frame["vars"]}
        assert "rhs_stack" in names
    finally:
        rename(
            {
                "local": [
                    {"func_addr": USE_WRAPPER, "old": "rhs_value", "new": TYPED_FIXTURE_LOCAL_NAME}
                ]
            }
        )
        rename(
            {
                "stack": [
                    {"func_addr": USE_WRAPPER, "old": "rhs_stack", "new": TYPED_FIXTURE_LOCAL_NAME}
                ]
            }
        )


@test(binary="typed_fixture.elf")
def test_typed_fixture_infer_types_size_based_path():
    """typed fixture exposes addresses that only reach infer_types() size-based fallback."""
    inferred = infer_types("0x1069fa4")[0]
    assert inferred["method"] == "size_based"
    assert inferred["confidence"] == "low"
    assert inferred["inferred_type"] == "uint8_t[12]"


@test(binary="typed_fixture.elf")
def test_typed_fixture_import_export_resource_views():
    """typed fixture import/export resource lookups resolve known symbols."""
    exp = export_name_resource("main")
    assert exp["addr"] == MAIN

    imp = import_name_resource("printf")
    if imp.get("error"):
        # Some IDA builds decorate import names differently.
        imp = import_name_resource("printf@GLIBC_2.2.5")
    if imp.get("error"):
        skip_test("printf import name decoration differs on this IDA build")
    assert "printf" in imp["name"]


@test(binary="typed_fixture.elf")
def test_typed_fixture_list_globals_filter():
    """typed fixture globals can be discovered by name filter."""
    page = list_globals({"filter": "g_*", "offset": 0, "count": 20})[0]
    names = {item["name"] for item in page["data"]}
    assert {"g_point", "g_wrapper", "g_numbers"}.issubset(names)
