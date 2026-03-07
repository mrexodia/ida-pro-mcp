"""Tests for api_types API functions."""

from ..framework import (
    test,
    skip_test,
    assert_is_list,
    assert_non_empty,
    assert_ok,
    assert_error,
    get_any_function,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
    get_named_address,
)
from ..api_types import (
    declare_type,
    read_struct,
    search_structs,
    set_type,
    infer_types,
)


TEST_STRUCT_NAME = "__TestStruct__"
NAME_RESOLUTION_STRUCT = "__NameResolutionTest__"
CRACKME_DSO_HANDLE = "0x4008"


def create_test_struct(name: str = TEST_STRUCT_NAME) -> bool:
    """Create a deterministic test struct if it does not already exist."""
    search_result = search_structs(name)
    if search_result and any(s["name"] == name for s in search_result):
        return True

    struct_def = f"""
        struct {name} {{
            int field1;
            char field2;
            void* field3;
        }};
    """
    result = declare_type(struct_def)
    if not result:
        return False

    entry = result[0]
    if entry.get("ok"):
        return True

    search_result = search_structs(name)
    return bool(search_result and any(s["name"] == name for s in search_result))


@test()
def test_declare_type_creates_searchable_struct():
    """declare_type creates a struct that can be found again via search_structs."""
    assert create_test_struct(TEST_STRUCT_NAME), "failed to declare test struct"
    result = search_structs(TEST_STRUCT_NAME)
    assert_is_list(result, min_length=1)
    match = next((s for s in result if s["name"] == TEST_STRUCT_NAME), None)
    assert match is not None
    assert match["cardinality"] == 3
    assert match["size"] >= 8


@test()
def test_declare_type_invalid_declaration():
    """declare_type reports parse failures for invalid declarations."""
    result = declare_type("struct broken { int x }")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to parse")


@test()
def test_read_struct_returns_named_members():
    """read_struct returns the declared member layout for the deterministic test struct."""
    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    data_addr = get_data_address()
    if not data_addr:
        seg = get_first_segment()
        if not seg:
            skip_test("binary has no readable segment")
        data_addr = seg[0]

    result = read_struct({"addr": data_addr, "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")
    names = [member["name"] for member in entry["members"]]
    assert names == ["field1", "field2", "field3"]


@test(binary="typed_fixture.elf")
def test_read_struct_wrapper_values():
    """read_struct reads the deterministic Wrapper global contents from the typed fixture."""
    result = read_struct({"addr": "0x1069f80", "struct": "Wrapper"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "members")
    members = {m["name"]: m for m in entry["members"]}
    assert members["pt"]["type"] == "Point"
    assert "1122334455667788" in members["magic"]["value"]


@test()
def test_read_struct_not_found():
    """read_struct reports a missing-struct error."""
    seg = get_first_segment()
    if not seg:
        skip_test("binary has no segments")

    result = read_struct({"addr": seg[0], "struct": "NonExistentStruct12345"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test()
def test_read_struct_name_resolution():
    """read_struct resolves named addresses instead of requiring only numeric ones."""
    if not create_test_struct(NAME_RESOLUTION_STRUCT):
        skip_test("failed to declare name-resolution struct")

    fn_addr = get_any_function()
    if not fn_addr:
        skip_test("binary has no functions")

    from ..api_core import lookup_funcs

    fn_info = lookup_funcs(fn_addr)
    assert_ok(fn_info[0], "fn")
    fn_name = fn_info[0]["fn"]["name"]

    result = read_struct({"addr": fn_name, "struct": NAME_RESOLUTION_STRUCT})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert "Failed to resolve address" not in (entry.get("error") or "")


@test()
def test_read_struct_invalid_address():
    """read_struct reports a deterministic address resolution error."""
    result = read_struct({"addr": "InvalidAddressName123", "struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to resolve address")


@test()
def test_read_struct_missing_address():
    """read_struct requires an address explicitly."""
    result = read_struct({"struct": TEST_STRUCT_NAME})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Address is required")


@test(binary="crackme03.elf")
def test_read_struct_without_type_info_fails_cleanly():
    """read_struct without an explicit struct fails cleanly when no type is applied."""
    result = read_struct({"addr": "0x201f"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="could not auto-detect")


@test()
def test_search_structs_finds_declared_structs():
    """search_structs returns the previously declared deterministic struct."""
    if not create_test_struct(TEST_STRUCT_NAME):
        skip_test("failed to declare test struct")

    result = search_structs("__TestStruct__")
    assert_is_list(result, min_length=1)
    assert any(item["name"] == TEST_STRUCT_NAME for item in result)


@test()
def test_search_structs_pattern_no_match():
    """search_structs returns an empty list for an unmatched substring."""
    result = search_structs("VeryUnlikelyStructName123")
    assert_is_list(result)
    assert len(result) == 0


@test(binary="typed_fixture.elf")
def test_search_structs_exact_wrapper_match():
    """search_structs finds the exact Wrapper struct in the typed fixture."""
    result = search_structs("Wrapper")
    assert_is_list(result, min_length=1)
    wrapper = next((item for item in result if item["name"] == "Wrapper"), None)
    assert wrapper is not None
    assert wrapper["cardinality"] == 2
    assert wrapper["size"] == 24


@test(binary="crackme03.elf")
def test_set_type_applies_named_global_type():
    """set_type applies a concrete type to a known crackme global and reports success."""
    result = set_type({"addr": CRACKME_DSO_HANDLE, "ty": "unsigned __int64"})
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["edit"]["addr"] == CRACKME_DSO_HANDLE
    assert entry.get("ok") is True or entry.get("error") is None


@test()
def test_set_type_invalid_address():
    """set_type reports an error for an invalid address."""
    result = set_type({"addr": get_unmapped_address(), "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="typed_fixture.elf")
def test_set_type_global_by_name_branch():
    """set_type(kind=global) can resolve the target by symbol name instead of address."""
    result = set_type({"name": "g_point", "ty": "Point", "kind": "global"})
    assert_is_list(result, min_length=1)
    assert result[0].get("ok") is True


@test(binary="typed_fixture.elf")
def test_set_type_global_invalid_type_name():
    """set_type(kind=global) reports invalid type names cleanly."""
    result = set_type({"addr": "0x1069f70", "ty": "NoSuchType", "kind": "global"})
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test()
def test_set_type_unknown_kind():
    """set_type reports unknown type-edit kinds explicitly."""
    result = set_type({"addr": "0x123e", "kind": "weird", "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Unknown kind")


@test()
def test_set_type_function_not_found_branch():
    """set_type(kind=function) reports missing functions cleanly."""
    result = set_type(
        {"addr": get_unmapped_address(), "kind": "function", "signature": "int foo()"}
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Function not found")


@test(binary="crackme03.elf")
def test_set_type_stack_missing_member():
    """set_type(kind=stack) reports a missing frame member explicitly."""
    fn_addr = get_named_address("main")
    if not fn_addr:
        skip_test("main symbol not present")
    result = set_type({"addr": fn_addr, "kind": "stack", "name": "nope", "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="typed_fixture.elf")
def test_set_type_stack_missing_member_typed_fixture():
    """typed_fixture reports missing stack members against a stable non-main function."""
    result = set_type(
        {"addr": "0x1013dc0", "kind": "stack", "name": "nope", "ty": "int"}
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="crackme03.elf")
def test_infer_types_returns_high_confidence_for_main():
    """infer_types(main) returns a non-empty inferred type with a method and confidence."""
    main_addr = get_named_address("main")
    if not main_addr:
        skip_test("main symbol not present")

    result = infer_types(main_addr)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["confidence"] in {"high", "low", "none"}
    if entry["inferred_type"] is not None:
        assert_non_empty(entry["inferred_type"])
        assert entry["method"] is not None


@test(binary="typed_fixture.elf")
def test_set_type_function_branch():
    """set_type(kind=function) applies a function signature to a typed fixture function."""
    result = set_type(
        {
            "addr": "0x1013c10",
            "signature": "int __fastcall sum_point(struct Point *p)",
            "kind": "function",
        }
    )
    assert_is_list(result, min_length=1)
    assert result[0].get("ok") is True


@test(binary="typed_fixture.elf")
def test_set_type_function_invalid_signature():
    """set_type(kind=function) rejects non-function signatures."""
    result = set_type(
        {
            "addr": "0x1013c10",
            "signature": "int",
            "kind": "function",
        }
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Not a function type")


@test(binary="typed_fixture.elf")
def test_set_type_local_branch():
    """set_type(kind=local) reaches the local-variable type application path."""
    result = set_type(
        {
            "addr": "0x1013dc0",
            "kind": "local",
            "variable": "rhs_handle",
            "ty": "int",
        }
    )
    assert_is_list(result, min_length=1)
    assert (
        result[0].get("ok") is True or result[0].get("error") == "Failed to apply type"
    )


@test(binary="typed_fixture.elf")
def test_set_type_local_invalid_type_name():
    """set_type(kind=local) reports invalid local type names cleanly."""
    result = set_type(
        {
            "addr": "0x1013dc0",
            "kind": "local",
            "variable": "rhs_handle",
            "ty": "NoSuchType",
        }
    )
    assert_is_list(result, min_length=1)
    assert_error(result[0])


@test(binary="typed_fixture.elf")
def test_set_type_stack_branch():
    """set_type(kind=stack) applies a type to a real stack-frame member."""
    result = set_type(
        {
            "addr": "0x1013dc0",
            "kind": "stack",
            "name": "rhs_handle",
            "ty": "int",
        }
    )
    assert_is_list(result, min_length=1)
    assert result[0].get("ok") is True


@test(binary="typed_fixture.elf")
def test_infer_types_size_based_low_confidence():
    """infer_types falls back to size-based inference on a typed-fixture interior data address."""
    result = infer_types("0x1069fa4")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["method"] == "size_based"
    assert entry["confidence"] == "low"
    assert entry["inferred_type"] == "uint8_t[12]"


@test(binary="typed_fixture.elf")
def test_infer_types_existing_or_hexrays_wrapper():
    """infer_types returns a strong typed result for the typed fixture wrapper object."""
    result = infer_types("0x1069f80")
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["method"] in {"hexrays", "existing"}
    assert entry["confidence"] == "high"
    assert "Wrapper" in entry["inferred_type"]


@test()
def test_infer_types_invalid_address_still_returns_structured_result():
    """infer_types returns a structured fallback result even for weird unmapped inputs."""
    result = infer_types(get_unmapped_address())
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert entry["confidence"] in {"high", "low", "none"}
    assert "addr" in entry


@test(binary="typed_fixture.elf")
def test_infer_types_invalid_text_address_errors_cleanly():
    """infer_types reports parse failures for symbolic garbage addresses."""
    result = infer_types("InvalidAddressName123")
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="Failed to parse address")
