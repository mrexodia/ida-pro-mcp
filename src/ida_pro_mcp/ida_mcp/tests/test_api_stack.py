"""Tests for api_stack API functions."""

from ..framework import (
    test,
    skip_test,
    assert_valid_address,
    assert_is_list,
    assert_ok,
    assert_error,
    get_data_address,
)
from ..api_stack import (
    stack_frame,
    declare_stack,
    delete_stack,
)


CRACKME_MAIN = "0x123e"
TEST_STACK_VAR = "__test_stack_var__"


@test(binary="crackme03.elf")
def test_stack_frame_main_contains_expected_members():
    """stack_frame(main) returns the known crackme frame layout."""
    result = stack_frame(CRACKME_MAIN)
    assert_is_list(result, min_length=1)
    entry = result[0]
    assert_ok(entry, "vars")
    names = [var["name"] for var in entry["vars"]]
    assert "__return_address" in names
    assert "__saved_registers" in names
    for var in entry["vars"]:
        assert_valid_address(var["offset"])
        assert_valid_address(var["size"])


@test()
def test_stack_frame_no_function():
    """stack_frame reports an error for a non-function address."""
    data_addr = get_data_address()
    if not data_addr:
        skip_test("binary has no data segment")

    result = stack_frame(data_addr)
    assert_is_list(result, min_length=1)
    assert result[0].get("vars") is None
    assert_error(result[0])


@test(binary="crackme03.elf")
def test_declare_delete_stack_roundtrip():
    """declare_stack adds a local and delete_stack removes it again."""
    before = stack_frame(CRACKME_MAIN)[0]
    assert_ok(before, "vars")
    assert TEST_STACK_VAR not in [var["name"] for var in before["vars"]]

    try:
        declared = declare_stack(
            {"addr": CRACKME_MAIN, "name": TEST_STACK_VAR, "offset": -8, "ty": "int"}
        )[0]
        assert "error" not in declared
        during = stack_frame(CRACKME_MAIN)[0]
        assert TEST_STACK_VAR in [var["name"] for var in during["vars"]]
    finally:
        delete_stack({"addr": CRACKME_MAIN, "name": TEST_STACK_VAR})

    after = stack_frame(CRACKME_MAIN)[0]
    assert TEST_STACK_VAR not in [var["name"] for var in after["vars"]]


@test()
def test_declare_stack_no_function_error():
    """declare_stack reports a clean error when the target is not a function."""
    result = declare_stack({"addr": "0x201f", "name": "x", "offset": -8, "ty": "int"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="No function found")


@test()
def test_delete_stack_no_function_error():
    """delete_stack reports a clean error when the target is not a function."""
    result = delete_stack({"addr": "0x201f", "name": "x"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="No function found")


@test(binary="typed_fixture.elf")
def test_stack_frame_batch_on_typed_fixture():
    """stack_frame accepts batched addresses and preserves per-item results."""
    result = stack_frame(["0x1013dc0", "0x1069f80"])
    assert_is_list(result, min_length=2)
    assert result[0]["addr"] == "0x1013dc0"
    assert "error" not in result[0]
    assert any(var["name"] == "rhs_handle" for var in result[0]["vars"])
    assert result[1]["addr"] == "0x1069f80"
    assert result[1].get("vars") is None
    assert_error(result[1])


@test(binary="typed_fixture.elf")
def test_declare_delete_stack_roundtrip_typed_fixture():
    """declare_stack/delete_stack round-trip on a stable typed_fixture function."""
    before = stack_frame("0x1013dc0")[0]
    assert_ok(before, "vars")
    assert TEST_STACK_VAR not in [var["name"] for var in before["vars"]]

    try:
        declared = declare_stack(
            {"addr": "0x1013dc0", "name": TEST_STACK_VAR, "offset": -0x18, "ty": "int"}
        )[0]
        assert "error" not in declared
        during = stack_frame("0x1013dc0")[0]
        assert TEST_STACK_VAR in [var["name"] for var in during["vars"]]
    finally:
        delete_stack({"addr": "0x1013dc0", "name": TEST_STACK_VAR})

    after = stack_frame("0x1013dc0")[0]
    assert TEST_STACK_VAR not in [var["name"] for var in after["vars"]]


@test(binary="typed_fixture.elf")
def test_declare_stack_invalid_type_error():
    """declare_stack reports invalid type names from the shared type resolver."""
    result = declare_stack(
        {"addr": "0x1013dc0", "name": "x", "offset": -0x18, "ty": "NoSuchType"}
    )
    assert_is_list(result, min_length=1)
    # Error message may vary: "Unable to retrieve ... type info object" or similar
    assert_error(result[0], contains="NoSuchType")


@test(binary="typed_fixture.elf")
def test_delete_stack_missing_member_error():
    """delete_stack reports missing frame members explicitly."""
    result = delete_stack({"addr": "0x1013dc0", "name": "nope"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="not found")


@test(binary="typed_fixture.elf")
def test_delete_stack_special_member_error():
    """delete_stack rejects special frame members such as the return address."""
    result = delete_stack({"addr": "0x1013dc0", "name": "__return_address"})
    assert_is_list(result, min_length=1)
    assert_error(result[0], contains="special frame member")
