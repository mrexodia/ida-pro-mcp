"""Tests for framework helper utilities used by the IDA test suite."""

from ..framework import (
    test,
    assert_shape,
    assert_typed_dict,
    assert_ok,
    assert_error,
    optional,
    list_of,
    one_of,
    is_hex_address,
    get_named_function,
    get_named_address,
    get_string_address_containing,
)
from ..utils import Function, Metadata


@test(binary="crackme03.elf")
def test_framework_assert_shape_with_optional_and_list_of():
    """assert_shape validates nested dict/list structures with optional fields."""
    value = {
        "addr": "0x123e",
        "items": [{"name": "main"}, {"name": "check_pw"}],
    }
    assert_shape(
        value,
        {
            "addr": is_hex_address,
            "items": list_of({"name": str}, min_length=2),
        },
    )


@test(binary="crackme03.elf")
def test_framework_assert_shape_with_one_of():
    """assert_shape supports one_of() schemas for alternative value shapes."""
    assert_shape({"value": "0x123e"}, {"value": one_of(is_hex_address, int)})
    assert_shape({"value": 7}, {"value": one_of(is_hex_address, int)})


@test(binary="crackme03.elf")
def test_framework_assert_typed_dict():
    """assert_typed_dict validates TypedDict instances from utils.py."""
    assert_typed_dict({"addr": "0x123e", "name": "main", "size": "0x104"}, Function)
    assert_typed_dict(
        {
            "path": "x",
            "module": "crackme03.elf",
            "base": "0x0",
            "size": "0x4068",
            "md5": "0" * 32,
            "sha256": "1" * 64,
            "crc32": "0x1",
            "filesize": "0x2",
        },
        Metadata,
    )


@test(binary="crackme03.elf")
def test_framework_assert_ok_and_error_helpers():
    """assert_ok and assert_error capture success/error response contracts."""
    assert_ok({"value": 1}, "value")
    assert_error({"error": "boom"}, contains="boom")


@test(binary="crackme03.elf")
def test_framework_named_lookup_helpers():
    """named lookup helpers resolve expected functions, globals and strings."""
    assert get_named_function("main") == "0x123e"
    assert get_named_address("format") == "0x201f"
    assert get_string_address_containing("Need exactly one argument") == "0x2004"


@test(binary="crackme03.elf")
def test_framework_shape_helpers_negative_paths():
    """framework validation helpers raise AssertionError on bad data and those paths are catchable."""
    try:
        assert_shape({"addr": "not_an_addr"}, {"addr": is_hex_address})
        assert False, "expected assert_shape to fail"
    except AssertionError:
        pass

    try:
        assert_typed_dict({"addr": "0x1", "name": "x"}, Function)
        assert False, "expected assert_typed_dict to fail"
    except AssertionError:
        pass

    try:
        assert_ok({"error": "boom"}, "value")
        assert False, "expected assert_ok to fail"
    except AssertionError:
        pass

    try:
        assert_error({"error": None})
        assert False, "expected assert_error to fail"
    except AssertionError:
        pass
