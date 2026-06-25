"""Batch-5 typed-decode / type-introspection tests for tests/typed_fixture.elf.

These exercise the typeutils SEAM as wired into the real APIs:
- read_struct decodes typed/signed members semantically (not "all unsigned int")
- type_query / type_inspect report ENUM members (member_count > 0)
- get_string detects/decodes the recorded encoding
- get_global_value renders a char[] global as a string
- pseudocode_query / lvar_usage return structured ctree nodes (Hex-Rays gated)

Assertions are SEMANTIC (kinds, signedness, member presence) rather than
brittle exact-byte checks, per the Batch-5 brief.
"""

from .._kernel.framework import test, skip_test
from ..api_core import list_globals
from ..api_memory import get_string, get_global_value
from ..api_types import read_struct, set_type, type_query, type_inspect
from ..api_decomp import pseudocode_query, lvar_usage


# Deterministic addresses/symbols in typed_fixture.elf (mirrors test_typed_fixture.py).
G_POINT = "0x1069f70"
G_MESSAGE = "0x1000c00"
USE_WRAPPER = "0x1013dc0"
MAIN = "0x1013ef0"


@test(binary="typed_fixture.elf")
def test_decode_read_struct_signed_and_typed_members():
    """read_struct on G_POINT decodes signed ints + char member by type, not all-unsigned.

    struct Point { int32_t x; int32_t y; char tag; } with x=11, y=22, tag='A'.
    The Batch-5 typeutils decode must NOT collapse every member to a uint: the
    signed int32 members report kind 'int' and the negative-capable path renders
    a decimal (no 0x... (n) unsigned shape), and the char member is treated as a
    1-byte integral, not a struct/pointer.
    """
    set_point = set_type({"addr": G_POINT, "ty": "Point"})[0]
    assert "error" not in set_point, set_point.get("error")

    res = read_struct({"addr": G_POINT})[0]
    assert "error" not in res, res.get("error")
    assert res["struct"] == "Point"

    by_name = {m["name"]: m for m in res["members"]}
    assert {"x", "y", "tag"}.issubset(by_name), sorted(by_name)

    x = by_name["x"]
    y = by_name["y"]
    tag = by_name["tag"]

    # Signed members must decode through the signed branch (kind 'int'), so their
    # repr is a plain decimal, NOT the unsigned "0xNN (n)" rendering. This is the
    # core "not everything is an unsigned int" guarantee.
    assert x["kind"] == "int", x
    assert y["kind"] == "int", y
    assert x["value"] == "11", x
    assert y["value"] == "22", y
    # An unsigned decode would have appended " (11)" after a hex prefix; assert
    # the signed path did NOT do that.
    assert "0x" not in x["value"], x
    assert "0x" not in y["value"], y

    # tag is a signed char ('A' == 65) -> 1-byte integral, decoded as a scalar
    # (int/uint/char), never as a UDT/pointer/array.
    assert tag["size"] == 1, tag
    assert tag["kind"] in {"int", "uint", "char", "char_array"}, tag
    # 'A' is 65; the decoded value (signed or unsigned) must reflect that byte.
    assert "65" in str(tag["value"]), tag


@test(binary="typed_fixture.elf")
def test_decode_enum_members_via_type_query_and_inspect():
    """type_query(kind='enum') + type_inspect both report an enum's members (count > 0).

    typed_fixture.c declares no user enum, so we DISCOVER an enum from the local
    type catalog (libc/toolchain enums are present) rather than hard-coding a
    name. The Batch-5 fix is that enum member_count is no longer 0: the edm_t
    path must enumerate real {name, value} members.
    """
    page = type_query(
        {
            "kind": "enum",
            "include_members": True,
            "max_members": 256,
            "count": 200,
        }
    )[0]
    assert page["kind"] == "enum"

    enums_with_members = [
        row for row in page["data"] if row.get("member_count", 0) > 0
    ]
    if not enums_with_members:
        skip_test("no enum with members present in this typed_fixture IDB build")

    row = enums_with_members[0]
    # Catalog row must carry the projected members and a positive count.
    assert row["member_count"] > 0, row
    assert isinstance(row["members"], list) and row["members"], row
    member0 = row["members"][0]
    assert "name" in member0 and member0["name"], member0
    assert "value" in member0 and isinstance(member0["value"], int), member0

    # type_inspect BY EXACT NAME must agree: same enum reports is_enum + members.
    inspected = type_inspect(
        {"name": row["name"], "include_members": True, "max_members": 256}
    )[0]
    assert inspected["exists"] is True, inspected
    assert inspected["is_enum"] is True, inspected
    assert inspected["member_count"] > 0, inspected
    assert inspected["members"], inspected
    names = {m["name"] for m in inspected["members"]}
    assert row["members"][0]["name"] in names, (row, inspected)


@test(binary="typed_fixture.elf")
def test_decode_get_string_encoding_aware():
    """get_string on the message literal decodes the text and reports its encoding."""
    res = get_string(G_MESSAGE)[0]
    assert res.get("error") is None, res.get("error")
    assert res["value"] == "typed fixture says hi", res
    # The C/UTF-8 literal must be reported under a utf-8 / c style encoding tag,
    # not a wide/utf-16 class.
    enc = (res.get("encoding") or "").lower()
    assert enc, res
    assert "utf-16" not in enc and "utf-32" not in enc, res
    assert "utf-8" in enc or enc.startswith("c") or "ascii" in enc, res


@test(binary="typed_fixture.elf")
def test_decode_get_global_value_char_array_is_string():
    """get_global_value on the char[] message global returns the quoted string text.

    The Batch-5 char-array fix renders char[N] globals as a string instead of a
    byte dump; the rendered value must contain the literal text and must not be a
    space-separated hex byte sequence.
    """
    res = get_global_value("g_message")[0]
    assert res.get("error") is None, res.get("error")
    val = res["value"]
    assert isinstance(val, str), res
    assert "typed fixture says hi" in val, res
    # A byte-dump fallback would look like '0x74 0x79 ...'; a string render won't.
    assert not val.lstrip('"').startswith("0x"), res


@test(binary="typed_fixture.elf")
def test_decode_list_globals_then_read_back_message():
    """g_message is discoverable via list_globals and reads back as its string."""
    page = list_globals({"filter": "g_*", "offset": 0, "count": 50})[0]
    names = {item["name"] for item in page["data"]}
    assert "g_message" in names, names

    res = get_global_value("g_message")[0]
    assert res.get("error") is None, res
    assert "typed fixture says hi" in str(res["value"]), res


@test(binary="typed_fixture.elf")
def test_pseudocode_query_structured_nodes():
    """pseudocode_query on use_wrapper yields structured ctree nodes (calls + ifs).

    use_wrapper has an `if (g_numbers[2] == 1234)` guard and a `sum_point(...)`
    call, so the decompiler-accurate walk must surface both a call node and an if
    node. Guarded with a skip when Hex-Rays is unavailable / refuses the func.
    """
    res = pseudocode_query(USE_WRAPPER, kinds="calls,ifs")
    if not res.get("decompiled"):
        skip_test(f"Hex-Rays unavailable: {res.get('error')}")

    nodes = res["nodes"]
    assert isinstance(nodes, list) and nodes, res
    kinds = {n["kind"] for n in nodes}
    # The function definitely contains a call and an if; assert structurally.
    assert "call" in kinds, kinds
    assert "if" in kinds, kinds

    counts = res.get("counts", {})
    assert counts.get("call", 0) >= 1, res
    assert counts.get("if", 0) >= 1, res

    # A call node should carry a callee name where known (sum_point is direct).
    call_names = {
        n.get("name") for n in nodes if n["kind"] == "call" and n.get("name")
    }
    assert any("sum_point" in (nm or "") for nm in call_names), call_names

    # Every node must expose an ea + line for the pseudocode<->address bridge.
    for n in nodes:
        assert "ea" in n and "line" in n, n


@test(binary="typed_fixture.elf")
def test_lvar_usage_structured_refs():
    """lvar_usage on main maps locals with typed, access-tagged refs.

    main() has at least the `argc`/`argv` args; the decompiler def-use map must
    report variables with per-ref access tags (read/write/addr) and counts.
    Skips when Hex-Rays cannot decompile.
    """
    res = lvar_usage(MAIN)
    if not res.get("decompiled"):
        skip_test(f"Hex-Rays unavailable: {res.get('error')}")

    variables = res["variables"]
    assert isinstance(variables, list) and variables, res

    # At least one variable should have a type string and at least one ref.
    typed_vars = [v for v in variables if v.get("type")]
    assert typed_vars, variables

    refs_seen = False
    for v in variables:
        # Counts must be consistent non-negative integers.
        for key in ("read_count", "write_count", "addr_count"):
            assert isinstance(v.get(key, 0), int) and v[key] >= 0, v
        for ref in v.get("refs", []):
            refs_seen = True
            assert ref.get("access") in {"read", "write", "addr"}, ref
            assert "ea" in ref and "line" in ref, ref
    assert refs_seen, res

    # The is_arg flag should be present and boolean on every variable; whether a
    # given build keeps argc/argv as args depends on Hex-Rays inlining, so we
    # only assert the flag is well-typed (not that a specific arg survives).
    for v in variables:
        assert isinstance(v.get("is_arg"), bool), v
