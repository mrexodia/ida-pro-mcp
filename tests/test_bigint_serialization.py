"""Integers outside the JS safe range must not reach the wire as JSON numbers.

Node MCP clients parse responses with a BigInt-preserving reviver, then die with
"TypeError: Do not know how to serialize a BigInt" when they re-serialize the
tool result. 64-bit IDA values (u64 reads, arm64 immediates, enum values)
routinely exceed that range.
"""

import json
import pathlib
import sys
import unittest
from typing import NotRequired, TypedDict

from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import McpServer, call_rpc, load_ida_rpc_module

rpc = load_ida_rpc_module()

SAFE_MAX = 2**53 - 1


class IntReadResult(TypedDict):
    """Mirrors api_memory.IntReadResult."""

    addr: str
    ty: str
    value: int | str | None
    error: NotRequired[str]


def get_int(value: int) -> list[IntReadResult]:
    """Read integer values from memory addresses"""
    return [{"addr": "0x1000", "ty": "u64le", "value": value}]


def analyze(value: int) -> list[dict]:
    """Extract immediate constants from a function"""
    return [{"addr": "0x100007a8c", "decimal": value}]


def _call(tool_fn, value: int) -> tuple[dict, dict]:
    """Run a tool through the production middleware, returning (response, outputSchema)."""
    server = McpServer("bigint-test")
    server.tool(tool_fn)
    rpc.install_tools_call_middleware(server)
    name = tool_fn.__name__
    response = call_rpc(server, "tools/call", name=name, arguments={"value": value})
    schema = next(
        t["outputSchema"] for t in call_rpc(server, "tools/list")["tools"] if t["name"] == name
    )
    return response, schema


class TestSanitizeBigints(unittest.TestCase):
    def test_safe_range_boundary(self):
        self.assertEqual(rpc.sanitize_bigints(SAFE_MAX), SAFE_MAX)
        self.assertEqual(rpc.sanitize_bigints(-SAFE_MAX), -SAFE_MAX)
        self.assertEqual(rpc.sanitize_bigints(SAFE_MAX + 1), "9007199254740992")
        self.assertEqual(rpc.sanitize_bigints(-(2**63)), "-9223372036854775808")

    def test_bools_are_not_treated_as_ints(self):
        self.assertIs(rpc.sanitize_bigints(True), True)

    def test_recurses_and_leaves_other_types_alone(self):
        value = {
            "items": [{"decimal": 2**63}, {"decimal": 5}],
            "pair": (2**53, 7),
            "text": "18446744073709551615",
            "ratio": 1.5,
            "nothing": None,
        }
        self.assertEqual(
            rpc.sanitize_bigints(value),
            {
                "items": [{"decimal": "9223372036854775808"}, {"decimal": 5}],
                "pair": ["9007199254740992", 7],
                "text": "18446744073709551615",
                "ratio": 1.5,
                "nothing": None,
            },
        )


class TestToolsCallMiddleware(unittest.TestCase):
    def test_u64_read_is_stringified_and_still_schema_valid(self):
        response, schema = _call(get_int, 0xFFFFFFFFFFFFFFFF)

        self.assertEqual(
            response["structuredContent"]["result"][0]["value"], "18446744073709551615"
        )
        Draft202012Validator(schema).validate(response["structuredContent"])

    def test_untyped_result_is_sanitized(self):
        response, _ = _call(analyze, 0x7FFFFFFFFFFFFFFF)

        self.assertEqual(
            response["structuredContent"]["result"][0]["decimal"], "9223372036854775807"
        )

    def test_safe_value_passes_through_unchanged(self):
        response, _ = _call(get_int, 1234)

        self.assertEqual(response["structuredContent"]["result"][0]["value"], 1234)

    def test_content_text_matches_structured_content(self):
        response, _ = _call(get_int, 2**63)

        self.assertEqual(
            json.loads(response["content"][0]["text"]), response["structuredContent"]
        )


if __name__ == "__main__":
    unittest.main()
