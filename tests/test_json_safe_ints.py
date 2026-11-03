"""Regression tests for #510: keep tools/call JSON/JS-safe.

MCP clients that preserve BigInt turn 64-bit integers outside the JavaScript
safe range into values that cannot be serialized again. The server must emit
those integers as strings while leaving small integers, booleans and existing
strings unchanged.
"""

import json
import sys
import pathlib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import McpServer, call_rpc, load_ida_rpc_module


MAX_SAFE = 2**53 - 1


def _patched_server() -> McpServer:
    rpc = load_ida_rpc_module()
    srv = McpServer("json-safe-int-tests")
    original = srv.registry.methods["tools/call"]

    def patched(name, arguments=None, _meta=None):
        response = rpc._sanitize_response_ints(original(name, arguments, _meta))
        return rpc._limit_output_response(response)

    srv.registry.methods["tools/call"] = patched
    return srv


class JsonSafeIntTests(unittest.TestCase):
    def test_boundary_and_nested_values(self):
        srv = _patched_server()

        @srv.tool
        def numbers() -> dict:
            """Return values around the JavaScript safe-integer boundary."""
            return {
                "max": MAX_SAFE,
                "over": MAX_SAFE + 1,
                "neg_max": -MAX_SAFE,
                "neg_over": -(MAX_SAFE + 1),
                "flag": True,
                "small": 42,
                "nested": [MAX_SAFE + 1, {"value": 2**63, "ok": True}],
                "hex": "0xffffffffffffffff",
            }

        result = call_rpc(srv, "tools/call", name="numbers", arguments={})
        structured = result["structuredContent"]

        self.assertEqual(structured["max"], MAX_SAFE)
        self.assertEqual(structured["over"], str(MAX_SAFE + 1))
        self.assertEqual(structured["neg_max"], -MAX_SAFE)
        self.assertEqual(structured["neg_over"], str(-(MAX_SAFE + 1)))
        self.assertIs(structured["flag"], True)
        self.assertEqual(structured["small"], 42)
        self.assertEqual(structured["nested"][0], str(MAX_SAFE + 1))
        self.assertEqual(structured["nested"][1]["value"], str(2**63))
        self.assertIs(structured["nested"][1]["ok"], True)
        self.assertEqual(structured["hex"], "0xffffffffffffffff")

    def test_text_content_matches_structured_content(self):
        srv = _patched_server()

        @srv.tool
        def one_big() -> dict:
            """Return one unsafe integer."""
            return {"value": 2**63}

        result = call_rpc(srv, "tools/call", name="one_big", arguments={})
        text = result["content"][0]["text"]
        self.assertEqual(json.loads(text), result["structuredContent"])
        self.assertIn('"value":"9223372036854775808"', text)


if __name__ == "__main__":
    unittest.main()
