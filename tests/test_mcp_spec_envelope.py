"""JSON-RPC 2.0 envelope compliance over real HTTP."""

import json
import sys
import pathlib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import (
    JSONRPC_RESPONSE_SCHEMA,
    McpHttpTestServer,
    McpServer,
    assert_schema,
)


def _minimal_server() -> McpServer:
    srv = McpServer("envelope-tests")

    @srv.tool
    def echo(value: str) -> str:
        """echo the value back."""
        return value

    return srv


class JsonRpcEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.harness = McpHttpTestServer(_minimal_server())
        self.harness.__enter__()

    def tearDown(self):
        self.harness.__exit__(None, None, None)

    def test_successful_call_response_has_valid_envelope(self):
        status, _hdrs, body = self.harness.post_jsonrpc("tools/list", request_id=1)
        self.assertEqual(status, 200)
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        self.assertIn("result", body)
        self.assertNotIn("error", body)

    def test_id_is_echoed_as_integer(self):
        _, _, body = self.harness.post_jsonrpc("tools/list", request_id=42)
        self.assertEqual(body["id"], 42)

    def test_id_is_echoed_as_string(self):
        _, _, body = self.harness.post_jsonrpc("tools/list", request_id="abc-123")
        self.assertEqual(body["id"], "abc-123")

    def test_id_is_echoed_as_null(self):
        _, _, body = self.harness.post_jsonrpc("tools/list", request_id=None)
        self.assertIsNone(body["id"])

    def test_jsonrpc_field_is_exactly_2_0(self):
        _, _, body = self.harness.post_jsonrpc("tools/list")
        self.assertEqual(body["jsonrpc"], "2.0")

    def test_unknown_method_returns_method_not_found_error(self):
        _, _, body = self.harness.post_jsonrpc("this/method/does/not/exist", request_id=7)
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], -32601)
        self.assertEqual(body["id"], 7)

    def test_error_message_is_non_empty_string(self):
        _, _, body = self.harness.post_jsonrpc("does/not/exist")
        self.assertIsInstance(body["error"]["message"], str)
        self.assertGreater(len(body["error"]["message"]), 0)

    def test_error_code_is_in_jsonrpc_range(self):
        _, _, body = self.harness.post_jsonrpc("does/not/exist")
        code = body["error"]["code"]
        self.assertGreaterEqual(code, -32768)
        self.assertLessEqual(code, -32000)

    def test_success_response_has_result_and_no_error(self):
        _, _, body = self.harness.post_jsonrpc("ping")
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        self.assertIn("result", body)
        self.assertNotIn("error", body)

    def test_tools_call_on_known_tool_returns_result(self):
        _, _, body = self.harness.post_jsonrpc(
            "tools/call", params={"name": "echo", "arguments": {"value": "hi"}}
        )
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        self.assertIn("result", body)

    def test_tools_call_on_unknown_tool_returns_is_error_true(self):
        # MCP distinguishes protocol errors from tool errors: unknown tool
        # is a normal response with isError: true.
        _, _, body = self.harness.post_jsonrpc(
            "tools/call", params={"name": "no_such_tool", "arguments": {}}
        )
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        self.assertIn("result", body)
        self.assertTrue(body["result"].get("isError"))


class NotificationEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.harness = McpHttpTestServer(_minimal_server())
        self.harness.__enter__()

    def tearDown(self):
        self.harness.__exit__(None, None, None)

    def test_notifications_initialized_returns_no_body(self):
        status, _hdrs, body = self.harness.post_jsonrpc(
            "notifications/initialized", notification=True
        )
        self.assertIn(status, (200, 202, 204))
        self.assertIsNone(body)

    def test_notifications_cancelled_returns_no_body(self):
        status, _hdrs, body = self.harness.post_jsonrpc(
            "notifications/cancelled",
            params={"requestId": 1, "reason": "user canceled"},
            notification=True,
        )
        self.assertIn(status, (200, 202, 204))
        self.assertIsNone(body)


class MalformedRequestEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.harness = McpHttpTestServer(_minimal_server())
        self.harness.__enter__()

    def tearDown(self):
        self.harness.__exit__(None, None, None)

    def _post_raw(self, body_text: str):
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            self.harness.base_url + "/mcp",
            data=body_text.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code

        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else None
        except json.JSONDecodeError:
            parsed = None
        return status, parsed

    def test_invalid_json_returns_parse_error_envelope(self):
        status, body = self._post_raw("not valid json {")
        # Accept either a JSON-RPC parse-error envelope or an HTTP 4xx.
        if body is not None and isinstance(body, dict) and "error" in body:
            self.assertEqual(body["jsonrpc"], "2.0")
            self.assertEqual(body["error"]["code"], -32700)
        else:
            self.assertGreaterEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
