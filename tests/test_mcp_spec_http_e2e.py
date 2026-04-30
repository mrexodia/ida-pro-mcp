"""End-to-end tests over a real localhost HTTP socket."""

import sys
import pathlib
import time
import unittest
from typing import Annotated, TypedDict

from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import (
    CALL_TOOL_RESULT_SCHEMA,
    INITIALIZE_RESULT_SCHEMA,
    JSONRPC_RESPONSE_SCHEMA,
    McpHttpTestServer,
    McpServer,
    PROMPTS_LIST_RESULT_SCHEMA,
    RESOURCES_LIST_RESULT_SCHEMA,
    TOOLS_LIST_RESULT_SCHEMA,
    assert_schema,
)


class _JsonR(TypedDict):
    format: str
    items: list[dict]


class _HdrR(TypedDict):
    format: str
    content: str


def _make_server() -> McpServer:
    srv = McpServer("e2e-test", version="9.9.9")

    @srv.tool
    def echo(value: Annotated[str, "the value to echo"]) -> str:
        """Echo a string."""
        return value

    @srv.tool
    def add(a: Annotated[int, "left"], b: Annotated[int, "right"]) -> int:
        """Add two ints."""
        return a + b

    @srv.tool
    def export_data(fmt: Annotated[str, "format"] = "json") -> _JsonR | _HdrR:
        """Union-of-TypedDicts (PR #357 regression surface)."""
        if fmt == "json":
            return {"format": "json", "items": [{"k": 1}]}
        return {"format": "c_header", "content": "// header"}

    @srv.resource("test://doc")
    def doc() -> str:
        """A test document."""
        return "hello"

    @srv.prompt
    def greet(name: Annotated[str, "the name"]) -> str:
        """Say hi."""
        return f"hello {name}"

    return srv


class HttpE2EBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = McpHttpTestServer(_make_server())
        cls.harness.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.harness.__exit__(None, None, None)

    def test_initialize_returns_valid_initialize_result(self):
        _, headers, body = self.harness.post_jsonrpc(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        )
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        assert_schema(body["result"], INITIALIZE_RESULT_SCHEMA)
        self.assertEqual(body["result"]["serverInfo"]["name"], "e2e-test")
        self.assertEqual(body["result"]["serverInfo"]["version"], "9.9.9")
        session_id = headers.get("Mcp-Session-Id")
        self.assertTrue(session_id)
        self.assertTrue(self.harness.server.has_http_session(session_id))

    def test_ping_returns_empty_result(self):
        _, _, body = self.harness.post_jsonrpc("ping")
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        self.assertEqual(body["result"], {})

    def test_http_session_registry_is_bounded(self):
        srv = McpServer("session-bounds")
        srv.http_session_max_count = 2
        srv.register_http_session("a")
        srv.register_http_session("b")
        srv.register_http_session("c")
        self.assertFalse(srv.has_http_session("a"))
        self.assertTrue(srv.has_http_session("b"))
        self.assertTrue(srv.has_http_session("c"))

    def test_http_session_registry_expires_stale_entries(self):
        srv = McpServer("session-ttl")
        srv.http_session_ttl_sec = 1
        srv.register_http_session("expired")
        srv._http_sessions["expired"] = time.monotonic() - 10
        self.assertFalse(srv.has_http_session("expired"))


class HttpE2EToolsDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = McpHttpTestServer(_make_server())
        cls.harness.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.harness.__exit__(None, None, None)

    def test_tools_list_over_http_is_mcp_spec_valid(self):
        _, _, body = self.harness.post_jsonrpc("tools/list")
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        assert_schema(body["result"], TOOLS_LIST_RESULT_SCHEMA)

    def test_tools_list_returns_registered_tools(self):
        _, _, body = self.harness.post_jsonrpc("tools/list")
        names = [t["name"] for t in body["result"]["tools"]]
        self.assertIn("echo", names)
        self.assertIn("add", names)
        self.assertIn("export_data", names)

    def test_every_tool_has_object_root_outputSchema(self):
        # PR #357 regression check on the wire.
        _, _, body = self.harness.post_jsonrpc("tools/list")
        for tool in body["result"]["tools"]:
            osch = tool.get("outputSchema")
            if osch is None:
                continue
            with self.subTest(name=tool["name"]):
                self.assertEqual(osch.get("type"), "object")

    def test_tools_call_echo_returns_valid_call_tool_result(self):
        _, _, body = self.harness.post_jsonrpc(
            "tools/call", params={"name": "echo", "arguments": {"value": "world"}}
        )
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        assert_schema(body["result"], CALL_TOOL_RESULT_SCHEMA)
        self.assertFalse(body["result"].get("isError"))

    def test_tools_call_returns_structured_content_matching_schema(self):
        _, _, ls = self.harness.post_jsonrpc("tools/list")
        schema = next(t["outputSchema"] for t in ls["result"]["tools"] if t["name"] == "export_data")
        _, _, body = self.harness.post_jsonrpc(
            "tools/call", params={"name": "export_data", "arguments": {"fmt": "json"}}
        )
        assert_schema(body["result"], CALL_TOOL_RESULT_SCHEMA)
        Draft202012Validator(schema).validate(body["result"]["structuredContent"])

    def test_tools_call_union_variant_b_also_validates(self):
        _, _, ls = self.harness.post_jsonrpc("tools/list")
        schema = next(t["outputSchema"] for t in ls["result"]["tools"] if t["name"] == "export_data")
        _, _, body = self.harness.post_jsonrpc(
            "tools/call", params={"name": "export_data", "arguments": {"fmt": "c_header"}}
        )
        Draft202012Validator(schema).validate(body["result"]["structuredContent"])

    def test_tools_call_with_primitive_return_wraps_in_result(self):
        _, _, ls = self.harness.post_jsonrpc("tools/list")
        schema = next(t["outputSchema"] for t in ls["result"]["tools"] if t["name"] == "add")
        _, _, body = self.harness.post_jsonrpc(
            "tools/call", params={"name": "add", "arguments": {"a": 2, "b": 3}}
        )
        Draft202012Validator(schema).validate(body["result"]["structuredContent"])


class HttpE2EPromptsAndResourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = McpHttpTestServer(_make_server())
        cls.harness.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.harness.__exit__(None, None, None)

    def test_prompts_list_over_http(self):
        _, _, body = self.harness.post_jsonrpc("prompts/list")
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        assert_schema(body["result"], PROMPTS_LIST_RESULT_SCHEMA)
        self.assertIn("greet", [p["name"] for p in body["result"]["prompts"]])

    def test_resources_list_over_http(self):
        _, _, body = self.harness.post_jsonrpc("resources/list")
        assert_schema(body, JSONRPC_RESPONSE_SCHEMA)
        assert_schema(body["result"], RESOURCES_LIST_RESULT_SCHEMA)
        self.assertIn("test://doc", [r["uri"] for r in body["result"]["resources"]])


class HttpContentTypeAndHeadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = McpHttpTestServer(_make_server())
        cls.harness.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.harness.__exit__(None, None, None)

    def test_response_content_type_is_json(self):
        _, hdrs, _ = self.harness.post_jsonrpc("ping")
        ct = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
        self.assertIn("application/json", ct)


class HttpSessionManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = McpHttpTestServer(_make_server())
        cls.harness.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.harness.__exit__(None, None, None)

    def test_server_assigns_or_echoes_session_id_on_initialize(self):
        _, hdrs, _ = self.harness.post_jsonrpc(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "c", "version": "0"},
            },
        )
        session_id = next((hdrs[k] for k in hdrs if k.lower() == "mcp-session-id"), None)
        if session_id is not None:
            self.assertGreater(len(session_id), 0)


if __name__ == "__main__":
    unittest.main()
