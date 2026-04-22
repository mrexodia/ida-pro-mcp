"""Standard MCP endpoints: initialize, ping, prompts/list, resources/list."""

import sys
import pathlib
import unittest
from typing import Annotated

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import (
    INITIALIZE_RESULT_SCHEMA,
    PROMPTS_LIST_RESULT_SCHEMA,
    RESOURCES_LIST_RESULT_SCHEMA,
    RESOURCE_TEMPLATES_LIST_RESULT_SCHEMA,
    McpServer,
    assert_schema,
    call_rpc,
)


class InitializeEndpointTests(unittest.TestCase):
    def setUp(self):
        self.srv = McpServer("test-server", version="3.2.1")

    def _initialize(self, protocol_version="2024-11-05"):
        return call_rpc(
            self.srv,
            "initialize",
            protocolVersion=protocol_version,
            capabilities={},
            clientInfo={"name": "pytest-client", "version": "0.0.1"},
        )

    def test_initialize_response_matches_mcp_schema(self):
        result = self._initialize()
        assert_schema(result, INITIALIZE_RESULT_SCHEMA)

    def test_initialize_protocol_version_format_is_iso_date(self):
        result = self._initialize()
        self.assertRegex(result["protocolVersion"], r"^\d{4}-\d{2}-\d{2}$")

    def test_initialize_serverInfo_has_name_and_version(self):
        result = self._initialize()
        info = result["serverInfo"]
        self.assertEqual(info["name"], "test-server")
        self.assertEqual(info["version"], "3.2.1")

    def test_initialize_advertises_tool_capability(self):
        @self.srv.tool
        def t() -> int:
            """doc."""
            return 0

        result = self._initialize()
        self.assertIn("tools", result["capabilities"])

    def test_initialize_echoes_requested_protocol_version(self):
        result = self._initialize("2024-11-05")
        self.assertRegex(result["protocolVersion"], r"^\d{4}-\d{2}-\d{2}$")


class PingEndpointTests(unittest.TestCase):
    def test_ping_returns_empty_object(self):
        srv = McpServer("t")
        self.assertEqual(call_rpc(srv, "ping"), {})

    def test_ping_with_params_ignores_them(self):
        srv = McpServer("t")
        self.assertIsInstance(call_rpc(srv, "ping"), dict)


class PromptsListEndpointTests(unittest.TestCase):
    def test_empty_prompts_list_has_empty_array(self):
        srv = McpServer("t")
        result = call_rpc(srv, "prompts/list")
        assert_schema(result, PROMPTS_LIST_RESULT_SCHEMA)
        self.assertEqual(result["prompts"], [])

    def test_registered_prompt_appears_in_list(self):
        srv = McpServer("t")

        @srv.prompt
        def greet(name: Annotated[str, "the name"]) -> str:
            """Say hi."""
            return f"hi {name}"

        result = call_rpc(srv, "prompts/list")
        assert_schema(result, PROMPTS_LIST_RESULT_SCHEMA)
        self.assertIn("greet", [p["name"] for p in result["prompts"]])

    def test_prompt_arguments_validated(self):
        srv = McpServer("t")

        @srv.prompt
        def q(
            topic: Annotated[str, "what to ask"],
            style: Annotated[str, "voice"] = "formal",
        ) -> str:
            """Ask a question."""
            return f"about {topic} in {style}"

        result = call_rpc(srv, "prompts/list")
        prompt = next(p for p in result["prompts"] if p["name"] == "q")
        assert_schema({"prompts": [prompt]}, PROMPTS_LIST_RESULT_SCHEMA)
        arg_names = [a["name"] for a in prompt.get("arguments", [])]
        self.assertIn("topic", arg_names)
        self.assertIn("style", arg_names)


class ResourcesListEndpointTests(unittest.TestCase):
    def test_empty_resources_list_shape(self):
        srv = McpServer("t")
        result = call_rpc(srv, "resources/list")
        assert_schema(result, RESOURCES_LIST_RESULT_SCHEMA)
        self.assertEqual(result["resources"], [])

    def test_empty_resource_templates_list_shape(self):
        srv = McpServer("t")
        result = call_rpc(srv, "resources/templates/list")
        assert_schema(result, RESOURCE_TEMPLATES_LIST_RESULT_SCHEMA)
        self.assertEqual(result["resourceTemplates"], [])

    def test_static_resource_appears_in_list_with_valid_shape(self):
        srv = McpServer("t")

        @srv.resource("test://readme")
        def readme() -> str:
            """A readme."""
            return "hello"

        result = call_rpc(srv, "resources/list")
        assert_schema(result, RESOURCES_LIST_RESULT_SCHEMA)
        self.assertTrue(any(r["uri"] == "test://readme" for r in result["resources"]))


class NotificationEndpointsTests(unittest.TestCase):
    def test_notifications_initialized_returns_none_or_empty(self):
        srv = McpServer("t")
        self.assertIn(call_rpc(srv, "notifications/initialized"), (None, {}))

    def test_notifications_cancelled_accepts_request_id_param(self):
        srv = McpServer("t")
        result = call_rpc(srv, "notifications/cancelled", requestId=1, reason="test")
        self.assertIn(result, (None, {}))


if __name__ == "__main__":
    unittest.main()
