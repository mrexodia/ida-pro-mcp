"""tools/list invariants. Regression guard for PR #357 / issue #368."""

import re
import sys
import pathlib
import unittest
from typing import Annotated, NotRequired, Optional, TypedDict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import (
    McpServer,
    TOOL_NAME_PATTERN,
    TOOL_SCHEMA,
    TOOLS_LIST_RESULT_SCHEMA,
    assert_schema,
    call_rpc,
)


class FuncExportJson(TypedDict):
    format: str
    items: list[dict]


class FuncExportHeader(TypedDict):
    format: str
    content: str


class FuncExportPrototypes(TypedDict):
    format: str
    names: list[str]


class NestedResult(TypedDict):
    inner: FuncExportJson
    count: int


class OptionalFieldResult(TypedDict):
    always: str
    maybe: NotRequired[int]


def _register_broad_tool_suite(srv: McpServer) -> None:
    @srv.tool
    def tool_primitive_int() -> int:
        """returns int."""
        return 1

    @srv.tool
    def tool_primitive_bool() -> bool:
        """returns bool."""
        return True

    @srv.tool
    def tool_primitive_str() -> str:
        """returns str."""
        return "x"

    @srv.tool
    def tool_list_of_primitives() -> list[str]:
        """list of str."""
        return []

    @srv.tool
    def tool_list_of_typed_dicts() -> list[FuncExportJson]:
        """list of TypedDict."""
        return []

    @srv.tool
    def tool_dict_str_typed_dict() -> dict[str, FuncExportJson]:
        """dict of TypedDict."""
        return {}

    @srv.tool
    def tool_single_typed_dict() -> FuncExportJson:
        """single TypedDict."""
        return {"format": "json", "items": []}

    @srv.tool
    def tool_union_of_typed_dicts() -> FuncExportJson | FuncExportHeader | FuncExportPrototypes:
        """union of TypedDicts."""
        return {"format": "json", "items": []}

    @srv.tool
    def tool_optional_typed_dict() -> Optional[FuncExportJson]:
        """Optional[TypedDict]."""
        return None

    @srv.tool
    def tool_nested_typed_dict() -> NestedResult:
        """nested TypedDict."""
        return {"inner": {"format": "json", "items": []}, "count": 0}

    @srv.tool
    def tool_typed_dict_with_notrequired() -> OptionalFieldResult:
        """NotRequired field."""
        return {"always": "x"}

    @srv.tool
    def tool_with_annotated_args(
        x: Annotated[int, "an x value"],
        y: Annotated[str, "a y value"] = "default",
    ) -> FuncExportJson:
        """Annotated args."""
        return {"format": "json", "items": []}

    @srv.tool
    def tool_no_return_type():
        """no return type."""
        return None


class ToolsListSpecComplianceTests(unittest.TestCase):
    def setUp(self):
        self.srv = McpServer("test")
        _register_broad_tool_suite(self.srv)
        self.tools = call_rpc(self.srv, "tools/list")["tools"]

    def test_tools_list_response_matches_mcp_schema(self):
        assert_schema({"tools": self.tools}, TOOLS_LIST_RESULT_SCHEMA)

    def test_every_tool_matches_mcp_tool_schema(self):
        for tool in self.tools:
            with self.subTest(name=tool.get("name")):
                assert_schema(tool, TOOL_SCHEMA)

    def test_every_tool_name_matches_mcp_name_pattern(self):
        pat = re.compile(TOOL_NAME_PATTERN)
        for tool in self.tools:
            with self.subTest(name=tool["name"]):
                self.assertRegex(tool["name"], pat)

    def test_no_duplicate_tool_names(self):
        names = [t["name"] for t in self.tools]
        self.assertEqual(len(names), len(set(names)))

    def test_every_tool_has_non_empty_description(self):
        for tool in self.tools:
            with self.subTest(name=tool["name"]):
                self.assertIn("description", tool)
                self.assertGreater(len(tool["description"].strip()), 0)

    def test_every_tool_inputSchema_root_type_is_object(self):
        for tool in self.tools:
            with self.subTest(name=tool["name"]):
                self.assertEqual(tool["inputSchema"].get("type"), "object")

    def test_every_tool_outputSchema_root_type_is_object_when_present(self):
        # Regression guard for PR #357 / issue #368.
        for tool in self.tools:
            osch = tool.get("outputSchema")
            if osch is None:
                continue
            with self.subTest(name=tool["name"]):
                self.assertEqual(osch.get("type"), "object")

    def test_union_of_typed_dicts_outputSchema_has_root_object_type(self):
        tool = next(t for t in self.tools if t["name"] == "tool_union_of_typed_dicts")
        self.assertEqual(tool["outputSchema"].get("type"), "object")

    def test_optional_typed_dict_outputSchema_has_root_object_type(self):
        tool = next(t for t in self.tools if t["name"] == "tool_optional_typed_dict")
        if "outputSchema" in tool:
            self.assertEqual(tool["outputSchema"].get("type"), "object")

    def test_list_of_typed_dicts_outputSchema_has_root_object_type(self):
        tool = next(t for t in self.tools if t["name"] == "tool_list_of_typed_dicts")
        self.assertEqual(tool["outputSchema"].get("type"), "object")

    def test_primitive_returns_have_object_root_outputSchema(self):
        for name in ("tool_primitive_int", "tool_primitive_bool", "tool_primitive_str"):
            with self.subTest(name=name):
                tool = next(t for t in self.tools if t["name"] == name)
                self.assertEqual(tool["outputSchema"].get("type"), "object")


class ProductionToolsSpecComplianceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = McpServer("test")
        _register_broad_tool_suite(cls.srv)
        cls.tools = call_rpc(cls.srv, "tools/list")["tools"]

    def test_tools_list_passes_strict_mcp_validation(self):
        assert_schema({"tools": self.tools}, TOOLS_LIST_RESULT_SCHEMA)

    def test_no_tool_has_empty_or_missing_inputSchema(self):
        for tool in self.tools:
            with self.subTest(name=tool["name"]):
                self.assertIn("inputSchema", tool)
                self.assertIsInstance(tool["inputSchema"], dict)

    def test_tool_name_does_not_contain_spaces_or_control_chars(self):
        for tool in self.tools:
            name = tool["name"]
            with self.subTest(name=name):
                self.assertNotIn(" ", name)
                self.assertTrue(name.isprintable())


if __name__ == "__main__":
    unittest.main()
