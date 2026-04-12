"""Tests for MCP outputSchema generation and structuredContent consistency.

Validates that the advertised outputSchema matches the structuredContent
actually returned by _mcp_tools_call, especially for union-of-objects
return types that should NOT be wrapped in a {"result": ...} envelope.
"""

import http.server  # Preload stdlib http before adding local ida_mcp paths.
import json
import pathlib
import sys
import unittest
from typing import Annotated, TypedDict

_ZEROMCP_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
sys.path.insert(0, str(_ZEROMCP_SRC))
try:
    from zeromcp.mcp import McpServer
finally:
    sys.path.remove(str(_ZEROMCP_SRC))


# ---------------------------------------------------------------------------
# Fixture types mirroring the export_funcs pattern
# ---------------------------------------------------------------------------

class JsonResult(TypedDict):
    format: str
    items: list[dict]

class HeaderResult(TypedDict):
    format: str
    content: str

class PrototypesResult(TypedDict):
    format: str
    names: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _matches_schema(instance, schema: dict) -> bool:
    """Minimal JSON-Schema validator (enough for the shapes we care about)."""
    if "anyOf" in schema:
        return any(_matches_schema(instance, sub) for sub in schema["anyOf"])

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(instance, dict):
            return False
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        if not required.issubset(instance.keys()):
            return False
        if schema.get("additionalProperties") is False:
            if not set(instance.keys()).issubset(props.keys()):
                return False
        for key, sub_schema in props.items():
            if key in instance and not _matches_schema(instance[key], sub_schema):
                return False
        return True
    if expected_type == "array":
        return isinstance(instance, list)
    if expected_type == "string":
        return isinstance(instance, str)
    if expected_type == "integer":
        return isinstance(instance, int)
    if expected_type == "number":
        return isinstance(instance, (int, float))
    if expected_type == "boolean":
        return isinstance(instance, bool)
    if expected_type == "null":
        return instance is None
    return True


class SchemaIsObjectLikeTests(unittest.TestCase):
    """Unit tests for McpServer._schema_is_object_like."""

    def setUp(self):
        self.srv = McpServer("test")

    def test_plain_object(self):
        self.assertTrue(self.srv._schema_is_object_like({"type": "object"}))

    def test_anyof_all_objects(self):
        schema = {"anyOf": [{"type": "object"}, {"type": "object"}]}
        self.assertTrue(self.srv._schema_is_object_like(schema))

    def test_anyof_mixed(self):
        schema = {"anyOf": [{"type": "object"}, {"type": "string"}]}
        self.assertFalse(self.srv._schema_is_object_like(schema))

    def test_anyof_no_objects(self):
        schema = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
        self.assertFalse(self.srv._schema_is_object_like(schema))

    def test_primitive(self):
        self.assertFalse(self.srv._schema_is_object_like({"type": "string"}))

    def test_array(self):
        self.assertFalse(self.srv._schema_is_object_like({"type": "array"}))

    def test_nested_anyof_objects(self):
        schema = {
            "anyOf": [
                {"type": "object"},
                {"anyOf": [{"type": "object"}, {"type": "object"}]},
            ]
        }
        self.assertTrue(self.srv._schema_is_object_like(schema))

    def test_nested_anyof_with_non_object(self):
        schema = {
            "anyOf": [
                {"type": "object"},
                {"anyOf": [{"type": "object"}, {"type": "string"}]},
            ]
        }
        self.assertFalse(self.srv._schema_is_object_like(schema))

    def test_empty_schema(self):
        self.assertFalse(self.srv._schema_is_object_like({}))


class OutputSchemaUnionOfObjectsTests(unittest.TestCase):
    """outputSchema for union-of-TypedDicts must NOT be wrapped in {"result": ...}."""

    def setUp(self):
        self.srv = McpServer("test")

    def _register_and_get_schema(self, func):
        self.srv.tool(func)
        schema = self.srv._generate_tool_schema(func.__name__, func)
        return schema

    def test_union_of_typed_dicts_not_wrapped(self):
        def multi_format(fmt: str = "json") -> JsonResult | HeaderResult | PrototypesResult:
            """Returns one of several result shapes."""
            ...

        schema = self._register_and_get_schema(multi_format)
        out = schema["outputSchema"]

        self.assertIn("anyOf", out, "union-of-objects should produce anyOf at top level")
        self.assertNotIn("result", out.get("properties", {}),
                         "union-of-objects must not be wrapped in a 'result' property")
        self.assertNotIn("required", out,
                         "top-level should have no required list (it's anyOf, not object)")

    def test_single_typed_dict_not_wrapped(self):
        def single_format() -> JsonResult:
            """Returns a single result shape."""
            ...

        schema = self._register_and_get_schema(single_format)
        out = schema["outputSchema"]

        self.assertEqual(out["type"], "object")
        self.assertIn("format", out["properties"])
        self.assertNotIn("result", out.get("properties", {}))

    def test_primitive_return_is_wrapped(self):
        def count_things() -> int:
            """Returns a count."""
            ...

        schema = self._register_and_get_schema(count_things)
        out = schema["outputSchema"]

        self.assertEqual(out["type"], "object")
        self.assertIn("result", out["properties"])
        self.assertEqual(out["required"], ["result"])

    def test_list_return_is_wrapped(self):
        def list_things() -> list[str]:
            """Returns a list."""
            ...

        schema = self._register_and_get_schema(list_things)
        out = schema["outputSchema"]

        self.assertEqual(out["type"], "object")
        self.assertIn("result", out["properties"])

    def test_union_with_non_object_is_wrapped(self):
        def maybe_string(x: str) -> dict | str:
            """Could return either."""
            ...

        schema = self._register_and_get_schema(maybe_string)
        out = schema["outputSchema"]

        self.assertIn("result", out.get("properties", {}),
                       "mixed union (object + primitive) should still wrap")


class StructuredContentMatchesSchemaTests(unittest.TestCase):
    """End-to-end: structuredContent returned by tools/call validates against outputSchema."""

    def setUp(self):
        self.srv = McpServer("test")

    def _register_tool(self, func):
        self.srv.tool(func)
        return self.srv._generate_tool_schema(func.__name__, func)

    def _call_tool(self, name, arguments=None):
        return self.srv._mcp_tools_call(name, arguments)

    def test_union_typed_dict_json_variant(self):
        def export(
            fmt: Annotated[str, "Output format"] = "json",
        ) -> JsonResult | HeaderResult | PrototypesResult:
            """Export data."""
            return {"format": "json", "items": [{"a": 1}]}

        schema = self._register_tool(export)
        result = self._call_tool("export", {"fmt": "json"})

        self.assertFalse(result["isError"])
        structured = result["structuredContent"]
        output_schema = schema["outputSchema"]

        self.assertTrue(
            _matches_schema(structured, output_schema),
            f"structuredContent {structured} does not match outputSchema {json.dumps(output_schema, indent=2)}",
        )

    def test_union_typed_dict_header_variant(self):
        def export2(
            fmt: Annotated[str, "Output format"] = "json",
        ) -> JsonResult | HeaderResult | PrototypesResult:
            """Export data."""
            return {"format": "c_header", "content": "// header"}

        schema = self._register_tool(export2)
        result = self._call_tool("export2", {"fmt": "c_header"})

        self.assertFalse(result["isError"])
        structured = result["structuredContent"]
        output_schema = schema["outputSchema"]

        self.assertTrue(
            _matches_schema(structured, output_schema),
            f"structuredContent {structured} does not match outputSchema {json.dumps(output_schema, indent=2)}",
        )

    def test_union_typed_dict_prototypes_variant(self):
        def export3(
            fmt: Annotated[str, "Output format"] = "json",
        ) -> JsonResult | HeaderResult | PrototypesResult:
            """Export data."""
            return {"format": "prototypes", "names": ["main", "foo"]}

        schema = self._register_tool(export3)
        result = self._call_tool("export3", {"fmt": "prototypes"})

        self.assertFalse(result["isError"])
        structured = result["structuredContent"]
        output_schema = schema["outputSchema"]

        self.assertTrue(
            _matches_schema(structured, output_schema),
            f"structuredContent {structured} does not match outputSchema {json.dumps(output_schema, indent=2)}",
        )

    def test_primitive_return_wrapped_consistently(self):
        def count() -> int:
            """Count something."""
            return 42

        schema = self._register_tool(count)
        result = self._call_tool("count")

        self.assertFalse(result["isError"])
        structured = result["structuredContent"]
        output_schema = schema["outputSchema"]

        self.assertEqual(structured, {"result": 42})
        self.assertTrue(
            _matches_schema(structured, output_schema),
            f"structuredContent {structured} does not match outputSchema {json.dumps(output_schema, indent=2)}",
        )

    def test_single_typed_dict_not_wrapped(self):
        def info() -> JsonResult:
            """Get info."""
            return {"format": "json", "items": []}

        schema = self._register_tool(info)
        result = self._call_tool("info")

        self.assertFalse(result["isError"])
        structured = result["structuredContent"]
        output_schema = schema["outputSchema"]

        self.assertNotIn("result", structured,
                         "single TypedDict should pass through without wrapping")
        self.assertTrue(
            _matches_schema(structured, output_schema),
            f"structuredContent {structured} does not match outputSchema {json.dumps(output_schema, indent=2)}",
        )


if __name__ == "__main__":
    unittest.main()
