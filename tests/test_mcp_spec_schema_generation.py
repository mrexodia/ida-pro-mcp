"""Schema generation edge cases: every return-type shape must produce a
root `type: "object"` outputSchema, and the runtime return value must
validate against it."""

import sys
import pathlib
import unittest
from typing import Annotated, NotRequired, Optional, TypedDict

from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import McpServer, TOOL_SCHEMA, assert_schema, call_rpc


class Inner(TypedDict):
    x: int
    y: str


class NestedOuter(TypedDict):
    inner: Inner
    label: str


class ListOfInner(TypedDict):
    items: list[Inner]


class DictOfInner(TypedDict):
    table: dict[str, Inner]


class WithOptional(TypedDict):
    required_field: str
    maybe: NotRequired[int]


class OptionalContextFields(TypedDict):
    context_id: NotRequired[str]
    transport_context_id: NotRequired[str | None]
    isolated_contexts: NotRequired[bool]


class IdalibStyleResult(OptionalContextFields, total=False):
    success: bool
    error: str


class SessionInfo(TypedDict):
    session_id: str
    input_path: str


class SessionListInfo(SessionInfo, total=False):
    is_active: bool
    is_current_context: bool
    bound_contexts: int


class SessionListResult(OptionalContextFields, total=False):
    sessions: list[SessionListInfo]
    error: str


class VariantA(TypedDict):
    kind: str
    value_a: int


class VariantB(TypedDict):
    kind: str
    value_b: str


class VariantC(TypedDict):
    kind: str
    value_c: list[str]


def _register_and_get(srv: McpServer, fn):
    srv.tool(fn)
    return next(t for t in call_rpc(srv, "tools/list")["tools"] if t["name"] == fn.__name__)


def _call_and_get_structured(srv: McpServer, name: str, **params):
    return call_rpc(srv, "tools/call", name=name, arguments=params)


class OutputSchemaShapeTests(unittest.TestCase):
    def setUp(self):
        self.srv = McpServer("test")

    def _schema_of(self, fn):
        return _register_and_get(self.srv, fn)["outputSchema"]

    def test_primitive_int_root_type_is_object(self):
        def f() -> int:
            """doc."""
            return 0
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_primitive_float_root_type_is_object(self):
        def f() -> float:
            """doc."""
            return 1.0
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_primitive_bool_root_type_is_object(self):
        def f() -> bool:
            """doc."""
            return True
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_primitive_str_root_type_is_object(self):
        def f() -> str:
            """doc."""
            return ""
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_list_of_str_root_type_is_object(self):
        def f() -> list[str]:
            """doc."""
            return []
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_list_of_typed_dicts_root_type_is_object(self):
        def f() -> list[Inner]:
            """doc."""
            return []
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_single_typed_dict_root_type_is_object(self):
        def f() -> Inner:
            """doc."""
            return {"x": 1, "y": ""}
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_nested_typed_dict_root_type_is_object(self):
        def f() -> NestedOuter:
            """doc."""
            return {"inner": {"x": 1, "y": ""}, "label": "z"}
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_typed_dict_with_list_field_root_type_is_object(self):
        def f() -> ListOfInner:
            """doc."""
            return {"items": []}
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_typed_dict_with_dict_field_root_type_is_object(self):
        def f() -> DictOfInner:
            """doc."""
            return {"table": {}}
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_typed_dict_with_notrequired_root_type_is_object(self):
        def f() -> WithOptional:
            """doc."""
            return {"required_field": "x"}
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_inherited_notrequired_fields_are_not_required(self):
        def f() -> IdalibStyleResult:
            """doc."""
            return {"error": "bad input"}
        schema = self._schema_of(f)
        self.assertEqual(schema.get("type"), "object")
        self.assertNotIn("context_id", schema.get("required", []))
        self.assertNotIn("transport_context_id", schema.get("required", []))
        self.assertNotIn("isolated_contexts", schema.get("required", []))

    def test_optional_typed_dict_root_type_is_object(self):
        def f() -> Optional[Inner]:
            """doc."""
            return None
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_union_of_typed_dicts_root_type_is_object(self):
        def f() -> VariantA | VariantB | VariantC:
            """doc."""
            return {"kind": "a", "value_a": 1}
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_union_of_object_and_primitive_root_type_is_object(self):
        def f() -> Inner | str:
            """doc."""
            return "x"
        self.assertEqual(self._schema_of(f).get("type"), "object")

    def test_dict_str_typed_dict_root_type_is_object(self):
        def f() -> dict[str, Inner]:
            """doc."""
            return {}
        self.assertEqual(self._schema_of(f).get("type"), "object")


class StructuredContentValidatesAgainstOutputSchemaTests(unittest.TestCase):
    def setUp(self):
        self.srv = McpServer("test")

    def _both(self, fn):
        tool = _register_and_get(self.srv, fn)
        result = _call_and_get_structured(self.srv, fn.__name__)
        return tool["outputSchema"], result

    def test_primitive_int_roundtrip(self):
        def f() -> int:
            """doc."""
            return 42
        osch, result = self._both(f)
        self.assertIn("structuredContent", result)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_list_of_primitives_roundtrip(self):
        def f() -> list[str]:
            """doc."""
            return ["a", "b"]
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_single_typed_dict_roundtrip(self):
        def f() -> Inner:
            """doc."""
            return {"x": 1, "y": "y"}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_union_of_typed_dicts_variant_a_roundtrip(self):
        def f() -> VariantA | VariantB:
            """doc."""
            return {"kind": "a", "value_a": 7}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_union_of_typed_dicts_variant_b_roundtrip(self):
        def f() -> VariantA | VariantB:
            """doc."""
            return {"kind": "b", "value_b": "z"}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_nested_typed_dict_roundtrip(self):
        def f() -> NestedOuter:
            """doc."""
            return {"inner": {"x": 1, "y": "y"}, "label": "L"}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_notrequired_omitted_field_roundtrip(self):
        def f() -> WithOptional:
            """doc."""
            return {"required_field": "x"}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_notrequired_present_field_roundtrip(self):
        def f() -> WithOptional:
            """doc."""
            return {"required_field": "x", "maybe": 99}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_inherited_notrequired_omitted_fields_roundtrip(self):
        def f() -> IdalibStyleResult:
            """doc."""
            return {"error": "bad input"}
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])

    def test_session_list_declared_metadata_roundtrip(self):
        def f() -> SessionListResult:
            """doc."""
            return {
                "sessions": [
                    {
                        "session_id": "s1",
                        "input_path": "sample.bin",
                        "is_active": True,
                        "is_current_context": True,
                        "bound_contexts": 1,
                    }
                ]
            }
        osch, result = self._both(f)
        Draft202012Validator(osch).validate(result["structuredContent"])


class InputSchemaShapeTests(unittest.TestCase):
    def setUp(self):
        self.srv = McpServer("test")

    def _schema_of(self, fn):
        return _register_and_get(self.srv, fn)["inputSchema"]

    def test_annotated_args_are_described(self):
        def f(x: Annotated[int, "the x value"], y: Annotated[str, "optional y"] = "z") -> int:
            """doc."""
            return 0
        sch = self._schema_of(f)
        self.assertEqual(sch["type"], "object")
        self.assertEqual(sch["properties"]["x"]["description"], "the x value")
        self.assertIn("x", sch["required"])
        self.assertNotIn("y", sch["required"])

    def test_no_args_has_empty_properties(self):
        def f() -> int:
            """doc."""
            return 0
        sch = self._schema_of(f)
        self.assertEqual(sch["type"], "object")
        self.assertEqual(sch["properties"], {})
        self.assertEqual(sch["required"], [])

    def test_optional_typed_dict_arg_root_remains_object(self):
        def f(data: Optional[Inner] = None) -> int:
            """doc."""
            return 0
        sch = self._schema_of(f)
        self.assertEqual(sch["type"], "object")
        self.assertIn("data", sch["properties"])


class RegisteredToolMatchesSpecTests(unittest.TestCase):
    def setUp(self):
        self.srv = McpServer("test")

    def _register_all(self, fns):
        for fn in fns:
            self.srv.tool(fn)
        return call_rpc(self.srv, "tools/list")["tools"]

    def test_every_shape_registers_as_valid_mcp_tool(self):
        def t_int() -> int:
            """."""
            return 0

        def t_list() -> list[str]:
            """."""
            return []

        def t_dict() -> Inner:
            """."""
            return {"x": 0, "y": ""}

        def t_union() -> VariantA | VariantB:
            """."""
            return {"kind": "a", "value_a": 0}

        def t_optional() -> Optional[Inner]:
            """."""
            return None

        def t_nested() -> NestedOuter:
            """."""
            return {"inner": {"x": 0, "y": ""}, "label": ""}

        tools = self._register_all([t_int, t_list, t_dict, t_union, t_optional, t_nested])
        for tool in tools:
            with self.subTest(name=tool["name"]):
                assert_schema(tool, TOOL_SCHEMA)


if __name__ == "__main__":
    unittest.main()
