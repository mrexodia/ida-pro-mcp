"""Structured parameter coercion for tools/call arguments."""

import pathlib
import sys
import unittest
from typing import TypedDict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import McpServer


class RenameBatch(TypedDict, total=False):
    start: str
    end: str


def _server() -> McpServer:
    srv = McpServer("union-param-tests")

    @srv.tool
    def take_addrs(addrs: list[str] | str) -> str:
        """Echo addrs back with its Python type."""
        return f"{type(addrs).__name__}:{addrs}"

    @srv.tool
    def take_items(items: list[dict] | dict) -> str:
        """Echo items back with its Python type."""
        return f"{type(items).__name__}:{items}"

    @srv.tool
    def take_batch(batch: RenameBatch) -> str:
        """Echo batch back with its Python type."""
        return f"{type(batch).__name__}:{batch}"

    @srv.tool
    def take_action_args(action_args: dict) -> str:
        """Echo action_args back with its Python type."""
        return f"{type(action_args).__name__}:{action_args}"

    @srv.tool
    def take_names(names: list[str]) -> str:
        """Echo names back with its Python type."""
        return f"{type(names).__name__}:{names}"

    @srv.tool
    def take_label(label: str) -> str:
        """Echo label back with its Python type."""
        return f"{type(label).__name__}:{label}"

    return srv


class UnionParamTests(unittest.TestCase):
    def setUp(self):
        self.srv = _server()

    def _call(self, name: str, **arguments):
        resp = self.srv.registry.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        result = resp["result"]
        self.assertFalse(result.get("isError"), result)
        return result["structuredContent"]["result"]

    def test_str_union_keeps_numeric_string(self):
        self.assertEqual(self._call("take_addrs", addrs="4670"), "str:4670")

    def test_str_union_keeps_json_looking_string(self):
        self.assertEqual(
            self._call("take_addrs", addrs='["0x10"]'), 'str:["0x10"]'
        )

    def test_non_str_union_still_decodes_json_string(self):
        self.assertEqual(
            self._call("take_items", items='[{"addr": "0x10"}]'),
            "list:[{'addr': '0x10'}]",
        )


class StructuredParamTests(unittest.TestCase):
    """Non-union dict/list parameters, e.g. `rename` and `diff_before_after`."""

    def setUp(self):
        self.srv = _server()

    def _call(self, name: str, **arguments):
        result = self.srv.registry.dispatch(self._request(name, arguments))["result"]
        self.assertFalse(result.get("isError"), result)
        return result["structuredContent"]["result"]

    def _error_text(self, name: str, **arguments):
        result = self.srv.registry.dispatch(self._request(name, arguments))["result"]
        self.assertTrue(result.get("isError"), result)
        return result["content"][0]["text"]

    @staticmethod
    def _request(name: str, arguments: dict):
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }

    def test_typeddict_accepts_json_string(self):
        self.assertEqual(
            self._call("take_batch", batch='{"start": "0x100"}'),
            "dict:{'start': '0x100'}",
        )

    def test_bare_dict_accepts_json_string(self):
        self.assertEqual(
            self._call("take_action_args", action_args='{"name": "main"}'),
            "dict:{'name': 'main'}",
        )

    def test_bare_list_accepts_json_string(self):
        self.assertEqual(
            self._call("take_names", names='["main", "init"]'),
            "list:['main', 'init']",
        )

    def test_str_param_keeps_json_looking_string(self):
        self.assertEqual(
            self._call("take_label", label='["not", "decoded"]'),
            'str:["not", "decoded"]',
        )

    def test_undecodable_string_keeps_the_type_error(self):
        self.assertEqual(
            self._error_text("take_names", names="start here"),
            "Invalid params: names expected list, got str",
        )


if __name__ == "__main__":
    unittest.main()
