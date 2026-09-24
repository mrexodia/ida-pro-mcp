"""Union parameter coercion for tools/call arguments."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import McpServer


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


if __name__ == "__main__":
    unittest.main()
