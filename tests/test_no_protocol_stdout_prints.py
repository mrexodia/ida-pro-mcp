"""Protocol/runtime modules must not write logs to stdout.

stdio MCP uses stdout for JSON-RPC frames, so accidental print() calls in
zeromcp corrupt the transport. Use logging (stderr by default) instead.
"""

import ast
from pathlib import Path


PROTOCOL_MODULES = [
    Path("src/ida_pro_mcp/ida_mcp/zeromcp/jsonrpc.py"),
    Path("src/ida_pro_mcp/ida_mcp/zeromcp/mcp.py"),
    Path("src/ida_pro_mcp/ida_mcp/http.py"),
    Path("src/ida_pro_mcp/idalib_supervisor.py"),
]


def test_protocol_modules_do_not_call_print():
    offenders: list[str] = []
    for path in PROTOCOL_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                offenders.append(f"{path}:{node.lineno}")
    assert offenders == []
