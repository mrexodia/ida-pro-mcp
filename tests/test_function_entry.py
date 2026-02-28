#!/usr/bin/env python3
"""Function entry resolution and name-based lookup tests (PR #264)

Tests that get_function returns the function entry point when queried
with an interior address, and that decompile/disasm accept function
names in addition to numeric addresses.

Requires the IDA MCP server to be running (default: http://localhost:13337).

Usage:
    python tests/test_function_entry.py
    python tests/test_function_entry.py http://localhost:13337
"""

import sys, json, socket

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 13337


def call(method, **kwargs):
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": method, "arguments": kwargs},
        "id": 1,
    }).encode()

    request = (
        f"POST /mcp HTTP/1.0\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

    with socket.create_connection((HOST, PORT)) as sock:
        sock.sendall(request)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk

    raw = response.split(b"\r\n\r\n", 1)[1].decode()
    return json.loads(raw)["result"]["structuredContent"]


if __name__ == "__main__":
    results = []

    def test(name, ok, detail=""):
        results.append(ok)
        suffix = f"  ({detail})" if detail else ""
        print(f"[{'PASS' if ok else 'FAIL'}] {name}{suffix}")

    # crackme03.elf: check_pw @ 0x11a9, main @ 0x123e
    CHECK_PW_EA = "0x11a9"
    CHECK_PW_INTERIOR = "0x11ad"  # push rbp, second instruction inside check_pw
    MAIN_EA = "0x123e"

    # get_function: interior address must return the function entry, not the queried addr
    r = call("lookup_funcs", queries=CHECK_PW_INTERIOR)["result"][0]
    test("get_function: interior address resolves to a function", r["fn"] is not None, CHECK_PW_INTERIOR)
    if r["fn"]:
        test(
            "get_function: start_ea is the function entry point",
            r["fn"]["addr"] == CHECK_PW_EA,
            f"got {r['fn']['addr']}, expected {CHECK_PW_EA}",
        )
        test(
            "get_function: start_ea differs from the queried interior address",
            r["fn"]["addr"] != CHECK_PW_INTERIOR,
            f"start_ea={r['fn']['addr']}, queried={CHECK_PW_INTERIOR}",
        )

    # decompile/disasm: accept a function name string
    for tool in ("decompile", "disasm"):
        for name in ("check_pw", "main"):
            r = call(tool, addr=name)
            test(
                f"{tool}: accepts name '{name}'",
                r.get("error") is None,
                f"error={r.get('error')}",
            )

    # decompile/disasm: unknown name must return an error
    for tool in ("decompile", "disasm"):
        r = call(tool, addr="nonexistent_xyz")
        test(
            f"{tool}: unknown name returns an error",
            r.get("error") is not None,
            f"error={r.get('error')}",
        )

    # disasm: header must use func.start_ea when querying an interior address
    r = call("disasm", addr=CHECK_PW_INTERIOR)
    asm = r.get("asm", {})
    test(
        "disasm: header start_ea is the function entry, not the queried interior address",
        asm.get("start_ea") == CHECK_PW_EA,
        f"start_ea={asm.get('start_ea')}, queried={CHECK_PW_INTERIOR}",
    )

    passed = sum(results)
    failed = len(results) - passed
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
