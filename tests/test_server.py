import json
import os
import threading
from pathlib import Path
import sys
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / "src"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(ROOT))

import ida_pro_mcp.server.core as core

class StubLLM:
    def __init__(self, *a, **k):
        pass

    def chat(self, messages, stream=False):
        if stream:
            def gen():
                yield "pong"
            return gen()
        return "pong"


class _IO:
    def __init__(self, buffer):
        self.buffer = buffer


def start_core(r_in: int, w_out: int):
    in_file = os.fdopen(r_in, "rb", buffering=0)
    out_file = os.fdopen(w_out, "wb", buffering=0)
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = _IO(in_file)
    sys.stdout = _IO(out_file)
    try:
        core.main([])
    finally:
        sys.stdin = old_in
        sys.stdout = old_out


def test_chat_pipe():
    r_in, w_in = os.pipe()
    r_out, w_out = os.pipe()

    thread = threading.Thread(target=start_core, args=(r_in, w_out), daemon=True)
    with mock.patch("ida_pro_mcp.server.core.LocalLLM", StubLLM):
        thread.start()
        with os.fdopen(w_in, "wb", buffering=0) as writer, os.fdopen(r_out, "rb", buffering=0) as reader:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "chat",
                "params": {"messages": [{"role": "user", "content": "ping"}]},
            }
            writer.write(json.dumps(request).encode() + b"\n")
            writer.flush()
            response = json.loads(reader.readline())
            assert response["result"] == "pong"
    thread.join(timeout=1)