import json
import os
import socket
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


def start_core(fd: int):
    core.main(["--socket-fd", str(fd)])


def test_chat_pipe():
    s1, s2 = socket.socketpair()

    thread = threading.Thread(target=start_core, args=(s1.fileno(),), daemon=True)
    with mock.patch("ida_pro_mcp.server.core.LocalLLM", StubLLM):
        thread.start()
        with s2.makefile("wb", buffering=0) as writer, s2.makefile("rb", buffering=0) as reader:
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