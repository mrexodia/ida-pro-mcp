from __future__ import annotations

import argparse
import json
import os
import sys
from typing import BinaryIO

from offline_llm.backend import LocalLLM


class JSONRPCServer:
    """Simple JSON-RPC 2.0 server using a LocalLLM backend."""

    def __init__(self, llm: LocalLLM, *, inp: BinaryIO, out: BinaryIO) -> None:
        self.llm = llm
        self.inp = inp
        self.out = out

    def _send(self, obj: dict) -> None:
        self.out.write(json.dumps(obj).encode() + b"\n")
        self.out.flush()

    def _handle_chat(self, req_id, params: dict) -> None:
        messages = params.get("messages", [])
        stream = params.get("stream", False)
        try:
            if stream:
                for chunk in self.llm.chat(messages, stream=True):
                    self._send({"id": req_id, "chunk": chunk})
                self._send({"id": req_id, "done": True})
            else:
                result = self.llm.chat(messages, stream=False)
                self._send({"id": req_id, "result": result})
        except Exception as e:  # pragma: no cover - unexpected errors
            self._send({"id": req_id, "error": str(e)})

    def handle(self, req: dict) -> bool:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})
        if method == "chat":
            self._handle_chat(req_id, params)
        elif method == "shutdown":
            self._send({"id": req_id, "result": None})
            return False
        else:
            self._send({"id": req_id, "error": f"Unknown method: {method}"})
        return True

    def serve_forever(self) -> None:
        while True:
            line = self.inp.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line.decode())
            except Exception:
                self._send({"error": "invalid json"})
                continue
            if not self.handle(req):
                break


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Offline MCP core")
    parser.add_argument("--socket-fd", type=int, help="fd for anonymous pipe")
    parser.add_argument("--config", help="LLM configuration file")
    args = parser.parse_args(argv)

    if args.socket_fd is not None:
        sock = os.fdopen(args.socket_fd, "r+b", buffering=0)
        inp = sock
        out = sock
    else:
        inp = sys.stdin.buffer
        out = sys.stdout.buffer

    llm = LocalLLM(args.config)
    server = JSONRPCServer(llm, inp=inp, out=out)
    server.serve_forever()


__all__ = ["JSONRPCServer", "LocalLLM", "main"]
