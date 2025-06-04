from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from offline_llm.backend import LocalLLM


class JSONRPCServer:
    def __init__(self, llm: LocalLLM, fd: int | None = None) -> None:
        self.llm = llm
        if fd is not None:
            self.infile = os.fdopen(fd, "r+b", buffering=0)
            self.outfile = self.infile  # duplex pipe
        else:
            self.infile = sys.stdin.buffer
            self.outfile = sys.stdout.buffer

    def serve_forever(self) -> None:
        while True:
            line = self.infile.readline()
            if not line:
                break
            try:
                request = json.loads(line)
            except Exception:
                continue
            response = self.handle_request(request)
            if response is not None:
                self.outfile.write(json.dumps(response).encode() + b"\n")
                self.outfile.flush()

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        method = request.get("method")
        rpc_id = request.get("id")
        params = request.get("params", {})
        if method != "chat":
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        messages = params.get("messages", [])
        stream = params.get("stream", False)
        if stream:
            for token in self.llm.chat(messages, stream=True):
                token_resp = {"jsonrpc": "2.0", "id": rpc_id, "token": token}
                self.outfile.write(json.dumps(token_resp).encode() + b"\n")
                self.outfile.flush()
            return {"jsonrpc": "2.0", "id": rpc_id, "done": True}
        result = self.llm.chat(messages)
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Offline LLM JSON-RPC server")
    parser.add_argument("--config", type=str, help="Path to config toml")
    parser.add_argument("--socket-fd", type=int, help="Socket FD from the plugin")
    args = parser.parse_args(argv)

    llm = LocalLLM(args.config)
    server = JSONRPCServer(llm, fd=args.socket_fd)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":  # pragma: no cover
    main()