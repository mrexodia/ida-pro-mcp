import json
import sys
from offline_llm.backend import LocalLLM  # offline LLM client

class JSONRPCServer:
    def __init__(self, llm: LocalLLM):
        self.llm = llm

    def handle(self, request: dict):
        method = request.get("method")
        if method == "chat":
            params = request.get("params", {})
            messages = params.get("messages", [])
            stream = params.get("stream", False)
            result = self.llm.chat(messages, stream=stream)
            if stream and not isinstance(result, str):
                return "".join(result)
            return result
        raise Exception(f"Unknown method {method}")


def main(argv: list[str] | None = None, llm_class=LocalLLM) -> None:
    llm = llm_class()
    server = JSONRPCServer(llm)
    for line in sys.stdin.buffer:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        try:
            result = server.handle(request)
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
        except Exception as e:
            response = {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32000, "message": str(e)}}
        sys.stdout.buffer.write(json.dumps(response).encode() + b"\n")
        sys.stdout.buffer.flush()
