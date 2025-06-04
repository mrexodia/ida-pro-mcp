from ..jsonrpc_server.core import JSONRPCServer, main as _main
from offline_llm.backend import LocalLLM

def main(argv: list[str] | None = None) -> None:
    _main(argv, llm_class=LocalLLM)


__all__ = ["JSONRPCServer", "LocalLLM", "main"]
