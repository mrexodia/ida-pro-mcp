"""End-to-end MCP mode for the test framework.

When enabled, every @tool-decorated function is monkeypatched to route
through a real MCP client/server HTTP round-trip and the response is
validated against its advertised outputSchema. Lets the existing test
suite double as a runtime-conformance check without rewriting anything.
"""

import asyncio
import inspect
import socket
import sys
import threading
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Iterator

from jsonschema import Draft202012Validator

from ..rpc import MCP_SERVER


class _AsyncHarness:
    """Event loop on a background thread; sync callers schedule coros."""

    def __init__(self):
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self):
        def loop_target():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self._ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=loop_target, daemon=True)
        self.thread.start()
        self._ready.wait()

    def stop(self):
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread is not None:
            self.thread.join(timeout=2)

    def run(self, coro, timeout: float = 20.0):
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout=timeout)


class _McpMode:
    def __init__(self):
        self.harness = _AsyncHarness()
        self.host = "127.0.0.1"
        self.port: int | None = None
        self.session = None
        self._http_ctx = None
        self._session_ctx = None
        self.output_schemas: dict[str, dict] = {}
        self._patched: list[tuple[Any, str, Callable]] = []

    def enable(self):
        self.driver_thread_id = threading.get_ident()
        self.harness.start()
        self.port = _pick_free_port(self.host)
        MCP_SERVER.serve(self.host, self.port, background=True)
        _wait_until_ready(f"http://{self.host}:{self.port}/mcp")
        self.harness.run(self._connect())
        self._patch_tools()

    def disable(self):
        self._unpatch_tools()
        try:
            self.harness.run(self._disconnect())
        except Exception:
            pass
        try:
            MCP_SERVER.stop()
        except Exception:
            pass
        self.harness.stop()

    async def _connect(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        self._http_ctx = streamablehttp_client(f"http://{self.host}:{self.port}/mcp")
        read, write, _ = await self._http_ctx.__aenter__()
        self._session_ctx = ClientSession(read, write)
        self.session = await self._session_ctx.__aenter__()
        await self.session.initialize()
        tools = await self.session.list_tools()
        for t in tools.tools:
            if getattr(t, "outputSchema", None):
                self.output_schemas[t.name] = t.outputSchema

    async def _disconnect(self):
        if self._session_ctx is not None:
            await self._session_ctx.__aexit__(None, None, None)
        if self._http_ctx is not None:
            await self._http_ctx.__aexit__(None, None, None)

    def _patch_tools(self):
        for name, original in MCP_SERVER.tools.methods.items():
            mod = sys.modules.get(original.__module__)
            if mod is None:
                continue
            if getattr(mod, name, None) is not original:
                continue
            proxy = self._make_proxy(name, original)
            self._patched.append((mod, name, original))
            setattr(mod, name, proxy)

    def _unpatch_tools(self):
        for mod, name, original in self._patched:
            setattr(mod, name, original)
        self._patched.clear()

    def _make_proxy(self, name: str, original: Callable) -> Callable:
        sig = inspect.signature(original)
        schema = self.output_schemas.get(name)
        harness = self.harness
        state = self

        @wraps(original)
        def proxy(*args, **kwargs):
            # Only route through MCP for calls originating on the test-driver
            # thread. Nested tool calls run on the server's HTTP handler thread
            # and must execute directly, otherwise we'd re-enter the event
            # loop the outer call is blocking on.
            if threading.get_ident() != state.driver_thread_id:
                return original(*args, **kwargs)

            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)

            async def _call():
                return await state.session.call_tool(name, arguments=arguments)

            result = harness.run(_call())

            if getattr(result, "isError", False):
                msg = ""
                if result.content:
                    msg = getattr(result.content[0], "text", str(result.content[0]))
                raise RuntimeError(f"MCP tool {name!r} returned isError: {msg}")

            structured = getattr(result, "structuredContent", None)
            if schema is not None and structured is not None:
                Draft202012Validator(schema).validate(structured)

            if (
                isinstance(structured, dict)
                and set(structured.keys()) == {"result"}
            ):
                return structured["result"]
            return structured

        return proxy


_instance: _McpMode | None = None


def enable_mcp_mode() -> None:
    global _instance
    assert _instance is None, "MCP mode already enabled"
    _instance = _McpMode()
    _instance.enable()


def disable_mcp_mode() -> None:
    global _instance
    if _instance is not None:
        _instance.disable()
        _instance = None


@contextmanager
def mcp_mode() -> Iterator[None]:
    enable_mcp_mode()
    try:
        yield
    finally:
        disable_mcp_mode()


def _pick_free_port(host: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until_ready(url: str, timeout: float = 2.0) -> None:
    import time
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="OPTIONS")
            with urllib.request.urlopen(req, timeout=0.2):
                return
        except urllib.error.HTTPError:
            return
        except (urllib.error.URLError, ConnectionRefusedError, socket.timeout):
            time.sleep(0.02)
    raise RuntimeError(f"server at {url} not ready within {timeout}s")
