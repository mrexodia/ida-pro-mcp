import json
import os
import threading
from typing import Any, Optional

from .zeromcp import (
    McpRpcRegistry,
    McpServer,
    McpToolError,
    McpHttpRequestHandler,
    get_current_request_external_base_url,
)

MCP_UNSAFE: set[str] = set()
MCP_EXTENSIONS: dict[str, set[str]] = {}  # group -> set of function names
MCP_SERVER = McpServer("ida-pro-mcp", extensions=MCP_EXTENSIONS)

# ============================================================================
# Output Size Limiting
# ============================================================================

OUTPUT_LIMIT_MAX_CHARS = 50000
OUTPUT_CACHE_MAX_SIZE = 100
_output_cache: dict[str, Any] = {}
_output_cache_lock = threading.Lock()
_download_base_url: str = os.environ.get("IDA_MCP_URL", "http://127.0.0.1:13337")


def set_download_base_url(url: str) -> None:
    global _download_base_url
    _download_base_url = url.rstrip("/")


def get_download_base_url() -> str:
    return get_current_request_external_base_url() or _download_base_url


def get_current_transport_session_id() -> str | None:
    return MCP_SERVER.get_current_transport_session_id()


def _generate_output_id() -> str:
    import uuid

    return str(uuid.uuid4())


OUTPUT_LIMIT_PREVIEW_ITEMS = 10
OUTPUT_LIMIT_PREVIEW_STR_LEN = 1000

_TRUNCATE_MAX_DEPTH = 5


def _truncate_value(value: Any, depth: int = 0) -> Any:
    # Past the recursion cap, keep truncating scalars but stop descending into
    # nested containers so an unbounded subtree can never pass through raw.
    if depth > _TRUNCATE_MAX_DEPTH:
        if isinstance(value, str) and len(value) > OUTPUT_LIMIT_PREVIEW_STR_LEN:
            return value[:OUTPUT_LIMIT_PREVIEW_STR_LEN] + f"... [{len(value)} chars total]"
        if isinstance(value, list):
            return f"[... {len(value)} items, depth-truncated]"
        if isinstance(value, dict):
            return f"{{... {len(value)} keys, depth-truncated}}"
        return value

    if isinstance(value, str) and len(value) > OUTPUT_LIMIT_PREVIEW_STR_LEN:
        return value[:OUTPUT_LIMIT_PREVIEW_STR_LEN] + f"... [{len(value)} chars total]"

    if isinstance(value, list):
        # IMPORTANT: Do not inject sentinel objects like {"_truncated": "..."} into lists.
        # Many tool schemas constrain list item shapes (additionalProperties: false),
        # so sentinels can break structured output validation. Truncation is reported
        # via _meta.ida_mcp and the download_hint content.
        return [
            _truncate_value(item, depth + 1)
            for item in value[:OUTPUT_LIMIT_PREVIEW_ITEMS]
        ]

    if isinstance(value, dict):
        return {k: _truncate_value(v, depth + 1) for k, v in value.items()}

    return value


def _build_download_meta(output_id: str, total_chars: int) -> dict:
    download_url = f"{get_download_base_url()}/output/{output_id}.json"
    return {
        "output_truncated": True,
        "total_chars": total_chars,
        "output_id": output_id,
        "download_url": download_url,
        "download_hint": f"Output truncated. Run: curl -o .ida-mcp/{output_id}.json {download_url}",
    }


def get_cached_output(output_id: str) -> Optional[Any]:
    with _output_cache_lock:
        return _output_cache.get(output_id)


def _cache_output(output_id: str, data: Any) -> None:
    with _output_cache_lock:
        if len(_output_cache) >= OUTPUT_CACHE_MAX_SIZE:
            oldest_key = next(iter(_output_cache))
            del _output_cache[oldest_key]
        _output_cache[output_id] = data


def _install_tools_call_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]

    def patched(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        response = original(name, arguments, _meta)

        if response.get("isError"):
            return response

        structured = response.get("structuredContent")
        if structured is None:
            return response

        serialized = json.dumps(structured)
        if len(serialized) <= OUTPUT_LIMIT_MAX_CHARS:
            return response

        output_id = _generate_output_id()
        _cache_output(output_id, structured)

        preview = _truncate_value(structured)
        download_meta = _build_download_meta(output_id, len(serialized))

        content = [{
            "type": "text",
            "text": json.dumps(preview, separators=(",", ":")),
        }, {
            "type": "text",
            "text": download_meta["download_hint"],
        }]

        return {
            "structuredContent": preview,
            "content": content,
            "isError": False,
            "_meta": {"ida_mcp": download_meta},
        }

    MCP_SERVER.registry.methods["tools/call"] = patched


# Install the output limiting patch
_install_tools_call_patch()


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri, *, mime="application/json"):
    return MCP_SERVER.resource(uri, mime=mime)


def prompt(func):
    return MCP_SERVER.prompt(func)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


_SAFETY_ANNOTATIONS: dict[str, dict[str, bool]] = {
    "READ": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "WRITE": {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "DESTRUCTIVE": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    "EXECUTE": {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
}

_SAFETY_UNSAFE_LEVELS = {"DESTRUCTIVE", "EXECUTE"}


def title(text: str):
    """Attach a human-friendly MCP tool title (toolDef.title)."""

    def decorator(func):
        func.__mcp_title__ = text
        return func

    return decorator


def safety(level: str):
    """Classify a tool's safety and emit MCP toolAnnotations.

    level in {"READ","WRITE","DESTRUCTIVE","EXECUTE"}. Sets
    func.__mcp_annotations__ with readOnlyHint/destructiveHint/idempotentHint/
    openWorldHint. For DESTRUCTIVE and EXECUTE this ALSO registers the tool into
    MCP_UNSAFE (so @safety subsumes @unsafe for those levels). @unsafe keeps
    working as-is for back-compat.
    """
    if level not in _SAFETY_ANNOTATIONS:
        raise ValueError(
            f"Unknown safety level {level!r}; expected one of {sorted(_SAFETY_ANNOTATIONS)}"
        )

    def decorator(func):
        func.__mcp_annotations__ = dict(_SAFETY_ANNOTATIONS[level])
        if level in _SAFETY_UNSAFE_LEVELS:
            MCP_UNSAFE.add(func.__name__)
        return func

    return decorator


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.

    The group string is arbitrary: MCP_EXTENSIONS is populated lazily here and the
    server resolves any group generically (_parse_extensions / _get_tool_extension),
    so any @ext("name") exposes those tools under ?ext=name with no extra wiring.
    This server ships a single group, "dbg" (debugger + the probe/watch toolkit).
    """

    def decorator(func):
        if group not in MCP_EXTENSIONS:
            MCP_EXTENSIONS[group] = set()
        MCP_EXTENSIONS[group].add(func.__name__)
        return func

    return decorator


__all__ = [
    "McpRpcRegistry",
    "McpServer",
    "McpToolError",
    "McpHttpRequestHandler",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "MCP_EXTENSIONS",
    "tool",
    "unsafe",
    "safety",
    "title",
    "ext",
    "resource",
    "prompt",
    "get_cached_output",
    "set_download_base_url",
    "get_download_base_url",
    "get_current_transport_session_id",
]
