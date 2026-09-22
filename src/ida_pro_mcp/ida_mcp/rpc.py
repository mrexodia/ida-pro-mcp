import json
import os
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
_DOWNLOAD_BASE_URL_DEFAULT = "http://127.0.0.1:13337"


def configured_download_base_url() -> Optional[str]:
    """The public base URL the operator configured (#383), None if unset.

    The other IDA_MCP_* knobs (idalib_supervisor._env_float/_env_int,
    zeromcp._parse_bool_env) already treat a blank value as unset; so does the
    download base url here, otherwise a blank IDA_MCP_URL degrades the
    truncated-output hint to a bare "/output/<id>.json" path.
    """
    return os.environ.get("IDA_MCP_URL", "").strip() or None


_download_base_url: str = configured_download_base_url() or _DOWNLOAD_BASE_URL_DEFAULT


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
OUTPUT_LIMIT_PREVIEW_STR_LEN = 4000
OUTPUT_LIMIT_PREVIEW_MAX_CHARS = 40000


def _truncate_value_with_limits(
    value: Any, depth: int, string_limit: int, item_limit: int
) -> Any:
    if isinstance(value, str) and len(value) > string_limit:
        if string_limit == 0:
            return ""
        return value[:string_limit] + f"... [{len(value)} chars total]"

    if isinstance(value, list):
        # IMPORTANT: Do not inject sentinel objects like {"_truncated": "..."} into lists.
        # Many tool schemas constrain list item shapes (additionalProperties: false),
        # so sentinels can break structured output validation. Truncation is reported
        # via _meta.ida_mcp and the download_hint content.
        return [
            _truncate_value_with_limits(item, depth + 1, string_limit, item_limit)
            for item in value[:item_limit]
        ]

    if isinstance(value, dict):
        return {
            k: _truncate_value_with_limits(v, depth + 1, string_limit, item_limit)
            for k, v in value.items()
        }

    return value


def _truncate_value(value: Any, depth: int = 0) -> Any:
    """Build a schema-preserving preview bounded across the whole value."""
    limits = (
        (OUTPUT_LIMIT_PREVIEW_STR_LEN, OUTPUT_LIMIT_PREVIEW_ITEMS),
        (2000, 10),
        (1000, 10),
        (1000, 5),
        (500, 5),
        (500, 2),
        (200, 2),
        (200, 1),
        (100, 1),
        (50, 1),
        (0, 0),
    )
    preview: Any = value
    for string_limit, item_limit in limits:
        preview = _truncate_value_with_limits(
            value, depth, string_limit, item_limit
        )
        if len(json.dumps(preview)) <= OUTPUT_LIMIT_PREVIEW_MAX_CHARS:
            break
    return preview


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
    return _output_cache.get(output_id)


def _cache_output(output_id: str, data: Any) -> None:
    if len(_output_cache) >= OUTPUT_CACHE_MAX_SIZE:
        oldest_key = next(iter(_output_cache))
        del _output_cache[oldest_key]
    _output_cache[output_id] = data


def _limit_output_response(response: dict) -> dict:
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


def _install_tools_call_patch() -> None:
    original = MCP_SERVER.registry.methods["tools/call"]

    def patched(
        name: str, arguments: Optional[dict] = None, _meta: Optional[dict] = None
    ) -> dict:
        response = original(name, arguments, _meta)
        return _limit_output_response(response)

    MCP_SERVER.registry.methods["tools/call"] = patched


# Install the output limiting patch
_install_tools_call_patch()


# ============================================================================
# Decorators
# ============================================================================


def tool(func):
    return MCP_SERVER.tool(func)


def resource(uri):
    return MCP_SERVER.resource(uri)


def unsafe(func):
    MCP_UNSAFE.add(func.__name__)
    return func


def ext(group: str):
    """Mark a tool as belonging to an extension group.

    Tools in extension groups are hidden by default. Enable via ?ext=group query param.
    Example: @ext("dbg") marks debugger tools that require ?ext=dbg to be visible.
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
    "ext",
    "resource",
    "get_cached_output",
    "set_download_base_url",
    "get_download_base_url",
    "get_current_transport_session_id",
]
