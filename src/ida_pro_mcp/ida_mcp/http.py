import html
import json
import logging
import re
import threading
import ida_netnode
from urllib.parse import urlparse, parse_qs
from typing import TypeVar, cast
from http.server import HTTPServer

from .profile import dump_profile, parse_profile
from .sync import idasync
from .rpc import (
    McpRpcRegistry,
    McpHttpRequestHandler,
    MCP_SERVER,
    MCP_UNSAFE,
    get_cached_output,
)


logger = logging.getLogger(__name__)

T = TypeVar("T")


@idasync
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        logger.warning(
            "Invalid JSON stored in netnode %r: %r from netnode: %s",
            key,
            json_blob,
            e,
        )
        return default


@idasync
def config_json_set(key: str, value) -> bool:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    res = node.setblob(json_blob, 0, "C")
    return True if res is None else bool(res)


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Changed to registry to enable configured tools, returns original tools."""
    original_tools = registry.methods.copy()
    enabled_tools = config_json_get(
        config_key, {name: True for name in original_tools.keys()}
    )
    original_enabled_tools = enabled_tools.copy()
    new_tools = [name for name in original_tools if name not in enabled_tools]

    removed_tools = [name for name in enabled_tools if name not in original_tools]
    if removed_tools:
        for name in removed_tools:
            enabled_tools.pop(name)

    if new_tools:
        enabled_tools.update({name: True for name in new_tools})

    if enabled_tools != original_enabled_tools:
        config_json_set(config_key, enabled_tools)

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


DEFAULT_CORS_POLICY = "local"


def get_cors_policy(port: int) -> str:
    """Retrieve the current CORS policy from configuration."""
    match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
        case "unrestricted":
            return "*"
        case "local":
            return "127.0.0.1 localhost"
        case "direct":
            return f"http://127.0.0.1:{port} http://localhost:{port}"
        case _:
            return "*"


ORIGINAL_TOOLS = handle_enabled_tools(MCP_SERVER.tools, "enabled_tools")

_cors_policy_lock = threading.Lock()
_cached_cors_policy: str | None = None
_cors_policy_generation: int = 0
_cors_idb_hook = None
_cors_idp_hook = None


def invalidate_cors_policy_cache() -> None:
    """Drop cached CORS policy (call whenever the active IDB changes or closes)."""
    global _cached_cors_policy, _cors_policy_generation
    with _cors_policy_lock:
        _cors_policy_generation += 1
        _cached_cors_policy = None
        MCP_SERVER.cors_allowed_origins = MCP_SERVER.cors_localhost
        MCP_SERVER._cors_policy_gen = None


def refresh_cors_policy_on_main_thread() -> None:
    """Refresh and publish active IDB's CORS policy while already on IDA main thread."""
    read_fn = getattr(config_json_get, "__wrapped__", config_json_get)
    policy = read_fn("cors_policy", DEFAULT_CORS_POLICY)
    _publish_cors_policy(MCP_SERVER, policy)


def _install_cors_idb_hook() -> None:
    """Install IDB/IDP lifecycle hooks so open/close/switch updates CORS cache."""
    global _cors_idb_hook, _cors_idp_hook
    try:
        import ida_idp
    except Exception:
        return

    if _cors_idb_hook is None and hasattr(ida_idp, "IDB_Hooks"):
        class _CorsIdbHook(ida_idp.IDB_Hooks):
            def closebase(self, *args):
                invalidate_cors_policy_cache()
                return 0

        idb_hook = _CorsIdbHook()
        if idb_hook.hook():
            _cors_idb_hook = idb_hook

    if _cors_idp_hook is None and hasattr(ida_idp, "IDP_Hooks"):
        class _CorsIdpHook(ida_idp.IDP_Hooks):
            def ev_newfile(self, *args):
                refresh_cors_policy_on_main_thread()
                return 0

            def ev_oldfile(self, *args):
                refresh_cors_policy_on_main_thread()
                return 0

        idp_hook = _CorsIdpHook()
        if idp_hook.hook():
            _cors_idp_hook = idp_hook


_install_cors_idb_hook()


def _apply_cors_policy_to_server(mcp_server, policy: str) -> None:
    match policy:
        case "unrestricted":
            mcp_server.cors_allowed_origins = "*"
        case "local":
            mcp_server.cors_allowed_origins = mcp_server.cors_localhost
        case "direct":
            mcp_server.cors_allowed_origins = None


def _publish_cors_policy(mcp_server, cors_policy: str) -> None:
    """Atomically cache and publish a newly configured CORS policy."""
    global _cached_cors_policy, _cors_policy_generation
    with _cors_policy_lock:
        _cors_policy_generation += 1
        _cached_cors_policy = cors_policy
        _apply_cors_policy_to_server(mcp_server, cors_policy)
        mcp_server._cors_policy_gen = _cors_policy_generation


@idasync
def _save_and_publish_cors_policy(mcp_server, cors_policy: str) -> bool:
    """Persist CORS policy to active IDB and publish on success on IDA main thread."""
    save_fn = getattr(config_json_set, "__wrapped__", config_json_set)
    if save_fn("cors_policy", cors_policy) is False:
        return False
    _publish_cors_policy(mcp_server, cors_policy)
    return True


def _sync_cors_policy(mcp_server, refresh: bool = False) -> None:
    """Ensure mcp_server reflects the active IDB's CORS policy without racing updates."""
    global _cached_cors_policy, _cors_policy_generation
    for _ in range(8):
        with _cors_policy_lock:
            if not refresh and _cached_cors_policy is not None:
                if (
                    getattr(mcp_server, "_cors_policy_gen", None)
                    != _cors_policy_generation
                ):
                    _apply_cors_policy_to_server(mcp_server, _cached_cors_policy)
                    mcp_server._cors_policy_gen = _cors_policy_generation
                return
            gen = _cors_policy_generation

        fetched = config_json_get("cors_policy", DEFAULT_CORS_POLICY)
        with _cors_policy_lock:
            if _cors_policy_generation == gen:
                _cached_cors_policy = fetched
                _cors_policy_generation += 1
                _apply_cors_policy_to_server(mcp_server, fetched)
                mcp_server._cors_policy_gen = _cors_policy_generation
                return
            if _cached_cors_policy is not None:
                _apply_cors_policy_to_server(mcp_server, _cached_cors_policy)
                mcp_server._cors_policy_gen = _cors_policy_generation
                return
            # Another IDB transition invalidated the cache mid-read; retry with current gen.

    raise RuntimeError("Failed to load current CORS policy across concurrent IDB switches")


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def _check_api_request(self) -> bool:
        if self.headers.get("Origin") and (
            _cached_cors_policy is None
            or getattr(self.mcp_server, "_cors_policy_gen", None)
            != _cors_policy_generation
        ):
            from .mainthread import get_pump

            if _cached_cors_policy is None and get_pump().busy_status() is not None:
                self.send_error(503, "Database busy; retry once IDB open completes")
                return False
            self.update_cors_policy()
        return super()._check_api_request()

    def update_cors_policy(self, refresh: bool = False):
        _sync_cors_policy(self.mcp_server, refresh=refresh)

    def do_POST(self):
        """Handles POST requests."""
        if urlparse(self.path).path == "/config":
            if not self._check_origin():
                return
            self._handle_config_post()
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/config.html":
            if not self._check_host():
                return
            self._handle_config_get()
            return

        if path == "/profile.txt":
            if not self._check_host():
                return
            self._handle_profile_export()
            return

        # Handle output download requests
        output_match = re.match(r"^/output/([a-f0-9-]+)\.(\w+)$", path)
        if output_match:
            if not self._check_api_request():
                return
            self._handle_output_download(output_match.group(1), output_match.group(2))
            return

        super().do_GET()

    def _handle_profile_export(self):
        """Return the currently enabled tools as a profile file."""
        enabled = sorted(self.mcp_server.tools.methods.keys())
        body = dump_profile(
            enabled,
            header="ida-pro-mcp profile exported from /config.html",
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", 'attachment; filename="ida-mcp-profile.txt"'
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_output_download(self, output_id: str, extension: str):
        """Handle download of cached output data."""
        data = get_cached_output(output_id)
        if data is None:
            self.send_error(404, "Output not found or expired")
            return

        if extension == "json":
            content = json.dumps(data, indent=2)
        elif isinstance(data, dict) and "code" in data:
            content = str(data["code"])
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            content = "\n\n".join(
                str(item.get("code", item.get("asm", item.get("lines", ""))))
                for item in data
            )
        else:
            content = json.dumps(data, indent=2)

        body = content.encode("utf-8")
        self.send_response(200)
        content_type = "application/json" if extension == "json" else "text/plain"
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{output_id}.{extension}"'
        )
        self.end_headers()
        self.wfile.write(body)

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    def _check_origin(self) -> bool:
        """Validate Origin for config POST requests.

        Delegates to the zeromcp ``_check_api_request`` which already
        handles non-loopback bindings (LAN) and respects the configured
        CORS policy.  When the server is bound to 0.0.0.0 the Host
        check passes for any client; the Origin check still enforces
        the CORS policy so ``unrestricted`` is needed for browser-based
        LAN config access.
        """
        return self._check_api_request()

    def _check_host(self) -> bool:
        """Validate Host header for config page access.

        Delegates to ``_check_api_request`` so the same rules apply as
        for MCP API calls: loopback-bound servers only accept loopback
        Host headers; non-loopback servers (0.0.0.0) accept any Host.
        """
        return self._check_api_request()

    def _send_html(self, status: int, text: str):
        """
        Prevents clickjacking by blocking iframes (X-Frame-Options for older
        browsers, frame-ancestors for modern ones). Other CSP directives
        provide defense-in-depth against content injection attacks.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "; ".join(
                [
                    "frame-ancestors 'none'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "default-src 'self'",
                    "form-action 'self'",
                ]
            ),
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        cors_policy = config_json_get("cors_policy", DEFAULT_CORS_POLICY)

        body = """<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP Config</title>
  <style>
:root {
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 800px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.4;
}

h1 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

h2 {
  font-size: 1.1rem;
  margin-top: 1.5rem;
  margin-bottom: 0.5rem;
}

label {
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}

label:hover {
  background: var(--hover);
}

input[type="checkbox"],
input[type="radio"] {
  margin-right: 0.5rem;
  accent-color: var(--accent);
}

input[type="submit"] {
  margin-top: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

input[type="submit"]:hover {
  opacity: 0.9;
}

.tooltip {
  border-bottom: 1px dotted var(--text);
}
  </style>
  <script defer>
  function setTools(mode) {
    document.querySelectorAll('input[data-tool]').forEach(cb => {
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    });
  }
  </script>
</head>
<body>
<h1>IDA Pro MCP Config</h1>

<form method="post" action="/config">

<h2>API Access</h2>
"""
        cors_options = [
            (
                "unrestricted",
                "⛔ Unrestricted",
                "Any website can make requests to this server. A malicious site you visit could access or modify your IDA database.",
            ),
            (
                "local",
                "🏠 Local apps only",
                "Only web apps running on localhost can connect. Remote websites are blocked, but local development tools work.",
            ),
            (
                "direct",
                "🔒 Direct connections only",
                "Browser-based requests are blocked. Only direct clients like curl, MCP tools, or Claude Desktop can connect.",
            ),
        ]
        for value, label, tooltip in cors_options:
            checked = "checked" if cors_policy == value else ""
            body += f'<label><input type="radio" name="cors_policy" value="{html.escape(value)}" {checked}><span class="tooltip" title="{html.escape(tooltip)}">{html.escape(label)}</span></label>'
        body += "<br><input type='submit' value='Save'>"

        quick_select = """<p style="font-size: 0.9rem; margin: 0.5rem 0;">
  Select:
  <a href="#" onclick="setTools('all'); return false;">All</a> ·
  <a href="#" onclick="setTools('none'); return false;">None</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">Disable unsafe</a>
</p>"""

        body += "<h2>Enabled Tools</h2>"
        body += (
            '<p style="font-size: 0.9rem; margin: 0.5rem 0;">'
            '<a href="/profile.txt" download>Export as --profile file</a>'
            "</p>"
        )
        body += quick_select
        for name, func in ORIGINAL_TOOLS.items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe_prefix = "⚠️ " if name in MCP_UNSAFE else ""
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}'{checked}{unsafe_attr} data-tool>{unsafe_prefix}{html.escape(name)}: {html.escape(description)}</label>"
        body += quick_select
        body += "<br><input type='submit' value='Save'>"

        body += "<h2>Import Profile</h2>"
        body += (
            "<p style='font-size: 0.9rem; margin: 0.5rem 0;'>"
            "Paste profile contents (one tool name per line, <code>#</code> for comments) "
            "to replace the current Enabled Tools selection."
            "</p>"
        )
        body += (
            "<textarea name='profile_text' rows='6' "
            "style='width:100%;font-family:monospace;' "
            "placeholder='# paste profile here'></textarea>"
        )
        body += "<br><input type='submit' name='apply_profile' value='Apply profile'>"
        body += "</form></body></html>"
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Validate Content-Type
        content_type = self.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(400, f"Unsupported Content-Type: {content_type}")
            return

        body = self._read_body()
        if body is None:
            return
        try:
            postvars = parse_qs(body.decode("utf-8"))
        except UnicodeDecodeError:
            self.send_error(400, "Invalid form encoding")
            return

        # Update CORS policy (save + publish together on the IDA main thread)
        cors_policy = postvars.get("cors_policy", [DEFAULT_CORS_POLICY])[0]
        if not _save_and_publish_cors_policy(self.mcp_server, cors_policy):
            self.send_error(500, "Failed to save CORS policy")
            return

        # Update the server's tools
        if "apply_profile" in postvars:
            whitelist = parse_profile(postvars.get("profile_text", [""])[0])
            enabled_tools = {name: name in whitelist for name in ORIGINAL_TOOLS.keys()}
        else:
            enabled_tools = {name: name in postvars for name in ORIGINAL_TOOLS.keys()}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in ORIGINAL_TOOLS.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)

        # Redirect back to the config page. No body follows, but under
        # keep-alive that must be signalled explicitly (Content-Length: 0) -
        # under the prior HTTP/1.0-only behavior the connection just closed,
        # which made this ambiguous framing harmless.
        self.send_response(302)
        self.send_header("Location", "/config.html")
        self.send_header("Content-Length", "0")
        self.end_headers()
