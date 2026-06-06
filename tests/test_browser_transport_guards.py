import pathlib
import sys
import unittest
import http.server  # Preload stdlib http before adding local ida_mcp paths.


_ZEROMCP_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
sys.path.insert(0, str(_ZEROMCP_SRC))
try:
    from zeromcp.mcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        _derive_external_base_url,
        _host_header_allowed_for_bind,
        _origin_allowed_by_policy,
    )
finally:
    sys.path.remove(str(_ZEROMCP_SRC))


class _DummyHandler(McpHttpRequestHandler):
    def __init__(self):
        pass


def _make_handler(
    *,
    host: str | None,
    origin: str | None,
    bound_host: str = "127.0.0.1",
    allowed=None,
):
    mcp_server = McpServer("test")
    if allowed is not None:
        mcp_server.cors_allowed_origins = allowed

    server = type(
        "_FakeServer",
        (),
        {
            "server_address": (bound_host, 13337),
            "server_port": 13337,
            "mcp_server": mcp_server,
        },
    )()
    handler = _DummyHandler.__new__(_DummyHandler)
    handler.server = server
    handler.mcp_server = mcp_server
    headers = {}
    if host is not None:
        headers["Host"] = host
    if origin is not None:
        headers["Origin"] = origin
    handler.headers = headers
    errors = []
    handler.send_error = lambda code, message=None, explain=None: errors.append(
        (code, message)
    )
    return handler, errors


class BrowserTransportGuardTests(unittest.TestCase):
    def test_loopback_host_helper_rejects_rebinding_domain(self):
        self.assertFalse(
            _host_header_allowed_for_bind("127.0.0.1", "evil.example:13337")
        )
        self.assertTrue(
            _host_header_allowed_for_bind("127.0.0.1", "localhost:13337")
        )
        self.assertTrue(
            _host_header_allowed_for_bind("127.0.0.1", "127.0.0.1:13337")
        )
        self.assertTrue(_host_header_allowed_for_bind("::1", "[::1]:13337"))

    def test_origin_policy_helper_matches_cors_behavior(self):
        self.assertTrue(
            _origin_allowed_by_policy(
                ["http://127.0.0.1:3000"], "http://127.0.0.1:3000"
            )
        )
        self.assertFalse(
            _origin_allowed_by_policy(None, "http://127.0.0.1:3000")
        )

    def test_check_api_request_rejects_rebinding_host(self):
        handler, errors = _make_handler(
            host="evil.example:13337",
            origin="http://evil.example:13337",
        )
        self.assertFalse(handler._check_api_request())
        self.assertEqual(errors, [(403, "Invalid Host")])

    def test_check_api_request_rejects_browser_origin_in_direct_mode(self):
        handler, errors = _make_handler(
            host="127.0.0.1:13337",
            origin="http://127.0.0.1:3000",
            allowed=None,
        )
        handler.mcp_server.cors_allowed_origins = None
        self.assertFalse(handler._check_api_request())
        self.assertEqual(errors, [(403, "Invalid Origin")])

    def test_check_api_request_allows_direct_clients_without_origin(self):
        handler, errors = _make_handler(
            host="127.0.0.1:13337",
            origin=None,
        )
        handler.mcp_server.cors_allowed_origins = None
        self.assertTrue(handler._check_api_request())
        self.assertEqual(errors, [])

    def test_check_api_request_allows_local_browser_origin(self):
        handler, errors = _make_handler(
            host="localhost:13337",
            origin="http://127.0.0.1:3000",
        )
        self.assertTrue(handler._check_api_request())
        self.assertEqual(errors, [])

    # -- LAN connectivity tests (bound to 0.0.0.0) --

    def test_nonloopback_bind_allows_lan_host(self):
        self.assertTrue(
            _host_header_allowed_for_bind("0.0.0.0", "192.168.1.10:13337")
        )
        self.assertTrue(
            _host_header_allowed_for_bind("0.0.0.0", "10.0.0.5:13337")
        )

    def test_check_api_request_allows_lan_client_without_origin(self):
        handler, errors = _make_handler(
            host="192.168.1.10:13337",
            origin=None,
            bound_host="0.0.0.0",
        )
        self.assertTrue(handler._check_api_request())
        self.assertEqual(errors, [])

    def test_check_api_request_allows_lan_origin_with_wildcard_cors(self):
        handler, errors = _make_handler(
            host="192.168.1.10:13337",
            origin="http://192.168.1.20:3000",
            bound_host="0.0.0.0",
            allowed="*",
        )
        self.assertTrue(handler._check_api_request())
        self.assertEqual(errors, [])

    def test_check_api_request_rejects_lan_origin_with_local_cors(self):
        handler, errors = _make_handler(
            host="192.168.1.10:13337",
            origin="http://192.168.1.20:3000",
            bound_host="0.0.0.0",
        )
        self.assertFalse(handler._check_api_request())
        self.assertEqual(errors, [(403, "Invalid Origin")])

    def test_derive_external_base_url_prefers_forwarded_headers(self):
        base = _derive_external_base_url(
            {
                "Host": "127.0.0.1:13337",
                "Forwarded": 'for=127.0.0.1;proto=https;host="mcp.example.com"',
            },
            bound_host="127.0.0.1",
            bound_port=13337,
        )
        self.assertEqual(base, "https://mcp.example.com")

    def test_derive_external_base_url_supports_forwarded_prefix(self):
        base = _derive_external_base_url(
            {
                "Host": "127.0.0.1:13337",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "mcp.example.com",
                "X-Forwarded-Prefix": "/ida/proxy/",
            },
            bound_host="127.0.0.1",
            bound_port=13337,
        )
        self.assertEqual(base, "https://mcp.example.com/ida/proxy")

    def test_derive_external_base_url_prefers_propagated_header(self):
        base = _derive_external_base_url(
            {
                "Host": "127.0.0.1:13337",
                EXTERNAL_BASE_HEADER: "https://public.example/base/",
                "X-Forwarded-Proto": "http",
                "X-Forwarded-Host": "ignored.example",
            },
            bound_host="127.0.0.1",
            bound_port=13337,
        )
        self.assertEqual(base, "https://public.example/base")


if __name__ == "__main__":
    unittest.main()
