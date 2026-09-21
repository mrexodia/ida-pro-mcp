"""Generated client URLs must keep the brackets an IPv6 authority requires.

Discovery maps a wildcard IPv6 bind to "::1" (tests/test_discovery_wildcard_host.py)
and server._resolve_ida_rpc copies that value into installer.IDA_HOST, but
urlparse() strips the brackets from a URL host, so re-joining host and port with
":" produces an authority that no client can parse: http://::1:13337/mcp.
"""

import unittest
from unittest.mock import patch
from urllib.parse import urlparse

from ida_pro_mcp import installer
from ida_pro_mcp.installer import (
    force_mcp_path,
    generate_mcp_config,
    normalize_transport_url,
)


def _ida_rpc(host: str, port: int):
    return patch.multiple(installer, IDA_HOST=host, IDA_PORT=port)


class NormalizeTransportUrlTests(unittest.TestCase):
    def test_ipv6_authority_keeps_its_brackets(self):
        self.assertEqual(
            normalize_transport_url("http://[::1]:13337/mcp"),
            "http://[::1]:13337/mcp",
        )
        self.assertEqual(
            normalize_transport_url("http://[2001:db8::10]:8744/sse"),
            "http://[2001:db8::10]:8744/sse",
        )

    def test_generated_url_can_be_parsed_again(self):
        parsed = urlparse(normalize_transport_url("http://[::1]:13337/mcp"))
        self.assertEqual(parsed.hostname, "::1")
        self.assertEqual(parsed.port, 13337)

    def test_ipv4_and_named_hosts_are_unchanged(self):
        for host in ("127.0.0.1", "localhost", "ida.internal"):
            self.assertEqual(
                normalize_transport_url(f"http://{host}:13337/sse"),
                f"http://{host}:13337/sse",
            )


class ForceMcpPathTests(unittest.TestCase):
    def test_ipv6_authority_survives_the_path_rewrite(self):
        self.assertEqual(
            force_mcp_path("http://[::1]:13337/sse"),
            "http://[::1]:13337/mcp",
        )


class GeneratedConfigTests(unittest.TestCase):
    def test_every_http_client_gets_a_bracketed_ipv6_host(self):
        with _ida_rpc("::1", 13337):
            self.assertEqual(
                generate_mcp_config(client_name="Generic", transport="streamable-http"),
                {"type": "http", "url": "http://[::1]:13337/mcp"},
            )
            self.assertEqual(
                generate_mcp_config(client_name="Claude", transport="sse"),
                {"type": "sse", "url": "http://[::1]:13337/sse"},
            )
            self.assertEqual(
                generate_mcp_config(client_name="Codex", transport="streamable-http"),
                {"url": "http://[::1]:13337/mcp"},
            )
            self.assertEqual(
                generate_mcp_config(
                    client_name="Opencode", transport="streamable-http"
                ),
                {"type": "remote", "url": "http://[::1]:13337/mcp"},
            )

    def test_ipv4_host_still_generates_a_plain_url(self):
        with _ida_rpc("127.0.0.1", 13337):
            self.assertEqual(
                generate_mcp_config(client_name="Generic", transport="streamable-http"),
                {"type": "http", "url": "http://127.0.0.1:13337/mcp"},
            )


if __name__ == "__main__":
    unittest.main()
