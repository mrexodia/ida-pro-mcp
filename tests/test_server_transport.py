import json
import time
import unittest
from unittest.mock import patch

from ida_pro_mcp import server


class _FakeResponse:
    def __init__(self, status=200, reason="OK", body=b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'):
        self.status = status
        self.reason = reason
        self._body = body

    def read(self):
        return self._body


class _BaseFakeConnection:
    instances = []

    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_calls = 0
        self.closed = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def request(self, method, path, body, headers):
        self.request_calls += 1

    def close(self):
        self.closed = True


class _ResponseFailureConnection(_BaseFakeConnection):
    def getresponse(self):
        raise TimeoutError("read timeout")


class _Http503Connection(_BaseFakeConnection):
    def getresponse(self):
        return _FakeResponse(status=503, reason="Service Unavailable", body=b"busy")


class _ConnectFailureConnection(_BaseFakeConnection):
    def request(self, method, path, body, headers):
        super().request(method, path, body, headers)
        raise ConnectionRefusedError("refused")


class DispatchProxyTransportTests(unittest.TestCase):
    def setUp(self):
        _ResponseFailureConnection.reset()
        _Http503Connection.reset()
        _ConnectFailureConnection.reset()
        self._old_host = server.IDA_HOST
        self._old_port = server.IDA_PORT
        self._old_session = getattr(server.mcp._transport_session_id, "data", None)
        self._old_targets = server._session_proxy_targets.copy()
        self._old_target_last_seen = server._session_proxy_last_seen.copy()
        self._old_target_ttl = server.SESSION_PROXY_TARGET_TTL_SEC
        self._old_target_max = server.SESSION_PROXY_TARGET_MAX_SIZE

    def tearDown(self):
        server.IDA_HOST = self._old_host
        server.IDA_PORT = self._old_port
        server._session_proxy_targets.clear()
        server._session_proxy_targets.update(self._old_targets)
        server._session_proxy_last_seen.clear()
        server._session_proxy_last_seen.update(self._old_target_last_seen)
        server.SESSION_PROXY_TARGET_TTL_SEC = self._old_target_ttl
        server.SESSION_PROXY_TARGET_MAX_SIZE = self._old_target_max
        server.mcp._transport_session_id.data = self._old_session

    def test_proxy_request_forwards_external_base_header(self):
        original_getter = server.get_current_request_external_base_url

        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.path = path
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.get_current_request_external_base_url = lambda: "https://mcp.example.com/base"
        try:
            with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
                server._proxy_to_instance("127.0.0.1", 13337, b"{}")
        finally:
            server.get_current_request_external_base_url = original_getter

        self.assertEqual(len(_RecordingConnection.instances), 1)
        self.assertEqual(
            _RecordingConnection.instances[0].headers.get("X-IDA-MCP-External-Base"),
            "https://mcp.example.com/base",
        )

    def test_proxy_response_records_output_download_target(self):
        output_id = "12345678-1234-1234-1234-123456789abc"

        class _OutputResponseConnection(_BaseFakeConnection):
            def getresponse(self):
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [],
                            "_meta": {
                                "ida_mcp": {
                                    "output_id": output_id,
                                    "download_url": f"http://example/output/{output_id}.json",
                                }
                            },
                        },
                        "id": 1,
                    }
                ).encode("utf-8")
                return _FakeResponse(body=body)

        _OutputResponseConnection.reset()
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _OutputResponseConnection):
            server._proxy_to_instance("127.0.0.1", 13337, b"{}")

        self.assertEqual(server._get_output_proxy_target(output_id), ("127.0.0.1", 13337))

    def test_select_instance_is_scoped_to_transport_session(self):
        with patch("ida_pro_mcp.server.probe_instance", lambda host, port: True):
            server.mcp._transport_session_id.data = "http:session-a"
            result_a = server.select_instance(port=11111, host="127.0.0.1")
            self.assertTrue(result_a["success"])

            server.mcp._transport_session_id.data = "http:session-b"
            result_b = server.select_instance(port=22222, host="127.0.0.1")
            self.assertTrue(result_b["success"])

            server.mcp._transport_session_id.data = "http:session-a"
            self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 11111))

            server.mcp._transport_session_id.data = "http:session-b"
            self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 22222))

    def test_select_instance_does_not_change_process_default_for_session(self):
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        with patch("ida_pro_mcp.server.probe_instance", lambda host, port: True):
            server.mcp._transport_session_id.data = "http:session-a"
            result = server.select_instance(port=14444, host="127.0.0.1")
            self.assertTrue(result["success"])
            self.assertEqual((server.IDA_HOST, server.IDA_PORT), ("127.0.0.1", 13337))

            server.mcp._transport_session_id.data = "http:session-b"
            self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 13337))

    def test_session_scoped_targets_are_bounded(self):
        server.SESSION_PROXY_TARGET_MAX_SIZE = 2
        server.SESSION_PROXY_TARGET_TTL_SEC = 0
        with patch("ida_pro_mcp.server.probe_instance", lambda host, port: True):
            server.mcp._transport_session_id.data = "http:session-a"
            self.assertTrue(server.select_instance(port=11111, host="127.0.0.1")["success"])
            server.mcp._transport_session_id.data = "http:session-b"
            self.assertTrue(server.select_instance(port=22222, host="127.0.0.1")["success"])
            server.mcp._transport_session_id.data = "http:session-c"
            self.assertTrue(server.select_instance(port=33333, host="127.0.0.1")["success"])

        self.assertNotIn("http:session-a", server._session_proxy_targets)
        self.assertIn("http:session-b", server._session_proxy_targets)
        self.assertIn("http:session-c", server._session_proxy_targets)

    def test_session_scoped_targets_expire(self):
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337
        server.SESSION_PROXY_TARGET_TTL_SEC = 1
        server.mcp._transport_session_id.data = "http:stale"
        server._session_proxy_targets["http:stale"] = ("127.0.0.1", 15555)
        server._session_proxy_last_seen["http:stale"] = time.monotonic() - 10

        self.assertEqual(server._get_active_ida_target(), ("127.0.0.1", 13337))
        self.assertNotIn("http:stale", server._session_proxy_targets)

    def test_proxy_to_ida_uses_session_scoped_target(self):
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.path = path
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.mcp._transport_session_id.data = "http:session-a"
        server._session_proxy_targets["http:session-a"] = ("127.0.0.1", 15555)
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
            server._proxy_to_ida(b"{}")
        self.assertEqual((_RecordingConnection.instances[0].host, _RecordingConnection.instances[0].port), ("127.0.0.1", 15555))

    def test_dispatch_proxy_does_not_retry_post_send_failures(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ResponseFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("not retried automatically", response["error"]["message"])
        self.assertIn("read timeout", response["error"]["data"])
        self.assertEqual(len(_ResponseFailureConnection.instances), 1)
        self.assertEqual(_ResponseFailureConnection.instances[0].request_calls, 1)
        self.assertTrue(_ResponseFailureConnection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_http_503(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _Http503Connection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("HTTP 503 Service Unavailable", response["error"]["data"])
        self.assertEqual(len(_Http503Connection.instances), 1)
        self.assertEqual(_Http503Connection.instances[0].request_calls, 1)
        self.assertTrue(_Http503Connection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_connection_failures(self):
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ConnectFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("refused", response["error"]["data"])
        self.assertEqual(len(_ConnectFailureConnection.instances), 1)
        self.assertEqual(_ConnectFailureConnection.instances[0].request_calls, 1)
        self.assertTrue(_ConnectFailureConnection.instances[0].closed)


if __name__ == "__main__":
    unittest.main()
