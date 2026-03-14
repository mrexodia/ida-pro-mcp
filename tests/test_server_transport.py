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
