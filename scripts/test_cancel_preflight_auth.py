"""Offline authentication and transport regressions for cancellation preflight."""

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from cancel_test_preflight import (
    HEALTH_BODY,
    McpClient,
    PreflightError,
    bearer_token_from_environment,
    check_test_server_health,
)


FAKE_TOKEN = "A" * 43


class FakeResponse:
    def __init__(self, status=200, payload=None, content_type="application/json", body=None, lines=None, headers=None):
        self.status = status
        self.headers = {"Content-Type": content_type}
        self.headers.update(headers or {})
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        self.body = b"{}" if body is None else body
        self.lines = iter(lines or [])

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, _limit=-1):
        return self.body

    def readline(self, _limit=-1):
        return next(self.lines, b"")


class MalformedToolEnvelopeTests(unittest.TestCase):
    def test_unexpected_structured_or_conflicting_content_is_not_status_evidence(self):
        client = McpClient()
        for result in ({"structuredContent": {"enabled": True}},
                       {"content": [], "structuredContent": {"enabled": True}},
                       {"content": [{"type": "text", "text": "Approval required."}], "structuredContent": {"enabled": True}},
                       {"content": [{"type": "text", "text": "true"}]},
                       {"content": [{"type": "text", "text": "null"}]}):
            with self.subTest(result=result), patch.object(client, "rpc", return_value=result), self.assertRaises(PreflightError):
                client.tool("burp_get_intercept_status")

    def test_invalid_error_flags_and_wrapped_results_are_rejected(self):
        client = McpClient()
        for result in ({"isError": "true", "structuredContent": {"enabled": True}},
                       {"isError": 0, "structuredContent": {"enabled": True}},
                       {"result": {}, "structuredContent": {"enabled": True}},
                       {"error": {"code": 1}, "structuredContent": {"enabled": True}}):
            with self.subTest(result=result), patch.object(client, "rpc", return_value=result), self.assertRaises(PreflightError):
                client.tool("burp_get_intercept_status")

    def test_malformed_content_cannot_return_a_status(self):
        client = McpClient()
        for content in (None, {}, [], [{}], [{"type": "text", "text": 3}]):
            with self.subTest(content=content), patch.object(client, "rpc", return_value={"content": content}), self.assertRaises(PreflightError):
                client.tool("burp_get_intercept_status")


class FakeConnection:
    def __init__(self, response=None, request_error=None, response_error=None):
        self.response = response or FakeResponse(payload={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
        self.request_error = request_error
        self.response_error = response_error
        self.request_args = None
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        if headers is None:
            headers = {}
        self.request_args = (method, path, body, dict(headers))
        if self.request_error:
            raise self.request_error

    def getresponse(self):
        if self.response_error:
            raise self.response_error
        return self.response

    def close(self):
        self.closed = True


class AuthenticationPreflightTests(unittest.TestCase):
    def test_boolean_rpc_id_cannot_match_integer_request_id(self):
        connection = FakeConnection(FakeResponse(payload={"jsonrpc": "2.0", "id": True, "result": {"ok": True}}))
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaises(PreflightError):
                self.client(lambda *_a, **_k: connection).rpc("initialize")
        self.assertTrue(connection.closed)

    def test_content_type_substrings_are_not_json_or_event_stream(self):
        for media_type in ("application/jsonish", "text/plain; note=application/json", "text/event-streamish"):
            connection = FakeConnection(FakeResponse(content_type=media_type, payload={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}))
            with self.subTest(media_type=media_type), patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
                with self.assertRaisesRegex(PreflightError, "unexpected content type"):
                    self.client(lambda *_a, **_k: connection).rpc("initialize")
            self.assertTrue(connection.closed)

    def client(self, factory):
        return McpClient(connection_factory=factory)

    def test_missing_token_fails_before_connection(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(PreflightError, "missing"):
                self.client(lambda *_a, **_k: self.fail("network must not be touched")).rpc("initialize")

    def test_empty_token_fails_before_connection(self):
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": ""}, clear=True):
            with self.assertRaisesRegex(PreflightError, "empty"):
                self.client(lambda *_a, **_k: self.fail("network must not be touched")).rpc("initialize")

    def test_prefixed_whitespace_and_malformed_tokens_fail_closed(self):
        for token in (f"Bearer {FAKE_TOKEN}", f" {FAKE_TOKEN}", f"{FAKE_TOKEN} ", "short-token"):
            with self.subTest(token_shape="prefixed" if token.startswith("Bearer") else "invalid"):
                with self.assertRaisesRegex(PreflightError, "bare 43-character"):
                    bearer_token_from_environment({"BURP_MCP_TOKEN": token})

    def test_valid_token_is_sent_as_one_bearer_header_without_logging(self):
        connection = FakeConnection()
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            result = self.client(lambda *_a, **_k: connection).rpc("initialize")
        self.assertEqual({"ok": True}, result)
        self.assertEqual("Bearer " + FAKE_TOKEN, connection.request_args[3]["Authorization"])
        self.assertTrue(connection.closed)

    def test_streamable_http_sse_returns_without_waiting_for_stream_eof(self):
        event = b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}'
        response = FakeResponse(
            content_type="text/event-stream",
            lines=[b"event: message\r\n", b"data: " + event + b"\r\n", b"\r\n"],
        )
        connection = FakeConnection(response)
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            result = self.client(lambda *_a, **_k: connection).rpc("initialize")
        self.assertEqual("2025-03-26", result["protocolVersion"])
        self.assertTrue(connection.closed)

    def test_stateless_requests_send_negotiated_protocol_without_session_header(self):
        connection = FakeConnection()
        client = self.client(lambda *_a, **_k: connection)
        client._protocol_version = "2025-06-18"
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            client.rpc("ping")
        headers = connection.request_args[3]
        self.assertEqual("2025-06-18", headers["MCP-Protocol-Version"])
        self.assertNotIn("Mcp-Session-Id", headers)
        self.assertTrue(connection.closed)

    def test_401_stale_or_incorrect_token_is_classified_safely(self):
        connection = FakeConnection(FakeResponse(status=401, body=b"sensitive server detail"))
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "HTTP 401") as raised:
                self.client(lambda *_a, **_k: connection).rpc("initialize")
        self.assertNotIn(FAKE_TOKEN, str(raised.exception))
        self.assertNotIn("sensitive server detail", str(raised.exception))

    def test_403_is_not_misreported_as_bad_credentials(self):
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "HTTP 403"):
                self.client(lambda *_a, **_k: FakeConnection(FakeResponse(status=403))).rpc("initialize")

    def test_http_error_status_is_reported_without_response_body(self):
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "HTTP 503") as raised:
                self.client(lambda *_a, **_k: FakeConnection(FakeResponse(status=503, body=b"private"))).rpc("initialize")
        self.assertNotIn("private", str(raised.exception))

    def test_connection_refusal_is_safe_and_bounded(self):
        def refused(*_args, **_kwargs):
            raise ConnectionRefusedError("secret endpoint details")

        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "connection was refused") as raised:
                self.client(refused).rpc("initialize")
        self.assertNotIn("secret endpoint details", str(raised.exception))

    def test_network_timeout_is_safe_and_bounded(self):
        def timed_out(*_args, **_kwargs):
            raise TimeoutError("sensitive detail")

        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "timed out") as raised:
                self.client(timed_out).rpc("initialize")
        self.assertNotIn("sensitive detail", str(raised.exception))

    def test_response_timeout_after_mcp_request_is_safe_and_never_claims_test_was_sent(self):
        connection = FakeConnection(response_error=TimeoutError("private timeout detail"))
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "timed out") as raised:
                self.client(lambda *_a, **_k: connection).rpc("initialize")
        self.assertIn("cancellation test request was not sent", str(raised.exception))
        self.assertNotIn("private timeout detail", str(raised.exception))
        self.assertIsNotNone(connection.request_args)
        self.assertTrue(connection.closed)

    def test_malformed_content_type_json_and_response_id_fail(self):
        with patch.dict(os.environ, {"BURP_MCP_TOKEN": FAKE_TOKEN}, clear=True):
            with self.assertRaisesRegex(PreflightError, "unexpected content type"):
                self.client(lambda *_a, **_k: FakeConnection(FakeResponse(content_type="text/plain"))).rpc("initialize")
            with self.assertRaisesRegex(PreflightError, "unreadable response"):
                self.client(lambda *_a, **_k: FakeConnection(FakeResponse(body=b"not-json"))).rpc("initialize")
            with self.assertRaisesRegex(PreflightError, "mismatched response ID"):
                self.client(lambda *_a, **_k: FakeConnection(FakeResponse(payload={"jsonrpc": "2.0", "id": 99, "result": {}}))).rpc("initialize")

    def test_child_process_inherits_process_token_without_emitting_it(self):
        env = dict(os.environ)
        env["BURP_MCP_TOKEN"] = FAKE_TOKEN
        code = "import os,sys; sys.exit(0 if os.getenv('BURP_MCP_TOKEN') == '" + FAKE_TOKEN + "' else 1)"
        result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(FAKE_TOKEN, result.stdout + result.stderr)

    def test_server_health_identity_must_match_active_mode_values(self):
        run_id = "11111111-2222-3333-4444-555555555555"
        response = FakeResponse(
            body=HEALTH_BODY,
            headers={"X-MCP-Test-Run": run_id, "X-MCP-Server-Identity": FAKE_TOKEN},
        )
        connection = FakeConnection(response)
        check_test_server_health(run_id, FAKE_TOKEN, lambda *_a, **_k: connection)
        self.assertTrue(connection.closed)
        self.assertEqual(run_id, connection.request_args[3]["X-MCP-Test-Run"])
        self.assertEqual(FAKE_TOKEN, connection.request_args[3]["X-MCP-Server-Identity"])

        mismatch = FakeConnection(FakeResponse(body=HEALTH_BODY, headers={"X-MCP-Test-Run": run_id}))
        with self.assertRaisesRegex(PreflightError, "server identity did not match"):
            check_test_server_health(run_id, FAKE_TOKEN, lambda *_a, **_k: mismatch)

        with self.assertRaisesRegex(PreflightError, "Both unattended local test identity values"):
            check_test_server_health(run_id, None, lambda *_a, **_k: self.fail("invalid identity pair must not connect"))


if __name__ == "__main__":
    unittest.main()
