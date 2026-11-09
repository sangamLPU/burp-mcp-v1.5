import hashlib
import json
from pathlib import Path
import tempfile
import socket
import threading
import unittest
from unittest.mock import patch

from cancellation_client import admissible_terminal, capture_once, classify_response


class SocketFixture:
    def __init__(self, chunks):
        self.chunks, self.sends, self.closed = iter(chunks), 0, False
    def settimeout(self, value): pass
    def sendall(self, request): self.sends += 1
    def recv(self, limit):
        value = next(self.chunks, b"")
        if isinstance(value, Exception): raise value
        return value
    def close(self): self.closed = True


class CancellationClientTests(unittest.TestCase):
    def test_real_local_socket_streams_cover_eof_error_partial_and_timeout(self):
        for wire, hold, expected in ((b"", False, "EOF_WITHOUT_RESPONSE"),
                                     (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4\r\n\r\nnope", False, "HTTP_RESPONSE_COMPLETE"),
                                     (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 9\r\n\r\nabc", False, "PARTIAL_HTTP_RESPONSE"),
                                     (b"", True, "READ_TIMEOUT")):
            client, peer = socket.socketpair()
            release = threading.Event()
            def serve():
                try:
                    peer.recv(4096)
                    if wire: peer.sendall(wire)
                    if hold: release.wait(2)
                finally: peer.close()
            thread = threading.Thread(target=serve); thread.start()
            try:
                with tempfile.TemporaryDirectory() as directory:
                    result = capture_once(b"GET /synthetic HTTP/1.1\r\n\r\n", Path(directory)/"evidence.json",
                                          timeout=.2, connection_factory=lambda *a, **k: client)
                    self.assertEqual(expected, result["outcome"])
            finally:
                release.set(); thread.join(timeout=2); client.close()

    def observe(self, chunks):
        fixture = SocketFixture(chunks)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"client.json"
            result = capture_once(b"synthetic request", path, connection_factory=lambda *a, **k: fixture)
            self.assertEqual(result, json.loads(path.read_text()))
            self.assertEqual(1, result["requestAttempts"])
            self.assertEqual(1, fixture.sends)
            self.assertTrue(fixture.closed)
            self.assertTrue(result["evidencePersistedBeforePublication"])
        return result

    def test_socket_close_without_response_is_exactly_recorded(self):
        result = self.observe([b""])
        self.assertEqual("EOF_WITHOUT_RESPONSE", result["outcome"])
        self.assertEqual(0, result["wireBytes"])
        self.assertTrue(admissible_terminal(result))

    def test_complete_http_error_retains_status_framing_bytes_and_hash(self):
        wire = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4\r\n\r\nnope"
        result = self.observe([wire[:24], wire[24:]])
        self.assertEqual("HTTP_RESPONSE_COMPLETE", result["outcome"])
        self.assertEqual(502, result["statusCode"])
        self.assertEqual("HTTP_ERROR", result["httpClass"])
        self.assertEqual(4, result["bodyBytes"])
        self.assertEqual(hashlib.sha256(wire).hexdigest(), result["wireSha256"])
        self.assertTrue(admissible_terminal(result))

    def test_proxy_200_and_empty_200_are_complete_observations_not_upstream_delivery_proof(self):
        for body in (b"Burp dropped this synthetic request", b""):
            wire = b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body
            result = self.observe([wire])
            self.assertEqual(200, result["statusCode"])
            self.assertEqual(len(body), result["bodyBytes"])
            self.assertTrue(admissible_terminal(result))

    def test_partial_body_eof_keeps_status_and_received_bytes_but_cannot_pass(self):
        result = self.observe([b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 10\r\n\r\nabc", b""])
        self.assertEqual("PARTIAL_HTTP_RESPONSE", result["outcome"])
        self.assertEqual(502, result["statusCode"])
        self.assertEqual(3, result["bodyBytes"])
        self.assertEqual(10, result["expectedBodyBytes"])
        self.assertFalse(admissible_terminal(result))

    def test_partial_headers_are_not_silently_discarded(self):
        result = self.observe([b"HTTP/1.1 200 OK\r\nContent-Len", b""])
        self.assertEqual("INCOMPLETE_HEADERS", result["framing"])
        self.assertGreater(result["wireBytes"], 0)
        self.assertFalse(admissible_terminal(result))

    def test_timeout_with_or_without_partial_data_is_preserved_and_inconclusive(self):
        for chunks in ([TimeoutError()], [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx", TimeoutError()]):
            result = self.observe(chunks)
            self.assertEqual("READ_TIMEOUT", result["termination"])
            self.assertFalse(admissible_terminal(result))

    def test_connection_reset_and_abort_have_distinct_terminal_observations(self):
        for error, outcome in ((ConnectionResetError(), "CONNECTION_RESET"), (ConnectionAbortedError(), "CONNECTION_ABORTED")):
            result = self.observe([error])
            self.assertEqual(outcome, result["outcome"])
            self.assertTrue(admissible_terminal(result))

    def test_reset_after_partial_response_keeps_bytes_and_does_not_pass(self):
        result = self.observe([b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", ConnectionResetError()])
        self.assertEqual("CONNECTION_RESET", result["termination"])
        self.assertEqual("PARTIAL_HTTP_RESPONSE", result["outcome"])
        self.assertFalse(admissible_terminal(result))

    def test_close_delimited_response_requires_eof(self):
        wire = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nrejected"
        result = self.observe([wire, b""])
        self.assertEqual("CLOSE_DELIMITED", result["framing"])
        self.assertTrue(result["responseComplete"])
        self.assertFalse(admissible_terminal(classify_response(wire, "READ_TIMEOUT")))

    def test_timeout_after_declared_body_is_not_mistaken_for_socket_closure(self):
        result = self.observe([b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", TimeoutError()])
        self.assertEqual("READ_TIMEOUT", result["termination"])
        self.assertTrue(result["responseComplete"])
        self.assertFalse(admissible_terminal(result))

    def test_invalid_conflicting_extra_and_unsupported_framing_fail_closed(self):
        for wire in (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                     b"HTTP/1.1 100 Continue\r\n\r\n", b"invalid\r\n\r\n"):
            self.assertFalse(admissible_terminal(classify_response(wire, "EOF")))

    def test_connect_failure_is_not_cancellation_and_never_retries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"evidence.json"
            with patch("cancellation_client.socket.create_connection", side_effect=ConnectionRefusedError()):
                result = capture_once(b"test", path, connection_factory=lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
            self.assertEqual("CONNECT_ERROR", result["outcome"])
            self.assertFalse(admissible_terminal(result))

    def test_disk_failure_cannot_publish_a_successful_outcome(self):
        fixture = SocketFixture([b""])
        with patch("cancellation_client.atomic_json", side_effect=[None, OSError("disk failure")]):
            with self.assertRaises(OSError):
                capture_once(b"test", "unused.json", connection_factory=lambda *a, **k: fixture)
        self.assertEqual(1, fixture.sends)


if __name__ == "__main__": unittest.main()
