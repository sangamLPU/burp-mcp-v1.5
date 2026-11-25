"""Loopback-only echo server for manually checking Burp Proxy rewriting."""

import base64
import gzip
import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit


class Handler(BaseHTTPRequestHandler):
    def respond(self):
        if self.command == "GET" and self.path == "/fixture-websocket" and self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
            self.protocol_version = "HTTP/1.1"
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            fixture_case = self.headers.get("X-Fixture-Case")
            fixture_payloads = {
                "unicode": "localhost-fixture-café".encode("utf-8"),
                "unicode-binary": "localhost-fixture-café".encode("utf-8"),
                "ws-ascii": b"fixture-ws-ascii",
                "ws-hindi": "fixture-ws-hindi नमस्ते".encode("utf-8"),
                "ws-chinese": "fixture-ws-chinese 你好".encode("utf-8"),
                "ws-emoji": "fixture-ws-emoji 😀".encode("utf-8"),
                "ws-mixed": "fixture-ws-mixed hello नमस्ते 你好 😀".encode("utf-8"),
                "ws-invalid": b"fixture-ws-invalid \xff\xfe\xc3",
                "ws-arbitrary": b"fixture-ws-arbitrary \x00\x80\xfe\xff",
                "ws-valid-binary": "fixture-ws-valid-binary café".encode("utf-8"),
            }
            payload = fixture_payloads.get(fixture_case, b"localhost-fixture-hello")
            binary = fixture_case in ("unicode-binary", "ws-invalid", "ws-arbitrary", "ws-valid-binary")
            self.wfile.write(bytes((0x82 if binary else 0x81, len(payload))) + payload + b"\x88\x02\x03\xe8")
            self.wfile.flush()
            self.close_connection = True
            return
        if self.command == "GET" and self.path == "/response-test" and self.headers.get("X-Fixture-Case") == "delayed-stream":
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b'{"isPremium":false,', b'"keep":"original"', b'}'):
                self.wfile.write(f"{len(part):X}\r\n".encode("ascii") + part + b"\r\n")
                self.wfile.flush()
                time.sleep(0.6)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        if self.path in ("/coverage-json", "/coverage-html"):
            case = self.headers.get("X-Fixture-Case", "")
            status = 201 if self.path == "/coverage-json" else 200
            if case == "wrong-status":
                status = 202
            if case == "partial":
                status = 206
            if self.path == "/coverage-json":
                result = ('{"coverage_string":"old","coverage_null":17,'
                          '"nested":[{"coverage_string":"old",'
                          '"coverage_null":false}],"keep":"café"}').encode("utf-8")
                media = "application/json; charset=utf-8"
            else:
                result = '<!doctype html><p>Welcome, Guest</p><p>Keep café</p>'.encode("utf-8")
                media = "text/html; charset=utf-8"
            if case == "wrong-content-type":
                media = "text/plain; charset=utf-8"
            if case == "unsupported-charset":
                media = "application/json; charset=iso-8859-1"
            if case == "binary":
                media = "application/octet-stream"
            if case == "oversized":
                result = b'{"coverage_string":"old","filler":"' + b'x' * 1_048_576 + b'"}'
            if case in ("stream", "fixed-http11"):
                self.protocol_version = "HTTP/1.1"
            self.send_response(status)
            self.send_header("Content-Type", media)
            if case == "stream":
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", str(len(result)))
            if case == "partial":
                self.send_header("Content-Range", f"bytes 0-{len(result)-1}/{len(result)+1}")
            if case == "attachment":
                self.send_header("Content-Disposition", 'attachment; filename="fixture.txt"')
            if case == "etag":
                self.send_header("ETag", '"fixture-v1"')
            if case == "no-transform":
                self.send_header("Cache-Control", "no-transform")
            self.end_headers()
            if self.command != "HEAD":
                if case == "stream":
                    self.wfile.write(f"{len(result):X}\r\n".encode("ascii") + result + b"\r\n0\r\n\r\n")
                else:
                    self.wfile.write(result)
            return
        if self.command == "GET" and self.path == "/response-test" and self.headers.get("X-Fixture-Case") in ("pointer-only", "gzip"):
            result = b'{"user":{"credits":10,"keep":"same"},"other":11}'
            if self.headers.get("X-Fixture-Case") == "gzip":
                result = gzip.compress(result, mtime=0)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if self.headers.get("X-Fixture-Case") == "gzip":
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
        if self.command == "GET" and self.path in ("/response-pointer", "/response-gzip"):
            result = b'{"user":{"credits":10,"keep":"same"},"other":11}'
            if self.path == "/response-gzip":
                result = gzip.compress(result, mtime=0)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            if self.path == "/response-gzip":
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
        if self.command == "GET" and self.path == "/response-text":
            result = b"Keep prefix. Fixture status: original. Keep suffix."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
        if urlsplit(self.path).path in ("/global-a", "/global-b"):
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2_097_152:
                self.send_error(413)
                return
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            result = json.dumps({
                "isPremium": False,
                "nested": {"isPremium": False, "keep": "unchanged"},
                "request": {"method": self.command, "path": self.path, "body_utf8": body},
            }, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
        if self.command == "GET" and self.path == "/response-test":
            result = b'{"isPremium":false,"user":{"isPremium":false,"credits":10},"items":[{"isPremium":false,"keep":"original"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_097_152:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        result = json.dumps({
            "method": self.command,
            "path": self.path,
            "content_type": self.headers.get("Content-Type"),
            "content_length": length,
            "body_base64": base64.b64encode(body).decode("ascii"),
            "body_utf8": body.decode("utf-8", errors="replace"),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    do_GET = respond
    do_POST = respond
    do_PUT = respond
    do_PATCH = respond

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("REWRITE_FIXTURE_PORT", "18080"))
    print(f"Rewrite test server listening on http://127.0.0.1:{port}", flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
