"""Opt-in live Burp verification. Uses only Python's standard library and loopback.

Requires the NEW extension loaded, Burp Proxy on 127.0.0.1:8080, target scope and
allowlist containing http://127.0.0.1:8000, read-only OFF, live edits enabled locally.
Human approval dialogs remain mandatory. No model/provider credentials are needed.
"""
import concurrent.futures
import http.client
import itertools
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("BURP_MCP_TOKEN")
SESSION = None
PROTOCOL = "2025-03-26"
IDS = itertools.count(1)


def rpc(method, params=None, notification=False):
    global SESSION, PROTOCOL
    message = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    if not notification:
        message["id"] = next(IDS)
    connection = http.client.HTTPConnection("127.0.0.1", 9876, timeout=125)
    headers = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if SESSION:
        headers["Mcp-Session-Id"] = SESSION
        headers["MCP-Protocol-Version"] = PROTOCOL
    try:
        connection.request("POST", "/mcp", json.dumps(message), headers)
        response = connection.getresponse()
        SESSION = response.getheader("Mcp-Session-Id") or SESSION
        body = response.read().decode("utf-8")
        if response.status >= 400:
            raise RuntimeError("MCP HTTP status " + str(response.status))
        if notification:
            return None
        if "text/event-stream" in response.getheader("Content-Type", ""):
            payloads = [json.loads(line[5:].strip()) for line in body.splitlines() if line.startswith("data:")]
            payload = next(p for p in payloads if p.get("id") == message["id"])
        else:
            payload = json.loads(body)
        if "error" in payload:
            raise RuntimeError(str(payload["error"]))
        return payload["result"]
    finally:
        connection.close()


def tool(name, **arguments):
    result = rpc("tools/call", {"name": name, "arguments": arguments})
    text = "\n".join(c.get("text", "") for c in result.get("content", []))
    if result.get("isError"):
        raise RuntimeError(name + ": " + text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


hits = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.headers.get("X-MCP-Live"))
        body = b"original local response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def browser_request():
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=125)
    try:
        connection.request("GET", "http://127.0.0.1:8000/live-check",
                           headers={"Host": "127.0.0.1:8000", "Connection": "close"})
        return connection.getresponse().read().decode("utf-8")
    finally:
        connection.close()


def pending(direction):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        entries = tool("burp_list_pending_" + direction + "s")
        if entries:
            if len(entries) != 1:
                raise RuntimeError("Unexpected concurrent browser traffic; cancel and retry with other clients closed")
            return entries[0]
        time.sleep(0.2)
    raise RuntimeError("No pending " + direction + "; verify Proxy, scope, allowlist and live mode")


def main():
    global PROTOCOL
    if not TOKEN:
        raise RuntimeError("Set BURP_MCP_TOKEN to the token copied from Burp MCP")
    init = rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                              "clientInfo": {"name": "burp-live-local-verifier", "version": "1"}})
    PROTOCOL = init["protocolVersion"]
    rpc("notifications/initialized", notification=True)
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        status = tool("burp_get_intercept_status")
        if not status["editsEnabled"]:
            raise RuntimeError("Enable Allow AI edit proposals in Burp MCP, turn read-only OFF, and set hold timeout to 120 seconds")
        if tool("burp_list_pending_requests") or tool("burp_list_pending_responses"):
            raise RuntimeError("Existing pending traffic: finish or cancel it before this isolated test")
        tool("burp_set_live_interception_state", enabled=True)  # HUMAN dialog in Burp
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            browser = executor.submit(browser_request)
            request = pending("request")
            assert not hits and not browser.done(), "Request was sent before a queue decision"
            # Deliberately make no MCP calls longer than the former 15-second lease.
            time.sleep(17)
            heartbeat_status = tool("burp_get_intercept_status")
            assert heartbeat_status["enabled"] and heartbeat_status["heartbeatHealth"] == "HEALTHY", \
                "The locally approved heartbeat did not keep the session alive without client polling"
            assert heartbeat_status["pendingRequests"] == 1, "Held request did not survive the client-idle interval"
            tool("burp_propose_intercepted_request_edit", id=request["id"], revision=0,
                 headers={"X-MCP-Live": "approved-test"})
            tool("burp_approve_intercepted_request_edit", id=request["id"], revision=1)
            tool("burp_forward_intercepted_request", id=request["id"], revision=1)
            response = pending("response")
            assert hits == ["approved-test"] and not browser.done()
            tool("burp_propose_intercepted_response_edit", id=response["id"], revision=0,
                 body="live interception response modified")
            tool("burp_forward_intercepted_response", id=response["id"], revision=1)  # HUMAN dialog
            assert browser.result(timeout=5) == "live interception response modified"
            dropped = executor.submit(browser_request)
            request = pending("request")
            tool("burp_drop_intercepted_request", id=request["id"])
            try:
                dropped.result(timeout=5)  # Burp may close or return its own error response.
            except (http.client.HTTPException, ConnectionError):
                pass
            assert hits == ["approved-test"], "Dropped request reached the target"
        print("PASS: live Burp held/modified/forwarded request and response; dropped request never reached target")
    finally:
        try:
            tool("burp_cancel_interceptions")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit("Live verification failed: " + str(error))
