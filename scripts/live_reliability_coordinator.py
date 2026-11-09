"""Supervised, one-shot localhost verification of drop, timeout, expiry and isolation.

Requires fresh human activation in Burp. It never activates authorization, retries
an HTTP request, changes scope, or modifies the working interception rule engine.
"""
import argparse
import hashlib
import http.client
import json
import queue
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

import cancel_test_preflight as preflight
from live_rule_engine_coordinator import CoordinatorError, LiveRuleEngineCoordinator, EXPECTED_BUILD_ID


ROOT = Path(__file__).resolve().parents[1]


def aggregate_phase_status(phases):
    expected = {"4A", "4B", "4C", "4D"}
    return "PASS" if (len(phases) == 4 and {row["phase"] for row in phases} == expected
                       and all(row["state"] == "PASS" for row in phases)) else "INCONCLUSIVE"


def decode_tool_result(result):
    if not isinstance(result, dict) or result.get("isError", False) is not False:
        raise CoordinatorError("TOOL_REJECTED", "MCP tool rejected the exact operation")
    content = result.get("content")
    if ("structuredContent" in result or "error" in result or "result" in result or
            not isinstance(content, list) or len(content) != 1 or
            not isinstance(content[0], dict) or content[0].get("type") != "text" or
            not isinstance(content[0].get("text"), str) or
            not content[0]["text"].strip() or len(content[0]["text"]) > preflight.MAX_MCP_RESPONSE_BYTES):
        raise CoordinatorError("MALFORMED_TOOL_RESULT", "MCP tool result did not contain one bounded text payload")
    text = content[0]["text"]
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        if text.startswith(("DROPPED:", "FORWARDED:", "Human approved revision ")):
            return text
        raise CoordinatorError("UNEXPECTED_TOOL_RESULT", "MCP tool did not confirm the requested operation")
    if not isinstance(decoded, (dict, list)):
        raise CoordinatorError("MALFORMED_TOOL_RESULT", "MCP tool returned an unexpected scalar payload")
    return decoded


class ReliabilityCoordinator(LiveRuleEngineCoordinator):
    def __init__(self, client):
        super().__init__(client, native_intercept_prepared=True)
        self.tag = uuid.uuid4().hex
        self.report_path = ROOT / "build/reports/reliability" / f"phases-4abcd-{self.tag}.json"
        self.evidence_path = self.report_path.with_suffix(".exchanges.jsonl")
        self.report = {"state": "PREPARING", "buildId": EXPECTED_BUILD_ID, "phases": [], "toolsExercised": [], "clientAttempts": 0}
        self.active_workers = []

    def save(self):
        self.report["clientAttempts"] = self.client_attempts_started
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(json.dumps(self.report, indent=2), encoding="utf-8")

    def tool(self, name, **args):
        result = decode_tool_result(self.client.rpc("tools/call", {"name": name, "arguments": args}))
        if name not in self.report["toolsExercised"]:
            self.report["toolsExercised"].append(name)
        return result

    def health(self, minimum_ms=5000):
        status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
        mode = status["unattendedMode"]
        if (not mode["active"] or mode["testRunId"] != self.run_id or mode["serverIdentity"] != self.server_identity
                or mode["remainingMillis"] < minimum_ms):
            raise CoordinatorError("AUTHORIZATION_EXPIRED", "current local authorization no longer has the required identity and time")
        return status

    def assert_empty(self):
        requests = self.tool("burp_list_pending_requests", includeDiagnostics=False)
        responses = self.tool("burp_list_pending_responses", includeDiagnostics=False)
        if requests or responses:
            raise CoordinatorError("UNEXPECTED_QUEUE", "expected both queues empty; existing messages were left unchanged")

    def start_session(self, seconds):
        status = self.health(seconds * 1000 + 10000)
        self.assert_empty()
        if status["enabled"]:
            raise CoordinatorError("UNEXPECTED_SESSION", "session must be stopped before a new bounded test session")
        self.tool("burp_set_live_interception_state", enabled=True, sessionLifetimeSeconds=seconds)
        status = self.health()
        if not status["enabled"] or status["heartbeatHealth"] != "HEALTHY":
            raise CoordinatorError("SESSION_START_FAILED", "approved session did not become healthy")

    def records(self):
        path = ROOT / "build/live-test-server-observations.jsonl"
        if not path.exists():
            return []
        with path.open("rb") as stream:
            stream.seek(self.log_baseline)
            return [json.loads(line) for line in stream.read().decode("utf-8").splitlines() if line.strip()]

    def origin_count(self, path):
        return sum(record.get("path") == path for record in self.records())

    def send(self, path, case, body=None):
        self.health(15000)
        output = queue.Queue(maxsize=1)
        body_bytes = body.encode("utf-8") if body is not None else None
        run, identity = self.run_id, self.server_identity
        def worker():
            started = time.monotonic()
            connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=75)
            try:
                headers = {"Host": "127.0.0.1:8000", "Connection": "close", "X-MCP-Test-Run": run,
                           "X-MCP-Server-Identity": identity, "X-MCP-Test-ID": case}
                if body is not None:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                connection.request("POST" if body is not None else "GET", "http://127.0.0.1:8000"+path, body_bytes, headers)
                response = connection.getresponse()
                data = response.read(65537)
                if len(data) > 65536:
                    raise ValueError("bounded client response exceeded limit")
                try:
                    parsed = json.loads(data)
                except (ValueError, UnicodeDecodeError):
                    parsed = None
                output.put({"status": response.status, "bytes": len(data), "bodySha256": hashlib.sha256(data).hexdigest(),
                            "json": parsed, "seconds": round(time.monotonic()-started, 3)})
            except Exception as error:
                output.put({"errorType": type(error).__name__, "seconds": round(time.monotonic()-started, 3)})
            finally:
                connection.close()
        self.client_attempts_started += 1
        self.save()
        thread = threading.Thread(target=worker, daemon=True)
        self.active_workers.append(thread)
        thread.start()
        return output

    def pending(self, kind, path, timeout=5):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            entries = self.tool("burp_list_pending_"+kind+"s", includeDiagnostics=False)
            if any(row.get("hostname") != "127.0.0.1" for row in entries):
                raise CoordinatorError("UNEXPECTED_QUEUE", "unrelated traffic was not changed")
            found = [row for row in entries if row.get("urlPath") == path]
            if len(found) == 1:
                return found[0]
            if len(found) > 1:
                raise CoordinatorError("UNEXPECTED_QUEUE", "ambiguous path association; no operation was attempted")
            time.sleep(.1)
        raise CoordinatorError("CAPTURE_NOT_OBSERVED", "one-shot test did not appear in the expected queue")

    def terminal_client(self, output, timeout=7):
        try:
            result = output.get(timeout=timeout)
        except queue.Empty:
            raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "client did not terminate within the observation bound; no retry")
        self.report.setdefault("clientOutcomes", []).append(result)
        self.save()  # Preserve a terminal observation before any classifier can reject it.
        if result.get("errorType") in {"TimeoutError", "ValueError"}:
            raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "client timeout or unsupported response; no retry")
        return result

    @staticmethod
    def assert_cancelled_client(result):
        if 200 <= result.get("status", 0) < 300:
            # Burp may return a 200 HTML/error response after dropping a request.
            # Only a complete recorded observation without a fixture JSON response
            # can proceed to the independent zero-origin + terminal-event checks.
            if (result.get("json") is not None or "bytes" not in result
                    or len(result.get("bodySha256", "")) != 64):
                raise CoordinatorError("CLIENT_CANCELLATION_UNVERIFIED", "2xx cancellation requires complete client metadata and independent origin/event evidence")

    def event(self, ticket, action, outcome):
        events = self.tool("burp_get_intercept_diagnostics", count=100)["events"]
        found = [row for row in events if row.get("action") == action and row.get("outcome") == outcome and ticket["id"] in row.get("detail", "")]
        if not found:
            raise CoordinatorError("EVENT_MISSING", "matching terminal diagnostic evidence was not observed")
        return {key: found[0].get(key) for key in ("action", "outcome", "detail")}

    def stale(self, ticket, kind="request"):
        checks = [("burp_get_intercepted_"+kind, {"id": ticket["id"]}),
                  ("burp_propose_intercepted_"+kind+"_edit", {"id": ticket["id"], "revision": ticket["revision"], "headers": {"X-MCP-Stale": "test"}}),
                  ("burp_forward_intercepted_"+kind, {"id": ticket["id"], "revision": ticket["revision"]})]
        for name, args in checks:
            result = self.client.rpc("tools/call", {"name": name, "arguments": args})
            if result.get("isError") is not True:
                raise CoordinatorError("STALE_ID_ACCEPTED", "terminal message unexpectedly accepted another operation")
        return True

    def record_phase(self, name, evidence):
        self.report["phases"].append({"phase": name, "state": "PASS", **evidence})
        self.save()
        print(json.dumps({"phase": name, "state": "PASS"}), flush=True)

    def drop(self):
        path = "/test-cancel"
        case = "phase4a-"+uuid.uuid4().hex
        output = self.send(path, case)
        ticket = self.pending("request", path)
        self.health()
        self.tool("burp_drop_intercepted_request", id=ticket["id"])
        result = self.terminal_client(output)
        self.assert_cancelled_client(result)
        self.assert_empty()
        if self.origin_count(path) != 0:
            raise CoordinatorError("UNEXPECTED_ORIGIN_DELIVERY", "explicitly dropped request reached the origin")
        event = self.event(ticket, "intercept_drop", "dropped")
        policy = self.event(ticket, "unattended_local_test", "auto_approved")
        if "operation=DROP_REQUEST" not in policy["detail"]:
            raise CoordinatorError("APPROVAL_SOURCE_UNVERIFIED", "drop did not carry exact unattended policy evidence")
        self.record_phase("4A", {"case": case, "client": result, "originDeliveries": 0, "event": event,
                                 "approvalEvidence": policy, "staleIdRejected": self.stale(ticket)})

    def authorize_forward(self, ticket, kind):
        self.health(10000)
        if ticket.get("hostname") != "127.0.0.1" or ticket.get("urlPath") not in ("/test-concurrent-a", "/test-concurrent-b"):
            raise CoordinatorError("UNEXPECTED_MESSAGE", "exact synthetic concurrent path required")
        try:
            self.tool("burp_approve_intercepted_"+kind+"_edit", id=ticket["id"], revision=ticket["revision"])
        except (preflight.PreflightError, CoordinatorError) as error:
            raise CoordinatorError("WAITING_FOR_APPROVAL", "exact revision could not be automatically approved; no forward or retry") from error
        current = self.tool("burp_get_intercepted_"+kind, id=ticket["id"])
        if current.get("approvedRevision") != ticket["revision"]:
            raise CoordinatorError("WAITING_FOR_APPROVAL", "exact revision remains unapproved; forwarding was not attempted")
        approval = self.event(ticket, "intercept_approve", "auto_approved")
        self.tool("burp_forward_intercepted_"+kind, id=ticket["id"], revision=ticket["revision"])
        return approval

    def concurrency(self):
        cases = {letter: "phase3-"+letter+"-"+uuid.uuid4().hex for letter in ("A", "B")}
        def body(letter, modified):
            return urlencode({"test_id": cases[letter], "name": "case-"+letter,
                              "mcp_test": ("alpha" if letter == "A" else "beta")+("-modified" if modified else "-original"),
                              "marker": "keep-"+letter})
        outputs = {letter: self.send("/test-concurrent-"+letter.lower(), cases[letter], body(letter, False)) for letter in ("A", "B")}
        tickets = {letter: self.pending("request", "/test-concurrent-"+letter.lower()) for letter in ("A", "B")}
        if tickets["A"]["id"] == tickets["B"]["id"]:
            raise CoordinatorError("CROSS_ASSOCIATION", "concurrent requests share an ID")
        if len(self.tool("burp_list_pending_requests", includeDiagnostics=False)) != 2:
            raise CoordinatorError("QUEUE_ISOLATION_FAILED", "both unique requests must be held simultaneously")
        evidence = []
        for letter in ("B", "A"):
            request = tickets[letter]
            request = self.tool("burp_propose_intercepted_request_edit", id=request["id"], revision=request["revision"], body=body(letter, True))
            if letter == "B":
                untouched = self.tool("burp_get_intercepted_request", id=tickets["A"]["id"])
                if untouched["revision"] != 0 or untouched.get("approvedRevision") is not None:
                    raise CoordinatorError("CROSS_ASSOCIATION", "editing B changed A's revision or approval")
            request_approval = self.authorize_forward(request, "request")
            response = self.pending("response", "/test-concurrent-"+letter.lower())
            if letter == "B":
                if len(self.tool("burp_list_pending_requests", includeDiagnostics=False)) != 1:
                    raise CoordinatorError("QUEUE_ISOLATION_FAILED", "A must remain held while B's response is held")
            response_approval = self.authorize_forward(response, "response")
            client = self.terminal_client(outputs[letter])
            parsed = client.get("json") or {}
            if client.get("status") != 200 or parsed.get("TestId") != cases[letter] or parsed.get("ServerVerified") is not True:
                raise CoordinatorError("CLIENT_MISMATCH", "isolated response does not verify its own synthetic case")
            records = [r for r in self.records() if r.get("concurrentTestId") == cases[letter]]
            if len(records) != 1 or records[0].get("concurrentBodyVerified") is not True:
                raise CoordinatorError("ORIGIN_MISMATCH", "isolated case missing exact origin identity/framing evidence")
            evidence.append({"case": cases[letter], "requestId": request["id"], "responseId": response["id"],
                             "requestApproval": request_approval, "responseApproval": response_approval,
                             "client": client, "originDeliveries": 1, "originBodySha256": records[0]["bodySha256"],
                             "requestStaleRejected": self.stale(request), "responseStaleRejected": self.stale(response, "response")})
        self.assert_empty()
        self.record_phase("4D", {"maximumConcurrentRequests": 2, "mixedRequestResponseQueueVerified": True,
                                 "releaseOrder": ["B", "A"], "exchanges": evidence,
                                 "limit": "Existing two-message unattended limit retained; eight-slot saturation not attempted."})

    def message_timeout(self):
        path = "/test-timeout"
        status = self.health(90000)
        if status["sessionRemainingMillis"] < 75000:
            raise CoordinatorError("SESSION_WINDOW_LOW", "session cannot outlive the message timeout safely")
        output = self.send(path, "phase4b-"+uuid.uuid4().hex)
        ticket = self.pending("request", path)
        started = time.monotonic()
        deadline = started + 70
        while time.monotonic() < deadline:
            if not any(r["id"] == ticket["id"] for r in self.tool("burp_list_pending_requests", includeDiagnostics=False)):
                break
            self.health(10000)
            time.sleep(.5)
        else:
            raise CoordinatorError("MESSAGE_TIMEOUT_FAILED", "message exceeded bounded expiry observation")
        client = self.terminal_client(output)
        self.assert_cancelled_client(client)
        self.assert_empty()
        event = self.event(ticket, "intercept_expiration", "expired")
        if self.origin_count(path) or not self.health()["enabled"]:
            raise CoordinatorError("TIMEOUT_ISOLATION_FAILED", "timeout reached origin or terminated the entire session")
        self.record_phase("4B", {"configuredMessageTimeoutSeconds": status["timeoutSeconds"], "observedSeconds": round(time.monotonic()-started, 2),
                                 "originDeliveries": 0, "client": client, "event": event, "sessionStillHealthy": True,
                                 "staleIdRejected": self.stale(ticket)})

    def session_expiry(self):
        self.assert_empty()
        self.tool("burp_set_live_interception_state", enabled=False)
        self.start_session(60)
        time.sleep(5)  # The message deadline must be later than the session deadline.
        path = "/test-session-expiry"
        output = self.send(path, "phase4c-"+uuid.uuid4().hex)
        ticket = self.pending("request", path)
        initial = self.health()
        if ticket["remainingMillis"] <= initial["sessionRemainingMillis"] + 2000:
            raise CoordinatorError("DEADLINE_ORDER_FAILED", "session expiry must precede the message timeout")
        deadline = time.monotonic()+65
        while time.monotonic() < deadline:
            final = self.tool("burp_get_intercept_status", includeDiagnostics=False)
            if not final["enabled"]:
                break
            time.sleep(.5)
        else:
            raise CoordinatorError("SESSION_EXPIRY_FAILED", "bounded session did not expire")
        client = self.terminal_client(output)
        self.assert_cancelled_client(client)
        self.assert_empty()
        if final["sessionEndReason"] != "SESSION_EXPIRED" or final["heartbeatHealth"] != "EXPIRED" or self.origin_count(path):
            raise CoordinatorError("SESSION_CLEANUP_FAILED", "session expiry did not cancel its held request cleanly")
        event = self.event(ticket, "intercept_cancellation", "session_expired")
        self.record_phase("4C", {"sessionEndReason": final["sessionEndReason"], "heartbeatHealth": final["heartbeatHealth"],
                                 "client": client, "originDeliveries": 0, "event": event, "staleIdRejected": self.stale(ticket)})

    def run_phases(self, prior_drop_report=None):
        try:
            snapshot = self._snapshot(self.client)
            self.run_id, self.server_identity = self._validate_initial(snapshot)
            self.health(180000 if prior_drop_report else 240000)
            if (snapshot["interception"]["enabled"] or snapshot["interception"]["timeoutSeconds"] != 60
                    or snapshot["interception"].get("editsEnabled") is not True):
                raise CoordinatorError("PREPARATION_CHANGED", "requires stopped interception and the current 60-second message timeout")
            self._start_fixture()
            self.start_session(150 if prior_drop_report else 180)
            if prior_drop_report:
                previous = json.loads(Path(prior_drop_report).read_text(encoding="utf-8"))
                if previous.get("state") != "CLIENT_CANCELLATION_UNVERIFIED" or previous.get("clientAttempts") != 1:
                    raise CoordinatorError("INVALID_CONTINUATION", "prior report does not prove the single unretried cancellation attempt")
                self.report["phases"].append({"phase": "4A", "state": "INCONCLUSIVE", "priorReport": str(prior_drop_report),
                    "reason": "Drop recorded and origin not reached, but original client response metadata was not preserved; request will not be retried."})
                self.save()
            else:
                self.drop()
            self.concurrency()
            self.message_timeout()
            self.session_expiry()
            self.assert_empty()
            self._stop_fixture()
            self.report["state"] = aggregate_phase_status(self.report["phases"])
            self.report["cleanup"] = {"queuesEmpty": True, "fixtureStopped": True, "sessionExpired": True, "rulesConfigured": 0}
        except Exception as error:
            self.report["state"] = getattr(error, "code", "ERROR")
            self.report["errorType"] = type(error).__name__
            self.report["diagnostic"] = str(error)[:300]
            self._stop_fixture()
            # Never invoke confirmation or change held traffic on a failed/ambiguous operation.
            try:
                status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
                self.report["heldRequests"] = status["pendingRequests"]
                self.report["heldResponses"] = status["pendingResponses"]
                if status["enabled"] and not status["pendingRequests"] and not status["pendingResponses"]:
                    self.health()
                    self.tool("burp_set_live_interception_state", enabled=False)
            except Exception:
                pass
        self.save()
        return self.report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait-for-activation", action="store_true")
    parser.add_argument("--continue-after-drop-report")
    args = parser.parse_args()
    client = preflight.initialize(preflight.McpClient(timeout=3))
    if args.wait_for_activation:
        status = client.tool("burp_get_intercept_status", includeDiagnostics=False)
        if status["unattendedMode"]["active"] or status["enabled"]:
            raise SystemExit("Expected inactive authorization and session before arming")
        print("ARMED: waiting for fresh local activation; no traffic sent", flush=True)
        deadline = time.monotonic()+900
        while time.monotonic() < deadline:
            if client.tool("burp_get_intercept_status", includeDiagnostics=False)["unattendedMode"]["active"]:
                break
            time.sleep(1)
        else:
            raise SystemExit("Activation wait expired; no traffic sent")
    coordinator = ReliabilityCoordinator(client)
    result = coordinator.run_phases(args.continue_after_drop_report)
    print(json.dumps({"state": result["state"], "phases": [r["phase"] for r in result["phases"]],
                      "attempts": coordinator.client_attempts_started, "report": str(coordinator.report_path)}), flush=True)


if __name__ == "__main__":
    main()
