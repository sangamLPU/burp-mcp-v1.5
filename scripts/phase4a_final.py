"""Exactly one fresh, authorized cancellation test; no other live phase is run."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import socket
import subprocess
import threading
import time
import uuid

import cancel_test_preflight as preflight
from cancellation_client import admissible_terminal, atomic_json, capture_once
from live_reliability_coordinator import ReliabilityCoordinator
from live_rule_engine_coordinator import CoordinatorError


class Phase4A(ReliabilityCoordinator):
    def __init__(self, client):
        super().__init__(client)
        self.report_path = self.report_path.with_name("phase4a-final-"+self.tag+".json")
        self.evidence_path = self.report_path.with_suffix(".fixture-base.jsonl")
        self.client_path = self.report_path.with_suffix(".client.json")
        self.report.update(state="PREPARED", phase="4A", retries=0)

    def save(self):
        self.report["clientAttempts"] = self.client_attempts_started
        atomic_json(self.report_path, self.report)

    def one_client(self, case):
        self.health(20000)
        if self.client_attempts_started:
            raise CoordinatorError("RETRY_PROHIBITED", "this coordinator has already attempted its single request")
        request = ("GET http://127.0.0.1:8000/test-cancel HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n"
                   "Connection: close\r\nX-MCP-Test-Run: "+self.run_id+"\r\nX-MCP-Server-Identity: "+self.server_identity+
                   "\r\nX-MCP-Test-ID: "+case+"\r\n\r\n").encode("ascii")
        output = queue.Queue(maxsize=1)
        self.client_attempts_started = 1
        self.report.update(case=case, clientEvidence=str(self.client_path), state="REQUEST_INTENT_SAVED")
        self.save()
        def worker():
            try:
                value = capture_once(request, self.client_path)
                output.put((True, value))
            except BaseException as error:
                output.put((False, {"outcome": "EVIDENCE_CAPTURE_FAILED", "errorType": type(error).__name__}))
        thread = threading.Thread(target=worker, daemon=True)
        self.active_workers.append(thread)
        thread.start()
        return output

    def run_single(self):
        try:
            snapshot = self._snapshot(self.client)
            self.run_id, self.server_identity = self._validate_initial(snapshot)
            if snapshot["interception"]["enabled"]:
                raise CoordinatorError("UNEXPECTED_SESSION", "interception must be off before one-shot setup")
            self.report["authorizationReference"] = self.run_id
            self.report["initialQueuesEmpty"] = True
            self.save()
            self._start_fixture()
            self.start_session(60)
            case = "phase4a-"+uuid.uuid4().hex
            output = self.one_client(case)
            ticket = self.pending("request", "/test-cancel")
            if ticket["method"] != "GET" or ticket["revision"] != 0:
                raise CoordinatorError("UNEXPECTED_MESSAGE", "expected the unmodified synthetic GET")
            self.report["interception"] = {key: ticket.get(key) for key in ("id", "revision", "method", "hostname", "urlPath", "remainingMillis")}
            self.save()
            self.health()
            approval = self.tool("burp_drop_intercepted_request", id=ticket["id"])
            self.report["dropResult"] = approval
            self.save()
            self.report["dropEvent"] = self.event(ticket, "intercept_drop", "dropped")
            self.report["approvalDecision"] = self.event(ticket, "unattended_local_test", "auto_approved")
            self.save()
            try:
                okay, observation = output.get(timeout=20)
            except queue.Empty:
                raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "one-shot worker exceeded its observation bound; no retry")
            self.report["client"] = observation
            self.save()
            if not okay:
                raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "terminal metadata could not be durably saved")
            persisted = json.loads(self.client_path.read_text(encoding="utf-8"))
            self.report["clientEvidenceMatches"] = persisted == observation
            self.report["originDeliveries"] = self.origin_count("/test-cancel")
            self.assert_empty()
            self.report["queuesEmptyAfterDrop"] = True
            self.report["staleIdRejected"] = self.stale(ticket)
            self.report["checks"] = {
                "exactApprovedDrop": isinstance(approval, str) and approval.startswith("DROPPED") and
                    "operation=DROP_REQUEST" in self.report["approvalDecision"]["detail"],
                "actualDropState": self.report["dropEvent"]["outcome"] == "dropped",
                "originZeroDelivery": self.report["originDeliveries"] == 0,
                "completeTerminalObservation": admissible_terminal(observation),
                "terminalEvidenceRetained": self.report["clientEvidenceMatches"],
                "staleIdRejected": self.report["staleIdRejected"],
                "queuesEmpty": self.report["queuesEmptyAfterDrop"],
                "singleAttempt": self.client_attempts_started == 1,
            }
            self.save()
            if not all(self.report["checks"].values()):
                raise CoordinatorError("INCONCLUSIVE", "one or more required cancellation conditions were not established")
            self.report["state"] = "VERIFIED_PENDING_CLEANUP"
        except Exception as error:
            self.report.update(state="BLOCKED" if not self.client_attempts_started else "INCONCLUSIVE",
                               failureCode=getattr(error, "code", "ERROR"), errorType=type(error).__name__, diagnostic=str(error)[:300])
        finally:
            # The worker owns a separate durable outcome file even if setup/approval fails.
            for worker in self.active_workers:
                worker.join(timeout=17)
            if self.client_path.exists():
                try:
                    self.report["client"] = json.loads(self.client_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    self.report["clientEvidenceUnreadable"] = True
            self.save()  # Always precedes fixture/session cleanup.
            try:
                status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
                if status["enabled"] and not status["pendingRequests"] and not status["pendingResponses"]:
                    self.health()
                    self.tool("burp_set_live_interception_state", enabled=False)
                final = self.tool("burp_get_intercept_status", includeDiagnostics=False)
                self.report["cleanup"] = {key: final.get(key) for key in ("enabled", "sessionEndReason", "pendingRequests", "pendingResponses")}
            except Exception as error:
                self.report["cleanupErrorType"] = type(error).__name__
            self._stop_fixture()
            try:
                connection = socket.create_connection(("127.0.0.1", 8000), timeout=.5)
            except OSError:
                self.report["fixtureStopped"] = True
            else:
                connection.close()
                self.report["fixtureStopped"] = False
            cleanup = self.report.get("cleanup", {})
            if (self.report["state"] == "VERIFIED_PENDING_CLEANUP" and self.report["fixtureStopped"]
                    and cleanup.get("enabled") is False and cleanup.get("pendingRequests") == 0 and cleanup.get("pendingResponses") == 0):
                self.report["state"] = "PASS"
            elif self.report["state"] == "VERIFIED_PENDING_CLEANUP":
                self.report["state"] = "INCONCLUSIVE"
            self.save()
        return self.report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait-for-activation", action="store_true")
    parser.add_argument("--final-regression", action="store_true")
    args = parser.parse_args()
    client = preflight.initialize(preflight.McpClient(timeout=3))
    if args.wait_for_activation:
        status = client.tool("burp_get_intercept_status", includeDiagnostics=False)
        if status["enabled"] or status["unattendedMode"]["active"]:
            raise SystemExit("Fresh activation required after arming; no traffic sent")
        print("ARMED: exactly one Phase 4A request after fresh local activation", flush=True)
        deadline = time.monotonic()+900
        while time.monotonic() < deadline:
            if client.tool("burp_get_intercept_status", includeDiagnostics=False)["unattendedMode"]["active"]:
                break
            time.sleep(1)
        else:
            raise SystemExit("Activation wait expired; no traffic sent")
    coordinator = Phase4A(client)
    result = coordinator.run_single()
    print(json.dumps({"state": result["state"], "attempts": result["clientAttempts"], "client": result.get("client"),
                      "report": str(coordinator.report_path)}), flush=True)
    if args.final_regression and result["clientAttempts"] == 1:
        regression_path = coordinator.report_path.with_suffix(".full-regression.json")
        if regression_path.exists():
            raise SystemExit("Final regression already has an intent/result record; no automatic rerun")
        root = Path(__file__).resolve().parents[1]
        jar = root / "build/libs/burp-mcp-all.jar"
        before = hashlib.file_digest(jar.open("rb"), "sha256").hexdigest()
        previous_reports = set((root / "build/reports/full-validation").glob("*.json"))
        regression = {"state": "RUNNING", "phase4AState": result["state"], "jarBeforeSha256": before,
                      "mode": "LOCAL", "fullSuiteAttempts": 1, "liveBurpTestsRepeated": False}
        atomic_json(regression_path, regression)
        print("FINAL REGRESSION: one full local/offline suite, JAR packaging excluded", flush=True)
        try:
            with coordinator.report_path.with_suffix(".full-regression.log").open("wb") as output:
                completed = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                     str(root / "scripts/run-full-validation.ps1"), "-Mode", "LOCAL", "-ForceTestExecution",
                     "-OverallTimeoutSeconds", "900", "-PerTestTimeoutSeconds", "600"],
                    cwd=root, stdout=output, stderr=subprocess.STDOUT, timeout=930,
                    creationflags=subprocess.CREATE_NO_WINDOW, check=False)
            after = hashlib.file_digest(jar.open("rb"), "sha256").hexdigest()
            regression.update(jarAfterSha256=after, jarUnchanged=before == after, exitCode=completed.returncode,
                              state="PASS" if completed.returncode == 0 and before == after else "FAIL")
            reports = set((root / "build/reports/full-validation").glob("*.json")) - previous_reports
            regression["validationReports"] = [str(path) for path in sorted(reports)]
        except Exception as error:
            regression.update(state="INCONCLUSIVE", errorType=type(error).__name__)
        atomic_json(regression_path, regression)
        print(json.dumps({"finalRegression": regression["state"], "report": str(regression_path)}), flush=True)


if __name__ == "__main__":
    main()
