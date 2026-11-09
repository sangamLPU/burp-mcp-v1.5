import json
import queue
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

from live_reliability_coordinator import ReliabilityCoordinator, decode_tool_result, aggregate_phase_status
from live_rule_engine_coordinator import CoordinatorError, EXPECTED_BUILD_ID


class ReliabilityCoordinatorTests(unittest.TestCase):
    def test_malformed_tool_envelopes_never_count_as_success(self):
        for result in ({}, {"content": []}, {"content": None}, {"content": [{}]},
                       {"content": [{"type": "image", "text": "ok"}]},
                       {"content": [{"text": 3}]}, {"content": [{"text": ""}]},
                       {"isError": 0, "content": [{"text": "ok"}]},
                       {"structuredContent": {"ok": True}, "content": [{"text": "ok"}]},
                       {"error": {"code": 1}, "content": [{"text": "ok"}]}):
            with self.subTest(result=result), self.assertRaises(CoordinatorError):
                decode_tool_result(result)

    def test_unexpected_approval_or_denial_text_is_not_a_completed_action(self):
        for message in ("Approval required.", "Denied: no approval.", "Tool failed (TimeoutException)."):
            with self.subTest(message=message), self.assertRaises(CoordinatorError):
                decode_tool_result({"content": [{"type": "text", "text": message}]})

    def test_report_build_matches_shared_runtime_gate_without_starting_work(self):
        runner = ReliabilityCoordinator(object())
        self.assertEqual(runner.report['buildId'], EXPECTED_BUILD_ID)
        self.assertEqual(runner.client_attempts_started, 0)
        self.assertEqual(runner.report['phases'], [])

    def test_partial_or_inconclusive_phase_cannot_be_reported_as_overall_pass(self):
        phases = [{"phase": name, "state": "PASS"} for name in ("4A", "4B", "4C", "4D")]
        self.assertEqual("PASS", aggregate_phase_status(phases))
        self.assertEqual("INCONCLUSIVE", aggregate_phase_status(phases[1:]))
        phases[0]["state"] = "INCONCLUSIVE"
        self.assertEqual("INCONCLUSIVE", aggregate_phase_status(phases))

    def test_plain_terminal_tool_results_are_not_misclassified_as_json_errors(self):
        result = {"content": [{"type": "text", "text": "DROPPED: local callback released"}]}
        self.assertTrue(decode_tool_result(result).startswith("DROPPED"))
        self.assertEqual({"enabled": False}, decode_tool_result({"content": [{"type": "text", "text": '{"enabled":false}'}]}))
        with self.assertRaises(CoordinatorError):
            decode_tool_result({"isError": True, "content": [{"text": "rejected"}]})

    def test_expired_or_mismatched_identity_prevents_network_work(self):
        runner = ReliabilityCoordinator(object())
        runner.run_id, runner.server_identity = "run", "identity"
        for mode in ({"active": False}, {"active": True, "testRunId": "different"},
                     {"active": True, "testRunId": "run", "serverIdentity": "identity", "remainingMillis": 1}):
            with patch.object(runner, "tool", return_value={"unattendedMode": mode}):
                with patch("live_reliability_coordinator.http.client.HTTPConnection") as network:
                    with self.assertRaises(CoordinatorError):
                        runner.send("/test-cancel", "synthetic")
                    network.assert_not_called()
        self.assertEqual(0, runner.client_attempts_started)

    def test_native_or_existing_queue_is_never_silently_cleared(self):
        runner = ReliabilityCoordinator(object())
        with patch.object(runner, "tool", return_value=[{"id": "existing"}]) as tool:
            with self.assertRaises(CoordinatorError):
                runner.assert_empty()
        self.assertEqual(["burp_list_pending_requests", "burp_list_pending_responses"], [call.args[0] for call in tool.call_args_list])

    def test_short_authorization_cannot_start_a_session(self):
        runner = ReliabilityCoordinator(object())
        with patch.object(runner, "health", side_effect=CoordinatorError("AUTHORIZATION_EXPIRED", "expired")):
            with patch.object(runner, "tool") as tool:
                with self.assertRaises(CoordinatorError):
                    runner.start_session(180)
                tool.assert_not_called()

    def test_client_socket_error_has_one_attempt_and_is_not_retried(self):
        runner = ReliabilityCoordinator(object())
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory) / "report.json"
            with patch.object(runner, "health"):
                with patch("live_reliability_coordinator.http.client.HTTPConnection") as connection:
                    connection.return_value.request.side_effect = ConnectionResetError()
                    result = runner.send("/test-cancel", "synthetic").get(timeout=2)
                    self.assertEqual("ConnectionResetError", result["errorType"])
                    self.assertEqual(1, connection.return_value.request.call_count)
                    self.assertEqual(1, runner.client_attempts_started)

    def test_timeout_is_ambiguous_and_success_is_not_cancellation_evidence(self):
        runner = ReliabilityCoordinator(object())
        output = queue.Queue()
        output.put({"errorType": "TimeoutError"})
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory) / "report.json"
            with self.assertRaises(CoordinatorError):
                runner.terminal_client(output)
            saved = json.loads(runner.report_path.read_text())
            self.assertEqual("TimeoutError", saved["clientOutcomes"][0]["errorType"])
        with self.assertRaises(CoordinatorError):
            runner.assert_cancelled_client({"status": 200})
        runner.assert_cancelled_client({"status": 400})
        runner.assert_cancelled_client({"errorType": "RemoteDisconnected"})

    def test_proxy_generated_200_requires_complete_metadata_and_no_fixture_json(self):
        proxy = {"status": 200, "bytes": 400, "bodySha256": "a" * 64, "json": None}
        ReliabilityCoordinator.assert_cancelled_client(proxy)
        with self.assertRaises(CoordinatorError):
            ReliabilityCoordinator.assert_cancelled_client({**proxy, "json": {"serverVerified": True}})
        with self.assertRaises(CoordinatorError):
            ReliabilityCoordinator.assert_cancelled_client({**proxy, "bodySha256": ""})

    def test_rejected_client_observation_is_preserved_before_classification(self):
        runner = ReliabilityCoordinator(object())
        output = queue.Queue()
        output.put({"status": 200, "json": {"path": "/test-cancel"}, "bytes": 24, "bodySha256": "a" * 64})
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory) / "report.json"
            result = runner.terminal_client(output)
            with self.assertRaises(CoordinatorError):
                runner.assert_cancelled_client(result)
            saved = json.loads(runner.report_path.read_text())
            self.assertEqual(200, saved["clientOutcomes"][0]["status"])

    def test_approval_failure_never_forwards_response(self):
        runner = ReliabilityCoordinator(object())
        ticket = {"id": "response", "revision": 0, "hostname": "127.0.0.1", "urlPath": "/test-concurrent-b"}
        with patch.object(runner, "health"):
            with patch.object(runner, "tool", side_effect=CoordinatorError("TOOL_REJECTED", "approval unavailable")) as tool:
                with self.assertRaises(CoordinatorError) as error:
                    runner.authorize_forward(ticket, "response")
                self.assertEqual("WAITING_FOR_APPROVAL", error.exception.code)
                self.assertEqual(["burp_approve_intercepted_response_edit"], [call.args[0] for call in tool.call_args_list])

    def test_stale_operations_must_all_fail_before_a_phase_can_pass(self):
        class Client:
            def __init__(self): self.calls = []
            def rpc(self, method, arguments):
                self.calls.append(arguments)
                return {"isError": True}
        client = Client()
        self.assertTrue(ReliabilityCoordinator(client).stale({"id": "terminal", "revision": 1}))
        self.assertEqual(3, len(client.calls))

    def test_partial_evidence_survives_later_failure(self):
        runner = ReliabilityCoordinator(object())
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory) / "report.json"
            runner.record_phase("4A", {"originDeliveries": 0})
            with patch.object(runner, "_snapshot", side_effect=RuntimeError("next phase failure")):
                with patch.object(runner, "_stop_fixture"):
                    result = runner.run_phases()
            saved = json.loads(runner.report_path.read_text())
            self.assertEqual("ERROR", result["state"])
            self.assertEqual("4A", saved["phases"][0]["phase"])

    def test_concurrent_sequence_keeps_A_held_while_B_is_edited_and_completed(self):
        class Simulation(ReliabilityCoordinator):
            def __init__(self):
                super().__init__(object())
                self.requests, self.responses, self.outputs, self.cases, self.deliveries = {}, {}, {}, {}, []
            def send(self, path, case, body=None):
                ticket = {"id": path, "revision": 0, "approvedRevision": None,
                          "hostname": "127.0.0.1", "urlPath": path}
                self.requests[path] = ticket
                self.outputs[path] = queue.Queue()
                self.cases[path] = case
                return self.outputs[path]
            def pending(self, kind, path, timeout=5):
                return dict((self.requests if kind == "request" else self.responses)[path])
            def tool(self, name, **args):
                if name == "burp_list_pending_requests": return list(self.requests.values())
                if name == "burp_list_pending_responses": return list(self.responses.values())
                if name == "burp_get_intercepted_request": return self.requests[args["id"]]
                if name == "burp_propose_intercepted_request_edit":
                    fields = parse_qs(args["body"])
                    self.test.assertEqual(self.cases[args["id"]], fields["test_id"][0])
                    ticket = self.requests[args["id"]]
                    ticket["revision"] += 1
                    self.test.assertTrue(fields["mcp_test"][0].endswith("-modified"))
                    return dict(ticket)
                raise AssertionError(name)
            def authorize_forward(self, ticket, kind):
                path = ticket["urlPath"]
                if kind == "request":
                    self.responses[path] = {**self.requests.pop(path), "id": "response-"+path, "revision": 0}
                    self.deliveries.append({"concurrentTestId": self.cases[path], "concurrentBodyVerified": True, "bodySha256": "synthetic"})
                else:
                    self.responses.pop(path)
                    self.outputs[path].put({"status": 200, "json": {"TestId": self.cases[path], "ServerVerified": True}})
                return {"outcome": "auto_approved"}
            def records(self): return self.deliveries
            def stale(self, ticket, kind="request"): return True
        runner = Simulation()
        runner.test = self
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory) / "report.json"
            runner.concurrency()
        result = runner.report["phases"][0]
        self.assertEqual("4D", result["phase"])
        self.assertEqual(["B", "A"], result["releaseOrder"])
        self.assertEqual(2, len(result["exchanges"]))
        self.assertTrue(result["mixedRequestResponseQueueVerified"])


if __name__ == "__main__":
    unittest.main()
