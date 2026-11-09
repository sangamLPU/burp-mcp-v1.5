import json
from pathlib import Path
import queue
import tempfile
import unittest
from unittest.mock import patch

from cancellation_client import atomic_json, classify_response
from phase4a_final import Phase4A


class Simulation(Phase4A):
    def _snapshot(self, client): return {"interception": {"enabled": False}}
    def _validate_initial(self, snapshot): return "synthetic-run", "synthetic-identity"
    def _start_fixture(self): pass
    def _stop_fixture(self): self.cleanup_seen_client_file = self.client_path.exists()
    def start_session(self, seconds): self.enabled = True
    def health(self, minimum_ms=5000): pass
    def pending(self, kind, path, timeout=5):
        return {"id": "intercept-one", "revision": 0, "method": "GET", "hostname": "127.0.0.1", "urlPath": "/test-cancel"}
    def assert_empty(self): pass
    def stale(self, ticket, kind="request"): return True
    def origin_count(self, path): return self.origin_deliveries
    def event(self, ticket, action, outcome):
        return {"action": action, "outcome": outcome, "detail": "operation=DROP_REQUEST message=intercept-one"}
    def tool(self, name, **args):
        if name == "burp_drop_intercepted_request": return "DROPPED: exact revision"
        if name == "burp_set_live_interception_state": self.enabled = args["enabled"]
        return {"enabled": self.enabled, "pendingRequests": 0, "pendingResponses": 0, "sessionEndReason": "DISABLED"}
    def one_client(self, case):
        self.client_attempts_started += 1
        atomic_json(self.client_path, self.observation)
        q = queue.Queue(); q.put((True, self.observation)); return q


class Phase4AFinalTests(unittest.TestCase):
    def run_simulation(self, observation, origin=0):
        runner = Simulation(object()); runner.origin_deliveries = origin; runner.observation = observation
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory)/"report.json"
            runner.client_path = Path(directory)/"client.json"
            with patch("phase4a_final.socket.create_connection", side_effect=ConnectionRefusedError()):
                result = runner.run_single()
            saved = json.loads(runner.report_path.read_text())
            self.assertEqual(result, saved)
            self.assertTrue(runner.cleanup_seen_client_file)
            self.assertEqual(1, result["clientAttempts"])
        return result

    def test_complete_proxy_200_passes_only_with_all_independent_conditions(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        result = self.run_simulation(classify_response(wire, "FRAMING_COMPLETE"))
        self.assertEqual("PASS", result["state"])
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual("intercept-one", result["interception"]["id"])

    def test_complete_client_response_cannot_hide_actual_origin_delivery(self):
        result = self.run_simulation(classify_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "EOF"), origin=1)
        self.assertEqual("INCONCLUSIVE", result["state"])
        self.assertFalse(result["checks"]["originZeroDelivery"])

    def test_partial_client_response_stays_inconclusive_and_is_retained(self):
        result = self.run_simulation(classify_response(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 5\r\n\r\nx", "EOF"))
        self.assertEqual("INCONCLUSIVE", result["state"])
        self.assertEqual(1, result["client"]["bodyBytes"])

    def test_evidence_write_failure_cannot_become_success(self):
        runner = Phase4A(object())
        runner.run_id, runner.server_identity = "run", "identity"
        with tempfile.TemporaryDirectory() as directory:
            runner.report_path = Path(directory)/"report.json"; runner.client_path = Path(directory)/"client.json"
            with patch.object(runner, "health"):
                with patch("phase4a_final.capture_once", side_effect=OSError("disk failure")):
                    okay, observation = runner.one_client("phase4a-synthetic").get(timeout=2)
                    self.assertFalse(okay)
                    self.assertEqual("EVIDENCE_CAPTURE_FAILED", observation["outcome"])
                    with self.assertRaises(Exception): runner.one_client("phase4a-another")


if __name__ == "__main__": unittest.main()
