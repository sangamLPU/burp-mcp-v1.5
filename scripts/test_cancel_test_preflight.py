import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from cancel_test_preflight import (
    EXPECTED_BUILD_ID,
    INTERCEPTED_MESSAGE_TIMEOUT_MS,
    CLIENT_OBSERVATION_DEADLINE_MS,
    POST_REQUEST_SAFETY_MARGIN_MS,
    MIN_REMAINING_MS,
    MIN_SETUP_AUTHORIZATION_MS,
    TARGET_URL,
    LOCAL_TEST_URLS,
    discover_active_identities,
    drop_matching_request,
    initialize,
    main,
    start_supervised_session,
    run_preflight,
    run_setup_preflight,
    validate_mcp_snapshot,
    validate_setup_snapshot,
)

ACTIVE_RUN_ID = "11111111-2222-3333-4444-555555555555"
ACTIVE_SERVER_IDENTITY = "A" * 43


def valid_snapshot():
    return {
        "connection": {
            "burpConnected": True,
            "serverState": "running",
            "burpVersion": "Burp Suite Professional 2024.1.1.1-26891",
        },
        "server": {
            "serverState": "running",
            "lastError": None,
            "buildId": EXPECTED_BUILD_ID,
            "bearerAuthenticationRequired": True,
            "readOnlyMode": False,
        },
        "scope": {
            "checks": [{
                "url": TARGET_URL,
                "inBurpScope": True,
                "hostAllowlisted": True,
                "eligible": True,
            }],
        },
        "interception": {
            "enabled": True,
            "heartbeatHealth": "HEALTHY",
            "timeoutSeconds": 120,
            "sessionLifetimeSeconds": 300,
            "sessionRemainingMillis": 299_000,
            "leaseRemainingMillis": 14_000,
            "sessionEndReason": "NONE",
            "pendingRequests": 0,
            "pendingResponses": 0,
            "unattendedMode": {
                "active": True,
                "remainingMillis": 299_000,
                "testRunId": ACTIVE_RUN_ID,
                "serverIdentity": ACTIVE_SERVER_IDENTITY,
            },
        },
        "requests": [],
        "responses": [],
    }


def valid_setup_snapshot():
    snapshot = valid_snapshot()
    snapshot["interception"].update({
        "enabled": False,
        "heartbeatHealth": "STOPPED",
        "sessionRemainingMillis": 0,
        "leaseRemainingMillis": 0,
        "sessionEndReason": "DISABLED",
        "unattendedMode": {
            "active": True,
            "remainingMillis": 299_000,
            "testRunId": "11111111-2222-3333-4444-555555555555",
            "serverIdentity": "A" * 43,
        },
    })
    return snapshot


def all_scope_snapshot(snapshot=None):
    current = valid_setup_snapshot() if snapshot is None else snapshot
    current["scope"] = {"checks": [
        {"url": url, "inBurpScope": True, "hostAllowlisted": True, "eligible": True}
        for url in LOCAL_TEST_URLS
    ]}
    current["server"]["authorizedTargetCount"] = 1
    return current


class FakeDropClient:
    def __init__(self):
        self.dropped = False
        self.calls = []
        self.ticket = {
            "id": "request-123", "kind": "request", "revision": 0,
            "method": "GET", "hostname": "127.0.0.1", "urlPath": "/test-cancel",
        }

    def tool(self, name, **arguments):
        self.calls.append((name, arguments))
        if name == "burp_list_pending_requests":
            return [] if self.dropped else [self.ticket]
        if name == "burp_list_pending_responses":
            return []
        if name == "burp_get_intercept_status":
            result = valid_snapshot()["interception"]
            result["pendingRequests"] = 0 if self.dropped else 1
            return result
        if name == "burp_get_scope":
            return {"checks": [{"url": TARGET_URL, "inBurpScope": True,
                                "hostAllowlisted": True, "eligible": True}]}
        if name == "burp_get_intercept_diagnostics":
            return {"events": [
                {"action": "intercept_drop", "outcome": "dropped",
                 "detail": "request request-123 revision=0"},
                {"action": "unattended_local_test", "outcome": "auto_approved",
                 "detail": "operation=DROP_REQUEST path=/test-cancel message=request-123 revision=0"},
            ]}
        raise AssertionError(f"Unexpected MCP tool in offline regression: {name}")

    def rpc(self, method, params=None, notification=False):
        self.calls.append((method, params))
        name = params["name"]
        if name == "burp_drop_intercepted_request":
            self.dropped = True
            return {"isError": False, "content": [{"type": "text", "text": "DROPPED: locally approved message drop."}]}
        return {"isError": True, "content": [{"type": "text", "text": "stale request ID"}]}


class FakeInitializeClient:
    def __init__(self):
        self.calls = []
        self._protocol_version = None

    def rpc(self, method, params=None, notification=False):
        self.calls.append((method, params, notification))
        if method == "initialize":
            return {"protocolVersion": "2025-03-26"}
        return None


def has_failure_prefix(failures, prefix):
    return any(failure.startswith(prefix) for failure in failures)


class CancellationPreflightTests(unittest.TestCase):
    def test_cli_reports_unexpected_preflight_failure_without_traceback_or_secret_text(self):
        error_output = StringIO()
        with patch("cancel_test_preflight.initialize", side_effect=RuntimeError("synthetic private detail")):
            with redirect_stderr(error_output):
                exit_code = main(["--coordinator-identities", "180"])
        self.assertEqual(3, exit_code)
        self.assertIn("internal preflight error (RuntimeError)", error_output.getvalue())
        self.assertNotIn("Traceback", error_output.getvalue())
        self.assertNotIn("synthetic private detail", error_output.getvalue())
    def test_initialize_constructs_the_default_authenticated_mcp_client(self):
        fake = FakeInitializeClient()
        with patch("cancel_test_preflight.McpClient", return_value=fake) as factory:
            result = initialize()
        factory.assert_called_once_with()
        self.assertIs(fake, result)
        self.assertEqual("2025-03-26", result._protocol_version)
        self.assertEqual("initialize", result.calls[0][0])
        self.assertEqual("notifications/initialized", result.calls[1][0])
        self.assertTrue(result.calls[1][2])

    def test_initialize_reuses_an_explicit_client(self):
        fake = FakeInitializeClient()
        with patch("cancel_test_preflight.McpClient") as factory:
            result = initialize(fake)
        factory.assert_not_called()
        self.assertIs(fake, result)

    def test_all_prerequisites_pass(self):
        self.assertEqual([], validate_mcp_snapshot(valid_snapshot()))

    def test_coordinator_accepts_180_second_session_when_150_second_deadline_budget_remains(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["sessionLifetimeSeconds"] = 180
        snapshot["interception"]["sessionRemainingMillis"] = 176_000
        self.assertEqual([], validate_mcp_snapshot(
            snapshot,
            unattended_run_id=ACTIVE_RUN_ID,
            unattended_server_identity=ACTIVE_SERVER_IDENTITY,
            minimum_session_lifetime_seconds=180,
        ))

    def test_shorter_session_is_rejected_against_requested_minimum(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["sessionLifetimeSeconds"] = 150
        self.assertIn(
            "Live interception lifetime is below the requested 180-second minimum",
            validate_mcp_snapshot(snapshot, minimum_session_lifetime_seconds=180),
        )

    def test_identity_discovery_requires_all_nine_fixed_targets_and_matching_mode(self):
        snapshot = all_scope_snapshot()
        with patch("cancel_test_preflight.initialize", return_value=object()):
            with patch("cancel_test_preflight.read_mcp_snapshot", return_value=snapshot):
                identities = discover_active_identities(195_000)
        self.assertEqual(ACTIVE_RUN_ID, identities["testRunId"])
        self.assertEqual(ACTIVE_SERVER_IDENTITY, identities["serverIdentity"])
        self.assertEqual(9, identities["scopeEligibleCount"])
        self.assertNotIn("token", identities)

    def test_identity_discovery_fails_closed_if_any_local_target_is_ineligible(self):
        snapshot = all_scope_snapshot()
        snapshot["scope"]["checks"][2]["eligible"] = False
        with patch("cancel_test_preflight.initialize", return_value=object()):
            with patch("cancel_test_preflight.read_mcp_snapshot", return_value=snapshot):
                with self.assertRaisesRegex(Exception, "one or more fixed localhost targets"):
                    discover_active_identities(195_000)

    def test_session_start_requires_eligible_policy_budget_before_tool_call(self):
        snapshot = all_scope_snapshot()
        snapshot["interception"]["unattendedMode"]["remainingMillis"] = 189_999
        client = FakeDropClient()
        with patch("cancel_test_preflight.initialize", return_value=client):
            with patch("cancel_test_preflight.read_mcp_snapshot", return_value=snapshot):
                with patch("cancel_test_preflight.unattended_identity_from_environment",
                           return_value=(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)):
                    with self.assertRaisesRegex(Exception, "no session was requested"):
                        start_supervised_session(180)
        self.assertFalse(any(
            call[0] == "burp_set_live_interception_state" for call in client.calls
        ))

    def test_session_start_uses_bounded_180_second_policy_and_verifies_deadline(self):
        setup = all_scope_snapshot()
        setup["interception"]["unattendedMode"]["remainingMillis"] = 250_000
        client = FakeDropClient()
        status = valid_snapshot()["interception"]
        status.update({"sessionLifetimeSeconds": 180, "sessionRemainingMillis": 176_000})
        client.tool = lambda name, **arguments: status if name == "burp_get_intercept_status" else None
        with patch("cancel_test_preflight.initialize", return_value=client):
            with patch("cancel_test_preflight.read_mcp_snapshot", return_value=setup):
                with patch("cancel_test_preflight.unattended_identity_from_environment",
                           return_value=(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)):
                    result = start_supervised_session(180)
        self.assertTrue(result["enabled"])
        self.assertEqual(180, result["sessionLifetimeSeconds"])

    def test_one_exact_held_request_is_dropped_and_stale_operations_are_rejected(self):
        client = FakeDropClient()
        with patch("cancel_test_preflight.initialize", return_value=client):
            with patch("cancel_test_preflight.unattended_identity_from_environment",
                       return_value=(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)):
                result = drop_matching_request(wait_seconds=1)
        self.assertEqual("DROPPED", result["dropState"])
        self.assertEqual("AUTOMATIC", result["approvalMode"])
        self.assertTrue(result["staleGetRejected"])
        self.assertTrue(result["staleEditRejected"])
        self.assertTrue(result["staleForwardRejected"])
        self.assertEqual(1, sum(
            call[1].get("name") == "burp_drop_intercepted_request"
            for call in client.calls if call[0] == "tools/call"
        ))

    def test_drop_wait_refuses_nonmatching_message_without_invoking_drop(self):
        client = FakeDropClient()
        client.ticket["urlPath"] = "/test-post"
        with patch("cancel_test_preflight.initialize", return_value=client):
            with patch("cancel_test_preflight.unattended_identity_from_environment",
                       return_value=(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)):
                with self.assertRaisesRegex(Exception, "not the exact synthetic cancellation target"):
                    drop_matching_request(wait_seconds=1)
        self.assertFalse(any(
            call[1].get("name") == "burp_drop_intercepted_request"
            for call in client.calls if call[0] == "tools/call"
        ))

    def test_expired_or_absent_session_fails(self):
        snapshot = valid_snapshot()
        snapshot["interception"].update({
            "enabled": False,
            "heartbeatHealth": "EXPIRED",
            "sessionRemainingMillis": 0,
            "sessionEndReason": "SESSION_EXPIRED",
        })
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn("Live interception is not active", failures)
        self.assertIn("Live interception heartbeat is not healthy", failures)
        self.assertIn("Live interception has less than 150s remaining", " ".join(failures))

    def test_insufficient_remaining_time_fails(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["sessionRemainingMillis"] = 149_999
        failures = validate_mcp_snapshot(snapshot)
        self.assertTrue(any(
            failure.startswith("Live interception has less than 150s remaining")
            for failure in failures
        ))

    def test_deadline_budget_is_derived_from_client_deadline_and_safety_margin(self):
        self.assertEqual(120_000, INTERCEPTED_MESSAGE_TIMEOUT_MS)
        self.assertEqual(125_000, CLIENT_OBSERVATION_DEADLINE_MS)
        self.assertEqual(25_000, POST_REQUEST_SAFETY_MARGIN_MS)
        self.assertEqual(150_000, MIN_REMAINING_MS)

    def test_preflight_rejects_a_message_timeout_above_the_validated_budget(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["timeoutSeconds"] = 180
        self.assertIn(
            "Interception message timeout is not the validated 120-second limit",
            validate_mcp_snapshot(snapshot),
        )

    def test_session_deadline_boundaries_300_240_180_150_120_seconds(self):
        threshold_failure = "Live interception has less than 150s remaining"
        for remaining_seconds in (300, 240, 180, 150, 120):
            with self.subTest(session_remaining_seconds=remaining_seconds):
                snapshot = valid_snapshot()
                snapshot["interception"]["sessionRemainingMillis"] = remaining_seconds * 1000
                snapshot["interception"]["unattendedMode"]["remainingMillis"] = 300_000
                failures = validate_mcp_snapshot(
                    snapshot,
                    unattended_run_id=ACTIVE_RUN_ID,
                    unattended_server_identity=ACTIVE_SERVER_IDENTITY,
                )
                if remaining_seconds >= 150:
                    self.assertFalse(has_failure_prefix(failures, threshold_failure))
                else:
                    self.assertTrue(has_failure_prefix(failures, threshold_failure))

    def test_unattended_authorization_deadline_boundaries_300_240_180_150_120_seconds(self):
        threshold_failure = "Unattended authorization has less than 150s remaining"
        for remaining_seconds in (300, 240, 180, 150, 120):
            with self.subTest(authorization_remaining_seconds=remaining_seconds):
                snapshot = valid_snapshot()
                snapshot["interception"]["sessionRemainingMillis"] = 300_000
                snapshot["interception"]["unattendedMode"]["remainingMillis"] = remaining_seconds * 1000
                failures = validate_mcp_snapshot(
                    snapshot,
                    unattended_run_id=ACTIVE_RUN_ID,
                    unattended_server_identity=ACTIVE_SERVER_IDENTITY,
                )
                if remaining_seconds >= 150:
                    self.assertFalse(has_failure_prefix(failures, threshold_failure))
                else:
                    self.assertTrue(has_failure_prefix(failures, threshold_failure))

    def test_session_and_authorization_expiry_are_checked_independently(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["sessionRemainingMillis"] = 300_000
        snapshot["interception"]["unattendedMode"]["remainingMillis"] = 120_000
        failures = validate_mcp_snapshot(snapshot)
        self.assertFalse(has_failure_prefix(failures, "Live interception has less than 150s remaining"))
        self.assertTrue(has_failure_prefix(failures, "Unattended authorization has less than 150s remaining"))

        snapshot["interception"]["sessionRemainingMillis"] = 120_000
        snapshot["interception"]["unattendedMode"]["remainingMillis"] = 300_000
        failures = validate_mcp_snapshot(snapshot)
        self.assertTrue(has_failure_prefix(failures, "Live interception has less than 150s remaining"))
        self.assertFalse(has_failure_prefix(failures, "Unattended authorization has less than 150s remaining"))

    def test_scope_and_allowlist_are_independent_requirements(self):
        snapshot = valid_snapshot()
        snapshot["scope"]["checks"][0]["hostAllowlisted"] = False
        snapshot["scope"]["checks"][0]["eligible"] = False
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn("/test-cancel host is not in the MCP allowlist", failures)
        self.assertIn("/test-cancel is not eligible", failures)

    def test_nonempty_or_unavailable_queues_fail(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["pendingRequests"] = 1
        snapshot["requests"] = [{"id": "held"}]
        snapshot["responses"] = None
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn("Interception request queue is not empty", failures)
        self.assertIn("Pending request listing is missing or non-empty", failures)
        self.assertIn("Pending response listing is missing or non-empty", failures)

    def test_wrong_build_or_burp_version_fails(self):
        snapshot = valid_snapshot()
        snapshot["server"]["buildId"] = "stale-build"
        snapshot["connection"]["burpVersion"] = "Burp Suite Professional 2023.1"
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn(f"Loaded extension build does not match expected build {EXPECTED_BUILD_ID}", failures)
        self.assertIn("Burp version does not match Professional 2024.1.1.1", failures)

    def test_missing_snapshot_fails_closed(self):
        failures = validate_mcp_snapshot({})
        self.assertTrue(failures)
        self.assertIn("Live interception is not active", failures)

    def test_unattended_preflight_requires_current_matching_burp_and_server_identity(self):
        snapshot = valid_snapshot()
        self.assertEqual([], validate_mcp_snapshot(
            snapshot, unattended_run_id=ACTIVE_RUN_ID, unattended_server_identity=ACTIVE_SERVER_IDENTITY
        ))
        self.assertIn("Supplied test identity does not match the active Burp-local authorization", validate_mcp_snapshot(
            snapshot, unattended_run_id=ACTIVE_RUN_ID, unattended_server_identity="B" * 43
        ))
        snapshot["interception"]["unattendedMode"]["active"] = False
        self.assertIn("Unattended local test mode is not active", validate_mcp_snapshot(
            snapshot, unattended_run_id=ACTIVE_RUN_ID, unattended_server_identity=ACTIVE_SERVER_IDENTITY
        ))

    def test_final_preflight_uses_one_snapshot_after_local_checks(self):
        with patch("cancel_test_preflight.initialize", return_value=object()) as initialize:
            with patch("cancel_test_preflight.unattended_identity_from_environment", return_value=(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)):
                with patch("cancel_test_preflight.check_proxy_listener") as check_proxy:
                    with patch("cancel_test_preflight.check_test_server_health") as check_health:
                        with patch("cancel_test_preflight.read_mcp_snapshot", return_value=valid_snapshot()) as read_snapshot:
                            output = StringIO()
                            with redirect_stdout(output):
                                run_preflight()
        initialize.assert_called_once()
        check_proxy.assert_called_once()
        check_health.assert_called_once_with(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)
        read_snapshot.assert_called_once()
        self.assertIn("session 299s and unattended authorization 299s remain", output.getvalue())
        self.assertIn("/test-cancel was not sent", output.getvalue())

    def test_setup_preflight_passes_before_live_session_with_matching_identities(self):
        self.assertEqual([], validate_setup_snapshot(
            valid_setup_snapshot(),
            unattended_run_id="11111111-2222-3333-4444-555555555555",
            unattended_server_identity="A" * 43,
        ))

    def test_setup_preflight_performs_auth_fixture_and_one_mcp_snapshot_before_session(self):
        with patch("cancel_test_preflight.initialize", return_value=object()) as initialize:
            with patch("cancel_test_preflight.unattended_identity_from_environment", return_value=(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)):
                with patch("cancel_test_preflight.check_proxy_listener") as check_proxy:
                    with patch("cancel_test_preflight.check_test_server_health") as check_health:
                        with patch("cancel_test_preflight.read_mcp_snapshot", return_value=valid_setup_snapshot()) as read_snapshot:
                            output = StringIO()
                            with redirect_stdout(output):
                                run_setup_preflight()
        initialize.assert_called_once()
        check_proxy.assert_called_once()
        check_health.assert_called_once_with(ACTIVE_RUN_ID, ACTIVE_SERVER_IDENTITY)
        read_snapshot.assert_called_once()
        self.assertIn("SETUP PREFLIGHT PASS", output.getvalue())
        self.assertIn("unattended authorization 299s remain", output.getvalue())
        self.assertIn("live interception is off", output.getvalue())
        self.assertIn("/test-cancel was not sent", output.getvalue())

    def test_setup_authorization_budget_includes_session_activation_margin(self):
        self.assertEqual(180_000, MIN_SETUP_AUTHORIZATION_MS)
        threshold_failure = "Unattended authorization has less than 180s remaining"
        for remaining_seconds in (300, 240, 180, 150, 120):
            with self.subTest(setup_authorization_remaining_seconds=remaining_seconds):
                snapshot = valid_setup_snapshot()
                snapshot["interception"]["unattendedMode"]["remainingMillis"] = remaining_seconds * 1000
                failures = validate_setup_snapshot(
                    snapshot,
                    unattended_run_id="11111111-2222-3333-4444-555555555555",
                    unattended_server_identity="A" * 43,
                )
                if remaining_seconds >= 180:
                    self.assertFalse(has_failure_prefix(failures, threshold_failure))
                else:
                    self.assertTrue(has_failure_prefix(failures, threshold_failure))

    def test_setup_preflight_rejects_active_interception(self):
        snapshot = valid_setup_snapshot()
        snapshot["interception"]["enabled"] = True
        failures = validate_setup_snapshot(
            snapshot,
            unattended_run_id="11111111-2222-3333-4444-555555555555",
            unattended_server_identity="A" * 43,
        )
        self.assertIn("Live interception must be inactive during setup preflight", failures)

    def test_setup_preflight_requires_matching_fresh_identities(self):
        snapshot = valid_setup_snapshot()
        failures = validate_setup_snapshot(
            snapshot,
            unattended_run_id="11111111-2222-3333-4444-555555555555",
            unattended_server_identity="B" * 43,
        )
        self.assertIn("Supplied test identity does not match the active Burp-local authorization", failures)

    def test_setup_preflight_checks_scope_allowlist_and_empty_queues_before_session(self):
        snapshot = valid_setup_snapshot()
        snapshot["scope"]["checks"][0]["eligible"] = False
        snapshot["interception"]["pendingResponses"] = 1
        snapshot["responses"] = [{"id": "held"}]
        failures = validate_setup_snapshot(
            snapshot,
            unattended_run_id="11111111-2222-3333-4444-555555555555",
            unattended_server_identity="A" * 43,
        )
        self.assertIn("/test-cancel is not eligible", failures)
        self.assertIn("Interception response queue is not empty", failures)
        self.assertIn("Pending response listing is missing or non-empty", failures)


if __name__ == "__main__":
    unittest.main()
