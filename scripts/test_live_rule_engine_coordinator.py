"""Offline regressions for rule readiness and approval-wait coordination."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from live_rule_engine_coordinator import (
    CORE_ACTIVE_RULES,
    PAUSE_REQUEST_RULE,
    PAUSE_RESPONSE_RULE,
    REQUEST_RULE,
    RESPONSE_RULE,
    RULE_NAMES,
    EXPECTED_BUILD_ID,
    CoordinatorError,
    LiveRuleEngineCoordinator,
    WaitingForApproval,
    build_rule_specs,
    build_target_session_rule_specs,
    TARGET_SESSION_URL,
    TargetSessionExchangeBatch,
    target_session_preflight,
    require_target_session_readiness,
    require_pretraffic_readiness,
    response_wait_state,
    rule_readiness_failures,
)


RUN_ID = "11111111-2222-3333-4444-555555555555"


class TargetSessionPreparationTest(unittest.TestCase):
    def test_preflight_cli_cannot_enter_legacy_live_runner(self):
        import live_rule_engine_coordinator as module
        with patch.object(module.preflight, 'initialize'), patch.object(module, 'target_session_preflight', return_value={'state':'PASS'}), patch.object(module.LiveRuleEngineCoordinator, 'run') as live, patch('builtins.print'):
            self.assertEqual(module.main(['--target-preflight-only']), 0)
            live.assert_not_called()
        with patch.object(module.preflight, 'initialize') as initialize, patch('builtins.print'):
            self.assertEqual(module.main(['--unknown']), 2)
            initialize.assert_not_called()

    def test_missing_references_are_rejected_before_any_mcp_call(self):
        from unittest.mock import Mock
        client=Mock()
        for grant, expected, owned in (('', {}, []), ('bad-id', {'a':{},'b':{}}, ['a','b']),
                                       (RUN_ID, {'missing':{}}, [])):
            with self.assertRaises(CoordinatorError):
                require_target_session_readiness(client, grant, expected, owned)
        client.tool.assert_not_called()

    def ready_target_session(self):
        from unittest.mock import Mock
        expected = dict(zip(('request-id', 'response-id'), build_target_session_rule_specs(RUN_ID)))
        data = {
            'burp_get_intercept_status': dict(enabled=True, editsEnabled=True, heartbeatHealth='HEALTHY',
                sessionLifetimeSeconds=120, sessionRemainingMillis=100000, unattendedMode={'active': False}, pendingRequests=0, pendingResponses=0),
            'burp_list_target_rule_authorizations': [dict(id=RUN_ID, urls=[TARGET_SESSION_URL], remainingMillis=200000)],
            'burp_list_interception_rules': [dict(id=k, spec=copy.deepcopy(v), state='ACTIVE') for k,v in expected.items()],
            'burp_get_rule_engine_status': dict(configuredRules=2, enabledRules=2, emergencyStopped=False),
        }
        client = Mock()
        client.tool.side_effect = lambda name, **kwargs: data[name]
        return client, expected, data

    def test_per_attempt_gate_accepts_exact_state_and_serialization_defaults(self):
        client, expected, data = self.ready_target_session()
        for r in data['burp_list_interception_rules']:
            for key in ('action', 'priority', 'durationSeconds'):
                del r['spec'][key]
        self.assertTrue(require_target_session_readiness(client, RUN_ID, expected, expected))
        client.rpc.assert_not_called()
        self.assertTrue(all(call.args[0].startswith(('burp_get_', 'burp_list_')) for call in client.tool.call_args_list))

    def test_per_attempt_gate_rejects_boolean_and_fractional_counters(self):
        for tool, field, value in (
            ('burp_get_intercept_status', 'pendingRequests', False),
            ('burp_get_intercept_status', 'pendingResponses', 0.0),
            ('burp_get_intercept_status', 'sessionLifetimeSeconds', 120.0),
            ('burp_get_rule_engine_status', 'configuredRules', 2.0),
        ):
            with self.subTest(tool=tool, field=field):
                client, expected, data = self.ready_target_session()
                data[tool][field] = value
                with self.assertRaises(CoordinatorError):
                    require_target_session_readiness(client, RUN_ID, expected, expected)

    def test_per_attempt_gate_rejects_expiry_changed_grants_and_rule_specs(self):
        for variant in ('grant-missing','grant-path','grant-expired','session-expired','unattended','changed-rule','missing-rule'):
            with self.subTest(variant=variant):
                client, expected, data = self.ready_target_session()
                if variant == 'grant-missing': data['burp_list_target_rule_authorizations'] = []
                if variant == 'grant-path': data['burp_list_target_rule_authorizations'][0]['urls'] = ['http://127.0.0.1:8000/test-post']
                if variant == 'grant-expired': data['burp_list_target_rule_authorizations'][0]['remainingMillis'] = 1
                if variant == 'session-expired': data['burp_get_intercept_status']['sessionRemainingMillis'] = 1
                if variant == 'unattended': data['burp_get_intercept_status']['unattendedMode']['active'] = True
                if variant == 'changed-rule': data['burp_list_interception_rules'][0]['spec']['maximumMatches'] = 3
                if variant == 'missing-rule': data['burp_list_interception_rules'].pop()
                with self.assertRaises(CoordinatorError):
                    require_target_session_readiness(client, RUN_ID, expected, expected)

    def test_per_attempt_gate_rejects_unbound_active_control(self):
        client, expected, data = self.ready_target_session()
        data['burp_list_interception_rules'].append(dict(id='control', state='DISABLED'))
        data['burp_get_rule_engine_status']['configuredRules'] = 3
        owned = list(expected) + ['control']
        self.assertTrue(require_target_session_readiness(client, RUN_ID, expected, owned))
        data['burp_list_interception_rules'][-1]['state'] = 'ACTIVE'
        with self.assertRaises(CoordinatorError):
            require_target_session_readiness(client, RUN_ID, expected, owned)

    def test_failed_http_result_preserves_status_and_hash_without_raw_body(self):
        saved=[]
        response = {'status': 503, 'responseSha256': 'b'*64, 'body': {'unexpected': 'do not persist'}}
        batch = TargetSessionExchangeBatch(lambda c: response, lambda: True, lambda c: [], saved.append)
        with self.assertRaises(CoordinatorError):
            batch.run(['one','two','three'])
        self.assertEqual(saved[-1]['clientStatus'], 503)
        self.assertEqual(saved[-1]['responseSha256'], 'b'*64)
        self.assertNotIn('do not persist', json.dumps(saved))

    def test_read_only_preflight_checks_catalog_scope_and_clean_state(self):
        from unittest.mock import Mock
        import live_rule_engine_coordinator as module
        snapshot = {
            'connection': {'burpConnected': True, 'burpVersion': 'Burp Suite Professional 2024.1.1.1'},
            'server': {'extensionVersion': module.EXPECTED_EXTENSION_VERSION, 'buildId': EXPECTED_BUILD_ID, 'serverState': 'running',
                       'bearerAuthenticationRequired': True, 'readOnlyMode': False, 'authorizedTargetCount': 1},
            'interception': {'enabled': False, 'editsEnabled': True, 'unattendedMode': {'active': False},
                             'pendingRequests': 0, 'pendingResponses': 0},
            'engine': {'configuredRules': 0, 'enabledRules': 0, 'emergencyStopped': False},
            'requests': [], 'responses': [], 'rules': [],
            'scope': {'checks': [{'url': u, 'eligible': True} for u in module.preflight.LOCAL_TEST_URLS]},
        }
        client = Mock()
        client.rpc.return_value = {'tools': [{'name': f'tool-{i}'} for i in range(89)]}
        client.tool.side_effect = lambda name, **kwargs: {'checks': [{'url': u, 'eligible': True} for u in (TARGET_SESSION_URL, module.BROWSER_DEMO_URL)]} if name == 'burp_get_scope' else []
        with patch.object(LiveRuleEngineCoordinator, '_snapshot', return_value=snapshot), patch.object(module.preflight, 'check_proxy_listener'):
            self.assertEqual(target_session_preflight(client)['state'], 'PASS')
            snapshot['server']['extensionVersion'] = '1.5.0-dev.6'
            with self.assertRaises(CoordinatorError):
                target_session_preflight(client)
            snapshot['server']['extensionVersion'] = module.EXPECTED_EXTENSION_VERSION
            snapshot['server']['buildId'] = '20261107.3-scanner-permission-hardening-dev'
            with self.assertRaises(CoordinatorError):
                target_session_preflight(client)
            snapshot['server']['buildId'] = EXPECTED_BUILD_ID
            client.tool.side_effect = lambda name, **kwargs: {'checks': [{'url': TARGET_SESSION_URL, 'eligible': True}]} if name == 'burp_get_scope' else []
            with self.assertRaises(CoordinatorError):
                target_session_preflight(client)
            client.tool.side_effect = lambda name, **kwargs: {'checks': [{'url': u, 'eligible': True} for u in (TARGET_SESSION_URL, module.BROWSER_DEMO_URL)]} if name == 'burp_get_scope' else []
            snapshot['interception']['unattendedMode']['active'] = True
            with self.assertRaises(CoordinatorError):
                target_session_preflight(client)
        self.assertTrue(all(call.args[0] in ('burp_get_scope', 'burp_list_target_rule_authorizations') for call in client.tool.call_args_list))

    def test_bad_case_batch_cannot_start_network_or_reuse_identifiers(self):
        from unittest.mock import Mock
        sender = Mock()
        for cases in (None, ['same']*3, ['only-one'], ['good', 'bad/id', 'other']):
            batch = TargetSessionExchangeBatch(sender, lambda: True, lambda c: [], lambda e: None)
            with self.assertRaises(CoordinatorError):
                batch.run(cases)
        sender.assert_not_called()

    def test_malformed_json_response_is_not_success_and_closes_connection(self):
        from unittest.mock import Mock
        connection = Mock()
        connection.getresponse.return_value.read.return_value = b'not-json'
        connection.getresponse.return_value.getheaders.return_value = []
        with patch('live_rule_engine_coordinator.http.client.HTTPConnection', return_value=connection):
            with self.assertRaises(json.JSONDecodeError):
                LiveRuleEngineCoordinator._http_post('one', '', '', target_url=TARGET_SESSION_URL)
        connection.close.assert_called_once()

    @staticmethod
    def evidence(case):
        body = dict(case=case, enabled=True, name='original', mcp_test='after', marker='preserve',
                    nested={'keep': 17}, method='POST', path='/test-post-phase2', bodySha256='a'*64, bodyByteLength=123)
        origin = dict(ruleTestId=case, path='/test-post-phase2', postEnabled=True,
                      ruleTestHeaderObserved=True, bodyFramingVerified=True, utf8BodyValid=True,
                      bodySha256='a'*64, bodyByteLength=123)
        return {'status': 200, 'body': body}, origin

    def test_batch_sends_one_baseline_and_two_overlapping_clients_only_once(self):
        overlap = threading.Barrier(2)
        calls, saved = [], []
        def sender(case):
            calls.append(case)
            if case != 'baseline':
                overlap.wait(timeout=2)
            return self.evidence(case)[0]
        batch = TargetSessionExchangeBatch(sender, lambda: True, lambda c: [self.evidence(c)[1]], saved.append)
        self.assertEqual(len(batch.run(['baseline', 'concurrent-a', 'concurrent-b'])), 3)
        self.assertEqual(calls[0], 'baseline')
        self.assertEqual(batch.attempts, 3)
        self.assertEqual(len([e for e in saved if e['state'] == 'PASS']), 3)
        with self.assertRaises(CoordinatorError):
            batch.run(['another', 'batch', 'refused'])
        self.assertEqual(len(calls), 3)

    def test_failed_baseline_preserves_failure_without_retry_or_concurrent_clients(self):
        from unittest.mock import Mock
        sender = Mock(side_effect=TimeoutError('synthetic'))
        saved = []
        batch = TargetSessionExchangeBatch(sender, lambda: True, lambda c: [], saved.append)
        with self.assertRaises(TimeoutError):
            batch.run(['one', 'two', 'three'])
        sender.assert_called_once_with('one')
        self.assertEqual([e['state'] for e in saved], ['STARTED', 'FAIL'])

    def test_missing_readiness_starts_no_client(self):
        from unittest.mock import Mock
        sender = Mock()
        batch = TargetSessionExchangeBatch(sender, lambda: None, lambda c: [], lambda e: None)
        with self.assertRaises(CoordinatorError):
            batch.run(['one', 'two', 'three'])
        sender.assert_not_called()

    def test_malformed_response_duplicate_origin_and_missing_transform_fail(self):
        for variant in ('missing', 'duplicate', 'unmodified', 'wrong-case'):
            with self.subTest(variant=variant):
                result, origin = self.evidence('one')
                origins = [origin]
                if variant == 'missing': result = None
                if variant == 'duplicate': origins = [origin, origin]
                if variant == 'unmodified': result['body']['enabled'] = False
                if variant == 'wrong-case': origin['ruleTestId'] = 'other'
                batch = TargetSessionExchangeBatch(lambda c: result, lambda: True, lambda c: origins, lambda e: None)
                with self.assertRaises(CoordinatorError):
                    batch.run(['one', 'two', 'three'])
                self.assertEqual(batch.attempts, 1)

    def test_oversized_target_response_is_bounded_and_connection_closed(self):
        from unittest.mock import Mock
        connection = Mock()
        connection.getresponse.return_value.read.return_value = b'x' * 65537
        with patch('live_rule_engine_coordinator.http.client.HTTPConnection', return_value=connection):
            with self.assertRaises(CoordinatorError):
                LiveRuleEngineCoordinator._http_post('one', '', '', target_url=TARGET_SESSION_URL)
        connection.getresponse.return_value.read.assert_called_once_with(65537)
        connection.close.assert_called_once()

    def test_two_bounded_rules_bind_new_exact_path_and_combine_request_edits(self):
        request, response = build_target_session_rule_specs(RUN_ID)
        self.assertEqual(len(request['transformations']), 2)
        self.assertEqual(request['transformations'][1]['type'], 'SET_REQUEST_HEADER')
        self.assertEqual([request['direction'], response['direction']], ['REQUEST', 'RESPONSE'])
        for spec in (request, response):
            self.assertEqual(spec['authorizationReference'], RUN_ID)
            self.assertEqual(spec['targetUrl'], TARGET_SESSION_URL)
            self.assertEqual(spec['conditions']['path'], '/test-post-phase2')
            self.assertEqual(spec['durationSeconds'], 120)
            self.assertEqual(spec['maximumMatches'], 4)
            self.assertEqual(spec['maximumModifications'], 4)
        self.assertEqual(build_rule_specs(RUN_ID)[0]['targetUrl'], 'http://127.0.0.1:8000/test-post')

    def test_unapproved_client_target_is_rejected_before_connecting(self):
        with patch('live_rule_engine_coordinator.http.client.HTTPConnection') as connection:
            with self.assertRaises(CoordinatorError):
                LiveRuleEngineCoordinator._http_post('phase2-one', '', '', target_url='http://127.0.0.1:8000/test-post-phase2-extra')
            connection.assert_not_called()

    def test_phase2_client_uses_exact_url_without_legacy_identity_headers(self):
        from unittest.mock import Mock
        connection = Mock()
        connection.getresponse.return_value.read.return_value = b'{"enabled":true}'
        connection.getresponse.return_value.getheaders.return_value = []
        with patch('live_rule_engine_coordinator.http.client.HTTPConnection', return_value=connection):
            LiveRuleEngineCoordinator._http_post('phase2-one', '', '', target_url=TARGET_SESSION_URL)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ('POST', TARGET_SESSION_URL))
        self.assertEqual(json.loads(kwargs['body'])['enabled'], False)
        self.assertEqual(kwargs['headers']['X-MCP-Test-ID'], 'phase2-one')
        self.assertNotIn('X-MCP-Server-Identity', kwargs['headers'])
        connection.request.assert_called_once()
        connection.close.assert_called_once()


def rule_entries(active_names=CORE_ACTIVE_RULES):
    return [
        {"id": f"id-{spec['name']}", "spec": copy.deepcopy(spec),
         "state": "ACTIVE" if spec["name"] in active_names else "DISABLED"}
        for spec in build_rule_specs(RUN_ID)
    ]


def ready_status():
    return {
        "enabled": True,
        "heartbeatHealth": "HEALTHY",
        "sessionRemainingMillis": 55_000,
        "pendingRequests": 0,
        "pendingResponses": 0,
        "unattendedMode": {"active": True, "testRunId": RUN_ID,
                           "serverIdentity": "A" * 43, "remainingMillis": 120_000},
    }


class LiveRuleCoordinatorRegressionTests(unittest.TestCase):
    def test_loaded_kotlin_catalog_omits_default_action_and_priority(self):
        rules = rule_entries()
        for entry in rules:
            if entry["spec"]["action"] == "MODIFY_AND_FORWARD":
                del entry["spec"]["action"]
                del entry["spec"]["priority"]
        self.assertEqual([], rule_readiness_failures(rules, RUN_ID))
        rules[0]["spec"]["priority"] = 99
        self.assertTrue(rule_readiness_failures(rules, RUN_ID))

    def test_loaded_rule_statistics_are_a_single_record_array(self):
        class Client:
            def tool(self, name, **kwargs):
                return [{"ruleId": "one", "matchedResponses": 8}]
        coordinator = LiveRuleEngineCoordinator(Client())
        self.assertEqual(8, coordinator.tool("burp_get_interception_rule_stats", ruleId="one")["matchedResponses"])
        self.assertIsInstance(coordinator.tool("burp_get_interception_rule_stats"), list)

    def test_fixture_handoff_uses_json_and_files_instead_of_inherited_pipes(self):
        coordinator = LiveRuleEngineCoordinator(object())
        coordinator.run_id = RUN_ID
        coordinator.server_identity = "A" * 43
        def launch(args, **kwargs):
            self.assertIn("-Command", args)
            self.assertIn("ConvertTo-Json -Compress", args[-1])
            self.assertNotIn("capture_output", kwargs)
            self.assertNotIn("BURP_MCP_TOKEN", kwargs["env"])
            kwargs["stdout"].write(json.dumps({"State": "READY", "ProcessId": 123,
                                               "RuleEngineTestMode": True}).encode())
            return subprocess.CompletedProcess(args, 0)
        with tempfile.TemporaryDirectory() as directory:
            coordinator.evidence_path = Path(directory) / "evidence.jsonl"
            with patch("live_rule_engine_coordinator.subprocess.run", side_effect=launch):
                with patch("live_rule_engine_coordinator.preflight.check_test_server_health") as health:
                    coordinator._start_fixture()
            health.assert_called_once_with(RUN_ID, "A" * 43)
        self.assertEqual(123, coordinator.fixture_pid)
        self.assertTrue(coordinator.fixture_mode)

    def test_rule_specs_pair_request_and_response_at_same_priority(self):
        specs = {spec["name"]: spec for spec in build_rule_specs(RUN_ID)}
        self.assertEqual(set(specs), set(RULE_NAMES))
        self.assertEqual(specs[REQUEST_RULE]["priority"], specs[RESPONSE_RULE]["priority"])
        self.assertEqual(specs[REQUEST_RULE]["direction"], "REQUEST")
        self.assertEqual(specs[RESPONSE_RULE]["direction"], "RESPONSE")
        self.assertEqual(specs[RESPONSE_RULE]["conditions"]["responseStatus"], 200)
        self.assertEqual(specs[RESPONSE_RULE]["conditions"]["jsonPath"], "$.enabled")
        self.assertEqual(specs[RESPONSE_RULE]["conditions"]["jsonValueJson"], "false")
        self.assertEqual(specs[REQUEST_RULE]["conditions"]["jsonValueJson"], "false")

    def test_exact_failed_setup_is_rejected_before_first_request(self):
        rules = rule_entries(active_names=frozenset((REQUEST_RULE,)))
        engine = {"configuredRules": len(RULE_NAMES), "enabledRules": 1, "emergencyStopped": False}
        with self.assertRaises(CoordinatorError) as raised:
            require_pretraffic_readiness(ready_status(), engine, rules, RUN_ID)
        self.assertEqual(raised.exception.code, "READINESS_FAILED")
        self.assertIn("LIVE-RULE-RESPONSE-JSON state is DISABLED", str(raised.exception))
        self.assertIn("no request was sent", str(raised.exception))

    def test_disabled_response_during_exchange_is_reported_as_waiting_for_approval(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        response["state"] = "DISABLED"
        state, reason = response_wait_state([{"id": "synthetic-response"}], response, 0, 0)
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("not active", reason)

    def test_active_but_unmatched_response_reports_waiting_without_approval(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        state, reason = response_wait_state([{"id": "synthetic-response"}], response, 0, 0,
                                            processing_grace_elapsed=True)
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("no response rule matched", reason)

    def test_matched_response_is_given_a_short_processing_grace(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        state, reason = response_wait_state([{"id": "synthetic-response"}], response, 0, 1)
        self.assertEqual((state, reason), ("PROCESSING", None))

    def test_failed_or_skipped_response_is_reported_without_waiting_for_client_timeout(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        state, reason = response_wait_state(
            [{"id": "synthetic-response"}], response, 0, 1,
            failures_before=0, failures_after=1, last_error_code="RESPONSE_NOT_ASSOCIATED",
        )
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("RESPONSE_NOT_ASSOCIATED", reason)
        state, reason = response_wait_state(
            [{"id": "synthetic-response"}], response, 0, 0,
            skipped_before=0, skipped_after=1,
        )
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("manual approval", reason)

    def test_native_intercept_response_contract_fails_closed(self):
        from unittest.mock import Mock
        acknowledgement = {"content": [{"type": "text", "text": "Native Proxy interception updated."}], "isError": False}
        client = Mock()
        client.rpc.return_value = acknowledgement
        coordinator = LiveRuleEngineCoordinator(client)
        self.assertEqual(coordinator.tool("burp_set_proxy_intercept_state", enabled=False), {"confirmed": True})
        client.rpc.assert_called_once_with("tools/call", {"name": "burp_set_proxy_intercept_state", "arguments": {"enabled": False}})
        fixtures = {
            "tool_error": {**acknowledgement, "isError": True},
            "unexpected_format": {"content": [{"type": "image", "data": "synthetic"}]},
            "missing_content": {},
            "missing_text": {"content": [{"type": "text"}]},
            "failed_transition": {"content": [{"type": "text", "text": "State change failed."}], "isError": False},
            "approval_required": {"content": [{"type": "text", "text": "Approval required."}], "isError": False},
            "approval_denied": {"content": [{"type": "text", "text": "Tool failed (IllegalStateException). Check the Burp MCP activity log for details."}], "isError": True},
            "malformed_json": {"content": [{"type": "text", "text": "{"}]},
            "json_without_confirmation": {"content": [{"type": "text", "text": '{}'}]},
            "conflicting_wrapper": {**acknowledgement, "structuredContent": {"enabled": True}},
            "missing_wrapper": None,
        }
        for label, response in fixtures.items():
            with self.subTest(label=label):
                client = Mock()
                client.rpc.return_value = response
                client.tool.return_value = {"unattendedMode": {"remainingMillis": 120000}}
                coordinator = LiveRuleEngineCoordinator(client)
                with self.assertRaises(CoordinatorError) as raised:
                    coordinator._start_session_and_enable_rules()
                self.assertEqual(raised.exception.code, "NATIVE_INTERCEPT_NOT_CONFIRMED")
                self.assertFalse(coordinator.native_intercept_prepared)
                self.assertFalse(coordinator.session_started)
                self.assertEqual(coordinator.client_attempts_started, 0)
                self.assertEqual([call.args[0] for call in client.tool.call_args_list], ["burp_get_intercept_status"])

    def test_native_intercept_confirmation_happens_before_session_start(self):
        class Client:
            def __init__(self):
                self.events = []
                self.status_reads = 0

            def rpc(self, method, params):
                self.events.append((params["name"], params["arguments"]))
                return {"content": [{"type": "text", "text": "Native Proxy interception updated."}],
                        "isError": False}

            def tool(self, name, **args):
                self.events.append((name, args))
                if name == "burp_get_intercept_status":
                    self.status_reads += 1
                    if self.status_reads == 1:
                        return {"unattendedMode": {"remainingMillis": 120_000}}
                    return ready_status()
                if name == "burp_list_interception_rules":
                    return rule_entries()
                if name == "burp_get_rule_engine_status":
                    return {"configuredRules": len(RULE_NAMES), "enabledRules": len(CORE_ACTIVE_RULES),
                            "emergencyStopped": False}
                return {}

        client = Client()
        coordinator = LiveRuleEngineCoordinator(client)
        coordinator.run_id = RUN_ID
        coordinator.server_identity = "A" * 43
        coordinator.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
        coordinator.rules = rule_entries(frozenset())

        coordinator._start_session_and_enable_rules()

        event_names = [name for name, _ in client.events]
        self.assertLess(event_names.index("burp_set_proxy_intercept_state"),
                        event_names.index("burp_set_live_interception_state"))
        session_start = event_names.index("burp_set_live_interception_state")
        first_enable = event_names.index("burp_enable_interception_rule")
        self.assertLess(session_start, first_enable)
        self.assertEqual(len([name for name in event_names if name == "burp_enable_interception_rule"]),
                         len(CORE_ACTIVE_RULES))
        self.assertEqual(rule_readiness_failures(coordinator.rules, RUN_ID, CORE_ACTIVE_RULES), [])

    def test_offline_coordinator_runs_request_response_pause_resume_and_cleanup_sequence(self):
        expected_stats = {
            REQUEST_RULE: {"matchedRequests": 8, "modified": 8, "forwarded": 8},
            RESPONSE_RULE: {"matchedResponses": 8, "modified": 8, "forwarded": 8},
            "LIVE-RULE-REQUEST-HEADER": {"matchedRequests": 2, "modified": 2, "forwarded": 2},
            PAUSE_REQUEST_RULE: {"matchedRequests": 1, "modified": 0, "forwarded": 1},
            PAUSE_RESPONSE_RULE: {"matchedResponses": 1, "modified": 0, "forwarded": 1},
        }

        class Client:
            def __init__(self):
                self.rule_states = {}
                self.status_reads = 0

            def tool(self, name, **args):
                if name == "burp_get_intercept_status":
                    self.status_reads += 1
                    if self.status_reads == 1:
                        return {"enabled": True, "pendingRequests": 0, "pendingResponses": 0}
                    return {"enabled": False, "heartbeatHealth": "EXPIRED", "sessionEndReason": "SESSION_EXPIRED",
                            "pendingRequests": 0, "pendingResponses": 0}
                if name == "burp_get_interception_rule":
                    return {"state": self.rule_states[args["ruleId"]]}
                if name == "burp_list_interception_rules":
                    return [
                        {"id": f"id-{spec['name']}", "spec": copy.deepcopy(spec),
                         "state": self.rule_states[f"id-{spec['name']}"]}
                        for spec in build_rule_specs(RUN_ID)
                    ]
                if name == "burp_get_interception_rule_stats":
                    rule_name = args["ruleId"].removeprefix("id-")
                    return {**expected_stats[rule_name], "failed": 0, "dropped": 0, "skipped": 0}
                if name == "burp_disable_interception_rule":
                    self.rule_states[args["ruleId"]] = "PAUSED"
                    return {}
                if name == "burp_enable_interception_rule":
                    self.rule_states[args["ruleId"]] = "ACTIVE"
                    return {}
                if name == "burp_delete_interception_rule":
                    del self.rule_states[args["ruleId"]]
                    return {}
                if name == "burp_get_rule_engine_status":
                    return {"configuredRules": len(self.rule_states)}
                return {}

        class Coordinator(LiveRuleEngineCoordinator):
            @staticmethod
            def _snapshot(client):
                return {"server": {"buildId": EXPECTED_BUILD_ID}}

            def _validate_initial(self, snapshot):
                return RUN_ID, "A" * 43

            def _stop_empty_session_before_setup(self):
                pass

            def _start_fixture(self):
                self.fixture_pid = 1

            def _create_rules_before_session(self):
                self.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
                self.client.rule_states = {rule_id: "DISABLED" for rule_id in self.rule_ids.values()}
                self.rules = rule_entries(frozenset())

            def _start_session_and_enable_rules(self):
                for name in CORE_ACTIVE_RULES:
                    self.client.rule_states[self.rule_ids[name]] = "ACTIVE"
                self.rules = rule_entries()
                self.response_rule = next(row for row in self.rules if row["spec"]["name"] == RESPONSE_RULE)

            def _exchange(self, case_id, *, expected_enabled=True, rule_header=False, pause_header=False,
                          response_rule_name=RESPONSE_RULE):
                self.exchanges.append((case_id, expected_enabled, rule_header, pause_header, response_rule_name))
                return {"case": case_id, "status": 200, "clientEnabled": expected_enabled,
                        "originEnabled": expected_enabled, "originDeliveryCount": 1}

            def _origin_records(self):
                return [{"ruleTestId": case_id} for case_id, *_ in self.exchanges]

            def _stop_fixture(self):
                self.fixture_pid = None
                self.fixture_stopped = True

            def __init__(self, client):
                super().__init__(client)
                self.exchanges = []
                self.fixture_stopped = False

        coordinator = Coordinator(Client())
        with patch("live_rule_engine_coordinator.preflight.check_proxy_listener"):
            result = coordinator.run()

        self.assertEqual(result["state"], "PASS")
        self.assertFalse(result["liveProxy"] is False)
        self.assertEqual(result["exchangeCount"], 9)
        self.assertEqual(len(result["exchanges"]), 9)
        self.assertEqual(result["clientResponsesVerified"], 9)
        self.assertEqual(result["originDeliveriesVerified"], 9)
        self.assertTrue(result["multipleRulesVerified"])
        self.assertTrue(result["pauseResumeVerified"])
        self.assertTrue(result["cleanup"]["rulesDeleted"])
        self.assertTrue(coordinator.fixture_stopped)
        self.assertEqual(len({case_id for case_id, *_ in coordinator.exchanges}), 9)
        self.assertEqual(sum(rule_header for _, _, rule_header, _, _ in coordinator.exchanges), 2)
        self.assertEqual(sum(pause_header for _, _, _, pause_header, _ in coordinator.exchanges), 1)
        self.assertTrue(all(expected is False for _, expected, _, pause_header, _ in coordinator.exchanges
                            if pause_header))

    def test_preapproved_native_intercept_does_not_reprompt_inside_authorization_window(self):
        coordinator = LiveRuleEngineCoordinator(object(), native_intercept_prepared=True)
        coordinator.run_id = RUN_ID
        coordinator.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
        results = {
            "burp_get_intercept_status": ready_status(),
            "burp_list_interception_rules": rule_entries(),
            "burp_get_rule_engine_status": {"configuredRules": 5, "enabledRules": 3, "emergencyStopped": False},
        }
        with patch.object(coordinator, "tool", side_effect=lambda name, **kwargs: results.get(name, {})) as tool:
            coordinator._start_session_and_enable_rules()
        names = [call.args[0] for call in tool.call_args_list]
        self.assertNotIn("burp_set_proxy_intercept_state", names)
        self.assertLess(names.index("burp_set_live_interception_state"), names.index("burp_enable_interception_rule"))

    def test_pause_fallback_rules_are_disabled_before_traffic(self):
        failures = rule_readiness_failures(rule_entries(), RUN_ID, CORE_ACTIVE_RULES)
        self.assertEqual(failures, [])
        paused_states = frozenset((PAUSE_REQUEST_RULE, PAUSE_RESPONSE_RULE))
        failures = rule_readiness_failures(rule_entries(paused_states), RUN_ID, paused_states)
        self.assertEqual(failures, [])

    def test_approval_gated_response_stops_coordinator_without_retry_or_later_exchange(self):
        class Clock:
            now = 0.0

            def __call__(self):
                return self.now

            def sleep(self, seconds):
                self.now += seconds

        class Client:
            def __init__(self):
                self.calls = []

        class Coordinator(LiveRuleEngineCoordinator):
            def __init__(self, client, clock):
                super().__init__(client, clock=clock, sleeper=clock.sleep, http_timeout=2)
                self.client_started = threading.Event()
                self.release_client = threading.Event()
                self.fixture_stopped = False

            @staticmethod
            def _snapshot(client):
                return {"server": {"buildId": EXPECTED_BUILD_ID}}

            def _validate_initial(self, snapshot):
                return RUN_ID, "A" * 43

            def _stop_empty_session_before_setup(self):
                pass

            def _start_fixture(self):
                self.fixture_pid = 1

            def _create_rules_before_session(self):
                self.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
                self.rules = rule_entries(frozenset())

            def _start_session_and_enable_rules(self):
                self.rules = rule_entries()
                self.response_rule = next(row for row in self.rules if row["spec"]["name"] == RESPONSE_RULE)

            def _http_post(self, *args, **kwargs):
                self.client.client_attempts = getattr(self.client, "client_attempts", 0) + 1
                self.client_started.set()
                self.release_client.wait(2)
                raise TimeoutError("synthetic offline client remains waiting")

            def _stop_fixture(self):
                self.fixture_stopped = True
                self.release_client.set()

            def tool(self, name, **args):
                self.client.calls.append((name, args))
                if name == "burp_get_interception_rule_stats":
                    return {"matchedResponses": 0}
                if name == "burp_get_intercept_status":
                    return {"enabled": True, "heartbeatHealth": "HEALTHY", "sessionRemainingMillis": 50_000}
                if name == "burp_list_pending_responses":
                    return [{"id": "held-response"}]
                if name == "burp_list_interception_rules":
                    return []
                return {}

        client = Client()
        clock = Clock()
        coordinator = Coordinator(client, clock)
        with patch("live_rule_engine_coordinator.preflight.check_proxy_listener"):
            with self.assertRaises(WaitingForApproval) as raised:
                coordinator.run()

        self.assertEqual(raised.exception.code, "WAITING_FOR_APPROVAL")
        self.assertEqual(client.client_attempts, 1)
        self.assertTrue(coordinator.fixture_stopped)
        self.assertTrue(coordinator.waiting_for_approval)
        self.assertEqual(coordinator.client_attempts_started, 1)
        self.assertTrue(coordinator.owned_rules_deleted)
        self.assertFalse(any(name in {"burp_forward_intercepted_response", "burp_drop_intercepted_response"}
                             for name, _ in client.calls))
        self.assertEqual(sum(name == "burp_disable_interception_rule" for name, _ in client.calls), len(RULE_NAMES))
        self.assertEqual(sum(name == "burp_delete_interception_rule" for name, _ in client.calls), len(RULE_NAMES))


if __name__ == "__main__":
    unittest.main()
