"""Bounded live coordinator for the local automatic request/response rule test.

This module intentionally separates readiness and approval-wait classification
from the live runner so those gates can be tested without Burp or network I/O.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import cancel_test_preflight as preflight


TARGET_URL = "http://127.0.0.1:8000/test-post"
TARGET_SESSION_URL = "http://127.0.0.1:8000/test-post-phase2"
BROWSER_DEMO_URL = "http://127.0.0.1:8000/test-form-browser-validation"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
EXPECTED_BUILD_ID = "20261109.1-rule-association-fix-dev"
EXPECTED_EXTENSION_VERSION = "1.5.0-dev.7"
SESSION_LIFETIME_SECONDS = 60
RULE_TTL_SECONDS = 60
SESSION_SAFETY_MARGIN_MS = 30_000
MIN_AUTHORIZATION_MS = SESSION_LIFETIME_SECONDS * 1000 + SESSION_SAFETY_MARGIN_MS
CLIENT_TIMEOUT_SECONDS = 12
APPROVAL_DIAGNOSTIC_GRACE_SECONDS = 0.75
POLL_INTERVAL_SECONDS = 0.15

REQUEST_RULE = "LIVE-RULE-REQUEST-JSON"
RESPONSE_RULE = "LIVE-RULE-RESPONSE-JSON"
HEADER_RULE = "LIVE-RULE-REQUEST-HEADER"
PAUSE_REQUEST_RULE = "LIVE-RULE-PAUSE-REQUEST-FORWARD"
PAUSE_RESPONSE_RULE = "LIVE-RULE-PAUSE-RESPONSE-FORWARD"
RULE_NAMES = (
    REQUEST_RULE,
    RESPONSE_RULE,
    HEADER_RULE,
    PAUSE_REQUEST_RULE,
    PAUSE_RESPONSE_RULE,
)
CORE_ACTIVE_RULES = frozenset((REQUEST_RULE, RESPONSE_RULE, HEADER_RULE))


def build_target_session_rule_specs(grant_id: str) -> list[dict]:
    """Prepare exactly two target-session rules; this function performs no MCP calls."""
    request, response, header, *_ = build_rule_specs(grant_id, duration_seconds=120)
    request["transformations"].extend(header["transformations"])
    for spec in (request, response):
        spec["targetUrl"] = TARGET_SESSION_URL
        spec["conditions"]["path"] = "/test-post-phase2"
        # Keep both rules ACTIVE through response association for the third POST.
        # The client batch, not rule exhaustion, enforces the three-attempt limit.
        spec["maximumMatches"] = 4
        spec["maximumModifications"] = 4
    return [request, response]


class CoordinatorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class WaitingForApproval(CoordinatorError):
    def __init__(self, message: str, pending_responses: int):
        super().__init__("WAITING_FOR_APPROVAL", message)
        self.pending_responses = pending_responses


class TargetSessionExchangeBatch:
    """One explicit baseline plus two concurrent clients; never creates authorization.

    The caller supplies current-session readiness, a one-shot sender, exact origin
    lookup and durable sanitized evidence storage. No work happens on construction.
    Cleanup remains with the supervisor: this runner never drops held traffic.
    """

    def __init__(self, sender, readiness, origin_records, evidence_sink):
        self.sender, self.readiness = sender, readiness
        self.origin_records, self.evidence_sink = origin_records, evidence_sink
        self.attempts = 0
        self.used = False
        self.stopped = False
        self.lock = threading.Lock()

    def _exchange(self, case_id):
        with self.lock:
            if self.stopped or self.attempts >= 3:
                raise CoordinatorError("BATCH_STOPPED", "no further client attempts are permitted")
            if self.readiness() is not True:
                self.stopped = True
                raise CoordinatorError("READINESS_FAILED", "current approved target session was not confirmed")
            self.attempts += 1
        record = {"case": case_id, "state": "STARTED", "target": TARGET_SESSION_URL}
        self.evidence_sink(record.copy())
        try:
            result = self.sender(case_id)
            # Preserve bounded terminal metadata even when validation fails. Never
            # persist arbitrary response bodies or exception strings.
            record['clientStatus'] = result.get('status') if isinstance(result, dict) and type(result.get('status')) is int else None
            digest = result.get('responseSha256') if isinstance(result, dict) else None
            if isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest):
                record['responseSha256'] = digest
            body = result.get("body") if isinstance(result, dict) else None
            origins = self.origin_records(case_id)
            if (not isinstance(body, dict) or type(result.get("status")) is not int or result["status"] != 200 or
                    not isinstance(origins, list) or len(origins) != 1 or not isinstance(origins[0], dict)):
                raise CoordinatorError("EXCHANGE_MISMATCH", "bounded HTTP result and one origin record required")
            origin = origins[0]
            expected = {"case": case_id, "enabled": True, "name": "original", "mcp_test": "after",
                        "marker": "preserve", "nested": {"keep": 17}, "method": "POST", "path": "/test-post-phase2"}
            if (any(body.get(k) != v for k, v in expected.items()) or body.get("enabled") is not True or
                    origin.get("ruleTestId") != case_id or origin.get("path") != "/test-post-phase2" or
                    origin.get("postEnabled") is not True or origin.get("ruleTestHeaderObserved") is not True or
                    origin.get("bodyFramingVerified") is not True or origin.get("utf8BodyValid") is not True or
                    body.get("bodySha256") != origin.get("bodySha256") or
                    body.get("bodyByteLength") != origin.get("bodyByteLength") or
                    not isinstance(body.get("bodySha256"), str) or len(body["bodySha256"]) != 64 or
                    any(c not in "0123456789abcdef" for c in body["bodySha256"])):
                raise CoordinatorError("EXCHANGE_MISMATCH", "client and independent origin evidence disagree")
            record.update(state="PASS", status=200, originDeliveryCount=1,
                          receivedBodySha256=body["bodySha256"])
            self.evidence_sink(record.copy())
            return record
        except Exception as error:
            with self.lock:
                self.stopped = True
            record.update(state="FAIL", code=getattr(error, "code", type(error).__name__))
            self.evidence_sink(record.copy())
            raise

    def run(self, case_ids):
        import re
        if (self.used or not isinstance(case_ids, (list, tuple)) or len(case_ids) != 3 or
                any(not isinstance(c, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", c) for c in case_ids)):
            raise CoordinatorError("INVALID_BATCH", "one batch of three unique bounded case IDs is required")
        if len(set(case_ids)) != 3:
            raise CoordinatorError("INVALID_BATCH", "case IDs must be unique")
        self.used = True
        results = [self._exchange(case_ids[0])]
        barrier = threading.Barrier(2)
        outcomes = queue.Queue()

        def worker(case_id):
            try:
                barrier.wait(timeout=5)
                outcomes.put((True, self._exchange(case_id)))
            except Exception as error:
                outcomes.put((False, error))

        workers = [threading.Thread(target=worker, args=(c,), daemon=True) for c in case_ids[1:]]
        for worker_thread in workers:
            worker_thread.start()
        # Sender must use the existing bounded client timeout; no retry or second batch.
        for worker_thread in workers:
            worker_thread.join(CLIENT_TIMEOUT_SECONDS + 5)
        if any(worker_thread.is_alive() for worker_thread in workers):
            self.stopped = True
            raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "a bounded client remains unresolved; do not retry")
        for _ in workers:
            success, outcome = outcomes.get_nowait()
            if not success:
                raise outcome
            results.append(outcome)
        return results


def require_target_session_readiness(client, grant_id, expected_rules, owned_rule_ids):
    """Read-only per-attempt gate after native approval; no permission is created.

    expected_rules maps the two approved IDs to immutable prepared specifications.
    Numeric authorization revisions remain server-private and are not invented.
    """
    if (not isinstance(expected_rules, dict) or len(expected_rules) != 2 or
            set(expected_rules) - set(owned_rule_ids) or not all(expected_rules)):
        raise CoordinatorError('READINESS_FAILED', 'exactly two owned approved rule references required')
    try:
        if str(uuid.UUID(grant_id)) != grant_id:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise CoordinatorError('READINESS_FAILED', 'canonical grant reference required') from None
    if sorted(expected_rules.values(), key=lambda s: s.get('name', '')) != sorted(build_target_session_rule_specs(grant_id), key=lambda s: s['name']):
        raise CoordinatorError('READINESS_FAILED', 'prepared specifications do not match the fixed Phase 2 plan')
    status = client.tool('burp_get_intercept_status', includeDiagnostics=False)
    grants = client.tool('burp_list_target_rule_authorizations', includeDiagnostics=False)
    rules = client.tool('burp_list_interception_rules', includeDiagnostics=False)
    engine = client.tool('burp_get_rule_engine_status', includeDiagnostics=False)
    if (not isinstance(status, dict) or not isinstance(engine, dict) or
            any(type(status.get(k)) is not int for k in ('sessionLifetimeSeconds', 'sessionRemainingMillis', 'pendingRequests', 'pendingResponses')) or
            any(type(engine.get(k)) is not int for k in ('configuredRules', 'enabledRules'))):
        raise CoordinatorError('READINESS_FAILED', 'integer session and queue evidence required')
    if (status.get('enabled') is not True or status.get('editsEnabled') is not True or
            status.get('heartbeatHealth') != 'HEALTHY' or status.get('sessionLifetimeSeconds') != 120 or
            status.get('sessionRemainingMillis', 0) < 30_000 or status.get('unattendedMode', {}).get('active') is not False or
            status.get('pendingRequests') != 0 or status.get('pendingResponses') != 0):
        raise CoordinatorError('READINESS_FAILED', 'healthy bounded target session with empty queues required')
    if (not isinstance(grants, list) or len(grants) != 1 or grants[0].get('id') != grant_id or
            grants[0].get('urls') != [TARGET_SESSION_URL] or grants[0].get('remainingMillis', 0) < 30_000):
        raise CoordinatorError('READINESS_FAILED', 'exact live preparation grant and lifetime required')
    if (not isinstance(rules, list) or {r.get('id') for r in rules} != set(owned_rule_ids) or
            len(rules) != len(set(owned_rule_ids)) or engine.get('configuredRules') != len(rules) or
            engine.get('enabledRules') != 2 or engine.get('emergencyStopped') is not False):
        raise CoordinatorError('READINESS_FAILED', 'only owned rules and two active approved rules required')
    defaults = dict(action='MODIFY_AND_FORWARD', priority=100, maximumMatches=32,
                    maximumModifications=32, durationSeconds=120, conditions={}, transformations=[])
    for rule in rules:
        if rule['id'] in expected_rules:
            if rule.get('state') != 'ACTIVE' or {**defaults, **rule.get('spec', {})} != expected_rules[rule['id']]:
                raise CoordinatorError('READINESS_FAILED', 'approved rule specification or state changed')
        elif rule.get('state') not in ('DISABLED', 'PAUSED'):
            raise CoordinatorError('READINESS_FAILED', 'unbound control rule became executable')
    return True


def target_session_preflight(client):
    """Read-only setup gate; never starts a fixture, grant, rule or session."""
    snapshot = LiveRuleEngineCoordinator._snapshot(client)
    status, engine, server = snapshot['interception'], snapshot['engine'], snapshot['server']
    tools = client.rpc('tools/list', {})
    catalog = tools.get('tools') if isinstance(tools, dict) else None
    scope = client.tool('burp_get_scope', urls=[TARGET_SESSION_URL, BROWSER_DEMO_URL, 'http://127.0.0.1:8000/', 'https://example.com/'])
    grants = client.tool('burp_list_target_rule_authorizations', includeDiagnostics=False)
    failures = []
    if (snapshot['connection'].get('burpConnected') is not True or
            not str(snapshot['connection'].get('burpVersion', '')).startswith(preflight.EXPECTED_BURP_VERSION_PREFIX)):
        failures.append('expected connected Burp Professional 2024.1.1.1 required')
    if (server.get('extensionVersion') != EXPECTED_EXTENSION_VERSION or server.get('buildId') != EXPECTED_BUILD_ID or
            server.get('serverState') != 'running' or server.get('bearerAuthenticationRequired') is not True or
            server.get('readOnlyMode') is not False or server.get('authorizedTargetCount') != 1):
        failures.append('expected authenticated development runtime and original single host allowlist required')
    if (not isinstance(catalog, list) or len(catalog) != 89 or
            len({t.get('name') for t in catalog if isinstance(t, dict)}) != 89 or tools.get('nextCursor')):
        failures.append('complete 89-tool catalog required')
    if (status.get('enabled') is not False or status.get('unattendedMode', {}).get('active') is not False or
            status.get('editsEnabled') is not True or status.get('pendingRequests') != 0 or status.get('pendingResponses') != 0 or
            snapshot['requests'] != [] or snapshot['responses'] != [] or snapshot['rules'] != [] or grants != [] or
            engine.get('configuredRules') != 0 or engine.get('enabledRules') != 0 or engine.get('emergencyStopped') is not False):
        failures.append('clean inactive runtime with edits enabled required')
    if {c.get('url') for c in scope.get('checks', []) if c.get('eligible') is True} != {TARGET_SESSION_URL, BROWSER_DEMO_URL}:
        failures.append('both exact fixtures must be eligible; root and external controls excluded')
    if {c.get('url') for c in snapshot['scope'].get('checks', []) if c.get('eligible') is True} != set(preflight.LOCAL_TEST_URLS):
        failures.append('original nine fixture scope checks changed')
    if failures:
        raise CoordinatorError('PREFLIGHT_FAILED', '; '.join(failures))
    preflight.check_proxy_listener()  # TCP availability only; no HTTP request.
    return {'state': 'PASS', 'buildId': EXPECTED_BUILD_ID, 'toolCount': 89,
            'target': TARGET_SESSION_URL, 'browserDemoTarget': BROWSER_DEMO_URL, 'applicationTrafficStarted': False,
            'nativeInterceptState': 'requires separate supported confirmation',
            'projectIdentity': 'requires operator confirmation of normal project'}


def build_rule_specs(authorization_reference: str, duration_seconds: int = RULE_TTL_SECONDS) -> list[dict]:
    """Return the five exact rules used by the live workflow, all initially disabled."""
    common = {"targetUrl": TARGET_URL, "authorizationReference": authorization_reference,
              "durationSeconds": duration_seconds}
    return [
        {
            **common, "name": REQUEST_RULE, "direction": "REQUEST", "action": "MODIFY_AND_FORWARD",
            "priority": 100, "maximumMatches": 16, "maximumModifications": 16,
            "conditions": {"method": "POST", "path": "/test-post", "contentType": "application/json",
                           "jsonPath": "$.enabled", "jsonValueJson": "false"},
            "transformations": [{"type": "SET_JSON_FIELD", "path": "$.enabled", "valueJson": "true"}],
        },
        {
            **common, "name": RESPONSE_RULE, "direction": "RESPONSE", "action": "MODIFY_AND_FORWARD",
            "priority": 100, "maximumMatches": 16, "maximumModifications": 16,
            "conditions": {"method": "POST", "path": "/test-post", "responseStatus": 200,
                           "contentType": "application/json", "jsonPath": "$.enabled", "jsonValueJson": "false"},
            "transformations": [{"type": "SET_JSON_FIELD", "path": "$.enabled", "valueJson": "true"}],
        },
        {
            **common, "name": HEADER_RULE, "direction": "REQUEST", "action": "MODIFY_AND_FORWARD",
            "priority": 100, "maximumMatches": 8, "maximumModifications": 8,
            "conditions": {"method": "POST", "path": "/test-post", "contentType": "application/json",
                           "headerName": "X-MCP-Rule-Test-Eligible", "headerValue": "active"},
            "transformations": [{"type": "SET_REQUEST_HEADER", "name": "X-MCP-Rule-Test", "value": "active"}],
        },
        {
            **common, "name": PAUSE_REQUEST_RULE, "direction": "REQUEST", "action": "FORWARD_UNCHANGED",
            "priority": 50, "maximumMatches": 2, "maximumModifications": 0,
            "conditions": {"method": "POST", "path": "/test-post", "headerName": "X-MCP-Pause-Forward",
                           "headerValue": "active"},
            "transformations": [],
        },
        {
            **common, "name": PAUSE_RESPONSE_RULE, "direction": "RESPONSE", "action": "FORWARD_UNCHANGED",
            "priority": 50, "maximumMatches": 2, "maximumModifications": 0,
            "conditions": {"method": "POST", "path": "/test-post", "responseStatus": 200,
                           "contentType": "application/json", "headerName": "X-MCP-Pause-Forward",
                           "headerValue": "active"},
            "transformations": [],
        },
    ]


def _entry_parts(entry: dict) -> tuple[str | None, dict, str | None]:
    spec = entry.get("spec") if isinstance(entry.get("spec"), dict) else entry
    # Kotlin serialization omits values equal to InterceptionRuleSpec defaults.
    spec = {"action": "MODIFY_AND_FORWARD", "priority": 100, **spec}
    return spec.get("name"), spec, entry.get("state")


def rule_readiness_failures(rules: list[dict], authorization_reference: str,
                            active_names: frozenset[str] = CORE_ACTIVE_RULES) -> list[str]:
    """Check exact target, direction, conditions, priorities, transforms, and states."""
    failures: list[str] = []
    if not isinstance(rules, list) or len(rules) != len(RULE_NAMES):
        return ["expected exactly five owned request/response rules"]
    by_name: dict[str, tuple[dict, str | None]] = {}
    for entry in rules:
        if not isinstance(entry, dict):
            failures.append("rule listing contains a malformed entry")
            continue
        name, spec, state = _entry_parts(entry)
        if not name or name in by_name:
            failures.append("rule names are missing or duplicated")
            continue
        by_name[name] = (spec, state)
    if set(by_name) != set(RULE_NAMES):
        failures.append("rule names do not match the expected test set")
        return failures

    expected_directions = {
        REQUEST_RULE: ("REQUEST", "MODIFY_AND_FORWARD", 100),
        RESPONSE_RULE: ("RESPONSE", "MODIFY_AND_FORWARD", 100),
        HEADER_RULE: ("REQUEST", "MODIFY_AND_FORWARD", 100),
        PAUSE_REQUEST_RULE: ("REQUEST", "FORWARD_UNCHANGED", 50),
        PAUSE_RESPONSE_RULE: ("RESPONSE", "FORWARD_UNCHANGED", 50),
    }
    for name, (spec, state) in by_name.items():
        direction, action, priority = expected_directions[name]
        if spec.get("authorizationReference") != authorization_reference or spec.get("targetUrl") != TARGET_URL:
            failures.append(f"{name} is not bound to the current run and exact localhost endpoint")
        if (spec.get("direction"), spec.get("action"), spec.get("priority")) != (direction, action, priority):
            failures.append(f"{name} has unexpected direction/action/priority: {spec.get('direction')}/{spec.get('action')}/{spec.get('priority')}")
        expected_state = "ACTIVE" if name in active_names else "DISABLED or PAUSED"
        accepted_states = {"ACTIVE"} if name in active_names else {"DISABLED", "PAUSED"}
        if state not in accepted_states:
            failures.append(f"{name} state is {state or 'missing'}; expected {expected_state}")

    request_spec = by_name[REQUEST_RULE][0]
    response_spec = by_name[RESPONSE_RULE][0]
    for spec, direction in ((request_spec, "request"), (response_spec, "response")):
        conditions = spec.get("conditions", {})
        if conditions.get("method") != "POST" or conditions.get("path") != "/test-post":
            failures.append(f"{direction} JSON rule does not match POST /test-post")
        if conditions.get("contentType") != "application/json" or conditions.get("jsonPath") != "$.enabled" or conditions.get("jsonValueJson") != "false":
            failures.append(f"{direction} JSON rule does not match application/json enabled=false")
        transformations = spec.get("transformations", [])
        if transformations != [{"type": "SET_JSON_FIELD", "path": "$.enabled", "valueJson": "true"}]:
            failures.append(f"{direction} JSON rule does not set only enabled=true")
    response_conditions = response_spec.get("conditions", {})
    if response_conditions.get("responseStatus") != 200:
        failures.append("response rule is not restricted to HTTP 200")

    header_spec = by_name[HEADER_RULE][0]
    if header_spec.get("conditions", {}).get("headerName") != "X-MCP-Rule-Test-Eligible" or \
       header_spec.get("transformations") != [{"type": "SET_REQUEST_HEADER", "name": "X-MCP-Rule-Test", "value": "active"}]:
        failures.append("compatible request-header rule is not safely conditioned")
    if by_name[PAUSE_REQUEST_RULE][0].get("conditions", {}).get("headerName") != "X-MCP-Pause-Forward":
        failures.append("pause request pass-through is not restricted to its synthetic marker")
    if by_name[PAUSE_RESPONSE_RULE][0].get("conditions", {}).get("headerName") != "X-MCP-Pause-Forward":
        failures.append("pause response pass-through is not restricted to its synthetic marker")
    return failures


def require_pretraffic_readiness(status: dict, engine: dict, rules: list[dict],
                                 authorization_reference: str) -> None:
    """Raise before traffic if authorization, session, queues, or rule states are incomplete."""
    failures: list[str] = []
    mode = status.get("unattendedMode", {}) if isinstance(status, dict) else {}
    if mode.get("active") is not True or not mode.get("testRunId") or not mode.get("serverIdentity"):
        failures.append("active local authorization and both identities are required")
    if mode.get("testRunId") != authorization_reference:
        failures.append("active rule authorization reference does not match the current run")
    if status.get("enabled") is not True or status.get("heartbeatHealth") != "HEALTHY":
        failures.append("a healthy approved live session is required")
    if int(status.get("sessionRemainingMillis", 0)) < 30_000 or int(mode.get("remainingMillis", 0)) < 30_000:
        failures.append("session or authorization has insufficient time remaining for a bounded exchange")
    if int(status.get("pendingRequests", -1)) != 0 or int(status.get("pendingResponses", -1)) != 0:
        failures.append("both interception queues must be empty before traffic")
    if int(engine.get("configuredRules", -1)) != len(RULE_NAMES) or engine.get("emergencyStopped") is not False:
        failures.append("the engine must contain only the five expected rules and must not be emergency-stopped")
    if int(engine.get("enabledRules", -1)) != len(CORE_ACTIVE_RULES):
        failures.append("exactly the request, response, and compatible-header rules must be active before traffic")
    failures.extend(rule_readiness_failures(rules, authorization_reference, CORE_ACTIVE_RULES))
    if failures:
        raise CoordinatorError("READINESS_FAILED", "; ".join(dict.fromkeys(failures)) + "; no request was sent")


def response_wait_state(pending_responses: list[dict], response_rule: dict,
                        matches_before: int, matches_after: int,
                        processing_grace_elapsed: bool = False,
                        failures_before: int = 0, failures_after: int = 0,
                        skipped_before: int = 0, skipped_after: int = 0,
                        last_error_code: str | None = None) -> tuple[str | None, str | None]:
    """Classify an in-flight response without approving or forwarding it."""
    if not pending_responses:
        return None, None
    _, _, state = _entry_parts(response_rule)
    if state != "ACTIVE":
        return "WAITING_FOR_APPROVAL", "the response rule is not active; the response remains held"
    if failures_after > failures_before or skipped_after > skipped_before:
        detail = f" ({last_error_code})" if last_error_code else ""
        return "WAITING_FOR_APPROVAL", f"automatic response processing did not release the message{detail}; it remains held for manual approval"
    if matches_after <= matches_before:
        if processing_grace_elapsed:
            return "WAITING_FOR_APPROVAL", "no response rule matched; the response remains held for local approval"
        return "PROCESSING", None
    if processing_grace_elapsed:
        return "WAITING_FOR_APPROVAL", "automatic response processing did not release the held response in time"
    return "PROCESSING", None


class LiveRuleEngineCoordinator:
    """Set up rules before session start, gate traffic on readiness, and stop at approval waits."""

    def __init__(self, client, *, clock=time.monotonic, sleeper=time.sleep, http_timeout=CLIENT_TIMEOUT_SECONDS,
                 native_intercept_prepared=False):
        self.client = client
        self.clock = clock
        self.sleeper = sleeper
        self.http_timeout = http_timeout
        self.rule_ids: dict[str, str] = {}
        self.fixture_pid: int | None = None
        self.log_baseline = 0
        self.fixture_mode = False
        self.session_started = False
        self.waiting_for_approval = False
        self.owned_rules_deleted = False
        self.run_id: str | None = None
        self.server_identity: str | None = None
        self.rules: list[dict] = []
        self.response_rule: dict | None = None
        self.client_attempts_started = 0
        # Set only after the supported Burp tool has completed local approval and disabled native Intercept.
        self.native_intercept_prepared = native_intercept_prepared
        self.verified_exchanges: list[dict] = []
        self.evidence_path = Path(__file__).resolve().parents[1] / "build" / "reports" / "live-rule-engine" / f"exchanges-{uuid.uuid4().hex}.jsonl"

    def tool(self, name: str, **args):
        if name == "burp_set_proxy_intercept_state":
            # This tool returns an MCP TextContent acknowledgement, not JSON.
            # Its handler acknowledges only after local approval and the state change.
            result = self.client.rpc("tools/call", {"name": name, "arguments": args})
            expected = [{"type": "text", "text": "Native Proxy interception updated."}]
            if (not isinstance(result, dict) or result.get("isError", False) is not False or
                    result.get("content") != expected or "structuredContent" in result):
                raise CoordinatorError("NATIVE_INTERCEPT_NOT_CONFIRMED",
                                       "Native Proxy state change was not confirmed; no session or traffic started")
            return {"confirmed": True}
        result = self.client.tool(name, **args)
        if name == "burp_get_interception_rule_stats" and args.get("ruleId") and isinstance(result, list):
            if len(result) != 1 or not isinstance(result[0], dict):
                raise CoordinatorError("INVALID_STATS", "expected exactly one rule statistics record")
            return result[0]
        return result

    @staticmethod
    def _snapshot(client):
        urls = list(preflight.LOCAL_TEST_URLS) + ["http://example.com/"]
        return {
            "connection": client.tool("burp_check_connection", includeBurpVersion=True),
            "server": client.tool("burp_get_status", includeDiagnostics=False),
            "scope": client.tool("burp_get_scope", urls=urls),
            "interception": client.tool("burp_get_intercept_status", includeDiagnostics=False),
            "requests": client.tool("burp_list_pending_requests", includeDiagnostics=False),
            "responses": client.tool("burp_list_pending_responses", includeDiagnostics=False),
            "engine": client.tool("burp_get_rule_engine_status", includeDiagnostics=False),
            "rules": client.tool("burp_list_interception_rules", includeDiagnostics=False),
        }

    def _validate_initial(self, snapshot: dict) -> tuple[str, str]:
        failures: list[str] = []
        server = snapshot["server"]
        connection = snapshot["connection"]
        status = snapshot["interception"]
        mode = status.get("unattendedMode", {})
        if server.get("serverState") != "running" or server.get("buildId") != EXPECTED_BUILD_ID:
            failures.append("the expected authenticated Burp MCP build is not loaded")
        if server.get("bearerAuthenticationRequired") is not True or server.get("readOnlyMode") is not False:
            failures.append("authenticated write mode is not available")
        if connection.get("burpConnected") is not True or connection.get("serverState") != "running":
            failures.append("Burp MCP connection is not healthy")
        if server.get("authorizedTargetCount") != 1:
            failures.append("the existing single localhost allowlist entry is not in place")
        checks = snapshot["scope"].get("checks", [])
        eligible_urls = {item.get("url") for item in checks if item.get("eligible") is True}
        if eligible_urls != set(preflight.LOCAL_TEST_URLS):
            failures.append("scope must contain exactly the nine approved localhost endpoints")
        control = next((item for item in checks if item.get("url") == "http://example.com/"), None)
        if not isinstance(control, dict) or control.get("eligible") is not False:
            failures.append("the external scope control must remain ineligible")
        if mode.get("active") is not True:
            failures.append("Unattended Local Test Mode is inactive")
        run_id, server_identity = preflight._identity_values(mode)
        if int(mode.get("remainingMillis", 0)) < MIN_AUTHORIZATION_MS:
            failures.append("authorization does not have enough time for setup and the bounded live session")
        if snapshot["requests"] or snapshot["responses"] or status.get("pendingRequests") != 0 or status.get("pendingResponses") != 0:
            failures.append("interception queues must be empty before setup")
        if snapshot["engine"].get("emergencyStopped") is not False:
            failures.append("the rule engine emergency stop is latched")
        if snapshot["rules"]:
            failures.append("unexpected in-memory rules exist; coordinator will not replace them")
        if failures:
            raise CoordinatorError("PREFLIGHT_FAILED", "; ".join(dict.fromkeys(failures)))
        return run_id, server_identity

    def _stop_empty_session_before_setup(self) -> None:
        status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
        if status.get("enabled") is not True:
            return
        if int(status.get("pendingRequests", -1)) != 0 or int(status.get("pendingResponses", -1)) != 0:
            raise CoordinatorError("PREFLIGHT_FAILED", "an active session has held traffic; no rules or traffic were changed")
        self.tool("burp_set_live_interception_state", enabled=False)
        stopped = self.tool("burp_get_intercept_status", includeDiagnostics=False)
        if stopped.get("enabled") is not False:
            raise CoordinatorError("PREFLIGHT_FAILED", "could not stop the empty session before rule configuration")

    def _start_fixture(self) -> None:
        root = Path(__file__).resolve().parents[1]
        log_path = root / "build" / "live-test-server-observations.jsonl"
        self.log_baseline = log_path.stat().st_size if log_path.exists() else 0
        script = root / "scripts" / "prepare-cancel-test-server.ps1"
        env = os.environ.copy()
        env["BURP_TEST_RUN_ID"] = self.run_id or ""
        env["BURP_TEST_SERVER_IDENTITY"] = self.server_identity or ""
        env.pop("BURP_MCP_TOKEN", None)
        env["BURP_RULE_FIXTURE_SCRIPT"] = str(script)
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        readiness_path = self.evidence_path.with_suffix(".fixture.json")
        error_path = self.evidence_path.with_suffix(".fixture.err.log")
        # A detached PowerShell fixture can inherit pipe handles. File-backed output
        # lets the launcher exit without communicate() waiting for the fixture's EOF.
        with readiness_path.open("wb") as stdout, error_path.open("wb") as stderr:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                 "& $env:BURP_RULE_FIXTURE_SCRIPT -IdentityFromEnvironment -RuleEngineTestMode -PassThru | ConvertTo-Json -Compress"],
                cwd=str(root), env=env, stdout=stdout, stderr=stderr, timeout=20, check=False,
            )
        if result.returncode != 0:
            raise CoordinatorError("FIXTURE_FAILED", "identity-bound rule-test fixture did not start cleanly")
        try:
            ready = json.loads(readiness_path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as error:
            raise CoordinatorError("FIXTURE_FAILED", "fixture readiness result was unreadable") from error
        if ready.get("State") != "READY" or ready.get("RuleEngineTestMode") is not True:
            raise CoordinatorError("FIXTURE_FAILED", "fixture did not confirm identity-bound rule-test mode")
        self.fixture_pid = int(ready["ProcessId"])
        preflight.check_test_server_health(self.run_id, self.server_identity)
        self.fixture_mode = True

    def _create_rules_before_session(self) -> None:
        status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
        if status.get("enabled") is True:
            raise CoordinatorError("SETUP_ORDER_FAILED", "rule creation requires the session to be stopped")
        for spec in build_rule_specs(self.run_id or ""):
            created = self.tool("burp_create_interception_rule", spec=spec)
            rule_id = created.get("id") or created.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id:
                raise CoordinatorError("SETUP_FAILED", "Burp did not return an ID for a created rule")
            self.rule_ids[spec["name"]] = rule_id
        self.rules = self.tool("burp_list_interception_rules", includeDiagnostics=False)
        failures = rule_readiness_failures(self.rules, self.run_id or "", frozenset())
        if failures:
            raise CoordinatorError("READINESS_FAILED", "; ".join(failures) + "; no request was sent")

    def _start_session_and_enable_rules(self) -> None:
        mode = self.tool("burp_get_intercept_status", includeDiagnostics=False).get("unattendedMode", {})
        if int(mode.get("remainingMillis", 0)) < SESSION_LIFETIME_SECONDS * 1000 + 10_000:
            raise CoordinatorError("AUTHORIZATION_WINDOW_LOW", "not enough authorization remains to start the bounded session")
        # Native Proxy Intercept uses Burp's separate human approval dialog.
        # Resolve it before opening the bounded live-interception session.
        if not self.native_intercept_prepared:
            self.tool("burp_set_proxy_intercept_state", enabled=False)
            self.native_intercept_prepared = True
        self.tool("burp_set_live_interception_state", enabled=True,
                  sessionLifetimeSeconds=SESSION_LIFETIME_SECONDS)
        self.session_started = True
        for name in sorted(CORE_ACTIVE_RULES):
            self.tool("burp_enable_interception_rule", ruleId=self.rule_ids[name])
        self.rules = self.tool("burp_list_interception_rules", includeDiagnostics=False)
        status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
        engine = self.tool("burp_get_rule_engine_status", includeDiagnostics=False)
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_path.with_suffix(".rules.json").write_text(json.dumps(self.rules, indent=2), encoding="utf-8")
        require_pretraffic_readiness(status, engine, self.rules, self.run_id or "")
        self.response_rule = next(rule for rule in self.rules if _entry_parts(rule)[0] == RESPONSE_RULE)

    def _origin_records(self) -> list[dict]:
        path = Path(__file__).resolve().parents[1] / "build" / "live-test-server-observations.jsonl"
        if not path.exists():
            return []
        with path.open("rb") as stream:
            stream.seek(self.log_baseline)
            raw = stream.read().decode("utf-8", errors="strict")
        records = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("path") == "/test-post" and record.get("ruleTestId"):
                records.append(record)
        return records

    def _verify_origin(self, case_id: str, expected_enabled: bool, expect_rule_header: bool,
                       expect_pause_header: bool) -> dict:
        deadline = self.clock() + 2.0
        while self.clock() < deadline:
            found = [record for record in self._origin_records() if record.get("ruleTestId") == case_id]
            if found:
                if len(found) != 1:
                    raise CoordinatorError("ORIGIN_DUPLICATE", "origin logged more than one delivery for a unique test ID")
                record = found[0]
                if record.get("postEnabled") is not expected_enabled or record.get("bodyFramingVerified") is not True or record.get("utf8BodyValid") is not True:
                    raise CoordinatorError("ORIGIN_MISMATCH", "origin body value or framing did not match the planned exchange")
                if record.get("ruleTestHeaderObserved") is not expect_rule_header or record.get("pauseHeaderObserved") is not expect_pause_header:
                    raise CoordinatorError("ORIGIN_HEADER_MISMATCH", "origin header observations did not match the planned exchange")
                return record
            self.sleeper(0.05)
        raise CoordinatorError("ORIGIN_EVIDENCE_MISSING", "client completed without a matching origin log record")

    @staticmethod
    def _http_post(case_id: str, run_id: str, server_identity: str, *, rule_header=False, pause_header=False,
                   timeout=CLIENT_TIMEOUT_SECONDS, target_url=TARGET_URL) -> dict:
        if target_url not in (TARGET_URL, TARGET_SESSION_URL):
            raise CoordinatorError("UNAPPROVED_CLIENT_TARGET", "client target is outside the two fixed fixture URLs")
        body_object = {"enabled": False, "name": "original", "mcp_test": "after", "marker": "preserve",
                       "case": case_id, "nested": {"keep": 17}}
        body = json.dumps(body_object, separators=(",", ":")).encode("utf-8")
        headers = {
            "Host": "127.0.0.1:8000", "Content-Type": "application/json", "Accept": "application/json",
            "Connection": "close",
            "X-MCP-Test-ID": case_id,
        }
        if target_url == TARGET_URL:
            headers.update({"X-MCP-Test-Run": run_id, "X-MCP-Server-Identity": server_identity})
        if rule_header:
            headers["X-MCP-Rule-Test-Eligible"] = "active"
        if pause_header:
            headers["X-MCP-Pause-Forward"] = "active"
        connection = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=timeout)
        try:
            connection.request("POST", target_url, body=body, headers=headers)
            response = connection.getresponse()
            response_bytes = response.read(65537) if target_url == TARGET_SESSION_URL else response.read()
            if target_url == TARGET_SESSION_URL and len(response_bytes) > 65536:
                raise CoordinatorError("CLIENT_RESPONSE_TOO_LARGE", "target fixture response exceeded 64 KiB")
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            parsed = json.loads(response_bytes.decode("utf-8"))
            return {
                "status": response.status, "body": parsed,
                "requestSha256": hashlib.sha256(body).hexdigest(),
                "responseSha256": hashlib.sha256(response_bytes).hexdigest(),
                "pauseResponseHeader": response_headers.get("x-mcp-pause-forward"),
            }
        finally:
            connection.close()

    def _exchange(self, case_id: str, *, expected_enabled=True, rule_header=False, pause_header=False,
                  response_rule_name=RESPONSE_RULE) -> dict:
        active_response_rule = next((rule for rule in self.rules if _entry_parts(rule)[0] == response_rule_name), None)
        if active_response_rule is None:
            raise CoordinatorError("READINESS_FAILED", "response rule was not verified before traffic")
        before_stats = self.tool("burp_get_interception_rule_stats", ruleId=self.rule_ids[response_rule_name])
        matches_before = int(before_stats.get("matchedResponses", 0))
        failures_before = int(before_stats.get("failed", 0))
        skipped_before = int(before_stats.get("skipped", 0))
        outcome: queue.Queue = queue.Queue(maxsize=1)

        def send_once():
            try:
                outcome.put((True, self._http_post(case_id, self.run_id or "", self.server_identity or "",
                                                  rule_header=rule_header, pause_header=pause_header,
                                                  timeout=self.http_timeout)))
            except BaseException as error:  # propagate the single attempt; never retry it
                outcome.put((False, error))

        # Count before starting the worker so diagnostics remain conservative if
        # thread scheduling or socket setup fails after the one-shot attempt.
        self.client_attempts_started += 1
        threading.Thread(target=send_once, name="burp-local-rule-client", daemon=True).start()
        deadline = self.clock() + self.http_timeout + 1.0
        pending_since = None
        while self.clock() < deadline:
            try:
                success, result = outcome.get_nowait()
            except queue.Empty:
                success = result = None
            if success is True:
                break
            if success is False:
                pending = self.tool("burp_list_pending_responses", includeDiagnostics=False)
                if pending:
                    raise WaitingForApproval("client attempt ended while the response remained in Burp's approval queue; no retry was made", len(pending))
                raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "client attempt failed without a response queue entry; no retry was made") from result

            status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
            pending = self.tool("burp_list_pending_responses", includeDiagnostics=False)
            if pending:
                if pending_since is None:
                    pending_since = self.clock()
                current_stats = self.tool("burp_get_interception_rule_stats", ruleId=self.rule_ids[response_rule_name])
                state, reason = response_wait_state(
                    pending, active_response_rule, matches_before, int(current_stats.get("matchedResponses", 0)),
                    processing_grace_elapsed=self.clock() - pending_since >= APPROVAL_DIAGNOSTIC_GRACE_SECONDS,
                    failures_before=failures_before, failures_after=int(current_stats.get("failed", 0)),
                    skipped_before=skipped_before, skipped_after=int(current_stats.get("skipped", 0)),
                    last_error_code=current_stats.get("lastErrorCode"),
                )
                if state == "WAITING_FOR_APPROVAL":
                    self.waiting_for_approval = True
                    raise WaitingForApproval(reason or "response remains held", len(pending))
            else:
                pending_since = None
            if int(status.get("sessionRemainingMillis", 0)) < 2_000 or status.get("enabled") is not True:
                raise CoordinatorError("SESSION_EXPIRED", "session expired while the one-shot client request was in flight; no retry was made")
            self.sleeper(POLL_INTERVAL_SECONDS)
        else:
            pending = self.tool("burp_list_pending_responses", includeDiagnostics=False)
            if pending:
                self.waiting_for_approval = True
                raise WaitingForApproval("response remained held beyond the coordinator wait budget; no retry was made", len(pending))
            raise CoordinatorError("CLIENT_OUTCOME_UNKNOWN", "client response deadline elapsed; the request was not retried")

        if result["status"] != 200 or result["body"].get("enabled") is not expected_enabled:
            raise CoordinatorError("CLIENT_RESPONSE_MISMATCH", "client-visible JSON response did not match the expected enabled value")
        for key, value in (("name", "original"), ("mcp_test", "after"), ("marker", "preserve"),
                           ("case", case_id), ("nested", {"keep": 17})):
            if result["body"].get(key) != value:
                raise CoordinatorError("CLIENT_RESPONSE_MISMATCH", f"client-visible response field {key} was not preserved")
        if pause_header and result.get("pauseResponseHeader") != "active":
            raise CoordinatorError("CLIENT_RESPONSE_MISMATCH", "pause pass-through response marker was not received")
        origin = self._verify_origin(case_id, expected_enabled=not pause_header,
                                     expect_rule_header=rule_header and not pause_header,
                                     expect_pause_header=pause_header)
        evidence = {"case": case_id, "status": result["status"], "clientEnabled": result["body"]["enabled"],
                "clientSha256": result["responseSha256"], "originSha256": origin.get("bodySha256"),
                "originEnabled": origin.get("postEnabled"), "originDeliveryCount": 1,
                "clientBody": result["body"], "requestSha256": result["requestSha256"],
                "originFramingVerified": origin.get("bodyFramingVerified"),
                "originHeaderObserved": origin.get("ruleTestHeaderObserved"),
                "originPauseHeaderObserved": origin.get("pauseHeaderObserved")}
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with self.evidence_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(evidence, separators=(",", ":")) + "\n")
        self.verified_exchanges.append(evidence)
        return evidence

    def _stats(self) -> dict[str, dict]:
        return {name: self.tool("burp_get_interception_rule_stats", ruleId=self.rule_ids[name]) for name in RULE_NAMES}

    def _verify_counters(self) -> dict[str, dict]:
        stats = self._stats()
        expected = {
            REQUEST_RULE: (8, 8, 8),
            RESPONSE_RULE: (8, 8, 8),
            HEADER_RULE: (2, 2, 2),
            PAUSE_REQUEST_RULE: (1, 0, 1),
            PAUSE_RESPONSE_RULE: (1, 0, 1),
        }
        for name, (matches, modifications, forwarded) in expected.items():
            row = stats[name]
            observed = (int(row.get("matchedRequests", 0)) + int(row.get("matchedResponses", 0)),
                        int(row.get("modified", 0)), int(row.get("forwarded", 0)))
            if (observed != (matches, modifications, forwarded) or int(row.get("failed", 0)) != 0 or
                    int(row.get("dropped", 0)) != 0 or int(row.get("skipped", 0)) != 0):
                raise CoordinatorError("COUNTER_MISMATCH", f"{name} counters did not match actual expected messages")
        return stats

    def _stop_fixture(self) -> None:
        if self.fixture_pid is None:
            return
        command = (
            f"$process=Get-CimInstance Win32_Process -Filter 'ProcessId={self.fixture_pid}'; "
            "if($process -and $process.CommandLine -match 'local-test-server\\.ps1'){"
            f"Stop-Process -Id {self.fixture_pid} -Force -ErrorAction SilentlyContinue}}"
        )
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                       capture_output=True, text=True, timeout=10, check=False)
        self.fixture_pid = None

    def _cleanup_success(self) -> dict:
        status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
        if int(status.get("pendingRequests", 0)) or int(status.get("pendingResponses", 0)):
            raise CoordinatorError("CLEANUP_BLOCKED", "held traffic requires its existing approval path; cleanup did not release it")
        for name, rule_id in self.rule_ids.items():
            rule = self.tool("burp_get_interception_rule", ruleId=rule_id)
            if rule.get("state") == "ACTIVE":
                self.tool("burp_disable_interception_rule", ruleId=rule_id)
            self.tool("burp_delete_interception_rule", ruleId=rule_id)
        self.rule_ids.clear()
        self._stop_fixture()
        # Let the short, empty session reach its normal bounded expiry.
        deadline = self.clock() + SESSION_LIFETIME_SECONDS + 5
        final = status
        while self.clock() < deadline:
            final = self.tool("burp_get_intercept_status", includeDiagnostics=False)
            if final.get("enabled") is not True:
                break
            self.sleeper(0.5)
        if (final.get("enabled") is True or final.get("sessionEndReason") != "SESSION_EXPIRED" or
                final.get("heartbeatHealth") != "EXPIRED" or int(final.get("pendingRequests", -1)) != 0 or
                int(final.get("pendingResponses", -1)) != 0):
            raise CoordinatorError("CLEANUP_FAILED", "session did not expire cleanly with empty queues")
        engine = self.tool("burp_get_rule_engine_status", includeDiagnostics=False)
        if int(engine.get("configuredRules", -1)) != 0:
            raise CoordinatorError("CLEANUP_FAILED", "owned rules remain configured")
        return {"sessionExpired": True, "sessionEndReason": final.get("sessionEndReason"),
                "queuesEmpty": True, "rulesDeleted": True}

    def run(self) -> dict:
        snapshot = self._snapshot(self.client)
        self.run_id, self.server_identity = self._validate_initial(snapshot)
        self._stop_empty_session_before_setup()
        preflight.check_proxy_listener()
        if snapshot["server"].get("buildId") != EXPECTED_BUILD_ID:
            raise CoordinatorError("PREFLIGHT_FAILED", "unexpected candidate build")
        try:
            self._start_fixture()
            self._create_rules_before_session()
            self._start_session_and_enable_rules()

            exchanges = []
            exchanges.append(self._exchange(self._case_id("single")))
            for index in range(1, 6):
                exchanges.append(self._exchange(self._case_id(f"sequential-{index:02d}")))
            exchanges.append(self._exchange(self._case_id("multiple"), rule_header=True))

            for name in CORE_ACTIVE_RULES:
                self.tool("burp_disable_interception_rule", ruleId=self.rule_ids[name])
            self.tool("burp_enable_interception_rule", ruleId=self.rule_ids[PAUSE_REQUEST_RULE])
            self.tool("burp_enable_interception_rule", ruleId=self.rule_ids[PAUSE_RESPONSE_RULE])
            self.rules = self.tool("burp_list_interception_rules", includeDiagnostics=False)
            pause_active = frozenset((PAUSE_REQUEST_RULE, PAUSE_RESPONSE_RULE))
            failures = rule_readiness_failures(self.rules, self.run_id or "", pause_active)
            if failures:
                raise CoordinatorError("PAUSE_READINESS_FAILED", "; ".join(failures))
            exchanges.append(self._exchange(self._case_id("paused"), expected_enabled=False, pause_header=True,
                                            response_rule_name=PAUSE_RESPONSE_RULE))

            self.tool("burp_disable_interception_rule", ruleId=self.rule_ids[PAUSE_REQUEST_RULE])
            self.tool("burp_disable_interception_rule", ruleId=self.rule_ids[PAUSE_RESPONSE_RULE])
            for name in sorted(CORE_ACTIVE_RULES):
                self.tool("burp_enable_interception_rule", ruleId=self.rule_ids[name])
            self.rules = self.tool("burp_list_interception_rules", includeDiagnostics=False)
            failures = rule_readiness_failures(self.rules, self.run_id or "", CORE_ACTIVE_RULES)
            if failures:
                raise CoordinatorError("RESUME_READINESS_FAILED", "; ".join(failures))
            self.response_rule = next(rule for rule in self.rules if _entry_parts(rule)[0] == RESPONSE_RULE)
            exchanges.append(self._exchange(self._case_id("resumed"), rule_header=True))

            counters = self._verify_counters()
            expected_cases = {entry["case"] for entry in exchanges}
            origin_cases = [record.get("ruleTestId") for record in self._origin_records()]
            if any(origin_cases.count(case_id) != 1 for case_id in expected_cases) or len(origin_cases) != len(expected_cases):
                raise CoordinatorError("ORIGIN_DUPLICATE", "origin record count does not equal the one-shot client exchange count")
            cleanup = self._cleanup_success()
            return {"state": "PASS", "liveProxy": True, "exchangeCount": len(exchanges),
                    "exchanges": exchanges, "evidencePath": str(self.evidence_path),
                    "clientResponsesVerified": len(exchanges), "originDeliveriesVerified": len(expected_cases),
                    "multipleRulesVerified": True, "pauseResumeVerified": True, "counters": counters,
                    "cleanup": cleanup}
        except WaitingForApproval:
            self.waiting_for_approval = True
            remaining_rules = dict(self.rule_ids)
            for name, rule_id in list(self.rule_ids.items()):
                try:
                    self.tool("burp_disable_interception_rule", ruleId=rule_id)
                except Exception:
                    pass
                try:
                    self.tool("burp_delete_interception_rule", ruleId=rule_id)
                    remaining_rules.pop(name, None)
                except Exception:
                    pass
            self.rule_ids = remaining_rules
            try:
                remaining = self.tool("burp_list_interception_rules", includeDiagnostics=False)
                remaining_names = {_entry_parts(entry)[0] for entry in remaining}
                self.owned_rules_deleted = not self.rule_ids and not (set(RULE_NAMES) & remaining_names)
            except Exception:
                self.owned_rules_deleted = False
            self._stop_fixture()
            raise
        except Exception:
            if not self.waiting_for_approval:
                self._cleanup_without_held_traffic()
            raise

    def _cleanup_without_held_traffic(self) -> None:
        try:
            status = self.tool("burp_get_intercept_status", includeDiagnostics=False)
            if int(status.get("pendingRequests", 0)) or int(status.get("pendingResponses", 0)):
                self._stop_fixture()
                return
            for rule_id in list(self.rule_ids.values()):
                try:
                    self.tool("burp_disable_interception_rule", ruleId=rule_id)
                    self.tool("burp_delete_interception_rule", ruleId=rule_id)
                except Exception:
                    continue
            self.rule_ids.clear()
            if status.get("enabled") is True:
                self.tool("burp_set_live_interception_state", enabled=False)
            self._stop_fixture()
        except Exception:
            self._stop_fixture()

    def _case_id(self, suffix: str) -> str:
        return f"rule-{uuid.uuid4().hex}-{suffix}"


def main(argv=None) -> int:
    coordinator = None
    try:
        args = list(sys.argv[1:] if argv is None else argv)
        if args not in ([], ['--target-preflight-only']):
            raise CoordinatorError('INVALID_ARGUMENTS', 'unsupported invocation; no session or traffic started')
        client = preflight.initialize()
        if args == ['--target-preflight-only']:
            print(json.dumps(target_session_preflight(client), separators=(',', ':')))
            return 0
        coordinator = LiveRuleEngineCoordinator(client)
        result = coordinator.run()
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except WaitingForApproval as error:
        print(json.dumps({"state": error.code, "pendingResponses": error.pending_responses,
                          "diagnostic": str(error), "retry": False,
                          "clientAttemptsStarted": coordinator.client_attempts_started if coordinator else 0,
                          "ownedRulesDeleted": coordinator.owned_rules_deleted if coordinator else False},
                         separators=(",", ":")))
        return 3
    except (CoordinatorError, preflight.PreflightError, OSError, ValueError) as error:
        code = error.code if isinstance(error, CoordinatorError) else "PREFLIGHT_FAILED"
        print(json.dumps({"state": code, "diagnostic": str(error),
                          "liveTrafficStarted": bool(coordinator and coordinator.client_attempts_started),
                          "clientAttemptsStarted": coordinator.client_attempts_started if coordinator else 0},
                         separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
