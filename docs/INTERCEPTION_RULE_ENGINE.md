# Burp MCP interception rule engine

For current v1.5.0 target-specific preparation/session execution and verification
limits, see [v1.5.0 verification](V1_5_0_VERIFICATION.md). The unattended workflow
below describes the separate legacy nine-path policy, which cannot approve target
grant/session prompts.

For practical manual/automated browsing, independent edit controls and current
recovery limitations, read [browser/Burp workflow](BROWSER_BURP_WORKFLOW.md).
The legacy queue behavior below must not be applied to target sessions: unsupported,
conflicted or unauthorized target-session traffic continues unchanged without
entering the manual queue. Target sessions reject DROP and still require exact
grant/session binding. The original nine localhost rule targets cannot use target
grants instead of their separate unattended authority.

## What it does

The rule engine runs inside the existing `LiveInterception` Proxy request and response callbacks. It evaluates bounded rules against each held message before the existing callback releases it. A matching rule does not make a network decision by itself: the exact message still has to pass the current Burp scope, explicit MCP allowlist, identity, revision, heartbeat, session, and unattended-policy checks. The existing decision queue remains the source of message IDs, revisions, deadlines, one-time approval, and final release.

Rules run locally in Burp; no per-message MCP polling or model round trip is needed. A rule that does not match leaves the message on the existing manual queue. A conflict, unsupported encoding, malformed body, sensitive message, failed validation, expired authorization, or changed rule state also leaves it for manual handling. No modified message is automatically released on an ambiguous result.

The engine is process-local and starts with zero enabled rules after extension reload. It supports up to 64 configured rules, eight transformations per rule, 16 conditions, 32 matches and a separately reserved cap of 32 actual modifications per rule, at most 300 seconds per rule, 64 KiB per message, 500 sanitized events, the existing eight queue slots, and the unattended policy's two automatic in-flight messages. A no-op forward consumes a match but not a modification. Concurrent changed messages reserve modification slots before release, so they cannot exceed the configured modification cap.

## Authorization boundary

The current policy supports only `http://127.0.0.1:8000` and these nine existing paths:

```text
/test-html
/test-post
/test-form
/test-upload
/test-cancel
/test-timeout
/test-session-expiry
/test-concurrent-a
/test-concurrent-b
```

The `targetUrl` must be one exact URL from this list, or the fixed authority `http://127.0.0.1:8000` paired with an exact `path` or safe `pathPrefix` condition. At runtime the authority form still matches only the nine listed paths. It does not add a Burp scope entry or expand the unattended allowlist.

An operator must activate Unattended Local Test Mode through its existing visible Burp control. MCP rule tools cannot activate or renew it. The authenticated rule configuration must reference the current synthetic **test-run ID**. The server identity and bearer token are not placed in rule configuration. Each automatic operation is checked again against the current authorization and session; rule TTL is capped by the remaining time in both. Ending the session pauses active rules. Deactivating unattended mode pauses them immediately. There is no automatic renewal.

The existing local “live edits” control must be enabled for `MODIFY_AND_FORWARD`. The existing read-only setting must remain off. Native Proxy Intercept is a separate Burp control and is not changed by rules. The live-test coordinator requests that native interception be disabled before it starts the bounded session; Burp's separate `Approve once` prompt remains human-controlled.

Automatic response edits are permitted only when the response rule is active and the response belongs to a synthetic request that already passed the unattended policy as an automatic test request. The response still has to pass its own target, status, content-type, JSON-condition, session, identity, scope and authorization checks. A missing, disabled, unmatched, skipped or policy-rejected response rule leaves the response in the existing manual-review queue. The coordinator reports `WAITING_FOR_APPROVAL`, stops sending further test requests, disables and deletes only its owned rules, and stops the fixture. The held response remains available through Burp's existing manual approval path; the coordinator never approves, forwards, drops or retries it.

## Rule lifecycle

1. Authenticate to the loopback MCP endpoint.
2. Explicitly activate Unattended Local Test Mode in Burp.
3. Confirm the exact localhost scope/allowlist and empty request/response queues.
4. Start the identity-bound local fixture and create all request and response rules while the live-interception session is stopped. Rules are created disabled.
5. Disable native Proxy Intercept through its separate supported control and complete Burp's `Approve once` prompt if shown.
6. Start the existing bounded interception session. Its usual local approval policy applies.
7. Enable every rule needed for the planned exchanges, including the response rule, then verify exact rule state, priority, conditions, empty queues, active identity and remaining session/authorization time before sending the first request. Reject incomplete setup without sending traffic.
8. Send only synthetic traffic through Burp Proxy. Burp evaluates the rules on each matching request and its associated response.
9. If a response stays held, surface `WAITING_FOR_APPROVAL` promptly and stop the sequence; keep the existing human approval path intact.
10. Read rule statistics/events as needed. Pause or disable rules explicitly when done.
11. Stop the session or deactivate unattended mode. Active rules pause; they do not resume automatically.

The MCP API provides:

| Tool | Use |
| --- | --- |
| `burp_create_interception_rule` | Validate and store a disabled rule |
| `burp_list_interception_rules` / `burp_get_interception_rule` | Inspect configurations and lifecycle state |
| `burp_update_interception_rule` | Replace a disabled rule before session start; replacement is disabled |
| `burp_enable_interception_rule` / `burp_disable_interception_rule` | Enable within current session / pause one rule |
| `burp_delete_interception_rule` / `burp_clear_interception_rules` | Remove configurations |
| `burp_preview_interception_rule` | Dry-run a bounded synthetic sample; sends no traffic |
| `burp_get_interception_rule_stats` / `burp_get_interception_rule_events` | Inspect counts and bounded sanitized outcomes |
| `burp_get_rule_engine_status` | Inspect active/configured count and emergency latch |
| `burp_clear_interception_rule_stats` | Clear counters only |
| `burp_pause_all_interception_rules` | Stop automatic rule processing; session remains active |
| `burp_emergency_stop_rules` | Latch rules off, disable local authorization, stop the session, and drop held messages |

## Matching

All configured conditions are ANDed. Conditions include method, exact path, safe path prefix, query name/value, current-message header name/value, content type, typed JSON path/value, form field/value, and response status. Header names are matched case-insensitively; configured values are exact. Query and form comparisons use UTF-8 URL decoding. Matching is against the original message snapshot; transforms then run in deterministic priority order (higher number first, then stable rule ID).

JSON paths support `$`, dot members such as `$.account.enabled`, and numeric array indexes such as `$.items[0].enabled`. JSON values are typed JSON: `false` is a boolean, while `"false"` is a string. Parent objects must exist; a set may create the final object member. Array indexes must already exist. Duplicate JSON object keys are rejected to avoid collapsing ambiguous input. Bodies and configured JSON literals are limited to 64 nesting levels; a JSON value literal is limited to 4 KiB.

There is no regex or script execution. `pathPrefix` is literal and bounded. A rule with the authority target must include an exact path or a prefix that selects at least one predefined test path; the callback and the unattended policy still reject every path outside the fixed nine.

## Transformations and framing

Supported operations are `SET_JSON_FIELD`, `REMOVE_JSON_FIELD`, `SET_QUERY_PARAMETER`, `REMOVE_QUERY_PARAMETER`, `SET_FORM_FIELD`, `REMOVE_FORM_FIELD`, request/response header set/remove, and literal `REPLACE_EXACT_TEXT` for UTF-8 `text/plain` or `text/html` bodies.

Setting a repeated query/form name updates every occurrence; if there is no occurrence, it appends one. Removing a repeated name removes all occurrences. Setting a header replaces all values for that name with one configured value. Other headers and fields remain unchanged. JSON is re-serialized as UTF-8; its formatting may change, but unrelated JSON values/types are preserved.

Host, framing, connection, authorization, cookie, Set-Cookie, and MCP identity headers cannot be edited automatically. Cookie and credential-bearing traffic remains subject to existing manual review. If any active co-matched rule condition is unsupported or ambiguous, the engine leaves the entire message for manual handling instead of applying other rules as though that rule did not exist. Body edits reject compressed content, non-UTF-8 text, multipart/binary content, duplicate or incorrect `Content-Length`, and `Transfer-Encoding`. When a body changes, a missing Content-Length is added and an existing one is recalculated from the UTF-8 byte count. Montoya constructs the resulting message; the extension validates the resulting size and framing before approval and release.

Multipart, binary, compressed, chunked, streaming, and WebSocket transformations are not supported by this engine. They remain on manual handling. A response `DROP` is not auto-approved: the existing policy allows automatic request drops only, and dropping a response cannot undo its upstream request.

## Multiple rules and conflicts

Compatible transformations on separate fields can be combined in one message. Higher priority wins when two rules write the same resource; the lower-priority write is skipped. JSON paths that are equal or parent/child overlap count as the same resource. Same-priority conflicting writes, equal-priority differing actions, or overlapping text/body transformations produce a conflict and leave the message pending for manual review. A higher-priority `DROP` controls over lower-priority forward rules; an equal-priority drop/forward conflict is not resolved automatically.

Rule updates and disables are generation-checked. A change during evaluation invalidates that plan before it can release a message. Automatic forwarding uses the existing queue ticket, exact revision approval record, rate limiter, and one-shot forwarding state. No queue cap or automatic concurrency limit is increased.

## Observability and current evidence

Counters report request/response matches, actual modifications, automatic forwards/drops, skipped operations, failures, remaining match and modification budgets, expiry, and last sanitized error code. Clearing audit counters does not reset the separately tracked consumed match/modification budgets. Event history is bounded to 500 entries and records rule/message IDs, direction, outcome, approval mode, and short codes. It never stores headers, bodies, tokens, cookies, or server identity.

Unit and mocked Proxy-callback tests establish evaluator and integration behavior. They are not `LIVE_PROXY` evidence. The separately approved dev.5 Batch A proved its two exact-target transformations reached the origin and client; it does not establish all operations or the remaining native priority/lifecycle/reliability cases. See [development status](DEVELOPMENT_STATUS.md). See [AI agent examples](AI_AGENT_INTERCEPTION_EXAMPLES.md) for prompts and MCP call ordering.
