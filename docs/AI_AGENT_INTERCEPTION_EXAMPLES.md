# AI-agent interception rule examples

These examples describe the legacy predefined localhost unattended workflow.
They do not authorize arbitrary websites or supply authority for target sessions.
For the current exact-path, two-native-approval target workflow, natural-language
mapping, browser setup and limits, use [browser/Burp workflow](BROWSER_BURP_WORKFLOW.md).
The original nine localhost rule targets cannot substitute a target preparation
grant for unattended authority. Target sessions reject DROP and leave unsupported
traffic unchanged; the legacy queue/drop behavior below is a separate mode.

## Change a JSON field in every matching request

User instruction:

> On my authorized local test, set `enabled` from boolean false to boolean true on every matching JSON request, then forward it.

The agent should inspect Burp's current authenticated status, confirm the active local test-run ID, scope, allowlist and empty queues, then create a disabled `REQUEST` rule. For example:

```json
{
  "name": "Enable JSON flag on requests",
  "targetUrl": "http://127.0.0.1:8000/test-post",
  "authorizationReference": "<current synthetic test-run ID>",
  "direction": "REQUEST",
  "conditions": {
    "method": "POST",
    "contentType": "application/json",
    "jsonPath": "$.enabled",
    "jsonValueJson": "false"
  },
  "transformations": [
    { "type": "SET_JSON_FIELD", "path": "$.enabled", "valueJson": "true" }
  ],
  "action": "MODIFY_AND_FORWARD",
  "priority": 100,
  "maximumMatches": 5,
  "maximumModifications": 5,
  "durationSeconds": 120
}
```

Call `burp_create_interception_rule` with that object under `spec`. It must return `DISABLED`. Start the bounded session using the existing session-control tool and its current local-approval policy, then call `burp_enable_interception_rule` with the returned rule ID. The extension will process each qualifying request until the match cap, rule TTL, interception-session expiry, or local authorization expiry. The shortest deadline wins.

## Change JSON in each direction

User instruction:

> For the authorized localhost test, change `enabled=false` to `enabled=true` in matching JSON requests and responses.

Use `direction: "BOTH"` with the typed JSON condition/transformation above and a target path that produces both a JSON request and JSON response. Request and response callbacks are evaluated independently. A response is eligible only when the existing unattended policy can associate it with a matching authorized synthetic request. Verify the origin-received request and client-received response independently; one direction does not prove the other.

## Combine compatible rules

Create separate rules, all disabled initially:

1. Set JSON `$.enabled` to boolean `true` on matching requests.
2. Set request header `X-Test-Mode` to `active`.
3. Set response JSON `$.status` to the string `"verified"`.

Create them before starting the session, start one approved session, and enable the rules while the queues are empty. Distinct fields are applied deterministically. If rules of equal priority write conflicting values to the same field, the extension leaves the message pending for manual review and records a conflict.

## Other examples

- **Request header:** `SET_REQUEST_HEADER`, `name: "X-Test-Mode"`, `value: "active"`.
- **Response header:** `SET_RESPONSE_HEADER`, `name: "X-Test-Result"`, `value: "verified"`.
- **Query parameter:** `SET_QUERY_PARAMETER`, `name: "mode"`, `value: "test"`; every duplicate `mode` value is updated.
- **Form field:** `SET_FORM_FIELD`, `name: "enabled"`, `value: "true"` on URL-encoded request bodies.
- **HTML response:** `REPLACE_EXACT_TEXT` with a literal search/replacement on UTF-8 `text/html`; this is literal text matching, not a regular expression.
- **Drop:** set `action: "DROP"` on an exact request rule. Response drops still require the existing local review.

## Operate and observe rules

- “Show my active interception rules.” → call `burp_list_interception_rules` and `burp_get_rule_engine_status`.
- “Pause rule `<id>`.” → call `burp_disable_interception_rule`.
- “Resume rule `<id>`.” → call `burp_enable_interception_rule`; it must still be within current authorization/session and empty-queue requirements.
- “How many requests did the rule modify?” → call `burp_get_interception_rule_stats` with its ID.
- “Show the last ten rule outcomes.” → call `burp_get_interception_rule_events` with `count: 10`.
- “Stop all automatic rule changes.” → call `burp_pause_all_interception_rules`; this pauses rules but leaves the bounded session unchanged.
- “Emergency stop everything.” → call `burp_emergency_stop_rules`; this ends the local authorization and interception session and drops held traffic. Fresh human-visible activation is required before automatic processing can be enabled again.

## Expiry and unsupported traffic

“Until I stop” means until the rule is manually paused, its maximum matches or actual modifications are consumed, its configured TTL expires, its interception session ends, or its local authorization expires—whichever happens first. No-op forwards consume a match but not the modification cap. No tool call renews authorization. A new session does not silently resume prior rules.

Compressed, multipart, binary, malformed JSON, duplicate-key JSON, invalid framing, credential/cookie-bearing, or otherwise unsupported messages do not get an automatic modified release. They remain under existing manual controls or are rejected by the current fail-closed policy. Use the dry-run `burp_preview_interception_rule` with synthetic input to inspect match and support status before enabling a rule.

## Evidence boundary

Rule creation, schema checks, deterministic transforms, and mocked Proxy callbacks are not proof of live network delivery. Report `LIVE_PROXY` only after a real synthetic request crosses the running Burp Proxy and the origin/client observations confirm the exact result. Never label mock or preview output as a live success.
