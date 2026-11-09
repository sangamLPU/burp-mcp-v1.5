# Continuous interception rule engine: LIVE_PROXY verification

Verified against the already loaded Burp MCP 1.4.0 build `20261101.13-burp2024.1.1.1` and Burp Professional 2024.1.1.1 on 2026-11-02. No extension rebuild, reload, full-suite run, or GitHub push was performed for this test.

## LIVE_PROXY results

**PASS: nine unique POST exchanges, nine HTTP 200 client responses, nine actual origin deliveries, zero duplicate deliveries.** Each request was sent once through `127.0.0.1:8080` to the identity-bound fixture at `127.0.0.1:8000/test-post`. Both modification rules were verified ACTIVE before the first POST. The 60-second interception session was started before rule enablement because the engine requires a healthy session to enable rules.

| Phase | Exchanges | Origin request enabled | Client response enabled | Result |
|---|---:|---|---|---|
| Complete request/response modification | 1 | true | true | PASS |
| Five sequential modifications | 5 | true | true | PASS |
| Compatible JSON and request-header rules | 1 | true; added header observed | true | PASS |
| Modification rules paused; bounded pass-through rules active | 1 | false; pause marker observed | false | PASS |
| Modification rules resumed | 1 | true; added header observed | true | PASS |

Clients originally sent `enabled=false`. The rule-test fixture deliberately emits `enabled=false` in its origin response, allowing the response rule's independent change to be checked at the HTTP client. Client evidence records the returned synthetic JSON, status and SHA-256. Origin observations record the unique case ID, received enabled value, header observations, exact body byte count and SHA-256. All nine origins passed UTF-8 and framing validation, and unrelated client JSON fields were preserved. The `originSha256` field is the received request-body hash, not an origin response-body hash.

| Rule | Matches | Modifications | Forwards | Failures / drops / skips |
|---|---:|---:|---:|---|
| Request JSON | 8 | 8 | 8 | 0 / 0 / 0 |
| Response JSON | 8 | 8 | 8 | 0 / 0 / 0 |
| Compatible request header | 2 | 2 | 2 | 0 / 0 / 0 |
| Paused-phase request pass-through | 1 | 0 | 1 | 0 / 0 / 0 |
| Paused-phase response pass-through | 1 | 0 | 1 | 0 / 0 / 0 |

These are per-rule counts: compatible rules can count the same message. The actual network count remains nine complete exchanges. No response required manual approval. No ambiguous request was retried.

## Cleanup and expiry

All five owned rules were deleted, the fixture process was stopped, and both queues were empty. The empty session reached normal `SESSION_EXPIRED` with heartbeat state `EXPIRED`; live interception was disabled. The final read-only check also confirmed unattended authorization expired naturally: inactive with zero remaining milliseconds. This verifies session and authorization expiration after cleanup. Individual rule TTL expiration was not exercised because the rules had already been deleted.

## Reproduced coordinator defects and targeted regressions

The initial launcher/registration attempts sent zero POSTs. Their setup failures were corrected under the same bounded local authorization:

1. The PowerShell fixture launcher returned display-formatted objects, while Python expected JSON; inherited output pipes also kept Python waiting after launcher exit. The coordinator now serializes the readiness object with `ConvertTo-Json -Compress` and uses file-backed stdout/stderr. The unused first fixture was explicitly stopped.
2. Kotlin omits `InterceptionRuleSpec` default values when serializing. The coordinator now interprets omitted `action` as `MODIFY_AND_FORWARD` and omitted `priority` as 100, matching the loaded schema; explicit unexpected values still fail readiness.
3. Rule statistics are returned as a one-item array even with `ruleId`. The coordinator now unwraps exactly one object for a requested rule and rejects an ambiguous cardinality.

The earlier preparation also reproduced and fixed the `PAUSED` versus `DISABLED` lifecycle mismatch. The offline coordinator simulation now uses the actual PAUSED transition.

**OFFLINE, separate from LIVE_PROXY:** 14 targeted coordinator tests passed after the launcher, default-serialization and statistics-array fixes. No full test suite was rerun. Per-exchange evidence is persisted before cleanup, so a later failure cannot erase earlier verified exchanges.

## Evidence artifacts

- [Supervised report, counters and rule events](../build/reports/live-rule-engine/supervised-live-20261102.json)
- [Nine client/origin exchange records](../build/reports/live-rule-engine/exchanges-c0d7399e9f5b4efc9a71ded185bc08b0.jsonl)
- [Active rule configurations checked before traffic](../build/reports/live-rule-engine/exchanges-c0d7399e9f5b4efc9a71ded185bc08b0.rules.json)
- [Fixture readiness record](../build/reports/live-rule-engine/exchanges-c0d7399e9f5b4efc9a71ded185bc08b0.fixture.json)
- [Actual origin observation log](../build/live-test-server-observations.jsonl)

The artifacts contain synthetic traffic evidence and rule IDs, with no bearer token or server identity. Build artifacts are local and may be ignored by Git; this document preserves the result summary.
