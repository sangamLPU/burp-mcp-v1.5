# Reliability follow-up after the nine-exchange LIVE_PROXY milestone

Final Phase 4A PASS is recorded in [release readiness](FINAL_RELEASE_READINESS_v1.4.0.md). Earlier live results: [Phase 4A INCONCLUSIVE; 4B, 4C and 4D PASS](PHASE_4_LIVE_RESULTS_2026_11_02.md). The preparation section below is retained as the test plan, not the final status.

## Preserved milestone

The successful continuous request/response rule test remains recorded in [LIVE_RULE_ENGINE_2026_11_02.md](LIVE_RULE_ENGINE_2026_11_02.md). Its nine successful exchanges and origin/client evidence have not been replaced.

The working JAR, complete source/scripts/docs snapshot and existing successful live evidence were copied to `build/milestones/live-proxy-9-exchanges-20261102T090247Z/`. The [preservation manifest](../build/milestones/live-proxy-9-exchanges-20261102T090247Z/manifest.json) records both archive and JAR hashes. The preserved JAR and current `build/libs/burp-mcp-all.jar` share SHA-256 `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`. No rebuild, reload, working rule-engine change, or GitHub push was performed.

## Independent verification completed

| Check | Result | Limit |
|---|---|---|
| Bounded live MCP stability | PASS: 64 fresh clients in eight rounds, eight concurrent workers, 71 seconds; slowest client 146 ms. Each initialized, pinged, listed 86 tools and retrieved running build .13 status. No session headers or failures. | The historical freeze did not recur in this bounded sample; its original cause is not established. |
| Safe local MCP tool audit | 38 PASS, one expected unsupported Repeater enumeration result, one expected unknown-scan rejection, zero failures. | A returned empty collection or negative-path rejection does not prove positive behavior for every capability. |
| Original response corroboration | All nine prior synthetic exchanges found in Burp history with original origin-response `enabled=false`, independently of client evidence. | No raw history or identity-bearing headers were persisted by the audit. |
| Phase coordinator targeted tests | 10 PASS: identity/expiry gates, no network on failed authorization, no queue clearing, one-shot client behavior, ambiguous timeout classification, exact approval requirement, stale-ID rejection, retained partial evidence, B-before-A mixed queue isolation. | Offline orchestration evidence, not Phase 4 LIVE_PROXY completion. |
| Real fixture preparation | PASS: identity-bound launcher, health through Burp Proxy without interception, direct A/B form fixtures with exact case IDs and correct framing/field preservation. Fixture stopped afterward. | Preparation only; continuous interception was off. |

Evidence: [bounded stability](../build/reports/reliability/bounded-stability.json), [tool audit](../build/reports/reliability/local-tool-audit.json), [all 86 tool coverage entries](../build/reports/reliability/tool-coverage.json), [fixture preparation](../build/reports/reliability/phase-preparation.json).

The coverage inventory distinguishes prior live verification, current safe checks, expected unsupported/rejection outcomes, pending held-message tests, and unverified tools. Network send/Repeater/scan actions, configuration/editor/task changes, emergency/manual-only actions, and external Collaborator behavior are not blanket-approved by the unattended localhost policy. Unrestricted scanner issue listing was not invoked against unrelated project findings.

## Prepared approval-dependent phases

`scripts/live_reliability_coordinator.py` uses the already loaded .13 build and the existing 60-second message timeout. It preserves evidence after each passing phase and never retries an HTTP request. No rule is configured or rewritten by this coordinator.

Execution order is 4A, 4D, 4B, 4C so all checks fit inside one fresh 300-second local activation:

1. **4A:** hold one synthetic `/test-cancel` request, drop it through the existing policy, require matching drop and automatic-approval diagnostics, zero origin delivery, a terminal client outcome, empty queues and stale-ID rejection.
2. **4D:** hold exactly two distinct form requests, edit and release B while A stays at revision zero, observe A-request/B-response coexistence, require exact-revision automatic approval before each forward, complete B then A, verify separate origin/client identities and framing, and reject stale IDs. The existing two-message unattended limit is retained; eight-slot live queue saturation is not attempted.
3. **4B:** hold `/test-timeout` without forwarding until its 60-second message deadline expires. Require an expiration event, zero origin delivery, terminal client outcome, stale-ID rejection and a still-healthy longer session.
4. **4C:** stop the empty longer session and start a fresh 60-second session. Send a held `/test-session-expiry` request five seconds later so session expiry precedes the message deadline. Require `SESSION_EXPIRED`, heartbeat expiry, callback cancellation, zero origin delivery, terminal client outcome and empty queues.

The coordinator requires a matching fresh run identity, all nine existing scope/allowlist targets, authenticated write mode, enabled live edits, no rules, empty queues, inactive interception before setup, at least 240 seconds of authorization for the full plan, and deadlines that fit the active authorization. A failed or ambiguous response approval stops the sequence without forwarding it. Held traffic is left to its existing human approval/deadline path; cleanup never silently approves it.

**Current Phase 4 status: PREPARED, awaiting fresh local activation.** Prior live session-expiry-after-empty-cleanup evidence remains valid, but is distinct from the newly prepared held-request expiry case. The full suite has not been rerun.
