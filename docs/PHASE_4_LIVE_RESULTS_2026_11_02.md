# Phase 4 reliability: supervised LIVE_PROXY results

**Final Phase 4A follow-up: PASS** in one fresh, authorized request with complete durable client evidence. See [final release readiness](FINAL_RELEASE_READINESS_v1.4.0.md). The earlier INCONCLUSIVE result below remains preserved as historical evidence; 4B/4C/4D were not repeated.

Verified with the already loaded `.13` build under one human-activated 300-second localhost authorization. No activation renewal, rule-engine rewrite, JAR rebuild/reload, full-suite rerun, or GitHub push occurred. The earlier nine-exchange rule-engine milestone and its preserved JAR/source/evidence archive remain intact.

## Per-phase results

| Phase | Status | Actual evidence |
|---|---|---|
| **4A: request drop/cancellation** | **INCONCLUSIVE** | One GET `/test-cancel` was captured and dropped with exact `DROP_REQUEST` automatic-approval and `intercept_drop` diagnostics. Zero origin deliveries, empty queues, and stale get/edit/forward rejection confirmed. The client completed with a 2xx response, but the original coordinator rejected that observation before saving the exact status/body metadata. The request was not repeated. |
| **4B: intercepted-message timeout** | **PASS** | GET `/test-timeout` expired at its 60-second message deadline; observation 60.02 s, client completion 60.042 s. Matching `intercept_expiration: expired`, zero origin delivery, stale-ID rejection and empty queues. The longer interception session remained healthy. |
| **4C: session expiration and stale IDs** | **PASS** | A fresh 60-second session held GET `/test-session-expiry`, sent five seconds after session start. The saved deadline snapshot shows 14,314 ms session time versus 19,353 ms message time. Session expiry cancelled the held callback before message expiry; matching cancellation event, zero origin delivery, stale get/edit/forward rejection, heartbeat `EXPIRED` and empty queues. Client completed after 55.754 s. |
| **4D: concurrency and queue isolation** | **PASS** | Two distinct requests held together. B was edited and completed before A; A remained unapproved at revision zero while B was edited. A-request/B-response coexistence verified. Both request revisions and both responses carried `UNATTENDED_LOCAL_TEST` approval diagnostics. Clients received HTTP 200 with their own verified case IDs and preserved fields; each origin received exactly one correctly framed modified form. Both directions reject stale IDs. |

Five total client attempts were made: the initial cancellation attempt, two isolated exchanges, one timeout and one session-expiry request. Only the two concurrency requests reached the origin. No ambiguous request was retried. No response required manual approval.

The unattended two-message limit was retained. Eight-slot queue saturation, extension unload, emergency cancellation requiring a human dialog, and individual rule TTL expiry were not exercised by this run.

## Client outcome classification

Burp returned HTTP 200 with a 1,368-byte non-JSON body for both the message-timeout and session-expiry terminations. Their identical body SHA-256 was `0dc4adcbf9fd2c5eadaa3327dbafdcd0de537b9fe7ad5fd7b377888013808ec5`. These were proxy-generated terminal responses: independent diagnostics and zero-origin evidence establish that neither request reached its fixture. A 2xx status alone cannot establish upstream delivery.

This observation explains the coordinator's overly strict 4A classifier. It does not recover the exact original 4A client response; that phase remains INCONCLUSIVE instead of being retroactively marked PASS.

## Reproducible coordinator fixes and offline regressions

1. **Premature 2xx rejection:** a complete HTTP response after a Burp terminal decision is now retained for correlation with its terminal diagnostic and zero-origin evidence. A successful fixture JSON response or incomplete client metadata still fails cancellation verification.
2. **Lost client evidence:** every terminal client observation is now saved before classification or assertions. This includes ambiguous outcomes; successful phase evidence remains saved before the next phase.
3. **Incorrect aggregate PASS:** a continuation initially printed PASS despite preserving Phase 4A as INCONCLUSIVE. Aggregate PASS now requires all four distinct phases to pass. The report retains the original printed aggregate in `coordinatorReportedState` and explicitly records its correction; no per-phase evidence was changed.

**OFFLINE:** 13 targeted coordinator tests passed, including terminal evidence preservation, 2xx classification constraints, and prevention of overall PASS with an inconclusive or missing phase. These tests are separate from the LIVE_PROXY results above. No extension source change was needed.

## Cleanup and evidence

Read-only cleanup verification confirmed interception disabled with `SESSION_EXPIRED`, heartbeat `EXPIRED`, zero pending requests/responses, zero configured/enabled rules, and the fixture listener stopped. No further traffic was sent after the phases completed. The authorization was left to its existing bounded natural expiry and was never renewed.

- [Phase 4A original outcome and post-failure corroboration](../build/reports/reliability/phases-4abcd-fba913f9071a4d4583e49e479909c7a2.json)
- [Phase 4B/4C/4D evidence and corrected aggregate](../build/reports/reliability/phases-4abcd-7fef424d6ec64aa1b3d509cb3e68ef14.json)
- [Held-request versus session deadline snapshot](../build/reports/reliability/phase4c-held-deadline-snapshot.json)
- [Origin log](../build/live-test-server-observations.jsonl)
- [Updated 86-tool coverage inventory](../build/reports/reliability/tool-coverage.json)

The `.13` JAR SHA-256 remains `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`. Earlier successful evidence has not been overwritten.
