# Complete Burp MCP Validation

Final sign-off: [v1.4.0 .13 release readiness](FINAL_RELEASE_READINESS_v1.4.0.md): final one-shot Phase 4A PASS; complete final regression PASS (217 JVM and 91 Python tests plus PowerShell/local checks). The existing .13 JAR remains unchanged. Release is ready for the verified HTTP feature scope with documented limitations.

Latest Phase 4 results: [4A INCONCLUSIVE; 4B, 4C and 4D LIVE_PROXY PASS](PHASE_4_LIVE_RESULTS_2026_11_02.md), with actual client/origin evidence and 13 targeted coordinator regressions. The nine-exchange continuous rule-engine milestone remains preserved.

Reliability follow-up: [preserved milestone, bounded MCP stability, safe tool audit and prepared Phases 4A–4D](RELIABILITY_FOLLOWUP_2026_11_02.md).

Latest live verification: [2026-11-02 continuous rule engine LIVE_PROXY results](LIVE_RULE_ENGINE_2026_11_02.md): nine complete exchanges passed, including sequential modifications, compatible rules, pause/resume, counters and session expiry. The earlier [connection and stateless transport check](CONNECTION_CHECK_2026_11_02.md) verified build .13, 86 tools and enforced authentication, with 217 JVM and 56 Python tests passing. The live run required only 14 targeted coordinator regressions; the full suite was not repeated.

**Date:** 2026-11-01
**Repository:** D:\Projects\MCP
**Branch/base:** main / 57cf38165bb2e3e1f26f3867b2d4a9c2f21beeb8 before this validation cycle
**Running build:** unconfirmed; last reported `20261101.5-burp2024.1.1.1` (candidate .12 is not loaded)
**Burp:** Professional 2024.1.1.1-26891
**Loaded extension version:** unconfirmed; last reported `1.3.2` (candidate version is `1.4.0`)
**Current candidate:** `20261101.12-burp2024.1.1.1`
**Montoya compile baseline:** 2023.12.1
**Primary artifact:** build/libs/burp-mcp-all.jar

## Executive summary

The runtime paragraphs and matrix below preserve the earlier .5 verification snapshot; they are not current verification of candidate .12. During the .12 work, read-only MCP connection/status probes did not return within the bounded 52-second observation window and were not retried. The current loaded build, authentication responsiveness, and live tool catalog are therefore **unconfirmed**.

Candidate .12 compiled and packaged for Burp 2024.1.1.1 / Montoya 2023.12.1. The complete JUnit suite passed **214/214**, and the OFFLINE coordinator reported **18 PASS, 0 FAIL, 3 BLOCKED, 2 UNVERIFIED**. These tests include rule-engine state and transformation checks, MCP schema/control integration, and mocked request/response callback behavior; they do not establish real Proxy delivery. No live rule was enabled and no live traffic was sent by this work.

The Burp `.5` artifact remains preserved as the rollback. Candidate .12 has not been loaded. **Phase 4A remains INCONCLUSIVE** until a real request crosses Burp Proxy and drop, origin non-delivery, client outcome, stale-ID, approval-source, and queue-cleanup evidence is recorded.

Candidate .12 SHA-256 is `97cce49be2b52263006090f95b418bf0eb4c727e45d772dd796bfe99cc876e66`; full artifact and rollback details appear in the .12 addendum. The full-validation coordinator excludes `shadowJar` by default; candidate packaging requires explicit opt-in.

Machine-readable results:
- [Latest LOCAL coordinator report](../build/reports/full-validation/validation-f3caf344080f419789e343edcb8d8bb6.json)
- [Latest OFFLINE coordinator report](../build/reports/full-validation/validation-29830fabd6a748e490fc9d2aa79f29c1.json)
- [Latest SUPERVISED preflight report](../build/reports/supervised-reliability-20261101T072516Z-8740b7cd.json)
- [OFFLINE coordinator report](../build/reports/full-validation/validation-6abf0e7fb826423ea699ea968b6f6aa1.json)
- [71-tool catalog and input signatures](../build/reports/tool-catalog-audit.json)
- [Mission summary JSON](../build/reports/burp-mcp-validation-summary.json)

## Prior runtime evidence for build .5 (not re-confirmed for .12)

The following table is retained as a dated prior snapshot. Its PASS entries do not establish current runtime state or candidate .12 behavior.

| Check | Result | Evidence |
|---|---|---|
| MCP connection | PASS, live | burp_check_connection returned connected/running at the expected loopback endpoint and Burp version. |
| MCP authentication | PASS, live | The endpoint reports bearer authentication required; authenticated read-only MCP calls succeeded. No token was displayed or written. |
| Runtime build | PASS, live | burp_get_status and burp_get_capabilities both report 20261101.5-burp2024.1.1.1. |
| Tool catalog | PASS, registration/schema | Connector metadata has 71 entries, matching expectation. Seven read-only calls were executed; 64 were not executed individually. |
| Burp version | PASS, live | Burp Suite Professional 2024.1.1.1-26891. |
| Scope and allowlist | PASS, live | All nine exact localhost URLs returned eligible. This is a URL eligibility check; Montoya does not expose a full enumerable scope ruleset here. |
| Live interception | OFF | enabled=false; sessionEndReason=SESSION_EXPIRED; heartbeat is EXPIRED because there is no active session. |
| Unattended Local Test Mode | OFF | active=false, no current identities, remaining time zero. It was not activated by this validation. |
| Pending request queue | PASS, live | Empty. |
| Pending response queue | PASS, live | Empty. |
| Run ID/server identity copy controls | PASS, component tests; GUI UNVERIFIED | JUnit covers presence, read-only Run ID, masked server identity, current-state recheck, secure copy commands, and conditional clipboard cleanup. `cua.getState()` and `cua.listWindows()` failed with the native-pipe-unavailable error after a clean reconnect; the helper process and a matching pipe are visible locally, but the supported API cannot connect. No control was clicked or clipboard changed. |
| Local fixture | PASS, local | The bounded fixture and identity-enforcement regressions passed; port 8000 was released after testing. |
| MCP responsiveness | PASS now; freeze unresolved | Live read-only calls returned successfully. Local integration tests passed eight cases, including eight concurrent status calls while a mock approval was pending. The historical service-wide freeze was not reproduced and its root cause is still unknown. |

The seven live-verification tool calls were burp_check_connection, burp_get_status, burp_get_capabilities, burp_get_intercept_status, burp_list_pending_requests, burp_list_pending_responses, and burp_get_scope.

## Earlier validation results before candidate .12

### Full LOCAL validation

Coordinator run ID: f3caf344080f419789e343edcb8d8bb6.

- 21 coordinator checks passed; no coordinator failures or blocked items. The wrapper aggregate is INCONCLUSIVE because two checks remain unverified.
- Two items remain UNVERIFIED by design: approval-gated live Burp behavior and creation of a new candidate JAR.
- This LOCAL coordinator run completed in 52.81 seconds with 21 PASS, 0 FAIL, 0 BLOCKED, 0 INCONCLUSIVE, and 2 UNVERIFIED. A forced Gradle execution in the same validation cycle passed 182 JUnit tests, with no failures, errors, or skipped tests. The direct command excluded shadowJar and did not rebuild the JAR.
- The JUnit set includes eight local MCP integration tests: bearer rejection, tool listing, input validation, safe disclosure behavior, pending approval serialization, graceful shutdown, and concurrent status responsiveness.
- The server fixture reported 23 local cases passed; the separate identity-enforcement script exited successfully.
- JAR packaging was excluded. Existing manifest identity and SHA-256 were checked read-only.

### Offline cancellation and authentication regressions

- Cancellation preflight policy/coordinator API: **31 Python tests passed**, including the 150-second cancellation budget, independently expiring session and authorization deadlines, active identity retrieval, nine-target scope, one-shot drop evidence, and stale-ID operations.
- Setup authorization budget: setup requires **180 seconds** remaining: the 150-second request budget plus 30 seconds for the required Burp-local session activation. Values at 300, 240, and 180 pass; 150 and 120 fail before session activation.
- Authentication transport: **14 Python tests passed**.
- PowerShell auth/process handling: **38 assertions passed**, including secure prompt fallback after HTTP 401, missing/rejected tokens, stderr/nonzero child exit, zero/one/multiple Python arguments, and captured identity handoff without console output.
- Copied workflow simulation: **26 assertions passed**. A controlled child process exercised fixture readiness, setup preflight before pause, pause/resume, final preflight, setup/final failures, and the no-request gate. It contacted no Burp or origin server.
- Supervised coordinator simulation: **22 assertions passed** in actual PowerShell child processes. It exercised identity capture, fixture lifecycle, setup-before-session ordering, a single runner and drop, cleanup, setup-failure gating, inactive-authorization blocking, and aggregate status propagation; no Burp or HTTP request was sent.
- Identity-bound fixture handoff: **10 local assertions passed** using the real prepare script and server. It verified process-environment identities, a matching direct health response, no identity/token values in process arguments or result output, and cleanup of only the fixture's listener.
- Cancellation response validator: **19 framing/outcome cases passed**; NetworkRequestsSent=0.
- Concurrent runner validator: positive edited framing, malformed framing rejection, and cross-association rejection passed; NetworkRequestsSent=0.
- PowerShell syntax checks and git diff --check passed.
- Full OFFLINE coordinator: **18 PASS, 0 FAIL, 3 BLOCKED, 2 UNVERIFIED**; the aggregate is BLOCKED. The three blocked items are the local-only suites deliberately excluded by OFFLINE mode.

## Reliability fixes verified offline

1. A structurally valid but rejected environment token now triggers a secure prompt fallback under -PromptForMcpToken. The token remains in process memory, is not printed, and is not placed on a command line or persisted. A bad prompted token produces a clear, non-secret failure.
2. PreflightArguments @() is accepted with AllowEmptyCollection; Python receives no additional arguments for the final preflight.
3. The final request budget is derived from the 125-second client observation deadline plus 25 seconds of safety margin, yielding 150 seconds. Both interception-session and unattended-authorization remaining time are checked independently.
4. The copied workflow now runs authenticated setup, identity, scope, queue, and fixture checks before the user activates interception. After that single human action, it pauses once, performs one fast final preflight, and sends at most one request. Any preflight failure prevents test traffic.
5. run-full-validation.ps1 no longer overwrites the packaged JAR by default. The Gradle test task depends on shadowJar, so normal validation adds -x shadowJar. A candidate build requires explicit -BuildCandidate; backup, packaging, and candidate copy are then intentional.
6. Deadline tests and runner tests keep both session and unattended authorization expiry distinct. The runner never retries an ambiguous request.
7. The new `run-supervised-reliability-suite.ps1` keeps OFFLINE, LOCAL, and SUPERVISED modes distinct. In SUPERVISED mode it reads identities through authenticated MCP into process memory, verifies all nine targets, starts the fixture, passes setup preflight, asks the existing unattended policy for one 180-second session, then runs one request/drop and verifies cleanup. It never activates unattended mode or retries traffic.
8. Direct runtime testing found that `initialize()` required a client argument even though production preflight entry points called it without one. It now creates the default MCP client when omitted; direct construction and injection both have regressions. Unexpected errors are returned as bounded, non-secret preflight failures rather than tracebacks.

Detailed root causes and fixes are in [BURP_MCP_BUG_FIX_LOG.md](BURP_MCP_BUG_FIX_LOG.md).

## Prior phase status and coverage matrix

This matrix describes the earlier .5 baseline and must not be read as candidate .12 live evidence. Historical live results were not rerun for this candidate.

| Area | Level | Status | Evidence / limitation |
|---|---|---|---|
| MCP connectivity | Live | PASS | Current connection and status tools succeeded. |
| Authentication | Live + offline | PASS | Bearer required; authenticated MCP preflight succeeded; 14 transport tests and 38 PowerShell assertions passed. |
| Tool registration | Live catalog | PASS | 71 connector entries. |
| Tool schemas | Catalog metadata | PASS | All 71 entries include a callable signature and required/optional argument extraction. |
| All 71 tool behaviors | Per-tool | PARTIAL | Seven read-only calls live-verified; 64 are registration/schema verified only. See catalog JSON; no blanket functionality claim. |
| Burp scope | Live | PASS | All nine fixed localhost URLs eligible. |
| Target allowlist | Live | PASS | Same nine exact URLs all allowlisted. |
| Local scope helper | Live state change | UNVERIFIED | Not invoked because the existing targets already qualify and its local approval is required. |
| Unattended policy | Unit/local identity | PASS offline/local | Exact paths, host/port, identities, limits, expiry, and manual activation are covered by tests. Live mode remains off. |
| Automatic approvals | Live | UNVERIFIED | No live automatic decision was made; authorization is currently inactive. |
| Manual approval serialization | Local mock | PASS | Pending mock approval did not block eight status calls. No live human prompt was triggered. |
| Phase 4A request cancellation | Live | INCONCLUSIVE | No /test-cancel request was sent. Actual capture, approval source, drop, origin zero-delivery, client result, stale ID, and cleanup still require supervised evidence. |
| Phase 4A preflight and client classifier | Offline | PASS | Deadline, authentication, byte framing, terminal outcome, wrong ID, duplicate delivery, and no-traffic tests passed. |
| Supervised coordinator | Offline simulation + live read-only preflight | PARTIAL | 22 actual PowerShell child-process assertions passed. Live preflight confirmed the mode is inactive and stopped before fixture/session; no request was sent. |
| Phase 4B message timeout | Offline state machine | PASS | Expiry, fail-closed callback behavior, stale decision rejection, and queue cleanup covered. Live timeout remains UNVERIFIED. |
| Phase 4C session expiry/disable/emergency stop | Offline state machine | PASS | Expiry, disable, emergency cancellation, heartbeat cleanup, and callback release covered. Live variants remain UNVERIFIED. |
| Phase 4D queue capacity and concurrency | Offline state machine | PASS | Deterministic 1/2/4/8 message isolation and capacity tests passed. Live unattended mode remains limited to two in-flight messages; larger live tests are not authorized. |
| Approval serialization/BUSY | Offline + historical live | PARTIAL | Serialization and responsiveness pass locally; prior BUSY behavior was consistent with one-at-a-time prompts. No live repeat. |
| Stale IDs and revisions | Offline | PASS | Stale revisions, invalidated approvals, and terminal IDs are rejected by tests. Live stale-ID test pending. |
| Duplicate forwarding | Offline | PASS | Competing terminal decisions complete once; live repeat not run. |
| GET / POST / PUT / PATCH / DELETE request handling | Local fixture + historical live | PARTIAL | Local fixture validates methods; prior supervised GET/POST interception passed historically. Current Burp interception was not enabled. |
| Query/path/header editing | Historical live + offline | PARTIAL | Earlier live header/path/body workflows are documented; not rerun here. |
| JSON and nested JSON | Historical live + unit/local | PARTIAL | JSON request modifications passed historically; this mission did not send through Burp. |
| URL-encoded forms | Local fixture + historical live | PARTIAL | Fixture and historical form edit evidence exists; no live repeat. |
| Multipart and file uploads | Local fixture + historical live | PARTIAL | Bounded local multipart/file integrity passed; previous 41-byte live upload and SHA-256 result is historical only. |
| Request cookies | Historical live | PARTIAL | Earlier synthetic cookie editing passed; not rerun. Current auth/cookie analysis is redacting. |
| Response headers and Set-Cookie | Historical live + local tests | PARTIAL | Prior live header/cookie edits passed; not rerun. |
| HTML response editing/browser rendering | Historical live | PARTIAL | Prior modified HTML rendered in Burp browser; not rerun. |
| Response-body modification | Offline/mock + historical live | PARTIAL | Callback patch/drop unit tests pass; historical HTML/JSON edits are not rerun. |
| Content-Length | Local + offline + historical live | PARTIAL | Local fixture, parser, and historical modified-body checks pass; no live current-run framing test. |
| Chunked transfer | Fixture limitation | UNSUPPORTED by fixture | The local fixture explicitly rejects chunked request framing; extension-through-Burp behavior remains UNVERIFIED. |
| Binary integrity | Local fixture | PASS | Synthetic binary byte integrity was verified locally. |
| Unicode | Local fixture | PASS | UTF-8 body byte count/identity validated locally. |
| Duplicate delivery / request-response association | Offline + historical live | PARTIAL | Queue isolation tests pass; previous two-request live association result is historical. |
| HTTPS/TLS | None | UNVERIFIED | No localhost certificate fixture or trust changes were used. |
| HTTP/2 | Capability/tool surface | PARTIAL | Burp reports HTTP/2 request capabilities and tools; interception/editing over HTTP/2 was not tested. |
| gzip/deflate/Brotli | Source + no live fixture | PARTIAL | Body replacement on non-identity Content-Encoding is explicitly rejected; pass-through integrity and decompression were not tested. |
| Streaming/SSE through proxy | Source/capability | UNVERIFIED | No streaming interception test; MCP streamable HTTP transport support is separate from proxied streaming. |
| WebSockets | Source inspection | PARTIAL | A ProxyWebSocketMessage serializer exists, but WebSocket history is deliberately not exposed because connection metadata is insufficient for scope enforcement; frame interception was not tested. |
| HTTP/3 | Source/capability | UNSUPPORTED | No HTTP/3 capability or tool is exposed by this Burp/Montoya integration. |
| Extension shutdown/recovery | Local mock | PASS partial | MCP integration shutdown test passed; Burp extension unload/reload was not performed. |
| MCP responsiveness/freeze | Live + mock | INCONCLUSIVE | Current server responsive; local concurrency tests passed; historical service-wide freeze has no confirmed root cause or fix. |
| Repeated-session/soak testing | None | UNVERIFIED | No soak test was run in this turn. |

## Prior protocol and compatibility notes

The capability endpoint reports Montoya baseline 2023.12.1, HTTP/1 and HTTP/2 request operations, Professional scanner findings, passive audit, Repeater send, and Collaborator support. It reports no Repeater tab enumeration and disables active audit because legacy checks can be intrusive.

Build metadata says 1.3.2 / 20261101.5-burp2024.1.1.1; the JAR was built with JDK 18 and the project targets Java 17 bytecode. The exact loaded Burp version is confirmed. The packaged artifact was not modified during validation. HTTPS/TLS, HTTP/2 interception, compression, streaming, and long-lived protocols remain unverified or unsupported as marked above.

## Artifact, backup, and repository state at the earlier .5 snapshot

- Existing JAR SHA-256: 75186ec81d6f9d16c19802368677d4b33d1294d62e020cf338ccc3da5103b1d4.
- Existing preserved artifacts include the versioned .1 through .4 JARs and hash-named backups. The current .5 JAR remains in place.
- No JAR rebuild occurred in this validation. No Burp reload is needed because no packaged artifact was changed.
- This report records the pre-commit validation state. The reviewed source, test, and documentation changes are committed locally at handoff. No secrets or private identities were included, and no push has occurred.
- Candidate is suitable to keep for supervised testing, but **not ready to push or claim release-ready** until Phase 4A has live evidence and the remaining supervised protocol/reliability limitations are recorded.

## Minimum remaining actions

1. The supported desktop-control API currently cannot connect to its native pipe, so GUI automation is blocked. A human must enable Unattended Local Test Mode in Burp; no attempt was made to bypass that UI requirement.
2. After the mode is active, run or authorize the coordinator command `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-supervised-reliability-suite.ps1 -Mode SUPERVISED`. It handles identity, fixture, session, one-shot traffic, policy drop, and verification. If Burp presents a confirmation that requires a physically present human, that confirmation must be handled locally.
3. The latest SUPERVISED attempt authenticated and stopped before fixture/session startup because unattended mode was inactive. It sent no request. Phase 4A stays INCONCLUSIVE until every live evidence item passes.
4. Continue live 4B/4C/4D only while the current explicit authorization remains valid and their individual preconditions pass; otherwise retain their offline results and mark live behavior UNVERIFIED.

## 2026-11-01 addendum: interception rule engine candidate .9

This addendum supersedes the earlier artifact statement for this feature work only. The prior .5 runner-validation cycle did not rebuild a JAR; the rule-engine implementation changes Kotlin extension source and therefore required a new candidate.

| Item | Result | Evidence |
|---|---|---|
| Source candidate | `1.4.0`, build `20261101.9-burp2024.1.1.1` | `gradle.properties` and `BuildInfo.kt` compile as the same identity. |
| Candidate JAR | `build/libs/burp-mcp-20261101.9-burp2024.1.1.1.jar` and `build/libs/burp-mcp-all.jar` | Manifest reports version 1.4.0 and build .9. SHA-256: `c752771a373933f864ab0c8587ac864d753b27f374a8d678ebf5413052a59695`. |
| Superseded candidate .8 | `build/libs/burp-mcp-20261101.8-burp2024.1.1.1.jar` | Preserved before fail-closed matching and JSON-literal validation fixes; SHA-256: `e29c6b8a4b773afa6b95ddbd33be602660651b7e2f8a18f02934ded83d2a94b3`. |
| Superseded candidate .7 | `build/libs/burp-mcp-20261101.7-burp2024.1.1.1.jar` | Preserved after reservation and JSON depth hardening; SHA-256: `30956e9d8b4eb4d452e268ed548fa9db34bf304590117a99e127586fd5f92e83`. |
| Superseded candidate .6 | `build/libs/burp-mcp-20261101.6-burp2024.1.1.1.jar` | Preserved after the post-package Content-Length fix; SHA-256: `9e54c5e4f52dd4d402f07b934d9aa2e1829794f7b4b22d9117b93862e7f6d2d5`. |
| Known-good .5 | `build/backups/burp-mcp-20261101.5-known-good.jar` | SHA-256 remains `75186ec81d6f9d16c19802368677d4b33d1294d62e020cf338ccc3da5103b1d4`, identical to the original .5 artifact. |
| Burp/Montoya compatibility | Compile PASS | Compiled against Montoya API 2023.12.1; no Burp upgrade. |
| Java compatibility | PASS | Candidate class-file major version is 61 (Java 17); Gradle source/target and Kotlin JVM target are 17. |
| MCP catalog | PASS in embedded integration server | 86 Professional tools: existing 71 plus 15 rule-engine controls. The test checks the expected set and nested schemas. This is not a live loaded-Burp catalog check. |
| Full JUnit suite | PASS | 210 tests, 0 failures, 0 errors, 0 skipped after packaging .9. |
| Offline validation coordinator | PASS with explicit non-live outcomes | 18 PASS, 0 FAIL, 3 BLOCKED (local network tests are intentionally omitted in OFFLINE mode), 2 UNVERIFIED (approval-gated Burp work and coordinator candidate-copy step). See `../build/reports/full-validation/validation-961e2c979d934534998c3b15f7e14777.json`. The `.9` JAR was separately packaged and hash-verified. |
| Rule evaluator | UNIT PASS | Typed/nested JSON, query/form, headers, literal text, matching, priority/conflicts, TTL/match caps, counters, malformed/duplicate/deep JSON, framing, limits, safe path matching, one-shot reservations, fail-closed co-matches, and 1/2/4/8 concurrent evaluations. |
| Request/response callbacks | MOCK PASS | Mocked Montoya callbacks exercised request modification, associated response modification, authorization gates, manual fallback, and queue release. They did not pass through the running Burp Proxy. |
| MCP control workflow | Embedded MCP integration PASS | Authenticated create/list/enable/stats/disable/delete calls ran in the test server with mocked Burp API/scope. No live authorization was activated. |
| Live Proxy | UNVERIFIED | No traffic crossed the running Burp Proxy and no live approval was made. The available connected MCP tool registry still exposes 71 existing names and no rule-engine tools. Read-only connection/status probes did not return during a 52-second observation window; the currently loaded runtime build could not be re-confirmed. Candidate .9 has not been loaded. |

The engine runs in the existing `LiveInterception` request/response pipeline and reuses its message IDs, revisions, approval queue, scope checks, allowlist, rate limiter, session, and unattended authorization. Rules are memory-only, disabled on creation, and bounded by active authorization/session expiry, a 300-second maximum TTL, 32 matches, 64 KiB messages, 64 configured rules, eight outstanding evaluator reservations, and the existing two-message auto-approval limit. A rule-condition parse failure blocks co-matched automatic changes for that message; ambiguous content types and JSON deeper than 64 levels stay manual. Automatic `DROP` is limited to request-direction rules because the current policy does not authorize automatic response drops. Only the fixed nine localhost paths are eligible.

New MCP controls: `burp_create_interception_rule`, `burp_list_interception_rules`, `burp_get_interception_rule`, `burp_update_interception_rule`, `burp_enable_interception_rule`, `burp_disable_interception_rule`, `burp_delete_interception_rule`, `burp_clear_interception_rules`, `burp_preview_interception_rule`, `burp_get_interception_rule_stats`, `burp_get_interception_rule_events`, `burp_get_rule_engine_status`, `burp_clear_interception_rule_stats`, `burp_pause_all_interception_rules`, and `burp_emergency_stop_rules`.

The historical MCP freeze remains undiagnosed. This feature's callback tests passed, but did not reproduce that freeze. The stalled read-only status probes are a current responsiveness symptom, but do not identify whether the cause is the extension, client transport, or another runtime layer. Candidate .9 is ready for supervised live validation after installation; it is not live-verified or release-proven. No GitHub push was performed.

Guides: [Interception rule engine](INTERCEPTION_RULE_ENGINE.md) and [AI agent examples](AI_AGENT_INTERCEPTION_EXAMPLES.md). Machine-readable results: `../build/reports/interception-rule-engine-validation.json` and `.md`.

## 2026-11-01 addendum: interception rule engine candidate .11

This addendum supersedes the .9 artifact and test summary above. Candidate .10 is retained as a superseded intermediate; .5 remains the known-good rollback artifact.

| Item | Result | Evidence |
|---|---|---|
| Source candidate | `1.4.0`, build `20261101.11-burp2024.1.1.1` | `gradle.properties` and `BuildInfo.kt` match. |
| Candidate JAR | `build/libs/burp-mcp-20261101.11-burp2024.1.1.1.jar` and `build/libs/burp-mcp-all.jar` | Manifest reports version 1.4.0 and build .11. SHA-256: `572d3a3005b459a24ecf249eef5647982061f3861a18f4b117689ebd5fa7fe49`. Versioned copy and primary artifact hashes match. |
| Java/Burp compatibility | PASS at compile/bytecode level | Montoya API 2023.12.1 compile; Java 17 bytecode major 61; 11,354 class files. No Burp upgrade. |
| Full JUnit suite | PASS | 213 tests, 0 failures, 0 errors, 0 skipped, `validation.mode=all`. This includes rule engine, MCP integration schema/status, and mocked request/response callback tests. |
| Modification cap | UNIT/MOCK PASS | Independent per-rule match and actual-modification limits; no-op forwards do not consume modification capacity; in-flight changes reserve budget atomically; engine status and stats expose the limits. |
| MCP catalog | Embedded integration PASS / live UNVERIFIED | Embedded server schema and control tests expect 86 tools (existing 71 plus 15). The connected agent registry has not shown these new tools; the candidate is not loaded in Burp. |
| Offline runner regressions | PASS | The bounded coordinator report `../build/reports/full-validation/validation-5ea15fb490be468e94e12a4e85ba0d00.json` recorded 18 PASS, 0 FAIL, 3 BLOCKED and 2 UNVERIFIED against .11 source. The three OFFLINE blocks are network-only cases; the two unverified entries remain approval-gated/live or candidate-copy checks. |
| LIVE_PROXY | UNVERIFIED | No real Burp Proxy request/response, live rule execution, approval or origin/client effect was observed. Phase 4A remains INCONCLUSIVE. |
| Runtime / MCP responsiveness | UNVERIFIED; freeze not diagnosed | A prior read-only MCP status probe stalled during a 52-second observation; it was stopped without retry. Candidate .11 has not been loaded. |

Rule specs now expose `maximumModifications`; stats expose `remainingModifications`; rule-engine status exposes `maximumModificationsPerRule`. Concurrent modified messages reserve these slots before a release, and a no-op forward consumes only a match. The fixed localhost authorization boundary, human-visible activation, request-only automatic DROP, and existing two-message auto-approval limit are unchanged.

Candidate .11 is a built, locally tested candidate, not a live-verified release. The connected Burp runtime still needs a human-controlled reload, followed by a supervised localhost test that records actual client, origin, drop, approval and queue evidence. No GitHub push was performed.

## 2026-11-01 addendum: interception rule engine candidate .12

Candidate .12 adds a security-boundary correction after reviewing clear-audit behavior. Rule consumption limits now use enforcement counters separate from clearable statistics, so `burp_clear_interception_rule_stats` cannot restore match or modification capacity. An in-flight modification reservation remains counted while audit fields are cleared.

| Item | Result | Evidence |
|---|---|---|
| Candidate | `1.4.0`, build `20261101.12-burp2024.1.1.1` | `gradle.properties` and `BuildInfo.kt` match. |
| Versioned and primary JARs | PASS | `build/libs/burp-mcp-20261101.12-burp2024.1.1.1.jar` and `build/libs/burp-mcp-all.jar`; SHA-256 `97cce49be2b52263006090f95b418bf0eb4c727e45d772dd796bfe99cc876e66`. Manifest verified. |
| Full JUnit suite | PASS | 214 passed, 0 failed, 0 errors, 0 skipped. |
| Focused engine suite | PASS | 27 passed, 0 failed, 0 errors, 0 skipped, including match/modification cap, concurrency reservations, no-op accounting, and counter clearing. |
| OFFLINE coordinator | PASS with explicit non-live outcomes | 18 PASS, 0 FAIL, 3 BLOCKED, 2 UNVERIFIED. The blocked entries are local network tests excluded by OFFLINE mode. Report: `../build/reports/full-validation/validation-f4aeaf3e15a04dcdbdbaf81226e0bfd9.json`. |
| Runtime and live Proxy | UNVERIFIED | Candidate .12 is not loaded in Burp. No live rule or proxy request was executed. The last read-only MCP probe stalled and the historical freeze remains undiagnosed. |

Candidate .11 is preserved and `.5` remains the known-good rollback. Candidate .12 has not been loaded into Burp or exercised through `LIVE_PROXY`.
