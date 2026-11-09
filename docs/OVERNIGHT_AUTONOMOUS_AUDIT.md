# Burp MCP autonomous engineering audit

**Audit date:** 2026-11-01 (Asia/Calcutta)
**Repository:** `D:\Projects\MCP`
**Source base:** `63d7c89db7de4557d180d4d91ef9637b95d0e3ee`
**Candidate:** `1.3.2 / 20261101.2-burp2024.1.1.1`
**Overall result:** Candidate source and local regression suites are ready for review. The running MCP service became unresponsive, so the candidate was not deployed and no live Burp interception test was run. Phase 4A remains **INCONCLUSIVE**.

Machine-readable evidence is in `build/reports/overnight_autonomous_audit.json`. Final full validation records are `build/reports/full-validation/validation-31417335e46744fba9853eb79878fab9.{md,json}` (LOCAL), `build/reports/full-validation/validation-d266f7dd78dc4291a60ad3e075aaf56f.{md,json}` (OFFLINE), and `build/reports/full-validation/validation-ec34cb50e2754aa3ad820e303cef64ed.{md,json}` (SUPERVISED).

## Executive summary

- Added an explicit, disabled-by-default unattended local test policy. It only considers HTTP requests to the exact nine synthetic `127.0.0.1:8000` paths, requires Burp’s actual destination, exact `Host`, matching ephemeral run/server identities, active session and healthy heartbeat, scope and allowlist eligibility, an unexpired message and exact revision, safe content, and size/concurrency/request limits.
- Added visible Burp controls for activation, expiry, deactivation, and emergency stop. Activation is process-local, requires one explicit Burp UI action, lasts 60–300 seconds (120-second default), and is not restored on extension reload. The mode has not been deployed or enabled; no automatic approval happened.
- Hardened the Phase 4A runner, authenticated read-only preflight, bounded localhost fixture, cancellation outcome classifier, and delivery-evidence checks. The runner aborts before its request if any required check is absent, stale, or unhealthy.
- Final validation completed with **17 PASS, 0 FAIL, 0 BLOCKED, 1 UNVERIFIED** in LOCAL, **15 PASS, 0 FAIL, 2 BLOCKED, 1 UNVERIFIED** in OFFLINE, and **17 PASS, 0 FAIL, 1 BLOCKED, 0 UNVERIFIED** in SUPERVISED. The final all-tag Gradle run passed 173 tests with 0 failures, 0 errors, and 0 skipped; the preceding OFFLINE run passed 130 tests. SUPERVISED blocks only approval-gated live Burp actions.
- A service-wide MCP freeze was reproduced: MCP and Proxy ports were listening, but authenticated MCP calls timed out. A thread dump showed no JVM deadlock marker; available evidence does not establish the cause. No Burp restart was attempted.

## Current system health

| Component | Evidence | Result |
|---|---|---|
| Burp runtime build | Last successful status before the freeze reported `20261031.2-burp2024.1.1.1` | Last confirmed; later status is not queryable |
| Burp edition/version | Professional `2024.1.1.1-26891` | Last confirmed |
| MCP and Proxy listeners | `127.0.0.1:9876` and `127.0.0.1:8080` still appeared as listening sockets at final check | Listening, but this does not establish application health |
| MCP calls | Five read-only connector calls timed out; bounded local MCP status requests also timed out | **FAIL / unusable for reliable tool calls at audit end** |
| Interception | Last successful status: disabled; heartbeat expired; queues empty | Last confirmed before freeze; no action in this audit changed it |
| Local test server | Port 8000 listener count was zero at final check | Stopped |
| Candidate loaded/enabled | Not loaded; unattended mode not enabled | Disabled |

The service freeze was reproduced without sending HTTP to the cancellation endpoint. The captured JVM dump in `build/reports/burp-thread-dump-reproduced-20261101.txt` records 99 live threads at capture time, with no deadlock marker. It contains Netty event-loop threads and Kotlin dispatcher workers, but no MCP/Ktor request stack that identifies a blocked handler. This is evidence of a responsive TCP listener paired with an unresponsive MCP application, not proof of thread starvation, approval-dialog blockage, or a particular deadlock. The old engine/thread groups make lifecycle cleanup a hypothesis to investigate; they do not prove it caused the freeze.

No restart, reload, or repeated status hammering was done, so the dump and the original unresponsive state were preserved.

## Authentication and Phase 4A preflight

### Changes

- `scripts/cancel_test_preflight.py` reads `BURP_MCP_TOKEN` from the current process environment only. It requires the extension’s bare 43-character Base64URL token, sends `Authorization: Bearer …`, never prints or persists the value, and has bounded connection/read sizes and timeouts.
- The preflight uses supported MCP initialize/status and scope/interception tools. It checks the loaded build and Burp version, authenticated MCP health, `/test-cancel` eligibility in Burp scope and the MCP allowlist, active interception, `HEALTHY` heartbeat, empty pending lists and queue counts, a four-minute minimum remaining on the 300-second session, a live Proxy listener, and an identity-bound local-server health route when unattended-mode identities are supplied.
- HTTP 401 is reported as an authentication rejection; HTTP 403 is kept distinct. Error bodies are not copied to the report. JSON and Streamable HTTP SSE results are bounded and correlated by request ID.
- `scripts/run-cancel-test.ps1` performs the auth-only preflight before full readiness validation and before opening the test socket. `-PromptForMcpToken` uses secure PowerShell input only for missing, malformed, or HTTP 401 tokens. It does not ask for a token after timeouts, 403, or an unavailable service. The token remains in the parent process environment for the Python child and is restored on exit.
- Offline regressions cover missing/empty/malformed/prefixed/stale tokens, 401, 403, other HTTP errors, refusal, network and response timeouts, malformed MCP response/content type/ID, SSE, process inheritance, and identity mismatch.

### Result

The runner-side failure handling is repaired and its offline tests pass. The historical live HTTP 401 root cause is **not established**. The endpoint could not be authenticated while it was frozen, so token validity and whether the previous 401 came from a stale child environment or a changed Burp token remain **UNVERIFIED**. Authentication was not disabled or bypassed.

## MCP responsiveness, approval waits, and lifecycle

- A test now issues eight concurrent read-only `burp_get_status` calls against the mocked local MCP integration server; it passed in the LOCAL suite.
- Existing bounded approval timeout/cancellation tests and new queue tests cover approval timeout, cancellation of a held callback, late or stale revisions, mode expiry, concurrent queue decisions at 1/2/4/8 messages, capacity, single terminal action, and revocation of unattended approvals while retaining human approvals.
- The MCP integration tests verify authentication rejection before tool access and verify that tool listing/status remains responsive in the local mock server.
- A new local MCP integration regression holds one mocked Burp approval dialog open, confirms a second simultaneous approval fails closed, and issues eight status calls while the first approval is pending; all status calls complete, and the first approval remains tied to its exact queue revision. This checks that a suspended approval handler does not monopolize MCP health calls in the local server.
- The final SUPERVISED run executed all 173 JUnit tests, including the loopback-tagged integration tests, with 0 failures, errors, or skips; the orchestrator reported live Burp actions as BLOCKED because no human was present.
- These tests do not reproduce the service-wide freeze in the running Burp process. The runtime freeze remains **unexplained**; do not report it fixed. No confirmed deadlock or specific root cause was found.

## Unattended local test mode

### Policy and controls

- Mode starts **off** on every extension load. Only the Burp UI activation button can enable it. The UI displays the exact target, paths, methods, automatic operations, duration, limits, ephemeral identities, expiry, and warning before/while the operator activates it.
- Duration is 120 seconds by default, configurable from 60 to 300 seconds, with no automatic extension. An emergency control disables the mode and ends the interception session. Normal traffic keeps its local approval requirements when the mode is off.
- Allowed target is exactly `http://127.0.0.1:8000` and these paths: `/test-html`, `/test-post`, `/test-form`, `/test-upload`, `/test-cancel`, `/test-timeout`, `/test-session-expiry`, `/test-concurrent-a`, `/test-concurrent-b`.
- Requests must match the actual Burp HTTP service, canonical URL and exact path, exact `Host: 127.0.0.1:8000`, one active run ID, one ephemeral server identity, and a unique test-case ID. Both Burp scope and the MCP allowlist must admit the effective revision. Credentials, sensitive names/values, bearer/basic or JWT-shaped values in arbitrary headers/query/body, non-identity content encodings, redirects, unsupported direction/operation, mismatched destination, expired session/heartbeat/message, stale revision, replay, missing identity, or oversized/unmeasurable messages fail closed to manual review or denial.
- Automatic operations are centralized through `UnattendedLocalTestMode`: exact-revision proposal/approval, forwarding, eligible request drop, synthetic content disclosure, restricted local scope configuration, and start/stop of a restricted session. Session start requires all nine URLs eligible and the exact local-only allowlist; scope configuration never adds other URLs. State-changing operations outside this narrow policy retain local confirmation.
- Limits: two automatic in-flight messages, eight total queue slots (more than two requires manual review), 32 distinct requests per activation, 64 KiB per message, and the 60–300 second activation lifetime. Automatic approvals are tagged by source and revoked on expiry/deactivation; human approvals are preserved.
- Audit entries contain timestamp, operation, path, run/message/revision identifiers, decision, reason, and session state. No raw body or bearer token is written by the new policy.
- A final security review added detection for bearer-like values in arbitrary headers and decoded query values. The focused regression passes. It prevents a matching request from being auto-approved; it does not weaken existing credential checks.

### Tests and deployment status

The 14 `UnattendedLocalTestModeTest` cases and `LiveInterceptionTest` cases cover disabled/manual behavior, explicit activation, expiry/deactivation, emergency stop, exact paths/host/port/methods, run/server identity, destination consistency, scope/allowlist, heartbeat/session/message deadlines, revision/state, duplicate forwarding/replay, credentials, payload limits, response association, management actions, and harmless versus out-of-policy edits. Concurrency tests exercise simultaneous policy decisions. Local server identity tests rejected unauthenticated health, invalid path, absent/mismatched identity, and wrong run ID; the exact identity was accepted. The first draft of the new approval responsiveness test exposed that its mocked persisted object always returned `readOnly=true`; the fixture now overrides that one test setting, and the focused plus full regressions pass.

The candidate has not been loaded into Burp. Activation and live automatic approval remain unverified and require the operator after deployment. The current running `.2` build does not contain this feature.

## Tool coverage

Source and the mocked MCP integration test enumerate **71 unique tools**, including `burp_configure_local_test_scope`. The integration test checks every tool name, description, object input schema, field type declaration, required-field membership, and uniqueness. The live connector had exposed 71 definitions earlier in the session, but its calls later timed out, so current live registration cannot be re-queried.

The JSON evidence includes all 71 names with per-tool status. Twenty-three tools were invoked by tests against mocked Burp APIs and are marked `MOCK_TESTED`; all remaining tools are marked `REGISTERED`. All 71 have registration/schema checks. Tool behavior is **not** fully verified per tool: runtime authorization, output contracts, Burp scope side effects, per-tool error/timeout behavior, and live concurrency are not implied by registration. No unsafe state-changing live tools were run. No tool is marked `LIVE_VERIFIED`.

`burp_configure_local_test_scope` mock tests verify approval denial makes no changes, approved configuration adds only the predefined nine URLs and exact `127.0.0.1:8000` allowlist entry, preserves prior allowlist values, and reports partial results. No live Burp scope was changed during this audit.

## Request and response testing

### Loopback server

The bounded local server suite passed 23 checks: GET, JSON POST, URL-encoded form, multipart boundary/filename/content type/field/file integrity, cancellation identity path, timeout/session-expiry fixtures, Unicode UTF-8 byte counts, binary bytes, empty body, bounded oversized body, PUT/PATCH/DELETE fixture handling, custom headers, malformed/conflicting Content-Length, explicit chunked-request rejection, keep-alive closure, premature EOF, and exact synthetic identity/delivery records. It binds only to `127.0.0.1`, limits runtime/request count/body size/headers/time per request, excludes health and rejected requests from delivery evidence, and is stopped after each run.

These tests are direct to the loopback fixture and do not prove Burp proxy interception or browser rendering. They contain synthetic content only.

### Cancellation response classifier

Twenty offline categories passed, including complete HTTP errors, unexpected HTTP 200 rejection, EOF/reset/abort, empty timeout, one-byte partial timeout/EOF, partial or malformed headers, partial body, conflicting or incorrect Content-Length, extra bytes, close-delimited error responses, complete and partial chunked framing, malformed/non-HTTP data, socket error mapping, incorrect test IDs, duplicate server delivery, and server delivery evidence. The validator requires an observable, bounded terminal outcome plus exact zero-origin delivery evidence; an empty log without a running identified server cannot pass.

The HTTP 200 from the invalid historical retest is not classified as a Burp-generated synthetic error page. The originating component and any safe marker cannot be proved from existing evidence. The retest followed session and server expiry and therefore was not intercepted under a valid session. We did not accept arbitrary HTTP 200, change the validator to do so, or inspect/log raw response contents.

## Cancellation and session reliability

Phase 4A remains **INCONCLUSIVE**. Historical results remain separate:

1. First attempt: the request was dropped, origin delivery was reported zero, stale ID rejected, and queues cleaned, but the client was observed only as a partial socket read. Terminal client outcome was not established.
2. Second attempt: client observed HTTP 200 with zero reported origin requests, but both the 300-second session and local server had expired before the request. The request was not proved intercepted; zero origin count is not valid evidence when the origin was no longer running. The response provenance is unknown.
3. Third attempt: authenticated preflight returned HTTP 401 and correctly stopped before the cancellation request.

The corrected runner now rejects stale/missing sessions before sending, and uses the server identity plus run/test IDs to associate evidence. No new `/test-cancel` request, drop operation, or live cancellation was performed. No live message ID is available to prove a new DROPPED state. No retry occurred.

Session tests cover bounded creation, heartbeat, missed heartbeat, expiry, explicit stop/cancel, queue cleanup, pending callback release, late approvals, message deadlines, and mode expiry. A live Burp heartbeating session was not enabled.

## Concurrency and queues

Queue regressions passed for 1, 2, 4, and 8 independent entries, plus concurrent forward/drop races, simultaneous cancellation, unique IDs, revision isolation, one terminal action, capacity, and source-specific approval revocation. MCP mock integration passed eight simultaneous status calls. Automatic mode caps automatic work at two simultaneous messages; higher occupancy returns to manual review. Live Proxy concurrency and throughput remain **UNVERIFIED** because the service was frozen and no interception session was active.

## Security and privacy review

- MCP remains bearer-authenticated; the existing constant-time comparison and pre-route authentication check were not weakened. Python reads only the process environment. The PowerShell token prompt is secure and in-memory; test fixtures use synthetic fake tokens.
- No external site or unrelated target was contacted, authorized, or added to live Burp scope/allowlist. No real cookie, credential, private file, or production data was used.
- The unattended policy checks actual service identity plus effective URL and revision, exact host/path/port, scope, allowlist, run/server identity, deadlines, queue limits, and sensitive content. It does not auto-authorize arbitrary web traffic or configuration, scan, certificate, shell, or global security operations.
- Intercepted content remains untrusted. No prompt-injection text was used to alter policy or scope.
- Final source secret scan passed. One intermediate scan correctly flagged a synthetic bearer-shaped test literal; the fixture now assembles that synthetic value at runtime, preserving the regression without embedding a token-shaped string.

## Protocol status

| Protocol/feature | Status | Evidence / limit |
|---|---|---|
| HTTP/1.1 | PARTIALLY_VERIFIED | Local framing and fixture behavior verified; live Burp forwarding not verified |
| HTTP keep-alive | PARTIALLY_VERIFIED | Local server deliberately closes; no multi-request live proxy test |
| HTTP/2 | PARTIALLY_VERIFIED | Request construction/mock tests only; no live Burp protocol test |
| HTTPS/TLS | UNVERIFIED | No live TLS test or certificate trust changes |
| Chunked transfer | PARTIALLY_VERIFIED | Cancellation response classifier covers complete/partial chunks; test server explicitly rejects chunked requests |
| Close-delimited response | PARTIALLY_VERIFIED | Offline cancellation classifier exercises it; no live Burp response test |
| Compressed bodies | UNVERIFIED | Replacement behavior rejects unsupported compressed text editing; no end-to-end compression test |
| Binary and Unicode | PARTIALLY_VERIFIED | Exact loopback bytes and UTF-8 lengths verified; not a live Burp interception test |
| Streaming | UNKNOWN | No end-to-end streaming evidence |
| WebSockets | UNKNOWN | Not tested |
| HTTP/3 | UNKNOWN | Not tested |

## Automated regressions

- Final LOCAL orchestrator: 17 PASS, 0 FAIL, 0 BLOCKED, 1 UNVERIFIED. Includes the all-tag Gradle test run, PowerShell syntax checks for 14 scripts, secret scan, cancellation/auth/concurrency offline regressions, 23 server checks, and identity enforcement checks.
- Final OFFLINE orchestrator: 15 PASS, 0 FAIL, 2 BLOCKED, 1 UNVERIFIED. Loopback network suites are intentionally blocked in OFFLINE mode. At the end of that run, its JUnit XML recorded 130 tests, 0 failed, 0 errored, 0 skipped.
- Final SUPERVISED orchestrator: 17 PASS, 0 FAIL, 1 BLOCKED, 0 UNVERIFIED. Its all-tag Gradle run recorded 173 tests, 0 failed, 0 errored, 0 skipped; the single blocked group is live Burp approval-gated work.
- Additional focused Python runs: 14 authentication/transport tests and 8 preflight parsing/policy tests passed.
- Cancellation offline validator: 20 checks passed; network request count was 0.
- Final PowerShell parser check: all 14 project scripts parsed.
- `git diff --check` passed.

Suite figures overlap between modes and should not be summed as unique test cases.

## Source modifications

Changes are limited to the project source, tests, runner/server scripts, build identity, ignore rules, and this report. The principal additions are `UnattendedLocalTestMode.kt`, `LocalTestTargets.kt`, the authenticated preflight and local identity scripts, plus unit/integration regressions. The working extension remains preserved separately.

## Build results and backups

| Artifact | SHA-256 | Status |
|---|---|---|
| Candidate `build/candidates/burp-mcp-1.3.2-20261101.2-burp2024.1.1.1.jar` | `a5e5aa8f870b55f949e6d76b5ef14ae95e99e62882d36c85ec069322c2622648` | Built, manifest verified, not deployed |
| Current packaged `build/libs/burp-mcp-all.jar` | `a5e5aa8f870b55f949e6d76b5ef14ae95e99e62882d36c85ec069322c2622648` | Candidate build output, not the running runtime |
| Preserved build `.2` backup | `59089ff5248cab06fdf6918202165a2a4617c29a8e178f50c0eeab0243f84ce0` | Preserved |
| Known-good build `.1` | `1d4af1215ea184c549d20dd59d278023d0b3f102e5868e4d8223c09bdf659c8f` | Preserved at project parent path |

Candidate manifest reports version `1.3.2`, build `20261101.2-burp2024.1.1.1`, Montoya dependency `2023.12.1`, Java class-file major 61 (Java 17 bytecode), and a JDK 18 build. JDK 17 was not installed in this environment. Source/bytecode compatibility is checked, but loading this candidate in the exact Burp build is still required to verify runtime compatibility. The running extension was not rebuilt or replaced in Burp; no reload is needed until an operator chooses to deploy the candidate.

## Git status

The original base is `63d7c89db7de4557d180d4d91ef9637b95d0e3ee`. A local review commit is prepared after final diff and secret checks; its hash and tree status are recorded in `build/reports/overnight_autonomous_audit.json`. No remote was changed and nothing was pushed. Build artifacts/reports remain ignored under `build/`; Python `__pycache__` is ignored.

## Unsolved issues

1. MCP service-wide freeze is reproduced but root cause is unconfirmed. Listeners alone are not enough to use MCP safely. A Burp operator needs to inspect/recover the extension service before live verification.
2. Actual token freshness and the cause of the historical HTTP 401 remain unverified because the MCP service did not answer.
3. Candidate has not been loaded into Burp 2024.1.1.1; unattended UI behavior and Montoya callback behavior need a supervised runtime check.
4. Phase 4A has no valid new live capture, applied DROP record, origin-zero evidence from a running server, client terminal result, stale-ID rejection, and empty queues from the same run. It remains inconclusive.
5. Per-tool behavior is only partly mocked. Registration and input schemas are verified for all 71; many tool-specific authorization, output, and live behavior cases remain unverified.
6. Live HTTP/2, HTTPS, browser rendering, WebSockets, streaming, compressed framing, and HTTP/3 are not established.

## Human actions

1. Recover MCP responsiveness in Burp when present. Keep the thread dump and current logs; inspect before reloading or restarting. Confirm MCP authentication and `burp_get_status` after recovery.
2. Review and, if accepted, load `build\candidates\burp-mcp-1.3.2-20261101.2-burp2024.1.1.1.jar` using Burp Extensions. Confirm the new build ID and the 71-tool catalog. Do not mistake a successful build for a deployed build.
3. In the Burp MCP scope UI, configure only the fixed localhost paths if needed; with mode disabled, use the local confirmation. Verify each exact URL reports `eligible=true`.
4. Review the unattended policy panel, then click **Enable Unattended Local Test Mode** only when ready to supervise the deployment. Default authorization is 120 seconds; it expires without renewal. This audit did not activate it.
5. For a later identity-bound run, set the two values shown in the active Burp panel, start the bounded fixture, then run the preflighted runner. Keep any bearer token in the PowerShell process environment or use the secure prompt.
6. After the request is held, apply the drop with the matching message ID through Burp MCP and provide the required local Burp confirmation unless the operator has explicitly enabled the limited mode. Verify the same run's DROPPED state, origin record count zero while the server is running, stale-ID rejection, terminal client outcome, and empty queues. Do not retry automatically.

Prepared command sequence (placeholders must be copied from the active Burp panel only after deployment and explicit activation):

```powershell
$env:BURP_TEST_RUN_ID = '<Run ID shown in Burp>'
$env:BURP_TEST_SERVER_IDENTITY = '<Server identity shown in Burp>'
.\scripts\prepare-cancel-test-server.ps1 -TestRunId $env:BURP_TEST_RUN_ID -ServerIdentity $env:BURP_TEST_SERVER_IDENTITY
.\scripts\run-cancel-test.ps1 -PromptForMcpToken
```

The runner fails before opening the Proxy request if authenticated MCP, server identity, scope, interception, heartbeat, queue, deadline, or listener preflight cannot be verified. Do not run this sequence against the currently unresponsive MCP service.

## Recommendations

1. Recover and observe the frozen MCP service before any supervised test; capture a second bounded health sample only after recovery.
2. Load the candidate in a supervised session and verify startup, build ID, tool list, scope checks, emergency stop, and expiry. Keep `.1` and `.2` backups untouched.
3. Explicitly activate the local mode in Burp only for a short supervised run; verify its UI identities match the local fixture.
4. Complete one valid Phase 4A run with a single request and all listed evidence, then separately test other operations and protocols.
5. Expand individual MCP tool authorization/output/error tests before calling the catalog fully behavior-verified.
