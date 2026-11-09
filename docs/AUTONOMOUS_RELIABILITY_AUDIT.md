# Burp MCP autonomous reliability audit

- **Audit date:** 2026-10-31
- **Repository baseline:** `a89c433a03b416e730fe02669221adcd7c5992c6` (`main`, tracking `origin/main`)
- **Burp:** Burp Suite Professional `2024.1.1.1-26891`
- **Extension:** `1.3.1`; loaded instance observed as build `20261031.1-burp2024.1.1.1`
- **Build produced by this audit:** `20261031.2-burp2024.1.1.1`
- **MCP endpoint:** `http://127.0.0.1:9876/mcp`; loopback only
- **Proxy / synthetic origin:** `127.0.0.1:8080` / `127.0.0.1:8000`
- **Java:** JDK 17; compile-only Montoya API baseline `2023.12.1`

## Overall result

The source and test build is healthy. The final LOCAL orchestrator run completed with 12 checks passed, 0 failed, 0 blocked, and 1 approval-gated live item unverified. Its Gradle suite had **151 tests, 0 failures, 0 errors, 0 skipped**. The local HTTP harness completed **23 checks, 0 failures**. The final default OFFLINE run completed with 11 passed, 0 failed, 1 intentionally blocked (localhost tests are excluded in OFFLINE mode), and 1 unverified (approval-gated live actions).

The MCP endpoint answered short, bounded read-only checks during discovery and again at the end of the audit. The final `burp_check_connection` result reported `burpConnected=true`, server `running`, and Burp `2024.1.1.1-26891`. `burp_get_status` confirmed the loaded extension is still build `20261031.1-burp2024.1.1.1`, bearer authentication is required, `readOnlyMode=false`, and the authorized-target count is zero. `burp_get_intercept_status` showed interception disabled and zero pending requests/responses; the heartbeat was `EXPIRED` because no session was active. The final authoritative scope check found all nine localhost URLs still ineligible. No state-changing tool was called. The earlier reported service-wide MCP stalls were not reproduced, and the source does not establish a root cause for them. No retries or process restarts were used to chase the historical stall.

The live Burp extension is still the existing `.1` build. This audit built and validated `.2`, but did not load or hot-swap it. The current live MCP catalog therefore remains the original 70 tools. The new source build registers 71 tools, retaining the original 70 and adding the approval-protected localhost scope helper.

## Validation evidence

| Area | Result | Evidence and limits |
|---|---|---|
| Default OFFLINE command | **PASS** | 111 Gradle tests passed; orchestrator 11 PASS, 0 FAIL, 1 BLOCKED, 1 UNVERIFIED. It excludes tests tagged `loopback`, sends no network requests, and exits zero when there are no FAIL results. Final report run `652534765bb14609bb52cb577dde5176`. |
| Full LOCAL Gradle suite | **PASS** | 151 tests, 0 failures/errors/skips. Includes all mock-based tool tests, MCP integration, session/queue tests, and local HTTP integration tests. Final run `fc0013e92c50489dbe63f9a0ee88adbf`. |
| Local origin harness | **PASS** | 23 bounded checks; synthetic data only; server ran on loopback and was stopped by the test harness. Verified framing, origin counts, byte lengths, SHA-256, and metadata-only logs. |
| Cancellation runner | **PASS offline regression** | Complete HTTP errors, clean EOF, reset, abort, partial status/header/body, wrong Content-Length, timeout, malformed data, chunked and close-delimited response framing, unexpected 200 rejection, size bounds, and origin non-delivery logic. `NetworkRequestsSent=0`. |
| Concurrent runner | **PASS offline regression** | Positive edited-length case, framing mismatch, crossed request identity, and zero network requests. |
| MCP catalog and schemas | **PASS in LOCAL integration** | Exact expected set of 71 names, uniqueness, object input schema, property types, required-field consistency, descriptions, and key tool invocation/error paths. |
| Current MCP service | **PASS, bounded read-only check** | Responsive during discovery. This is a point-in-time observation, not evidence that the historical hangs are fixed. |
| Current Burp target scope | **FAIL eligibility / expected unconfigured state** | All nine requested localhost URLs reported `inBurpScope=false`, `hostAllowlisted=false`, `eligible=false`. No live scope change was made. |
| New JAR metadata | **PASS** | Manifest and runtime identity match version `1.3.1`, build `20261031.2-burp2024.1.1.1`. SHA-256 `59089ff5248cab06fdf6918202165a2a4617c29a8e178f50c0eeab0243f84ce0`. |
| Burp reload / live `.2` compatibility | **UNVERIFIED** | Requires a human to install/reload the extension in Burp. |
| Phase 4A cancellation | **INCONCLUSIVE** | Preserve the earlier evidence and status in [LIVE_INTERCEPTION_TEST_RESULTS.md](LIVE_INTERCEPTION_TEST_RESULTS.md). Corrected offline runner tests pass; a supervised live retest is still required. |

Generated machine-readable and Markdown orchestrator reports are under the ignored `build/reports/full-validation/` directory. The final OFFLINE report is `validation-652534765bb14609bb52cb577dde5176.{md,json}`; the final LOCAL report is `validation-fc0013e92c50489dbe63f9a0ee88adbf.{md,json}`. Per-test stdout/stderr and the synthetic server metadata log are under ignored `build/validation/`.

## MCP tool-by-tool result

The live catalog contained 70 names at discovery. The full LOCAL integration test now checks those names exactly, plus `burp_configure_local_test_scope`, so a future removal or rename fails the suite. Every catalog entry passed the basic schema and registration check. The behavior results below are deliberately narrower: `PASS` applies only to the named mock or read-only check; it does not imply a live Burp action was performed.

| Result | Tools | Test scope |
|---|---|---|
| **PASS — live read-only** (4) | `burp_check_connection`, `burp_get_intercept_status`, `burp_get_scope`, `burp_get_status` | Bounded connection and extension-status checks, disabled/empty interception status, and eligibility checks for the nine localhost URLs. |
| **PASS — LOCAL integration or Montoya/approval mock** (20) | `base64_decode`, `base64_encode`, `burp_get_capabilities`, `burp_get_intercept_diagnostics`, `burp_get_intercepted_request`, `burp_modify_request`, `create_repeater_tab_http2`, `generate_collaborator_payload`, `generate_random_string`, `get_active_editor_contents`, `get_collaborator_interactions`, `get_proxy_http_history`, `send_http1_request`, `send_http2_request`, `set_active_editor_contents`, `set_project_options`, `set_proxy_intercept_state`, `set_task_execution_engine_state`, `url_decode`, `url_encode` | Unit/integration fixtures or synthetic Montoya mocks. Request sends, Repeater actions, editor/config changes and toggles were not executed against the user's live Burp state. `burp_modify_request` includes a negative header-injection validation case. |
| **BLOCKED — live action requires human approval** (17) | `burp_approve_intercepted_request_edit`, `burp_approve_intercepted_response_edit`, `burp_cancel_interceptions`, `burp_drop_intercepted_request`, `burp_drop_intercepted_response`, `burp_forward_intercepted_request`, `burp_forward_intercepted_response`, `burp_propose_intercepted_request_edit`, `burp_propose_intercepted_response_edit`, `burp_request_intercept_disclosure`, `burp_send_http_request`, `burp_send_to_repeater`, `burp_set_live_interception_state`, `burp_set_proxy_intercept_state`, `burp_start_scan`, `burp_stop_scan`, `create_repeater_tab` | No live calls were made. These actions can disclose content, change Burp state, create/send traffic, or release/drop held messages; their local human-approval gates remain intact. |
| **UNVERIFIED — behavior not independently invoked or fixture-tested** (29) | `burp_analyze_authentication`, `burp_analyze_cookies`, `burp_analyze_cors`, `burp_analyze_request`, `burp_analyze_response`, `burp_analyze_security_headers`, `burp_compare_responses`, `burp_find_sensitive_data`, `burp_generate_security_report`, `burp_get_intercepted_response`, `burp_get_project_info`, `burp_get_proxy_history`, `burp_get_repeater_tabs`, `burp_get_request`, `burp_get_response`, `burp_get_response_headers`, `burp_get_scan_status`, `burp_get_scanner_issues`, `burp_get_site_map`, `burp_list_pending_requests`, `burp_list_pending_responses`, `burp_search_http_history`, `get_organizer_items`, `get_organizer_items_regex`, `get_proxy_http_history_regex`, `get_scanner_issues`, `output_project_options`, `output_user_options`, `set_user_options` | Registration and schema passed. Behavior needs specific safe fixture coverage or a suitable empty/local Burp dataset. `burp_get_repeater_tabs` is intentionally described in source as unsupported because this Montoya Repeater API cannot enumerate tabs; its runtime error response was not invoked in this audit. |

The new 71st tool, `burp_configure_local_test_scope`, passed local positive/negative approval-mock tests. Those verify it requests local confirmation, includes only nine fixed `http://127.0.0.1:8000/...` URLs, and adds only `127.0.0.1:8000` to the host allowlist after approval. Its actual Burp effect is **BLOCKED pending local confirmation after installing build `.2`**.

### Primary functional and risk classification

These primary groups cover all 70 existing names; the risk flags overlap. Historical data tools remain read-only but may require the configured data-access approval. Pending-message getters return safe metadata by default; sharing content requires separate disclosure approval.

| Class | Count and tools | Guardrails / notes |
|---|---|---|
| Pure local transformations and utilities | **6:** `base64_decode`, `base64_encode`, `burp_modify_request`, `generate_random_string`, `url_decode`, `url_encode` | No Burp state change or request transmission. `burp_modify_request` operates only on caller-supplied request text and redacts credential-like values. |
| Read-only Burp status, history, analysis, editor, configuration, and result access | **38:** `burp_analyze_authentication`, `burp_analyze_cookies`, `burp_analyze_cors`, `burp_analyze_request`, `burp_analyze_response`, `burp_analyze_security_headers`, `burp_check_connection`, `burp_compare_responses`, `burp_find_sensitive_data`, `burp_generate_security_report`, `burp_get_capabilities`, `burp_get_intercept_diagnostics`, `burp_get_intercept_status`, `burp_get_intercepted_request`, `burp_get_intercepted_response`, `burp_get_project_info`, `burp_get_proxy_history`, `burp_get_repeater_tabs`, `burp_get_request`, `burp_get_response`, `burp_get_response_headers`, `burp_get_scan_status`, `burp_get_scanner_issues`, `burp_get_scope`, `burp_get_site_map`, `burp_get_status`, `burp_list_pending_requests`, `burp_list_pending_responses`, `burp_search_http_history`, `get_active_editor_contents`, `get_collaborator_interactions`, `get_organizer_items`, `get_organizer_items_regex`, `get_proxy_http_history`, `get_proxy_http_history_regex`, `get_scanner_issues`, `output_project_options`, `output_user_options` | Some expose sensitive captured/configuration data and use redaction plus optional data-access approval. `burp_get_intercepted_request/response` expose only safe metadata until disclosure is locally approved. `burp_get_repeater_tabs` is explicitly unsupported by this Montoya API. |
| Interception edits, approvals, release/drop, disclosure, and session control | **11:** `burp_approve_intercepted_request_edit`, `burp_approve_intercepted_response_edit`, `burp_cancel_interceptions`, `burp_drop_intercepted_request`, `burp_drop_intercepted_response`, `burp_forward_intercepted_request`, `burp_forward_intercepted_response`, `burp_propose_intercepted_request_edit`, `burp_propose_intercepted_response_edit`, `burp_request_intercept_disclosure`, `burp_set_live_interception_state` | Interception-related and approval-dependent. Exact message ID/revision checks remain required. Drop, cancel, and session stop can discard held traffic. Dropping a response cannot undo the upstream request. |
| HTTP send, Repeater, passive scan, and Collaborator actions | **9:** `burp_send_http_request`, `burp_send_to_repeater`, `burp_start_scan`, `burp_stop_scan`, `create_repeater_tab`, `create_repeater_tab_http2`, `generate_collaborator_payload`, `send_http1_request`, `send_http2_request` | Authorization-sensitive. Request sends and scan actions require scope, explicit host allowlisting, rate capacity, read-only mode off, and one-time approval. Repeater insertion does not send until the user clicks Send. The HTTP send path is limited by Montoya's lack of cancellation. |
| Configuration, editor, Proxy toggle, task engine, and native interception changes | **6:** `burp_set_proxy_intercept_state`, `set_active_editor_contents`, `set_project_options`, `set_proxy_intercept_state`, `set_task_execution_engine_state`, `set_user_options` | State-changing and locally gated. Config changes can affect Burp project/user settings; the two Proxy toggles are separate from the extension's managed interception session. |

Potentially destructive actions are the interception drop/cancel/session-stop paths, scan deletion, and user/project configuration updates. Scanner availability and some Collaborator behavior depend on Professional Edition; current live verification used Professional 2024.1.1.1. The Community Edition base-tool registration was checked in a mock fixture (50 tools without the live interception module); a full Community runtime catalog was not available in this environment.

Historical live PASS evidence supplied for this task remains distinct from this audit's fresh results. It includes request/response editing, form and multipart changes, cookie and header edits, exact framing, browser rendering, and two independent concurrent interceptions. Those results remain documented in [LIVE_INTERCEPTION_TEST_RESULTS.md](LIVE_INTERCEPTION_TEST_RESULTS.md); they are not being used to mark untested tools above as PASS.

## Confirmed issues and repairs

### Approval dialogs had no bounded wait

Several MCP paths awaited local approval dialogs without a timeout. A caller could therefore remain suspended indefinitely if a dialog was missed or the UI did not answer. This is a confirmed unbounded-wait defect, but there is no evidence that it caused the earlier service-wide MCP stall.

Added a shared two-minute timeout that fails closed and records a payload-free `timed_out` activity event. Applied it to state changes, data-access approval, HTTP request approval, and interception stop/cancel confirmations. The Swing dialog continuation disposes a queued/open dialog when cancellation fires. Regression tests cover timeout, dialog cancellation, and propagation of both ordinary cancellation and an outer request deadline.

### Runtime build identity lagged Gradle metadata

`gradle.properties` and the packaged manifest moved to build `.2`, but checked-in `BuildInfo` still reported `.1`. The build identity and packaged-manifest tests reproduced the mismatch. Updated runtime identity to `.2`; the full build and manifest identity tests now pass. These constants remain duplicated, with `BuildInfoTest` serving as the mismatch guard.

### Local server treated HTTP body length as characters

The local test server needed byte-accurate request framing and bounded parsing for binary/Unicode fixtures. It now parses headers and bodies as bytes, rejects conflicting or oversized framing, has request/body/runtime limits, closes connections explicitly, and records metadata only. The localhost suite verifies byte counts and hashes, malformed framing, premature EOF, response lengths, and log redaction.

### Cancellation runner false-failure defect

The earlier runner stopped after the first received byte and treated that byte as a complete client outcome. The corrected runner reads until complete HTTP framing or a bounded terminal outcome and separately checks origin delivery. Offline cases pass. The previous live result remains **INCONCLUSIVE** until the supervised one-request drop test is repeated.

### Validation harness defects fixed during this audit

The first orchestrator attempts exposed (a) a MockK coroutine import mismatch in the new timeout test, (b) a non-stateful persisted-object mock in the scope helper test, and (c) PowerShell `Start-Process` exit-code capture behavior. Each was fixed with a targeted test or process-wrapper correction. The final OFFLINE and LOCAL orchestrator runs both exit successfully and correctly report failures if a child command fails or times out.

## Architecture, concurrency, and lifecycle findings

- MCP HTTP request handling runs on Ktor Netty. `KtorServerManager`'s single-thread executor serializes server start/stop lifecycle work; it does not execute MCP tool calls. The historical global hang was not reproduced, so no deadlock or pool-starvation root cause is established.
- `McpTool` bounds serialized arguments, returns structured tool errors, records payload-free status, and rethrows coroutine cancellation. MCP authentication uses bearer-token validation with constant-time byte comparison. The token is not logged or exposed by status tools.
- Interception uses an eight-message shared queue, monotonic deadlines, bounded terminal records, exact revision checks, final forward/drop transitions, automatic expiry, and a local heartbeat/session lease. Tests cover stale revisions, approval invalidation, duplicate/competing terminal transitions, expiry, cancellation, unload, scope revocation, no resurrection, and bounded queue capacity.
- Disclosure prompts are serialized by a one-at-a-time semaphore. A competing request can report `BUSY`; this is intentional dialog serialization, not approval reuse. The historical two-request live test passed and reported this behavior. Four/eight simultaneous live interceptions were not generated.
- Proxy callback waiting is synchronous and can occupy a Burp callback thread until its bounded per-message deadline (maximum 120 seconds). The queue is capped at eight. This remains an operational risk if many requests are held simultaneously; no architecture rewrite was justified by the evidence.
- `BurpHttpRequestExecutor` bounds live request waits to 10 seconds and limits itself to four daemon workers. Burp 2024.1's Montoya API has no per-request cancellation method; a timed-out request may still complete inside Burp. The extension does not retry it. Four stuck sends can consume the worker limit; this API limitation remains.
- Session and queue unit tests cover lifecycle transitions, but the historical MCP service-wide stall is not reproduced by the local tests. A supported extension reload with an empty queue and fresh status check is still needed to verify the loaded build after return.

## Protocol coverage and limits

The local server harness validates HTTP/1.1 `Content-Length` exchanges with GET/POST/PUT/PATCH/DELETE, JSON, URL-encoded and multipart forms, cookies and headers, UTF-8, binary bodies, empty bodies, a 64 KiB body, request identity, SHA-256, timeout behavior, malformed/conflicting framing, oversized bodies, premature EOF, and a declared keep-alive request that the test server closes explicitly.

This test server intentionally handles one request per connection, closes rather than reuses keep-alive connections, and returns `501` for chunked requests. It does not claim to validate extension keep-alive or chunked behavior. Missing Content-Length, compressed payloads, client/origin disconnects through Burp, actual HTTPS/TLS, HTTP/2 proxy interception, WebSockets, streaming, and HTTP/3 are not live-tested. HTTP/2 request construction has mocked unit coverage only. No certificate trust was changed, and no external domain or service was contacted.

## Scope and approval status

The current live instance reported `authorizedTargetCount=0`; the nine requested endpoint URLs were all ineligible because neither Burp scope nor the extension allowlist contained them. The Montoya API version used by this project exposes `Scope.includeInScope(String)` and `excludeFromScope(String)`. The new helper uses that supported API only for the nine fixed localhost URLs and runs the extension's existing state-change confirmation first. It does not disable scope checks, read-only checks, authentication, or per-request approval.

The new helper has **not** run in live Burp. The helper is present only in the new JAR; the loaded extension is still `.1`. Do not infer that the live Target scope has changed. After the human reload and local approval, call `burp_get_scope` for the nine exact paths and require `eligible=true` for each.

## Build and artifact safety

- The original known-good JAR was preserved unchanged at `D:\Projects\MCP-known-good-20261031.1-burp2024.1.1.1.jar`, SHA-256 `1d4af1215ea184c549d20dd59d278023d0b3f102e5868e4d8223c09bdf659c8f`.
- Before the final `.2` rebuild, the prior output JAR was copied to `D:\Projects\MCP-build-backups\burp-mcp-pre-validation-8bc9487671093252ccbb10ae4101b3e9b54ea7d5f86397bdd9f287a1683e9184.jar` and hash-verified.
- The final `build/libs/burp-mcp-all.jar` is 20,212,225 bytes, version `1.3.1`, build `20261031.2-burp2024.1.1.1`, SHA-256 `59089ff5248cab06fdf6918202165a2a4617c29a8e178f50c0eeab0243f84ce0`. A matching copy is at `D:\Projects\MCP-build-backups\burp-mcp-20261031.2-burp2024.1.1.1-59089ff5248cab06fdf6918202165a2a4617c29a8e178f50c0eeab0243f84ce0.jar`.
- The most recent pre-build output, SHA-256 `b27d58c385b91809bb62a48e8eacbfade88d1cdfa0ecc7491b540002d26e5511`, is retained at `D:\Projects\MCP-build-backups\burp-mcp-pre-validation-b27d58c385b91809bb62a48e8eacbfade88d1cdfa0ecc7491b540002d26e5511.jar`.
- Gradle embeds a fresh `Built-Date` in the manifest, so rebuilding unchanged sources changes the JAR hash. The version, build ID, and matching manifest checks remain stable; the hash above identifies the final artifact.
- Compilation and tests used JDK 17 and the project's Montoya `2023.12.1` compile baseline. This validates compile-time compatibility; only a human reload in Burp `2024.1.1.1-26891` can verify runtime compatibility.

## Git and remaining actions

The audit began at baseline commit `a89c433a03b416e730fe02669221adcd7c5992c6`. Preexisting cancellation work was preserved and reviewed. `git diff --check` and the changed-text secret scan passed. No JAR, raw request/response capture, bearer token, private key, or generated local traffic log is intended for Git. No push was performed.

### When you return

1. In Burp **Extensions → Installed**, confirm the interception session is disabled and the pending request/response counts are zero. Unload the current `.1` extension and load `D:\Projects\MCP\build\libs\burp-mcp-all.jar`. Reconnect the MCP client if it caches the old tool list.
2. Verify `burp_get_status` reports build `20261031.2-burp2024.1.1.1` and `burp_get_intercept_status` reports disabled with zero pending messages.
3. Call `burp_configure_local_test_scope` and approve the Burp-local confirmation. Then call `burp_get_scope` with exactly the nine localhost URLs listed in this report and verify all are eligible. No other host is authorized by that helper.
4. Reproduce the safe local suite with `.\scripts\run-full-validation.ps1 -Mode LOCAL`.
5. To finish Phase 4A, start `.\scripts\local-test-server.ps1 -LogPath .\build\live-test-server-observations.jsonl -MaxRequests 40 -MaxBodyBytes 1048576 -RequestTimeoutSeconds 10 -MaxRunSeconds 300` in one PowerShell window. In a second window run `.\scripts\run-cancel-test.ps1` once. Enable the bounded interception session with local approval, identify its single pending `/test-cancel` request, and use the locally confirmed drop action. Let the runner finish; it waits at most 125 seconds, sends no retry, parses complete framing, and checks the origin log independently. Mark Phase 4A PASS only if the runner proves the client observed a complete HTTP error or terminal connection failure and exactly zero origin deliveries. Otherwise keep it INCONCLUSIVE and save only metadata.

The `.2` extension is built and ready for review; it is not installed in the running Burp process. No push was performed.
