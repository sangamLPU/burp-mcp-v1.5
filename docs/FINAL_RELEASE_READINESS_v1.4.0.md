# Burp MCP v1.4.0 build .13 — release readiness

**Release decision: READY for the verified v1.4.0 HTTP interception feature set on Burp Suite Professional 2024.1.1.1, with the limitations below.** Final Phase 4A passed in exactly one request. The complete offline/local regression ran once and passed; the working .13 JAR and backups remain unchanged. The earlier nine-exchange and Phase 4B/4C/4D successes were preserved without repeating those live tests.

## Verified evidence and boundaries

| Level | Evidence | Current status |
|---|---|---|
| LIVE_PROXY | Nine complete request/response exchanges: single, five sequential, compatible rules, pause and resume; independent origin/client evidence and rule counters | PASS, preserved |
| LIVE_PROXY | Phase 4B message timeout, Phase 4C held-request session expiry, Phase 4D two-message/mixed-queue isolation and stale IDs | PASS, preserved |
| LIVE_PROXY | Phase 4A exact approved drop/DROPPED state, zero origin delivery, complete durable client terminal outcome, stale IDs and safe cleanup | PASS: one fresh attempt, zero retries; prior inconclusive attempt retained separately |
| LIVE MCP | 64 fresh clients across eight concurrent rounds, 71 seconds, slowest 146 ms; initialize/ping/list/status, no observed freeze | PASS for that bounded sample |
| Integration | Final 217-test JVM run includes 11 embedded MCP integration cases plus two local HTTP queue/callback integration cases. Authentication, exact 86-tool catalog/schema contract, stateless GET rejection, client churn, pending approval responsiveness, restart/shutdown | PASS: zero failures, errors or skips |
| Unit/mock | Remaining 204 JVM tests include evaluator/transforms, counter budgets, pause/resume/delete, approval boundaries, queues, timeout/session lifecycle, compatibility and cleanup | PASS in the final forced run |
| Cancellation unit/local streams | 14 new classifier/capture tests, including actual local socket streams, plus four one-shot orchestration tests; existing 13 reliability tests | PASS before activation |
| Final offline/local suite | All 91 Python tests; existing PowerShell cancellation/authentication/concurrency/orchestration harnesses; local identity/server/fixture checks | PASS: 21 validation checks, zero failures or blocked checks; two expected unverified exclusions described below |
| Individual tools | All 86 registered; inventory distinguishes 38 safe audit passes, prior live checks, current Phase 4 checks, expected unsupported/rejection cases and unverified tools | Classified, not universal positive-path live coverage |

Primary evidence: [nine-exchange milestone](LIVE_RULE_ENGINE_2026_11_02.md), [Phase 4 results](PHASE_4_LIVE_RESULTS_2026_11_02.md), [stability/tool audit](RELIABILITY_FOLLOWUP_2026_11_02.md), [86-tool inventory](../build/reports/reliability/tool-coverage.json).

## Final Phase 4A — verified result and capture contract

**Final live outcome: PASS.** On the fresh activation, exactly one request was sent. The interception recorded in the ignored local report, revision 0, received an exact `DROP_REQUEST` automatic-policy decision and a matching `intercept_drop: dropped` event. The fixture received zero requests to `/test-cancel`. Stale get/edit/forward operations were rejected; both queues were empty, the session was stopped and the fixture listener was verified closed.

The client completed in **0.191 seconds** with **EOF**, **HTTP 200**, **1,555 wire bytes**, **187 header bytes** and **1,368 body bytes**, using close-delimited framing. The body SHA-256 is `0dc4adcbf9fd2c5eadaa3327dbafdcd0de537b9fe7ad5fd7b377888013808ec5`; the wire SHA-256 is `ce878d085847c063adaaf65715ee579a7419dd31bcb7a3ca0470f7e7702816a1`. This is the proxy-generated terminal response, not an origin delivery. The separate client file was saved before publication and matched the report before cleanup. All eight required live checks passed.

Evidence: [complete one-shot report](../build/reports/reliability/phase4a-final-72b432345cbd4e2faf552eff997ca5eb.json), [durable client metadata](../build/reports/reliability/phase4a-final-72b432345cbd4e2faf552eff997ca5eb.client.json), [single final-regression intent/result](../build/reports/reliability/phase4a-final-72b432345cbd4e2faf552eff997ca5eb.full-regression.json).

The dedicated `scripts/phase4a_final.py` sends exactly one new GET `/test-cancel` after fresh human authorization. It does not run 4B, 4C, 4D or the nine modification exchanges. Before sending it requires the loaded .13 identity, bearer authentication, write permission, all nine existing localhost targets, empty queues, no configured rules and a healthy authorized session. The fixture and native proxy health have been checked; no cancellation request was sent during preparation.

The client now captures bounded raw response bytes in memory and persists only exact metadata: outcome, socket termination, HTTP status, header names, framing, expected/observed byte counts, wire/body SHA-256, elapsed time and error type. Request headers, bearer tokens, ephemeral server identities and raw response content are not persisted.

The terminal client file is atomically replaced after `flush`/`fsync` **inside the worker before publication to the coordinator**, independently of the final report. A write failure cannot publish success. The report retains the terminal file before session/fixture cleanup, including inconclusive results. Partial responses retain received byte counts/hashes/status where available; empty EOF, reset, abort, timeout, HTTP error, empty HTTP response and full proxy-generated HTTP 200 are distinct observations. Timeouts and partial/unsupported framing cannot pass. A complete HTTP status alone does not prove upstream delivery.

PASS additionally requires the exact interception ID/revision, the approved drop result and matching drop/automatic-approval events, zero origin deliveries, successful stale-ID rejection, empty queues, one attempt, matching durable client evidence and verified cleanup. No automatic retry or authorization renewal exists.

The one-shot client conservatively rejects Transfer-Encoding responses and interim informational responses as unsupported/nonterminal rather than inventing complete framing. The older PowerShell classifier separately has chunked-framing regressions; they are not a claim that the new capture client supports chunked responses.

[Preparation evidence](../build/reports/release/phase4a-final-preparation.json). Preparation requested at least 120 seconds. Burp reported an actual fresh **300-second** human activation, bound to the same run throughout the one-shot test. The coordinator verified its minimum 90-second setup window, the 60-second session plus margin, and at least 20 seconds of authorization before sending. No activation was renewed and no further live test was sent.

## Final regression — complete

After the one cancellation attempt, the armed command ran the complete applicable suite **once** through `run-full-validation.ps1 -Mode LOCAL -ForceTestExecution`. JVM dependencies were used offline; isolated loopback integration and local fixture tests were included. `test --rerun` forced execution of the test task, while `-x shadowJar` excluded packaging. All 91 Python `test_*.py` regressions ran, including the repaired terminal capture and one-shot coordinator. Existing PowerShell authentication, cancellation, concurrency, lifecycle/fixture and validation-orchestration harnesses also passed.

The run completed in **179.06 seconds**, with **217 JVM tests passed, zero failures/errors/skips**, and **91 Python tests passed**. The validation coordinator recorded **21 PASS, zero FAIL/BLOCKED/INCONCLUSIVE, and two UNVERIFIED**. Those two explicit exclusions are: approval-gated Burp actions were not repeated inside this offline/local run, and no new candidate JAR was built. Actual Burp Phase 4A and preserved earlier live evidence remain separate from that runner's scope.

Both before/after JAR hashes equal `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`. No successful live Burp phase was repeated by the suite. [Full validation report](../build/reports/full-validation/validation-f831d444afaf4c60890f93a7282a61ed.json), [test details](../build/reports/full-validation/validation-f831d444afaf4c60890f93a7282a61ed.md), [final verification summary](../build/reports/release/final-verification.json).

Cleanup checks confirmed the fixture stopped, interception disabled, both queues empty and zero configured/enabled rules. MCP remained running with bearer authentication required. A final read-only check confirmed authorization **inactive with zero remaining milliseconds** after natural expiry. It was never renewed or used for more live traffic.

## Integrity, backups, Git and compatibility

- Manifest-matching release artifact `build/libs/burp-mcp-all.jar` (also preserved in the release bundle): ZIP integrity PASS; manifest version 1.4.0 and build `20261101.13-burp2024.1.1.1`; SHA-256 `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`, unchanged from the preserved successful milestone.
- All 709 extension class files inspected target bytecode major 61 (Java 17). Montoya compile baseline remains 2023.12.1. Connected Burp reports **Professional 2024.1.1.1-26891**, build .13, connected and bearer-required. Existing live evidence proves these tested paths on this exact runtime; it does not prove every edition/API capability.
- `build/milestones/live-proxy-9-exchanges-20261102T090247Z/` preserves the working JAR and source/evidence ZIP. JAR hash, archive hash, archive integrity and current extension source versus archived extension source all match. The Phase 4 evidence has its own preserved archive.
- Local release finalization commits the validated implementation, regression harnesses and sanitized documentation. Generated evidence and binaries remain ignored under `build/`. The linked audit records the pre-commit state; use `git log` and `git status` for the finalized commit. No GitHub push or release publication is performed. [Exact Git/backup audit](../build/reports/release/git-and-backup-audit.json), [artifact audit](../build/reports/release/artifact-audit.json).
- MCP exposes loaded build identity, not a byte-for-byte hash of loaded JVM classes. The preserved on-disk JAR hash is not represented as an in-memory checksum.

The separately named historical `build/libs/burp-mcp-20261101.13-burp2024.1.1.1.jar` has SHA-256 `3c481bd6bb8407e889560a68a8ea8094fe21a2aaba2f1f779a8d4e739f313e32` and **does not match** the release manifest hash. It is retained unchanged as a historical artifact. Four class entries and packaging metadata differ; `javap -p -c` instruction listings for all four classes are identical, with debug metadata differences observed. Use the manifest-matching release bundle for artifact review; do not silently substitute the historical JAR. See [local release finalization](LOCAL_RELEASE_CANDIDATE_v1.4.0.md).

## Remaining limitations

| Area | Classification and practical limit |
|---|---|
| Cookie and Set-Cookie rewriting | **Unsupported by the automatic rule engine.** Credential/cookie/framing headers are protected, and the current live-proposal API protects Cookie/Set-Cookie headers. Historical synthetic/manual cookie tests from an earlier build do not establish automatic rewriting support in .13. |
| WebSocket frames | **Unsupported interception/editing.** Existing HTTP Proxy handlers/rules do not implement WebSocket frame modification; an internal serializer does not provide scope-safe frame interception. |
| Individual MCP tools | **Partially live verified.** Utility/history/analysis fixtures, schema registration and selected actual state changes have evidence. External Collaborator, scanner workflows, editor/task/config mutations, disclosure/manual-only and other untested positive paths remain unverified unless individually recorded. Unknown-scan rejection is negative-path evidence only. |
| Burp 2024 API fallbacks | Repeater tab enumeration and Organizer enumeration are unsupported; project identity can be unavailable. HTTP send has a bounded MCP wait, but this Montoya runtime cannot cancel a timed-out upstream send; no automatic retry. |
| Message formats/protocols | TLS/HTTP2 live interception, compressed/streaming/binary transformations and public targets are not certified by these localhost results. HTTP/3 is not exposed. Automatic rules intentionally reject compressed, chunked, multipart/binary and credential-bearing transformations. |
| Queue load | Eight-slot bounds have unit/state-machine evidence; live unattended operation is limited to two simultaneous messages and has two-message isolation evidence. |
| Historical transport freeze | **Not conclusively resolved.** The loaded stateless transport and bounded churn/responsiveness tests passed without recurrence. The original stall's root cause was not demonstrated; long-duration/extension-unload behavior is not guaranteed by the sample. |

The supported release claim remains bounded: authorized localhost HTTP rule processing and the individually recorded behaviors, with existing authentication, approval, scope, deadline, queue and rate boundaries intact.
