# Burp MCP connection and stateless transport verification

Checked on 2026-11-02 against the existing dirty working tree. Existing changes were retained. No GitHub push or Burp extension reload was performed.

## Loaded runtime

| Check | Result |
|---|---|
| Burp | Connected; Professional 2024.1.1.1-26891 |
| Extension | 1.4.0, build `20261101.13-burp2024.1.1.1` |
| Listener | Running at `http://127.0.0.1:9876/mcp`, no reported error |
| Authentication | Authenticated tools succeed; POST ping with missing or incorrect bearer token returns HTTP 401 |
| Registered tools | Direct `tools/list` returns 86 tools, 86 unique names; embedded tests check the exact tool set and schemas |
| Stateless transport | Authenticated GET accepting SSE returns HTTP 405 with `Allow: POST`; POST clients receive no session header |
| Responsiveness | 24 independent initialize/ping/status sequences with eight concurrent workers completed in 1.52 seconds; slowest sequence 350 ms; all reported build .13 |
| Interception | Disabled, empty request and response queues, no active unattended authorization; authorized-target count zero |

These checks used MCP calls and loopback HTTP only. Tokens were read from the process environment and were not printed or persisted.

## Changes and verification

The existing source change selects the SDK's `mcpStatelessStreamableHttp` transport. This tool-only server does not need a persistent GET/SSE listener or resumable sessions. The loaded build's observed GET and POST behavior matches that design.

This session corrected the live rule coordinator's stale .12 build pin to .13. The Python MCP client now sends `MCP-Protocol-Version` for stateless requests, independent of whether the server issues a session ID. A regression checks the negotiated version with no session header.

The integration suite now keeps the mock approval prompt pending until all eight independent health clients finish; a timer can no longer let approval complete before the health check. It also restarts the listener three times on the same port and checks fresh initialization, ping and status after each restart. Test teardown shuts down the manager executor. The standard validation runner now includes the rule coordinator tests and, in LOCAL/SUPERVISED mode, its loopback request/response fixture.

| Validation | Result |
|---|---|
| Final `gradlew.bat test --console=plain` | PASS: 217 tests, zero failures, errors or skips; 11 MCP integration tests |
| Python discovery, `test_*.py` under `scripts` | PASS: 56 tests |
| `test-live-rule-engine-fixture.ps1` | PASS: response starts with enabled=false, unrelated fields preserved, origin headers/framing recorded |
| `test-local-server.ps1` | PASS: 23 checks, zero failures |
| `test-local-server-identity.ps1` | PASS: missing/wrong identities rejected, exact identity accepted, identity values not persisted |
| `test-validation-orchestrator.ps1` | PASS: five assertions and PowerShell parser check |
| `git diff --check` | PASS |

`test shadowJar --rerun-tasks` also completed successfully before the final test refinements. The rebuilt `build/libs/burp-mcp-all.jar` manifest reports version 1.4.0 and build .13; SHA-256 is `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`. The existing versioned .13 artifact was preserved. The rebuilt JAR was not reloaded into Burp; build identity and live transport behavior were checked, but the loaded artifact's byte-for-byte checksum was not available through MCP.

Final live status still reports running, authentication required, no error, and both pending queues empty. The callback and loopback harness results above are local/mock integration evidence, distinct from the real Burp Proxy rule test below.

## Limits and next live step

The historical service-wide freeze was not reproduced. Successful client churn and restart checks establish current responsiveness, not the definitive cause of that historical stall.

The real Proxy rule coordinator was attempted and returned `PREFLIGHT_FAILED`: unattended local test mode is inactive. It reported `liveTrafficStarted: false` and `clientAttemptsStarted: 0`. No session or rule was enabled. Actual rule modifications reaching an origin and client through the running Burp Proxy remain unverified in this session.

For that next test, activate Unattended Local Test Mode in Burp for 300 seconds, leaving live interception off for setup. Call `burp_configure_local_test_scope` to configure the fixed nine localhost test paths under the existing local policy, then run `python scripts/live_rule_engine_coordinator.py`. The coordinator requires that exact scope and the single localhost allowlist entry, prepares both request and response rules, verifies readiness, and sends only its synthetic fixture exchanges. Complete any native Intercept approval prompt locally. A held response is reported as `WAITING_FOR_APPROVAL` without automatic approval or retry.

An overlapping Gradle attempt failed on an open test-results file. The additional validation wrapper was stopped before completion to prevent another overlap; it has no completed aggregate result. The final standalone Gradle result is the authoritative result for this session.
