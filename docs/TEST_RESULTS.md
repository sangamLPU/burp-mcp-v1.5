# Consolidated verification — 2026-10-31

The authoritative source now combines the Burp 2024.1 Montoya compatibility fixes with the live interception improvements and diagnostics tool.

```powershell
.\gradlew.bat clean test shadowJar --no-daemon --console=plain
```

Result: **BUILD SUCCESSFUL; 146 tests, 0 failures, 0 errors, 0 skipped.** The Professional MCP integration test discovers 70 tools, calls `burp_get_intercept_diagnostics`, and parses the exact `extensionVersion` and `buildId` fields returned by both `burp_get_status` and `burp_get_capabilities`. Three build-identity tests verify the compiled runtime values, the packaged JAR manifest, and rejection of missing or incorrect manifests. The definitive artifact is `build/libs/burp-mcp-all.jar` (20,173,573 bytes; SHA-256 `1D4AF1215EA184C549D20DD59D278023D0B3F102E5868E4D8223C09BDF659C8F`), version `1.3.1`, build ID `20261031.1-burp2024.1.1.1`.

| Suite | Tests | Coverage |
|---|---:|---|
| `McpServerIntegrationTest` | 6 | Authenticated Streamable HTTP initialization, 70-tool discovery, read-only diagnostics contents, missing-token rejection, input validation, and shutdown |
| `MontoyaRuntimeCompatTest` | 5 | Burp 2024.1 API surface, project/Organizer fallbacks, stable history IDs, optional response timeout, bounded send and no retry |
| `LiveInterceptionTest` | 15 | Held request/response callbacks, exact-revision approval, proposal invalidation, heartbeat, scope, timeout, UI-thread/size handling, cancellation and unload |
| `LiveInterceptionLocalHttpTest` | 1 | Loopback HTTP exchange with approved request-header and response-header edits across callback boundaries |
| `DecisionQueueTest` | 9 | Exact revision approval, timeout drop, bounded capacity, cancellation, duplicate/concurrent decisions and disclosure isolation |
| `DecisionQueueLocalHttpTest` | 1 | Real local HTTP exchange gated by queue decisions; drop prevents the follow-up send |
| Remaining regression suites | 106 | Configuration, target validation, redaction, approval cancellation, authorization, history serialization, HTTP/2, tools, pagination and utilities |

The loopback tests use Montoya adapters/mocks; they exercise real local HTTP but do not install this JAR into Burp's live Proxy handler pipeline. The loaded extension remains untouched. Burp's Installed panel reported `D:\Projects\MCP\build\libs\burp mcp all.jar`, while the verified artifact is `D:\Projects\MCP\build\libs\burp-mcp-all.jar`; the reported path does not exist on disk. Its in-memory contents therefore could not be verified, and the 70-tool count is not treated as proof of build identity. Follow [Burp 2024.1 compatibility](BURP_2024_1_COMPATIBILITY.md) and [Live interception verification](LIVE_INTERCEPTION.md#verification) for the runtime boundary and manual local approval steps.
