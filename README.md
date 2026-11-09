# Burp MCP

Burp MCP is a Burp Suite extension that exposes scoped traffic inspection,
analysis and human-approved testing operations as Model Context Protocol tools.
It uses the Montoya API, Kotlin MCP SDK and a local Streamable HTTP endpoint.
It builds on [PortSwigger's MCP server](https://github.com/PortSwigger/mcp-server).

**Current checkpoint: v1.5.0-dev.6**, build
`20261107.3-scanner-permission-hardening-dev`. Development is paused and features
are frozen. **v1.5.0 is not approved as a stable release or release candidate.**
The verified **v1.4.0 rollback release remains preserved**. See
[development status](docs/DEVELOPMENT_STATUS.md) for evidence and remaining gates.

## Runtime and authentication

The qualified runtime is **Burp Suite Professional 2024.1.1.1**. The extension
compiles against Montoya 2023.12.1 and targets Java 17. Community supports a subset;
Scanner and Collaborator require Professional. Other Burp releases are not implied
verified. See [compatibility notes](docs/BURP_2024_1_COMPATIBILITY.md).

MCP listens at `http://127.0.0.1:9876/mcp`, using Streamable HTTP and bearer
authentication. Dev.6 refuses non-loopback binding or disabled authentication.
Clients send the current local token through `Authorization: Bearer`, preferably
from an environment variable. Keep tokens and local client configuration out of
Git. Host/Origin validation and native Burp permissions remain independent controls.
There is no bundled SSE-to-stdio proxy or mandatory model gateway.

## Existing capabilities

- Runtime/capability status, scoped/redacted Proxy history and Site Map, bounded
  request/response retrieval, comparisons and heuristic security analysis.
- Human-approved HTTP/1 and HTTP/2 sends, Repeater insertion and bounded passive
  audit operations where the runtime supports them. Repeater insertion does not send.
- Manual interception with separate disclosure and exact-revision edit/forward
  approvals, queues, deadlines and cleanup controls.
- Disabled-rule preparation, bounded target grants and separately approved target
  execution sessions; deterministic priority/conflict handling and response association.
- Scanner scope/attachment filtering, authorized-only report counts, metadata
  redaction and the dev.6 legacy Scanner native-permission correction.

HTTP rule transformations support JSON field set/remove, query parameter
set/remove, URL-encoded form field set/remove, request/response header set/remove,
and literal replacement in UTF-8 `text/plain` or `text/html`. Body edits validate
encoding/framing and recalculate Content-Length. Routing, framing and credential
headers are protected. Rules do not execute scripts or regex replacements.

## Authorization boundaries

A destination must pass current Burp Target scope and the MCP host allowlist.
A target preparation grant allows only disabled rule preparation. Execution needs
a second native human approval binding exact rule IDs/specifications and lifetime.
Target sessions cannot authorize DROP. Read-only mode, data-disclosure approval,
request approval and native Proxy Intercept are separate controls. Unattended Local
Test Mode is a separate legacy policy and cannot approve target grants or sessions.

Never treat installation, preflight, a saved plan or an old approval as permission
to send traffic, scan, seed findings, expand scope, enable interception or renew
sessions. Use synthetic controlled targets and separate approval for every live batch.

## Build and manual installation

On Windows, use Git, a Java 17 JDK, PowerShell 5.1+ and Python 3.10+ for the
coordinators. From the repository root:

```powershell
.\gradlew.bat -PdevelopmentBuild=true --no-configuration-cache test shadowJar --console=plain
```

The wrapper downloads pinned Gradle/dependencies on first use. Development output:
`build\dev-v1.5.0\libs\burp-mcp-1.5.0-dev.6-all.jar`. JARs are not committed.
Preserve existing same-version artifacts before rebuilding. Do not run `build.ps1`
or default-output clean/package commands against the preserved v1.4.0 workspace.

1. In the intended Burp project, inspect queues/authority before any extension
   replacement. The human unloads the older MCP instance and adds the intended
   Java JAR through Extensions > Installed > Add. Confirm only one is Loaded.
2. Verify the actual loaded path, manifest/version/build and disk SHA-256; filenames
   alone do not establish identity. Confirm Burp MCP reports Running on loopback.
3. Keep bearer authentication and required native approvals enabled. Configure
   the client with the local token; see [Codex connection setup](docs/CODEX_SETUP.md),
   [.mcp.json example](.mcp.json.example) or [OpenCode example](opencode.json.example).
4. Confirm authenticated MCP initialization and tool discovery with safe status
   tools. Scope/allowlist configuration needs its own narrow human review. The
   original controlled configuration is documented in the agent guide.

[Agent setup and operation](docs/AGENT_SETUP.md) is the self-contained text guide
for a fresh restart/clone, building, loading, token handling, safe tools, rules,
preflight and cleanup. It also supplies manual setup instructions. The requested
Word guides `docs/Burp_MCP_Manual_Setup_and_Use.docx` and
`docs/Burp_MCP_Agent_Automated_Setup_Runbook.docx` are **missing** from this
checkpoint; they have not been added or reviewed.

## Tests and non-traffic preflight

The Gradle command above runs mock-backed JVM and embedded local MCP transport
tests. Against an existing matching development JAR, this fast subset avoids
repackaging:

```powershell
.\gradlew.bat -PdevelopmentBuild=true -x shadowJar --no-configuration-cache test --tests '*BuildInfoTest' --tests '*McpServerIntegrationTest.scanner listing permission*' --console=plain
python -B -m unittest discover -s scripts -p 'test_live_rule_engine_coordinator.py'
powershell -NoProfile -File .\scripts\test-phase2-method-fixture.ps1
git diff --check
```

The full offline Python suite is `python -B -m unittest discover -s scripts -p 'test_*.py'`. The pure fixture suite creates no listener or request.
With the intended running Burp and existing approved configuration:

```powershell
python -B scripts/live_rule_engine_coordinator.py --target-preflight-only
```

This checks MCP/runtime/scope and Proxy TCP availability; it sends no application
HTTP request and creates no authorization. **Do not omit the flag:** the legacy
no-argument coordinator executes traffic. Native project identity and Intercept
state require separate observation. No live campaign is run by this checkpoint.

## Verified status and limitations

Dev.6 authenticated connectivity, loaded identity/checksum, 89 unique tool discovery
and non-traffic preflight passed runtime verification. **89 registered tools does
not mean every tool was individually live-tested.** The offline dev.5 baseline is
303 JVM and 118 Python passes, four offline PowerShell suites and 24 syntax checks.
Dev.6 native-permission hardening has focused regression evidence.

Batch A HTTP transformations passed live on **dev.5**: exactly three POSTs, three
HTTP 200 responses, three independent origin deliveries, correct counters and full
cleanup. This is preserved historical evidence, not a repeated dev.6 live result.
The later dev.6 negative-only Scanner call returned denial without Scanner data,
but its native dialog category and human DENY selection were not conclusively
captured. That gate is not fully verified.

Native nonempty Scanner security and lifecycle/reliability testing remain incomplete.
Repeater tab enumeration is unsupported; project identification/Organizer APIs may
be unavailable on this baseline. Active audits are disabled. Rule transforms do
not support multipart, binary, compressed, chunked, streaming or WebSocket content.
Analysis is heuristic and credential redaction is not a general data-loss guarantee.
Timeout/cancellation does not prove that a native request never reached its origin.

Read [remaining supervised batches](docs/SUPERVISED_CAMPAIGN.md),
[target authorization](docs/V1_5_0_TARGET_AUTHORIZATION.md),
[Phase 2 plan](docs/PHASE2_TARGET_SESSION_PLAN.md),
[rule reference](docs/INTERCEPTION_RULE_ENGINE.md) and
[verification details](docs/V1_5_0_VERIFICATION.md) before resuming.
Private reports/build outputs stay local under ignored `build/`; sanitized handoff
summaries are committed under `docs/`. No v1.5.0 tag, release or release candidate
is created by this development checkpoint.
