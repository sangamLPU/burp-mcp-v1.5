# Codex connection diagnosis — 2026-11-06

## Initial investigation: recovered state

- Branch: `dev/v1.5.0`; starting HEAD: `fd0d1418fab90039f1eb08cea87fe3b1102c0af7`.
- Working tree was clean. No reset, clean, checkout, commit or push was performed.
- Listener: `127.0.0.1:9876`, PID 2976, Java 18.0.2.1; Burp Professional 2024.1.1.1.
- Burp Extensions → Installed → Details identifies
  `D:\Projects\MCP\build\dev-v1.5.0\libs\burp-mcp-all.jar`.
- That JAR's manifest and authenticated MCP initialize identify
  `1.5.0-dev.2+20261102.2-target-live-session-dev`. Before rebuilding, the JAR's
  BuildInfo and KtorServerManager classes matched existing compiled output.
- Loaded-path JAR SHA-256:
  `d407ffc069e72d8f1172bc7394e4d624967e10fb79977e8367c31f7e20319f6d`.
- CLI 0.167.0 resolves the enabled `burp` registration to Streamable HTTP,
  `http://127.0.0.1:9876/mcp`, `bearer_token_env_var = "BURP_MCP_TOKEN"`,
  with no extra HTTP headers. No `.codex/config.toml` exists in the project
  or its ancestors. User configuration was not modified.

## Independent causes

**401:** The agent's inherited environment token differed from the running
extension's masked Copy value. Only the comparison result was emitted. The
inherited token returned 401 both with and without an approved Origin. The
current extension token returned valid initialize results with HTTP 200 in both
cases. No bearer parser defect was found: the scheme is case-insensitive, the
supplied value is trimmed, and UTF-8 token bytes are compared using
`MessageDigest.isEqual`.

`McpConfig` reads `bearerToken` from `api.persistence().extensionData()` and
generates/persists 32 random bytes encoded as unpadded URL-safe Base64 only if
the stored value is blank. It never reads the client's environment variable.
Normal server restarts do not rotate it. Loss of extension storage or a new
temporary project can explain token replacement; the historical replacement
event was not established.

**403:** The exact log is emitted by the User-Agent browser heuristic, which
matches `mozilla/`, `chrome/`, `safari/`, `webkit/`, `gecko/`, `firefox/`,
`edge/`, `opera/` or `browser`. Origin is not globally required for native
clients. The old `else if` lacked an `origin == null` guard, so it also rejected
an approved Origin when the User-Agent matched. Both browser-like requests
reproduced HTTP 403 with the current valid token. The precise historical
User-Agent and token changes between the user's earlier requests are unknown.

**Codex 0 tools:** A controlled fresh `codex --no-daemon` process using the
current token reported `burp: connected (89 tools)` through the unchanged
registration. A normal `codex` process launched with the same current token
still reported `burp: failed (0 tools)`; its warning explicitly reported 401 on
initialize. This isolates a shared-daemon credential/environment difference;
the daemon's actual environment was not read. The verified workaround is
`codex --no-daemon`. No daemon restart was attempted during active work.

## Minimal correction and validation

`KtorServerManager` now checks `origin == null` before rejecting a browser-like
User-Agent as missing Origin. Native originless behavior, bearer authentication,
Host, Referer, CORS and bind configuration are unchanged. CORS can reject an
explicit origin before the call interceptor; within that interceptor,
authentication precedes Origin/Host/Referer checks. No proxy or SSE-to-stdio
wrapper is used by the registered HTTP connection.

The approved-browser-Origin regression failed before the correction (1 test,
1 failure). After the correction, the final focused run passed 9 tests with
0 failures: five connection-security integration tests, one persisted-token
secure-default test, and three build-identity tests. The integration tests use
a real embedded loopback HTTP server and mocked Montoya services; they are
regression evidence, not proof that the replacement JAR is loaded in Burp.

Coverage includes valid native originless initialize and tools/list (89 unique
tools), both approved localhost origins with a browser User-Agent, absent,
wrong and malformed credentials on initialize and tools/list, disallowed
origins, invalid Host/port, retained originless-browser rejection, and malformed
initialize producing JSON-RPC -32602 without a result.

Live checks against the still-loaded dev.2 JAR independently established:

| Check | Actual result |
| --- | --- |
| Current token, native request, no Origin | Initialize HTTP 200, valid JSON-RPC result |
| Current token, approved localhost Origin | Initialize HTTP 200 |
| Current token, tools/list | HTTP 200; 89 unique tools; no nextCursor |
| Missing token, no Origin | HTTP 401 |
| Current token, invalid Origin | HTTP 403 |
| Current token, invalid Host | HTTP 403 |
| Current token, browser User-Agent, approved Origin, old JAR | HTTP 403, confirmed branch defect |
| Codex --no-daemon with current token | Connected, 89 tools |
| Normal Codex with current token and existing daemon | Failed, 0 tools; initialize HTTP 401 |

## Initial replacement artifact and handoff

Replacement identity: `1.5.0-dev.3+20261106.1-connection-origin-dev`.
Artifact: `build/dev-v1.5.0/libs/burp-mcp-1.5.0-dev.3-all.jar`.
SHA-256: `c4f75003f09a209f670808011646c141e4ec108c6d18650cd89c5e563511be51`.

The focused compilation/test pass ran with `-PdevelopmentBuild=true -x shadowJar`.
The final package/identity pass used the following temporary Gradle init script
at `build/dev-v1.5.0/connection-origin.init.gradle` to avoid overwriting the JAR
currently loaded in Burp:

```groovy
allprojects {
    afterEvaluate {
        tasks.named('shadowJar') {
            archiveFileName.set('burp-mcp-1.5.0-dev.3-all.jar')
        }
    }
}
```

```powershell
.\gradlew.bat -PdevelopmentBuild=true -I build/dev-v1.5.0/connection-origin.init.gradle test --tests '*McpServerIntegrationTest.connection security*' --tests '*McpConfigTest.secure defaults*' --tests '*BuildInfoTest'
```

In Burp **Extensions → Installed**, manually unload the current Burp MCP
extension and add the replacement Java JAR. Preserve project data and security
settings. Keep **Require bearer token** checked and bind host `127.0.0.1`.
Copy the token from the reloaded extension's **Burp MCP → Security** panel and
use the secure prompt in `CODEX_SETUP.md`, launching `codex --no-daemon`.
Use `/mcp` and confirm 89 tools. Replacement-JAR runtime verification remains
pending until this manual reload. Do not run Milestone 3 traffic checks.

No application requests, traffic inspection tools, intercepted-message edits,
authorization grants, allowlist changes or Emergency Stop changes were made.
Bearer tokens and raw Authorization headers were never printed or stored in
repository files. Stable v1.4.0 artifacts and the loaded-path dev.2 JAR were
not modified. No security settings or Codex registration were changed.

## Finalization follow-up: current verified state

This section supersedes the initial pending reload and uninspected daemon
statements above. Branch and HEAD remain `dev/v1.5.0` and
`fd0d1418fab90039f1eb08cea87fe3b1102c0af7`. This follow-up began with five
tracked modifications and this untracked document already present. Existing
work was preserved; no commit or push was made.

### Loaded development build

Both authenticated `burp_get_status` and MCP initialize now identify
`1.5.0-dev.3 / 20261106.1-connection-origin-dev`. Reload is verified; no further
JAR replacement is required. The versioned replacement artifact retains the
SHA-256 recorded above. Runtime identity does not independently attest its
loaded filesystem path or byte-for-byte JAR identity. No JAR was rebuilt.

The listener is exclusively `127.0.0.1:9876`, owned by Burp Java PID 2976.
Status reports mandatory bearer authentication, zero authorized targets and
read-only mode **false**. This existing mode was left unchanged. No write or
traffic tool was called. Direct tools/list returned 89 unique tools, no
nextCursor and no JSON-RPC error.

### Shared daemon: directly verified credential mismatch

Installed CLI/server version is 0.167.0. `codex app-server daemon version`
reports a running PID-managed local server. Windows process inventory identifies
PID 7192 as the managed `codex.exe app-server --listen unix://
--analytics-default-enabled --managed-daemon`, started at 12:57:33 local time.
PID 12980 runs its daemon PID update loop. Both belong to `Sangam\Sangam` and
have parent PID 22088. PID 23772 is an independent `--no-daemon --yolo` client.
These processes were not stopped or restarted.

Read-only inspection of PID 7192's Windows environment established that its
`BURP_MCP_TOKEN` exists and differs from this follow-up's launch environment.
Only presence/equality booleans were emitted. The daemon credential was used
in memory for a loopback MCP initialize check and returned HTTP 401. The launch
credential returned HTTP 200 with the exact dev.3 server identity. No token,
environment dump, raw Authorization header or token hash was emitted or saved.

A fresh interactive `codex --yolo --no-alt-screen` attached to the existing
daemon. `/mcp` reported `burp: failed (0 tools)` while all other enabled servers
connected. `/warnings` explicitly reported HTTP 401 on initialize. The
display-only no-alt-screen option does not bypass the daemon. No model prompt
or task was submitted in this diagnostic CLI.

Effective `codex mcp get burp --json` and parsed user configuration agree:
Streamable HTTP, `http://127.0.0.1:9876/mcp`, environment credential name
`BURP_MCP_TOKEN`, no static or environment HTTP header overrides, no profiles
and no daemon feature overrides. No project or ancestor `.codex/config.toml`
exists. User configuration and environment settings were not modified.

**Confirmed cause:** the persistent daemon retains a rejected startup credential
while the launch shell has a valid credential. Starting another normal CLI does
not refresh that credential in this installation. The historical event that
made it stale remains unknown. A separate MCP cache or application defect is
not demonstrated or needed to explain the failure. No supported in-place
environment refresh was established from installed help or consulted docs.

### Current security checks and focused tests

These checks contacted only the local MCP control endpoint. Invalid Origin/Host
strings were header values, not traffic destinations.

| Runtime dev.3 check | Result |
| --- | --- |
| Valid launch credential, native initialize | 200, valid result and exact dev.3 identity |
| Valid credential, tools/list | 200, 89 unique tools |
| Missing / incorrect credential | 401 / 401 |
| Invalid / null Origin | 403 / 403 |
| Invalid Host / loopback Host with wrong port | 403 / 403 |
| Browser User-Agent, approved 127.0.0.1 / localhost Origin | 200 / 200, valid initialize results |
| Browser User-Agent without Origin | 403 |
| Daemon startup credential | 401 |
| Normal shared-daemon CLI /mcp | Failed, 0 Burp tools |

Fresh focused test execution used the command above with `-x shadowJar
--rerun-tasks` appended: **9 passed, 0 failed**, BUILD SUCCESSFUL. Manifest and
packaged-class tests used the existing versioned development artifact. No full
suite or packaging task ran. Stable release outputs were not changed.

The only production behavior change remains the existing missing-Origin guard.
Bearer, Host, loopback binding, native approvals, target authorization, expiry,
Emergency Stop and the fixed localhost allowlist were not edited or reconfigured.
Source/diff review and focused regressions support preservation; no live
authorization, expiry or Emergency Stop exercise was performed.

### Manual completion required: normal-mode success pending

Once this report and all other active or queued Codex work are finished, exit
the clients and open a regular PowerShell window. Populate the current Burp
token using the secure prompt in CODEX_SETUP.md, then run from that same window:

```powershell
cd D:\Projects\MCP
codex app-server daemon restart
codex app-server daemon version
codex --yolo
```

Run `/mcp` and report whether it says `burp: connected (89 tools)`. A restarted
process alone is not proof of MCP success. Installed CLI help confirms restart;
[official server management](https://learn.chatgpt.com/docs/developer-commands)
documents `/daemon` restart and warns of interruption to active or queued work.
[Official daemon guidance](https://learn.chatgpt.com/docs/environments/network-file-systems)
describes persistence between sessions and the single-launch bypass.

No shared daemon or existing user session was stopped. Normal-mode recovery is
pending manual restart and verification. The previously verified temporary
workaround remains `codex --no-daemon --yolo` from the current-token shell.
No Kotlin or configuration adjustment is justified for this credential-lifetime
problem. Milestone 3 remains on hold pending normal-mode verification and an
explicit supervised testing instruction. No application traffic was sent.
