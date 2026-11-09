# Codex connection and verification

For complete build/load/rule/cleanup instructions, read [agent setup](AGENT_SETUP.md).
[Development status](DEVELOPMENT_STATUS.md) is authoritative for current evidence.
Current checkpoint: dev.6, build `20261107.3-scanner-permission-hardening-dev`.
Authenticated connectivity and 89 unique tools passed. The last negative-only
Scanner call returned denial with no Scanner data; native dialog category and
human DENY selection remain unconfirmed. No retry or further data access is implied.

## Configure the client without storing a token

Burp exposes Streamable HTTP at `http://127.0.0.1:9876/mcp`. Keep loopback binding
and bearer authentication enabled. Merge this table into
`%USERPROFILE%\.codex\config.toml`; update an existing table instead of duplicating it:

```toml
[mcp_servers.burp]
url = "http://127.0.0.1:9876/mcp"
bearer_token_env_var = "BURP_MCP_TOKEN"
```

The environment-backed HTTP setting and `/mcp` status command are documented in the
[official OpenAI MCP guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
The token value belongs only in the local process environment or a suitable local
secret mechanism. Do not put it in this repository, TOML literal headers, command
arguments, reports or chat. The extension reads its token from Burp extension data,
not from the client's environment variable.

The human copies the current token locally from Burp MCP > Security and enters it
in a fresh PowerShell session using a masked prompt:

```powershell
Set-Location D:\Projects\MCP
$env:BURP_MCP_TOKEN = [System.Net.NetworkCredential]::new(
    '', (Read-Host 'Current Burp MCP token' -AsSecureString)
).Password
codex
```

Use the actual clone root if different. No approval-bypass CLI option is required.
In the client use `/mcp`; then safe status tools must report the expected running
version/build. Tool catalog registration alone does not prove the connection.
After use, run `Remove-Item Env:BURP_MCP_TOKEN` in the shell.

## Diagnose an authentication failure

HTTP 401 means Burp rejected the supplied credential. Confirm intended project,
Running endpoint, local token and variable name. A new Temporary Project or lost
extension data can generate another token; a normal server restart does not
necessarily rotate it. Do not rotate a working token or turn authentication off.
Existing processes retain their inherited environment after a user-variable change.

A historical dev.3 investigation established a shared-daemon/launch-environment
credential mismatch; it does not prove every future 401 has that cause. First
check local CLI help and `codex app-server daemon version`. If the current-token
launch works directly but the shared client does not, a separate `codex --no-daemon`
launch from that same environment can isolate the issue. Do not restart the daemon
without demonstrated need and coordination with all active sessions. When all
work has stopped and the operator has agreed, the locally supported recovery is
`codex app-server daemon restart` from the current-token shell, then reconnect.
No daemon restart was performed for this checkpoint.

HTTP 403 can indicate Host/Origin/Referer policy rejection. Browser-like clients
must supply a legitimately approved Origin. Do not fabricate headers to evade
policy or change server security settings as a credential fix. The dev.3 approved-
Origin correction is included in dev.6. Historical detail remains in Git history
and the local runtime reports indexed by DEVELOPMENT_STATUS.

## Replace the development JAR safely

Use only the isolated development build command in AGENT_SETUP. Do not use
`build.ps1` or overwrite `build\libs` in the rollback workspace. Preserve the
existing matching JAR before any same-version rebuild. Human replacement requires
safe empty state, unloading the old instance, loading the intended versioned JAR,
then checking actual path/hash/manifest/running identity and authenticated discovery.
No filename-only inference or permission reset is acceptable.

## Verify without application traffic

Use the administrative status tools listed in AGENT_SETUP and the dedicated
`python -B scripts/live_rule_engine_coordinator.py --target-preflight-only` command.
Observe native Proxy Intercept and project identity separately. Protected history,
Scanner and Organizer data are not administrative status checks and may need native
approval. Do not call them to debug authentication. Test plans and old approvals
never authorize a send, scan, grant, session or unattended activation.
