# Burp Suite MCP Server Extension — 1.0.0-custom

## Overview

Local customization of PortSwigger's Burp MCP extension for authorized
assessments. The stable package preserves the verified Windows JAR with
SHA-256 `98077D3013783F5846376B2A297585B4EC12B34EF6DF6D8BDE2DAB9117AC0799`.
`1.0.0-custom` labels this release package. The unchanged JAR retains
the internal build version `1.4.0`.

The running extension exposed 42 MCP tools in Community Edition. The final
source passed 163 tests each on Windows and Ubuntu WSL. Live loopback testing
covered HTTP/1.1 and TLS HTTP/2 response rewriting, global request parameters,
typed JSON, combined rewriting, local approval outcomes, and Emergency
Disable. The [verification report](docs/localhost-verification-report.md)
identifies the specific artifact used for each run. The build evidence is
local Windows and Ubuntu WSL evidence.

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Serves both Streamable HTTP (`/mcp`) and legacy SSE (`/`) transports
- Comes with packaged Stdio MCP proxy server

## Quick start

1. Extract the release ZIP and verify `burp-mcp-all.jar` against
   `SHA256SUMS.txt`. In Burp, choose **Extensions → Installed → Add → Java**
   and load that JAR. If upgrading, keep a single loaded MCP extension.
2. In Burp's **MCP** tab, enable the server on loopback. Connect Codex
   using Streamable HTTP at `http://127.0.0.1:9876/mcp`. The separate
   Burp Proxy listener is normally `127.0.0.1:8080`.
3. Before rewriting, configure **Target Scope** and save exact hostnames in
   **MCP Rewrite**. Approve each rule and its direction's master switch
   locally in Burp. Both masters start OFF. Use **EMERGENCY DISABLE** to
   turn both directions OFF.

See the [beginner's guide](docs/usage-guide.md) for setup, copy-paste Codex
instructions, and localhost examples.

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the customized source

Use the checkout or the `source` directory from the release's `source.zip`.
The source snapshot includes the Gradle wrapper and the original bundled
proxy input. With JDK 21 available, run `./gradlew test embedProxyJar`
on Linux or the Windows command below. The build writes
`build/libs/burp-mcp-all.jar`. Independent builds can have different hashes
because the JAR records build metadata.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

On Windows, build from PowerShell in the project directory with Java 21 on
your PATH:

```powershell
.\gradlew.bat test embedProxyJar
```

In Burp Community Edition, open **Extensions → Installed → Add**, select
**Java**, and select `build\libs\burp-mcp-all.jar`. Open the **MCP** tab and
enable the server. The default endpoint for Codex is
`http://127.0.0.1:9876/mcp`; the proxy listener is a separate Burp setting,
normally `127.0.0.1:8080`.

## Configuration

### Live JSON request rewriting

The `MCP Rewrite` Burp tab manages rules for requests passing through Burp Proxy.
Rewriting starts **off on every extension load**. Add exact hostnames (one per
line, without ports or wildcards) to its manual allowlist, configure Burp's
target scope, and approve the session switch in that tab. Both the allowlist
and Burp scope must match each request. Changing the allowlist turns the switch
off; the emergency button turns it off immediately. This switch and the
allowlist cannot be changed by MCP tools.

Codex can translate an instruction such as “for POST /api on example.test,
set /user/name to Alice” into `create_rewrite_rule`, using `"Alice"` as the
JSON literal and `application/json` as the media type. Rules match exact host,
method, path without query, and JSON media type. Field paths are RFC 6901 JSON
Pointers (for example `/items/0/name`, with `~1` for `/` and `~0` for `~`).
Only an existing field or array element is replaced; rules run in their listed
order. `update_rewrite_rule` replaces the configuration and disables the rule.
`enable_rewrite_rule` asks for approval in Burp; the user may also approve or
manage rules in the panel. `list_rewrite_rules`, `disable_rewrite_rule`, and
`remove_rewrite_rule` provide the remaining MCP operations. Rule approvals and
rules persist, but the master switch does not.

For a global typed JSON request rule, pass `fieldName` and `replacementJson`,
leaving `hostname`, `method`, `path`, `contentType`, and `jsonPointer` empty or
omitted. The exact case-sensitive field name matches throughout nested objects
and arrays on allowlisted, in-scope hosts. Alternatively provide `jsonPointer`
instead of `fieldName` for a precise JSON location. Optional nonempty filters
remain exact. Global field replacements must be JSON scalar literals. For
query, form, JSON string, and multipart parameters, use the existing global
parameter rule; no method or path is required.

The extension supports uncompressed UTF-8 JSON bodies up to 1 MiB and skips
requests with unsupported encodings, transfer encoding, ambiguous headers,
invalid JSON, or duplicate object keys. It preserves unrelated JSON bytes and
updates an existing Content-Length using the UTF-8 byte count. Rules only affect
Proxy requests; other Burp tools are not rewritten. A request already being
processed may complete as the switch is disabled. Rule replacement values are
stored in Burp extension persistence and displayed to the local user for
approval; avoid putting credentials in rule values. MCP rule lists and recent
event logs omit replacement values and request data.

### Global parameter rewriting

The same controls also govern `Global Parameter Rules` in the MCP Rewrite tab.
`create_global_parameter_rule` accepts `parameterName`, `replacementValue`, and
an optional `locations` array containing `query`, `json`, `form`, or `multipart`;
omitting it selects all four. Creation and updates leave the rule disabled.
Each rule must be approved locally before enabling; the session master switch
must also be approved locally. The list, update, enable, disable, and remove MCP
tools use the corresponding `*_global_parameter_rule[s]` names. Matches are
case-sensitive and apply to every path and method on exact allowlisted hosts
that are also in Burp Target Scope. Rules run locally in Proxy, without further
model calls. Cookies, authorization headers, and file parts are not rewritten.

For overlapping global rules, the earliest created enabled rule wins for each
parameter name and location. Existing exact JSON Pointer rules run first; a
global rule can then replace the same JSON value. JSON replacements are strings,
even when the original scalar had another type. JSON containers are not
replaced. Repeated query, form, and multipart text field names are all changed;
JSON with duplicate object keys is rejected. Malformed, encoded, oversized, or
otherwise unsupported requests pass through unchanged, with a redacted event.
Multipart support is limited to safely parsed conventional CRLF-framed UTF-8
text fields; requests containing a file part pass through unchanged. Rule values are
persisted in Burp extension storage and shown locally during approval, so treat
that storage as sensitive. MCP tool replies and rewrite event logs do not
include values or request contents.

The Overview tab lists request and response rules, their field or parameter,
replacement type, scope of matching, enabled state, and session match activity.
Counts and last-match times reset when the extension reloads. A request rule
matching multiple parameter locations can count once for each location. To
locate a rule without exposing stored values, `list_global_parameter_rules`
accepts an optional exact `parameterName`, and `list_response_rewrite_rules`
accepts an optional exact `fieldName`; replies still contain only IDs and
enabled states. Use the returned ID with the corresponding disable tool.

Common credential parameter names are excluded from global parameter rules.
JSON request and response bodies containing common credential field names pass
through unchanged. This name-based guard is conservative and cannot recognize
every application-specific secret; review scope and rules accordingly.

### Automatic response rewriting

`Response Rewrite Rules` operates on responses going to the Proxy client. It has
its own locally approved session switch, initially off on every extension load.
The same exact host allowlist and Burp Target Scope both apply. Changing the
allowlist or pressing Emergency Disable turns off both session switches. Rules
persist, but every new or edited rule is disabled and requires local approval.

`create_response_rewrite_rule` accepts `mode` (`json_field`, `json_pointer`, or
`text`), `match`, and `replacement`. For JSON modes the replacement is a JSON
scalar literal such as `true`, `123`, `null`, or `"hello"`; text mode uses
literal strings and is approved separately. Optional exact filters are
`hostname`, `method`, `path`, `status` (zero means any), and `contentType`.
Empty filters match any supported value. The five companion MCP tools list,
update, enable, disable, and remove rules. Lists and events omit values and
response contents. Earlier rules win overlapping matches against the original
body; text replacements do not cascade. Values are stored in extension data.

Existing response rules apply to complete HTTP/1 and HTTP/2 responses with
UTF-8 JSON, `text/plain`, or `text/html` bodies up to 1 MiB. HTTP/1 requires
a single valid Content-Length. For HTTP/2, a present Content-Length must match
the body size and is updated to the replacement's byte length. An absent
Content-Length stays absent. Burp manages HTTP/2 framing.

Responses still marked as compressed or chunked at the extension callback,
along with streaming media such as `text/event-stream`, partial, downloaded,
conditional, validator-bearing, malformed, and unsupported responses, pass
through. Montoya exposes Burp's processed response. It does not expose raw
HTTP/2 DATA frames, END_STREAM, or the original position of trailer fields.
Known digest headers are skipped when visible after processing. Buffered,
complete JSON or text can still be eligible even if the origin wrote the
body incrementally. The existing HTTP/1 chunked-origin limitation is described
in the localhost verification report.
Burp Proxy can unpack compressed origin responses before the extension sees
them. To prevent decoded responses being mistaken for uncompressed origin
responses, disable Burp Proxy's **Unpack compressed responses** option before
enabling response rewriting. The extension checks this project option before
activation and again when an eligible response arrives. If it is enabled or
unavailable, response rewriting remains off or is switched off; the request
rewriting switch is independent. The extension does not change this setting.
Modified responses receive `Cache-Control: no-store`; conditional responses
and existing validator-bearing responses are not modified. Existing browser
caches may therefore need clearing before testing. Security headers are not
removed or changed. No regular expressions or scripts are executed.

### Local fixture and troubleshooting

The repository includes a loopback-only test server. From PowerShell in the
project directory, start it in a terminal and leave that terminal running:

```powershell
python -u tools/rewrite_test_server.py
```

In Burp Target Scope, include `http://127.0.0.1:18080/`. In **MCP Rewrite**,
save `127.0.0.1` as an exact hostname on its own line. Create and locally
approve a test rule, then approve the relevant request or response session
switch. For example, a global response field rule uses `json_field` as its
mode, `isPremium` as the match, and `true` as a JSON boolean replacement.

To send the provided fixture request through Burp from another PowerShell
window, use:

```powershell
curl.exe --noproxy= --proxy=http://127.0.0.1:8080 http://127.0.0.1:18080/response-test
```

The original fixture contains `isPremium:false`. A successfully approved
response rule changes matching values to `true` in the client response. The
Overview and Recent events show matching rule IDs without response bodies or
replacement values. Use **EMERGENCY DISABLE** to turn off both directions.

If a rule does not match, check both master-switch labels and the rule's
enabled state, exact host, Target Scope, method, path and content-type filters.
Saving the allowlist or reloading the extension turns both session switches
off. Check that Proxy interception is forwarded or disabled, and inspect the
sanitized recent events for a skip reason. The localhost fixture is stopped with
Ctrl+C in its terminal. For the separate TLS HTTP/2 fixture and ALPN probe, see
[the localhost verification report](docs/localhost-verification-report.md).

### Known limitations

- Rewriting applies to supported Burp Proxy traffic. MCP's direct HTTP send
  tools and other Burp tools are separate. In-flight work can complete when
  a master is disabled. Rules and local approvals persist across reloads,
  and both masters start OFF.
- Compressed responses pass through when content encoding is visible. Burp's
  **Unpack compressed responses** option must be off to arm response rewriting.
- Burp can remove HTTP/1 chunked framing before either Montoya response
  callback observes it. The verification report records a chunked-origin
  response that was rewritten after normalization. The extension cannot
  reliably identify all chunked-origin responses.
- Eligible response bodies are complete UTF-8 JSON or compatible plain
  text or HTML up to 1 MiB. Unsupported charsets and media types, binary data,
  downloads, malformed JSON, partial or conditional responses, visible
  validators, and event streams pass through. Buffered JSON or text can be
  eligible regardless of the origin's write boundaries. Montoya supplies
  processed HTTP/2 responses without raw frame completion or trailer placement.

The MCP WebSocket history tools can display non-ASCII text incorrectly. For
example, a UTF-8 text frame containing `café` was reported as `cafÃ©` in a
localhost test. The history API used by this extension does not identify
whether a payload is a text or binary frame, so the extension retains Burp's
original payload representation rather than guessing an encoding for binary
data. Inspect the frame bytes in Burp when exact WebSocket content matters;
the WebSocket history output is not a reliable Unicode text rendering.

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, it listens on `http://127.0.0.1:9876`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. Currently, Claude Desktop only support STDIO MCP Servers
   for the service it needs.
   This approach isn't ideal for desktop apps like Burp, so instead, Claude will start a proxy server that points to the
   Burp instance,  
   which hosts a web server at a known port (`localhost:9876`).

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

### Codex

Use **Settings → MCP servers → Add server** in the desktop app. Choose
**Streamable HTTP**, enter `http://127.0.0.1:9876/mcp`, and restart as
prompted. Codex connects directly to the extension. For manual configuration,
use the following entry in `~/.codex/config.toml`:

```toml
[mcp_servers.burp]
url = "http://127.0.0.1:9876/mcp"
```

The equivalent Codex CLI commands are:

```bash
codex mcp add burp --url http://127.0.0.1:9876/mcp
codex mcp list
```

Rule approval takes place in Burp. The MCP tab controls separate permissions
for direct sends and project data access. See the [official Codex MCP setup](https://developers.openai.com/codex/mcp).

## License

The extension is based on PortSwigger's GPL-3.0 project. The release includes
the upstream [license text](LICENSE), the customized source snapshot, and
license and provenance notices for the package.

## Manual installations
If you want to install the MCP server manually you can either use the extension's SSE server directly or the packaged
Stdio proxy server.

### Streamable HTTP MCP Server
Clients that support the Streamable HTTP transport (e.g. Codex) can use the `/mcp` path on the configured server URL:
```
http://127.0.0.1:9876/mcp
```

### SSE MCP Server
To use the legacy SSE server directly, provide the configured server URL to your MCP client:
```
http://127.0.0.1:9876
```

### Stdio MCP Proxy Server
The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy)

In order to support MCP Clients which only support Stdio MCP Servers, the extension comes packaged with a proxy server for
passing requests to the SSE MCP server extension.

If you want to use the Stdio proxy server you can use the extension's installer option to extract the proxy server jar.
Once you have the jar you can add the following command and args to your client configuration:
```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

If you modify the proxy source, rebuild and copy it into this project before packaging the extension:
```bash
# From mcp-proxy
./gradlew shadowJar
cp build/libs/mcp-proxy-all.jar /path/to/mcp-server/libs/mcp-proxy-all.jar

# From mcp-server
./gradlew embedProxyJar
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string or a `List<ContentBlock>` to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.
