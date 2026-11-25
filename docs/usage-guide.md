# Burp MCP 1.0.0-custom usage guide

This is a local, customized build of PortSwigger's Burp MCP extension. The
examples use bundled synthetic fixtures on your own machine. Use the extension
only on systems and traffic you are authorized to assess.

## 1. Install the extension

1. Extract the release ZIP into a dedicated folder. Check the JAR against
   `SHA256SUMS.txt` before loading it. In PowerShell, run
   `Get-FileHash -Algorithm SHA256 .\burp-mcp-all.jar`.
2. In Burp, select **Extensions → Installed → Add → Java**, choose
   `burp-mcp-all.jar`, and finish the dialog. If replacing this customization,
   use its existing extension entry and reload the JAR from the stable path.
   Keep only one MCP extension loaded so it can own the listening port.
3. Open **MCP** and enable its server on loopback. The default MCP endpoint is
   `http://127.0.0.1:9876/mcp`. The usual **Burp Proxy** address is
   `127.0.0.1:8080`. Check each in its own panel.
4. Open **MCP Rewrite**. Request and Response start OFF. The master switches
   are independent of the MCP server and of each individual rule.

## 2. Connect Codex

In the desktop app, open **Settings → MCP servers → Add server**, name the server
`burp`, choose **Streamable HTTP**, and enter `http://127.0.0.1:9876/mcp`.
Save and restart as prompted. If the server is already configured, verify its
URL in the existing entry.

Alternatively, in a local shell with the Codex CLI installed:

```text
codex mcp add burp --url http://127.0.0.1:9876/mcp
codex mcp list
```

In a new Codex chat, ask it to list the Burp rewrite rules without changing
them. The rewrite tools should be visible, and this test needs no Proxy
traffic. Prompts in Burp are separate from any Codex tool permissions.
[Official Codex MCP setup](https://developers.openai.com/codex/mcp)

## 3. Configure the localhost scope and allowlist

1. Extract `source.zip` and open a shell in the extracted `source` directory.
   Run `python -u tools/rewrite_test_server.py` and leave that terminal open.
   The fixture listens on `127.0.0.1:18080`.
2. In **Burp → Target → Scope**, add `http://127.0.0.1:18080/` under
   **Include in scope**. To run the separate TLS fixture described in the
   verification report, use the corresponding `https://` scope entry.
3. In **MCP Rewrite**, add the exact hostname `127.0.0.1` as its own line in
   the manual allowlist and choose **Save allowlist**. Omit the scheme, port,
   path, and wildcards. `localhost` and `127.0.0.1` are distinct hostnames for
   this check. Saving the allowlist turns both masters OFF.
4. For response rewriting, locally disable **Unpack compressed responses**
   under **Burp Settings → Tools → Proxy → Miscellaneous**. The extension
   checks the setting and leaves response rewriting OFF if it cannot confirm
   that unpacking is disabled.

Every eligible Proxy request must match both the exact-host allowlist and
Target Scope before either direction can rewrite. For the fixture examples,
keep the armed scope and allowlist limited to the fixture. A global parameter
rule applies to every host that passes both checks.

## 4. Create rules with Codex

Paste one instruction at a time. Each creates a disabled rule. A global rule
works across compatible paths and methods once approved and armed. Use an
exact path filter when only one fixture endpoint should match.

**Global request parameter.** The replacement is a string. Supported
locations are query, form, JSON string replacement, and multipart text. Use
the dedicated typed JSON rule if the replacement must be a JSON boolean or
number.

> For the 127.0.0.1:18080 fixture, create a disabled global request parameter
> rule for demo_label. Replace it with reviewed in the query and form. Match
> all paths and methods within the existing scope and allowlist. Leave the
> masters off and show the rule ID.

**Typed JSON request.** The exact field name can recur in objects and arrays.

> Create a disabled JSON request rule for host 127.0.0.1. Replace the
> exact field demo_ready wherever it occurs in JSON with the boolean true.
> Leave path and method unspecified and return the rule ID.

**Global JSON response.** This field rule works across compatible responses,
including fields in arrays.

> Create a disabled global JSON response rule for 127.0.0.1. On the
> fixture only, replace the exact field coverage_null with the JSON value
> null wherever the field occurs. Leave method and path unspecified and
> return the rule ID.

**JSON Pointer response.** A pointer targets one existing location. For
example, `/items/0/label` addresses a field in the first array item. Use
`~1` for a literal slash within a key and `~0` for a tilde.

> Create a disabled JSON Pointer response rule for GET /coverage-json on
> 127.0.0.1. Replace /nested/0/coverage_string with the JSON string "reviewed".
> Leave other fields alone and return the rule ID.

**Literal text response.** This mode matches the given text exactly and
supports compatible `text/plain` and `text/html` bodies.

> Create a disabled literal-text response rule for GET /response-text on
> 127.0.0.1. Replace only "Fixture status: original." with "Fixture status:
> reviewed." in text/plain, and return the rule ID.

Choose the replacement type deliberately. The JSON literals `true`, `42`,
`null`, and `"reviewed"` mean boolean, number, null, and string,
respectively. `"true"` is a string. Global JSON field matching is exact and
case-sensitive. The rule replaces existing values.

## 5. Approve, verify, and stop

1. Ask Codex to request local approval for one rule ID, or select the rule and
   choose **Enable rule** in Burp. Review the match, replacement, and filters
   in the local dialog before approving. Deny or close the prompt to leave
   the disabled rule off.
2. In **MCP Rewrite**, choose **Enable rewriting** for requests or **Enable
   response rewriting** for responses, then approve the corresponding
   confirmation. Enable only the directions you intend to test.
3. Send a fixture request through Burp Proxy. The command below uses the usual
   listener on port 8080. In PowerShell:

```powershell
curl.exe --noproxy= --proxy=http://127.0.0.1:8080 "http://127.0.0.1:18080/global-a?demo_label=old&keep=original"
curl.exe --noproxy= --proxy=http://127.0.0.1:8080 "http://127.0.0.1:18080/coverage-json"
curl.exe --noproxy= --proxy=http://127.0.0.1:8080 "http://127.0.0.1:18080/response-text"
```

4. Compare the fixture echo or response against the original. The first
   endpoint echoes the query in `request.path`. The second contains
   `coverage_null` and the JSON Pointer target. The third contains the
   literal status line.
5. Open **Overview** to see match count and last match time. **Recent events**
   displays rule IDs and sanitized results. Counters reset on extension reload.
6. Click **EMERGENCY DISABLE** to stop both directions for subsequent traffic.
   Confirm Request and Response both show OFF. The individual rules stay saved
   with their existing enabled states.

**Rule maintenance prompts**

> List the rewrite rule IDs and enabled states. Leave the rules and masters as they are.

> Update rule ID <paste-ID> to use "archived" as a JSON string. Preserve its existing match and filters. Show me the disabled rule before I request approval again.

> Disable rule ID <paste-ID>. Leave the other rules and master switches alone.

> Remove only my temporary fixture rule with ID <paste-ID>.

Use the actual ID and identify the rule family if several IDs are in view.
A material edit disables the rule pending local approval. Use **Disable rule**
when you might need the rule again. Removal deletes the saved rule.

## Troubleshooting and limits

| Symptom | Check |
|---|---|
| Codex cannot see the tools | Confirm the extension is loaded and MCP is enabled on the configured loopback port. The Streamable HTTP URL ends in `/mcp`. |
| Approval call waits | Look for a modal in Burp. Respond locally before the client times out. A cancelled call should close the modal and grant no approval. |
| Rule is enabled but has zero matches | Confirm its direction is ACTIVE, the traffic uses Proxy, and the URL and exact hostname pass both scope checks. Check path, method, status, type, and field spelling. Proxy interception can hold a request before the fixture receives it. |
| Response master stays OFF | Confirm Proxy's **Unpack compressed responses** setting is disabled and visible to the extension. Reapprove the switch locally after saving the setting. |
| Output remains original | Check the sanitized event log. Unsupported encodings, charsets, content types, malformed JSON, and framing can force pass-through. An earlier matching rule can also take precedence. |

The tested response path supports complete UTF-8 JSON and compatible text
bodies up to 1 MiB. Visible compression, transfer encoding, partial or
conditional responses, download metadata, validators, and event streams
are guarded. Burp may normalize HTTP/1 chunked-origin framing before Montoya
sees it, so some chunked-origin bodies can still be rewritten. Montoya also
exposes processed HTTP/2 responses without raw frame completion or original
trailer boundaries. Complete buffered JSON or text can remain eligible.
The two WebSocket history tools can misrender Unicode and can miss Unicode
regex matches. Read the [full limitations in the README](../README.md#known-limitations)
and the [verification report](localhost-verification-report.md) for the actual
observations by artifact.
