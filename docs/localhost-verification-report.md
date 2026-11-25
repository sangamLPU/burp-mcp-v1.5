# Burp MCP extension verification record

**Current candidate after the HTTP-tool UTF-8 fix:** the Windows JAR is
`build/libs/burp-mcp-all.jar`, 33,240,559 bytes, SHA-256
`3CC6241E8C51908A4CC4FCCD33DF2DB24EB0B70FF09FD5DE0CFD2885A2EC06E5`.
Clean Windows and Ubuntu builds each passed 155 tests with zero failures,
errors, or skips, and embedded the proxy JAR. The same Burp project loaded
this candidate with one request handler and one response handler; both master
switches are OFF and the five saved rules remain enabled. Live localhost
HTTP/1.1 and TLS HTTP/2 MCP requests both returned UTF-8 `café` correctly.
Active combined rewriting, gzip pass-through, and Emergency Disable were
subsequently verified on `3CC624…` as recorded below. The chunked-origin safeguard remains unresolved.


This is an evidence record, not a release approval. No GitHub publication has
been authorized. Review the partial and untested items before deploying.

The earlier guarded artifact `9CC223…` passed live
rewriting and compression checks, but subsequently deadlocked. The corrected
artifact `94BC415…` has been loaded in the same project. Clean Windows and
Ubuntu builds pass, and the response-only workload that previously deadlocked
now completes with Burp responsive. Combined rewriting, scope, independent
request/response allowlist, and final Emergency Disable passed live.

**Previous artifact:** `DAFB274…` was built after fixing UTF-8 rendering of
textual HTTP history and a JDK executable lookup issue. Both clean Windows and
Ubuntu suites passed 154 tests, and both embedded the proxy JAR. The new JAR
was loaded into the same Burp project with both rewriting switches OFF. The
previously mojibake Organizer response now reports `café` correctly. Active
combined rewriting, request scope/allowlist checks, and Emergency Disable
were subsequently verified on `DAFB274…` as detailed at the end of this
report. Other live results apply to the specifically named earlier artifacts.

**New failure:** The response-only benchmark on artifact `9CC223…` timed out.
A JVM thread dump confirmed a deadlock: the proxy thread held the rewrite
manager monitor while Burp's settings export waited for the Swing event thread,
which was itself waiting for that monitor. A narrowly targeted JVM thread
interrupt recovered the unresponsive Burp window without a restart or project
reset. A source fix moves settings export outside the monitor, with focused
concurrency and emergency-disable regression tests passing. Clean builds and
the affected live workload passed on the corrected artifact.

## Prior artifact DAFB274 and builds

The following entries are historical; the current candidate and totals are
given at the top of this report.

- Windows JAR: `build/libs/burp-mcp-all.jar`, 33,239,921 bytes.
- SHA-256: `DAFB27426A0167F941EBE9E9B22F7890F96905592843CEBCD64C7C190323092F`.
- Clean Windows build, no build cache: **154 tests, 0 failures, 0 errors, 0 skipped**; `embedProxyJar` succeeded.
- Clean Ubuntu/WSL build with bounded workers and heap, no build cache: **154 tests, 0 failures, 0 errors, 0 skipped**; `embedProxyJar` succeeded. The `src` trees matched before the build.
- The Windows artifact contains the request and response handlers, rewrite manager, and `mcp-proxy-all.jar`.
- The new artifact was reloaded into the same Burp Temporary Project; both masters reset to OFF, the allowlist and rule enabled states persisted, and MCP reconnected with 42 tools. Handler registration was checked previously on `94BC415…`.
- Earlier live observations below were made on artifacts `53607E…` and `9CC223…`; neither establishes active behavior of `94BC415…`.

## Feature verification

Statuses below state the result of the explicitly named evidence, including
earlier artifacts. They are not all live results for `3CC624…`. The current
candidate-specific matrix immediately follows this table.

| Feature | Status | Evidence / qualification |
|---|---|---|
| Request query, form, duplicate fields, nested JSON, multipart text | PARTIAL | Query, form, duplicate fields and nested JSON passed live on the corrected artifact; multipart text passed live on an earlier artifact and in current automated tests. |
| Request JSON Pointer, typed scalar, unchanged fields | PASS | Corrected artifact changed `/fixture/count` 7 → 42 on POST while preserving unrelated data. |
| Response JSON field, nested objects and arrays | PASS | Corrected artifact changed root and nested boolean fields and separately rewrote string and null fields inside arrays in live localhost probes. |
| Response JSON Pointer | PASS | Corrected artifact changed `/user/credits` 10 → 42 live, preserving unrelated fields. |
| Literal response text | PASS | Corrected artifact changed the selected text live, preserving surrounding text. |
| Combined requests/responses across methods and paths | PASS | Corrected artifact passed POST `/global-a` and PUT `/global-b`. |
| Live Target Scope enforcement | PASS | Corrected artifact left traffic to allowlisted `127.0.0.1:18081` unchanged in both directions. |
| Independent live allowlist enforcement | PASS | With both hostnames in scope and only `127.0.0.1` allowlisted, global request rewriting affected only the IP. A host-unfiltered response probe changed `other:11` to `99` on the IP and left `localhost` at `11`. |
| Malformed JSON, credential protection, upload protection | PARTIAL | Previous artifact live evidence and current-source automated tests; not all variants independently retested on final artifact. |
| Compression handling | PARTIAL | Corrected artifact passed a gzip response byte-for-byte; mid-session guard was verified live on `9CC223…` and in corrected-source automated tests. |
| Chunked-origin response pass-through | FAIL | The valid HTTP/1.1 origin sent a 118-byte chunked body; with response rewriting active, the client received a modified 132-byte body. Both Proxy response callbacks saw Content-Length and no Transfer-Encoding. A finite chunked response is not by itself evidence of long-lived streaming behavior. |
| Rule precedence | PASS | Corrected artifact selected earlier pointer value 42 over later value 77 live. |
| Emergency Disable | PASS | On prior candidate `DAFB274…`, both masters went OFF, five rules remained enabled, a matching request and response passed unchanged, all five counters remained unchanged, and no rewrite event appeared after the disable event. |
| Persistence, switch reset, reconnect | PASS | Observed after final artifact reload in the same Temporary Project; rules and allowlist persisted, switches reset OFF, and 42-tool MCP reconnection succeeded. |
| Event accuracy on discarded request rewrite | PARTIAL | `9CC223…` forwarded the unsupported request unchanged, logged a sanitized skip and left the pointer counter at 56; corrected artifact retest pending. |
| Original tools and schema parity | PARTIAL | Automated parity test covers both transports and editions; live registration confirmed. Individual tool status is below. |
| GitHub CI | BLOCKED | No modified-code GitHub Actions run or job logs were available; the cause of a GitHub failure is unverified. No push made. |

### Current candidate 3CC624 verification matrix

| Requirement | Status | Evidence and limits |
|---|---|---|
| Clean Windows and Ubuntu test/build | PASS | 155 tests per OS, zero failures/errors/skips, embedded proxy; current source. |
| MCP HTTP/1 and TLS HTTP/2 UTF-8 rendering | PASS | Live localhost calls returned `café`; binary/unsupported fallback covered by automated tests. |
| WebSocket ASCII history | PASS | Prior live synthetic ASCII frame returned by both history tools. |
| WebSocket UTF-8 text history | FAIL | Live text frame `café` returned `cafÃ©`; binary-frame type is not exposed in history. |
| Combined request and response rewriting | PASS | Live POST and PUT plus JSON and text response checks passed on `3CC624…`, with unaffected values preserved. |
| Request scope and allowlist boundaries | PARTIAL | Live passed on `DAFB274…`; current source covered by tests, not live-retested. |
| Response scope and allowlist boundaries | PARTIAL | Live independently isolated on `94BC415…`; no equivalent current-candidate live isolation. |
| Chunked-origin pass-through | FAIL | Valid finite HTTP/1.1 chunked origin was rewritten on `94BC415…`; current rewrite code has no demonstrated remedy. |
| Gzip and unsupported response pass-through | PARTIAL | Gzip passed byte-for-byte on `3CC624…`; partial and other selected cases passed on `94BC415…` and current-source tests. |
| Rule conflict handling | PARTIAL | Live conflict resolved deterministically on `94BC415…`; current-source automated test passed. |
| Emergency Disable active-to-OFF transition | PASS | On `3CC624…`, both masters went OFF; matching request and response passed unchanged and all five counters stayed at 56, 114, 58, 1, 1. |
| Persistence and switch reset | PASS | Five rules persisted and both masters showed OFF after current candidate load. |
| All 42 MCP tools | PARTIAL | Registered; individual live and mock coverage is detailed in the tool inventory. |
| Request-only / response-only performance | PARTIAL | Bounded measurements exist on `94BC415…` but not on this candidate. |
| Combined and OFF performance | PARTIAL | Bounded measurements exist on `DAFB274…` but not on this candidate; no causal comparison established. |
| GitHub Actions | BLOCKED | No relevant published modified-code run or job logs; no push authorized. |

### Explicit coverage limits

- **PARTIAL — request content and edge cases:** Form, duplicate parameters,
  escaped keys, duplicate-JSON-key and oversized-body handling and multipart
  file protection were observed on the corrected artifact. Multipart text,
  all empty and missing field cases, and replay behavior lack complete
  independent live checks on that artifact.
- **PARTIAL — response values and filters:** Boolean, numeric, string and null
  replacements, literal text, HTML, Unicode, no-store and selected path,
  method, status and content-type filters have corrected-JAR live evidence;
  not every possible filter combination or cache variant was exercised.
- **PARTIAL — unsupported responses:** Corrected-JAR gzip, partial,
  conditional, binary-content and download handling have live evidence.
  HTTP/2 and true long-lived streaming have not been independently exercised
  live; chunked-origin pass-through failed as described below.
- **PARTIAL — performance:** Four switch states were measured using the same
  bounded workload on the corrected artifact. Rule matching and parsing were
  not isolated with a profiler; JVM heap peak and normalized CPU utilization
  were not measured.
- **PARTIAL — original tools:** All 42 were discovered and schema parity was
  checked in automated tests. The per-tool table below distinguishes live
  invocation from registration and mocked coverage; several permission-gated
  behaviors remain untested live.

## Repository and CI evidence

- Checkout: branch `main`, commit `2910340` (`Update BappManifest.bmf`), with uncommitted changes and new rewrite/test files. The only configured remote is the PortSwigger upstream `origin`; no push or release was made.
- `.github/workflows/ci.yml` uses Ubuntu, Temurin Java 21, the Gradle wrapper, `./gradlew test` and `./gradlew embedProxyJar`, and uploads test reports on failure. The wrapper targets Gradle 9.2.0. Local Windows and bounded Ubuntu clean builds passed, but they do not prove a GitHub-hosted run passed or explain a GitHub failure without its job logs.
- The JAR manifest includes a build timestamp and builder/JDK metadata, so independently built artifacts are not expected to be byte-for-byte reproducible without further build changes. The recorded SHA-256 identifies the particular Windows artifact tested, not all equivalent builds.
- To verify CI on an authorized fork, commit the intended changes on a review branch, push only after the owner's approval, then inspect the corresponding Actions job and downloaded failure report if it fails. No repository write has been performed during this audit.

## Workspace changes and outstanding work

The checkout reports modifications to `.gitignore`, `README.md`,
`build.gradle.kts`, and these existing Kotlin files:

- `src/main/kotlin/net/portswigger/mcp/ExtensionBase.kt`
- `src/main/kotlin/net/portswigger/mcp/KtorServerManager.kt`
- `src/main/kotlin/net/portswigger/mcp/providers/ProxyJarManager.kt`
- `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- `src/main/kotlin/net/portswigger/mcp/schema/serialization.kt`
- `src/test/kotlin/net/portswigger/mcp/McpServerIntegrationTest.kt`
- `src/test/kotlin/net/portswigger/mcp/ProxyEndToEndTest.kt`

The untracked UTF-8 serializer and its test are `src/main/kotlin/net/portswigger/mcp/schema/Utf8MessageSerialization.kt` and `src/test/kotlin/net/portswigger/mcp/schema/Utf8MessageSerializationTest.kt`.

The untracked rewrite implementation comprises `GlobalParameters.kt`,
`ResponseProxyHandler.kt`, `ResponseRules.kt`, `ResponseSafety.kt`,
`RewriteManager.kt`, `RewritePanel.kt`, `RewriteProxyHandler.kt`,
`RewriteTools.kt`, and `SensitiveFields.kt` under
`src/main/kotlin/net/portswigger/mcp/rewrite/`. Its accompanying test classes
are under the corresponding `src/test/kotlin/.../rewrite/` directory. The
untracked `tools/` directory contains the loopback HTTP and HTTP/2 fixtures,
coverage probe, and benchmark; `docs/` contains this report. Untracked does not mean these
files are committed or published.

Earlier confirmed defects addressed in this checkout include a queued server
restart/shutdown race, configuration-secret exposure, resource cleanup,
excessive JSON nesting, counters recorded for discarded request changes, and
the response-configuration check deadlock described above. The remaining
chunked-origin safeguard failure is unresolved. The observed callbacks expose
normalized framing, so the evidence does not support a safe selective fix by
checking those headers alone. HTTP/2 and indefinitely open streaming behavior
remain unverified live. No GitHub Actions failure can be attributed to this
checkout without the relevant run logs.

## Actual live samples on preceding artifact

- Response fixture direct: `{"user":{"credits":10,"keep":"same"},"other":11}`.
- Same response through proxy with the pointer rule: `{"user":{"credits":42,"keep":"same"},"other":11}`; Content-Length 48 in both cases.
- Direct text: `Keep prefix. Fixture status: original. Keep suffix.` Proxy: `Keep prefix. Fixture status: updated. Keep suffix.` Content-Length matched bytes in both cases.
- Combined POST: fixture received query `user_id=12345&keep=query` and JSON body `{"user_id":"12345","fixture":{"count":42,"keep":"safe"},"other":11}`; client received root and nested `isPremium:true` with nested `keep:"unchanged"`.
- After Emergency Disable, the same fixture received query `user_id=old&keep=query` and JSON body `{"user_id":"old","fixture":{"count":7,"keep":"safe"},"other":11}`; client received root and nested `isPremium:false` and unchanged unrelated values. The five counters remained 58, 174, 58, 3 and 1.
- Gzip probe: origin sent Content-Encoding gzip and 66 bytes containing `credits:10`; client received an uncompressed 48-byte response containing `credits:42`. The extension cannot infer from its outgoing callback alone that Burp already unpacked the response.
- Follow-up with both rewrite masters OFF: a temporary localhost-only diagnostic reported `Content-Encoding` absent in both Montoya's general HTTP response callback and its Proxy response-received callback. The direct origin still sent gzip, and the proxy client received the decoded body with `credits:10`. Thus neither observed callback can reliably identify that origin encoding in this Burp configuration. The diagnostic handler and logging were removed; the exact previously tested JAR was restored and reloaded, with both masters OFF.

## Actual live samples on earlier guarded artifact `9CC223…`

- JSON pointer direct: `{"user":{"credits":10,"keep":"same"},"other":11}`; through proxy: `{"user":{"credits":42,"keep":"same"},"other":11}`. Both lengths were 48. The competing rule requested 77 and did not win.
- Nested response direct: `{"isPremium":false,"user":{"isPremium":false,"credits":10},"items":[{"isPremium":false,"keep":"original"}]}`; proxy: `{"isPremium":true,"user":{"isPremium":true,"credits":42},"items":[{"isPremium":true,"keep":"original"}]}`. Proxy Content-Length was 104, equal to body bytes.
- Direct text was `Keep prefix. Fixture status: original. Keep suffix.`; proxy text was `Keep prefix. Fixture status: updated. Keep suffix.`
- Gzip origin and proxy both had `Content-Encoding: gzip`, length 66, and SHA-256 `f88e72947649c2411c8e3e32b78bb99beaba6126f90a6a6a7333fb9a25173427`; decoded body retained `credits:10`.
- POST `/global-a` reached the server with query `user_id=12345&keep=query`, JSON `user_id:"12345"`, `fixture.count:42` and unrelated values intact. The client received root and nested `isPremium:true`. PUT `/global-b` also rewrote the parameter and response; its request-pointer value remained 7 because that rule's method filter did not match.
- A request to `127.0.0.1:18081` with both masters active retained `user_id=old` and returned `isPremium:false`.
- A JSON request with `user_id` as an object caused the combined request rewrite to be discarded: the fixture received the original query and body, the pointer rule counter stayed at 56, and the event log reported an unsupported or malformed request without exposing its contents.
- After the user enabled Burp response unpacking mid-session, a gzip-origin response arrived at the client decoded but unchanged (`credits:10`), the response master became OFF, the request master remained ACTIVE, and the event log recorded that response unpacking was enabled or unavailable. This confirms the extension stopped rewriting before it could alter the decoded response.

## Bounded performance observations

Subsequent final-JAR coverage confirmed UTF-8 string and null replacement in
nested JSON arrays, literal HTML replacement, `no-store`, status/method/media
filters and conditional/validator/download pass-through. An origin JSON body
of 118 bytes became 133 UTF-8 bytes with `Tester ✓` and `null` in the matching
fields; unrelated `café` remained unchanged. HTML changed only the intended
text and had a correct 54-byte Content-Length. Duplicate query/form parameters,
escaped JSON field names, multipart file protection, duplicate-key and malformed
JSON pass-through also passed live. Oversized request and response bodies were
unchanged (1,048,603 and 1,048,613 bytes respectively). Partial responses,
unsupported charsets and binary content-type cases passed unchanged.

The chunked case **failed** the requested safeguard: the origin had
`Transfer-Encoding: chunked` and 118 decoded body bytes, but the client received
a rewritten 133-byte body without the original transfer header. Burp's project
option `http.streaming_responses.strip_chunked_encoding_metadata` was true;
it is not yet established whether changing that option affects this finite
chunked response or whether Burp normalizes it independently.
The installed Montoya `InterceptedResponse` interface exposes the current
headers and body but no explicit original-framing field. Burp's UI labels the
option as applying to streaming responses; the streaming URL list is currently
empty, so its effect on this finite chunked fixture remains uncertain.

Follow-up: with `strip_chunked_encoding_metadata=false`, the same origin
still produced a 118-byte chunked body but the active proxy delivered a
rewritten 133-byte response. A temporary, fixture-specific diagnostic with
both rewrite masters OFF recorded `chunked=false length=true` at Proxy
response-received and response-to-be-sent callbacks. A separate temporary
general HTTP handler recorded the same result. These observations apply to this
Burp version and finite localhost fixture, not every protocol or future version.
The installed Montoya API also exposes a Proxy history `originalResponse()`,
but inspection of the fixture's recorded original response in Burp's HTTP
history showed `Content-Length: 118` and no `Transfer-Encoding` header. This
observed history view therefore did not recover the original framing either;
it does not prove all implementations of the history API behave identically.
Both diagnostic builds were unloaded, the temporary rules and fixture removed,
and the original `94BC415…` artifact restored and reloaded. Both masters reset
OFF and the original five rules remain individually enabled. The streaming
metadata setting remains disabled following the user's test change.

**Fixture correction:** The original chunked-response fixture used Python's
default HTTP/1.0 response status line despite sending chunked transfer encoding.
That is not a valid ordinary HTTP/1.0 chunked response, so the active-rewrite
failure above does not by itself establish behavior for a valid HTTP/1.1 origin.
The fixture now emits HTTP/1.1 for the chunked case. With both masters OFF, a
fresh localhost comparison found HTTP/1.1 and `Transfer-Encoding: chunked` at
the origin; Burp sent the client HTTP/1.1 with `Content-Length: 118` instead.
Both decoded bodies were 118 bytes with SHA-256
`53a4ffd7d48f3f84a096374e7859db585505e747a55b796db4278429b35c8479`.
An active-rewrite check using that corrected fixture subsequently confirmed
the failure: the direct origin returned status 201 with HTTP/1.1,
`Transfer-Encoding: chunked`, and 118 decoded bytes (SHA-256
`53a4ffd7d48f3f84a096374e7859db585505e747a55b796db4278429b35c8479`).
The client through Burp received status 201 and 132 bytes (SHA-256
`152a4ddbd67f85faf8355ae0c7156125613013a6147ad0b91cdf6e453a91064a`),
with both `coverage_string` values changed from `old` to `Tester ✓`, while
the other JSON fields stayed the same. A fixed-length control also rewrote
correctly. A temporary fixture-specific passive diagnostic with both masters
OFF recorded `chunked=false length=true` at both Proxy response-received and
response-to-be-sent callbacks for the valid HTTP/1.1 response. Thus, for this
Burp version and configuration, the original transfer framing was not visible
in those callbacks. A separate passive general Montoya HTTP response handler
also reported `chunked=false length=true` for the valid HTTP/1.1 response.
This finite response is not a test of long-lived streaming.
The diagnostic source was restored and the original JAR was reloaded with both
masters OFF; the disposable rule was removed and the fixture stopped.
As a further control, an HTTP/1.1 fixed-length origin and the valid HTTP/1.1
chunked origin emitted the same 118-byte body at the same status and media
type. With both masters OFF, the proxy delivered exactly the same status,
version, headers (including `Content-Length: 118`) and body hash for each.
This confirms their client-visible normalized responses were indistinguishable
in this controlled pair; it is not a statement about all metadata Burp may
possess internally.

An additional bounded delayed-stream fixture sent a JSON response in three
HTTP/1.1 chunks spaced 0.6 seconds apart. With both extension switches OFF,
the direct client received headers and the first byte after 28.7 ms and the
complete body after 1,830.1 ms. Through Burp, headers and the first byte both
arrived after 1,830.1 ms, with `Content-Length: 37` and the unchanged JSON
body. This demonstrates buffering in the observed Burp configuration even
without extension rewriting.

After the existing `isPremium` rule and the response master were locally
approved, the same delayed three-chunk fixture was tested on the restored
`94BC415…` JAR. The origin sent HTTP/1.1 chunked JSON
`{"isPremium":false,"keep":"original"}` (37 bytes; SHA-256
`88b033fb2115f615e17891723804e274879064beb87d770715396139b121652c`),
with its first byte at 29.5 ms and completion at 1,830.4 ms. The proxy client
received `{"isPremium":true,"keep":"original"}` (36 bytes; SHA-256
`faebe408b860dc56495f0c150b5768d9f5f2f0ee61ff252c057274bf96bfde63`),
with its first byte at 1,880.1 ms. The event log recorded a match for the
`isPremium` rule. A fixed-length positive control rewrote root and nested
fields as expected. This finite, deliberately paced response demonstrates that
streamed chunks can be buffered and rewritten; indefinitely open streams have
not been tested.

After the user activated Emergency Disable in that session, both switches
showed OFF and all five individual rules remained enabled. A proxy POST to
`/global-a?user_id=old&keep=query` reached the fixture with unchanged JSON
`{"user_id":"old","fixture":{"count":7,"keep":"safe"},"other":11}`.
The client received `isPremium:false` at the root and in `nested`, with
`keep:"unchanged"`; the full response was 230 bytes and its Content-Length
was 230. A delayed-chunk response also arrived as
`{"isPremium":false,"keep":"original"}`. The five displayed counters stayed
`0, 0, 2, 1, 0`, and the most recent event remained `Rewriting disabled`.
The local fixture was stopped afterwards.

The benchmark uses 5 warmups, 30 serial samples and 20 requests with four client workers against the local single-threaded fixture. These are observations, not a controlled cross-version or production-capacity study.

| Artifact / state | Median | P95 | Maximum | Parallel throughput |
|---|---:|---:|---:|---:|
| Preceding / both enabled | 28.349 ms | 39.038 ms | 65.362 ms | 105.29 requests/s |
| Preceding / both OFF | 25.047 ms | 32.725 ms | 47.121 ms | 158.80 requests/s |
| Earlier rebuilt artifact (`6EA024…`) / both OFF | 16.645 ms | 30.898 ms | 32.483 ms | 160.85 requests/s |
| Corrected `94BC415…` / response only | 30.402 ms | 33.024 ms | 34.051 ms | 163.49 requests/s |
| Corrected `94BC415…` / combined | 30.372 ms | 33.120 ms | 35.482 ms | 124.52 requests/s |
| Corrected `94BC415…` / both OFF | 29.094 ms | 34.917 ms | 34.918 ms | 141.12 requests/s |
| Corrected `94BC415…` / request only | 29.557 ms | 32.377 ms | 34.462 ms | 162.63 requests/s |
| Earlier guarded `9CC223…` / request only | 29.865 ms | 32.280 ms | 32.918 ms | 142.66 requests/s |
| Earlier guarded `9CC223…` / combined | 30.874 ms | 35.202 ms | 35.831 ms | 112.91 requests/s |

Burp working set sampled around the rebuilt OFF benchmark was approximately 725–737 MB and private bytes approximately 1.04 GB; these are snapshots, not peak usage. For the corrected request-only run, working set was 131,682,304 bytes before and 183,267,328 bytes after, private bytes were 1,545,539,584 and 1,550,344,192 respectively, and cumulative process CPU increased by 0.516 seconds. These snapshots do not establish peak usage or normalized CPU utilization. JVM heap and controlled CPU comparisons remain unmeasured.

The corrected request-only workload completed all 55 requests. A sample origin
echo showed query `user_id=12345&keep=query`, JSON `user_id=12345` and
`fixture.count=42`, with unrelated values preserved. Its client response kept
root and nested `isPremium:false`. The maximum concurrent latency was 31.484 ms.

The response-only test that deadlocked `9CC223…` completed on `94BC415…`:
5 warmup, 30 sequential, and 20 bounded concurrent requests returned successfully;
the sample server request kept both `user_id` values as `old`, while the client
received root and nested `isPremium:true`. Burp remained responsive and a
subsequent thread dump showed no matching deadlock. A direct/proxy gzip pair
both had 66 bytes and SHA-256
`f88e72947649c2411c8e3e32b78bb99beaba6126f90a6a6a7333fb9a25173427`.

With both masters ACTIVE, a POST through the corrected artifact to the
allowlisted IP reached the fixture with query and JSON `user_id=12345`,
`fixture.count=42`, and unchanged `keep` and `other` values; the client saw
root and nested `isPremium:true`. The same POST to in-scope `localhost`, which
was absent from the allowlist, reached the fixture with `user_id=old` and
`fixture.count=7`, and the client saw `isPremium:false`. The allowlisted IP
on out-of-scope port 18081 also passed unchanged. A PUT to a second path rewrote
the global parameter and response while the POST-filtered pointer retained 7.

For independent response allowlist isolation, a locally approved response rule
with no hostname filter changed `other` to 99 at `/response-test`. The
allowlisted `127.0.0.1` client received `{"user":{"credits":42,"keep":"same"},"other":99}`.
The in-scope, non-allowlisted `localhost` client received the original
`{"user":{"credits":10,"keep":"same"},"other":11}`. Each response was
48 bytes, matching its Content-Length.

Before the final Emergency Disable check, both masters displayed ACTIVE and
all seven staged rules displayed enabled. After the user clicked Emergency
Disable, both masters showed OFF and a proxy POST received HTTP 200 with 230
body bytes and matching Content-Length. The client received:

```json
{"isPremium":false,"nested":{"isPremium":false,"keep":"unchanged"},"request":{"method":"POST","path":"/global-a?user_id=old&keep=query","body_utf8":"{\"user_id\":\"old\",\"fixture\":{\"count\":7,\"keep\":\"safe\"},\"other\":11}"}}
```

The seven counters stayed 56, 114, 112, 2, 1, 0, and 1 in displayed order,
and the newest event remained `Rewriting disabled`. The two disposable
conflict/allowlist probe rules were removed; the five pre-existing test rules
were retained. Both loopback fixture processes were stopped. A final extension
reload preserved those five rules and the allowlist, reset both masters OFF,
and MCP reconnected with 42 tools.

After the subsequent request-only benchmark, the user again activated Emergency
Disable. Both masters showed OFF, and all five retained rules stayed enabled.
A matching proxy POST returned HTTP 200 with Content-Length 230 matching the
230 body bytes. Its origin echo contained `user_id=old` in both query and JSON
body and `fixture.count=7`; the client received root and nested `isPremium:false`,
with `keep` and `other` unchanged, as in the JSON sample above. The five counters
were 55, 110, 0, 0, 0 both before and after, and the latest event remained
`Rewriting disabled`. The verified localhost fixture process was stopped afterward.

## MCP tool inventory

`PASS` in this table means the specifically stated live operation succeeded; it does not establish all inputs, errors, or permissions for that tool. `PARTIAL` means registration, schema, mocks, or a narrower local-approval check was verified but the full live operation was not. `BLOCKED` denotes an attempted operation that required local approval and timed out. Automated tests use mocks where applicable.

| Tool | Status | Evidence and limits |
|---|---|---|
| send_http1_request | PASS | A live localhost GET returned HTTP 200 and the fixture's original 107-byte JSON response; the earlier approval-gated call timed out. |
| send_http2_request | PARTIAL | A TLS localhost HTTP/2 fixture returned HTTP/2 200 with the expected JSON. A cleartext HTTP/2 fixture worked with a direct Node client but this tool returned a null response; the reason for that h2c behavior remains unconfirmed. |
| create_repeater_tab | PASS | Live localhost request staged in a Repeater tab; no request was sent. |
| create_repeater_tab_http2 | PASS | Live localhost HTTP/2-form request staged in a Repeater tab; network HTTP/2 behavior was not exercised. |
| send_to_intruder | PASS | Live localhost request staged in an Intruder tab; no attack was started. |
| url_encode | PASS | Live utility; automated test |
| url_decode | PASS | Live utility; automated test |
| base64_encode | PASS | Live utility; automated test |
| base64_decode | PASS | Live utility; automated test |
| generate_random_string | PASS | Live utility; automated test |
| output_project_options | PASS | Live read-only invocation verified for scope and compression setting |
| output_user_options | PASS | Live invocation returned configuration; contents were not added to the report. |
| set_project_options | PARTIAL | Registered; not changed during audit |
| set_user_options | PARTIAL | Registered; not changed during audit |
| get_proxy_http_history | PASS | Live one-item retrieval succeeded; automated pagination uses mocks. |
| get_proxy_http_history_regex | PASS | Live localhost-filtered retrieval returned the recorded synthetic fixture request and response. |
| get_organizer_items | PASS | Live synthetic localhost item retrieved; UTF-8 `café` verified after reload of `DAFB274…`. |
| get_organizer_items_regex | PASS | Live localhost-filtered synthetic item retrieved with UTF-8 `café` after reload of `DAFB274…`. |
| get_proxy_websocket_history | PARTIAL | ASCII localhost payload returned correctly; UTF-8 text `café` was reported as `cafÃ©` on `3CC624…`, as detailed below. |
| get_proxy_websocket_history_regex | PARTIAL | ASCII filter worked live; a UTF-8 text payload was returned with mojibake on `3CC624…`, as detailed below. |
| set_task_execution_engine_state | PARTIAL | Registered; automated mock coverage; not changed live |
| set_proxy_intercept_state | PARTIAL | Registered; automated mock coverage; not changed live |
| get_active_editor_contents | PASS | Live invocation read the synthetic localhost Intruder request. |
| set_active_editor_contents | PASS | A harmless header was added to the synthetic Intruder request, verified, and the original was restored. |
| create_rewrite_rule | PASS | Live staged/disposable rule creation on preceding artifact |
| update_rewrite_rule | PASS | Live disposable update on preceding artifact |
| list_rewrite_rules | PASS | Live listing on preceding artifact |
| enable_rewrite_rule | PARTIAL | Registered; local approval mechanism exercised through Burp UI |
| disable_rewrite_rule | PASS | Live disposable disable on preceding artifact |
| remove_rewrite_rule | PASS | Live disposable removal on preceding artifact |
| create_global_parameter_rule | PASS | Live staged/disposable creation on preceding artifact |
| update_global_parameter_rule | PASS | Live disposable update on preceding artifact |
| list_global_parameter_rules | PASS | Live listing on preceding artifact |
| enable_global_parameter_rule | PARTIAL | Registered; local approval mechanism exercised through Burp UI |
| disable_global_parameter_rule | PASS | Live disposable disable on preceding artifact |
| remove_global_parameter_rule | PASS | Live disposable removal on preceding artifact |
| create_response_rewrite_rule | PASS | Live staged/disposable creation on preceding artifact |
| update_response_rewrite_rule | PASS | Live disposable update on preceding artifact |
| list_response_rewrite_rules | PASS | Live listing on preceding artifact |
| enable_response_rewrite_rule | PARTIAL | Registered; local approval mechanism exercised through Burp UI |
| disable_response_rewrite_rule | PASS | Live disable on preceding artifact |
| remove_response_rewrite_rule | PASS | Live disposable removal on preceding artifact |


## Current assessment

**Not release-ready: chunked-origin pass-through and WebSocket UTF-8 history failed live verification.** The
previous `94BC415…` artifact passed live response-only, combined, scope, allowlist,
compressed pass-through, and Emergency Disable checks. The prior `DAFB274…`
artifact has passed the Organizer UTF-8 check, the active combined rewrite
checks, and the Emergency Disable pass-through documented below. Some content variants
and MCP tools remain automated-only or untested live; an actual GitHub Actions
run remains unavailable. The
response-unpacking guard requires Burp's unpack option to remain disabled;
configuration changes can race with a response already in flight. After the
additional coverage and passive diagnostic tests, the rebuilt JAR was loaded;
both switches show OFF and the five original test rules remain
individually enabled. The
additional `http://localhost:18080/` scope entry used for the allowlist test
remains present; no scope or allowlist was reset.

To close additional live-coverage gaps, three temporary response rules were
subsequently created disabled: `85a5af89-84c5-4127-850f-b30bceae786b`
(string), `054b5bd3-8646-4f5e-b855-8564b9815686` (null), and
`1623f1a8-940e-4216-9b2d-f5547a054fef` (HTML literal). After local approval,
the coverage probe ran and its 11 cases passed as described above. The three
temporary rules were subsequently removed and the fixture was stopped. The
earlier Emergency Disable evidence applies to the prior active test session;
both masters reset OFF when the original JAR was reloaded after diagnostics.


## Active localhost retest on prior candidate DAFB274…

After local activation of both masters, the loaded artifact with SHA-256
`DAFB27426A0167F941EBE9E9B22F7890F96905592843CEBCD64C7C190323092F`
was tested through Burp on 127.0.0.1:8080. Direct GET `/response-test`
returned `{"isPremium":false,"user":{"isPremium":false,"credits":10},
"items":[{"isPremium":false,"keep":"original"}]}` (107 bytes). The proxy
client received `{"isPremium":true,"user":{"isPremium":true,"credits":42},
"items":[{"isPremium":true,"keep":"original"}]}` (104 bytes), with a matching
Content-Length. Direct `/response-text` returned `Keep prefix. Fixture status:
original. Keep suffix.`; the proxy returned `Keep prefix. Fixture status: updated.
Keep suffix.` with correct byte lengths (51 and 50).

The fixture's POST `/global-a` echo reported query `user_id=12345&keep=query`
and body `{"user_id":"12345","fixture":{"count":42,"keep":"safe"},"other":11}`.
The PUT `/global-b` echo had the same rewritten parameter values, while
`fixture.count` remained 7 because its request pointer rule is POST-filtered.
Both client responses contained root and nested `isPremium:true` and preserved
`keep:"unchanged"`. All tested response Content-Length values equalled body bytes.
After those probes, the Overview counters were 1, 4, 3, 1, 1 in displayed
order, and recent events attributed matches to the request and response rules.

A bounded combined benchmark with five warmups, 30 serial samples and 20
requests at concurrency four measured median 31.215 ms, p95 37.331 ms, maximum
40.957 ms and parallel throughput 138.88 requests/s (parallel maximum 38.391 ms).
This is a local sample rather than a comparable four-mode benchmark on this JAR.
Post-benchmark counters were 56, 114, 58, 1, 1.

With both masters active, the proxy passed a request to in-scope but non-allowlisted
`localhost:18080` unchanged, and passed an allowlisted IP request to out-of-scope
`127.0.0.1:18081` unchanged: the fixture saw query and JSON `user_id=old`,
`fixture.count=7`, and the client saw root and nested `isPremium:false`. These
checks independently exercise the global request rule boundaries; the response
rules also have host filters, so those particular response observations alone do
not isolate the response allowlist or scope checks. The 18081 fixture was stopped.
The final-candidate Emergency Disable test subsequently passed as documented below.


## Emergency Disable on prior candidate DAFB274…

After the user activated Emergency Disable, Burp showed both request and
response masters OFF while all five rules remained individually enabled. A
POST through the actual proxy to `/global-a?user_id=old&keep=query` reached
the fixture with the query unchanged and body
`{"user_id":"old","fixture":{"count":7,"keep":"safe"},"other":11}`.
The client received HTTP 200, 230 bytes with Content-Length 230, and
`{"isPremium":false,"nested":{"isPremium":false,"keep":"unchanged"},
"request":{"method":"POST","path":"/global-a?user_id=old&keep=query",
"body_utf8":"{\"user_id\":\"old\",\"fixture\":{\"count\":7,\"keep\":\"safe\"},\"other\":11}"}}`.
The five displayed counters stayed `56, 114, 58, 1, 1`, and the latest
event remained `Rewriting disabled` after the pass-through probe and the
bounded OFF benchmark. The localhost fixture was stopped.

The same bounded benchmark used for the combined sample measured both OFF:
median 29.899 ms, p95 31.778 ms, maximum 32.102 ms, parallel throughput
183.94 requests/s, and parallel maximum 32.658 ms. Each measurement used five
warmups, 30 sequential samples and 20 requests at concurrency four. These
are small local samples collected at different times and do not isolate parsing
or establish a causal performance regression.


## Local Montoya API framing review

The locally cached Montoya 2025.10 interfaces were inspected with `javap`
following the final shutdown test. `InterceptedResponse` exposes the response
headers, body, HTTP version, initiating request and ordinary message metadata,
but no declared original transfer-framing property. Its `attributes` API exposes
`CONTENT_LENGTH` among other response-analysis attributes, but the locally
installed `AttributeType` enum has no transfer-encoding or original-framing
attribute. `Annotations` exposes notes and highlight color. These observations
concern the inspected public API, not private Burp internals or later releases.

Combined with the controlled live observation that fixed-length and chunked
origin responses arrived at the inspected callbacks with the same normalized
status, headers and body, this review supplies no reliable selective predicate
for distinguishing those origins. Rejecting all responses would prevent the
requested automatic rewriting, and inferring original framing from request or
body content would be unsound. No production change was made on that basis.


## HTTP MCP tool UTF-8 correction on 3CC624…

Before the fix, a live `send_http1_request` to `/coverage-json` returned
the fixture value `café` as `cafÃ©` inside the existing Montoya wrapper.
The shared HTTP request/response renderer now converts only bodies identified
as valid UTF-8 JSON or text, preserving the original wrapper and falling back
to Burp's original rendering for unsupported data or unrecognized wrappers.
After reload, the same live HTTP/1.1 call returned `"keep":"café"`; a TLS
HTTP/2 localhost call returned `"unicode":"café"`. No external host was
contacted. The temporary fixture and certificate were removed.

Both clean builds passed 155 tests; the focused regression covers the wrapper,
safe decoding, encoded fallback, and unrecognized-wrapper fallback. The new
JAR has both master switches OFF and all five earlier rules remain enabled.
The response framing limitation and release assessment above remain unchanged.


## WebSocket history UTF-8 limitation on 3CC624…

A localhost WebSocket server sent a text frame with opcode 1 and UTF-8 bytes
`6c6f63616c686f73742d666978747572652d636166c3a9`
(`localhost-fixture-café`). The client received and decoded the original bytes,
but both `get_proxy_websocket_history` and its regex variant reported the
payload as `localhost-fixture-cafÃ©`. This is a confirmed original-tool output
defect, separate from the HTTP text fix.

A second localhost connection sent the identical bytes in a binary frame
(opcode 2); the client verified opcode 2. The MCP regex history returned two
otherwise indistinguishable payload/direction/notes objects for the text and
binary messages. Locally inspected Montoya 2025.10 `ProxyWebSocketMessage` and
its public parent expose payload and direction but no opcode or text/binary
flag. Decoding every valid UTF-8 byte sequence would change the existing
representation of binary messages, so no blanket production change was made.
The fixture was stopped; this behavior remains uncorrected and is a release
limitation pending a safe way to distinguish frame type or a compatible
representation agreed for binary data.


### Earlier WebSocket callbacks

The locally installed Montoya API also exposes a per-connection
`ProxyMessageHandler` with separate text and binary callbacks. Those callbacks
do distinguish frame kinds, but the public `InterceptedTextMessage` and
`InterceptedBinaryMessage` interfaces expose payload, direction, and
annotations without the history entry's `id` or `webSocketId`. The public
`ProxyWebSocket` interface likewise exposes no history connection ID.
Consequently, the inspected signatures alone do not provide a documented
identity join between these callbacks and existing history entries; identical
bytes in text and binary frames make payload-only matching ambiguous. This
does not rule out a supported correlation mechanism elsewhere or in a later
API, but an unverified hash/order join would not reliably preserve binary
compatibility or account for messages predating extension load.


### Installed Burp API comparison

The public interface classes packaged inside the running Burp installation at
`D:/BurpSuite/burpsuite.jar` were also inspected locally with `javap`. Its
`InterceptedResponse` exposes no original transfer-framing property, and its
`InterceptedTextMessage`, `InterceptedBinaryMessage`, and `ProxyWebSocket`
interfaces expose no history message or connection ID. Its
`ProxyWebSocketMessage` exposes history IDs but no frame-type property. Thus
the particular metadata gaps identified above are also present in the public
interfaces bundled with the installed Burp version, not just the cached
2025.10 dependency. This observation does not rule out a different public API
or a future version.


## Current candidate OFF pass-through

With `3CC624…` loaded, both masters OFF, and all five saved rules enabled,
a matching localhost POST through Burp reached `/global-a?user_id=old&keep=query`
with body `{"user_id":"old","fixture":{"count":7,"keep":"safe"},"other":11}`.
The client received HTTP 200 with root and nested `isPremium:false`, nested
`keep:"unchanged"`, and Content-Length 230 matching 230 bytes. The five rule
counters remained zero and the recent-events panel stayed empty. This verifies
post-reload OFF pass-through; it is not a new active-to-OFF Emergency Disable
transition test. The fixture was stopped.


## Active localhost checks on current candidate 3CC624…

With both masters locally activated, direct `/response-test` returned
`{"isPremium":false,"user":{"isPremium":false,"credits":10},"items":[{"isPremium":false,"keep":"original"}]}`
(107 bytes); through Burp the client received
`{"isPremium":true,"user":{"isPremium":true,"credits":42},"items":[{"isPremium":true,"keep":"original"}]}`
(104 bytes). Direct text was `Keep prefix. Fixture status: original. Keep
suffix.` and proxy text `Keep prefix. Fixture status: updated. Keep suffix.`
The fixture echoed POST `/global-a?user_id=12345&keep=query` with JSON
`{"user_id":"12345","fixture":{"count":42,"keep":"safe"},"other":11}`;
PUT `/global-b` also rewrote the parameter and kept POST-filtered count at 7.
The client received root/nested `isPremium:true` and unchanged unrelated
fields in both cases. All tested Content-Length headers matched body bytes.

A gzip fixture returned the same 66 bytes directly and through Burp, with
SHA-256 `f88e72947649c2411c8e3e32b78bb99beaba6126f90a6a6a7333fb9a25173427`
and unmodified `credits:10`. A combined bounded run (five warmups, 30 serial
samples, 20 requests at concurrency four) measured median 30.339 ms, p95
39.077 ms, max 44.101 ms and parallel throughput 111.99 requests/s. Afterward
the five counters were `56, 114, 58, 1, 1`, and events attributed matches to
the applicable rule IDs. The fixture was stopped. The subsequent active-to-OFF Emergency Disable check passed as recorded below.


## Emergency Disable on current candidate 3CC624…

After local Emergency Disable, the request and response masters showed OFF,
all five rules remained enabled, and the latest event was `Rewriting disabled`.
A matching POST through Burp reached the fixture with query
`user_id=old&keep=query` and body
`{"user_id":"old","fixture":{"count":7,"keep":"safe"},"other":11}`.
The client received root and nested `isPremium:false` with `keep:"unchanged"`;
HTTP status was 200 and Content-Length 230 matched 230 bytes. The five
matching counters remained `56, 114, 58, 1, 1`, and no later rewrite event
appeared. Both switches remained OFF and the fixture was stopped.


## Focused final-defect investigation

The PortSwigger Montoya documentation states that the Proxy response-received
callback is called when a response is received and the to-be-sent callback
after Proxy processing before delivery. `InterceptedHttpMessage.messageId()`
is documented as unique to a request/response pair, so it is suitable to
correlate callbacks, but an identity does not recover original transfer
framing if the first observable callback already lacks it. The fixed-length
and valid chunked localhost controls and both Proxy callbacks and general HTTP
handler were tested as recorded above. In the observed Burp version and
configuration, both responses reached the callback boundary with identical
normalized framing. This observation does not establish the exact internal
Burp processing stage or rule out all other versions or APIs. Sources:
https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyResponseHandler.html
and https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/InterceptedHttpMessage.html

The documented `ProxyMessageHandler` has separate text and binary callbacks;
`ProxyWebSocketMessage` history exposes byte payload, message and connection
IDs, but the installed callback interfaces lack a documented matching history
identity and the history interface has no message type. Relevant documentation:
https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/websocket/ProxyMessageHandler.html
and https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/ProxyWebSocketMessage.html

A localhost test on `3CC624…` sent eight WebSocket frames through the real
Burp Proxy; the client verified the following wire payloads (Base64) and
opcodes. Both MCP history tools returned all eight for an ASCII-prefix regex.

| Case | Opcode | Original payload, Base64 | Existing MCP output |
|---|---:|---|---|
| ASCII | 1 | `Zml4dHVyZS13cy1hc2NpaQ==` | ASCII correct |
| Hindi | 1 | `Zml4dHVyZS13cy1oaW5kaSDgpKjgpK7gpLjgpY3gpKTgpYc=` | Mojibake |
| Chinese | 1 | `Zml4dHVyZS13cy1jaGluZXNlIOS9oOWlvQ==` | Mojibake |
| Emoji | 1 | `Zml4dHVyZS13cy1lbW9qaSDwn5iA` | Mojibake |
| Mixed language | 1 | `Zml4dHVyZS13cy1taXhlZCBoZWxsbyDgpKjgpK7gpLjgpY3gpKTgpYcg5L2g5aW9IPCfmIA=` | Mojibake |
| Invalid UTF-8 | 2 | `Zml4dHVyZS13cy1pbnZhbGlkIP/+ww==` | Legacy byte-to-string rendering |
| Arbitrary binary | 2 | `Zml4dHVyZS13cy1hcmJpdHJhcnkgAID+/w==` | Legacy byte-to-string rendering |
| Valid UTF-8 bytes in binary | 2 | `Zml4dHVyZS13cy12YWxpZC1iaW5hcnkgY2Fmw6k=` | Legacy byte-to-string rendering; type unavailable |

Regex searches using the original Hindi, Chinese and emoji characters returned
no entries, while the ASCII-prefix search returned all eight. The invalid UTF-8
case was deliberately a binary frame: invalid UTF-8 is not a valid WebSocket
text payload. The fixture process was stopped.

A possible additive representation is to retain the existing `payload` field,
include raw bytes as Base64, and label type `unknown` unless a documented
correlation identifies it. This would preserve byte access without guessing
frame type, but it changes output shape, duplicates payload data in the output,
and requires a clear truncation/size policy; strict clients could reject new
fields. It would not, by itself, identify text frames or correct Unicode regex
filtering. No production implementation was made and this remains a limitation.
For responses, failing closed whenever original framing is unknown means
skipping all response rewriting for the observed normalized traffic, including
ordinary fixed-length JSON; that would sacrifice the core feature. No behavior
change was made.

## TLS HTTP/2 response rewriting candidate, 25 November 2026

This section applies to the HTTP/2 candidate with Windows JAR SHA-256
`1f1fd962b18711d268fea333fb0123c94c9769034a8bd26ec9e5ec983f0d603d`.
The separate HTTP/1 chunked-origin and WebSocket history findings above remain
open and were outside this change.

### Montoya feasibility and validation

The installed Montoya 2025.10 API exposes the processed response's
`httpVersion()`, `body()`, and `withBody(ByteArray)`. The existing Proxy
`handleResponseToBeSent` callback can return that response via
`ProxyResponseToBeSentAction.continueWith`. The handler recognizes `HTTP/2`,
validates an optional Content-Length against the original bytes, and checks
the version, status, length and prohibited connection-specific fields on the
replacement before forwarding it. Existing HTTP/1 responses still require a
valid Content-Length. The handler issues no HTTP/2 frames.
[Montoya ProxyResponseHandler](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyResponseHandler.html),
[Montoya HttpResponse](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/responses/HttpResponse.html),
[RFC 9113 HTTP message framing](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1)

The callback has no raw DATA frame, END_STREAM, or original trailer boundary.
With rewriting off, Burp retained an absent Content-Length and promoted the
fixture's `x-fixture-trailer` to a regular response header. A visible Trailer
or known digest header disqualifies the response. An arbitrary header cannot
be recognized as a former trailer from this API. Event streams use an
unsupported media type. If Burp delivers a complete buffered JSON or text
body assembled from several writes, the handler evaluates the buffered
message under the same rules as any other complete response.
[PortSwigger HTTP/2 behavior](https://portswigger.net/burp/documentation/desktop/http2),
[PortSwigger streaming settings](https://portswigger.net/burp/documentation/desktop/settings/network/http)

### Build and installed tool checks

| Check | Result |
|---|---|
| Windows clean `test embedProxyJar` | PASS, 159 tests in 29 suites, zero failures, errors or skips. |
| Ubuntu WSL clean `test embedProxyJar` | PASS, 159 tests in 29 suites, zero failures, errors or skips. |
| Automated HTTP/2 regressions | PASS for fixed and absent Content-Length, HTTP/1 length requirement, prohibited response headers, duplicate and mismatched lengths, and invalid mutation results. |
| Reload and persistence | PASS in Burp Community 2026.11.2. One Proxy request handler, one Proxy response handler, both masters OFF, and all eight rules retained. |
| Installed MCP tool list | PASS, 42 distinct tool names from the live `/mcp` endpoint, including the six response rule tools. Original tool parity tests passed. |

Both builds used one Gradle worker, offline dependencies, a 768 MiB Gradle
heap, and no persistent Gradle daemon. Ubuntu also used the established
low-memory test profile and in-process Kotlin compilation.

### Loopback test procedure

From PowerShell, generate a disposable fixture key and start the fixture.
The probe is restricted to 127.0.0.1 and requires TLS ALPN `h2` explicitly.

```powershell
$env:REWRITE_FIXTURE_P12 = Join-Path $env:TEMP ('burp-h2-fixture-' + [guid]::NewGuid() + '.p12')
keytool -genkeypair -alias fixture -keyalg RSA -storetype PKCS12 -keystore $env:REWRITE_FIXTURE_P12 -storepass fixture-only -dname 'CN=127.0.0.1' -ext 'SAN=IP:127.0.0.1' -validity 1
node tools/http2_fixture.js
```

In another terminal, the following open several independent streams on one
TLS HTTP/2 session. Scope must include `https://127.0.0.1:18080/`, the exact
allowlist must include `127.0.0.1`, and enabling live response rules and the
response master requires local approval. The fixture's certificate is used
only for this local test. Stop the fixture and remove its disposable P12 when
finished.

```powershell
node tools/http2_probe.js direct /h2-fixed /h2-no-length /h2-text /h2-empty /h2-malformed /h2-gzip /h2-partial /h2-events /h2-digest
node tools/http2_probe.js proxy /h2-fixed /h2-no-length /h2-text /h2-empty /h2-malformed /h2-gzip /h2-partial /h2-events /h2-digest
```

### Observed network evidence

The pre-upgrade pass-through control through Burp negotiated `h2` at the
client and origin, and delivered six concurrent streams. A direct run of the
updated TLS fixture also negotiated `h2` and returned the original top-level
and nested `fixtureFlag:false`, numeric `user.score:10`, `café`, and
`keep:"original"`. On the fixed path with the test query the body was 210
bytes and Content-Length was 210. The lengthless path returned 191 bytes
without Content-Length. The gzip origin payload was 59 bytes with SHA-256
`848f889b681fa3e68aba713ca8ec9172a5403fa1b0e4b74e3134e9ab8de52703`.

After loading the new JAR, a pass-through control on the out-of-scope port
18081 also negotiated `h2` on both sides of Burp. Three client stream IDs
were 1, 3, and 5 on one session. The fixed response was 187 bytes with a
matching Content-Length. The lengthless response stayed at 191 bytes without
Content-Length. Burp promoted the `/h2-digest` trailer to `content-digest`,
and the SHA-256 matched the 188-byte body received by the client. All three
kept `fixtureFlag:false`, `user.score:10`, `café`, and `keep:"original"`.
Both masters were off for this control.

### Approved live response-only run

The existing Burp Community 2026.11.2 Temporary Project owned both loopback
listeners, Proxy 8080 and MCP 9876. The MCP configuration editor was disabled.
The operator saved the prepared `https://127.0.0.1:18080/` scope prefix and
approved the three fixture rules and the response master in Burp. The
allowlist contained only `127.0.0.1`, and the request master stayed OFF.
The MCP `enable_response_rewrite_rule` invocation returned a sanitized
operation error before presenting a dialog. The MCP handler passes a null
parent to `Dialogs.requestOption`; the shared dialog builder immediately
calls `SwingUtilities.getWindowAncestor(parent)`. A standalone probe using
Burp's bundled Java 25.0.5.1 runtime reproduced the `NullPointerException`
at that lookup. The Burp panel's separate confirmation path presented and
saved the local approvals successfully. The fix and retest on the replacement
JAR are recorded below.

| Check | Result | Live evidence |
|---|---|---|
| HTTP/2 and multiplexing | PASS | Client ALPN `h2`; origin ALPN `h2` in JSON; nine streams on one client session with IDs `1,3,5,7,9,11,13,15,17`. |
| Fixed-length JSON and typed replacements | PASS | `/h2-fixed?user_id=old&keep=query`: origin JSON `fixtureFlag:false` at the root and inside `items[0]`, and numeric `user.score:10`; client JSON `fixtureFlag:true` in both places and numeric `user.score:42`. Original 210 bytes; client body and Content-Length both 208 bytes. |
| Lengthless JSON | PASS | `/h2-no-length`: the same typed changes; 190 bytes received with no Content-Length. The separately negotiated origin stream ID accounts for one byte of variation between runs. |
| Literal UTF-8 text | PASS | `Keep prefix. Fixture status: original. Keep café.` became `Keep prefix. Fixture status: updated. Keep café.` The response went from 50 to 49 bytes, with matching Content-Length. |
| Unrelated values, response integrity, and independent switches | PASS | Client JSON preserved `café`, `keep:"original"`, and `items[0].keep`. The origin echoed `user_id=old&keep=query`. All three modified responses retained status 200 and HTTP/2, carried `Cache-Control: no-store`, and had no `Transfer-Encoding` or `Connection` header. |
| Empty and malformed JSON | PASS | Empty stayed 0 bytes. The 20-byte malformed body `{"fixtureFlag":false` stayed byte-for-byte unchanged. |
| Gzip | PASS | `Content-Encoding: gzip` and all 59 bytes unchanged; SHA-256 `848f889b681fa3e68aba713ca8ec9172a5403fa1b0e4b74e3134e9ab8de52703` matched the direct origin. |
| Partial response | PASS | Status 206 and Content-Range `bytes 0-188/190` passed through with `fixtureFlag:false` and `user.score:10`. |
| Event stream | PASS | Same 56-byte payload through Burp and direct, SHA-256 `53772ba9b40b3be6ee8116e7cdc6313bb761fb42dc4f054c0bc2cc50c67e041d`. The proxy client received the first bytes at 188 ms and completed at 678 ms. |
| Digest trailer | PASS | Burp presented `Content-Digest` as a header. Digest and 189-byte body matched the direct origin, SHA-256 `04ff0358e919445b8daad16cc2b201b69f908f19c1c90e85e6f704d773fe37c6`. |
| Mandatory Target Scope | PASS | The same host on port 18081 was outside scope and retained `fixtureFlag:false`, numeric `user.score:10`, and the original query. Its 210-byte SHA-256 `a87a92af7e577d365a2c29098e145b91e84a14468e576b2e1d00a8bba21d9d33` matched the direct origin control while the in-scope port rewrote. |

Burp recorded two matches each for the field and pointer rules and one for
the text rule. Both request-rule counters and all unrelated response-rule
counters stayed at zero. Recent events contained rule IDs and sanitized skip
reasons. The unsupported cases in the table refer to the tested complete
responses and the finite SSE fixture.

### Emergency Disable

PASS on `1F1FD962…`. After the local Emergency Disable click, both masters
showed OFF and the three fixture rules stayed individually enabled. A replay
of the three previously rewritten requests negotiated `h2` on both sides of
Burp. Fixed JSON returned 210 bytes with Content-Length 210. Lengthless JSON
returned 191 bytes without Content-Length. Both contained the original
root and nested `fixtureFlag:false`, `user.score:10`, `café`, and the unrelated
`keep` fields. The origin echoed `user_id=old&keep=query`. Text returned the
original 50 UTF-8 bytes `Keep prefix. Fixture status: original. Keep café.`.
The only new rewrite event was `Rewriting disabled`, and the three counters
remained at 2, 2, and 1. The fixed-path body's origin stream ID varies between
connections, so JSON is compared with that transport metadata accounted for.

## Shared MCP approval dialog fix, 25 November 2026

Windows JAR SHA-256
`98077d3013783f5846376b2a297585b4ec12b34ef6df6d8bde2dab9117ac0799`.
The shared Swing builder now resolves its owner on the Event Dispatch Thread.
It prefers a supplied Frame or Dialog, walks component and window ancestry
when applicable, uses the existing Burp-frame lookup when needed, and can
create an unowned `JDialog` when no suitable window exists. The modal
confirmation, outcome mapping, and cancellation-triggered disposal remain in
place. HTTP and project-data approval handlers recheck coroutine cancellation
before applying an approval result.

Callers audited include all three rewrite enable tools, both HTTP send tools,
the HTTP and WebSocket history tools with and without regex, and the Organizer
tools with and without regex. Existing project-data permissions already allow
these reads, so their dialog outcomes were verified in automated tests without
changing those permissions in the running project.

Windows and Ubuntu WSL each passed `clean test embedProxyJar` with 163 tests
in 29 suites, zero failures, errors or skips, and one Gradle worker. The
Windows JAR was reloaded into the same Burp Community 2026.11.2 project.

| Live approval check on the fixed JAR | Result | Evidence |
|---|---|---|
| Response rule | PASS | Local approval of the temporary `/keep` rule for `/h2-approval-check` returned `Response rule enabled.` The rule was listed as enabled. |
| JSON request rule | PASS | An initial Allow returned `Rule enabled.` The test rule was reset, then a local Deny returned `Rule not enabled.` and the rule stayed disabled. The request master stayed OFF. |
| Global parameter rule and cancellation | PASS | The modal opened. A concurrent MCP `tools/list` returned 42 tools, then the client sent `notifications/cancelled`. The dialog closed and the rule remained disabled. |
| HTTP request | PASS | One-time approval for `localhost:18080`, distinct from the existing auto-approved `127.0.0.1`, returned `HTTP/2 200 OK`. The fixture reported ALPN `h2` and the original UTF-8 JSON. The saved target list still contained only `127.0.0.1` after the test. |

The active HTTP/2 replay on the fixed JAR used four streams through Burp Proxy.
The fixture and downstream client both negotiated `h2`. The fixed-length path
`/h2-approval-check?user_id=old&keep=query` went from 219 to 217 bytes with
Content-Length 217. The root and nested booleans became `true`, `user.score`
became numeric `42`, and the newly approved rule changed only the root
`keep:"original"` to `keep:"approved"`. The nested `keep`, `café`, and the
origin's query echo were preserved. The lengthless response kept its absent
Content-Length, plain text rewrote to `updated` at 49 UTF-8 bytes, and gzip's
59 bytes retained their original digest.

Emergency Disable also passed on the fixed JAR. After the operator clicked
the button, both masters showed OFF and the four matched response rules
remained individually enabled. The same four streams returned the original
JSON values, restored `keep:"original"`, and preserved `user_id=old&keep=query`.
The fixed response matched the direct origin apart from its stream ID and
declared and delivered 219 bytes. The lengthless response delivered 191 bytes
without Content-Length. The original text returned at 50 UTF-8 bytes, and the
59-byte gzip digest matched. No replay response gained a rewrite cache header.
The match counts stayed at `2, 2, 1, 1`, and `Rewriting disabled` was the only
new rewrite event. The three temporary approval-test rules and the TLS fixture
were cleaned up after verification. The eight pre-existing rules are retained.
