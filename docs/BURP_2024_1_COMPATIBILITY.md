# Burp Suite Professional 2024.1 compatibility

This extension is compiled against Montoya API `2023.12.1`, which is the API surface compatible with the fixed Burp Suite Professional `2024.1.1.1-26891` runtime. The connected Burp MCP reported that exact Burp version during verification. The installed extension was not replaced or reloaded.

## Runtime API differences

| Newer API call used by the previous source | Burp 2024.1 behavior | Compatible implementation |
| --- | --- | --- |
| `ProxyHttpRequestResponse.id()` | Absent; the old history tool failed at runtime when it called this method. | Feature-detect the native method. When absent, derive a stable positive integer from the request, response, HTTP service, and capture time. History lookup recomputes the same ID and retains existing history tools. |
| `MontoyaApi.project()` | Absent. | `burp_get_project_info` remains registered and returns `available=false` with an explicit reason. |
| `Organizer.items()` / filtered `items(...)` and `OrganizerItem` | Organizer retrieval types/methods are absent; the old Organizer API can submit messages but cannot enumerate them. | Feature-detect `items()` and locally apply regex filtering when available. The existing Organizer read tools stay registered and return an explicit unsupported-capability error on this runtime. |
| `RequestOptions.withResponseTimeout(long)` | Absent in this runtime. | Feature-detect and call it on newer runtimes. On Burp 2024.1 a bounded, four-worker MCP wait stops after 10 seconds and never retries. Montoya has no cancellation API here, so Burp may finish a timed-out send in the background; the tool reports that limitation. |

## Interception queue diagnostics and lifecycle

Proxy request and response handlers are both registered. The request callback does not filter by method, so eligible GETs are processed through the same authorization path as other methods. A message passes through unmodified, with a safe diagnostic event, if live interception is off or the target fails the host allowlist / URL-service / Burp scope checks. If the callback runs on Burp's UI thread or the message exceeds the size limit, it is explicitly dropped with the reason logged so it cannot bypass local review. Queue saturation, expiry, cancellation, session expiry, and release outcomes are logged separately. The queue remains bounded to eight held messages and each held message keeps its configured timeout.

`burp_get_intercept_diagnostics` exposes the bounded in-memory log through a read-only MCP tool. Events contain only redacted method/host/path, IDs, revisions, and reason/status text; they never include HTTP headers, bodies, cookies, or bearer tokens.

Edited messages remain blocked until the exact proposed revision receives local Burp approval. Any new proposal clears the previous approval. A forward releases only that approved revision. Existing scope checks, explicit host allowlists, bearer authentication, read-only mode, session heartbeat/expiry, rate limits, and bounded queues remain in force.

## Verification boundary

The full automated suite compiles against the old Montoya API surface. The request and response edit test sends real HTTP traffic only to loopback and exercises the registered interception callbacks through test adapters for Montoya messages. It confirms that the local origin receives the edited request header and the local HTTP client receives the edited response header while the response body and existing header are preserved.

This test does not load the replacement JAR into the connected Burp process. Since the installed Burp instance must remain untouched, its actual Proxy handler lifecycle and UI approval dialogs cannot be exercised against the replacement extension here.
