# v1.5.0 target authorization

Current source/runtime is **dev.6**, build
`20261107.3-scanner-permission-hardening-dev`, with 89 tools. See
[development status](DEVELOPMENT_STATUS.md) and [agent setup](AGENT_SETUP.md).
The separately authorized dev.5 Batch A passed three exact-target POSTs/origins,
native grant/session binding, both transformations/counters and complete cleanup.
It is preserved historical evidence and must not be repeated automatically.
The dev.6 denied Scanner call did not conclusively capture its native category or
human selection; security and lifecycle gates remain open. Milestone build/count
and not-yet-loaded statements below are implementation history, not current status.

## Historical milestone implementation notes

Current development status: milestone 2 implements bounded target-specific continuous
request/response execution. See the milestone 2 section below. Milestone 1 notes
are retained as implementation history; its execution block is superseded.

Development starts at verified v1.4.0 commit `73274b38a783e503ef7557086dfde40554f32cee`.
This milestone adds target-specific human authorization and disabled rule preparation.
It does not enable automatic execution for additional websites.

## Approval and bounds

`burp_request_target_rule_authorization` accepts 1–16 unique exact HTTP(S) URLs
on one lowercase host with an explicit port and a duration of 1–300 seconds.
Each URL must have a non-root path. Credentials, queries, fragments, wildcards,
encoded paths, duplicate slashes and dot traversal segments are rejected.
IPv6 and internationalized host names are not supported by this first milestone.

Every path must already be in Burp Target scope, and the existing MCP allowlist
must contain the exact `host:port` entry. Host-only and wildcard entries cannot
satisfy this check. The tool never changes either scope or allowlists.

Approval always uses the existing **Approve once / Deny** Burp dialog, including
the exact paths, duration and preparation-only limitation. Unattended localhost
mode cannot approve these grants. Denial, timeout or cancellation grants nothing.
Policy is rechecked after approval. Grants live only in memory, have a monotonic
deadline, and are not extended by use or status calls. A new grant always needs
another human approval. At most 16 grants can exist.

`burp_list_target_rule_authorizations` returns current grants. The ID can be used
as `authorizationReference` with the existing create/update rule tools. These
rules remain disabled. Expiry, observed scope/allowlist removal, read-only mode,
authentication disablement or session shutdown invalidates permission. Emergency
Stop also clears grants and invalidates pending approvals. Expired prepared rules
report `AUTHORIZATION_ENDED`; Emergency Stop keeps its existing latch and state.

The development MCP catalog has 88 tools, preserving all 86 existing tools.
Existing localhost rule execution, protected headers, credential filtering,
human disclosure approvals and emergency controls remain in place.

## Validation

Run development tests with isolated output:

```powershell
.\gradlew.bat -PdevelopmentBuild=true --no-configuration-cache test --tests '*TargetRuleAuthorizationTest' --tests '*LiveInterceptionTest' --tests '*InterceptionRuleEngineTest' --tests '*UnattendedLocalTestModeTest' --tests '*McpServerIntegrationTest' --tests '*BuildInfoTest' --console=plain
```

Tests use synthetic `.example` URLs and mocked approvals, clocks and Burp scope.
The MCP transport regressions use an embedded local server, not the running Burp
listener. No third-party traffic or live interception activation is required.
Outputs go to `build/dev-v1.5.0`; the stable release JAR is preserved.

## Remaining before external continuous execution

Bind grants to an explicitly approved live session and enforce the exact origin,
service identity, Host header, path and remaining authorization lifetime before
capture, evaluation and forwarding of every original and edited revision.
Then integrate credential-safe manual disclosure and forwarding decisions for
non-synthetic traffic, retaining the current fail-closed behavior and Emergency
Stop. External rules are deliberately rejected by the enable path until that
integration and its security tests are complete. v1.5.0 is not release-ready.

## Milestone validation result

The six listed test classes passed: 88 tests, zero failures, errors or skips.
The exact MCP catalog test confirms all 86 previous tools plus the two new tools.
The working and canonical v1.4.0 JAR SHA-256 values remain
`930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`.

## Milestone 2: live session binding and execution

After preparing disabled rules, call `burp_start_target_rule_session` with one
grant ID, 1–16 exact rule IDs and a 60–300 second session duration. The grant must
have that much lifetime remaining. Burp displays a second **Approve once / Deny**
dialog listing the exact targets, rule IDs, directions, actions and transformations.
The rules and grant are revalidated after approval. Changed rule revisions, stale
approvals, insufficient lifetime, disabled authentication, read-only mode and
nonempty queues prevent activation. Modifications also require the existing
Burp-local live-edit control. Local unattended mode cannot approve this operation.

The grant binds to one generated session ID and immutable rule specifications.
The existing engine activates the approved rules with TTL capped by the grant,
session and rule deadlines. Rules do not authorize themselves. Emergency Stop
revokes grants, invalidates pending approval epochs and preserves its engine latch.
A new, explicit human-approved session is required to clear that latch.

Automatic target processing uses the existing evaluator, transformation validator,
materializer and engine commit transaction. It checks authorization before selection,
before each speculative transformation, before materialization and at final release.
No speculative edited object reaches a Proxy callback unless the final checks pass.
The lock order is live session, rule engine, grant store; grant-store actions never
acquire the engine lock. Scope/allowlist change callbacks increment an atomic policy
revision without acquiring those locks. This also prevents restored scope or
allowlist entries from reviving an old grant. Scope is read again at action boundaries.

The target path has two nonblocking automatic processing slots and a 64 KiB limit
for original requests, responses and edited output. Excess, unrelated, sensitive,
revoked, expired, unsupported or conflicted traffic continues unchanged, without
entering the manual decision queue or generating an automatic drop. Existing native
Burp intercept behavior is preserved. The existing localhost manual queue and its
timeout/drop semantics are unchanged.

Each automatic message must match the exact granted scheme, host, port and raw path,
its actual HTTP service and a single matching Host header. Only omitted default
HTTP/HTTPS ports are canonicalized; credentials, fragments, encoded/traversal paths,
path aliases and destination changes are refused. Safe queries can change within
the same granted path, with credential checks on both original and proposed content.

Responses require a one-use association with the session's observed request. The
association checks the Proxy request/response pair ID, exact target, SHA-256 of the
outgoing request bytes and active rule revisions. Paused/resumed rules, replay,
wrong initiating requests, stale sessions and mismatched IDs cannot reuse it. The
association cache stores only digests/IDs/revisions, is capped at 128 entries, and
is cleared on session shutdown. Pair IDs use the documented Montoya
[request/response correlation API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/InterceptedRequest.html#messageId()).

Cookie/Authorization input, credential-like content, compressed content, redirects
and unsupported framing remain protected. No automatic disclosure, Cookie editing,
WebSocket editing or automatic target DROP is introduced. Request/response
modification and unchanged forwarding are the permitted target operations.

### Development build and verification

Development identity is `1.5.0-dev.2`, build `20261102.2-target-live-session-dev`.
The MCP catalog has 89 tools: the original 86 and three target authorization tools.
`-PdevelopmentBuild=true` builds under `build/dev-v1.5.0`; the working `.13` JAR
and release/rollback directories are not replaced. No running extension reload is
part of this milestone.

`TargetLiveSessionTest` uses deterministic synthetic HTTP objects, a monotonic fake
clock, mocked human dialogs, installed Proxy callbacks and latches. It tests successful
request/response edits; exact origin, Host and service checks; operation restrictions;
credential/payload/redirect rejection; response replay and association mismatches;
grant/session/heartbeat expiry; scope/allowlist events; Emergency Stop; pause/delete;
stale approvals and sessions; two simultaneous actions and unchanged excess traffic.
Revocation is injected during request and response materialization to check that no
edited object is committed afterward. These are synthetic tests, not external live
verification. Existing localhost, queue, approval, authentication, credential-filter
and embedded MCP transport regressions are also run.

### Remaining limitations and next milestone

The mechanism is implemented but has not been verified against a reloaded extension
and an approved live service on Burp Professional 2024.1.1.1. The code compiles against
the existing Montoya 2023.12.1 baseline. Strict exact-path/Host rules may intentionally
leave real traffic unchanged; the bounded association cache can also evict requests.
The next milestone should use a separately approved local service and supervised
extension reload to verify real Proxy request/response association, native intercept
behavior, expiry and emergency cleanup on the supported Burp runtime. Third-party
testing and release publication require separate authorization.


Focused milestone 2 command:

```powershell
.\gradlew.bat -PdevelopmentBuild=true --no-configuration-cache test --tests '*TargetLiveSessionTest' --console=plain
```

The session-binding transition also has a latch-controlled callback test: callbacks
cannot observe a partially initialized target session and enter the manual queue.

Final milestone 2 regression result: **154 tests passed**, zero failures, errors or
skips, including all 21 `TargetLiveSessionTest` cases. Build identity and the exact
89-tool catalog also passed. The running Burp extension was not reloaded.
