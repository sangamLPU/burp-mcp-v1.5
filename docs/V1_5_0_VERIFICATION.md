# v1.5.0 verification and safe operation

Current checkpoint on 2026-11-07: **1.5.0-dev.6**, build
`20261107.3-scanner-permission-hardening-dev`. Features are frozen and development
is paused. **NOT READY FOR A RELEASE CANDIDATE.**
[Development status](DEVELOPMENT_STATUS.md) gives the portable evidence summary;
[agent setup](AGENT_SETUP.md) gives fresh-clone/restart instructions and
[remaining campaign](SUPERVISED_CAMPAIGN.md) preserves the B-H approval boundaries.

The qualified dev.6 runtime passed actual loaded path/hash/build, authenticated
initialization, 89 unique tools, safe state and non-traffic preflight checks.
Original scope restoration remains preserved. A later exactly-one negative-only
legacy Scanner call returned the exact permission-denied error with no Scanner
data. Required approval stayed enabled; Always allow HTTP history stayed unchecked.
The native dialog category and explicit human DENY selection were not conclusively
captured. This gate remains BLOCKED, not a full native denial PASS. The earlier
unexpected persistent-permission transition is historical and unresolved; no agent
changed those controls. There is no authorization for another protected-data call.

The legacy permission bypass was reproduced offline on dev.5, corrected before
issue enumeration in dev.6 and covered by focused regressions. Batch A remains
LIVE TESTED **on dev.5 only**: three POST attempts, three HTTP 200 responses and
three independent origins, two transformations/counters, native approvals and full
cleanup. Dev.3 results and dev.5 Batch A are not new dev.6 live evidence. Do not
repeat Batch A automatically. No Batch B-H result is implied by runtime reload.

The unchanged offline dev.5 baseline is 303 JVM/118 Python passes, four offline
PowerShell suites and 24 syntax checks. Dev.6 focused/package results are separate
and overlap; do not sum them as a new full-suite result. Local reports under
`build/reports/` are deliberately ignored and absent from a clone. Exact report
paths and artifact checksums are indexed in DEVELOPMENT_STATUS; preserve private
originals separately. No release publication, scope expansion or traffic is
authorized by this document.

A Scanner data-scope disclosure bypass was reproduced with synthetic findings and
fixed in dev.4: finding scope/host/service checks run before pagination, attached
HTTP exchanges are independently filtered, and report counts exclude unauthorized
findings. Dev.3 still has the old behavior. Do not rely on its Scanner listing tools
to enforce the intended data boundary; corrected-runtime verification is a release gate.

Local evidence: `build/reports/verification-v1.5.0-20261107/REPORT.md` and its complete
89-tool JSON/CSV matrix. Registration, synthetic unit tests, embedded MCP transport
with mocked Montoya, direct fixture HTTP and real Burp evidence are separate.
A rejected malformed argument does not establish successful tool functionality.
The original package is historical evidence; the linked latest review records
current scope/allowlist observations and subsequent focused test results.

## Functionality and limits

Rules implement typed JSON set/remove with dot members and numeric array indices,
query/form set/remove, request/response header set/remove and literal replacement
in text/plain or text/html. Root JSON replacement, scripts, expressions and regex
replacement are unsupported. Body edits accept UTF-8; dev.4 rejects unsupported,
duplicate and malformed charset declarations before editing. Duplicate parameter
updates replace all matching occurrences; unrelated encoded pairs retain their
bytes. Body edits recalculate Content-Length from UTF-8 bytes. Routing, framing
and credential headers are protected. Failed speculative transformations do not
commit partial output.

These semantics have offline evidence. Full real Montoya materialization remains
subject to the remaining supervised cases; the positive dev.5 Batch A is separate. Legacy dev.3 nine-exchange evidence is retained;
it does not verify target-session execution or dev.4. Two concurrent clients do
not by themselves establish simultaneous internal slot occupancy.

Other tools expose redacted history/analysis, configuration/editor controls,
request/Repeater actions, passive Scanner audit and Professional Collaborator.
Active audit is disabled. Repeater tab enumeration is unsupported. Older Montoya
can lack project identification and Organizer retrieval. Analysis results are
heuristics, not confirmed vulnerabilities. Consult the tool matrix for individual
coverage gaps; registration alone never establishes integration support.

## Authorization model

Dev.4 refuses startup when bearer authentication is disabled or the configured
bind host is not loopback. The listener always authenticates requests, even if
the mutable configuration flag changes after startup. The localhost bind name
uses a numeric loopback address rather than DNS resolution. This is stricter than
dev.3's configurable deployment policy. Keep bearer authentication enabled; never
expose the listener or disable authentication to recover a connection.

Ordinary send, Repeater and passive-scan operations require current Burp scope,
explicit host allowlisting, write mode, rate capacity and per-operation local
approval. Some older allowlist functions accept host-only/wildcard entries; target
grants require the exact host:port entry. Safety pause/delete/Emergency Stop do not
grant execution authority. Data access can require a native prompt unless the
operator previously allowed it using the existing local controls.

A preparation grant authorizes only disabled rule preparation for 1–16 canonical
paths on one exact HTTP(S) scheme/host/explicit port, for at most 300 seconds.
Root paths, encoded/traversal paths, userinfo, query and fragment grant URLs are
rejected. Execution requires a second native approval binding exact rule IDs and
immutable specifications to a 60–300 second session within the grant's lifetime.
Target sessions cannot authorize DROP. Expiry, policy revocation, session stop and
Emergency Stop invalidate authority; there is no automatic renewal.

Safe execution queries can vary within the approved path. Actual service identity,
one matching Host header, exact scheme/host/port/raw path, current policy and active
rule revisions are rechecked. Responses require one-use request association and
outgoing-request digest. Sensitive, unrelated, unsupported or expired target
traffic continues unchanged without entering the legacy manual queue. Credential
filtering is heuristic: do not put real credentials into fixtures.

Unattended Local Test Mode is separate, human-activated authority for nine fixed
localhost paths. It cannot approve target grant/session prompts and must remain
inactive for Phase 2. Native Proxy Intercept is also separate from the managed
session. See [target authorization](V1_5_0_TARGET_AUTHORIZATION.md) and
[Phase 2](PHASE2_TARGET_SESSION_PLAN.md).

## Startup, token and connection

Use the normal Windows account and intended Burp project; do not import abandoned
isolated-project settings. Build only with isolated development output:

```powershell
.\gradlew.bat -PdevelopmentBuild=true test shadowJar --offline --console=plain
```

Load an explicitly versioned development JAR only after its tests, manifest and
SHA-256 checks pass. Older generic development JARs are historical; current
development packaging uses the version in its filename. Never run default-output packaging or clean against v1.4.0's preserved
directory. Extension reload is a separate supervised action: first inspect queues,
sessions and grants because unload can resolve held traffic.

Keep MCP at `http://127.0.0.1:9876/mcp` and the intended Proxy on loopback. Use
[Codex setup](CODEX_SETUP.md) for the existing secure local token/environment and
MCP connection procedure. Do not put tokens in source, command arguments, reports
or chat. Refreshing a rejected credential does not authorize traffic. Confirm
loaded version/build, 89 unique tools, native Intercept off, inactive unattended
mode, empty queues and the intended rule/grant/session/Emergency Stop state.

## Rule workflow and Phase 2

1. Inspect current scope/allowlist eligibility without application traffic.
2. Obtain separate operator traffic authorization and any narrowly reviewed scope
   restoration approval. A written test plan supplies neither.
3. Request the exact preparation grant and wait for native Approve once.
4. Create disabled rules and retain their exact IDs/specifications.
5. Request the bounded session for only the intended rules; wait for native approval.
6. Recheck grant/session lifetime, bound rules and queues before every attempt.
   Record each attempt before sending and never automatically retry.
7. Compare independent client/origin identity, bytes/hashes, framing, preserved
   fields and counters. MCP success alone is insufficient.
8. Stop new attempts on failure, retain partial evidence and clean up owned state.

The only preapproval Phase 2 CLI invocation is:

```powershell
python scripts/live_rule_engine_coordinator.py --target-preflight-only
```

The no-argument entry point is still the legacy nine-exchange runner. Phase 2 uses
the supervised helpers for exactly three POST attempts to
`http://127.0.0.1:8000/test-post-phase2`: one baseline, then two concurrent clients.
It requires one 300-second preparation grant, one 120-second session and two rules
with four-match/four-modification budgets, keeping the request rule active through
the final response association. Client attempts remain limited to three. Require
180 seconds of grant lifetime before requesting the session and 30 seconds on both
authorizations before each attempt. Health checks are separate from those POSTs.

## Emergency Stop, recovery and cleanup

Emergency Stop immediately latches rules off, invalidates grants, disables
unattended authority, ends the session and drops held traffic. Do not use it as
routine cleanup. Leave its latch in the approved state; recovery needs fresh
human-visible activation. Dropping a response cannot undo upstream side effects.
Client timeout/cancellation does not prove zero origin deliveries.

For normal cleanup prevent new attempts, wait for bounded clients, inspect queues,
pause only owned rules, and stop the owned session through native approval or
observe its approved expiry. Verify grants/session inactive, delete only owned
rules and stop only the verified fixture PID. Nonempty queues require the existing
human decision/deadline path. Keep unresolved client outcomes UNKNOWN. Preserve
unrelated settings, scope/exclusions, rules and processes.

Require native Intercept off, queues empty, no owned rules/grants/session/unattended
authority, no fixture listener and the intended Emergency Stop state. Current-source
empty-state replacement/reconnection is runtime-verified. Held-message unload,
callback uniqueness and adversarial recovery still need supervised evidence.

## Troubleshooting

- HTTP 401: refresh the rejected/missing client credential locally; keep auth on.
- HTTP 403: inspect Origin/Host/Referer policy; do not fabricate bypass headers.
- Scope preflight failure: compare actual entries to the saved original snapshot.
  One allowlist entry does not prove that it is the required localhost entry.
- Stale rule/message: inspect ID, lifecycle and exact revision; do not replay a
  terminal action or silently renew expired authorization.
- Malformed response: coordinator hardening rejects missing content, invalid error
  flags, nested wrappers and unexpected approval text. Some legacy handlers return
  denial text with isError=false; require exact acknowledgement and state evidence.
- Burp send timeout: MCP waits are bounded, but Montoya 2024.1 cannot cancel an
  individual send. A timed-out send may finish later. Four workers are bounded;
  reconcile origin evidence and never automatically retry.
- Legacy held-message callbacks wait synchronously within deadlines, with eight
  shared queue slots. Target processing has two nonblocking slots and bounded
  associations. Synthetic overlap is distinct from live utilization.

Offline passes do not remove the supervised live and cleanup/restart release gates.
