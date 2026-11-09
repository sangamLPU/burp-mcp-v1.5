# Phase 2 exact target session

Current source/runtime checkpoint: **dev.6**, build
`20261107.3-scanner-permission-hardening-dev`, 89 unique tools. Authenticated
identity and non-traffic preflight passed. The later legacy Scanner negative-only
call returned denial without data, but native category/human DENY attribution
remains BLOCKED. Always allow HTTP history was unchecked afterward. See
[development status](DEVELOPMENT_STATUS.md) and [verification](V1_5_0_VERIFICATION.md).

**Batch A passed on dev.5 and is complete.** Its three exact-target POST attempts,
three independent origin deliveries, transformations, counters and native approvals
are preserved locally; no authority remains. This document preserves the reviewed
procedure, not permission to repeat it. The fixture/coordinator were initially
prepared against commit 2170934/dev.3 and later qualified for dev.5 Batch A.
Historical build/configuration sections below retain that provenance. Future
security/reliability windows are in [remaining campaign](SUPERVISED_CAMPAIGN.md)
and each requires separate operator/native approval.

## Exact target and independent authorization

Use only `http://127.0.0.1:8000/test-post-phase2`. No scope or host-allowlist
change is required if the normal runtime retains its original configuration:
basic HTTP `/test-post` prefix plus exact `127.0.0.1:8000` host allowlist.
The saved primary matrix actually includes `/test-post-extra`; eligibility of
the new exact URL must still be queried on the restored runtime.

Source evidence:

- `config/LocalTestTargets.kt` contains nine exact URLs, not prefix matching.
  The new URL is neither one of them nor RULE_AUTHORITY_URL.
- `LiveInterception.checkRuleBearerAndMode` and `createInterceptionRule` take
  the target-grant branch for the new URL. No unattended activation is needed.
- `startTargetRuleSession` excludes the exact legacy list and DROP, requires
  current grants and immutable rule revisions, and asks for native approval.
- `TargetRuleAuthorization.permits` checks exact URL membership. Binding checks
  exact rule specifications and session ID; a preparation grant cannot execute.
- `LiveInterception.exactTarget` checks scheme, service, host, port, raw path,
  a single matching Host header and current Burp scope. `processTargetMessage`
  rechecks permission at release and associates each response with its request.
  Safe query values may vary on an approved path by design; this is not blanket
  query authorization or evidence that redirect/Host manipulation was tested.

Broader static prefix eligibility is not a grant for adjacent URLs. All claims
above are source inspection, not a new live authorization result.

## Fixture and coordinator reuse

`local-test-server.ps1` has one test-only `/test-post-phase2` alias sharing the
existing method-response builder. It requires RuleEngineTestMode, POST JSON,
the fixed synthetic fields and a matching X-MCP-Test-ID. It exposes received
body length/hash and returns synthetic case/nested fields with enabled=false,
allowing a response edit to be checked independently. Origin observations
retain postEnabled, body framing/hash, case ID and the synthetic header flag.
The existing `/test-method` response fields and case behavior are preserved.

Keep the old identity-bound path list unchanged. For this target-mode test,
launch the existing fixture in rule-test mode without unattended identities;
verify PID, full script path/hash, unique log and loopback listener ownership.
Do not use the unattended fixture launcher with active-mode identities: that
fixture mode deliberately accepts only its nine predefined paths.

`build_target_session_rule_specs(grant_id)` prepares exactly two 120-second
rules, each bounded to four matches/modifications. The client batch enforces
three attempts. A budget of three can exhaust the request rule before the last
response, invalidating its association with the approved active rule set.
Request JSON sets enabled
to true and adds X-MCP-Rule-Test: active. Response JSON independently sets
enabled to true. Both match POST, exact new path and application/json; response
also requires HTTP 200. They are created disabled by the server.

Reuse `LiveRuleEngineCoordinator._http_post(..., target_url=TARGET_SESSION_URL)`
for one-shot exchanges, not its legacy `run()` method. The fixed target guard
refuses other destinations before socket creation. Target-mode clients omit
legacy identity headers. `TargetSessionExchangeBatch` sends one baseline then
two barrier-released clients, refuses reuse, requires readiness before each
attempt, validates client/origin evidence and stores STARTED/PASS/FAIL records
through a caller-supplied durable evidence sink. It never obtains authorization
or performs automatic cleanup/forwarding. The supervisor retains those duties.
The readiness callback must read the actual grant/session and intended active
rule specifications before every attempt; it must return exactly True only
when bound authorization, identity, lifetime and empty queues are confirmed.
Use `require_target_session_readiness(client, grant_id, expected_rules,
owned_rule_ids)` for that callback. `expected_rules` maps exactly the two approved
IDs to the prepared specifications; `owned_rule_ids` also includes disabled
negative controls. It rejects changed specifications, missing references,
expired grants/sessions, active unattended mode and active unbound rules.
The origin lookup must return exactly the current case's records from this
run's unique log, with a bounded wait for log flush. Persist each sink record
before continuing. Never use a constant readiness callback in a live run.

`target_session_preflight(client)` is read-only: build/version, complete tool
catalog, original scope controls, new path eligibility, host count, inactive
authorization/interception, live edits, rule/queue state and Proxy TCP availability.
It does not prove the project identity or native Intercept toggle; confirm those
separately. Initialization uses the existing authenticated `preflight.initialize`.
This preparation does not start sessions or traffic.

After manual normal-runtime startup, the non-traffic invocation is:

```powershell
python scripts/live_rule_engine_coordinator.py --target-preflight-only
```

Do not invoke this script without that flag for Phase 2: its no-argument entry
point remains the previously verified legacy nine-exchange workflow. Phase 2
uses the supervised target helpers only after explicit traffic approval and
native approvals. No CLI command automatically requests those approvals.

## Approved-run proposal (fresh approval still required)

1. Verify normal primary project, current qualified dev.6/89 tools, exact new URL scope eligibility,
   existing allowlist, inactive unattended mode, no grants/session/rules/queues,
   edits enabled and Emergency Stop clear. Confirm native Intercept off through
   its existing human-approved path. Do not import isolated project settings.
2. Start the owned fixture after approval, with a unique observation log and
   payload/run limits. Health checks are distinct from the three POST exchanges.
3. Attempt preparation with a missing/invalid grant reference: expect rejection
   and no rule. Obtain one exact 300-second preparation grant through native
   Approve once. Verify exact URL and remaining time. Never silently renew it.
4. Prepare two transformation rules plus only the approved disabled controls:
   an excluded FORWARD_UNCHANGED rule and a request DROP rule. Verify grant-only
   enable fails and DROP session startup fails without native authorization.
5. Request a 120-second session for exactly the two intended rule IDs/revisions.
   Stop for native approval; require sufficient remaining grant time afterward.
   Verify healthy session and intended active rules; excluded-rule enable fails.
   Rule revisions are enforced internally by Burp but not exposed as a numeric
   revision field in InterceptionRuleView. Preserve exact IDs/specifications,
   native approval events and specification hashes; do not invent revision values.
6. Send exactly one baseline POST, then exactly two clients released from a
   barrier, each once, with unique bounded case IDs. Before sending, verify
   active bound authorization and sufficient remaining lifetime. Stop on any
   malformed result, unexpected prompt, authorization failure or mismatch.
7. Require three HTTP 200 results and exactly three origin records. For each,
   verify original client enabled=false, origin enabled=true, header observed,
   framing and transformed-request hash, client enabled=true, case/nested fields
   preserved and method metadata still POST. Compare client metadata/hash to
   its matching origin record. Expected counters: each approved rule matches,
   modifies and forwards three times; no failures/drops/skips. Two concurrent
   clients do not establish internal slot utilization or saturation.
8. Preserve all partial sanitized evidence before cleanup. Stop/pause only owned
   rules; stop the owned target session through its supported native approval
   path or let its approved deadline expire. Do not broaden approval to resolve
   held traffic. Verify grants revoked/inactive, no session or held messages,
   delete only owned rules, stop only the owned fixture, and verify unattended
   mode inactive and Emergency Stop unchanged. No scope cleanup is necessary.

## Historical preparation validation

- 32 Python coordinator tests cover the original sequential workflow and new
  fixed-target refusal, two-rule plan, target headers, preflight, three-attempt
  concurrency, malformed/oversized results and durable failure/no-retry behavior.
- 15 pure PowerShell fixture checks passed: synthetic response/evidence,
  preservation of the legacy handler, case IDs, mode/path/method/content-type
  rejection and malformed/extra-field rejection. No listener or HTTP request.
- PowerShell AST parsing passed for the fixture, shared builder and pure tests.
- `git diff --check` passed. That preparation alone needed no Kotlin changes or
  JAR rebuild; subsequent hardening produced dev.5 and then the corrected dev.6 artifact.
  Current loading/readiness comes from DEVELOPMENT_STATUS, not this historical run.
- 27 focused JVM tests passed: TargetRuleAuthorizationTest (6) and
  TargetLiveSessionTest (21), using mocked approvals/clocks/HTTP objects.
  Command: `gradlew.bat -PdevelopmentBuild=true -x shadowJar test
  --tests '*TargetRuleAuthorizationTest' --tests '*TargetLiveSessionTest'`.
  Existing compiled classes were up to date and JAR tasks were skipped.
- On the subsequent engineering review, 32 coordinator tests and 14 reliability
  coordinator tests passed. The unchanged 15 pure fixture checks, three parsing
  checks and 27 JVM tests retain the prior passing results; they were not rerun
  merely for activity. The reliability change only corrects report metadata to
  the shared development build; phase order, timing and traffic behavior are unchanged.

## Timing and failure gates

Complete code review, specification construction, logging setup, ownership
checks, native Intercept-off confirmation and all read-only setup work before
requesting the grant. Use a unique log and stop if port 8000 is occupied.
The 300-second grant starts only after native approval. Before requesting the
120-second session, require at least 180 seconds remaining as a practical
approval/setup margin; the server rechecks at least 120 seconds after approval.
This margin is not a promise that a delayed prompt can complete. If insufficient
time remains, do not request/start the session or renew the grant automatically.
After approval, require a healthy 120-second session, matching exact grant/rules,
and at least 30 seconds on both session and grant before each client attempt.
The one-shot client uses its existing 12-second timeout. Concurrent clients can
already be in flight together if one fails; never retry or start later work.

Save all successful and failed evidence before cleanup, including attempted
client count. If a client remains unresolved, mark its outcome UNKNOWN and do
not release or drop messages based on a timeout alone. Verify no live worker is
remaining before stopping its fixture. Retain any existing held-message approval
path. Deleting rules alone does not prove session or grant cleanup.

## Historical dev.5 runtime restoration

The current normal Burp Professional 2024.1.1.1 Temporary Project has working
authenticated MCP :9876 and loopback Proxy :8080, with native Intercept off.
Read-only mode is already off; the agent did not change it. The operator has
confirmed the intended project and explicitly approved only static restoration.
The loaded dev.5 artifact matches the
tested source/package; further native/live security gates remain open.

Fresh scope export equals `build/reports/phase2-scope-snapshot-20261106.json`:
basic mode, nine enabled HTTP prefixes with subdomains disabled, empty excludes
and no duplicates. Only `127.0.0.1:8000` is host-allowlisted. The approved existing
workflow and native confirmation applied this delta; unrelated project-option
hashes and listener records remain unchanged. Phase 2 is eligible under /test-post;
root, unrelated path, wrong host/port, HTTPS and external controls are ineligible.
The dedicated no-traffic preflight passes. Static eligibility still grants no
target preparation/execution authority. No grant/session or live batch was started;
no credential or daemon intervention is currently needed.

## Cleanup ownership and evidence checklist

Before requesting the grant, capture one evidence bundle containing the runtime
identity, scope-only snapshot, exact planned specifications, unique case IDs,
fixture script hash/process identity and unique log/evidence paths. Do not reuse
historical run IDs. Record the server's reported remaining grant time and the
actual session expiry timestamp; do not infer approval from tool registration.
Capture each native approval event immediately, because the activity log is bounded.

Use an evidence sink that appends each batch STARTED/PASS/FAIL record to a unique
JSONL file under `build/reports/phase2-target-session/`. A failed response retains
its numeric status and bounded digest without arbitrary body or exception text.
Separately retain sanitized original request bytes/hash, the fixed fixture
response contract, exact origin records and final counters for all owned rules.
Counts must distinguish three HTTP attempts from per-rule match totals. Record
the exact request/response specifications and IDs, not fabricated revision numbers.

Cleanup order: block further client attempts; wait for already-started bounded
clients or report UNKNOWN; inspect both queues; pause only owned rules; request
supported target-session shutdown (human confirmation), or observe its existing
deadline; verify the grant list and session state; delete only owned rule IDs;
stop only the verified fixture PID. Do not clear all rules or use Emergency Stop
as routine cleanup. Repeated cleanup first lists what still exists and acts only
on remaining owned objects. If queues are nonempty, stop automatic cleanup and
use the existing human decision/deadline path. Verify scope preservation,
inactive unattended mode, empty queues, no grant/session, no owned listener and
unchanged Emergency Stop before reporting success.

## Remaining Milestone 3 batches (separate approvals)

| Order / isolated batch | Existing evidence | New live result required | Window and cleanup |
|---|---|---|---|
| Phase 2 baseline + two concurrent clients | Completed live on dev.5 with three attempts/origins and complete cleanup | No automatic repeat; Batch A does not close B-H gates | Historical 300-second grant / 120-second session, now inactive |
| Priority winner and equal-priority conflict | Evaluator unit coverage; compatible rules live | Correct winner and unchanged conflict on target path, with counters/events and no partial edit | Each immutable rule configuration needs a fresh approved session; cleanup/revocation can require a fresh grant. No DROP execution |
| Target expiry and revocation | Phase 1 preparation-grant expiry live; empty local session expiry live; target boundary revocation synthetic | Target session/grant expiry with stale-use rejection; separately approved owned-session shutdown or narrow policy revocation | Separate terminal windows; never send after expiry or renew automatically. Restore only a separately approved narrow policy edit |
| Execution destination and response association | Exact destination/replay/association unit coverage; Phase 1 invalid declarations live | Controlled same-host mismatches leave traffic unchanged; never send to external systems. Replayed/stale association behavior only if observable safely | Can share a target window only with explicit added traffic approval and exact fixed controls; current three exchanges do not authorize this |
| Historical legacy reliability | v1.4.0 live drop, timeout, held-session expiry and two-message queue isolation passed | Revalidate native behavior on the corrected current artifact separately from target mode | The latest runtime report's campaign F uses ordinary native human decisions with unattended inactive. The legacy coordinator remains offline preparation evidence; do not invoke it under these limits |
| Emergency Stop, last | Unit/in-flight synthetic coverage; not independently live verified here | Latch, session/grant invalidation and safe terminal state; held-message drop is separate | Isolated explicit approval; leave latch engaged until separately approved recovery. No routine cleanup workaround |
| Final regression / candidate readiness | Stable v1.4.0 protected; focused current results | Consolidated required live evidence, unresolved failures and clean runtime/source state | Run only justified regression checks after code changes. Release packaging/publication needs its own authorization |

The target auto-processing path uses two nonblocking slots, not the legacy
held-message queue. Target DROP is intentionally unsupported. Two concurrent
HTTP clients do not prove simultaneous slot occupancy, overflow behavior or
queue saturation. Deterministic in-flight expiry/revocation and excess-slot
behavior remain synthetic-only unless safely observable controls are approved.
These limitations are not reasons to weaken authorization or rewrite infrastructure.

The dev.5 Batch A report now supplies live preparation/binding, three exact-target
exchanges and cleanup evidence. Broader execution restrictions and other native
security/lifecycle/reliability cases still need their separately authorized batches.
Earlier Phase 1 and nine-exchange evidence remains preserved. Isolated account/
scope-conversion work is abandoned for this plan.
