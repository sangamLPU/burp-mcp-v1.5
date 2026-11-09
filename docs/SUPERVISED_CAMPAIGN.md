# Remaining supervised campaign

This portable summary preserves the reviewed B-H plans from the local dev.5
`LIVE_CAMPAIGN.md` and post-Batch-A readiness reports. It authorizes no operation.
Use the qualified current artifact, not a historical filename. Batch A passed
on dev.5 and must not be repeated automatically. See
[development status](DEVELOPMENT_STATUS.md) for evidence and open gates.

## Common controls

Every subwindow needs fresh operator authorization naming exact targets, methods,
operations and attempt limits, plus native human approvals where required. No
automatic retries, redirects, renewal, external targets, scope changes or unattended
activation. Client attempts and independent origin deliveries are separate counts.
The fixture/Proxy/MCP use loopback ports 8000/8080/9876. A fixture start or health
request is never implicit approval; count any approved health exchange separately.

Before each window confirm intended project, build/hash/authentication, unchanged
nine-prefix basic scope and sole `127.0.0.1:8000` host allowlist, native Intercept
OFF, unattended inactive, empty queues/rules/grants/sessions and clear Emergency
Stop unless specifically testing terminal recovery. Do not resolve a failed gate
by changing permissions. A preparation grant permits no traffic or disclosure.

Target windows use supported preparation/create/session tools, frozen rule IDs and
specification hashes, then one-shot approved clients. Require at least 180 seconds
of grant lifetime before requesting a 120-second session and at least 30 seconds
on grant/session before every send. Lifetimes/budgets below are upper bounds, not
permission to spend extra requests. Numeric private rule revisions are not exposed.

Allowed administrative evidence reads include status/connection/scope, interception
status, pending lists, grant/rule lists, engine status, owned counters/events and
payload-free diagnostics. Protected project-data/disclosure reads need their own
native decisions. Never use a legacy alias to evade denial.

For every traffic window collect unique case IDs, original synthetic request
hash/length, origin records, client status/hash, framing, observed deadlines,
native approvals and owned-rule counters/events. Tool success alone cannot pass.
Stop new attempts on a leak, extra/unknown delivery, mismatched case/hash/revision,
unexpected prompt/target, malformed evidence, expired authority or unresolved worker.
Timeout is UNKNOWN until independent evidence resolves it.

Cleanup C0: stop attempts; resolve bounded workers; inspect queues; pause only owned
rules; native-approved owned-session stop or observe existing expiry; verify grants
and session inactive; delete only owned rules; stop only the owned fixture PID.
Held messages retain the native human decision/deadline path. Verify empty queues,
no owned authority/rules/listener, Proxy OFF, unattended inactive, preserved policy
and expected stop latch. Never clear unrelated state or use Emergency Stop as
routine cleanup. Each batch below includes C0 where applicable.

## Batch B Scanner disclosure

**BLOCKED.** First resolve explicit-native-DENY attribution. Then separately approve
bounded filtered inventory and establish nonempty synthetic findings with known
native provenance. Allowed root/attachment: `http://127.0.0.1:8000/test-post`;
excluded root/attachment: `http://127.0.0.1:8000/`. Application exchanges zero,
Scanner starts zero, no grants/session/rules, read window at most 120 seconds,
count at most 20, offsets 0/1. Each protected read uses human Allow Once, never
Always Allow. Do not display unrelated findings to prove filtering.

Use `burp_get_scanner_issues`, `get_scanner_issues` and authorized security-report
counts; owned audit status only if a controlled audit already exists. Check decoded
root/attachment membership, metadata/definition/status/URL/content-type/reason,
synthetic credential absence, counts, pagination and invalid-input errors. PASS
requires positive allowed records and absent excluded records/metadata/canaries.
Empty/end results or unsupported status are BLOCKED, not PASS. Any unauthorized
disclosure is FAIL and release-blocking.

Supported potential zero-traffic setup is Montoya `SiteMap.add(AuditIssue)` with
documented `AuditIssue.auditIssue` factories, present in the compile API baseline.
A separate test-only helper was prepared locally but never loaded or seeded.
Its native retention/deduplication/attachment behavior is unverified. Loading,
one-shot seeding and human removal of only owned synthetic issues each need
separate approval. No issue-removal API is assumed; unloading does not delete data.
Seeding proves storage/serialization, not Scanner engine discovery or audit-status
generation. Reviewed helper source and pure offline checks are preserved in
[test support](../test-support/README.md); its JAR remains local and native behavior
unqualified. Source availability does not authorize build/load/seed. No scan is implied.

Cleanup: preserve only sanitized assertions/digests, remove owned seeded data by
the separately approved native procedure, and verify the common inactive state.

Native paging specifics: modern list max count 25, legacy max 100; test count
0/-1, negative offset, oversize 26/101 and wrong types with bounded sanitized errors.
Modern empty JSON and legacy end sentinels are distinct output contracts. Approved
controlled-data subwindows must also cover deny/approval-timeout without retry.
No sanitizer proves the provenance of arbitrary prose within an otherwise authorized
finding: current policy filters root records and attachments and redacts known
credential forms. The stronger claim that authorized prose cannot mention an
out-of-scope URL remains unestablished and needs explicit policy review if required.

## Batch C Priority and conflict

Exact target `http://127.0.0.1:8000/test-post-phase2`, POST, **two total attempts**
in two independent one-attempt windows. Each: native preparation grant at most
300 seconds, session/TTL at most 120 seconds, request-rule budgets 2/2. No
response rule or DROP. C1: enabled=true writer priority 200, false writer priority
100, compatible `X-MCP-Rule-Test: active` header writer. C2: equal priority 100
conflicting true/false writers. Freeze each window's specs before native approval.
PASS: C1 correct winner/header/contributor counters; C2 whole original unchanged,
conflict event and zero modifications. Exactly one origin per attempt. Stop on
partial edits or common failure conditions. C0 between windows.

## Batch D Expiration and revocation

Same exact Phase 2 target, **two POST attempts total**, isolated windows, each
with native 300-second grant and 60-second session/TTL, two reviewed request/response
rules with 2/2 budgets. D1 sends once with more than 30 seconds remaining, observes
expiry for at most 75 seconds without a post-expiry send, then checks stale-use
rejection. D2 sends once, checks queues, obtains native session-stop approval,
and checks revocation/stale-reference rejection. PASS: one origin each, inactive
authority cannot revive, correct deadlines and cleanup. C0 after each.
Optional separately approved grant-only expiry: zero exchanges, 15-second native
grant, no rules/session, observe at most 25 seconds. In-flight expiry races remain
synthetic evidence until a safe native trigger is independently approved.

## Batch E Destination and response association

Only physical destination `127.0.0.1:8000`, **four POST attempts maximum**:
Phase 2 exact path; Phase 2 `?case=destination-safe`; `/test-post` wrong-path
control; Phase 2 with `Host: localhost:8000` mismatching-host control. Approval
must explicitly include all variants. Native 300-second grant authorizes only
the exact Phase 2 path; native session/TTL 120 seconds, two A rules with 4/4
budgets. PASS: first two transform/associate correctly; controls remain unchanged
with no modification increments, exactly four attributable origins and no crossed
responses. Retain any fixture Host-rejection status rather than inventing success.
Stop on unknown delivery, unauthorized edits or association mismatch; C0. No
external/wrong-port/HTTPS requests. Forged native IDs/replays remain synthetic
unless a safe supported native mechanism is separately approved.

## Batch F Manual reliability and queue isolation

Five one-shot attempts total, exact HTTP localhost paths `/test-cancel`,
`/test-concurrent-a`, `/test-concurrent-b`, `/test-timeout`, `/test-session-expiry`.
The saved readiness plan uses synthetic GET controls for cancel/timeout/expiry,
POST URL-encoded forms for both A and B; freeze exact payloads before approval.
No preparation grants, target sessions/rules or unattended mode. Two native
managed-session windows: first at most 300 seconds with 60-second message timeout;
second 60 seconds with separately approved 120-second message timeout. Restore
prior timeout only after queues are empty and with the relevant approval.
Native activation/termination, disclosure, exact-revision approval/forward and
needed request-drop decisions remain human-controlled. PASS: cancel/timeout/expiry
zero origins; A/B each one origin, B releases while A stays held, correct individual
edits and association, no stale/crossed decisions and empty queues. Keep the fixture
alive to prove zero delivery; absent fixture is not proof of cancellation. No
legacy unattended runner. C0 between windows; saturation remains unverified.

## Batch G Emergency Stop and recovery

Two attempts maximum, independent approved windows. G1: one Phase 2 POST, native
300-second grant/120-second target session/TTL, two A rules with 2/2 budgets;
then explicitly approved Emergency Stop with empty queues. G2: one held
`http://127.0.0.1:8000/test-cancel` request in a new native 60-second managed
session; Emergency Stop is explicitly authorized to drop it. Fresh human-visible
activation/approval is required between windows. No target DROP.
PASS: G1 one origin if sent, G2 zero origins, latch engaged, authority invalidated,
stale references denied, held message dropped and queues empty. C0 leaving the
terminal latch engaged. Recovery is a separate zero-exchange approved operation:
empty-state unload/reload/reconnect or fresh activation as specifically authorized.
Observe actual latch/callback state; do not assume reload retains it.

## Batch H Remaining native integration

Each subwindow needs individual operator/native approvals and C0; at most 120
seconds per operation, no preparation grant or target session.

| Window | Target and exchange cap | Required assertion and cleanup |
|---|---|---|
| H1 protected reads / optional Organizer | Owned synthetic history on `/test-post` or Phase 2; zero new exchanges; count <=20, offsets 0/1 | Correct redacted scoped content and owned Organizer effects if approved. Runtime-unavailable does not pass retrieval; remove only owned data. |
| H2a explicit send | `http://127.0.0.1:8000/test-post`; one send maximum | One origin, correct framing/association, no retry. Unresolved native send is UNKNOWN and stops later work. |
| H2b Repeater insertion | Same target; zero exchanges; never click Send | Correct owned tab/request, no origin, approved removal of only owned tab. Enumeration remains unsupported. |
| H2c owned passive audit | Same target; at most one expected origin from one approved invocation | No active audit/crawl. Stop before invocation if scheduling cannot meet cap. Verify owned audit/status, metadata and approved stop/delete; otherwise BLOCKED. Passive does not mean zero traffic. |
| H3 Proxy / extension lifecycle | Local native UI only; zero exchanges | Separately approved Proxy ON then OFF and empty-state reload; one loaded instance, reconnection, no stale authority. Snapshot alone cannot prove callback uniqueness or held-message unload behavior. |

Collaborator generation/polling is outside localhost-only authorization. No
remaining plan result may be marked LIVE TESTED until its independent evidence
and final cleanup satisfy the approved contract.
