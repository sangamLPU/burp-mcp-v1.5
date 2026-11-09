# Development checkpoint on 7 November 2026

**Development is at the v1.5.0-dev.7 packaging checkpoint. This is neither a release candidate nor a
stable v1.5.0 release.** The feature set is frozen. v1.4.0 remains the verified
rollback release. Start with [agent setup](AGENT_SETUP.md); remaining supervised
work is summarized in [the campaign plan](SUPERVISED_CAMPAIGN.md).

## dev.7 supervised browser case: 9 November 2026

**LIVE VERIFIED for one synthetic exact-target case.** A separately authorized
single browser POST to `/test-form-browser-validation` passed through Burp's
built-in Chromium. The human reported one click and supplied the browser JSON;
the independent origin logged one delivery and verified the modified form and
framing. Both rules recorded exactly one match, modification and forward, with
the same request/response message ID. The request exhausted its one-match budget
before the associated response was modified. The origin's `serverVerified` and
the added `browser_verified` were both true in the user-reported response. This
verifies the dev.7 final-budget association correction for that one case only.

The browser's raw original request was not separately exported from history;
its original marker is supported by the prepared form and the request rule's
match condition. Cleanup verified no remaining grants, session, rules, held
messages or fixture listener; unattended mode inactive, Emergency Stop clear and
native Proxy Intercept OFF. Local-only evidence is under
`build/reports/dev7-supervised-20261109T075819Z/`. The other supervised campaign
and native Scanner denial-attribution gates remain open. This is not a release
candidate or general validation of arbitrary sites, credentials or body formats.

## dev.7 runtime preflight: 9 November 2026

The human loaded dev.7 and enabled edit proposals. Current read-only observations
confirm one loaded MCP extension at the qualified JAR path, runtime build
`20261109.1-rule-association-fix-dev`, authenticated initialization, 89 unique
tools, original nine enabled scope prefixes and sole localhost allowlist entry.
Native Proxy Intercept is OFF; required approvals/filtering and bearer authentication
are ON, and persistent Always Allow exceptions are OFF. Managed interception and
unattended mode are inactive; no grants, rules or queued messages; Emergency Stop
clear. The documented non-traffic preflight returned PASS, exit 0, with no
application traffic. Its full sanitized result is in ignored report
`build/reports/dev7-runtime-preflight-20261109T061603Z/`.

The dedicated browser profile remains uncreated/unverified and actual proxy
traffic is unproven. The isolated demo remains inert. A separately authorized
exact one-POST plan and fresh native grant/session decisions are required. No
dev.7 live transformation or Scanner decision has been tested by this preflight.

## dev.7 packaging addendum: 9 November 2026

The corrected source is packaged as **1.5.0-dev.7**,
`20261109.1-rule-association-fix-dev`, at
`build/dev-v1.5.0/libs/burp-mcp-1.5.0-dev.7-all.jar`, SHA-256
`c2a0acb4d6e149c6df1056e5287fe3335583ac291f38c138a436cf649f46a26e`.
It is a development checkpoint, not a release. At packaging time the running
instance was still dev.6; see the newer runtime preflight above. Strict coordinator
identity checks now require dev.7 and reject dev.6; do not run traffic-producing
coordinator modes. After reload and human-enabled live edits, run only the
documented `--target-preflight-only` and record its actual result. This gate now
checks the revised browser-demo URL as well as the existing Phase 2 target.

Gradle development packaging and 109 focused JVM checks passed, including the
two Scanner listing permission tests. A subsequent 31-case target-session run
passed including the exact proposed form pair; catalog integration verified 89
unique names. These runs overlap and must not be summed. Python coordinator tests
(33), 15 pure fixture assertions and seven pure proposed-fixture cases passed.
ZIP integrity, manifest, 742 project class headers/Java 17 bytecode and matching
compiled classes passed; six Scanner-named classes match dev.6 byte-for-byte.
These checks do not prove live behavior or resolve the historical native Scanner
decision-attribution gap. dev.6, stable v1.4.0 and historical evidence are retained.

The exact `/test-form-browser-validation` proposal and isolated fixture remain
disabled/prepared; no fixture, browser, grant, session or application request was
started. Corrected runtime identity, security, scope, allowlist, queues and native
Proxy Intercept must be observed after human replacement. Live edits require the
human's separate local checkbox action. Browser routing and actual traffic remain
unverified. See [browser/Burp workflow](BROWSER_BURP_WORKFLOW.md).

## Recovery addendum: 9 November 2026

The following describes the earlier recovery state before dev.7 packaging above.

Repository recovery started clean on `dev/v1.5.0` at
`e86eeca7920395a4df4e7bd760e97be274c83e64`. No commit, push, reload or packaging
was performed. Runtime remains the qualified dev.6 build; its and stable v1.4.0's
artifact hashes are unchanged. See [browser/Burp workflow](BROWSER_BURP_WORKFLOW.md)
for current native/MCP observations, manual browsing and browser-controller recovery.

Restored nine-prefix scope and exact localhost allowlist are verified. Native
security controls are observed enabled, persistent exceptions unchecked, native
Proxy Intercept OFF and Temporary Project selected. Windows native Computer Use
works; browser access host remains unavailable. Effective dedicated-browser proxy
routing and future HTTPS trust remain unverified. No application traffic occurred.
The documented non-traffic preflight exits 2 because live edits remain OFF; no
permission setting was changed. A PASS would not validate the original demo plan.

Two additional preparation findings must survive handoff:

- The original `/test-form` demo incorrectly uses target preparation/session
  authority for a reserved legacy localhost rule target. Its rule creation and
  session path reject this with unattended mode inactive. Keep the original page
  disabled and specs inert; revise the plan rather than bypassing that restriction.
  An isolated, disabled proposal at `/test-form-browser-validation` with matching
  copied fixture and review-only browser launch description is prepared privately;
  fixture syntax/seven pure form cases/origin JSON schema checks pass, but this
  proposal is not approved, launched or browser/traffic verified.
- A focused synthetic regression reproduced a product defect: request-rule budget
  exhaustion removes its revision from the response association's ACTIVE-only
  snapshot, skipping a separately authorized paired response. The working-tree
  source correction retains MAX_MATCHES/MAX_MODIFICATIONS rules in association
  identity only, keeps evaluation and budgets unchanged, and checks original
  revisions again at final release. This correction is **not in the loaded JAR**.

Final affected source validation passed 107 JVM tests across BuildInfo,
InterceptionRuleEngine, LiveInterception, TargetLiveSession, TargetRuleAuthorization
and UnattendedLocalTestMode; 33 coordinator tests and 15 pure fixture assertions
also passed. Seven new target-session cases cover prefix isolation, reserved-path
dispatch, one-budget pairs, repeated pairs, modification-budget exhaustion,
pause/delete of exhausted rules and pause/resume during response materialization.
The failing one-budget reproduction and before/after reports are preserved in a
new ignored recovery evidence directory. These results do not supersede historical
live verification or resolve the native Scanner-denial evidence gap.

A new unique development artifact was required to deploy the source fix; dev.7
has now been prepared as described above, and reviewed reload remains required.
Do not silently overwrite the qualified dev.6 JAR or adjust strict
preflight identity checks to conceal a source/runtime mismatch. Demonstration
readiness remains BLOCKED pending a valid revised exact test plan, live-edit
approval/configuration, dedicated browser routing and deployment of the correction.

## Source and artifact identity

| Item | Checkpoint |
|---|---|
| Branch | `dev/v1.5.0` |
| Build | `20261107.3-scanner-permission-hardening-dev` |
| Repository | `sangamLPU/burp-mcp`, PRIVATE as checked on 2026-11-07 |
| Starting HEAD | `2170934a53cdfec123d62844979aed330ab27ac3` |
| Core hardening local commit | `9ca1cfdc387d259d1edda529e8d63fa982708388` |
| Regression/infrastructure local commit | `6c004fc6075bf2413befc967d61c78c7a2a507f7` |
| History | Existing target-grant/session and connection fixes retained; reviewed hardening, regression/infrastructure and handoff commits follow the starting HEAD |
| Publication | Local checkpoint only; no push, merge, tag or release performed |
| Runtime baseline | Burp Suite Professional 2024.1.1.1; Montoya compile API 2023.12.1; Java 17 bytecode |
| Development JAR | `build/dev-v1.5.0/libs/burp-mcp-1.5.0-dev.6-all.jar` |
| Qualified JAR SHA-256 | `2dc9a09331397f3cf7dddf0b9bf6f9460d26eb9a5e3742c322b7fa07ee6859dc` |
| Stable v1.4.0 JAR SHA-256 | `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2` |

The final documentation commit cannot contain its own hash. Use `git log -3
--oneline`, `git rev-parse HEAD`, `git status --short` and `git branch -vv` for the
actual final IDs, cleanliness and remote relationship. A local commit does not
make the remote branch current. JARs, private reports and environment configuration
are intentionally absent from Git; preserve them separately before changing machines.

## Implemented work preserved

- Exact-path, expiring native-approved target preparation grants and a separately
  approved execution session binding immutable rule specifications and IDs.
  Service/Host/path enforcement, one-use response association, revocation and
  bounded rule budgets remain part of the existing architecture.
- HTTP JSON/query/form/header/text transformations with protected headers,
  byte-accurate body framing, charset checks, deterministic conflict handling
  and rollback of unsuccessful speculative edits.
- Loopback-only bearer-authenticated MCP; Host/Origin validation; strict coordinator
  response parsing and failure/readiness handling. The Professional catalog has
  89 unique tools, including legacy aliases; registration is not live verification.
- Scoped Scanner roots, independently scoped attachments and authorized-only
  report counts. Metadata, URL, content-type, reason text and definition identifiers
  use bounded credential-redacted untrusted rendering.
- The legacy `get_scanner_issues` native HTTP-history permission gate now runs
  before issue enumeration, matching the protected newer listing path.
- Standard-library Python preflight/coordinator helpers, synthetic fixtures and
  regressions for malformed results, authorization, lifecycle, framing and encoding.

No production code was changed during the final documentation/checkpoint task.
The inventory generator's stale permission/build descriptions were corrected;
without supplied passing JUnit XML it now leaves test references unqualified.
Historical generated matrices remain frozen rather than being overwritten.
Reviewed synthetic oracle/transport and seed-helper source was copied unchanged
into [test support](../test-support/README.md) so it survives a source clone.
Compiled helpers, private observations and logs remain ignored and local.

## Evidence classifications

| Evidence | Verified result and limit |
|---|---|
| UNIT / INTEGRATION TESTED, dev.5 offline baseline | 303 JVM tests, 118 Python tests, four offline PowerShell suites and 24 script syntax checks passed. Tool matrix: 78 integration-level, 10 unit-level, one unsupported. Mocked Montoya and embedded MCP transport are not native side-effect proof. |
| INTEGRATION TESTED, dev.6 correction | The denied-permission regression first reproduced the legacy bypass; corrected focused neighboring run passed 91 JVM tests. Five package/permission checks then passed under dev.6 identity, including two overlapping permission methods. Do not add these as unique totals or claim a new full 305-test run. |
| OFFLINE TESTED, dev.6 preparation | 49 coordinator Python tests, 26 report-local oracle/transport tests, seven test-helper assertions and 15 pure fixture checks passed. Report-local helpers are private preparation artifacts, not approved live runners. |
| RUNTIME VERIFIED, dev.6 | One loaded MCP extension, exact path/manifest/hash/running build, authenticated initialization, 89 expected unique tools and non-traffic target preflight passed. Configured loopback scope/host policy and safe state were observed. |
| LIVE TESTED, dev.5 Batch A only | Exactly three POST attempts to `/test-post-phase2`, three HTTP 200 clients and three independent origin deliveries. Two rules each matched/modified/forwarded three times; body/header/framing, case/hash response association, native grant/session approvals and full cleanup agreed. |
| RUNTIME VERIFIED with an unresolved decision, dev.6 | One later negative-only legacy Scanner call returned `isError=true` and the exact public permission-denied error without Scanner data. Project-data approval stayed required and Always allow HTTP history stayed unchecked. The actual native dialog category and human DENY selection were not conclusively captured. This explicit-human-denial gate remains BLOCKED. |

The final checkpoint validation re-executes only the five BuildInfo/Scanner-permission
JVM checks, 33 coordinator tests, 26 copied offline-support tests and 15 pure Phase 2
fixture assertions. Python syntax (18 files), PowerShell syntax (24 scripts),
42 local documentation links and two inventory evidence-qualification smoke runs
also pass. It does not rerun a live campaign or
rebuild the JAR. The broader results above retain their original versions and dates.

Batch A remains historical dev.5 evidence. Although dev.6 interception classes were
reported byte-identical, that is not a repeated dev.6 live test or proof of Scanner,
adversarial destination, priority/conflict, expiry, timeout or Emergency Stop behavior.

## Remaining release blockers and limitations

1. Confirm the dialog category and actual human decision for the already completed
   negative attempt. A denied result does not prove which native button was chosen.
   The earlier unexpected unchecked-to-checked permission transition remains
   historically unexplained; it was not reproduced by the later denied call.
   Do not retry or change permissions under old authorization.
2. Batch B needs nonempty controlled native findings with known provenance and
   allowed/excluded roots, attachments and synthetic metadata sentinels. Test
   paging/counts/errors and positive visibility as well as absence of forbidden
   data. Empty lists cannot pass. Any disclosure is release-blocking.
3. Native Scanner audit/status behavior, target-rule priority/conflict, expiration,
   revocation, destination/association negatives, cancellation/timeouts/queue
   isolation, Emergency Stop and recovery still need the approved B-H subwindows.
4. Repeater tab enumeration is unsupported by Montoya. Project identification and
   Organizer retrieval may be unavailable on this Burp API/runtime. Community is
   not the qualified 89-tool runtime; Scanner/Collaborator need Professional.
5. Active auditing is disabled. Collaborator can contact an external service and
   is outside the localhost campaign. No unrestricted crawl or audit is approved.
6. Rule body edits are bounded UTF-8 JSON/forms or literal plain/HTML text.
   Multipart, compressed, binary, chunked, streaming and WebSocket rule transforms
   are unsupported. Target sessions reject DROP. Credential filtering is heuristic.
7. Native send cancellation cannot be guaranteed on Burp 2024.1. Client timeout is
   not zero origin deliveries. Two concurrent clients do not prove slot saturation.
8. These requested files are missing, not integrated or tested:
   `docs/Burp_MCP_Manual_Setup_and_Use.docx` and
   `docs/Burp_MCP_Agent_Automated_Setup_Runbook.docx`.
   README and AGENT_SETUP provide usable text instructions in the meantime.

## Evidence retained locally

The following paths are local-only references, not links expected to exist in a
source clone. Do not stage their raw reports, traffic, logs or helper JARs.

| Local report directory under `build/reports/` | Purpose |
|---|---|
| `feature-freeze-20261107T114604Z/` | Offline baseline, tool matrix, defects, results and artifact checksums |
| `dev5-runtime-20261107T144748Z/` | Native identity/security observations and original `LIVE_CAMPAIGN.md` |
| `dev5-scope-restoration-20261107T151505Z/` | Approved scope/allowlist delta and restored policy |
| `dev5-batch-a-20261107T153445Z/` | Frozen Batch A evidence, all 43 files preserved |
| `post-batch-a-preparation-20261107T155141Z/` | Legacy permission repro/fix, focused regressions, B/C-H plans and unexecuted test-only helpers |
| `dev6-post-replacement-20261107T164110Z/` | Qualified loaded dev.6 artifact and first inconclusive probe |
| `dev6-native-denial-20261107T165827Z/` | One denied follow-up, unchanged permissions and unconfirmed native decision |
| `private-checkpoint-20261107T173744Z/` | Starting-file backups, preservation/secret review, fast checks and final local commit inventory |

Each frozen report has checksum evidence. Do not rerun historical evidence writers
in place. Useful sanitized conclusions live here so a clone can resume planning
without private data; original evidence must be recovered from the owner's local
backup when a claim needs re-examination.

## Resume in this order

1. Recover Git state, intended Burp project, actual loaded artifact and authenticated
   safe state using AGENT_SETUP. Do not assume persisted state survived a restart.
2. Resolve the already completed native-decision evidence gap with the human.
   If still inconclusive, seek fresh authorization for a separately supervised
   negative-only attempt; no automatic protected-data read or retry.
3. Obtain separate approval for a narrowly filtered controlled-finding inventory.
   If suitable findings are missing, review a separately authorized zero-traffic
   Montoya seeding option and cleanup before any load/seed. Do not start Scanner
   or application traffic to obtain findings without its own authorization.
4. Execute only the individually approved B-H subwindows, collecting independent
   evidence and verifying cleanup after each. Never repeat Batch A by default.
5. Fix only reproduced defects, add focused regressions, and issue a new uniquely
   identified development artifact if production code changes. Reload requires
   its own review. Reassess release readiness only after blockers are resolved.

No live batch, unattended activation, security-setting change, push or publication
is authorized by this checkpoint.
