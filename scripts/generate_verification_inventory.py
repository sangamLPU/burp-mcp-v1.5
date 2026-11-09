"""Build an evidence-linked catalog without calling tools or sending traffic.

Inputs are an explicitly captured tools/list response, Kotlin handlers/tests and
the named verification run. Registration and mock coverage are never live PASS.
"""
import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mask_kotlin(text):
    # Preserve offsets while excluding braces in literals and comments.
    pattern = r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def snake(name):
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', re.sub(r'([A-Z])([A-Z][a-z])', r'\1_\2', name)).lower()


def handlers():
    result = {}
    for path in (ROOT / 'src/main/kotlin').rglob('*.kt'):
        if path.name == 'McpTool.kt':
            continue
        text = path.read_text(encoding='utf-8')
        masked = mask_kotlin(text)
        for match in re.finditer(r'\b(mcpTool|mcpUnitTool|mcpPaginatedTool)(?:<([^>]+)>)?\s*\(', text):
            # Only registration invocations, not definitions/comments/literals.
            if masked[match.start():match.start()+3] != 'mcp':
                continue
            pos = masked.find('{', match.end())
            depth, end = 1, pos + 1
            while depth and end < len(masked):
                depth += (masked[end] == '{') - (masked[end] == '}')
                end += 1
            prefix = text[match.end():pos]
            strings = re.findall(r'"((?:\\.|[^"\\])*)"', prefix)
            if match[2]:
                name = snake(match[2].split(',')[0].strip())
                input_type = match[2].split(',')[0].strip()
            else:
                if not strings:
                    continue
                name, input_type = strings[0], None
            if name in result:
                raise ValueError('duplicate registration ' + name)
            description_parts = strings if match[2] else strings[1:]
            description = ''.join(json.loads('"'+s+'"') for s in description_parts)
            result[name] = {'source': path.relative_to(ROOT).as_posix(), 'line': text[:match.start()].count('\n')+1,
                            'sourceDescription': description,
                            'inputType': input_type, 'registrationKind': match[1],
                            'handler': text[pos:end]}
    return result


def direct_tests():
    evidence = {}
    for path in (ROOT / 'src/test/kotlin').rglob('*.kt'):
        text = path.read_text(encoding='utf-8')
        tests = list(re.finditer(r'@Test\s+(?:fun|suspend fun)\s+`([^`]+)`', text))
        for index, test in enumerate(tests):
            block = text[test.end():tests[index+1].start() if index+1 < len(tests) else len(text)]
            names = re.findall(r'\.callTool\(\s*"([a-z0-9_]+)"', block)
            if test[1] in {
                'history and analysis tool outputs filter scope and redact synthetic credentials',
                'security analysis and response comparison return bounded meaningful observations',
                'secondary content type metadata does not disclose credential values',
                'encoded credential query names are redacted in metadata URLs',
            }:
                names += re.findall(r'"((?:burp_|get_)[a-z0-9_]+)"', block)
            if test[1] in {
                'both scanner listing tools withhold out of scope attached HTTP exchanges',
                'scanner listing permission denial protects both APIs before issue access',
                'scanner listing permission approval preserves both APIs filtering and redaction',
            }:
                names += ['burp_get_scanner_issues', 'get_scanner_issues']
            for name in names:
                evidence.setdefault(name, []).append({'source': path.relative_to(ROOT).as_posix(),
                    'test': test[1], 'line': text[:test.start()].count('\n')+1,
                    'kind': 'embedded MCP transport with mocked Montoya; not live Burp'})
    return evidence


def unit_tests(handler):
    calls = set(re.findall(r'live\.(\w+)\(', handler['handler'])) - {'touch', 'health', 'unattendedSnapshot'}
    engine_calls = set(re.findall(r'live\.ruleEngine\.(\w+)\(', handler['handler']))
    analysis_calls = set(re.findall(r'SecurityAnalysis\.(\w+)\(', handler['handler']))
    result = []
    for path in (ROOT / 'src/test/kotlin').rglob('*.kt'):
        if path.name in ('McpServerIntegrationTest.kt', 'ToolsKtTest.kt'):
            continue
        text = path.read_text(encoding='utf-8')
        matches = list(re.finditer(r'@Test\s+(?:fun|suspend fun)\s+`([^`]+)`', text))
        for index, test in enumerate(matches):
            block = text[test.end():matches[index+1].start() if index+1 < len(matches) else len(text)]
            found = [m for m in calls if re.search(r'\.'+re.escape(m)+r'\(', block)]
            found += ['SecurityAnalysis.'+m for m in analysis_calls if re.search(r'SecurityAnalysis\.'+re.escape(m)+r'\(', block)]
            if path.name == 'InterceptionRuleEngineTest.kt':
                found += [m for m in engine_calls if re.search(r'\bengine\.'+re.escape(m)+r'\(', block)]
            if found:
                result.append({'source': path.relative_to(ROOT).as_posix(), 'test': test[1],
                    'methods': sorted(found), 'kind': 'synthetic subsystem operation; native dialogs/Montoya are mocked'})
    return result


NETWORK = {'send_http1_request', 'send_http2_request', 'burp_send_http_request', 'burp_start_scan',
           'burp_send_to_repeater', 'create_repeater_tab', 'create_repeater_tab_http2'}
STATE = {'set_project_options', 'set_user_options', 'set_active_editor_contents', 'set_proxy_intercept_state',
         'burp_set_proxy_intercept_state', 'set_task_execution_engine_state', 'burp_configure_local_test_scope',
         'generate_collaborator_payload', 'burp_stop_scan'}
RULE_WRITES = {'burp_create_interception_rule', 'burp_update_interception_rule', 'burp_enable_interception_rule',
              'burp_disable_interception_rule', 'burp_delete_interception_rule', 'burp_clear_interception_rules',
              'burp_clear_interception_rule_stats', 'burp_pause_all_interception_rules', 'burp_emergency_stop_rules'}


def policy(name, h):
    code = h['handler']
    change = name in NETWORK | STATE | RULE_WRITES or any(x in name for x in
        ('_propose_intercepted_', '_approve_intercepted_', '_drop_intercepted_', '_forward_intercepted_',
         '_request_intercept_disclosure', '_request_target_rule_authorization', '_start_target_rule_session',
         '_set_live_interception_state', '_cancel_interceptions'))
    native = 'No additional prompt for this read/pure computation.'
    authz = []
    if name in NETWORK:
        authz += ['Write mode, current Burp scope and explicit host allowlist, bounded rate capacity; per-operation approval. Repeater insertion itself does not send.']
        native = 'Required once per operation, even for allowlisted destinations.'
    if name in STATE:
        native = 'Required for mutation; config editing also requires its local opt-in. Collaborator may contact the configured service; never tested here.'
        authz += ['Read-only mode off and StateChangeSecurity or HTTP authorization handler; inspect linked handler for capability-specific checks.']
    if name in RULE_WRITES or name == 'burp_preview_interception_rule':
        authz += ['Create/update: bearer-authenticated write mode, empty queues, current synthetic identity or exact preparation grant. Enable: healthy approved session, rule/spec binding, bounded remaining TTL, live edits for modifications. Safety pause/delete/clear/counter operations do not grant execution. Preview currently requires unattended synthetic identity, not a target grant.']
        native = 'No per-call prompt for rule management; existing human activation/grant/session prerequisites apply. Emergency Stop immediately latches and drops held traffic without approval.'
    if 'intercepted_' in name or 'intercept_disclosure' in name:
        authz += ['Held-message ID/kind and revision checks. Editing requires write mode/live-edit control. Disclosure is separate from exact-revision forwarding permission.']
        native = ('Required for disclosure, approval, forward or drop unless the existing bounded synthetic local policy explicitly permits that operation; get/list expose metadata only before disclosure.' if any(x in name for x in ('approve_', 'forward_', 'drop_', 'disclosure')) else 'No prompt for metadata/proposal; content disclosure and final execution remain separately approved.')
    if name in {'burp_request_target_rule_authorization', 'burp_start_target_rule_session'}:
        authz += ['Exact canonical HTTP(S) origin/path already in static scope and exact host:port allowlist; authentication/write mode, queues empty. Preparation is not execution. Session requires immutable rule IDs/specifications, allowed operations, grant lifetime and inactive unattended mode.']
        native = 'Mandatory fresh native Approve once; unattended mode cannot substitute. Invocation requires separate operator campaign authorization.'
    if name in {'burp_set_live_interception_state', 'burp_cancel_interceptions'}:
        authz += ['Bounded managed session and existing safety checks. Stopping/canceling can drop held traffic.']
        native = 'Native approval required except explicitly eligible bounded local policy paths; cancel always prompts.'
    if 'requireHistoryAccess' in code or 'accessibleHistoryItem' in code or 'accessibleProxyHistory' in code:
        authz += ['HTTP-history permission plus scope/allowlist filtering; redaction and untrusted-data labeling.']
        native = 'Conditional data-access prompt through requireHistoryAccess; disabled approval or prior explicit Always Allow changes this behavior.'
    if 'checkDataAccessOrDeny' in code:
        authz += ['DataAccessSecurity approval unless explicitly disabled or previously allowed; per-item scope/host filtering.']
        native = 'Conditional data-access prompt; prior explicit Always Allow or disabled approval changes this behavior.'
    if name == 'get_scanner_issues':
        authz += ['Professional-only legacy Scanner listing: dev.6 checks the HTTP-history native data-access permission before issue enumeration; each finding and attached exchange is independently scope/host filtered.']
        native = 'Conditional HTTP-history data-access approval, as for burp_get_scanner_issues. Keep approval required and persistent Always Allow disabled for denial verification; a denied result alone does not establish the exact human dialog decision.'
    if name in {'output_project_options', 'output_user_options'}:
        authz += ['Configuration export has no native prompt. Credential filtering is operator-configurable; keep filterConfigCredentials enabled. Configuration-editing permission is separate and does not gate export.']
    if name == 'get_active_editor_contents':
        authz += ['Reads only the focused editor in the Burp frame; redacted/untrusted rendering. No target-scope filter or additional native prompt is applied to this explicit editor read.']
    if name == 'get_collaborator_interactions':
        authz += ['Professional-only poll of this extension Collaborator client; can contact the configured external service. No target-scope or per-poll native approval gate. External execution is outside this localhost campaign.']
        native = 'No per-poll prompt in the existing handler; do not execute under localhost-only authorization.'
    if name == 'burp_configure_local_test_scope':
        authz += ['Adds only the fixed nine localhost prefixes and exact host:port; ordinary configuration-editing opt-in is not required. Existing eligible unattended policy can replace per-call approval, but is inactive in this campaign.']
        native = 'Required Approve once while unattended mode is inactive; do not enable unattended mode to bypass it.'
    if not authz:
        authz = ['Authenticated transport; validation/capability/pagination checks in linked handler. No target execution authority is obtained.']
    return {'mode': 'STATE_CHANGING' if change else 'READ_ONLY_OR_PURE', 'authorization': authz, 'nativeApproval': native}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-dir', type=Path, required=True)
    parser.add_argument('--test-results-dir', type=Path, help='Use executed JUnit evidence to qualify test references')
    parser.add_argument('--historical-report-dir', type=Path, help='Retain earlier evidence separately; never promote it to current live evidence')
    args = parser.parse_args()
    out = args.report_dir.resolve()
    catalog_document = json.loads((out / 'runtime-catalog.json').read_text(encoding='utf-8'))
    catalog = catalog_document['tools']
    catalog_evidence = catalog_document.get('_evidence', {'kind': 'captured-unqualified', 'build': None})
    historical = {}
    if args.historical_report_dir:
        prior = json.loads((args.historical_report_dir / 'tool-coverage.json').read_text(encoding='utf-8'))
        historical = {row['name']: {'status': row['status'], 'runtimeEvidence': row['runtimeEvidence'],
            'qualification': 'Earlier campaign evidence; not a current runtime execution'} for row in prior['tools']}
    passed = None
    if args.test_results_dir:
        passed = set()
        result_files = list(args.test_results_dir.glob('TEST-*.xml'))
        if not result_files:
            raise ValueError('No executed JUnit XML evidence found')
        for path in result_files:
            for case in ET.parse(path).getroot().findall('testcase'):
                if case.find('failure') is None and case.find('error') is None and case.find('skipped') is None:
                    owner = case.get('classname', '').split('.')[-1].split('$')[0]
                    passed.add((owner, case.get('name', '').removesuffix('()')))
    def qualify(refs):
        for ref in refs:
            ref['executedPassing'] = passed is not None and (Path(ref['source']).stem, ref['test']) in passed
        return refs
    implementation, tests = handlers(), direct_tests()
    assert len(catalog) == len({t['name'] for t in catalog}) == 89
    assert {t['name'] for t in catalog} == implementation.keys(), (set(implementation) ^ {t['name'] for t in catalog})
    observed = {}
    for filename in ('runtime-readonly.json', 'runtime-safe-tools.json'):
        if not (out / filename).exists():
            continue
        for result in json.loads((out / filename).read_text(encoding='utf-8')):
            if result['status'] == 'fulfilled':
                entry = result['value']
                observed[entry['tool']] = {'file': filename, 'result': entry['result']}
    if (out / 'scope-restoration-proposal.json').exists() and catalog_evidence['kind'] != 'embedded':
        observed['output_project_options'] = {'file': 'scope-restoration-proposal.json', 'result': None,
            'qualification': 'Actual response JSON parsed and target.scope extracted. Full configuration deliberately not persisted; this is scope-export evidence only.'}
    rows = []
    for tool in sorted(catalog, key=lambda t: t['name']):
        name = tool['name']
        h = implementation[name]
        units = qualify(unit_tests(h))
        direct = qualify(tests.get(name, []))
        p = policy(name, h)
        live = observed.get(name)
        status = 'VERIFIED — LIVE' if live else 'VERIFIED — INTEGRATION' if any(r['executedPassing'] for r in direct) else 'VERIFIED — UNIT' if any(r['executedPassing'] for r in units) else 'IMPLEMENTED — NOT VERIFIED'
        limitation = 'No fresh live application traffic; authorization-sensitive execution requires separately approved batch.'
        if name == 'burp_get_repeater_tabs':
            status = 'NOT APPLICABLE'
            limitation = 'Enumeration is unsupported by Montoya. Earlier error evidence is retained separately; creating tabs remains a separate supported operation.'
        if name == 'burp_get_project_info':
            limitation = 'Burp 2024.1 lacks project(); explicit unavailable result verified, project identity requires native UI.'
        try:
            payload = json.loads(live['result']['content'][0]['text']) if live else None
            shape = {'type': type(payload).__name__, 'fields': list(payload) if isinstance(payload, dict) else None}
        except (ValueError, KeyError, IndexError, TypeError):
            shape = {'type': 'JSON object', 'fieldsObserved': ['target.scope'], 'partialObservation': True} if name == 'output_project_options' else {'type': 'text'}
        errors = ['isError=true TextContent for caught exceptions; generic sanitized exception class except McpToolError public messages. Coroutine cancellation propagates.']
        errors += sorted(set(re.findall(r'"([A-Z][A-Z_]{3,})"', h['handler'])))
        if 'Denied' in h['handler'] or 'denied' in h['handler']:
            errors += ['Some legacy denials are plain text with isError=false; clients must validate expected acknowledgements and independent state.']
        rows.append({
            'name': name, 'description': h['sourceDescription'], 'observedRuntimeDescription': tool.get('description'),
            'actualPurpose': {'summary': h['sourceDescription'], 'calledOperations': sorted(set(re.findall(r'\b(?:live|api|ruleEngine|SecurityAnalysis|MontoyaRuntimeCompat)\.([A-Za-z0-9_.]+)\(', h['handler']))),
                'qualification': 'Complete source handler below is authoritative; descriptions alone do not establish behavior.'},
            'purposeEvidence': f"{h['source']}:{h['line']} (complete handler included; description is not execution evidence)",
            'inputSchema': tool['inputSchema'], 'requiredParameters': tool['inputSchema'].get('required', []),
            'outputSchema': tool.get('outputSchema'),
            'outputFormat': {'envelope': 'MCP CallToolResult with TextContent; no registered output schema',
                'implementation': 'JSON serialized into text' if 'Json.encodeToString' in h['handler'] else 'TextContent/string or helper-returned text; see handler',
                'observed': shape if live else 'NOT OBSERVED', 'sampleEvidence': live},
            'authentication': 'Hardened dev.4 refuses non-loopback binding or disabled bearer at startup and always authenticates requests. Keep bearer enabled; rules additionally require the configured bearer flag. Current runtime evidence is recorded separately.',
            **p, 'expectedErrorsAndFailure': errors,
            'status': status, 'registration': '89 unique tools/list names match the Kotlin registration set; catalog provenance: '+catalog_evidence['kind'],
            'directExecutionTests': direct,
            'negativeArgumentCoverage': ('Embedded MCP test: all typed tools reject invalid arguments before handler execution (85 tool cases; executed JUnit evidence). Successful behavior is not inferred.'
                if h['inputType'] else 'No-argument handler; required-argument/deserialization rejection is NOT APPLICABLE. Functional evidence remains separate.'),
            'unitCoverage': units or 'No direct subsystem-operation test mapped; do not infer PASS from registration.',
            'runtimeEvidence': live or 'NOT EXECUTED against current Burp',
            'historicalEvidence': historical.get(name),
            'liveIntegrationEvidence': 'Current read/pure/unsupported-result only; no application exchange' if live else 'No new live integration; historical evidence separately indexed, never transferred to another build.',
            'missingCoverage': limitation + (' No executed passing direct-handler test qualified.' if not any(r['executedPassing'] for r in direct) else ' Real Montoya side effects remain distinct from mocks.'),
            'implementation': h,
        })
    properties = dict(line.split('=', 1) for line in (ROOT / 'gradle.properties').read_text(encoding='utf-8').splitlines()
                      if '=' in line and not line.lstrip().startswith('#'))
    (out / 'tool-coverage.json').write_text(json.dumps({'catalogBuild': catalog_evidence.get('build'), 'catalogEvidence': catalog_evidence,
        'sourceBuild': properties['version'] + ' / ' + properties['build.id'],
        'toolCount': len(rows), 'statusCounts': dict(Counter(r['status'] for r in rows)), 'tools': rows}, indent=2), encoding='utf-8')
    fields = ['name', 'status', 'mode', 'requiredParameters', 'nativeApproval', 'missingCoverage', 'purposeEvidence']
    with (out / 'tool-matrix.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] for key in fields})
    lines = ['# Complete tool coverage matrix', '',
             '89 registered tools. JSON companion contains full input schemas, required fields, output observations, authorization, errors, qualified test references and complete source handlers. INTEGRATION uses embedded MCP transport with mocked Montoya and requires supplied passing JUnit evidence. Historical evidence is separate and does not establish current-build live execution.', '',
             '| Tool | Evidence status | Mode | Direct handler tests | Missing live coverage |', '|---|---|---|---:|---|']
    for r in rows:
        lines.append(f"| `{r['name']}` | {r['status']} | {r['mode']} | {len(r['directExecutionTests'])} | {r['missingCoverage']} |")
    (out / 'TOOL_COVERAGE.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    index = []
    for path in (ROOT / 'src/test/kotlin').rglob('*.kt'):
        text = path.read_text(encoding='utf-8')
        for test in re.finditer(r'@Test\s+(?:fun|suspend fun)\s+`([^`]+)`', text):
            index.append({'source': path.relative_to(ROOT).as_posix(), 'test': test[1], 'line': text[:test.start()].count('\n')+1})
    (out / 'subsystem-test-index.json').write_text(json.dumps(index, indent=2), encoding='utf-8')
    print(json.dumps({'tools': len(rows), 'statuses': dict(Counter(r['status'] for r in rows)), 'sourceTestsIndexed': len(index)}))


if __name__ == '__main__':
    main()
