"""Bounded read-only MCP checks against the existing synthetic localhost history."""
import concurrent.futures
import hashlib
import json
import time
from pathlib import Path

import cancel_test_preflight as preflight


ROOT = Path(__file__).resolve().parents[1]


def audit():
    client = preflight.initialize()
    catalog = client.rpc("tools/list")["tools"]
    results = []

    def tool(name, **arguments):
        result = client.rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError("tool returned an error")
        text = "\n".join(item.get("text", "") for item in result.get("content", []))
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def check(name, arguments, validate=lambda value: value is not None):
        started = time.monotonic()
        try:
            value = tool(name, **arguments)
            if not validate(value):
                raise AssertionError("unexpected result shape or value")
            results.append({"tool": name, "state": "PASS", "milliseconds": round((time.monotonic() - started) * 1000)})
            return value
        except Exception as error:
            results.append({"tool": name, "state": "FAIL", "errorType": type(error).__name__})

    check("burp_get_status", {}, lambda x: x.get("buildId") == "20261101.13-burp2024.1.1.1" and x.get("bearerAuthenticationRequired") is True)
    check("burp_check_connection", {}, lambda x: x.get("burpConnected") is True)
    for name in ("burp_get_capabilities", "burp_get_project_info", "burp_get_intercept_status", "burp_get_rule_engine_status"):
        check(name, {})
    for name in ("burp_list_pending_requests", "burp_list_pending_responses", "burp_list_interception_rules", "burp_get_interception_rule_stats", "burp_get_interception_rule_events"):
        check(name, {}, lambda x: isinstance(x, list))
    check("burp_get_intercept_diagnostics", {"count": 10}, lambda x: isinstance(x, dict))
    check("burp_get_scope", {"urls": list(preflight.LOCAL_TEST_URLS) + ["http://example.com/"]},
          lambda x: {r["url"] for r in x["checks"] if r["eligible"]} == set(preflight.LOCAL_TEST_URLS))
    history = check("burp_get_proxy_history", {"host": "127.0.0.1", "count": 20, "offset": 0}, lambda x: isinstance(x, list)) or []
    # Use only the nine known synthetic case IDs; never persist raw history/configuration.
    live_path = ROOT / "build/reports/live-rule-engine/supervised-live-20261102.json"
    prior = json.loads(live_path.read_text(encoding="utf-8"))
    expected_cases = {entry["case"]: entry for entry in prior["exchanges"]}
    known = []
    corroboration = []
    for entry in history:
        if entry.get("url") != "http://127.0.0.1:8000/test-post":
            continue
        try:
            body = json.loads(entry["response"].split("\r\n\r\n", 1)[1])
        except (KeyError, ValueError, IndexError):
            continue
        case = body.get("case")
        if case in expected_cases:
            known.append(entry)
            corroboration.append({"case": case, "historyId": entry["historyId"],
                                  "originResponseEnabled": body["enabled"],
                                  "clientResponseEnabled": expected_cases[case]["clientEnabled"],
                                  "originalResponseSha256": hashlib.sha256(entry["response"].split("\r\n\r\n", 1)[1].encode()).hexdigest()})
    for name in ("burp_get_request", "burp_get_response", "burp_get_response_headers", "burp_analyze_request", "burp_analyze_response",
                 "burp_analyze_security_headers", "burp_analyze_cookies", "burp_analyze_cors", "burp_analyze_authentication", "burp_find_sensitive_data"):
        if known:
            check(name, {"historyId": known[0]["historyId"]})
    if len(known) >= 2:
        check("burp_compare_responses", {"firstHistoryId": known[0]["historyId"], "secondHistoryId": known[1]["historyId"]})
    check("burp_search_http_history", {"host": "127.0.0.1", "query": next(iter(expected_cases)), "count": 5, "offset": 0}, lambda x: isinstance(x, list) and len(x) == 1)
    # Legacy history variants still pass through the extension's scope/redaction layer.
    check("get_proxy_http_history", {"count": 1, "offset": 0})
    check("get_proxy_http_history_regex", {"regex": "rule-", "count": 1, "offset": 0})
    for name in ("output_project_options", "output_user_options"):
        check(name, {}, lambda x: isinstance(x, dict))
    check("base64_encode", {"content": "MCP-local-check"}, lambda x: x == "TUNQLWxvY2FsLWNoZWNr")
    check("base64_decode", {"content": "TUNQLWxvY2FsLWNoZWNr"}, lambda x: x == "MCP-local-check")
    check("url_encode", {"content": "local fixture +"}, lambda x: isinstance(x, str) and "%2B" in x.upper())
    check("url_decode", {"content": "local%20fixture%20%2B"}, lambda x: x == "local fixture +")
    check("generate_random_string", {"length": 16, "characterSet": "abc123"}, lambda x: isinstance(x, str) and len(x) == 16 and set(x) <= set("abc123"))
    check("burp_modify_request", {"rawRequest": "GET /test-html HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n", "headers": {"X-MCP-Audit": "synthetic"}})
    check("burp_get_site_map", {"count": 2, "offset": 0}, lambda x: isinstance(x, list))
    check("burp_generate_security_report", {"count": 2, "offset": 0}, lambda x: isinstance(x, dict))
    missing_scan = client.rpc("tools/call", {"name": "burp_get_scan_status", "arguments": {"scanId": "nonexistent-local-audit-id"}})
    results.append({"tool": "burp_get_scan_status", "state": "EXPECTED_REJECTION" if missing_scan.get("isError") else "REVIEW"})
    unsupported = client.rpc("tools/call", {"name": "burp_get_repeater_tabs", "arguments": {}})
    results.append({"tool": "burp_get_repeater_tabs", "state": "EXPECTED_UNSUPPORTED" if unsupported.get("isError") else "REVIEW"})
    exercised = {row["tool"] for row in results}
    return {"state": "PASS" if not any(row["state"] == "FAIL" for row in results) else "FAIL", "scope": "LOCAL_SYNTHETIC_HISTORY",
            "results": results, "registeredTools": len(catalog), "remainingUnverifiedInThisAudit": [t["name"] for t in catalog if t["name"] not in exercised],
            "originResponseCorroboration": corroboration,
            "allNineOriginalResponsesFalse": len(corroboration) == 9 and all(x["originResponseEnabled"] is False for x in corroboration)}


def stability(rounds=8, workers=8, interval=10):
    started = time.monotonic()
    rows = []
    def probe(index):
        begin = time.monotonic()
        try:
            client = preflight.initialize(preflight.McpClient(timeout=3))
            assert client.rpc("ping") == {}
            assert len(client.rpc("tools/list")["tools"]) == 86
            status = client.tool("burp_get_status", includeDiagnostics=False)
            assert status["buildId"] == "20261101.13-burp2024.1.1.1" and status["serverState"] == "running"
            return {"client": index, "state": "PASS", "milliseconds": round((time.monotonic()-begin)*1000), "sessionHeader": client._session_id is not None}
        except Exception as error:
            return {"client": index, "state": "FAIL", "errorType": type(error).__name__, "milliseconds": round((time.monotonic()-begin)*1000)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for round_number in range(rounds):
            rows.extend(pool.map(probe, range(round_number*workers, (round_number+1)*workers)))
            if any(row["state"] != "PASS" for row in rows):
                break  # Never retry an unsuccessful probe.
            if round_number < rounds-1:
                time.sleep(interval)
    return {"state": "PASS" if all(r["state"] == "PASS" for r in rows) else "FAIL", "clients": len(rows),
            "workers": workers, "durationSeconds": round(time.monotonic()-started, 2), "results": rows,
            "limitation": "Bounded sampling; historical freeze not proven impossible."}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--stability", action="store_true")
    args = parser.parse_args()
    result = stability() if args.stability else audit()
    path = ROOT / "build/reports/reliability" / ("bounded-stability.json" if args.stability else "local-tool-audit.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"state": result["state"], "report": str(path), "checks": len(result["results"])}))
