"""Bounded synthetic localhost checks, after local rule and switch approval."""
import base64
import http.client
import json
import sys
from urllib.parse import urlencode

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def request(path, method="GET", headers=None, body=None, proxied=True):
    connection = http.client.HTTPConnection("127.0.0.1", 8080 if proxied else 18080, timeout=10)
    target = ("http://127.0.0.1:18080" if proxied else "") + path
    connection.request(method, target, body, headers or {})
    response = connection.getresponse()
    raw = response.read()
    result = {"status": response.status, "headers": dict(response.getheaders()),
              "body": raw.decode("utf-8"), "bytes": len(raw)}
    connection.close()
    return result


def verify(label, ok, evidence):
    print(json.dumps({"case": label, "result": "PASS" if ok else "FAIL", "evidence": evidence}, ensure_ascii=False))
    if not ok:
        raise AssertionError(label)


origin = request("/coverage-json", proxied=False)
client = request("/coverage-json")
obj = json.loads(client["body"])
verify("json_string_null_nested_utf8", origin["status"] == client["status"] == 201
       and obj == {"coverage_string": "Tester ✓", "coverage_null": None,
                   "nested": [{"coverage_string": "Tester ✓", "coverage_null": None}], "keep": "café"}
       and int(client["headers"]["Content-Length"]) == client["bytes"]
       and "no-store" in client["headers"].get("Cache-Control", ""), {"origin": origin, "client": client})

html_origin = request("/coverage-html", proxied=False)
html_client = request("/coverage-html")
verify("html_literal_utf8", html_client["body"] == html_origin["body"].replace("Welcome, Guest", "Welcome, Tester")
       and int(html_client["headers"]["Content-Length"]) == html_client["bytes"], {"origin": html_origin, "client": html_client})

for case, method, headers in [
    ("wrong_status", "GET", {"X-Fixture-Case": "wrong-status"}),
    ("wrong_content_type", "GET", {"X-Fixture-Case": "wrong-content-type"}),
    ("wrong_method", "POST", {}),
    ("attachment", "GET", {"X-Fixture-Case": "attachment"}),
    ("validator", "GET", {"X-Fixture-Case": "etag"}),
    ("no_transform", "GET", {"X-Fixture-Case": "no-transform"}),
    ("conditional", "GET", {"If-None-Match": '"fixture"'}),
]:
    direct = request("/coverage-json", method, headers, proxied=False)
    proxy = request("/coverage-json", method, headers)
    verify(case, direct["status"] == proxy["status"] and direct["body"] == proxy["body"], {"origin": direct, "client": proxy})

form = urlencode([("user_id", "old"), ("keep", "café"), ("user_id", "second")])
echo = json.loads(request("/echo?user_id=old&keep=query&user_id=second", "POST",
                          {"Content-Type": "application/x-www-form-urlencoded"}, form)["body"])
verify("duplicate_query_form", echo["path"] == "/echo?user_id=12345&keep=query&user_id=12345"
       and echo["body_utf8"] == "user_id=12345&keep=caf%C3%A9&user_id=12345", echo)

malformed = '{"user_id":"old",'
echo = json.loads(request("/echo", "POST", {"Content-Type": "application/json"}, malformed)["body"])
verify("malformed_json", base64.b64decode(echo["body_base64"]) == malformed.encode(), echo)
