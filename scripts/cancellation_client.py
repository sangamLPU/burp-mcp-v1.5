"""Bounded HTTP wire observation for the one-shot synthetic cancellation test.

Only response metadata and hashes are persisted. Request headers (including
the ephemeral fixture identity) and raw response content are never saved.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import time
import uuid


MAX_RESPONSE_BYTES = 65536


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def classify_response(data, termination):
    result = {"schemaVersion": 1, "termination": termination, "wireBytes": len(data),
              "wireSha256": hashlib.sha256(data).hexdigest(), "statusCode": None,
              "responseComplete": False, "bodyBytes": None, "bodySha256": None,
              "framing": "NONE", "outcome": "PARTIAL_HTTP_RESPONSE"}
    if not data:
        result["outcome"] = {"EOF": "EOF_WITHOUT_RESPONSE", "CONNECTION_RESET": "CONNECTION_RESET",
                             "CONNECTION_ABORTED": "CONNECTION_ABORTED", "READ_TIMEOUT": "READ_TIMEOUT",
                             "CONNECT_ERROR": "CONNECT_ERROR", "READ_ERROR": "READ_ERROR"}.get(termination, "NO_RESPONSE")
        return result
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        result["framing"] = "INCOMPLETE_HEADERS"
        return result
    headers, body = data[:marker].split(b"\r\n"), data[marker+4:]
    result.update({"headerBytes": marker+4, "bodyBytes": len(body), "bodySha256": hashlib.sha256(body).hexdigest()})
    status = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?:[ \t][^\r\n]*)?", headers[0])
    if not status:
        result["outcome"] = "INVALID_HTTP_RESPONSE"
        return result
    result["statusCode"] = int(status[1])
    if result["statusCode"] < 200:
        result.update(outcome="NONTERMINAL_INFORMATIONAL_RESPONSE", framing="INFORMATIONAL")
        return result
    fields = {}
    for line in headers[1:]:
        if b":" not in line:
            result["outcome"] = "INVALID_HTTP_RESPONSE"
            return result
        key, value = line.split(b":", 1)
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            result["outcome"] = "INVALID_HTTP_RESPONSE"
            return result
        fields.setdefault(key.lower(), []).append(value.strip())
    result["headerNames"] = [key.decode("ascii") for key in sorted(fields)]
    lengths = fields.get(b"content-length", [])
    transfer = fields.get(b"transfer-encoding", [])
    if lengths and transfer:
        result.update(outcome="INVALID_HTTP_RESPONSE", framing="CONFLICTING_FRAMING")
        return result
    if lengths:
        if any(not re.fullmatch(rb"[0-9]+", value) for value in lengths) or len(set(lengths)) != 1:
            result.update(outcome="INVALID_HTTP_RESPONSE", framing="INVALID_CONTENT_LENGTH")
            return result
        expected = int(lengths[0])
        result.update(framing="CONTENT_LENGTH", expectedBodyBytes=expected)
        if len(body) > expected:
            result["outcome"] = "UNEXPECTED_EXTRA_BYTES"
            return result
        complete = len(body) == expected
    elif transfer:
        # A safe explicit limit rather than silently accepting an unparsed stream.
        result.update(outcome="UNSUPPORTED_FRAMING", framing="TRANSFER_ENCODING")
        return result
    elif result["statusCode"] in (204, 304) or result["statusCode"] < 200:
        result.update(framing="NO_BODY", expectedBodyBytes=0)
        complete = not body
        if body:
            result["outcome"] = "INVALID_HTTP_RESPONSE"
            return result
    else:
        result["framing"] = "CLOSE_DELIMITED"
        complete = termination == "EOF"
    if complete:
        result.update(outcome="HTTP_RESPONSE_COMPLETE", responseComplete=True,
                      httpClass="HTTP_ERROR" if result["statusCode"] >= 400 else "HTTP_RESPONSE")
    return result


def admissible_terminal(observation):
    if observation.get("outcome") == "HTTP_RESPONSE_COMPLETE":
        return (observation.get("responseComplete") is True
                and observation.get("termination") in {"EOF", "FRAMING_COMPLETE"})
    return (observation.get("outcome") in {"EOF_WITHOUT_RESPONSE", "CONNECTION_RESET", "CONNECTION_ABORTED"}
            and observation.get("wireBytes") == 0)


def capture_once(request, evidence_path, *, host="127.0.0.1", port=8080, timeout=15,
                 connection_factory=socket.create_connection):
    """One connect/send attempt. Final evidence is fsynced before returning."""
    started = time.monotonic()
    data = bytearray()
    connection = None
    termination = "CONNECT_ERROR"
    stage = "CONNECT"
    error_type = None
    atomic_json(evidence_path, {"outcome": "IN_PROGRESS", "stage": stage, "wireBytes": 0})
    try:
        connection = connection_factory((host, port), timeout=min(3, timeout))
        stage = "SEND"
        connection.settimeout(timeout)
        connection.sendall(request)
        stage = "READ"
        while True:
            remaining = timeout - (time.monotonic()-started)
            if remaining <= 0:
                termination = "READ_TIMEOUT"
                break
            connection.settimeout(remaining)
            chunk = connection.recv(min(8192, MAX_RESPONSE_BYTES+1-len(data)))
            if not chunk:
                termination = "EOF"
                break
            data.extend(chunk)
            if len(data) > MAX_RESPONSE_BYTES:
                termination = "RESPONSE_TOO_LARGE"
                break
    except (TimeoutError, socket.timeout) as error:
        termination = "READ_TIMEOUT" if stage == "READ" else "CONNECT_OR_SEND_TIMEOUT"
        error_type = type(error).__name__
    except ConnectionResetError as error:
        termination, error_type = "CONNECTION_RESET", type(error).__name__
    except ConnectionAbortedError as error:
        termination, error_type = "CONNECTION_ABORTED", type(error).__name__
    except Exception as error:
        termination = "CONNECT_ERROR" if stage == "CONNECT" else "READ_ERROR"
        error_type = type(error).__name__
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception as error:
                error_type = error_type or type(error).__name__
    result = classify_response(bytes(data), termination)
    if termination == "RESPONSE_TOO_LARGE":
        result.update(outcome="RESPONSE_TOO_LARGE", responseComplete=False)
    if stage != "READ":
        result.update(outcome=termination, responseComplete=False)
    result.update(stage=stage, seconds=round(time.monotonic()-started, 3), errorType=error_type,
                  requestAttempts=1, evidencePersistedBeforePublication=True)
    # Failure to save propagates to the coordinator and can never yield PASS.
    atomic_json(evidence_path, result)
    return result
