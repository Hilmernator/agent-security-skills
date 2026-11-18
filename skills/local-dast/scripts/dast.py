#!/usr/bin/env python3
"""Bounded HTTP assertions and ZAP analysis of recorded traffic, on loopback or one named HTTPS host. Python 3.10+."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import CookieError, SimpleCookie
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit
import zipfile

VERSION = "2.17.0"
ARCHIVE_SHA256 = "94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0"
ADDONS = {"automation", "callhome", "commonlib", "network", "pscan", "pscanrules", "exim", "reports"}
MAX_CASES, MAX_BODY, MAX_SENT = 50, 1024 * 1024, 64 * 1024
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
OPTIONAL = {"headers", "headers_env", "expect_json", "requires", "method", "json", "json_env", "form", "form_env", "multipart", "session", "expect_text", "forbid_text",
            "expect_headers", "forbid_headers", "session_token", "same_as", "take", "expect_canary", "forbid_canary", "policy"}
# JSON-RPC methods that only read or shake hands, as MCP names them. A POST that carries one of these and nothing else needs no --allow-writes.
RPC_READS = ("initialize", "ping", "tools/list", "resources/list", "resources/templates/list", "resources/read", "prompts/list", "prompts/get")
PART = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")  # a form field, a query parameter or an uploaded file's name: nothing a header or a URL reads as structure
MEDIA = re.compile(r"[a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64}\Z")
HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}\Z")
TOKEN = re.compile(r"[\x21-\x7e]{1,8192}\Z")  # what may follow "Bearer " in a header: no space, no control character
RUN_SECONDS, REQUEST_SECONDS, INTERVAL = 60, 5, 0.5
LABEL = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
# A taken value fills one path segment: no slash, no leading dot, nothing a URL reads as structure.
TAKEN = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._~-]{0,127}\Z")
REFERENCE = re.compile(r"\{([^{}]*)\}")
WHOLE = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}\Z")  # a value that is one {name} and nothing else
# Where a whole value may be a {name}. In the first two the taken value keeps its type; in the rest it is sent or compared as text.
TYPED, TEXTUAL = ("json", "expect_json"), ("form", "multipart", "expect_text", "forbid_text", "expect_headers", "forbid_headers")
REFUSED = {"host", "connection", "content-length", "transfer-encoding", "accept-encoding", "proxy-authorization", "upgrade"}
# A canary is a run of these in an answer, 8 characters or more; the plan holds only its SHA-256.
CANARY = re.compile(r"[A-Za-z0-9_-]{8,}")
BODY_CHECKS = {"expect_text", "forbid_text", "expect_canary", "forbid_canary", "expect_json"}
# A lowercase DNS name on port 443. The last label starts with a letter, so an IP address never matches.
REMOTE = re.compile(r"https://(?=[a-z0-9.-]{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\Z")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


class PlanError(ValueError):
    """What is wrong with the plan, in words that hold only the plan's own case IDs and variable names: safe to print."""


def env_value(variable, absent=None):
    """A DAST_ variable's value, or an error that names the variable and never shows the value. An unset variable gives absent when that is not None."""
    if not isinstance(variable, str) or not re.fullmatch(r"DAST_[A-Z0-9_]{1,64}", variable):
        raise ValueError("Credential references must use DAST_ environment variables")
    value = os.environ.get(variable) or absent
    if not value or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError(f"{variable} is absent or invalid; its value is not displayed")
    return value


def sent_body(case, absent=None):
    """The body of a case as bytes and its content type, or (None, None). Credential fields are filled from the environment here only."""
    if "form" in case or "form_env" in case:
        data = {**case.get("form", {}), **{key: env_value(variable, absent) for key, variable in case.get("form_env", {}).items()}}
        return urlencode(data).encode(), "application/x-www-form-urlencoded"
    if "multipart" in case:
        # ponytail: the boundary is a hash of the parts, not checked against their text; a part that holds it breaks the body. Check when a real upload needs it.
        boundary = hashlib.sha256(json.dumps(case["multipart"], sort_keys=True).encode()).hexdigest()[:32]
        body = ""
        for name, part in case["multipart"].items():
            head = f'Content-Disposition: form-data; name="{name}"'
            if isinstance(part, dict):
                head += f'; filename="{part["filename"]}"\r\nContent-Type: {part.get("content_type", "application/octet-stream")}'
            body += f"--{boundary}\r\n{head}\r\n\r\n{part['text'] if isinstance(part, dict) else part}\r\n"
        return (body + f"--{boundary}--\r\n").encode(), f"multipart/form-data; boundary={boundary}"
    if "json" not in case and "json_env" not in case:
        return None, None
    data = dict(case.get("json", {}))
    data.update({key: env_value(variable, absent) for key, variable in case.get("json_env", {}).items()})
    return json.dumps(data, allow_nan=False).encode(), "application/json"


def changes_state(case):
    """False for a GET, and for a POST whose whole body is one JSON-RPC request that only reads."""
    if case.get("method", "GET") == "GET":
        return False
    body = case.get("json")
    return not (case["method"] == "POST" and "json_env" not in case and isinstance(body, dict)
                and set(body) <= {"jsonrpc", "id", "method", "params"} and body.get("jsonrpc") == "2.0"
                and isinstance(body.get("method"), str) and body["method"] in RPC_READS)


def holds(expected, actual):
    """The answer has every field the case names, with the same type and value; an object is compared field by field."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and holds(value, actual[key]) for key, value in expected.items())
    return type(actual) is type(expected) and actual == expected


def answer_json(headers, body):
    """The JSON an answer carries. For text/event-stream (MCP's streamable HTTP) that is the data of the last event that has any."""
    text = body.decode("utf-8")
    if any(key.lower() == "content-type" and value.lower().startswith("text/event-stream") for key, value in headers):
        events = [[line[5:].strip() for line in event.splitlines() if line.startswith("data:")] for event in re.split(r"\r?\n\r?\n", text)]
        text = "\n".join(next((data for data in reversed(events) if data), []))
    return json.loads(text)


def dig(value, path):
    """The value at the end of a path of field names and list positions, or None."""
    for key in path:
        if isinstance(key, str) and isinstance(value, dict):
            value = value.get(key)
        elif type(key) is int and isinstance(value, list) and key < len(value):
            value = value[key]
        else:
            return None
    return value


def references(case):
    """The names a case fills in: {name} anywhere in its path or in a header's value, and a body or check value that is {name} and nothing else."""
    def strings(value):
        if isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)
        elif isinstance(value, str) and WHOLE.match(value):
            yield value[1:-1]
    headers = case.get("headers")
    inline = [case["path"], *(value for value in (headers.values() if isinstance(headers, dict) else ()) if isinstance(value, str))]
    return {name for text in inline for name in REFERENCE.findall(text)} | {name for field in TYPED + TEXTUAL for name in strings(case.get(field))}


def filled(case, values):
    """The case as sent and checked: every {name} replaced by the value an earlier answer gave. A JSON value keeps its type."""
    def fill(value, shape):
        if isinstance(value, dict):
            return {key: fill(item, shape) for key, item in value.items()}
        if isinstance(value, list):
            return [fill(item, shape) for item in value]
        return shape(values[value[1:-1]]) if isinstance(value, str) and WHOLE.match(value) else value
    case = dict(case, path=REFERENCE.sub(lambda match: str(values[match.group(1)]), case["path"]))
    if "headers" in case:
        case["headers"] = {key: REFERENCE.sub(lambda match: str(values[match.group(1)]), value) for key, value in case["headers"].items()}
    for fields, shape in ((TYPED, lambda value: value), (TEXTUAL, str)):
        for field in fields:
            if field in case:
                case[field] = fill(case[field], shape)
    return case


def take_shape(where):
    """True when a take names one place a value comes from: a JSON path, or one source with at most one cut."""
    def path(steps):
        return isinstance(steps, list) and 1 <= len(steps) <= 8 and all((isinstance(step, str) and step) or (type(step) is int and step >= 0) for step in steps)
    if isinstance(where, list):
        return path(where)
    if not isinstance(where, dict) or len(set(where) & {"json", "header", "body", "cookie"}) != 1 or set(where) - {"json", "header", "body", "cookie", "query", "segment"}:
        return False
    if "cookie" in where:
        return len(where) == 1 and isinstance(where["cookie"], str) and bool(PART.fullmatch(where["cookie"]))
    if "query" in where and ("segment" in where or not isinstance(where["query"], str) or not PART.fullmatch(where["query"])):
        return False
    if "segment" in where and (type(where["segment"]) is not int or not 1 <= where["segment"] <= 32):
        return False
    if "body" in where:
        # ponytail: the pattern runs on an answer of up to one MiB with no time limit; the agent writes it, the answer cannot choose it.
        try:
            return isinstance(where["body"], str) and len(where["body"]) <= 256 and len(where) == 1 and re.compile(where["body"]).groups == 1
        except re.error:
            return False
    return path(where["json"]) if "json" in where else isinstance(where["header"], str) and bool(HEADER_NAME.fullmatch(where["header"]))


def take_value(where, headers, text, parsed):
    """The value a take names, or None: from the JSON answer, a response header, a cookie the answer sets or the body's text; whole, or one query parameter or path segment of it."""
    if isinstance(where, list):
        return dig(parsed, where)
    if "cookie" in where:
        jar = SimpleCookie()
        for key, value in headers:
            try:
                jar.load(value if key.lower() == "set-cookie" else "")
            except CookieError:
                continue
        return jar[where["cookie"]].coded_value if where["cookie"] in jar else None
    if "body" in where:
        found = re.search(where["body"], text)
        return found.group(1) if found else None
    value = dig(parsed, where["json"]) if "json" in where else next((item for key, item in headers if key.lower() == where["header"].lower()), None)
    if "query" not in where and "segment" not in where:
        return value
    try:
        link = urlsplit(value) if isinstance(value, str) else None
    except ValueError:
        link = None
    if link is None:
        return None
    if "query" in where:
        return (parse_qs(link.query).get(where["query"]) or [None])[0]
    segments = [part for part in link.path.split("/") if part]
    return segments[where["segment"] - 1] if where["segment"] <= len(segments) else None


def only(plan, wanted):
    """The plan cut down to the named cases and everything they rest on: their requires, the case they are compared with, the cases their values come from,
    and every earlier case that changes state or shares a session with a kept case. A re-read judges a write that may fail its own check, so requires cannot name it."""
    cases = {case["id"]: case for case in plan["cases"]}
    if set(wanted) - cases.keys():
        raise PlanError("--only names a case the plan does not hold")
    source = {name: case["id"] for case in plan["cases"] for name in case.get("take", {})}
    order = [case["id"] for case in plan["cases"]]
    keep, queue = set(), list(wanted)
    while queue:
        name = queue.pop()
        if name not in keep:
            keep.add(name)
            case = cases[name]
            queue += [*case.get("requires", []), *([case["same_as"]] if "same_as" in case else []), *(source[ref] for ref in references(case) if ref in source)]
        if not queue:
            sessions = {cases[name].get("session") for name in keep} - {None}
            queue = [case["id"] for case in plan["cases"][:max(order.index(name) for name in keep)]
                     if case["id"] not in keep and (changes_state(case) or case.get("session") in sessions)]
    return {**plan, "cases": [case for case in plan["cases"] if case["id"] in keep]}


def parse_policy(text):
    """The Access policy section of security/profile.md: its status and, per row ID, each role's cell."""
    section = re.search(r"^## Access policy[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not section:
        raise ValueError("profile.md has no '## Access policy' section")
    status = re.search(r"^Status: (?:(PROPOSED)\b|confirmed by owner on \d{4}-\d{2}-\d{2}\b)", section[1], re.M)
    table = [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in section[1].splitlines() if line.lstrip().startswith("|")]
    head = table[0] if table else []
    if not status or head[:4] != ["ID", "Route", "Resource", "Action"] or head[-1:] != ["Enforced at"] or "anonymous" not in head[4:-1]:
        raise ValueError("The Access policy needs a Status line and the header | ID | Route | Resource | Action | anonymous | ... | Enforced at |")
    rows = {}
    for line in table[2:]:
        if len(line) != len(head) or not line[0] or line[0] in rows or any(not re.fullmatch(r"allow|deny|allow if \S.*", cell) for cell in line[4:-1]):
            raise ValueError("Each Access policy row needs a unique ID and, per role, allow, deny or allow if <condition>")
        rows[line[0]] = dict(zip(head[4:-1], line[4:-1]))
    if not rows:
        raise ValueError("The Access policy table has no rows")
    return {"status": "proposed" if status[1] else "confirmed", "rows": rows, "sha256": hashlib.sha256(section[0].encode()).hexdigest()}


def expected(policy, case):
    """allow or deny: what the policy says about the cell a case is tagged with."""
    tag = case["policy"]
    if policy is None:
        raise ValueError("A case tagged with policy needs --policy")
    if not isinstance(tag, dict) or not {"row", "role"} <= tag.keys() <= {"row", "role", "holds"} or not all(isinstance(tag[k], str) for k in ("row", "role")):
        raise ValueError("policy must be {row, role} and, for an allow-if cell, holds")
    cell = policy["rows"].get(tag["row"], {}).get(tag["role"])
    if cell is None or ("holds" in tag) != cell.startswith("allow if") or not isinstance(tag.get("holds", False), bool):
        raise ValueError("policy must name a row and role of the table, with holds exactly when the cell is allow if")
    return "allow" if cell == "allow" or tag.get("holds") else "deny"


def validate_plan(plan, writes=False, remote=None, policy=None, absent=None):
    """Validate the entire plan before the first connection; never resolve a hostname. Returns (host, port). An error names the case it stopped at."""
    seen = []
    try:
        return check_plan(plan, writes, remote, policy, absent, seen)
    except ValueError as error:
        label = seen[-1].get("id") if seen and isinstance(seen[-1], dict) else None
        where = f"Case {len(seen)}" + (f" ({label})" if isinstance(label, str) and LABEL.fullmatch(label) else "") + ": " if seen else ""
        raise PlanError(where + str(error)) from None


def check_plan(plan, writes, remote, policy, absent, seen):
    if not isinstance(plan, dict) or set(plan) != {"target", "cases"}:
        raise ValueError("Plan requires exactly target and cases")
    if remote is not None:
        # A deployed target is the one host named on the command line; a plan alone can never choose it.
        if not isinstance(remote, str) or not REMOTE.fullmatch(remote) or plan["target"] != remote:
            raise ValueError("A remote target must be one https://hostname origin, the same in the plan and in --remote")
        origin = (remote.removeprefix("https://"), 443)
    else:
        if not isinstance(plan["target"], str) or not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", plan["target"]):
            raise ValueError("Target must be an exact http://127.0.0.1:PORT origin")
        origin = ("127.0.0.1", urlsplit(plan["target"]).port)
        if not 1024 <= origin[1] <= 65535:
            raise ValueError("Target port must be between 1024 and 65535")
    cases = plan["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Plan must contain 1 to 50 cases")
    names, taken = set(), set()
    for case in cases:
        seen.append(case)
        required = {"id", "path", "expect_status"}
        if not isinstance(case, dict) or not required <= case.keys() or set(case) - required - OPTIONAL:
            raise ValueError("Invalid case fields")
        name, path = case["id"], case["path"]
        if not isinstance(name, str) or not LABEL.fullmatch(name) or name in names:
            raise ValueError("Case IDs must be unique lowercase labels")
        if not isinstance(path, str) or len(path) > 2048 or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Case path must be origin-relative")
        if any(ord(c) < 33 or ord(c) > 126 for c in path) or "\\" in path or "#" in path:
            raise ValueError("Case path must be ASCII without whitespace, fragments or backslashes")
        if "{" in REFERENCE.sub("", path) or "}" in REFERENCE.sub("", path) or references(case) - taken:
            raise ValueError("A {name} in a path, in a header or as a whole body or check value must be taken by a preceding case")
        statuses = case["expect_status"]
        if not isinstance(statuses, list) or not statuses or any(type(n) is not int or not 100 <= n <= 599 for n in statuses):
            raise ValueError("expect_status must be a nonempty array of HTTP status codes")
        if "expect_json" in case and (not isinstance(case["expect_json"], dict) or not case["expect_json"]):
            raise ValueError("expect_json must be a nonempty object of expected fields")
        dependencies = case.get("requires", [])
        if not isinstance(dependencies, list) or any(not isinstance(n, str) or n not in names for n in dependencies):
            raise ValueError("requires must refer to preceding cases")
        if "same_as" in case and (not isinstance(case["same_as"], str) or case["same_as"] not in names):
            raise ValueError("same_as must name one preceding case")
        headers = case.get("headers_env", {})
        if not isinstance(headers, dict) or len(headers) > 10:
            raise ValueError("headers_env must map at most ten header names to environment variable names")
        lowered = set()
        for key, variable in headers.items():
            if not isinstance(key, str) or not HEADER_NAME.fullmatch(key):
                raise ValueError("Invalid header name")
            if key.lower() in lowered | REFUSED:
                raise ValueError("Duplicate or transport-controlling header is not allowed")
            lowered.add(key.lower())
            env_value(variable, absent)
        literal = case.get("headers", {"x": "x"})
        if not isinstance(literal, dict) or not 1 <= len(literal) <= 10:
            raise ValueError("headers must map one to ten header names to a text")
        for key, value in literal.items():
            # Host may be set where the connection still goes to 127.0.0.1; a deployed host is the one on the command line.
            if not isinstance(key, str) or not HEADER_NAME.fullmatch(key) or key.lower() in lowered | (REFUSED - ({"host"} if remote is None else set())):
                raise ValueError("A header in headers has a plain name, once in the case, and does not control the transport")
            if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 32 or ord(c) > 126 for c in value) or set("{}") & set(REFERENCE.sub("", value)):
                raise ValueError("A header's value is a short printable text; a brace in it belongs to a {name}")
            lowered.add(key.lower())
        method = case.get("method", "GET")
        if method not in METHODS:
            raise ValueError("method must be GET, POST, PUT, PATCH or DELETE")
        if changes_state(case) and not writes:
            raise ValueError("State-changing cases run only with --allow-writes")
        for field in ("json", "json_env", "form", "form_env", "multipart"):
            if field in case and (method == "GET" or not isinstance(case[field], dict) or not case[field] or any(not isinstance(key, str) for key in case[field])):
                raise ValueError("json, form and multipart bodies must be nonempty objects on a state-changing case")
        if sum(bool(group & case.keys()) for group in ({"json", "json_env"}, {"form", "form_env"}, {"multipart"})) > 1:
            raise ValueError("A case sends one kind of body: json, form or multipart")
        if any(not PART.fullmatch(key) for field in ("form", "form_env", "multipart") for key in case.get(field, {})) or any(
                not isinstance(value, (str, int)) or isinstance(value, bool) for value in case.get("form", {}).values()):
            raise ValueError("A form field has a plain name and a text or whole-number value")
        for part in case.get("multipart", {}).values():
            if not isinstance(part, str) and not (isinstance(part, dict) and {"filename", "text"} <= part.keys() <= {"filename", "text", "content_type"}
                                                  and isinstance(part["filename"], str) and PART.fullmatch(part["filename"]) and isinstance(part["text"], str)
                                                  and isinstance(part.get("content_type", "a/b"), str) and MEDIA.fullmatch(part.get("content_type", "a/b"))):
                raise ValueError("A multipart part is a text, or a file with filename, text and an optional content_type")
        body, _ = sent_body(case, absent)
        if body is not None and len(body) > MAX_SENT:
            raise ValueError("Request body exceeds 64 KiB")
        if "session" in case and (not isinstance(case["session"], str) or not LABEL.fullmatch(case["session"]) or "cookie" in lowered):
            raise ValueError("session must be a lowercase label, without a Cookie header of its own")
        for field in ("expect_text", "forbid_text"):
            items = case.get(field, ["x"])
            if not isinstance(items, list) or not 1 <= len(items) <= 20 or any(not isinstance(item, str) or not 1 <= len(item) <= 256 for item in items):
                raise ValueError("expect_text and forbid_text must list 1 to 20 short strings")
        for field in ("expect_headers", "forbid_headers"):
            wanted = case.get(field, {"x": ""})
            if not isinstance(wanted, dict) or not 1 <= len(wanted) <= 10 or any(
                    not isinstance(key, str) or not HEADER_NAME.fullmatch(key) or not isinstance(part, str) or len(part) > 256
                    or any(ord(c) < 32 or ord(c) > 126 for c in part) for key, part in wanted.items()):
                raise ValueError("expect_headers and forbid_headers must map 1 to 10 header names to a short text, or to an empty text")
        path_to_token = case.get("session_token", ["x"])
        if ("session_token" in case and "session" not in case) or not isinstance(path_to_token, list) or not 1 <= len(path_to_token) <= 8 or any(
                not isinstance(key, str) or not key for key in path_to_token):
            raise ValueError("session_token must list 1 to 8 field names, on a case that has a session")
        for field in ("expect_canary", "forbid_canary"):
            digests = case.get(field, ["0" * 64])
            if not isinstance(digests, list) or not 1 <= len(digests) <= 20 or any(not isinstance(d, str) or not re.fullmatch(r"[0-9a-f]{64}", d) for d in digests):
                raise ValueError("expect_canary and forbid_canary must list 1 to 20 SHA-256 hex digests")
        # A 200 alone proves nothing: a read the policy judges asserts on the body, and an allowed case expects success.
        if "policy" in case and ((expected(policy, case) == "allow" and min(statuses) >= 400) or (not changes_state(case) and not BODY_CHECKS & case.keys())):
            raise ValueError("A policy case expects success where the policy allows, and a policy read asserts on the body")
        take = case.get("take", {"x": ["x"]})
        if not isinstance(take, dict) or not 1 <= len(take) <= 4 or any(
                not isinstance(key, str) or not NAME.fullmatch(key) or key in taken or not take_shape(where) for key, where in take.items()):
            raise ValueError("take must map 1 to 4 new names to a JSON path, or to one of json, header, cookie and body, the first two with at most one of query and segment")
        taken.update(case.get("take", {}))
        names.add(name)
    return origin


def request(origin, case, timeout, cookies=None, bearer=None, mcp_session=None):
    headers = {"Accept-Encoding": "identity", "Connection": "close", "User-Agent": "rasmus-local-dast/0.1"}
    headers.update({key: os.environ[variable] for key, variable in case.get("headers_env", {}).items()})
    headers.update(case.get("headers", {}))
    if bearer and "authorization" not in {key.lower() for key in headers}:  # a case's own Authorization header wins
        headers["Authorization"] = "Bearer " + bearer
    if mcp_session and "mcp-session-id" not in {key.lower() for key in headers}:
        headers["Mcp-Session-Id"] = mcp_session
    if cookies:
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    payload, kind = sent_body(case)
    if payload is not None:
        if len(payload) > MAX_SENT:  # a taken value can lengthen the body after the plan was checked
            raise ValueError("Request body exceeds 64 KiB")
        if "content-type" not in {key.lower() for key in headers}:  # a case's own Content-Type wins: a JSON body sent as text/plain is a case worth writing
            headers["Content-Type"] = kind
    host, port = origin
    if host == "127.0.0.1":
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    else:
        # The system trust store and the hostname check, as they are. A certificate that fails is a result to report.
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
    timer = None
    expired = threading.Event()
    started = time.monotonic()
    try:
        connection.connect()
        wire = connection.sock

        def expire():
            expired.set()
            try:
                wire.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(max(0.001, timeout - (time.monotonic() - started)), expire)
        timer.daemon = True
        timer.start()
        connection.request(case.get("method", "GET"), case["path"], body=payload, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        if expired.is_set() or time.monotonic() - started >= timeout:
            raise TimeoutError("Request deadline reached")
        if len(body) > MAX_BODY:
            raise ValueError("Response exceeds capture limit")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Compressed responses are not supported by this capture profile")
        length = response.getheader("Content-Length")
        if length is not None and int(length) != len(body):
            raise ValueError("Incomplete response body")
        return response.status, response.getheaders(), body, headers, payload
    finally:
        if timer:
            timer.cancel()
            timer.join()
        connection.close()


def har_entry(target, case, status, headers, body, sent, payload=None):
    def fields(items):
        return [{"name": key, "value": value} for key, value in items]
    kind = next((value for key, value in sent.items() if key.lower() == "content-type"), "application/json")
    posted = {"postData": {"mimeType": kind, "text": payload.decode("utf-8")}} if payload is not None else {}
    return {
        "startedDateTime": datetime.now(timezone.utc).isoformat(), "time": 0, "comment": case["id"],
        "request": {"method": case.get("method", "GET"), "url": target + case["path"], "httpVersion": "HTTP/1.1",
                    "headers": fields(sent.items()), "queryString": [], "cookies": [], "headersSize": -1,
                    "bodySize": len(payload or b""), **posted},
        "response": {"status": status, "statusText": http.client.responses.get(status, ""), "httpVersion": "HTTP/1.1",
                     "headers": fields(headers), "cookies": [], "redirectURL": "", "headersSize": -1,
                     "bodySize": len(body), "content": {"size": len(body), "mimeType": next((v for k, v in headers if k.lower() == "content-type"), "application/octet-stream"),
                     "text": base64.b64encode(body).decode("ascii"), "encoding": "base64"}},
        "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
    }


def remember_cookies(store, headers):
    """Keep the cookies a response sets, in memory only, for later cases of the same session."""
    # ponytail: name and value only; Path, Domain and expiry are ignored. Fine for one origin and a
    # 60-second run. Use a real cookie jar if a target scopes cookies by path.
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        jar = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            continue
        for name, morsel in jar.items():
            if morsel.value and morsel["max-age"] != "0":
                store[name] = morsel.coded_value
            else:
                store.pop(name, None)


def capture(plan, writes=False, remote=None, policy=None):
    origin = validate_plan(plan, writes, remote, policy)
    observations, entries, passed, sessions, bearers, answers, mcp, values = [], [], set(), {}, {}, {}, {}, {}
    deadline = time.monotonic() + RUN_SECONDS
    for case in plan["cases"]:
        row = {"id": case["id"], "state": "not-run"}
        if case.get("method", "GET") != "GET":
            row["method"] = case["method"]
        observations.append(row)
        if any(name not in passed for name in case.get("requires", [])):
            row["gap"] = "prerequisite-failed"
            continue
        if references(case) - values.keys():
            row["gap"] = "value-not-taken"
            continue
        case = filled(case, values)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            row["gap"] = "request-budget-exhausted"
            continue
        try:
            store = sessions.setdefault(case["session"], {}) if "session" in case else None
            status, headers, body, sent, payload = request(origin, case, min(REQUEST_SECONDS, remaining), store, bearers.get(case.get("session")),
                                                             mcp.get(case.get("session")))
            if store is not None:
                remember_cookies(store, headers)
                # MCP's streamable HTTP names its session in a response header, the way a cookie would. Same privacy as the token.
                for key, value in headers:
                    if key.lower() == "mcp-session-id" and TOKEN.fullmatch(value):
                        mcp[case["session"]] = value
            checks = {"status": status in case["expect_status"]}
            answers[case["id"]] = status, hashlib.sha256(body).hexdigest()
            if "same_as" in case:
                # Equal status and equal body. A case that got no answer is not "the same" as anything.
                checks["same"] = answers.get(case["same_as"]) == answers[case["id"]]
            text = body.decode("utf-8", "replace")
            for field, check, wanted in (("expect_text", "text", True), ("forbid_text", "absent", False)):
                if field in case:
                    # Which texts failed, by their place in the plan's list: a text may hold a taken value, a number never does.
                    wrong = [place for place, item in enumerate(case[field], 1) if (item in text) is not wanted]
                    checks[check] = not wrong
                    if wrong:
                        row[check + "_failed"] = wrong
            if "expect_canary" in case or "forbid_canary" in case:
                seen = {hashlib.sha256(word.encode()).hexdigest() for word in CANARY.findall(text)}
                if "expect_canary" in case:
                    checks["canary"] = all(item in seen for item in case["expect_canary"])
                if "forbid_canary" in case:
                    checks["canary_absent"] = not seen & set(case["forbid_canary"])
            for field, check, wanted in (("expect_headers", "headers", True), ("forbid_headers", "headers_absent", False)):
                if field in case:
                    checks[check] = all(any(key.lower() == name.lower() and part.lower() in value.lower() for key, value in headers) is wanted
                                        for name, part in case[field].items())
            if "expect_json" in case or "session_token" in case or "take" in case:
                try:
                    actual = answer_json(headers, body)
                except ValueError:
                    actual = None
                if "expect_json" in case:
                    checks["json"] = holds(case["expect_json"], actual)
                    if not checks["json"]:  # the names are the plan's own text, so they may stand in a report
                        row["json_failed"] = sorted(key for key, value in case["expect_json"].items() if not holds({key: value}, actual))
                if "session_token" in case:
                    # The token stays in memory and reaches only later requests of this session and the private HAR.
                    token = dig(actual, case["session_token"])
                    checks["token"] = isinstance(token, str) and bool(TOKEN.fullmatch(token))
                    if checks["token"]:
                        bearers[case["session"]] = token
                if "take" in case:
                    # Like the token: in memory, into later requests and the private HAR, never into a report.
                    found = {name: take_value(where, headers, text, actual) for name, where in case["take"].items()}
                    checks["taken"] = all((type(value) is int and 0 <= value < 2 ** 53) or (isinstance(value, str) and TAKEN.fullmatch(value))
                                          for value in found.values())
                    if checks["taken"]:
                        values.update(found)
            row.update(state="pass" if all(checks.values()) else "assertion-failed", status=status, checks=checks)
            if 300 <= status < 400:
                # A redirect is the case's result, expected (a login that answers 303) or not (a sign-in that should have been refused): never a gap.
                row["redirect"] = "redirect-not-followed"
            if row["state"] == "pass":
                passed.add(case["id"])
            row["body_sha256"] = answers[case["id"]][1]
            entries.append(har_entry(plan["target"], case, status, headers, body, sent, payload))
        except ssl.SSLCertVerificationError:
            row.update(state="incomplete", gap="tls-certificate-not-verified")
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            # Exceptions may embed target data or credentials. Return only a fixed reason.
            row.update(state="incomplete", gap="request-failed-or-response-limit")
        time.sleep(min(INTERVAL, max(0, deadline - time.monotonic())))
    return observations, {"log": {"version": "1.2", "creator": {"name": "local-dast", "version": "0.1"}, "entries": entries}}


def verify_archive(path):
    if digest(path) != ARCHIVE_SHA256:
        raise ValueError("ZAP archive does not match the bundled SHA-256 pin")


def extract_zap(archive, destination):
    """Use only the pinned distribution and required passive-analysis add-ons."""
    verify_archive(archive)
    inventory = []
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in item.filename or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Unsafe archive member")
            if item.filename.endswith(".zap"):
                if path.name.split("-")[0] not in ADDONS:
                    continue
                inventory.append(path.name)
            bundle.extract(item, destination)
    if {name.split("-")[0] for name in inventory} != ADDONS:
        raise ValueError("Pinned distribution is missing a required add-on")
    return destination / f"ZAP_{VERSION}", sorted(inventory)


def zap_plan(har, output, target):
    return {"env": {"contexts": [{"name": "local", "urls": [target], "includePaths": [re.escape(target) + r"/.*"]}],
                    "parameters": {"failOnError": True, "failOnWarning": True, "progressToStdout": False}},
            "jobs": [
                {"type": "passiveScan-config", "parameters": {"scanOnlyInScope": False}},
                {"type": "import", "parameters": {"type": "har", "fileName": str(har)}},
                {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                {"type": "report", "parameters": {"template": "traditional-json", "reportDir": str(output),
                                                  "reportFile": "zap-raw.json", "displayReport": False}},
            ]}


def numeric(value):
    text = str(value)
    if not re.fullmatch(r"[0-9]{1,10}", text):
        raise ValueError("Unexpected ZAP numeric field")
    return int(text)


def project_alerts(raw, plan):
    """Never send raw URLs, titles, evidence strings, response bodies or credentials to the model."""
    if not isinstance(raw, dict) or "site" not in raw or not isinstance(raw["site"], list):
        raise ValueError("Invalid ZAP report")
    findings = []
    case_ids = {}
    for case in plan["cases"]:
        case_ids.setdefault((case.get("method", "GET"), plan["target"] + case["path"]), []).append(case["id"])
    for site in raw["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list):
            raise ValueError("Invalid ZAP site report")
        for alert in site["alerts"]:
            rule, risk, confidence = (numeric(alert[key]) for key in ("pluginid", "riskcode", "confidence"))
            if risk > 3 or confidence > 4:
                raise ValueError("Unexpected ZAP risk or confidence")
            alert_ref = str(alert.get("alertRef", rule))
            if not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,4})?", alert_ref):
                raise ValueError("Unexpected ZAP alert reference")
            instances = alert.get("instances")
            if not isinstance(instances, list):
                raise ValueError("Missing ZAP instance evidence")
            matching, unmapped, ambiguous = set(), 0, 0
            for instance in instances:
                matches = case_ids.get((instance.get("method") or "GET", instance.get("uri")), []) if isinstance(instance, dict) else []
                matching.update(matches)
                unmapped += not matches
                ambiguous += len(matches) > 1
            findings.append({"id": f"DAST-{len(findings) + 1:04d}", "rule": rule,
                             "alert_ref": alert_ref,
                             "severity": ["info", "low", "medium", "high"][risk],
                             "scanner_confidence": confidence, "instances": numeric(alert["count"]),
                             "observed_cases": sorted(matching), "unmapped_instances": unmapped,
                             "ambiguous_instances": ambiguous,
                             "reference": f"https://www.zaproxy.org/docs/alerts/{alert_ref}/", "disposition": "unreviewed"})
    return findings


def analyze(archive, java, private, case_plan):
    with tempfile.TemporaryDirectory(prefix="rasmus-dast-zap-") as name:
        runtime = Path(name)
        home, addons = extract_zap(archive, runtime)
        work = private / "zap-home"
        work.mkdir(mode=0o700)
        plan = private / "zap-plan.json"
        write_json(plan, zap_plan(private / "traffic.har", private, case_plan["target"]))
        # ZAP opens its proxy port even when it only reads a file; a port of its own lets two runs on one machine both finish.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        args = [java, "-Xmx512m", "-Djava.awt.headless=true", "-jar", str(home / f"zap-{VERSION}.jar"),
                "-cmd", "-silent", "-host", "127.0.0.1", "-port", str(port), "-dir", str(work), "-autorun", str(plan),
                "-config", "autoupdate.checkOnStart=false", "-config", "autoupdate.downloadNewRelease=false",
                "-config", "autoupdate.installAddonUpdates=false", "-config", "autoupdate.installScannerRules=false",
                "-config", "api.enabled=false"]
        env = {"PATH": os.defpath, "HOME": str(runtime), "TMPDIR": str(runtime), "LANG": "en_US.UTF-8"}
        with (private / "zap.log").open("xb") as log:
            process = subprocess.Popen(args, cwd=home, env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                code = process.wait(timeout=120)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError("ZAP timed out or was interrupted; analysis is incomplete") from None
        if code != 0:
            raise ValueError("ZAP did not complete successfully; private log retained")
        raw_path = private / "zap-raw.json"
        if not raw_path.is_file() or raw_path.stat().st_size > 20 * MAX_BODY:
            raise ValueError("ZAP report is missing or exceeds limit")
        findings = project_alerts(json.loads(raw_path.read_text()), case_plan)
        return findings, {"version": VERSION, "archive_sha256": ARCHIVE_SHA256, "addons": addons,
                          "mode": "recorded-traffic-passive", "status": "complete"}


def policy_pairs(plan, policy, observations):
    """Each row, role and (for allow if) whether the condition holds: what the policy expects, the cases tagged with it, their result."""
    state = {row["id"]: row["state"] for row in observations}
    pairs = []
    for row, cells in policy["rows"].items():
        for role, cell in cells.items():
            for holds in ((True, False) if cell.startswith("allow if") else (None,)):
                tag = {"row": row, "role": role, **({} if holds is None else {"holds": holds})}
                cases = [case for case in plan["cases"] if case.get("policy") == tag]
                writes = [n for n, case in enumerate(cases) if changes_state(case)]
                states = {state[case["id"]] for case in cases}
                if not cases:
                    result = "missing"
                elif writes and all(changes_state(case) for case in cases[writes[-1] + 1:]):
                    result = "missing-reread"  # a write's status proves little; the read after it judges
                else:
                    result = "pass" if states == {"pass"} else "fail" if "assertion-failed" in states else "not-run"
                pairs.append({**tag, "expect": "allow" if cell == "allow" or holds else "deny", "cases": [case["id"] for case in cases], "result": result})
    return pairs


def render(report, directory):
    lines = ["# DAST observations", "", f"Status: {report['status']}", f"Target: {report['target']}", "",
             "Passing assertions describe only the supplied cases. Scanner alerts remain unreviewed.", "",
             "| Case | Method | Result | HTTP status | Failed checks | Coverage gap |", "| --- | --- | --- | --- | --- | --- |"]
    for row in report["cases"]:
        failed = ", ".join(name + (f" ({', '.join(map(str, row[name + '_failed']))})" if row.get(name + "_failed") else "")
                           for name, ok in row.get("checks", {}).items() if not ok) or "—"
        lines.append(f"| {row['id']} | {row.get('method', 'GET')} | {row['state']} | {row.get('status', '—')} | {failed} | {row.get('gap', row.get('redirect', '—'))} |")
    lines += ["", "| Candidate | ZAP rule | Severity | Instances | Observed cases |", "| --- | --- | --- | --- | --- |"]
    for finding in report["findings"]:
        cases = ", ".join(finding["observed_cases"]) or "unmapped"
        lines.append(f"| {finding['id']} | [{finding['rule']}]({finding['reference']}) | {finding['severity']} | {finding['instances']} | {cases} |")
    if "policy" in report:
        lines += ["", "## Access policy, " + ("PROPOSED: the owner has not confirmed it" if report["policy"]["status"] == "proposed" else "confirmed by the owner"), "",
                  "| Row | Role | Condition | Expected | Result | Cases |", "| --- | --- | --- | --- | --- | --- |"]
        for pair in report["policy"]["pairs"]:
            condition = {None: "—", True: "holds", False: "fails"}[pair.get("holds")]
            lines.append(f"| {pair['row']} | {pair['role']} | {condition} | {pair['expect']} | {pair['result']} | {', '.join(pair['cases']) or '—'} |")
    lines += ["", "## Coverage limits", ""] + [f"- {gap}" for gap in report["coverage_gaps"]]
    (directory / "review.md").write_text("\n".join(lines) + "\n")
    os.chmod(directory / "review.md", 0o600)


def run(plan, archive=None, java=None, writes=False, remote=None, policy=None, out=None):
    validate_plan(plan, writes, remote, policy)
    if archive:
        verify_archive(archive)
        if not java or not Path(java).is_absolute() or not Path(java).is_file() or not os.access(java, os.X_OK):
            raise ValueError("Supply an absolute path to a Java 17+ executable")
    directory = Path(tempfile.mkdtemp(prefix="rasmus-local-dast-", dir=out))
    private = directory / "private"
    private.mkdir(mode=0o700)
    write_json(private / "plan.json", plan)
    observations, har = capture(plan, writes, remote, policy)
    write_json(private / "traffic.har", har)
    findings = []
    zap = {"status": "skipped", "reason": "http-only-requested"}
    if archive:
        try:
            # ZAP names an alert's URL as it was sent; map it to a case through the paths the capture filled in.
            sent = {entry["comment"]: entry["request"]["url"][len(plan["target"]):] for entry in har["log"]["entries"]}
            findings, zap = analyze(archive, java, private, {**plan, "cases": [{**case, "path": sent.get(case["id"], case["path"])} for case in plan["cases"]]})
        except (OSError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
            zap = {"status": "incomplete", "reason": "analysis-failed-see-private-log"}
    pairs = policy_pairs(plan, policy, observations) if policy else []
    uncovered = [f"{p['row']} {p['role']}" + {None: "", True: " (condition holds)", False: " (condition fails)"}[p.get("holds")]
                 + (", no read after the write" if p["result"] == "missing-reread" else "") for p in pairs if p["result"].startswith("missing")]
    reasons = ([f"zap: {zap['reason']}"] if zap["status"] != "complete" else []) + [f"case {row['id']}: {row['gap']}" for row in observations if "gap" in row] + [
        f"policy: {pair}" for pair in uncovered]
    incomplete = bool(reasons)
    failed = bool(findings) or any(row["state"] == "assertion-failed" for row in observations)
    scope = (["No crawler, browser execution or active vulnerability scan. The TLS certificate was verified; the TLS configuration was not assessed.",
              "The target is a deployed environment: every request had its real effect there, and nothing was isolated or reset."]
             if remote else
             ["No crawler, browser execution, active vulnerability scan or TLS.",
              "Loopback scoping does not sandbox the application or prevent its outbound connections."])
    report = {"schema_version": 1, "status": "incomplete" if incomplete else "candidates" if failed else "no-candidates",
              "target": "remote" if remote else "loopback",
              "cases": observations, "findings": findings, "zap": zap, **({"incomplete_because": reasons} if reasons else {}),
              "coverage_gaps": ["Only the explicitly listed requests were sent; redirects were not followed.",
                                "Authentication and access policy are covered only by explicit identity and access assertions.", *scope],
              "evidence": {"har_sha256": digest(private / "traffic.har"), "plan_sha256": digest(private / "plan.json")}}
    if zap["status"] != "complete":
        report["coverage_gaps"].append("ZAP passive analysis did not complete.")
    if any(changes_state(case) for case in plan["cases"]):
        report["coverage_gaps"].append("State-changing requests were sent; reset the instance's data before another run.")
    if policy:
        report["policy"] = {"status": policy["status"], "pairs": pairs}
        report["evidence"]["policy_sha256"] = policy["sha256"]
        if policy["status"] == "proposed":
            report["coverage_gaps"].append("Judged against an access policy that is PROPOSED: the owner has not confirmed it.")
        if uncovered:
            report["coverage_gaps"].append("Access policy pairs without a case: " + "; ".join(uncovered) + ".")
    write_json(directory / "report.json", report)
    render(report, directory)
    return directory, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, nargs="?")
    parser.add_argument("--check", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--zap-archive", type=Path)
    group.add_argument("--http-only", action="store_true", help="Explicitly skip ZAP; result remains incomplete")
    parser.add_argument("--java", help="Absolute path to a Java 17+ executable")
    parser.add_argument("--allow-writes", action="store_true",
                        help="Send the plan's state-changing cases (POST, PUT, PATCH, DELETE; a JSON-RPC read needs no flag); only where data may be changed")
    parser.add_argument("--policy", type=Path, metavar="PROFILE",
                        help="security/profile.md of the source repository; its Access policy table judges the cases tagged with policy")
    parser.add_argument("--out", type=Path, metavar="FOLDER", help="An existing private folder to make the run directory in, instead of the system's temporary folder")
    parser.add_argument("--only", action="append", metavar="CASE",
                        help="Run this case and what it rests on (its requires, the case it is compared with, the cases its values come from); may be given more than once")
    parser.add_argument("--remote", metavar="ORIGIN",
                        help="Test this one https://hostname, a pre-production environment the user named, instead of a loopback port")
    args = parser.parse_args()
    if args.check:
        ready = False
        if args.zap_archive:
            verify_archive(args.zap_archive)
            ready = bool(args.java and Path(args.java).is_absolute() and Path(args.java).is_file() and os.access(args.java, os.X_OK))
        print(json.dumps({"status": "ready-for-run" if ready else "needs-setup", "zap_version": VERSION,
                          "java_runtime_verified": False, "network_used": False}))
        return 0 if ready else 2
    if not args.plan or not (args.zap_archive or args.http_only):
        parser.error("Supply a plan and either --zap-archive or --http-only")
    if args.plan.stat().st_size > 256 * 1024:
        parser.error("Plan exceeds 256 KiB")
    plan = json.loads(args.plan.read_text())
    policy = None
    if args.policy:
        try:
            policy = parse_policy(args.policy.read_text())
        except ValueError as error:  # the message names only what is wrong with the table's shape, never its text
            parser.error(str(error))
    if args.only:
        # The whole plan must be sound before part of it is cut out; the variables of the cases that are cut need not be set.
        validate_plan(plan, True, args.remote, policy, absent="unset")
        plan = only(plan, args.only)
    cases = plan.get("cases") if isinstance(plan, dict) else None
    if not args.allow_writes and isinstance(cases, list) and any(isinstance(c, dict) and changes_state(c) for c in cases):
        parser.error("The plan holds state-changing cases; they run only with --allow-writes")
    directory, report = run(plan, args.zap_archive, args.java, args.allow_writes, args.remote, policy, args.out)
    print(json.dumps({"status": report["status"], "report": str(directory / "report.json"), "review": str(directory / "review.md")}))
    return {"no-candidates": 0, "candidates": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except PlanError as error:
        print(json.dumps({"status": "incomplete", "error": str(error)}))
        sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, zipfile.BadZipFile):
        print(json.dumps({"status": "incomplete", "error": "Invalid plan, archive or runtime. See the skill's setup and plan reference."}))
        sys.exit(2)
