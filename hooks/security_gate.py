#!/usr/bin/env python3
"""Security gate: Claude Code hooks that make a person approve the edits that weaken checks.

  PreToolUse  Edit|Write|MultiEdit|NotebookEdit  ask when an edit adds a suppression marker, weakens a test or writes a protected file
  PreToolUse  Bash                               deny installing a package the public registry does not know; ask when it is under 30 days old
  PostToolUse Edit|Write|MultiEdit|NotebookEdit  remember the edited file for this session, in the temp directory
  Stop                                           block once when this session edited a file with a confirmed finding in security/findings.csv

Any error lets the tool run and prints nothing (fail open). AGENT_TOOLS_SECURITY_GATE=off turns the gate off.
Only a package name leaves the machine, and only to pypi.org or registry.npmjs.org.
"""
import concurrent.futures
import csv
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

EDITS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
MAX_FILE = 5_000_000
MAX_META = 2_000_000  # a registry document this large has a long release history, so the package is not new
NEW_DAYS = 30
TIMEOUT = 3

SUPPRESSIONS = {
    "# nosec": r"#\s*nosec\b",
    "nosemgrep": r"nosemgrep",
    "eslint-disable": r"eslint-disable",
    "# noqa: S…": r"#\s*noqa\s*:[^\n]*\bS\d",
    "@SuppressWarnings(security)": r"(?i)@SuppressWarnings\s*\([^)]*security",
    "NOSONAR": r"NOSONAR",
}
ASSERTS = re.compile(r"\bassert\w*|\bexpect\s*\(|\braises\s*\(|\bt\.(?:Error|Fatal)\w*\(")
SKIPS = re.compile(r"pytest\.mark\.(?:skip|skipif|xfail)\b|pytest\.(?:skip|xfail)\s*\(|unittest\.(?:skip\w*|expectedFailure)\b"
                   r"|\bskipTest\s*\(|\b(?:it|test|describe|context|suite)\.(?:skip|only|todo)\b"
                   r"|\b(?:xit|xtest|xdescribe|fit|fdescribe)\s*\(|#\[ignore\]|\bt\.Skip\w*\(")
TEST_NAME = re.compile(r"^test_.*\.py$|_test\.\w+$|\.(?:test|spec)\.[cm]?[jt]sx?$")

# A custom package source: the public registry cannot speak for it, so the install is not checked.
PRIVATE = {"-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links", "--no-index",
           "--registry", "--source"}
# Options that take a value. Treating a flag as valued only skips a name; the reverse could deny a real install.
VALUED = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--prefix", "--root",
          "--python", "-p", "--project", "--group", "-G", "--optional", "--extra", "-E", "--extras", "--tag", "-w",
          "--workspace", "--filter", "--platform", "--python-version", "--implementation", "--abi", "--src",
          "--cache-dir", "--log", "--upgrade-strategy", "--only-binary", "--no-binary", "--package", "--script",
          "--branch", "--rev", "--path", "--marker", "--directory", "--save-prefix", "--progress-bar", "--report"}
REGISTRY = {"pypi": "PyPI", "npm": "npm"}


def decide(decision, reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": "security gate: " + reason}}


def locate(event):
    inp = event.get("tool_input") or {}
    raw = inp.get("file_path") or inp.get("notebook_path")
    if not raw:
        return None, None
    cwd = Path(event.get("cwd") or os.getcwd()).resolve()
    path = (cwd / raw).resolve()
    try:
        return path, path.relative_to(cwd)
    except ValueError:
        return path, path


def texts(tool, inp, path):
    """The text before and after the edit, or (None, None) when it cannot be known."""
    if path.is_file() and path.stat().st_size > MAX_FILE:
        return None, None
    before = path.read_text(errors="replace") if path.is_file() else ""
    if tool == "Write":
        return before, inp.get("content") or ""
    if tool == "NotebookEdit":
        cells = json.loads(before).get("cells", []) if before.strip() else []
        cell = next((c for c in cells if c.get("id") == inp.get("cell_id")), None)
        src = cell.get("source", "") if cell else ""
        old = "".join(src) if isinstance(src, list) else src
        mode = inp.get("edit_mode") or "replace"
        return ("" if mode == "insert" else old), ("" if mode == "delete" else inp.get("new_source") or "")
    after = before
    for e in [inp] if tool == "Edit" else inp.get("edits") or []:
        old, new = e.get("old_string", ""), e.get("new_string", "")
        if old not in after:
            return None, None  # the tool will refuse this edit itself
        after = after.replace(old, new) if e.get("replace_all") else after.replace(old, new, 1)
    return before, after


def bandit(text):
    lines, inside = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("["):
            inside = line.strip().startswith(("[tool.bandit]", "[tool.bandit."))
        if inside:
            lines.append(line)
    return lines


def path_reasons(rel, before, after, new_file=False):
    where, name = "/" + rel.as_posix() + "/", rel.name
    if "/tests/security/" in where and not new_file:  # adding a proof weakens nothing; changing one might
        return ["changes a confirmed security proof under tests/security/"]
    if "/.claude/" in where and re.fullmatch(r"settings(?:\.local)?\.json", name):
        return ["changes Claude Code settings, where hooks such as this gate can be turned off"]
    if "/.github/workflows/" in where:
        return ["changes a CI workflow in .github/workflows/"]
    if name.startswith((".semgrep", ".eslintrc", "eslint.config.")) or name in (".bandit", "bandit.yaml", "bandit.yml"):
        return [f"changes scanner configuration ({name})"]
    if name == "pyproject.toml" and after is not None and bandit(before) != bandit(after):
        return ["changes the [tool.bandit] section of pyproject.toml"]
    return []


def edit_reasons(rel, before, after):
    reasons = []
    added = [m for m, rx in SUPPRESSIONS.items() if len(re.findall(rx, after)) > len(re.findall(rx, before))]
    if added:
        reasons.append("adds the suppression marker " + ", ".join(added))
    if {"test", "tests", "__tests__"} & set(rel.parts[:-1]) or TEST_NAME.search(rel.name):
        old, new = len(ASSERTS.findall(before)), len(ASSERTS.findall(after))
        if before.strip() and not after.strip():
            reasons.append("empties a test file")
        elif new < old:
            reasons.append(f"lowers the assertions in a test file from {old} to {new}")
        if len(SKIPS.findall(after)) > len(SKIPS.findall(before)):
            reasons.append("adds a skip, xfail or only marker to a test")
    return reasons


def pre_edit(event):
    path, rel = locate(event)
    if path is None:
        return None
    before, after = texts(event["tool_name"], event.get("tool_input") or {}, path)
    reasons = path_reasons(rel, before, after, not path.exists()) + (edit_reasons(rel, before, after) if after is not None else [])
    if reasons:
        return decide("ask", f"this edit of {rel.as_posix()} " + "; ".join(reasons) + ". A person should approve it.")
    return None


def installs(command):
    """(ecosystem, arguments) for each package install in a shell command."""
    for segment in re.split(r"&&|\|\||[;|&\n()]", command):
        try:
            t = shlex.split(segment)
        except ValueError:
            continue
        while t and (re.match(r"^[A-Za-z_]\w*=", t[0]) or t[0] in ("sudo", "command", "exec", "time", "nohup")):
            t = t[1:]
        if len(t) > 2 and re.fullmatch(r"python[\d.]*", os.path.basename(t[0])) and t[1] == "-m":
            t = t[2:]
        if not t:
            continue
        tool, sub = os.path.basename(t[0]), t[1:3]
        if re.fullmatch(r"pip[\d.]*", tool) and sub[:1] == ["install"] or tool in ("uv", "poetry") and sub[:1] == ["add"]:
            yield "pypi", t[2:]
        elif tool == "uv" and sub == ["pip", "install"]:
            yield "pypi", t[3:]
        elif tool == "npm" and sub[:1] in (["install"], ["i"], ["add"]) or tool in ("pnpm", "yarn", "bun") and sub[:1] == ["add"]:
            yield "npm", t[2:]


def package(eco, spec):
    """The registry name in an install argument, or None for paths, URLs, archives, git refs and aliases."""
    if "://" in spec or spec.startswith((".", "~", "/")) or re.search(r"\.(?:whl|tgz|zip|tar(?:\.\w+)?)$", spec):
        return None
    if eco == "npm":
        m = re.fullmatch(r"((?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*)(?:@[^:/]*)?", spec, re.I)
    else:
        m = None if "/" in spec or "\\" in spec else re.match(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:$|[\[=<>!~;@ ,])", spec)
    return m.group(1) if m else None


def names(eco, args):
    found, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a.split("=")[0] in PRIVATE:
            return []
        elif a.startswith("-"):
            skip = a in VALUED
        elif package(eco, a):
            found.append(package(eco, a))
    return found


def lookup(eco, name):
    """'missing', the first release time, or None when the registry does not answer clearly."""
    url = (f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json" if eco == "pypi"
           else "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    request = urllib.request.Request(url, headers={"User-Agent": "security-gate", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_META + 1)
        if len(body) > MAX_META:
            return None
        doc = json.loads(body)
        if eco == "pypi":
            times = [f.get("upload_time_iso_8601") for files in (doc.get("releases") or {}).values() for f in files]
        else:
            times = [(doc.get("time") or {}).get("created")]
        times = [datetime.datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times if t]
        return min(times) if times else None
    except urllib.error.HTTPError as e:
        return "missing" if e.code == 404 else None
    except Exception:
        return None


PUBLIC = re.compile(r"^https?://(registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|files\.pythonhosted\.org)(/|$)", re.I)
REGISTRY_ENV = {"npm": ("npm_config_registry", "NPM_CONFIG_REGISTRY", "YARN_NPM_REGISTRY_SERVER"),
                "pypi": ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX", "UV_EXTRA_INDEX_URL")}
REGISTRY_LINE = {"npm": re.compile(r"^\s*(?:@[\w.-]+:)?registry\s*=\s*(\S+)|^\s*npmRegistryServer\s*:\s*[\"']?([^\"'\s]+)", re.M),
                 "pypi": re.compile(r"^\s*(?:extra-)?index-url\s*=\s*(\S+)|^\s*url\s*=\s*[\"']([^\"']+)", re.M)}


def private_registry(eco, cwd):
    """Where a registry other than the public one is set up for this ecosystem (a file name or a variable name), or None.

    The package manager reads this configuration itself, so a name it resolves privately must not be sent to the public
    registry. Only names are returned, never values."""
    for var in REGISTRY_ENV[eco]:
        value = os.environ.get(var, "")
        if value and not all(PUBLIC.match(v) for v in value.split()):
            return var
    home = Path.home()
    folders = [cwd, *cwd.parents] if cwd else []
    if eco == "npm":
        files = [f / name for f in folders for name in (".npmrc", ".yarnrc.yml")] + [home / ".npmrc", home / ".yarnrc.yml"]
    else:
        files = ([Path(os.environ["PIP_CONFIG_FILE"])] if os.environ.get("PIP_CONFIG_FILE") else []) + \
                [home / ".config/pip/pip.conf", home / ".pip/pip.conf", home / "Library/Application Support/pip/pip.conf",
                 Path("/etc/pip.conf")] + [f / name for f in folders for name in ("pip.conf", "uv.toml", "pyproject.toml", "poetry.toml")]
    for f in files:
        try:
            text = f.read_text(errors="replace") if f.is_file() and f.stat().st_size < 1_000_000 else ""
        except OSError:
            continue
        if eco == "pypi" and f.name == "pyproject.toml" and not re.search(r"\[\[tool\.(uv\.index|poetry\.source)\]\]|\[tool\.uv\][^\[]*index", text):
            continue
        for m in REGISTRY_LINE[eco].finditer(text):
            url = next(g for g in m.groups() if g)
            if not PUBLIC.match(url):
                return f.name
    return None


def pre_bash(event):
    wanted = sorted({(eco, n) for eco, args in installs((event.get("tool_input") or {}).get("command") or "")
                     for n in names(eco, args)})
    if not wanted:
        return None
    cwd = Path(event["cwd"]) if event.get("cwd") else None
    private = {eco: private_registry(eco, cwd) for eco in {e for e, _ in wanted}}
    skipped = {eco: where for eco, where in private.items() if where}
    wanted = [(e, n) for e, n in wanted if e not in skipped]
    if not wanted:
        return {"systemMessage": "security gate: package names were not looked up on the public registry, because a private "
                "registry is configured (" + ", ".join(f"{REGISTRY[e]}: {w}" for e, w in sorted(skipped.items())) + ")"}
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        found = list(zip(wanted, pool.map(lambda w: lookup(*w), wanted)))
    missing = [f"{n} ({REGISTRY[e]})" for (e, n), v in found if v == "missing"]
    if missing:
        return decide("deny", f"{', '.join(missing)} does not exist in the public registry. Check the name: a name an agent "
                              "invented can be registered by an attacker (slopsquatting).")
    now = datetime.datetime.now(datetime.timezone.utc)
    young = [f"{n} ({REGISTRY[e]}, first published {v.date()})" for (e, n), v in found
             if isinstance(v, datetime.datetime) and now - v < datetime.timedelta(days=NEW_DAYS)]
    if young:
        return decide("ask", f"{', '.join(young)} is less than {NEW_DAYS} days old. Confirm it is the package you mean.")
    return None


def session_file(event):
    sid = re.sub(r"[^\w-]", "", str(event.get("session_id") or ""))
    return Path(tempfile.gettempdir()) / f"security-gate-{sid}.txt" if sid else None


def post_edit(event):
    path, _ = locate(event)
    log = session_file(event)
    if path and log:
        with log.open("a") as f:
            f.write(f"{path}\n")


def stop(event):
    log = session_file(event)
    if not log or not log.is_file():
        return None
    edited = set(log.read_text().splitlines())
    log.unlink()  # each stop judges the edits made since the last one, so a finding blocks once
    if event.get("stop_hook_active"):
        return None
    root, cwd = None, Path(event.get("cwd") or os.getcwd()).resolve()
    for d in (cwd, *cwd.parents):  # up to the repository root, never above it
        if (d / "security/findings.csv").is_file():
            root = d
            break
        if (d / ".git").exists():
            return None
    if root is None:
        return None
    with (root / "security/findings.csv").open(newline="") as f:
        hits = [r for r in csv.DictReader(f) if r.get("status") == "confirmed" and r.get("path")
                and str((root / r["path"]).resolve()) in edited]
    if not hits:
        return None
    listed = "; ".join(f"{r['path']} ({r.get('skill')}, {r.get('rule')}): {r.get('note')}" for r in hits)
    return {"decision": "block", "reason": "security gate: this session edited files that have confirmed findings in "
            f"security/findings.csv: {listed}. Before you stop, run each finding's proof again (tests/security/ when there "
            "is one) and tell the user whether your edits fix, keep or weaken each finding."}


def main(stdin=sys.stdin, stdout=sys.stdout):
    try:
        if os.environ.get("AGENT_TOOLS_SECURITY_GATE", "").lower() in ("off", "0", "false", "no"):
            return 0
        event = json.load(stdin)
        hook, tool = event.get("hook_event_name"), event.get("tool_name")
        out = None
        if hook == "PreToolUse" and tool == "Bash":
            out = pre_bash(event)
        elif hook == "PreToolUse" and tool in EDITS:
            out = pre_edit(event)
        elif hook == "PostToolUse" and tool in EDITS:
            post_edit(event)
        elif hook == "Stop":
            out = stop(event)
        if out:
            stdout.write(json.dumps(out))
    except Exception as error:
        # The tool call goes ahead, as it always has; say so, with the error's type only (no command, content or names).
        stdout.write(json.dumps({"systemMessage": f"security gate: this call was not checked ({type(error).__name__} inside the gate)"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
