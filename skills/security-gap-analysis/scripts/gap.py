"""Keep a repository's security/ folder consistent: requirements, file coverage and the boundary inventory.

  gap.py init      REPO --select asvs:2 [--select aisvs:2] [--select masvs]
  gap.py show      REPO [PREFIX ...] [--status S]
  gap.py set       REPO PREFIX ... --status S [--evidence "path:line; path:line-line"] [--notes TEXT]
  gap.py files     REPO [--list STATUS] [--mark PATH ... --status S [--notes TEXT]]
  gap.py inventory REPO [--list STATUS] [--mark --kind K --path P --lines A-B --status S [--notes TEXT]]
  gap.py check     REPO [--complete]
  gap.py probe     REPO INVARIANT --copy DIR --file PATH --old TEXT --new TEXT -- COMMAND ...

A PREFIX is standard:id-prefix, for example asvs:V6, asvs:V6.2.1, aisvs:9, aisvs-ac:AC.4, masvs:MASVS-STORAGE.
A PATH is a file or a directory; "." is the whole repository.
"""
import argparse
import contextlib
import csv
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CATALOGS = Path(__file__).resolve().parents[1] / "catalogs"
FIELDS = ["standard", "id", "level", "status", "evidence", "notes", "assessed"]
STATUSES = ["unassessed", "met", "partial", "missing", "not-applicable", "unverifiable", "risk-accepted"]
NEEDS_EVIDENCE = {"met", "partial"}
NEEDS_NOTES = set(STATUSES) - {"unassessed", "met"}
EVIDENCE = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")

FILE_FIELDS = ["path", "lines", "status", "sha", "notes"]
FILE_STATUSES = ["unread", "read", "skimmed", "skipped"]
INV_FIELDS = ["kind", "path", "line", "text", "status", "notes"]
INV_STATUSES = ["unreviewed", "boundary", "internal", "test"]
# The whole folder. A file outside this list is a problem: state lives in these, not in one more file per run.
SECURITY_FILES = ["profile.md", "files.csv", "inventory.csv", "requirements.csv", "gaps.md", "accepted-risks.md", "findings.csv"]
# findings.csv is written by ledger.py of local-security-review and local-dast; this is its header.
FINDING_FIELDS = ["fingerprint", "skill", "rule", "path", "status", "basis", "sha", "first_seen", "last_seen", "note"]
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__", "vendor", ".next"}
# Third-party code checked in beside the product's own. Its files are still listed (skip the folder in one mark), but raise no inventory lines.
VENDORED = {"vendor", "node_modules", "third_party"}
# A licence header's URL is not a network call.
LICENCE_URL = re.compile(r"(apache\.org|opensource\.org|gnu\.org|creativecommons\.org|mozilla\.org/MPL|eclipse\.org/legal)/", re.I)
CODE = re.compile(r"\.(m|c)?(t|j)sx?$|\.(py|rs|go|java|kt|kts|rb|php|cs|swift|m|mm|c|cc|cpp|h|hpp|html?|vue|svelte|astro"
                  r"|sh|ps1|ya?ml|toml|tf|xml|plist|entitlements|gradle|conf|conf\.template)$|(^|/)Dockerfile[^/]*$|(^|/)package\.json$")
# Where input from outside can enter, or where code acts on something outside. Recall matters more than
# precision: every hit is either named in the profile or marked internal or test with a reason.
SIGNALS = [
    ("listen", r"TcpListener|UdpSocket::bind|UnixListener|\.listen\(|createServer\(|HTTPServer\(|socketserver\."
               r"|uvicorn\.run|\bapp\.run\((\)|\s*(host|port|debug)=)|axum::serve|hyper::Server|warp::serve|ListenAndServe|^\s*EXPOSE\s"
               r"|containerPort|bind\(\s*\(?\s*[\"'](0\.0\.0\.0|127\.0\.0\.1|localhost|::)"),
    ("route", r"\b(app|router|server|fastify|api|hono)\.(get|post|put|patch|delete|all|route|use)\(\s*[\"'`]"
              r"|@\w+\.(get|post|put|patch|delete|route|api_route|websocket)\(|#\[(get|post|put|patch|delete|route)\("
              r"|\.route\(\s*\"|HandleFunc\(|\(\s*\"(GET|POST|PUT|PATCH|DELETE)\"\s*,|\bpath\(\s*[\"']"
              r"|\bdef\s+\w*handler\(\s*event\b|exports\.handler\s*=|export\s+const\s+handler\b"
              r"|^\s*Type:\s*(Http)?Api\s*$|^\s*Type:\s*(SQS|SNS|S3|Kinesis|DynamoDB|Schedule|EventBridgeRule)\s*$"
              r"|AWS::(ApiGateway|ApiGatewayV2|AppSync|Lambda::Url)\b"
              r"|export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|^\s*[\"']use server[\"']"
              r"|\b(public|protected)Procedure\b|@(Get|Post|Put|Patch|Delete|Request)Mapping\("
              r"|^\s*location\s+(=|~\*?|\^~)?\s*\S+\s*\{|\bre_path\(|\burl\(\s*r?[\"']\^"),
    ("process", r"Command::new\(|\bsubprocess\.|os\.system\(|os\.popen\(|child_process|\bexecFile(Sync)?\(|(?<!::)\bspawn(Sync)?\("
                r"|\bexecSync\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|NSTask|Process\(\)"),
    ("network-out", r"https?://[a-z0-9-]+(\.[a-z0-9-]+)+|reqwest::|ureq::|\bfetch\(|axios|requests\.(get|post|put|delete|request)"
                    r"|urllib\.request|httpx\.|http\.Client|URLSession|aiohttp|\bopenConnection\(|\bnew\s+URL\("),
    ("deserialize", r"pickle\.loads?|torch\.load|yaml\.load\(|marshal\.loads|jsonpickle|ObjectInputStream|BinaryFormatter"
                    r"|\bunserialize\(|joblib\.load|from_pretrained|\.safetensors|NSKeyedUnarchiver"),
    ("html-sink", r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html|\|\s*safe\b"
                  r"|mark_safe|Markup\("),
    ("eval", r"\beval\(|new Function\(|\bexec\(|vm\.run|setTimeout\(\s*[\"'`]"),
    ("sql", r"\b(SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s.+\sSET|DELETE\s+FROM)\b|\.execute\(|\.raw\(|sqlx::query|rusqlite"),
    ("ai", r"anthropic|openai|langchain|llama_index|ollama|generativeai|bedrock|BedrockRuntime|McpServer|FastMCP|MCPServer"
           r"|\b(from|import)\s+mcp\b|modelcontextprotocol|\"claude\"|\"codex\"|from transformers|import transformers|import torch"
           r"|\bmessages\.create\(|chat\.completions|\.choices\[0\]|\bgenerate_content\(|\binvoke_model\("),
    # A file opened or served under a name that is built at run time. Favour recall: a constant path is marked internal.
    ("fs-path", r"createReadStream\(|\breadFile(Sync)?\(|\bopen\(\s*os\.path\.join\(|\bopen\(\s*\w+\s*/\s*\w+|decodeURIComponent\("
                r"|\bfs::(read|read_to_string|write|remove_file)\(|\bFile::(open|create)\(|\bFileResponse\("
                r"|\bnew\s+File(Input|Output)Stream\(|\bFiles\.(newInputStream|readAllBytes|copy)\("),
    ("auth", r"\b(request|req)\.headers\b|jwt\.|jsonwebtoken|jose\b|passport\.|Auth0|Cognito|OAuth|oidc|openid|[Aa]uthorization|Bearer|getServerSession"
             r"|NextAuth|msal|api[_-]?key|password|Set-Cookie|session\["),
    ("headers", r"Access-Control-Allow|Content-Security-Policy|\bcors\(|X-Frame-Options|Strict-Transport-Security"),
    ("env", r"env::var|process\.env|os\.environ|getenv\(|ENV\["),
    ("ipc", r"UnixStream|NSXPC|postMessage|addEventListener\(\s*[\"']message|WKWebView|ipcMain|ipcRenderer|contextBridge"
            r"|registerProtocol|deep.?link|tauri::command|android:exported=\"true\"|CFBundleURLSchemes|<intent-filter"),
    ("weak-crypto", r"\b(md5|MD5|sha1|SHA1|Md5|Sha1)\b|\bECB\b|Math\.random\(|\brandom\.random\("
                    r"|verify\s*=\s*False|danger_accept_invalid_(certs|hostnames)|rejectUnauthorized:\s*false"
                    r"|InsecureSkipVerify:\s*true|NODE_TLS_REJECT_UNAUTHORIZED|NSAllowsArbitraryLoads"
                    r"|usesCleartextTraffic=\"true\""),
    ("cli", r"\benv::args(_os)?\(|\bclap::|derive\([^)]*\bParser\b|import argparse|argparse\.|sys\.argv|process\.argv|\bclick\.(command|group)"
            r"|\btyper\.|io::stdin\(|sys\.stdin|process\.stdin|\.cli\.command\("),
    ("upload", r"\bmultipart\b|MultipartFile|\bmulter\b|UploadFile|formidable|busboy|\.extractall\(|tarfile\.open|zipfile\.ZipFile|ZipArchive"
               r"|ZipInputStream|tar::Archive|\btar\s+-?x|\bunzip\b|[Cc]ontent-[Dd]isposition"
               r"|\brequest\.files\b|\breq\.files?\b|\bsend_file\(|\bsend_from_directory\(|\bsendFile\("),
    ("store", r"localStorage|sessionStorage|document\.cookie|indexedDB|SecItem(Add|CopyMatching|Update)|\bKeychain"
              r"|SharedPreferences|UserDefaults|\bs3\.|put_object|PutObjectCommand|put_item|\bredis\b|mongodb|dynamodb(?!:)|DynamoDB"),
    ("pipeline", r"pull_request_target|workflow_run|\$\{\{\s*github\.(event|head_ref)|\$\{\{\s*secrets\.|permissions:\s*write-all"
                 r"|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|\b(npm|cargo|twine|gem)\s+(publish|upload|push)\b"
                 r"|docker\s+push|\"(pre|post)?install\"\s*:|uses:\s*[\w./-]+@(?![0-9a-f]{40}\b)"),
    ("ffi", r"\bunsafe\s*(\{|fn\b|impl\b|extern\b)|extern\s+\"C\"|#\[no_mangle\]|\bctypes\.|\bdlopen\(|System\.loadLibrary"),
]
SIGNAL_RES = [(kind, re.compile(p, re.I if kind in {"sql", "auth"} else 0)) for kind, p in SIGNALS]


def catalogs():
    return {p.stem: {r["id"]: r for r in json.loads(p.read_text())["requirements"]} for p in CATALOGS.glob("*.json")}


def csv_path(repo):
    return Path(repo) / "security" / "requirements.csv"


def load(repo):
    path = csv_path(repo)
    if not path.exists():
        sys.exit(f"{path} does not exist; run init first")
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != FIELDS:
            sys.exit(f"{path}: header must be {','.join(FIELDS)}")
        return list(reader)


def save(repo, rows):
    path = csv_path(repo)
    path.parent.mkdir(exist_ok=True)
    order = {k: i for i, k in enumerate(sorted(catalogs()))}
    rows.sort(key=lambda r: (order.get(r["standard"], 99), natural(r["id"])))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def natural(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def matches(prefix, row):
    standard, _, p = prefix.partition(":")
    i = row["id"]
    return row["standard"] == standard and (not p or i == p or i.startswith(p + ".") or i.startswith(p + "-"))


def revision(repo):
    try:
        sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()
        # The security folder being written is not a change to the code being judged.
        dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--", ".", ":!security"], capture_output=True,
                               text=True, check=True).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return datetime.date.today().isoformat()


def ensure_ignored(repo, entry):
    """Keep security state out of commits without touching a tracked file: add it to .git/info/exclude."""
    def git(*a):
        try:
            return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
        except OSError:
            return subprocess.CompletedProcess(a, 1, "", "")
    if git("rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        return
    if git("ls-files", "--", entry).stdout.strip() or git("check-ignore", "-q", entry).returncode == 0:
        return
    exclude = Path(git("rev-parse", "--git-path", "info/exclude").stdout.strip())
    exclude = exclude if exclude.is_absolute() else Path(repo) / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    with exclude.open("a") as f:
        f.write(f"\n# local security state, not for commits\n{entry}\n")
    print(f"ignored: added {entry} to {exclude}")


def init(args):
    cats = catalogs()
    path = csv_path(args.repo)
    rows = load(args.repo) if path.exists() else []
    have = {(r["standard"], r["id"]) for r in rows}
    added = 0
    for sel in args.select:
        standard, _, level = sel.partition(":")
        if standard not in cats:
            sys.exit(f"unknown standard {standard}; known: {', '.join(sorted(cats))}")
        for req in cats[standard].values():
            if req["level"] <= int(level or 3) and (standard, req["id"]) not in have:
                rows.append({"standard": standard, "id": req["id"], "level": str(req["level"]),
                             "status": "unassessed", "evidence": "", "notes": "", "assessed": ""})
                added += 1
    save(args.repo, rows)
    print(f"{path}: {added} requirements added, {len(rows)} in total")


def show(args):
    cats = catalogs()
    for r in load(args.repo):
        if (not args.prefix or any(matches(p, r) for p in args.prefix)) and (not args.status or r["status"] in args.status):
            req = cats.get(r["standard"], {}).get(r["id"], {})
            print(f'{r["standard"]}:{r["id"]}\tL{r["level"]}\t{r["status"]}\t{req.get("section", "?")}\n'
                  f'  {req.get("text", "NOT IN CATALOG")}')
            for k in ("evidence", "notes"):
                if r[k]:
                    print(f"  {k}: {r[k]}")


def set_(args):
    rows = load(args.repo)
    hit = [r for r in rows if any(matches(p, r) for p in args.prefix)]
    if not hit:
        sys.exit("no row matches " + " ".join(args.prefix))
    rev = revision(args.repo)
    for r in hit:
        r["status"] = args.status
        if args.evidence is not None:
            r["evidence"] = args.evidence
        if args.notes is not None:
            r["notes"] = args.notes
        r["assessed"] = rev
    save(args.repo, rows)
    errors = [e for r in hit for e in problems(Path(args.repo), r, catalogs(), accepted_ids(args.repo))]
    print(f"{len(hit)} rows set to {args.status}")
    for e in errors:
        print("  problem: " + e)
    return 1 if errors else 0


def accepted_ids(repo):
    p = Path(repo) / "security" / "accepted-risks.md"
    return p.read_text() if p.exists() else ""


def evidence_items(row):
    return [e.strip() for e in row["evidence"].split(";") if e.strip()]


def problems(repo, r, cats, accepted):
    key = f'{r["standard"]}:{r["id"]}'
    out = []
    if r["id"] not in cats.get(r["standard"], {}):
        out.append(f"{key}: not in the bundled catalog")
    if r["status"] not in STATUSES:
        return out + [f'{key}: status "{r["status"]}" is not one of {", ".join(STATUSES)}']
    if r["status"] in NEEDS_EVIDENCE and not evidence_items(r):
        out.append(f"{key}: {r['status']} needs evidence (path:line)")
    if r["status"] in NEEDS_NOTES and not r["notes"].strip():
        out.append(f"{key}: {r['status']} needs notes saying why")
    if r["status"] == "risk-accepted" and key not in accepted:
        out.append(f"{key}: risk-accepted but not named in security/accepted-risks.md")
    return out + [f"{key}: {e}" for item in evidence_items(r) if (e := evidence_problem(repo, item))]


def evidence_problem(repo, item):
    """Why a path:line or path:start-end citation does not resolve, or None."""
    m = EVIDENCE.match(item)
    if not m:
        return f'evidence "{item}" is not path:line or path:start-end'
    f = (repo / m["path"]).resolve()
    if not f.is_relative_to(repo.resolve()) or not f.is_file():
        return f'evidence file {m["path"]} does not exist in the repository'
    lines = len(f.read_bytes().splitlines())
    start, end = int(m["start"]), int(m["end"] or m["start"])
    if not 1 <= start <= end <= lines:
        return f"evidence {item} is outside the file ({lines} lines)"
    return None


def policy_problems(repo, text):
    """The profile's Access policy section, if it has one, in the shape local-dast reads."""
    section = re.search(r"^## Access policy[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not section:
        return []
    where, out = "profile.md Access policy", []
    if not re.search(r"^Status: (PROPOSED\b|confirmed by owner on \d{4}-\d{2}-\d{2}\b)", section[1], re.M):
        out.append(f"{where}: needs a line 'Status: PROPOSED' or 'Status: confirmed by owner on YYYY-MM-DD'")
    table = [[c.strip() for c in line.strip().strip("|").split("|")] for line in section[1].splitlines() if line.lstrip().startswith("|")]
    head = table[0] if table else []
    if head[:4] != ["ID", "Route", "Resource", "Action"] or head[-1:] != ["Enforced at"] or "anonymous" not in head[4:-1]:
        return out + [f"{where}: the header must be | ID | Route | Resource | Action | anonymous | <other roles> | Enforced at |"]
    if len(table) < 3:
        out.append(f"{where}: the table has no rows")
    ids = [row[0] for row in table[2:]]
    out += [f"{where}: row ID {i} is used twice" for i in sorted({i for i in ids if ids.count(i) > 1})]
    for row in table[2:]:
        if len(row) != len(head):
            out.append(f"{where} {row[0]}: {len(row)} cells, the header has {len(head)}")
            continue
        out += [f'{where} {row[0]}: {role} is "{cell}", not allow, deny or allow if <condition>'
                for role, cell in zip(head[4:-1], row[4:-1]) if not re.fullmatch(r"allow|deny|allow if \S.*", cell)]
        if row[-1] == "public by design":
            if set(row[4:-1]) != {"allow"}:
                out.append(f"{where} {row[0]}: public by design needs allow in every role")
        elif row[-1] != "no check found":
            # partial: <lines> when the row is checked, but not as the policy says (signed in, yet no ownership check)
            out += [f"{where} {row[0]}: {e}" for item in row[-1].removeprefix("partial:").split(";") if (e := evidence_problem(repo, item.strip()))]
    return out


INV_HEAD = ["ID", "Invariant", "Tactic", "Enforced at", "Strength", "Test", "Status"]
INV_STATES = ["holds", "partial", "broken", "unverifiable"]
STRENGTHS = ["central", "per-path", "none"]
TEST_CELL = re.compile(r"(no test )?fails without \S+:\d+ \(\d{4}-\d{2}-\d{2}\): \S.*|not probed: \S.*")


def invariants(text):
    """The rows of the profile's Security invariants table as dicts, the section's text and its span, or ([], None, None)."""
    section = re.search(r"^## Security invariants[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not section:
        return [], None, None
    table = [[c.strip() for c in line.strip().strip("|").split("|")] for line in section[1].splitlines() if line.lstrip().startswith("|")]
    if not table or table[0] != INV_HEAD:
        return None, section[1], section.span(1)
    return [dict(zip(INV_HEAD, row)) | {"_cells": len(row)} for row in table[2:]], section[1], section.span(1)


def invariant_problems(repo, text):
    """The profile's Security invariants, if it has them: each a design rule of this product, where it is enforced, how strongly, whether a test notices its removal."""
    rows, _, _ = invariants(text)
    where = "profile.md Security invariants"
    if rows is None:
        return [f"{where}: the header must be | {' | '.join(INV_HEAD)} |"]
    tactics = {r["chapter"] for r in catalogs().get("design", {}).values()}
    ids = [r["ID"] for r in rows]
    out = [f"{where}: row ID {i} is used twice" for i in sorted({i for i in ids if ids.count(i) > 1})]
    for r in rows:
        w = f"{where} {r['ID']}"
        if r["_cells"] != len(INV_HEAD):
            out.append(f"{w}: {r['_cells']} cells, the header has {len(INV_HEAD)}")
            continue
        if r["Status"] not in INV_STATES:
            out.append(f'{w}: status "{r["Status"]}" is not {", ".join(INV_STATES[:-1])} or {INV_STATES[-1]}')
        if r["Tactic"] not in tactics:
            out.append(f'{w}: tactic "{r["Tactic"]}" is not one of the architectural tactics ({", ".join(sorted(tactics))})')
        if r["Strength"] not in STRENGTHS:
            out.append(f'{w}: strength "{r["Strength"]}" is not {", ".join(STRENGTHS[:-1])} or {STRENGTHS[-1]}')
        if not TEST_CELL.fullmatch(r["Test"]):
            out.append(f"{w}: the Test cell is written by gap.py probe, or says not probed: <why>")
        if r["Enforced at"] == "no check found":
            if r["Status"] in ("holds", "partial"):
                out.append(f"{w}: {r['Status']} needs the lines that enforce it")
        else:
            out += [f"{w}: {e}" for item in r["Enforced at"].split(";") if (e := evidence_problem(repo, item.strip()))]
    return out


def probe(args):
    """Switch one control off in a copy, run the tests, put the file back, and write what happened into the invariant's Test cell."""
    repo, copy = Path(args.repo).resolve(), Path(args.copy).resolve()
    command = args.command
    profile = repo / "security" / "profile.md"
    text = profile.read_text() if profile.exists() else ""
    rows, section, span = invariants(text)
    problem = None
    if copy == repo or copy.is_relative_to(repo) or repo.is_relative_to(copy):
        problem = "the copy must be a separate folder, not the repository or inside it"
    elif not command or any("|" in part for part in command):
        problem = "give the test command after --, without a | (put a pipeline in a script)"
    elif not rows or args.id not in [r["ID"] for r in rows]:
        problem = f"profile.md Security invariants has no row {args.id}"
    target = copy / args.file
    original = target.read_text() if not problem and target.is_file() else None
    if not problem and (original is None or original.count(args.old) != 1):
        problem = f"--old must occur exactly once in {args.file} of the copy"
    if problem:
        print("problem: " + problem)
        return 1

    def passes():
        try:
            return subprocess.run(command, cwd=copy, stdin=subprocess.DEVNULL, capture_output=True, timeout=args.timeout).returncode == 0
        except subprocess.TimeoutExpired:
            return None
    if passes() is not True:
        print("problem: the command must be one that passes before the edit, or the probe proves nothing; it failed or timed out")
        return 1
    try:
        target.write_text(original.replace(args.old, args.new))
        result = passes()
    finally:
        target.write_text(original)
    if result is None:
        print("problem: the command timed out with the edit; nothing was written")
        return 1
    tested = result is False
    line = original[:original.index(args.old)].count("\n") + 1
    cell = f"{'' if tested else 'no test '}fails without {args.file}:{line} ({datetime.date.today().isoformat()}): {' '.join(command)}"
    lines = section.split("\n")
    for n, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.lstrip().startswith("|") and cells[0] == args.id and len(cells) == len(INV_HEAD):
            cells[INV_HEAD.index("Test")] = cell
            lines[n] = "| " + " | ".join(cells) + " |"
    profile.write_text(text[:span[0]] + "\n".join(lines) + text[span[1]:])
    print(f"{args.id}: {'tested: the command fails without the control' if tested else 'untested: the command still passes without the control'}")
    return 0


def read_csv(path, fields):
    if not path.exists():
        return None
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != fields:
            sys.exit(f"{path}: header must be {','.join(fields)}")
        return list(reader)


def write_csv(path, fields, rows):
    path.parent.mkdir(exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def repo_files(repo):
    """Every file a review should account for: Git's tracked and unignored files, else a walk. Not security/."""
    try:
        out = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", "-co", "--exclude-standard"],
                             capture_output=True, check=True).stdout.decode()
        paths = [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        paths = []
        for root, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            paths += [os.path.relpath(os.path.join(root, n), repo) for n in names]
    return sorted({p for p in paths if not p.startswith("security/")
                   and (repo / p).is_file() and not (repo / p).is_symlink()})


def content(repo, path):
    """The file's bytes and whether it is text."""
    data = (repo / path).read_bytes()
    return data, b"\0" not in data[:8192]


def digest(data):
    return hashlib.sha1(data).hexdigest()[:12]


def under(path, prefixes):
    return any(p in (".", "") or path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def files_path(repo):
    return repo / "security" / "files.csv"


def sync_files(repo):
    """files.csv with one row per current file; marks and notes kept, gone files dropped."""
    old = {r["path"]: r for r in read_csv(files_path(repo), FILE_FIELDS) or []}
    rows = []
    for p in repo_files(repo):
        data, text = content(repo, p)
        r = old.get(p) or {"path": p, "status": "unread", "sha": "", "notes": ""}
        r["lines"] = str(len(data.splitlines())) if text else "0"
        if not text and r["status"] == "unread":
            r.update(status="skipped", sha=digest(data), notes="binary")
        rows.append(r)
    write_csv(files_path(repo), FILE_FIELDS, rows)
    return rows


def changed_files(repo, rows):
    return {r["path"] for r in rows if r["status"] != "unread" and r["sha"] != digest(content(repo, r["path"])[0])}


def files(args):
    repo = Path(args.repo)
    rows = sync_files(repo)
    if args.mark:
        if not args.status:
            sys.exit("--mark needs --status")
        if args.status == "skipped" and not args.notes:
            sys.exit("skipped needs --notes saying why")
        hit = [r for r in rows if under(r["path"], args.mark)]
        if not hit:
            sys.exit("no file matches " + " ".join(args.mark))
        for r in hit:
            r.update(status=args.status, sha=digest(content(repo, r["path"])[0]) if args.status != "unread" else "",
                     notes=args.notes if args.notes is not None else r["notes"])
        write_csv(files_path(repo), FILE_FIELDS, rows)
        print(f"{len(hit)} files marked {args.status}")
    changed = changed_files(repo, rows)
    if args.list:
        for r in rows:
            if r["status"] == args.list or (args.list == "changed" and r["path"] in changed):
                print(f'{r["path"]}\t{r["lines"]} lines\t{r["status"]}\t{r["notes"]}')
        return 0
    print(coverage_line(rows))
    by_dir = {}
    for r in rows:
        if r["status"] == "unread":
            d = os.path.dirname(r["path"]) or "."
            n, lines = by_dir.get(d, (0, 0))
            by_dir[d] = (n + 1, lines + int(r["lines"]))
    for d, (n, lines) in sorted(by_dir.items(), key=lambda kv: -kv[1][1]):
        print(f"  unread {d}/: {n} files, {lines} lines")
    for p in sorted(changed):
        print(f"  changed since marked: {p}")
    return 0


def coverage_line(rows):
    total = sum(int(r["lines"]) for r in rows) or 1
    parts = []
    for s in FILE_STATUSES:
        chosen = [r for r in rows if r["status"] == s]
        if chosen:
            lines = sum(int(r["lines"]) for r in chosen)
            parts.append(f"{s} {len(chosen)} ({lines} lines, {100 * lines // total} %)")
    return f"files: {len(rows)}; " + ", ".join(parts)


def inventory_path(repo):
    return repo / "security" / "inventory.csv"


def scan(repo):
    """Every signal line in the repository's code, keyed so that a mark survives the line moving."""
    hits, seen = [], {}
    for p in repo_files(repo):
        if not CODE.search(p) or VENDORED & set(p.split("/")[:-1]):
            continue
        data, text = content(repo, p)
        if not text or len(data) > 2 << 20:
            continue
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            for kind, rx in SIGNAL_RES:
                if rx.search(line) and not (kind == "network-out" and LICENCE_URL.search(line)):
                    t = line.strip()[:160]
                    k = (kind, p, t)
                    seen[k] = seen.get(k, 0) + 1
                    hits.append({"kind": kind, "path": p, "line": str(n), "text": t, "occurrence": seen[k]})
    return hits


def inv_key(r, occurrence):
    return (r["kind"], r["path"], r["text"], occurrence)


def keyed(rows):
    out, seen = {}, {}
    for r in rows:
        k = (r["kind"], r["path"], r["text"])
        seen[k] = seen.get(k, 0) + 1
        out[k + (seen[k],)] = r
    return out


def sync_inventory(repo):
    old = keyed(read_csv(inventory_path(repo), INV_FIELDS) or [])
    rows = []
    for h in scan(repo):
        prev = old.get(inv_key(h, h["occurrence"]))
        rows.append({"kind": h["kind"], "path": h["path"], "line": h["line"], "text": h["text"],
                     "status": prev["status"] if prev else "unreviewed", "notes": prev["notes"] if prev else ""})
    write_csv(inventory_path(repo), INV_FIELDS, rows)
    return rows


def inventory(args):
    repo = Path(args.repo)
    # A mark works on the saved inventory: rescanning a large repository on every mark took seconds each, an hour for a few thousand lines.
    # Running gap.py inventory without --mark rescans, and check says when the saved inventory no longer matches the code.
    saved = read_csv(inventory_path(repo), INV_FIELDS) if args.mark else None
    rows = saved if saved is not None else sync_inventory(repo)
    if args.mark:
        if not args.status or not (args.kind or args.path or args.match):
            sys.exit("--mark needs --status and at least one of --kind, --path and --match")
        if args.status in {"internal", "test"} and not args.notes:
            sys.exit(f"{args.status} needs --notes saying why")
        if args.lines and (not args.path or len(args.path) != 1 or not (repo / args.path[0]).is_file()):
            sys.exit("--lines needs --path to name one file; mark a folder without --lines")
        lo, _, hi = (args.lines or "").partition("-")
        try:
            match = re.compile(args.match) if args.match else None
        except re.error:
            sys.exit("--match is not a valid regular expression")
        hit = [r for r in rows if (not args.kind or r["kind"] in args.kind) and (not args.path or under(r["path"], args.path))
               and (not args.lines or int(lo) <= int(r["line"]) <= int(hi or lo)) and (not match or match.search(r["text"]))]
        if not hit:
            sys.exit("no inventory line matches")
        for r in hit:
            r["status"] = args.status
            if args.notes is not None:
                r["notes"] = args.notes
        write_csv(inventory_path(repo), INV_FIELDS, rows)
        print(f"{len(hit)} inventory lines marked {args.status}; {sum(r['status'] == 'unreviewed' for r in rows)} unreviewed")
        return 0
    want = args.list or "unreviewed"
    tally = {}
    for r in rows:
        tally.setdefault(r["kind"], {}).setdefault(r["status"], 0)
        tally[r["kind"]][r["status"]] += 1
    for kind, counts in sorted(tally.items()):
        print(f"{kind:12} " + "  ".join(f"{s} {counts[s]}" for s in INV_STATUSES if s in counts))
    chosen = [r for r in rows if r["status"] == want]
    for r in chosen[:300]:
        print(f'  {r["kind"]:12} {r["path"]}:{r["line"]}  {r["text"]}' + (f'  [{r["notes"]}]' if r["notes"] else ""))
    if len(chosen) > 300:
        print(f"  ... {len(chosen) - 300} more; narrow with --mark by --path or --kind")
    return 0


def coverage_problems(repo, reqs):
    """Whether the folder accounts for every file and every boundary signal, and evidence rests on read files."""
    out = []
    frows = read_csv(files_path(repo), FILE_FIELDS)
    irows = read_csv(inventory_path(repo), INV_FIELDS)
    if frows is None or irows is None:
        return ["files.csv or inventory.csv is missing; run gap.py files and gap.py inventory"], None
    current = repo_files(repo)
    if sorted(r["path"] for r in frows) != current:
        out.append("files.csv does not list the current files; run gap.py files")
    if set(keyed(irows)) != {inv_key(h, h["occurrence"]) for h in scan(repo)}:
        out.append("inventory.csv does not match the code; run gap.py inventory")
    status = {r["path"]: r["status"] for r in frows}
    unread = [r for r in frows if r["status"] == "unread"]
    if unread:
        out.append(f"{len(unread)} files are unread ({sum(int(r['lines']) for r in unread)} lines); "
                   "read them or mark them skimmed or skipped with a reason (gap.py files --list unread)")
    changed = changed_files(repo, [r for r in frows if (repo / r["path"]).is_file()])
    for p in sorted(changed):
        citing = [f'{r["standard"]}:{r["id"]}' for r in reqs
                  if any(EVIDENCE.match(e) and EVIDENCE.match(e)["path"] == p for e in evidence_items(r))]
        out.append(f"{p} changed since it was marked; reread it, mark it again and reassess "
                   + (", ".join(citing) if citing else "the rows it bears on"))
    for r in frows:
        if r["status"] not in FILE_STATUSES:
            out.append(f'{r["path"]}: status "{r["status"]}" is not one of {", ".join(FILE_STATUSES)}')
        elif r["status"] == "skipped" and not r["notes"].strip():
            out.append(f'{r["path"]}: skipped needs notes saying why')
    profile = repo / "security" / "profile.md"
    named = profile.read_text() if profile.exists() else ""
    out += policy_problems(repo, named)
    out += invariant_problems(repo, named)
    pending = [r for r in irows if r["status"] == "unreviewed"]
    if pending:
        out.append(f"{len(pending)} inventory lines are unreviewed (gap.py inventory)")
    unnamed = {}
    for r in irows:
        where = f'{r["kind"]} {r["path"]}:{r["line"]}'
        if r["status"] not in INV_STATUSES:
            out.append(f'{where}: status "{r["status"]}" is not one of {", ".join(INV_STATUSES)}')
        elif r["status"] in {"internal", "test"} and not r["notes"].strip():
            out.append(f"{where}: {r['status']} needs notes saying why")
        elif r["status"] == "boundary" and r["path"] not in named:
            unnamed[r["path"]] = unnamed.get(r["path"], 0) + 1
    out += [f"{p}: {n} boundary lines, but profile.md does not name the file (write its full path)" for p, n in sorted(unnamed.items())]
    for r in reqs:
        for e in evidence_items(r):
            m = EVIDENCE.match(e)
            if m and status.get(m["path"]) not in {"read", "skimmed", None}:
                out.append(f'{r["standard"]}:{r["id"]}: evidence {m["path"]} is {status[m["path"]]}, not read')
    return out, (frows, irows)


def gaps_sections(text):
    """gaps.md cut at its level-2 headings: the entries, and the Check outside the code section. The summary above the first heading and Not covered are neither."""
    entries, outside = [], []
    for part in re.split(r"^(?=## (?!#))", text, flags=re.M)[1:]:
        heading = part.splitlines()[0][3:].strip().lower()
        if heading.startswith("check outside the code"):
            outside.append(part)
        elif not heading.startswith("not covered"):
            entries.append(part)
    return "\n".join(entries), "\n".join(outside)


def gaps_problems(repo, rows):
    """Step 7's rule: each missing or partial row is named in an entry, each unverifiable row under Check outside the code."""
    gaps = repo / "security/gaps.md"
    entries, outside = gaps_sections(gaps.read_text(errors="replace") if gaps.exists() else "")

    def named(row, text):
        return re.search(rf"(?<![\w.]){re.escape(row['id'])}(?![\w]|\.\d)", text)

    def listed(ids):
        return ", ".join(ids[:8]) + (" …" if len(ids) > 8 else "")
    out = []
    no_entry = [r["id"] for r in rows if r["status"] in {"missing", "partial"} and not named(r, entries)]
    if no_entry:
        out.append(f"security/gaps.md has no entry for {len(no_entry)} missing or partial rows: {listed(no_entry)}")
    profile = repo / "security/profile.md"
    rules, _, _ = invariants(profile.read_text() if profile.exists() else "")
    open_rules = [r["ID"] for r in rules or [] if r.get("Status") in ("broken", "partial") and not named({"id": r["ID"]}, entries)]
    if open_rules:
        out.append(f"security/gaps.md has no entry for {len(open_rules)} broken or partial invariants: {listed(open_rules)}")
    not_outside = [r["id"] for r in rows if r["status"] == "unverifiable" and not named(r, outside)]
    if not_outside:
        out.append(f"security/gaps.md does not list {len(not_outside)} unverifiable rows under Check outside the code: {listed(not_outside)}")
    return out


def check(args):
    repo = Path(args.repo)
    rows, cats, accepted = load(repo), catalogs(), accepted_ids(repo)
    errors = []
    seen = set()
    for r in rows:
        key = (r["standard"], r["id"])
        if key in seen:
            errors.append(f"{r['standard']}:{r['id']}: listed twice")
        seen.add(key)
        errors += problems(repo, r, cats, accepted)
    tally = {}
    for r in rows:
        chapter = cats.get(r["standard"], {}).get(r["id"], {}).get("chapter", "?")
        tally.setdefault((r["standard"], chapter), {}).setdefault(r["status"], 0)
        tally[(r["standard"], chapter)][r["status"]] += 1
    for (standard, chapter), counts in sorted(tally.items(), key=lambda kv: (kv[0][0], natural(kv[0][1]))):
        print(f"{standard:6} {chapter[:48]:48} " + "  ".join(f"{s} {counts[s]}" for s in STATUSES if s in counts))
    total = {s: sum(r["status"] == s for r in rows) for s in STATUSES}
    print("total  " + "  ".join(f"{s} {n}" for s, n in total.items() if n))
    found, ledgers = coverage_problems(repo, rows)
    errors += found
    for p in sorted((repo / "security").iterdir()):
        if p.name not in SECURITY_FILES and not p.name.startswith("."):
            errors.append(f"security/{p.name}: not a file of this folder ({', '.join(SECURITY_FILES)}); move it out")
    findings = repo / "security/findings.csv"
    if findings.exists():
        with findings.open(newline="") as f:
            if next(csv.reader(f), None) != FINDING_FIELDS:
                errors.append(f"security/findings.csv: header must be {','.join(FINDING_FIELDS)}; write it only with ledger.py")
    if args.complete and total["unassessed"]:
        errors.append(f'{total["unassessed"]} requirements are unassessed')
    if args.complete:
        errors += gaps_problems(repo, rows)
    if ledgers:
        frows, irows = ledgers
        print(coverage_line(frows))
        print("inventory: " + ", ".join(f"{s} {sum(r['status'] == s for r in irows)}" for s in INV_STATUSES))
    for e in errors:
        print("problem: " + e)
    return 1 if errors else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("repo")
    p.add_argument("--select", action="append", required=True, help="standard[:max level]")
    p = sub.add_parser("show")
    p.add_argument("repo")
    p.add_argument("prefix", nargs="*")
    p.add_argument("--status", action="append", choices=STATUSES)
    p = sub.add_parser("set")
    p.add_argument("repo")
    p.add_argument("prefix", nargs="+")
    p.add_argument("--status", required=True, choices=STATUSES)
    p.add_argument("--evidence")
    p.add_argument("--notes")
    p = sub.add_parser("files")
    p.add_argument("repo")
    p.add_argument("--list", choices=FILE_STATUSES + ["changed"])
    p.add_argument("--mark", nargs="+", metavar="PATH")
    p.add_argument("--status", choices=FILE_STATUSES)
    p.add_argument("--notes")
    p = sub.add_parser("inventory")
    p.add_argument("repo")
    p.add_argument("--list", choices=INV_STATUSES)
    p.add_argument("--mark", action="store_true")
    p.add_argument("--kind", action="append", choices=[k for k, _ in SIGNALS])
    p.add_argument("--path", action="append")
    p.add_argument("--lines", help="A-B, with --path")
    p.add_argument("--match", help="a regular expression the line's text must match, such as ^import ")
    p.add_argument("--status", choices=INV_STATUSES)
    p.add_argument("--notes")
    p = sub.add_parser("check")
    p.add_argument("repo")
    p.add_argument("--complete", action="store_true", help="also fail while a requirement is unassessed")
    p = sub.add_parser("probe", help="switch one control off in a copy and run the tests")
    p.add_argument("repo")
    p.add_argument("id", help="the invariant's ID in profile.md")
    p.add_argument("--copy", required=True, help="a separate copy of the repository; the command runs there")
    p.add_argument("--file", required=True, help="the file to edit, relative to the copy")
    p.add_argument("--old", required=True, help="text that occurs exactly once in that file")
    p.add_argument("--new", required=True, help="what replaces it, so that the control no longer acts")
    p.add_argument("--timeout", type=int, default=600)
    argv = sys.argv[1:] if argv is None else list(argv)
    split = argv.index("--") if argv[:1] == ["probe"] and "--" in argv else len(argv)
    args = ap.parse_args(argv[:split])
    args.command = argv[split + 1:]
    with locked(Path(args.repo), create=args.cmd in ("init", "files", "inventory")):
        return run_command(args)


@contextlib.contextmanager
def locked(repo, create):
    """One gap.py at a time per repository. Two calls at once each reread a CSV, changed it and wrote it back, and the later one lost the other's marks."""
    try:
        import fcntl
    except ImportError:  # ponytail: no lock where fcntl is missing (Windows); run one call at a time there
        yield
        return
    folder = repo / "security"
    if create and repo.is_dir():
        folder.mkdir(exist_ok=True)
    if not folder.is_dir():  # nothing written yet, so nothing to race
        yield
        return
    handle = os.open(folder, os.O_RDONLY)  # the folder itself is the lock, so no lock file appears in it
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        os.close(handle)


def run_command(args):
    code = {"init": init, "show": show, "set": set_, "files": files, "inventory": inventory,
            "check": check, "probe": probe}[args.cmd](args) or 0
    if args.cmd in ("init", "files", "inventory"):
        ensure_ignored(args.repo, "security/")
    return code


if __name__ == "__main__":
    sys.exit(main())
