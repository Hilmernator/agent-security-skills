"""security-gap-analysis: catalogs, row selection, evidence checks."""
import contextlib
import shutil
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SKILL = Path(__file__).resolve().parents[1] / "skills/security-gap-analysis"
sys.path.insert(0, str(SKILL / "scripts"))
import gap


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = gap.main(list(argv))
    return code, out.getvalue()


class Catalogs(unittest.TestCase):
    def test_counts_and_levels(self):
        cats = {p.stem: json.loads(p.read_text()) for p in (SKILL / "catalogs").glob("*.json")}
        self.assertEqual({k: len(v["requirements"]) for k, v in cats.items()}, {"asvs": 345, "aisvs": 191, "aisvs-ac": 68, "masvs": 24, "cicd": 18, "design": 34})
        for key, doc in cats.items():
            if key not in ("cicd", "design"):  # written for this skill; the others are pinned upstream text
                self.assertRegex(doc["revision"], r"^[0-9a-f]{40}$")
            for r in doc["requirements"]:
                self.assertIn(r["level"], (1, 2, 3))
                self.assertTrue(r["text"] and r["chapter"] and r["section"])


    def test_build_and_release_have_rows_of_their_own(self):
        doc = json.loads((SKILL / "catalogs/cicd.json").read_text())
        ids = [r["id"] for r in doc["requirements"]]
        self.assertEqual(len(ids), len(set(ids)))
        # one chapter per OWASP CI/CD risk, so a gap can carry its CICD-SEC tag
        self.assertEqual(sorted({r["chapter"].split(" (")[-1].rstrip(")") for r in doc["requirements"]}), sorted(f"CICD-SEC-{n}" for n in range(1, 11)))
        repo = Path(tempfile.mkdtemp())
        run("init", str(repo), "--select", "cicd:1")
        with (repo / "security/requirements.csv").open() as f:
            rows = list(csv.DictReader(f))
        self.assertEqual({r["level"] for r in rows}, {"1"})
        self.assertEqual(len(rows), sum(r["level"] == 1 for r in doc["requirements"]))
        self.assertEqual(run("set", str(repo), "cicd:C8", "--status", "missing", "--notes", "Actions pinned to tags.")[0], 0)


    def test_design_rows_follow_the_architectural_tactics_and_name_their_principle(self):
        doc = json.loads((SKILL / "catalogs/design.json").read_text())
        tactics = {"Identify actors", "Authenticate actors", "Authorize actors", "Limit access", "Limit exposure", "Validate inputs",
                   "Verify message integrity", "Encrypt data", "Manage user sessions", "Audit", "Cross cutting"}
        self.assertEqual({r["chapter"] for r in doc["requirements"]}, tactics)  # the categories of CWE-1008, Architectural Concepts
        for r in doc["requirements"]:
            self.assertRegex(r["section"], r"^SA-8\(\d+\) [A-Z]")  # the NIST SP 800-53 design principle it applies
            self.assertTrue(r["text"].startswith("Verify that "), r["id"])
        ids = [r["id"] for r in doc["requirements"]]
        self.assertEqual(len(ids), len(set(ids)))


class Rows(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        (self.repo / "src").mkdir()
        (self.repo / "src/app.py").write_text("a\nb\nc\n")
        run("init", str(self.repo), "--select", "asvs:1")

    def rows(self):
        with (self.repo / "security/requirements.csv").open() as f:
            return {(r["standard"], r["id"]): r for r in csv.DictReader(f)}

    def test_init_selects_by_level_and_keeps_rows(self):
        self.assertEqual(len(self.rows()), 70)
        run("set", str(self.repo), "asvs:V1.2.1", "--status", "missing", "--notes", "No encoding.")
        code, out = run("init", str(self.repo), "--select", "asvs:2", "--select", "masvs")
        self.assertEqual(len(self.rows()), 70 + 183 + 24)
        self.assertEqual(self.rows()[("asvs", "V1.2.1")]["status"], "missing")

    def test_prefix_is_whole_segments(self):
        run("init", str(self.repo), "--select", "asvs:3")
        run("set", str(self.repo), "asvs:V1", "--status", "not-applicable", "--notes", "x")
        rows = self.rows()
        self.assertTrue(all(r["status"] == "not-applicable" for k, r in rows.items() if k[1].startswith("V1.")))
        self.assertTrue(all(r["status"] == "unassessed" for k, r in rows.items() if k[1].startswith("V10.")))

    def test_evidence_must_resolve(self):
        code, out = run("set", str(self.repo), "asvs:V1.2.1", "--status", "met", "--evidence", "src/app.py:2-3")
        self.assertEqual(code, 0, out)
        for bad in ("src/app.py:9", "src/nope.py:1", "../outside:1", "src/app.py"):
            code, out = run("set", str(self.repo), "asvs:V1.2.1", "--status", "met", "--evidence", bad)
            self.assertEqual(code, 1, bad)
        code, out = run("check", str(self.repo))
        self.assertEqual(code, 1)

    def test_statuses_need_their_reasons(self):
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "met")[0], 1)
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "missing")[0], 1)
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "risk-accepted", "--notes", "ok")[0], 1)
        (self.repo / "security/accepted-risks.md").write_text("- asvs:V1.2.1 accepted 2026-11-04\n")
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "risk-accepted", "--notes", "ok")[0], 0)

    def test_check_needs_the_coverage_ledgers(self):
        code, out = run("check", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("files.csv or inventory.csv is missing", out)
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo))
        code, out = run("check", str(self.repo))
        self.assertEqual(code, 0, out)
        self.assertIn("unassessed 70", out)
        code, out = run("check", str(self.repo), "--complete")
        self.assertEqual(code, 1)
        self.assertIn("70 requirements are unassessed", out)

    def test_a_complete_analysis_names_every_open_row_in_gaps_md(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo))
        first, second = [f'{r["standard"]}:{r["id"]}' for r in gap.load(self.repo)[:2]]
        run("set", str(self.repo), first, "--status", "missing", "--notes", "No such control.")
        run("set", str(self.repo), second, "--status", "unverifiable", "--notes", "Depends on hosting.")
        self.assertNotIn("gaps.md", run("check", str(self.repo))[1])
        out = run("check", str(self.repo), "--complete")[1]
        self.assertIn(f"security/gaps.md has no entry for 1 missing or partial rows: {first.split(':')[1]}", out)
        self.assertIn(f"security/gaps.md does not list 1 unverifiable rows under Check outside the code: {second.split(':')[1]}", out)

    def test_each_open_row_stands_where_step_7_puts_it(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo))
        first, second = [r["id"] for r in gap.load(self.repo)[:2]]
        run("set", str(self.repo), f"asvs:{first}", "--status", "missing", "--notes", "No such control.")
        run("set", str(self.repo), f"asvs:{second}", "--status", "unverifiable", "--notes", "Depends on hosting.")
        gaps = self.repo / "security/gaps.md"

        def complaints(text):
            gaps.write_text(text)
            return [line for line in run("check", str(self.repo), "--complete")[1].splitlines() if "gaps.md" in line]
        # A missing row named only in the summary, or only under the closing sections, has no entry.
        self.assertEqual(complaints(f"# Gaps\n\nTotals: {first}\n\n## Check outside the code\n\n- {second}: hosting\n\n## Not covered\n\n- {first}\n"),
                         [f"problem: security/gaps.md has no entry for 1 missing or partial rows: {first}"])
        # An unverifiable row belongs under Check outside the code, not in an entry.
        self.assertEqual(complaints(f"# Gaps\n\n## 1. No control\n\n- {first}, {second}\n\n## Check outside the code\n\n- hosting\n"),
                         [f"problem: security/gaps.md does not list 1 unverifiable rows under Check outside the code: {second}"])
        self.assertEqual(complaints(f"# Gaps\n\n## 1. No control\n\n- {first}\n\n## Check outside the code\n\n### Hosting\n\n- {second}\n\n## Not covered\n\nRuntime.\n"), [])

    def test_the_folder_holds_only_its_own_files(self):
        (self.repo / "security/notes-2026.md").write_text("x\n")
        (self.repo / "security/findings.csv").write_text("id,status\n")
        out = run("check", str(self.repo))[1]
        self.assertIn("security/notes-2026.md: not a file of this folder", out)
        self.assertIn("security/findings.csv: header must be fingerprint,skill,", out)
        self.assertNotIn("requirements.csv: not a file", out)

    def test_the_folder_is_ignored_by_git_unless_it_is_tracked(self):
        def git(repo, *args):
            return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
        git(self.repo, "init", "-q")
        self.assertIn("ignored: added security/", run("init", str(self.repo), "--select", "asvs:1")[1])
        self.assertEqual(git(self.repo, "status", "--porcelain", "--", "security").stdout, "")
        self.assertNotIn("ignored:", run("files", str(self.repo))[1])
        tracked = Path(tempfile.mkdtemp())
        git(tracked, "init", "-q")
        run("init", str(tracked), "--select", "asvs:1")
        (tracked / ".git/info/exclude").write_text("")
        git(tracked, "add", "security")
        run("files", str(tracked))
        self.assertEqual((tracked / ".git/info/exclude").read_text(), "")


class Coverage(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        (self.repo / "src").mkdir()
        (self.repo / "src/server.rs").write_text('fn main() {\n    let l = TcpListener::bind("0.0.0.0:80");\n'
                                                  '    std::thread::spawn(|| {});\n}\n')
        (self.repo / "src/util.rs").write_text("pub fn add(a: u8) -> u8 { a }\n")
        (self.repo / "logo.png").write_bytes(b"\x89PNG\0\0")
        run("init", str(self.repo), "--select", "masvs")
        run("set", str(self.repo), "masvs", "--status", "not-applicable", "--notes", "Not a mobile app.")

    def check(self):
        return run("check", str(self.repo))

    def test_every_file_and_signal_must_be_accounted_for(self):
        code, out = run("files", str(self.repo))
        self.assertIn("unread 2", out)
        self.assertIn("skipped 1", out)
        code, out = run("inventory", str(self.repo))
        self.assertIn("listen", out)
        self.assertNotIn("thread::spawn", out)
        code, out = self.check()
        self.assertIn("2 files are unread", out)
        self.assertIn("1 inventory lines are unreviewed", out)
        run("files", str(self.repo), "--mark", "src", "--status", "read")
        run("inventory", str(self.repo), "--mark", "--kind", "listen", "--status", "boundary")
        code, out = self.check()
        self.assertIn("src/server.rs: 1 boundary lines, but profile.md does not name the file", out)
        (self.repo / "security/profile.md").write_text("Port 80 is served by src/server.rs.\n")
        self.assertEqual(self.check()[0], 0, self.check()[1])

    def test_a_change_reopens_the_file_and_the_rows_citing_it(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo), "--mark", "--path", "src", "--status", "internal", "--notes", "test fixture")
        run("set", str(self.repo), "masvs:MASVS-CODE-1", "--status", "met", "--evidence", "src/util.rs:1")
        self.assertEqual(self.check()[0], 0, self.check()[1])
        (self.repo / "src/util.rs").write_text("pub fn add(a: u8) -> u8 { a + 1 }\n")
        code, out = self.check()
        self.assertIn("src/util.rs changed since it was marked; reread it, mark it again and reassess masvs:MASVS-CODE-1", out)
        (self.repo / "src/new.rs").write_text("let x = eval(input);\n")
        code, out = self.check()
        self.assertIn("files.csv does not list the current files", out)
        self.assertIn("inventory.csv does not match the code", out)

    def test_marks_from_parallel_calls_are_all_kept_and_a_line_range_needs_one_file(self):
        names = [f"src/m{n}.rs" for n in range(8)]
        for name in names:
            (self.repo / name).write_text("let x = eval(input);\n")
        run("files", str(self.repo))
        script = Path(gap.__file__)
        calls = [subprocess.Popen([sys.executable, str(script), "files", str(self.repo), "--mark", name, "--status", "read"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for name in names]
        self.assertEqual([c.wait() for c in calls], [0] * 8)
        with (self.repo / "security/files.csv").open() as f:
            marked = {r["path"] for r in csv.DictReader(f) if r["status"] == "read"}
        self.assertTrue(set(names) <= marked, set(names) - marked)
        run("inventory", str(self.repo))
        with self.assertRaises(SystemExit) as stop:
            run("inventory", str(self.repo), "--mark", "--path", "src", "--lines", "1-2", "--status", "internal", "--notes", "x")
        self.assertIn("one file", str(stop.exception.code))

    def test_a_mark_does_not_rescan_and_can_select_lines_by_their_text(self):
        (self.repo / "src/a.py").write_text("# docs at https://example.com/guide\nrequests.get(url)\n")
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo))
        from unittest.mock import patch
        with patch.object(gap, "scan", side_effect=AssertionError("a mark rescanned the repository")):
            code, out = run("inventory", str(self.repo), "--mark", "--match", "^#", "--status", "internal", "--notes", "Comments only.")
        self.assertEqual(code, 0, out)
        with (self.repo / "security/inventory.csv").open() as f:
            rows = {(r["text"], r["status"]) for r in csv.DictReader(f) if r["path"] == "src/a.py"}
        self.assertIn(("# docs at https://example.com/guide", "internal"), rows)
        self.assertIn(("requests.get(url)", "unreviewed"), rows)

    def test_a_boundary_file_the_profile_does_not_name_is_reported_once(self):
        (self.repo / "src/routes.py").write_text("".join(f"@app.get('/r{n}')\ndef r{n}(): pass\n" for n in range(5)))
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo), "--mark", "--path", ".", "--status", "internal", "--notes", "fixture")
        run("inventory", str(self.repo), "--mark", "--path", "src/routes.py", "--status", "boundary")
        out = [line for line in self.check()[1].splitlines() if "routes.py" in line]
        self.assertEqual(out, ["problem: src/routes.py: 5 boundary lines, but profile.md does not name the file (write its full path)"])

    def test_evidence_must_be_in_a_read_file(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("files", str(self.repo), "--mark", "src/util.rs", "--status", "skipped", "--notes", "trivial")
        run("inventory", str(self.repo), "--mark", "--path", "src", "--status", "internal", "--notes", "fixture")
        run("set", str(self.repo), "masvs:MASVS-CODE-1", "--status", "met", "--evidence", "src/util.rs:1")
        code, out = self.check()
        self.assertIn("evidence src/util.rs is skipped, not read", out)

    def test_the_access_policy_is_in_the_shape_local_dast_reads(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo), "--mark", "--path", "src", "--status", "internal", "--notes", "fixture")
        table = ("## Access policy\n\nStatus: PROPOSED\n\n| ID | Route | Resource | Action | anonymous | member | Enforced at |\n"
                 "| --- | --- | --- | --- | --- | --- | --- |\n| P1 | GET /x | x | read | deny | allow if own tenant | src/util.rs:1; src/server.rs:2-3 |\n"
                 "| P2 | PUT /x | x | update | deny | allow if owner | no check found |\n"
                 "| P3 | POST /signup | account | create | allow | allow | public by design |\n\n## Data\n")
        profile = self.repo / "security/profile.md"
        # partial: the row is checked, but not as the policy says (authenticated, yet no ownership check).
        for good in (table, table.replace("PROPOSED", "confirmed by owner on 2026-11-16"), "## Identity\nOne local user, no roles.\n",
                     table.replace("src/util.rs:1; src/server.rs:2-3", "partial: src/util.rs:1")):
            profile.write_text(good)
            self.assertEqual(self.check()[0], 0, self.check()[1])
        for broken, message in [(table.replace("Status: PROPOSED", "Status: draft"), "needs a line 'Status: PROPOSED'"),
                                (table.replace("| anonymous |", "| guest |"), "the header must be"),
                                (table.replace("allow if owner", "owner only"), 'P2: member is "owner only"'),
                                (table.replace("src/util.rs:1;", "src/util.rs:9;"), "P1: evidence src/util.rs:9 is outside the file"),
                                (table.replace("| P2 |", "| P1 |"), "row ID P1 is used twice"),
                                (table.replace("no check found", "public by design"), "P2: public by design needs allow in every role"),
                                (table.replace("| P2 |", "| P2 | extra |"), "P2: 8 cells, the header has 7"),
                                (table.replace("src/util.rs:1; src/server.rs:2-3", "partial: src/util.rs:9"), "P1: evidence src/util.rs:9 is outside the file")]:
            profile.write_text(broken)
            code, out = self.check()
            self.assertEqual(code, 1, broken)
            self.assertIn(message, out)


class Signals(unittest.TestCase):
    def kinds(self, name, text):
        repo = Path(tempfile.mkdtemp())
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
        return {h["kind"] for h in gap.scan(repo)}

    def test_entry_points_beyond_http_servers_are_found(self):
        for name, line, kind in [
            ("fn/app.py", "def lambda_handler(event, context):", "route"),
            ("template.yaml", "      Type: Api", "route"),
            ("app/api/items/route.ts", "export async function POST(req: Request) {", "route"),
            ("src/main.rs", "let args: Vec<String> = std::env::args().collect();", "cli"),
            ("tool.py", "import argparse", "cli"),
            ("api.py", "async def put(file: UploadFile):", "upload"),
            ("files.py", 'upload = request.files["file"]', "upload"),
            ("edge/static.ts", "createReadStream(path.join(root, decodeURIComponent(url.pathname))).pipe(res)", "fs-path"),
            ("files.py", "with open(os.path.join(upload_dir(), name)) as handle:", "fs-path"),
            ("src/files.rs", "let body = std::fs::read(base.join(&name))?;", "fs-path"),
            ("assistant.py", 'reply = client.messages.create(model=model, messages=turns)', "ai"),
            ("assistant.py", 'text = response.choices[0].message.content', "ai"),
            ("server.py", "from mcp.server.fastmcp import FastMCP", "ai"),
            ("server.ts", 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";', "ai"),
            ("files.py", "return send_file(os.path.join(base, name))", "upload"),
            ("auth.py", 'role = request.headers.get("X-Acting-Role")', "auth"),
            ("unpack.py", "tarfile.open(path).extractall(dest)", "upload"),
            ("web/app.js", "localStorage.setItem('token', t)", "store"),
            (".github/workflows/ci.yml", "      - uses: actions/checkout@v4", "pipeline"),
            (".github/workflows/ci.yml", "        run: curl -sSf https://sh.example.com | sh", "pipeline"),
            ("package.json", '    "postinstall": "node setup.js"', "pipeline"),
            ("src/lib.rs", "unsafe { ptr.read() }", "ffi"),
            ("client.py", "requests.get(url, verify=False)", "weak-crypto"),
            ("AndroidManifest.xml", '<activity android:exported="true">', "ipc"),
            ("services/web/nginx.conf.template", "    location /debug/ {", "route"),
            ("shop/urls.py", 're_path(r"^orders/(?P<order_id>[0-9]+)$", views.OrderView.as_view()),', "route"),
            ("mechanic/views.py", "return FileResponse(open(full_path, 'rb'))", "fs-path"),
            ("Jwt.java", "HttpURLConnection connection = (HttpURLConnection) jku.toURL().openConnection();", "network-out"),
            ("Client.java", "URL url = new URL(endpoint);", "network-out"),
            ("app/cli.py", "@app.cli.command(\"seed-demo\")", "cli"),
        ]:
            self.assertIn(kind, self.kinds(name, line + "\n"), line)

    def test_vendored_code_and_licence_headers_raise_no_lines(self):
        repo = Path(tempfile.mkdtemp())
        for name in ("services/community/vendor/github.com/lib/x.go", "web/node_modules/a/index.js", "third_party/b.py"):
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text("password := os.Getenv(\"X\")\neval(x)\n")
        (repo / "Jwt.java").write_text(" * Licensed under the Apache License, see http://www.apache.org/licenses/LICENSE-2.0\n")
        self.assertEqual(gap.scan(repo), [])

    def test_a_mark_answers_in_one_line(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "a.py").write_text("import argparse\nx = eval(y)\n")
        run("inventory", str(repo))
        self.assertEqual(run("inventory", str(repo), "--mark", "--kind", "cli", "--status", "boundary")[1], "1 inventory lines marked boundary; 1 unreviewed\n")

    def test_lookalikes_are_left_out(self):
        for name, line, kind in [
            (".github/workflows/ci.yml", "      - uses: actions/checkout@" + "a" * 40, "pipeline"),
            ("web/app.ts", "await uploadFile(blob)", "upload"),
            ("template.yaml", '        - "s3:CreateMultipartUpload"', "upload"),
            ("template.yaml", '        - "dynamodb:GetItem"', "store"),
            ("pyproject.toml", 'argparse = "^1.4.0"', "cli"),
            ("src/lib.rs", "let unsafe_name = 1;", "ffi"),
            ("app.py", "# the mcp routes are mounted under /mcp", "ai"),
            ("proxy.ts", 'const prefixes = ["/api", "/mcp"];', "ai"),
            ("csrf.py", 'EXEMPT = ("/mcp", "/oauth/token")', "ai"),
            ("util.py", "target = os.path.join(here, 'templates')", "fs-path"),
        ]:
            self.assertNotIn(kind, self.kinds(name, line + "\n"), line)


INVARIANTS = """
## Security invariants

| ID | Invariant | Tactic | Enforced at | Strength | Test | Status |
| --- | --- | --- | --- | --- | --- | --- |
| I1 | Only the owner may read a record | Authorize actors | src/app.py:2-3 | central | not probed: no tests yet | holds |
| I2 | At most three attempts a minute | Limit access | src/app.py:7 | per-path | not probed: no tests yet | holds |
| I3 | Signing keys belong to one tenant | Verify message integrity | no check found | none | not probed: nothing to probe | broken |
"""

APP = "def allowed(user):\n    if user != 'owner':\n        return False\n    return True\n\n\ndef under_limit(attempts):\n    return attempts <= 3\n"
TEST = "import unittest\nfrom src.app import allowed\n\n\nclass T(unittest.TestCase):\n    def test_peer_is_refused(self):\n        self.assertFalse(allowed('peer'))\n"


class Design(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        (self.repo / "src").mkdir()
        (self.repo / "src/__init__.py").write_text("")
        (self.repo / "src/app.py").write_text(APP)
        (self.repo / "test_app.py").write_text(TEST)
        run("init", str(self.repo), "--select", "design:1")
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo))
        self.profile = self.repo / "security/profile.md"

    def problems(self):
        return [line for line in run("check", str(self.repo))[1].splitlines() if "invariant" in line.lower()]

    def test_the_invariants_table_is_checked(self):
        self.profile.write_text("# Profile\n" + INVARIANTS)
        self.assertEqual(self.problems(), [])
        for old, new, expected in (
                ("| holds |\n| I2", "| fine |\n| I2", 'I1: status "fine" is not holds, partial, broken or unverifiable'),
                ("| src/app.py:2-3 |", "| no check found |", "I1: holds needs the lines that enforce it"),
                ("| src/app.py:7 |", "| src/app.py:70 |", "I2: evidence src/app.py:70 is outside the file"),
                ("| central | not probed: no tests yet", "| strong | not probed: no tests yet", 'I1: strength "strong" is not central, per-path or none'),
                ("| not probed: no tests yet | holds |\n| I2", "| tested | holds |\n| I2", "I1: the Test cell is written by gap.py probe, or says not probed: <why>"),
                ("| Limit access |", "| Rate limiting |", 'I2: tactic "Rate limiting" is not one of the architectural tactics')):
            with self.subTest(change=new):
                self.profile.write_text("# Profile\n" + INVARIANTS.replace(old, new))
                self.assertTrue(any(expected in line for line in self.problems()), (expected, self.problems()))

    def test_a_broken_invariant_needs_an_entry_in_gaps_md(self):
        self.profile.write_text("# Profile\n" + INVARIANTS)
        run("set", str(self.repo), "design", "--status", "not-applicable", "--notes", "Test fixture.")
        gaps = self.repo / "security/gaps.md"
        gaps.write_text("# Gaps\n\nI3 is broken.\n\n## Check outside the code\n\nNothing.\n")
        self.assertIn("problem: security/gaps.md has no entry for 1 broken or partial invariants: I3", run("check", str(self.repo), "--complete")[1])
        gaps.write_text("# Gaps\n\n## 1. Keys are shared\n\n- I3\n\n## Check outside the code\n\nNothing.\n")
        self.assertNotIn("invariant", run("check", str(self.repo), "--complete")[1])

    def test_a_probe_switches_a_control_off_in_a_copy_and_writes_what_the_tests_did(self):
        self.profile.write_text("# Profile\n" + INVARIANTS)
        copy = Path(tempfile.mkdtemp()) / "copy"
        shutil.copytree(self.repo, copy, ignore=shutil.ignore_patterns("security", ".git"))
        command = ["--", sys.executable, "-m", "unittest", "-q"]
        code, out = run("probe", str(self.repo), "I1", "--copy", str(copy), "--file", "src/app.py",
                        "--old", "    if user != 'owner':", "--new", "    if False:", *command)
        self.assertEqual(code, 0, out)
        self.assertIn("I1: tested", out)
        code, out = run("probe", str(self.repo), "I2", "--copy", str(copy), "--file", "src/app.py",
                        "--old", "    return attempts <= 3", "--new", "    return True", *command)
        self.assertIn("I2: untested", out)
        table = self.profile.read_text()
        # The cell names the line that was switched off, so the probe can be repeated and reviewed.
        self.assertRegex(table, r"\| I1 \|.*\| fails without src/app\.py:2 \(\d{4}-\d{2}-\d{2}\): .*unittest -q \| holds \|")
        self.assertRegex(table, r"\| I2 \|.*\| no test fails without src/app\.py:8 \(\d{4}-\d{2}-\d{2}\): .*unittest -q \| holds \|")
        self.assertEqual((copy / "src/app.py").read_text(), APP)  # the copy is put back after each probe
        self.assertEqual((self.repo / "src/app.py").read_text(), APP)
        self.assertEqual(self.problems(), [])
        # A probe needs a command that passes before the edit, an edit that applies once, and a copy that is not the repository.
        (copy / "test_app.py").write_text(TEST.replace("assertFalse", "assertTrue"))
        self.assertIn("passes before the edit", run("probe", str(self.repo), "I1", "--copy", str(copy), "--file", "src/app.py",
                                                    "--old", "    if user != 'owner':", "--new", "    if False:", *command)[1])
        self.assertIn("exactly once", run("probe", str(self.repo), "I1", "--copy", str(copy), "--file", "src/app.py",
                                          "--old", "absent text", "--new", "x", *command)[1])
        self.assertIn("not the repository", run("probe", str(self.repo), "I1", "--copy", str(self.repo), "--file", "src/app.py",
                                                "--old", "    if user != 'owner':", "--new", "    if False:", *command)[1])
        self.assertIn("no row I9", run("probe", str(self.repo), "I9", "--copy", str(copy), "--file", "src/app.py",
                                       "--old", "    if user != 'owner':", "--new", "    if False:", *command)[1])


if __name__ == "__main__":
    unittest.main()
