"""Interpreter hand-over, test-code noise and partial-scan reasons."""
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import _python  # noqa: E402
import sast  # noqa: E402


class Interpreter(unittest.TestCase):
    """A stock macOS python3 is 3.9; the scripts need 3.10+."""

    def test_an_old_interpreter_hands_over_to_a_newer_one(self):
        with mock.patch.object(_python.sys, "version_info", (3, 9, 6)), \
             mock.patch.object(_python.shutil, "which", lambda name: "/opt/py/bin/python3.12" if name == "python3.12" else None), \
             mock.patch.object(_python, "_version", lambda path: (3, 12)), \
             mock.patch.object(_python.os, "execv") as execv:
            _python.ensure(["/skill/scripts/security.py", "--check"])
        execv.assert_called_once_with("/opt/py/bin/python3.12", ["/opt/py/bin/python3.12", "/skill/scripts/security.py", "--check"])

    def test_a_new_interpreter_stays(self):
        with mock.patch.object(_python.sys, "version_info", (3, 12, 1)), mock.patch.object(_python.os, "execv") as execv:
            _python.ensure(["x.py"])
        execv.assert_not_called()

    def test_without_a_newer_interpreter_it_does_not_loop(self):
        with mock.patch.object(_python.sys, "version_info", (3, 9, 6)), mock.patch.object(_python.shutil, "which", lambda name: None), \
             mock.patch.object(_python, "_uv_find", lambda: None), mock.patch.object(_python.os, "execv") as execv:
            _python.ensure(["x.py"])
        execv.assert_not_called()

    def test_every_entry_script_hands_over_first(self):
        for script in sorted(SCRIPTS.glob("*.py")):
            text = script.read_text()
            if '__name__ == "__main__"' in text and script.name != "_python.py":
                guard = text.split('if __name__ == "__main__":', 1)[1].lstrip().splitlines()[0]
                self.assertRegex(guard, r"_python.*\.ensure\(", script.name)


class TestCodeNoise(unittest.TestCase):
    """On large repositories most candidates were these two rules in test code."""

    def test_assert_and_object_injection_in_tests_are_left_out_and_counted(self):
        bandit = {"metrics": {"/t/tests/test_a.py": {}, "/t/app.py": {}, "_totals": {}}, "errors": [], "results": [
            {"test_id": "B101", "filename": "/t/tests/test_a.py", "line_number": 3, "issue_severity": "LOW", "issue_confidence": "HIGH"},
            {"test_id": "B101", "filename": "/t/app.py", "line_number": 9, "issue_severity": "LOW", "issue_confidence": "HIGH"},
            {"test_id": "B602", "filename": "/t/tests/test_a.py", "line_number": 5, "issue_severity": "HIGH", "issue_confidence": "HIGH"}]}
        findings, coverage = sast.project("bandit", bandit, Path("/t"))
        self.assertEqual(sorted((f["rule"], f["path"]) for f in findings), [("B101", "app.py"), ("B602", "tests/test_a.py")])
        self.assertEqual(coverage["filtered"], {"B101 in test files": 1})
        eslint = [{"filePath": "/t/src/a.test.ts", "messages": [
            {"ruleId": "security/detect-object-injection", "line": 1, "severity": 1},
            {"ruleId": "security/detect-eval-with-expression", "line": 2, "severity": 2}]}]
        findings, coverage = sast.project("eslint", eslint, Path("/t"))
        self.assertEqual([f["rule"] for f in findings], ["security/detect-eval-with-expression"])
        self.assertEqual(coverage["filtered"], {"security/detect-object-injection in test files": 1})


class IncompleteReason(unittest.TestCase):
    """An incomplete scan said nothing about which files it could not read."""

    def test_a_partial_scan_names_how_many_files_and_which(self):
        message = sast.partial_reason([{"path": "a/migrations/0001.py", "type": "parse-or-read-error"},
                                       {"path": "b.py", "type": "parse-or-read-error"}], ["c.py"], 40)
        self.assertIn("3 of 40 selected files", message)
        self.assertIn("a/migrations/0001.py (parse-or-read-error)", message)
        self.assertIn("c.py (not in scanner output)", message)
        self.assertIn("findings for the other files are kept", message)


class RulePacks(unittest.TestCase):
    """Semgrep's packs come from URLs whose content changes, so a report must say which rules it ran."""

    def test_the_identity_of_the_installed_packs_is_their_recorded_hashes(self):
        import json
        import tempfile
        import setup_sast
        folder = Path(tempfile.mkdtemp())
        (folder / "manifest.json").write_text(json.dumps({"source": "https://x", "fetched_at": "2026-11-24T10:00:00+00:00",
                                                          "packs": {"p/python": {"sha256": "ab" * 32, "bytes": 10}}}))
        with mock.patch.object(setup_sast, "RULES_DIR", folder):
            self.assertEqual(setup_sast.rule_pack_identity(), {"fetched_at": "2026-11-24T10:00:00+00:00", "packs": {"p/python": "ab" * 32}})


class Candidates(unittest.TestCase):
    """Reading report.json whole put tens of thousands of characters into the reviewer's context; a grouped list does not."""

    def test_candidates_are_grouped_by_rule_with_counts_and_a_few_places(self):
        import json
        import subprocess
        import tempfile
        out = Path(tempfile.mkdtemp())
        findings = [{"id": f"SAST-{n:04}", "rule": "eslint.detect-object-injection", "path": f"web/src/m{n}.ts", "line": n,
                     "scanner_severity": "WARNING"} for n in range(1, 41)]
        findings += [{"id": "SAST-0041", "rule": "python.sqli", "path": "api/views.py", "line": 7, "scanner_severity": "ERROR"},
                     {"id": "SCA-0001", "rule": "GHSA-xxxx", "path": "poetry.lock", "line": 12, "scanner_severity": "HIGH",
                      "metadata": {"package": "pyjwt"}}]
        (out / "report.json").write_text(json.dumps({"findings": findings}))
        done = subprocess.run([sys.executable, str(SCRIPTS / "candidates.py"), str(out / "report.json")], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        text = done.stdout
        self.assertLess(len(text), 2000)
        self.assertIn("python.sqli  1  ERROR", text)
        self.assertIn("eslint.detect-object-injection  40  WARNING", text)
        self.assertIn("SAST-0041 api/views.py:7", text)
        self.assertEqual(text.count("web/src/"), 5)  # five places shown for a big group, the rest counted
        self.assertIn("and 35 more", text)
        self.assertLess(text.index("python.sqli"), text.index("detect-object-injection"))  # most severe first
        one = subprocess.run([sys.executable, str(SCRIPTS / "candidates.py"), str(out / "report.json"), "--rule",
                              "eslint.detect-object-injection", "--all"], capture_output=True, text=True).stdout
        self.assertEqual(one.count("web/src/"), 40)
        many = [{**findings[0], "id": f"SAST-{n}", "line": n} for n in range(20000)]  # more than a pipe buffer holds
        (out / "big.json").write_text(json.dumps({"findings": many}))
        piped = subprocess.run(f"{sys.executable} {SCRIPTS / 'candidates.py'} {out / 'big.json'} --all | head -1",
                               shell=True, capture_output=True, text=True)
        self.assertNotIn("Traceback", piped.stderr)  # a reader that stops early is not an error


class Sinks(unittest.TestCase):
    """The hunt missed request forgery and decompression flaws where no scanner fired; sinks.py lists those places."""

    def test_server_side_places_are_listed_and_client_calls_tests_and_docs_are_not(self):
        import subprocess
        import tempfile
        root = Path(tempfile.mkdtemp())
        files = {
            "app/storage.py": "import redis\ndef client(self):\n    return redis.StrictRedis(host=self.host, port=self.port)\n",
            "app/hooks.py": "import requests\ndef send(hook):\n    requests.post(hook.url, json={})\n",
            "app/importer.py": "from zipfile import ZipFile\ndef load(path):\n    with ZipFile(path) as z:\n        z.extractall('/tmp/x')\n",
            "app/settings/base.py": "SSRF_PROTECTION_ENABLED = get_bool_env('SSRF_PROTECTION_ENABLED', False)\n",
            "app/views.py": "def serve(f):\n    return FileResponse(f.open('rb'))\n",
            "app/templates/base.html": "<script>var keys = {{ hotkeys|safe }};</script>\n",
            "web/src/api.ts": "export const me = () => axios.get('/api/me');\nthis.requests.get(routes.about);\n",
            "tests/test_hooks.py": "import requests\nrequests.post(url)\n",
            "docs/page.ejs": "<%- partial('x') %>\n",
            "app/git.py": "import subprocess\ndef clone(url):\n    subprocess.run(['git', 'clone', url])\n",
            "cmd/fetch.go": "package main\nfunc get(r *http.Response) {\n\tdata, _ := io.ReadAll(r.Body)\n}\n",
            "cmd/server.go": "package main\nimport _ \"net/http/pprof\"\n",
            "src/worker.rs": "fn run() {\n    tokio::spawn(async move {});\n}\n",
            "conformance-tests/src/run.rs": "fn t() { Command::new(\"x\"); }\n",
        }
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        out = subprocess.run([sys.executable, str(SCRIPTS / "sinks.py"), str(root)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        for place in ("app/storage.py:3", "app/hooks.py:3", "app/importer.py:3", "app/importer.py:4", "app/settings/base.py:1",
                      "app/views.py:2", "app/templates/base.html:1", "app/git.py:3", "cmd/fetch.go:3", "cmd/server.go:2"):
            self.assertIn(place, out.stdout)
        for absent in ("web/src/api.ts", "tests/", "docs/", "src/worker.rs", "conformance-tests/"):
            self.assertNotIn(absent, out.stdout)


class ToolchainPython(unittest.TestCase):
    """Bandit parses with its venv's Python; a 3.12 venv could not read 3.14 syntax in ten files of one review."""

    def test_an_older_toolchain_venv_is_seen_as_older(self):
        import importlib.util
        import tempfile
        spec = importlib.util.spec_from_file_location("setup_sast", SCRIPTS / "setup_sast.py")
        setup_sast = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(SCRIPTS))
        spec.loader.exec_module(setup_sast)
        root = Path(tempfile.mkdtemp())
        self.assertEqual(setup_sast.venv_minor(root), 0)
        (root / "venv").mkdir()
        (root / "venv" / "pyvenv.cfg").write_text("home = /x\nversion_info = 3.12.9\n")
        self.assertLess(setup_sast.venv_minor(root), setup_sast.NEWEST_PYTHON)
        (root / "venv" / "pyvenv.cfg").write_text("home = /x\nversion = 3.14.4\n")
        self.assertEqual(setup_sast.venv_minor(root), 14)


if __name__ == "__main__":
    unittest.main()
