"""The security gate hooks: hook JSON on stdin, the decision on stdout. The registry is patched; no network."""
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "hooks/security_gate.py"
spec = importlib.util.spec_from_file_location("security_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

NOW = datetime.datetime.now(datetime.timezone.utc)
OLD = NOW - datetime.timedelta(days=4000)


class Gate(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp()).resolve()
        (self.repo / ".git").mkdir()
        self.session = f"test-{os.getpid()}-{id(self)}"
        os.environ.pop("AGENT_TOOLS_SECURITY_GATE", None)

    def tearDown(self):
        log = gate.session_file({"session_id": self.session})
        if log.exists():
            log.unlink()

    def hook(self, event, **fields):
        out = io.StringIO()
        gate.main(io.StringIO(json.dumps({"hook_event_name": event, "session_id": self.session, "cwd": str(self.repo), **fields})), out)
        return json.loads(out.getvalue()) if out.getvalue() else None

    def edit(self, rel, old, new, existing):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(existing)
        return self.hook("PreToolUse", tool_name="Edit", tool_input={"file_path": str(path), "old_string": old, "new_string": new})

    def write(self, rel, content, existing=None):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if existing is not None:
            path.write_text(existing)
        return self.hook("PreToolUse", tool_name="Write", tool_input={"file_path": rel, "content": content})

    def decision(self, out):
        return out and (out["hookSpecificOutput"]["permissionDecision"], out["hookSpecificOutput"]["permissionDecisionReason"])

    def bash(self, command, registry):
        with patch.object(gate, "lookup", side_effect=lambda eco, name: registry.get(name, OLD)) as lookup:
            out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": command})
        return self.decision(out), sorted(c.args for c in lookup.call_args_list)

    # 1a: suppression markers

    def test_each_new_suppression_marker_asks(self):
        for line in ("eval(x)  # nosec", "eval(x)  # nosemgrep", "// eslint-disable-next-line no-eval", "/* eslint-disable */",
                     "eval(x)  # noqa: E501, S307", '@SuppressWarnings("security:S2076")', "run(x); // NOSONAR"):
            with self.subTest(line):
                decision, reason = self.decision(self.edit("src/app.py", "eval(x)", line, "eval(x)\n"))
                self.assertEqual(decision, "ask")
                self.assertIn("suppression marker", reason)

    def test_markers_already_there_and_type_ignore_pass(self):
        self.assertIsNone(self.edit("app.py", "b = 2", "b = 3", "a = eval(x)  # nosec\nb = 2\n"))
        self.assertIsNone(self.edit("app.py", "b = f()", "b = f()  # type: ignore", "b = f()\n"))
        self.assertIsNone(self.edit("app.py", "b = f()", "b = f()  # noqa: E501", "b = f()\n"))

    def test_multiedit_applies_edits_in_order(self):
        path = self.repo / "app.py"
        path.write_text("a = 1\n")
        out = self.hook("PreToolUse", tool_name="MultiEdit", tool_input={"file_path": str(path), "edits": [
            {"old_string": "a = 1", "new_string": "a = 2"}, {"old_string": "a = 2", "new_string": "a = 2  # nosec"}]})
        self.assertEqual(self.decision(out)[0], "ask")

    def test_notebook_cell_with_new_marker_asks(self):
        path = self.repo / "nb.ipynb"
        path.write_text(json.dumps({"cells": [{"id": "c1", "cell_type": "code", "source": ["eval(x)\n"]}]}))
        ask = self.hook("PreToolUse", tool_name="NotebookEdit",
                        tool_input={"notebook_path": str(path), "cell_id": "c1", "new_source": "eval(x)  # nosec"})
        same = self.hook("PreToolUse", tool_name="NotebookEdit",
                         tool_input={"notebook_path": str(path), "cell_id": "c1", "new_source": "print(1)"})
        self.assertEqual(self.decision(ask)[0], "ask")
        self.assertIsNone(same)

    # 1b: tests

    def test_fewer_assertions_in_a_test_file_asks(self):
        body = "def test_a():\n    assert f() == 1\n    assert g() == 2\n"
        for rel in ("tests/test_app.py", "app_test.py", "web/app.test.ts", "web/app.spec.js", "web/__tests__/app.js"):
            with self.subTest(rel):
                decision, reason = self.decision(self.edit(rel, "    assert g() == 2\n", "", body))
                self.assertEqual(decision, "ask")
                self.assertIn("from 2 to 1", reason)
        self.assertIsNone(self.edit("src/app.py", "    assert g() == 2\n", "", body))
        self.assertIsNone(self.edit("tests/test_app.py", "f()", "h()", body))

    def test_expect_counts_as_an_assertion(self):
        body = "it('a', () => {\n  expect(a).toBe(1);\n  expect(b).toBe(2);\n});\n"
        self.assertEqual(self.decision(self.edit("app.test.js", "  expect(b).toBe(2);\n", "", body))[0], "ask")

    def test_skip_markers_ask(self):
        cases = [("def test_a():", "@pytest.mark.skip\ndef test_a():"), ("def test_a():", "@unittest.skip('x')\ndef test_a():"),
                 ("def test_a():", "@pytest.mark.xfail\ndef test_a():"), ("it('a'", "it.skip('a'"), ("it('a'", "xit('a'"),
                 ("it('a'", "test.only('a'"), ("it('a'", "describe.skip('a'")]
        for old, new in cases:
            with self.subTest(new):
                decision, reason = self.decision(self.edit("tests/test_a.py", old, new, "def test_a():\nit('a', f)\n"))
                self.assertEqual(decision, "ask")
                self.assertIn("skip", reason)

    def test_emptying_a_test_file_asks(self):
        decision, reason = self.decision(self.write("tests/test_a.py", "", existing="def test_a():\n    assert 1\n"))
        self.assertIn("empties a test file", reason)

    def test_new_test_file_passes(self):
        self.assertIsNone(self.write("tests/test_new.py", "def test_a():\n    assert 1\n"))

    # 1c: protected paths

    def test_protected_paths_ask_whatever_the_content(self):
        for rel in (".github/workflows/ci.yml", ".semgrep.yml", ".eslintrc.json", "eslint.config.mjs", ".bandit",
                    "bandit.yaml", ".claude/settings.json", ".claude/settings.local.json"):
            with self.subTest(rel):
                self.assertEqual(self.decision(self.write(rel, "x = 1\n"))[0], "ask")

    def test_a_new_security_proof_passes_and_changing_one_asks(self):
        self.assertIsNone(self.write("tests/security/test_idor.py", "def test_a():\n    assert 1\n"))
        decision, reason = self.decision(self.write("tests/security/test_idor.py", "x = 1\n", existing="x = 0\n"))
        self.assertEqual(decision, "ask")
        self.assertIn("security proof", reason)

    def test_pyproject_asks_only_for_the_bandit_section(self):
        old = '[project]\nname = "a"\n\n[tool.bandit]\nskips = []\n\n[tool.ruff]\nline-length = 100\n'
        self.assertIsNone(self.edit("pyproject.toml", 'name = "a"', 'name = "b"', old))
        self.assertIsNone(self.edit("pyproject.toml", "line-length = 100", "line-length = 120", old))
        decision, reason = self.decision(self.edit("pyproject.toml", "skips = []", 'skips = ["B602"]', old))
        self.assertIn("[tool.bandit]", reason)
        self.assertEqual(self.decision(self.write("pyproject.toml", '[tool.bandit]\nskips = ["B101"]\n', existing=""))[0], "ask")

    # 2: installs

    def test_missing_package_is_denied_and_only_names_are_looked_up(self):
        (decision, reason), calls = self.bash("cd app && pip install requests reqeusts-toolbelt==1.0", {"reqeusts-toolbelt": "missing"})
        self.assertEqual(decision, "deny")
        self.assertIn("reqeusts-toolbelt (PyPI) does not exist", reason)
        self.assertEqual(calls, [("pypi", "reqeusts-toolbelt"), ("pypi", "requests")])

    def test_young_package_asks(self):
        (decision, reason), _ = self.bash("npm i -D @acme/left-pad@^1.0", {"@acme/left-pad": NOW - datetime.timedelta(days=3)})
        self.assertEqual(decision, "ask")
        self.assertIn("@acme/left-pad (npm, first published", reason)

    def test_old_existing_package_passes(self):
        self.assertEqual(self.bash("python3 -m pip install 'django>=4.2' flask[async]", {}), (None, [("pypi", "django"), ("pypi", "flask")]))

    def test_registry_failure_fails_open(self):
        self.assertEqual(self.bash("yarn add lodash", {"lodash": None})[0], None)

    def test_each_installer_is_recognised(self):
        for command, expected in (("pip3 install a", ("pypi", "a")), ("uv add a", ("pypi", "a")), ("uv pip install a", ("pypi", "a")),
                                  ("poetry add --group dev a", ("pypi", "a")), ("npm install a", ("npm", "a")),
                                  ("npm add a", ("npm", "a")), ("pnpm add a", ("npm", "a")), ("yarn add a", ("npm", "a")),
                                  ("bun add a", ("npm", "a")), ("FOO=1 sudo pip install a", ("pypi", "a"))):
            with self.subTest(command):
                self.assertEqual(self.bash(command, {})[1], [expected])

    def test_installs_without_registry_names_are_not_looked_up(self):
        for command in ("pip install -r requirements.txt", "npm install", "npm ci", "pip install .", "pip install -e ./lib",
                        "pip install ./dist/a-1.0-py3-none-any.whl", "pip install git+https://github.com/a/b.git",
                        "npm install github:a/b", "npm install a/b", "npm install ../lib", "npm i ./a.tgz",
                        "pip install --index-url https://pypi.internal/simple private-pkg", "npm i --registry=https://npm.internal x",
                        "npm i alias@npm:real", "echo pip install a", "git status"):
            with self.subTest(command):
                self.assertEqual(self.bash(command, {}), (None, []))

    def test_lookup_reads_404_and_first_release(self):
        import urllib.error

        def fake(body=None, code=None):
            def urlopen(request, timeout):
                self.assertEqual(request.full_url, "https://registry.npmjs.org/@acme%2Fx")
                if code:
                    raise urllib.error.HTTPError(request.full_url, code, "", {}, None)
                return io.BytesIO(json.dumps(body).encode())
            return urlopen
        with patch.object(gate.urllib.request, "urlopen", fake(code=404)):
            self.assertEqual(gate.lookup("npm", "@acme/x"), "missing")
        with patch.object(gate.urllib.request, "urlopen", fake(code=503)):
            self.assertIsNone(gate.lookup("npm", "@acme/x"))
        with patch.object(gate.urllib.request, "urlopen", fake({"time": {"created": "2026-11-01T10:00:00.000Z"}})):
            self.assertEqual(gate.lookup("npm", "@acme/x").date(), datetime.date(2026, 11, 1))
        with patch.object(gate.urllib.request, "urlopen", side_effect=TimeoutError):
            self.assertIsNone(gate.lookup("npm", "@acme/x"))

    # 3: Stop

    def ledger(self, *rows):
        (self.repo / "security").mkdir()
        lines = ["fingerprint,skill,rule,path,status,basis,sha,first_seen,last_seen,note"]
        lines += [f"{i:016x},local-security-review,{rule},{path},{status},code,,2026-11-16,2026-11-16,{note}"
                  for i, (rule, path, status, note) in enumerate(rows)]
        (self.repo / "security/findings.csv").write_text("\n".join(lines) + "\n")

    def edited(self, rel):
        self.hook("PostToolUse", tool_name="Edit", tool_input={"file_path": str(self.repo / rel)})

    def test_stop_blocks_once_for_an_edited_file_with_a_confirmed_finding(self):
        self.ledger(("sqli", "app/db.py", "confirmed", "User input reaches execute."),
                    ("xss", "app/web.py", "confirmed", "Not edited."), ("eval", "app/db.py", "false-positive", "Constant."))
        self.edited("app/db.py")
        out = self.hook("Stop", stop_hook_active=False)
        self.assertEqual(out["decision"], "block")
        self.assertIn("app/db.py (local-security-review, sqli): User input reaches execute.", out["reason"])
        self.assertNotIn("web.py", out["reason"])
        self.assertNotIn("eval", out["reason"])
        self.assertIsNone(self.hook("Stop", stop_hook_active=False))

    def test_stop_respects_stop_hook_active_and_other_statuses(self):
        self.ledger(("sqli", "app/db.py", "confirmed", "x"), ("xss", "app/web.py", "likely", "y"))
        self.edited("app/db.py")
        self.assertIsNone(self.hook("Stop", stop_hook_active=True))
        self.edited("app/web.py")
        self.assertIsNone(self.hook("Stop", stop_hook_active=False))

    def test_stop_without_ledger_or_edits_passes(self):
        self.edited("app/db.py")
        self.assertIsNone(self.hook("Stop", stop_hook_active=False))
        self.ledger(("sqli", "app/db.py", "confirmed", "x"))
        self.assertIsNone(self.hook("Stop", stop_hook_active=False))
        self.assertEqual(sorted(p.name for p in (self.repo / "security").iterdir()), ["findings.csv"])

    # failing open, and the off switch

    def test_off_switch_and_bad_input_print_nothing(self):
        with patch.dict(os.environ, {"AGENT_TOOLS_SECURITY_GATE": "off"}):
            self.assertIsNone(self.write(".github/workflows/ci.yml", "x"))
        for stdin in ("not json", "{}", '{"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": null}'):
            run = subprocess.run([sys.executable, str(SCRIPT)], input=stdin, capture_output=True, text=True, timeout=30)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_script_runs_as_a_hook(self):
        event = {"hook_event_name": "PreToolUse", "session_id": self.session, "cwd": str(self.repo), "tool_name": "Write",
                 "tool_input": {"file_path": str(self.repo / ".github/workflows/ci.yml"), "content": "on: push\n"}}
        run = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(event), capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")


if __name__ == "__main__":
    unittest.main()
