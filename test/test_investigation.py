"""Investigation outputs: bulk assessments, agent findings, fix plan, secret probe."""
import csv
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/local-security-review/scripts"
sys.path.insert(0, str(SCRIPTS))
import iac
import scan
import secret_probe

spec = importlib.util.spec_from_file_location("render_review", SCRIPTS / "render_review.py")
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

REPORT = {"status": "findings", "scope": "working-tree", "findings": [
    {"id": "SAST-0001", "engine": "bandit", "rule": "B101", "path": "tests/test_a.py", "line": 3, "scanner_severity": "LOW"},
    {"id": "SAST-0002", "engine": "bandit", "rule": "B101", "path": "tests/test_b.py", "line": 7, "scanner_severity": "LOW"},
    {"id": "SAST-0003", "engine": "semgrep", "rule": "cors", "path": "src/main.rs", "line": 26, "scanner_severity": "WARNING"},
]}
DISMISS = {"ids": ["SAST-0001", "SAST-0002"], "disposition": "false-positive", "confidence": "high",
           "assessed_severity": "info", "evidence": "Pytest asserts.", "evidence_refs": [{"path": "tests/test_a.py", "line": 3}],
           "dismissal_reason": "Asserts run only in tests.", "recommendation": "No change."}
CORS = {"id": "SAST-0003", "disposition": "likely", "confidence": "medium", "assessed_severity": "low",
        "evidence": "Any origin may call the API.", "evidence_refs": [{"path": "src/main.rs", "line": 26}],
        "preconditions": "Victim browses a hostile page while the API runs.", "recommendation": "Allow only the UI origin.",
        "no_proof": "Needs a browser on another origin."}
HUNTED = [{"id": "AGENT-0001", "title": "Path traversal in GET /get", "rule": "path-traversal",
           "path": "src/handlers/read.rs", "line": 11, "cwe": "CWE-22"}]
TRAVERSAL = {"id": "AGENT-0001", "disposition": "confirmed", "confidence": "high", "assessed_severity": "high",
             "evidence": "Request path reaches fs::read_to_string unchanged.",
             "evidence_refs": [{"path": "src/handlers/read.rs", "line": 11}], "preconditions": "None.",
             "recommendation": "Canonicalize and require the uploads prefix.", "verify": "cargo test traversal"}
FAILED_TWICE = [{"exit": 101, "marker": True}, {"exit": 101, "marker": True}]
PROOFS = {"AGENT-0001": {"test": "tests/security_traversal.rs", "command": ["cargo", "test", "traversal"], "runs": FAILED_TWICE}}


class RenderTests(unittest.TestCase):
    def test_bulk_assessment_agent_findings_and_fix_plan_order(self):
        result = review.merge(REPORT, [DISMISS, CORS, TRAVERSAL], [], HUNTED, PROOFS)
        self.assertEqual(result["counts"], {"false-positive": 2, "likely": 1, "confirmed": 1})
        self.assertEqual((result["summary"]["scanner_findings"], result["summary"]["agent_findings"]), (3, 1))
        # The two-ID dismissal is one issue, not two.
        self.assertEqual(result["summary"]["issue_groups"], 3)
        self.assertIn(["SAST-0001", "SAST-0002"], [issue["finding_ids"] for issue in result["issues"]])
        text = review.markdown(result)
        plan = text.split("## Fix plan")[1].split("## All candidates")[0]
        self.assertLess(plan.index("Path traversal"), plan.index("cors"))
        self.assertIn("**Proven by:** tests/security_traversal.rs failed 2 of 2 runs on its assertion (cargo test traversal", plan)
        self.assertIn("**Verify the fix:** cargo test traversal", plan)
        self.assertIn("src/handlers/read.rs:11", plan)
        for finding_id in ("SAST-0001", "SAST-0002", "AGENT-0001"):
            self.assertIn(finding_id, text)

    def test_invalid_bulk_and_agent_entries_fail(self):
        for assessments, hunted in (([{**DISMISS, "id": "SAST-0001"}], []), ([{**DISMISS, "ids": []}], []),
                                    ([DISMISS, {**CORS, "id": "SAST-0001"}], []),
                                    ([], [{**HUNTED[0], "line": 0}]), ([], [{**HUNTED[0], "id": "SAST-0099"}]),
                                    ([{**TRAVERSAL, "proof": " "}], HUNTED)):
            with self.subTest(assessments=str(assessments)[:60], hunted=str(hunted)[:40]), self.assertRaises(ValueError):
                review.merge(REPORT, assessments, [], hunted, PROOFS)

    def test_tiers_come_from_proofs_and_sort_before_severity(self):
        critical = {**CORS, "assessed_severity": "critical"}
        open_question = {**CORS, "id": "SAST-0001", "disposition": "needs-review", "assessed_severity": "high"}
        result = review.merge(REPORT, [critical, TRAVERSAL, open_question], [], HUNTED, PROOFS)
        self.assertEqual({row["scanner_finding"]["id"]: row["tier"] for row in result["findings"]},
                         {"SAST-0001": "scanner", "SAST-0002": "scanner", "SAST-0003": "judged", "AGENT-0001": "confirmed"})
        self.assertEqual(result["summary"]["confirmed_issue_groups"], 1)
        text = review.markdown(result)
        plan = text.split("## Fix plan")[1].split("## Unresolved")[0]
        # A proven high comes before a judged critical: proof outranks severity.
        self.assertLess(plan.index("Path traversal"), plan.index("cors"))
        self.assertIn("**Tier:** confirmed, a test fails on the current code", plan)
        self.assertIn("**Tier:** judged, not proven: Needs a browser on another origin.", plan)
        unresolved = text.split("## Unresolved")[1].split("## All candidates")[0]
        self.assertLess(unresolved.index("SAST-0001"), unresolved.index("SAST-0002"))  # high before unknown
        self.assertIn("confirmed / confirmed / high / high", text)

    def test_confirmed_needs_a_proof_that_failed_twice_on_its_marker(self):
        crashed = [{"exit": 1, "marker": True}, {"exit": 1, "marker": False}]
        for assessments, proofs in (([TRAVERSAL], {}),  # no proof at all
                                    ([TRAVERSAL], {"AGENT-0001": {**PROOFS["AGENT-0001"], "runs": crashed}}),
                                    ([TRAVERSAL], {"AGENT-0001": {**PROOFS["AGENT-0001"], "runs": FAILED_TWICE[:1]}}),
                                    ([{**TRAVERSAL, "disposition": "likely", "no_proof": "x"}], PROOFS),  # proven, yet not confirmed
                                    ([{**TRAVERSAL, "disposition": "false-positive", "dismissal_reason": "x"}], PROOFS),
                                    ([{**CORS, "no_proof": " "}], {}),  # judged needs its reason
                                    ([CORS], {"SAST-0099": PROOFS["AGENT-0001"]}), ([CORS], [])):
            with self.subTest(assessments=str(assessments)[:60], proofs=str(proofs)[:60]), self.assertRaises(ValueError):
                review.merge(REPORT, assessments, [], HUNTED, proofs)
        # A failed attempt leaves the finding in its tier.
        attempt = {"AGENT-0001": {**PROOFS["AGENT-0001"], "runs": crashed}}
        row = review.merge(REPORT, [{**TRAVERSAL, "disposition": "likely", "no_proof": "Test crashed before its assertion."}],
                           [], HUNTED, attempt)["findings"][-1]
        self.assertEqual((row["tier"], "proof" in row["assessment"]), ("judged", False))


class ProveTests(unittest.TestCase):
    """prove.py runs the agent's test twice in a copy; render_review and the ledger carry the tier."""

    def setUp(self):
        temporary = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, temporary)
        self.target, self.copy, self.out = temporary / "repo", temporary / "copy", temporary / "out"
        for folder in (self.target, self.copy / "tests/security", self.out):
            folder.mkdir(parents=True)
        (self.target / "app.py").write_text("ROLE = 'admin'\n")
        (self.out / "report.json").write_text(json.dumps({"target": str(self.target), "status": "findings", "scope": "working-tree",
                                                          "findings": [{**REPORT["findings"][2], "path": "app.py", "line": 1}]}))
        self.test = self.copy / "tests/security/test_role_escalation.py"

    def prove(self, body, *extra, copy=None):
        self.test.write_text(body)
        return subprocess.run([sys.executable, str(SCRIPTS / "prove.py"), str(self.out / "report.json"), "SAST-0003",
                               "--copy", str(copy or self.copy), "--test", "tests/security/test_role_escalation.py",
                               "--expect", "BOUNDARY role changed", *extra, "--", sys.executable, "-I", str(self.test)],
                              capture_output=True, text=True)

    def test_the_test_must_run_outside_the_repository_and_hold_its_marker(self):
        for extra, copy in (((), self.target), (("--expect", "nowhere in the test"), None)):
            done = self.prove("assert False, 'BOUNDARY role changed'\n", *extra, copy=copy)
            self.assertEqual(done.returncode, 2, done.stdout)
        self.assertFalse((self.out / "proofs.json").exists())

    def test_each_attempt_starts_from_the_same_prepared_copy(self):
        # Both attempts used to run in one copy, so state the first left behind could decide the second.
        leaky = ("import pathlib\nflag = pathlib.Path('state.flag')\nif flag.exists():\n    raise SystemExit(0)\n"
                 "flag.write_text('x')\nassert False, 'BOUNDARY role changed'\n")
        done = self.prove(leaky)
        self.assertEqual((done.returncode, json.loads(done.stdout)["proven"]), (0, True), done.stderr)
        self.assertFalse((self.copy / "state.flag").exists())  # the prepared copy itself is never run in
        record = json.loads((self.out / "proofs.json").read_text())["SAST-0003"]
        self.assertEqual(record["isolation"], "fresh copy of the prepared copy for each attempt")
        self.assertEqual(self.prove(leaky, "--same-copy").returncode, 2)  # running in place needs the reset written down
        same = self.prove(leaky, "--same-copy", "--reset", "the test removes state.flag in its teardown")
        self.assertFalse(json.loads(same.stdout)["proven"])  # it does not, so the second attempt passed
        self.assertEqual(json.loads((self.out / "proofs.json").read_text())["SAST-0003"]["isolation"],
                         "same copy; reset: the test removes state.flag in its teardown")

    def test_a_failing_assertion_proves_and_a_crash_does_not(self):
        crash = self.prove("raise RuntimeError('fixture missing')\nassert False, 'BOUNDARY role changed'\n")
        self.assertEqual((crash.returncode, json.loads(crash.stdout)["proven"]), (1, False))
        proof = self.prove("role = 'admin'\nassert role == 'user', 'BOUNDARY role changed'\n")
        self.assertEqual((proof.returncode, json.loads(proof.stdout)["proven"]), (0, True), proof.stderr)
        proofs = json.loads((self.out / "proofs.json").read_text())
        self.assertIn("BOUNDARY role changed", proofs["SAST-0003"]["source"])
        self.assertEqual((self.out / "proofs.json").stat().st_mode & 0o777, 0o600)
        confirmed = {**CORS, "disposition": "confirmed", "evidence_refs": [{"path": "app.py", "line": 1}]}
        del confirmed["no_proof"]
        (self.out / "assessments.json").write_text(json.dumps([confirmed]))
        rendered = subprocess.run([sys.executable, str(SCRIPTS / "render_review.py"), str(self.out / "report.json")], capture_output=True, text=True)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertIn("**Tier:** confirmed", (self.out / "review.md").read_text())
        # The ledger keeps its header; the tier is its basis column: test, code or assumed.
        recorded = subprocess.run([sys.executable, str(SCRIPTS / "ledger.py"), "record", str(self.target), str(self.out / "review.json")],
                                  capture_output=True, text=True)
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        with (self.target / "security/findings.csv").open(newline="") as f:
            self.assertEqual([row["basis"] for row in csv.DictReader(f)], ["test"])


class ScannerProjectionTests(unittest.TestCase):
    def test_semgrep_duplicates_across_packs_and_parse_warnings(self):
        result = {"check_id": "rust.lang.security.unsafe-usage", "path": "a.rs", "start": {"line": 3, "col": 5},
                  "end": {"line": 3, "col": 9}, "extra": {"severity": "WARNING", "metadata": {}}}
        findings, coverage = scan.project("sast", {"results": [result, dict(result)], "paths": {"scanned": ["a.rs"]},
                                                   "errors": [{"type": "PartialParsing", "level": "warn", "path": "b.tsx"}]})
        self.assertEqual([item["id"] for item in findings], ["SAST-0001"])
        self.assertEqual((coverage["scanner_errors"], coverage["parse_warnings"]), (0, 1))

    def test_sca_marks_the_same_advisory_under_another_id(self):
        findings, _ = scan.project("sca", {"results": [{"source": {"path": "Cargo.lock"}, "packages": [{
            "package": {"name": "bytes", "version": "1.10.1", "ecosystem": "crates.io"},
            "vulnerabilities": [{"id": "RUSTSEC-1", "aliases": ["GHSA-1"]}, {"id": "GHSA-1", "aliases": ["RUSTSEC-1"]},
                                {"id": "RUSTSEC-2"}]}]}]})
        self.assertEqual([f.get("duplicate_of") for f in findings], [None, "SCA-0001", None])

    def test_terraform_module_guard_only_flags_downloadable_modules(self):
        self.assertFalse(iac.remote_modules("ec2.tf", b'user_data = file("${path.module}/proxy.sh")\n'))
        self.assertFalse(iac.remote_modules("main.tf", b'module "net" {\n  source = "./modules/net"\n}\n'))
        self.assertTrue(iac.remote_modules("main.tf", b'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'))
        self.assertTrue(iac.remote_modules("main.tf.json", json.dumps({"module": {"x": {"source": "git::https://e.invalid/m"}}}).encode()))
        self.assertFalse(iac.likely_iac("frontend/package-lock.json"))
        self.assertTrue(iac.likely_iac("infra/Dockerfile"))


@unittest.skipUnless(shutil.which("git"), "Git required")
class SecretProbeTests(unittest.TestCase):
    def test_probe_classifies_without_printing_values(self):
        real = "sk_live_" + "Zq8" + "rT2vX9mKp4LwN7bHs3JdYc6Fu1Ge5Ra0"
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            env = {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}
            subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
            (repo / "config.py").write_text(f'API_KEY = "{real}"\nOTHER = "your_api_key_here_example"\n'
                                            'ENVKEY = os.environ["API_KEY"]\nWEAK = "SUPER_SECRET_API_KEY"\n')
            (repo / ".gitignore").write_text(".env\n")
            (repo / ".env").write_text(f"TOKEN={real}\n")
            subprocess.run(["git", "-C", str(repo), "add", "config.py", ".gitignore"], check=True, env=env)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "x"], check=True, env=env)
            report = repo.parent / f"{repo.name}-report.json"
            findings = [{"id": f"SECRET-000{i}", "path": path, "line": line, "commit": ""}
                        for i, (path, line) in enumerate((("config.py", 1), ("config.py", 2), ("config.py", 3), (".env", 1)), 1)]
            report.write_text(json.dumps({"target": str(repo), "findings": findings}))
            self.addCleanup(report.unlink)
            output = subprocess.run([sys.executable, str(SCRIPTS / "secret_probe.py"), str(report), "--history"],
                                    capture_output=True, text=True, check=True).stdout
            self.assertNotIn(real, output)
            self.assertNotIn("your_api_key", output)
            result = {item["id"]: item for item in json.loads(output)}
            self.assertEqual(result["SECRET-0001"]["hint"], "looks-real-and-committed: rotate")
            self.assertTrue(result["SECRET-0002"]["looks_like_placeholder"])
            self.assertTrue(result["SECRET-0003"]["references_environment_or_template"])
            self.assertEqual(result["SECRET-0004"]["hint"], "looks-real-and-committed: rotate")
            self.assertTrue(result["SECRET-0004"]["git_ignored"])
            self.assertTrue(result["SECRET-0004"]["value_ever_committed"])
            by_file = subprocess.run([sys.executable, str(SCRIPTS / "secret_probe.py"), "--repo", str(repo), "--file", "config.py"],
                                     capture_output=True, text=True, check=True).stdout
            self.assertNotIn(real, by_file)
            hints = {item["id"]: item["hint"] for item in json.loads(by_file)}
            self.assertEqual(hints["config.py:4"], "low-entropy-literal: check where it is used; committed")

    def test_probe_file_accepts_absolute_path_through_a_symlinked_alias(self):
        # macOS: /tmp and /var are links into /private, so the agent's path and the resolved repo differ.
        with tempfile.TemporaryDirectory() as temporary:
            alias = Path(temporary)
            subprocess.run(["git", "init", "-q", str(alias)], check=True)
            (alias / "config.py").write_text('WEAK = "SUPER_SECRET_API_KEY"\n')
            probe = [sys.executable, str(SCRIPTS / "secret_probe.py"), "--repo", str(alias.resolve())]
            inside = subprocess.run(probe + ["--file", str(alias / "config.py")], capture_output=True, text=True)
            self.assertEqual(inside.returncode, 0, inside.stderr)
            self.assertEqual([item["id"] for item in json.loads(inside.stdout)], ["config.py:1"])
            outside = subprocess.run(probe + ["--file", str(Path(__file__).resolve())], capture_output=True, text=True)
            self.assertNotEqual(outside.returncode, 0)


if __name__ == "__main__":
    unittest.main()
