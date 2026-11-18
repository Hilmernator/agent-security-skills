# Investigate a finding

A scanner hit is a lead, not a verdict. For each candidate answer five questions,
with file:line evidence:

1. **What does the rule or advisory actually claim?** Read the rule (Semgrep packs
   are in `~/.cache/rasmus-security/semgrep/packs/`, bundled rules in
   `assets/semgrep/`) or the advisory link. Know the precise dangerous behavior.
2. **Where does the data come from?** Trace from the sink back to its sources
   across files: request params/body/headers, CLI args, files, env, database, other
   services. Note every validation, normalization and type conversion on the way.
3. **Who can reach it?** Use `context.md`: unauthenticated internet user, logged-in
   user, another tenant, local user, CI/build, the developer only. Test code and
   one-off scripts usually have no attacker; say so explicitly rather than assuming.
4. **What do existing controls stop?** Auth middleware, allowlists, framework
   escaping, parameterized APIs, canonicalize-and-check, size limits. Check that the
   control covers this exact path, at the sink, for every variant (absolute paths,
   encodings, redirects, alternative content types).
5. **What is the concrete impact?** Name the capability and the asset, for example
   "files outside `uploads/` that the service account can read become readable", not
   "path traversal risk". Describe the missing control and its consequence; there is
   no need to write out attack payloads.

## Prove it: three tiers

Every finding lands in one tier. `confirmed`: a test fails on the current code, and
`prove.py` saw it fail twice on its assertion. `judged`: you read the code path and
believe it, but no proof ran. `scanner`: a signal not yet judged (`needs-review`,
`unreviewed`). Reading your own finding again is not a proof; only a run is.

1. **Start from a test the project already has** for the same entrypoint or module:
   its test client, fixtures, factories and seeded database. Copy its setup. Without
   such a template, generated security tests seldom run.
2. **Write the test in the temporary copy**, in the project's test folder under
   `security/`, named after what it shows, not after the ID:
   `tests/security/test_peer_cannot_read_note.py`, `test/security/peer-cannot-read-note.test.ts`,
   Rust `tests/security_peer_cannot_read_note.rs` (or a `#[cfg(test)] mod security_…`
   beside a private function). Prefer the app's own test client over HTTP against a
   running server.
3. **Assert on the boundary crossed, not on a crash**: another user's marker is in the
   response, the role changed, the request reached the sink with the input in it, a
   file outside the base was read. Put a unique marker (`BOUNDARY peer read note`) in
   the assertion message and nowhere else. Build a fresh fixture or database in each
   run, so the second run does not see the first one's state. Use the smallest input
   that shows the boundary; no exploit payload beyond that.
4. **Run it with** `python3 scripts/prove.py <report.json> <ID> --copy <copy> --test <path in copy> --expect "<marker>" -- <test command>`.
   It runs the command twice and records the outcome and the test's source in
   `proofs.json` beside the report. Only two failing runs that both print the marker
   count; it refuses a copy that overlaps the repository. Then set `confirmed`;
   `render_review.py` refuses `confirmed` without such a proof, and refuses a proven
   finding that you call anything else.
5. **Classes with no executable oracle** (a weak cipher choice, a missing header or
   cookie flag, configuration) are proven by a pinned check: a test that reads the
   exact file and line (parses the config, inspects the constructed object) and
   asserts the setting. Say in `evidence` that the proof is a pinned check.
6. **When no proof can run**, keep `likely` and write `no_proof`: one line on why
   (needs an external service, timing or cryptanalysis, a build out of proportion,
   no test harness). An unproven finding is not a false one; it stays in its tier.

Work in a temporary copy of the repository outside it (`cp -R`, or
`git clone --local` plus copied uncommitted files) with synthetic data, so the user's
tree, build output and data stay untouched. Never touch external hosts, real
credentials, or user data. Keep the boundary input in the test file and out of
`evidence`. If a
build needs dependencies that are not cached locally, ask the user once whether
fetching them for the temporary copy is fine; otherwise prove at function level
(a small test file that includes only the vulnerable module; a minimal stub for a
third-party dependency is fine if it does not change the logic under test) or keep
`likely`. Reusing dependencies the project already installed is fine when you copy
them (an existing `node_modules`, or the project's virtualenv interpreter run with
`-I` against the copied tree, adding the copy's root to `sys.path` in the test, since
`-I` leaves the script's folder off it); never symlink into the user's tree. Check early whether
an offline build works, and note when you use existing build output that is older
than the source.

## Verdicts

| Disposition | Tier | Use when |
| --- | --- | --- |
| `confirmed` | confirmed | A proof test failed twice on its assertion under `prove.py`. |
| `likely` | judged | You traced the flow, nothing stops it, but no proof ran; `no_proof` says why. |
| `false-positive` | judged | You can name the guard, constant input or unreachable code that rules it out (high confidence only). |
| `needs-review` | scanner | Evidence is insufficient either way. Say exactly what would settle it. |

"Intentional", "in tests" or "validated" alone is not a dismissal: name the guard or
show the input is constant/synthetic.

Some rules claim a weakness, not a flow: a weak cipher or hash, a cookie without its
flags, a value that crosses a trust boundary, a hard-coded key. Such a finding is true
when the code does what the rule says at that line, with or without a demonstrated
exploit: give it `likely`, or `confirmed` with a pinned check, at `low` or `info` severity, and let the
severity carry how little it matters here. It is `false-positive` only when the claim
itself is false there (the hash is not used for security, the value is not a secret,
the cookie holds nothing a script may not read), with the file and line that show it.

Severity is your assessment, not the scanner's:

- **critical**: unauthenticated remote code execution, full data or credential
  compromise, auth bypass for admin.
- **high**: arbitrary file read/write/delete, SQL/command injection, auth bypass or
  cross-tenant access, live credential committed to git.
- **medium**: needs authentication or notable preconditions; limited data exposure;
  stored XSS; SSRF to internal metadata without credentials.
- **low**: hardening and defense in depth (permissive CORS without credentials, missing
  headers, panics that kill one request).
- **info**: no security impact in this context.

Rate the impact if the preconditions hold, then lower one level when exploitation
first needs another compromise (for example code execution on the host). A flow you
confirmed through a non-default exposure (a port bound to localhost) is still
`confirmed`; put the exposure in `preconditions` and let severity reflect it.

## Engine-specific shortcuts

**SCA.** Each finding carries the advisory `summary`, `fixed_versions` and, when the
same advisory appears under another database ID, `duplicate_of` (assess duplicates in
one `ids` entry with their original). Full advisory records are in the local
databases under `~/.cache/rasmus-security/sca/databases/`. Check the locked version
in the lockfile, whether it is runtime, build or dev, and for multi-environment
lockfiles (for example `uv.lock` resolution markers) which entry is actually used.

- Reachable or plausibly reachable at runtime: `likely`/`confirmed`, severity from
  the advisory and your trace. Spend tracing effort only when the upgrade is major or
  no fix exists.
- Cheap fix (patch/minor) but the vulnerable feature is not used: `likely` at `info`
  severity; it belongs in the routine update item, not a separate fix.
- Dev or build tooling that only processes developer-owned files: `false-positive`
  with that as the reason. Tooling that processes untrusted input (CI on pull
  requests, uploaded files) stays actionable.
- Unmaintained crate or package notices without a fix: `info`, recommend migration.
- An entry that is not installed in any supported environment: `false-positive`.

Group by root cause and fix: all advisories for one package version in one lockfile
form one issue; routine upgrades that one command fixes (`cargo update`,
`uv lock --upgrade`, `npm update`) may form one "update dependencies" issue across
packages in that lockfile, as long as every member is actionable.

**Secrets.** Run `scripts/secret_probe.py <report.json> SECRET-0001 ...` (add
`--history` to learn whether the value was ever committed). It returns only
booleans: placeholder, env reference, entropy, test path, tracked or ignored, and a
hint. Committed real-looking credentials: `confirmed`, rotate, and remove from
history if the repo is shared. Real values only in a git-ignored local file: `low`,
keep them out of git. Placeholders and env references: `false-positive` with the
probe result as evidence.

**IaC.** Check the resource and its policies, network paths and parameters. A missing
property is not proof of exposure; an assumed account-wide guard is not proof of
safety. For CDK, fix the construct, not the generated template.

**Noise classes.** Rules like Bandit `B101` (assert), ESLint
`detect-object-injection` or `detect-non-literal-fs-filename` in CLI tools are often
noise. Open enough instances to be sure the same reasoning holds, then assess the
whole class in one `ids` entry. Split out any instance where the input differs.

## Files

`assessments.json`: an array. Required: `id` (or `ids`), `disposition`,
`confidence` (`high|medium|low|unknown`), `assessed_severity`
(`critical|high|medium|low|info|unknown`), `evidence`, `recommendation`.
`confirmed`/`likely`/`false-positive` also need `evidence_refs`
(`[{"path": "src/a.rs", "line": 12}]`); `confirmed`/`likely` need `preconditions`
(attacker position and remaining assumptions, or "none"); `false-positive` needs
`dismissal_reason`; `likely` needs `no_proof` (one line on why no proof ran).
`confirmed` needs a proof in `proofs.json`, which only `prove.py` writes; never put
`proof` in an assessment. Optional: `verify` (how to check the fix: for a confirmed
finding, its proof test passing twice plus the project's own test command), and on an entry with `ids` a `title` for the issue in the fix plan
(without it the heading is a list of rule names). Write these texts as plain prose:
the renderer escapes markdown, so a code span comes out as `&#96;`.

```json
[
  {"id": "SAST-0004", "disposition": "confirmed", "confidence": "high", "assessed_severity": "high",
   "evidence": "GET /get/:alias/*path passes path unchanged to PathBuf::join and fs::read_to_string; '..' segments and absolute paths escape uploads/.",
   "evidence_refs": [{"path": "src/handlers/read.rs", "line": 11}, {"path": "src/utils/file.rs", "line": 9}],
   "preconditions": "None: the route is unauthenticated and bound to localhost:3001; any local process or a browser via CORS can call it.",
   "recommendation": "Reject absolute paths and '..' components, canonicalize the joined path and require it to start with the canonical uploads/<alias> directory.",
   "verify": "cargo test --test security_read_outside_uploads passes twice after the fix, and cargo test still passes."},
  {"id": "SAST-0007", "disposition": "likely", "confidence": "medium", "assessed_severity": "medium",
   "evidence": "The webhook handler parses the body before it checks the signature.",
   "evidence_refs": [{"path": "src/webhook.rs", "line": 30}], "preconditions": "Anyone who can reach /webhook.",
   "no_proof": "The signature check calls the payment provider's SDK, which the tests cannot run offline.",
   "recommendation": "Verify the signature on the raw body before parsing it."},
  {"ids": ["SAST-0010", "SAST-0011", "SAST-0012"], "disposition": "false-positive", "confidence": "high",
   "assessed_severity": "info", "evidence": "All three are assert statements in pytest files.",
   "evidence_refs": [{"path": "tests/test_api.py", "line": 8}],
   "dismissal_reason": "Asserts only run in the test suite; production code does not rely on them.",
   "recommendation": "No change."}
]
```

`groups.json` (optional): `[{"title", "finding_ids": [two or more], "root_cause",
"evidence", "preconditions", "recommendation", "verify"?}]`. A group's `evidence`
replaces the members' text in the fix plan, so write the impact there; member proofs
are listed under it, and the group takes its weakest member's tier. A multi-ID `ids` assessment already renders as one issue, so
group only when members have separate assessments. Group only signals with
the same root cause and the same fix; members must not mix actionable and dismissed
verdicts.

`agent_findings.json` (from the hunt): `[{"id": "AGENT-0001", "title", "rule"
(category such as "idor"), "path", "line", "cwe"?}]`, each with an assessment entry.
