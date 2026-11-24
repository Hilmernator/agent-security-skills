# Changelog

What changed in each version, newest first, and what an existing installation must do about it.

## Unreleased

- local-security-review: `prove.py` prints the end of the test's output when an attempt proves nothing, so a missing marker or a crash says why; `candidates.py` ends quietly when its reader stops early (`| head`).
- local-security-review and security-gap-analysis spend fewer tokens: `candidates.py` lists a scan's candidates one line per rule, so the report is never read whole; the skills say to read line ranges, batch independent reads, and give large reading to foreground subagents on a mid-tier model that return cited leads, while the main agent verifies the cited lines and keeps every verdict. Subagent slices must together cover every entrypoint, and every lead is assessed, low confidence included.
- local-security-review and local-dast: every script hands over to Python 3.10+ by itself when `python3` is older (`_python.py`); before, a stock macOS `python3` (3.9) had to be replaced by hand. Nothing to do on an installation.
- local-security-review: Bandit's `assert` check and ESLint's object-injection check are left out in test files and counted under `coverage.filtered` (on large repositories they were most of the candidates). A partial language scan says how many files and which. The hunt asks for every outbound request a user can aim and for the defaults of security settings, step 5 keeps at least a third of the session, a missing check is placed at the function that should hold it, and a host's refusal to read a `.env` file is recorded as a coverage gap instead of retried.
- security-gap-analysis: `gap.py probe` refuses a file that is absolute or resolves outside the copy (through `..` or a link) before it changes anything, for one probe and for a batch; before, a probe could edit a file outside the copy while the tests ran.
- local-dast: the ledger refuses `confirmed` unless `basis` is `test` and the assessment's new field `reproduced_in` names the other run's `report.json`, which must show the same case failed again (or the same alert). Assessments that recorded `confirmed` without it must add the second run.
- local-security-review: `prove.py` runs each of its two attempts in a fresh copy of the prepared copy; `--same-copy --reset "<how>"` runs in place and records how. `proofs.json` says which (`isolation`). Each scan report names the Semgrep rule packs it ran (`rule_packs`, their download time and hashes), because the packs come from URLs whose content changes; the README says which downloads are pinned and which are recorded.
- Security gate: no package name is looked up on the public registry when npm, yarn, pip, uv or poetry is set up for a private registry in a configuration file or the environment; the gate says it skipped the lookup. An error inside the gate still lets the call run, and now says that call was not checked (the kind of error only). The plugin description says what the hooks cover.
- security-gap-analysis: `set` writes nothing when a row has a problem (it saved evidence past the end of a file); a chapter may be named as `check` prints it (`aisvs:C1`); `show --compact` prints one line per row; `profile.md` may name boundary files by folder (`src/routes/`) or glob; a `read` mark over more than ten files is recorded as a bulk mark, and `check --complete` refuses a boundary file read only that way. On a repository too large to read in full, the skill reads by risk and says what it left.

## 0.4.0

security-gap-analysis gets a design layer. Requirements ask whether a named control exists; products usually fail in how controls compose, and in a blind run on a planted-flaw application of 2026-11-18 rows were correctly `met` inside functions whose design was broken (cross-tenant signing keys, a protocol session that replaced the token's identity, consent remembered by name). Three additions, all in the existing files:

- `--select design:<level>`: 34 security design requirements written for this skill, one chapter per architectural tactic of CWE-1008 (Architectural Concepts), each applying a principle of NIST SP 800-53 SA-8.
- A `## Security invariants` table in `profile.md`: the product's own design rules, each with every enforcement point, its strength (`central`, `per-path`, `none`), a test cell and a status. `gap.py check` checks its shape and evidence, and `--complete` needs every broken or partial invariant in an entry of `gaps.md`.
- `gap.py probe`: switches one control off in a copy, runs the project's tests before and after, puts the file back, and writes into the invariant's Test cell whether any test failed. The cell names the line it switched off, so anyone can repeat the probe. On the same application's own suite, 10 of 20 correctly built controls could be switched off with all 180 tests still passing (measured 2026-11-18). The skill also has a basic control behind each `met` authentication, authorization and session row probed, one probe per function; in two blind runs this found four untested controls each, in about three and a half minutes of probing.


security-gap-analysis on a larger codebase (a blind run on a five-service practice application of about 41,000 own lines plus 129,000 vendored, 2026-11-18): `gap.py` now takes a lock on the `security/` folder, because two calls at once each rewrote the same CSV and one run lost 1,215 inventory marks without a word. Vendored folders (`vendor/`, `node_modules/`, `third_party/`) raise no inventory lines (the run had 1,420 of them), nor do licence-header URLs. New patterns find nginx `location` blocks, Django `re_path` and `url(` routes, `FileResponse`, Java's `openConnection` and `new URL(`. `gap.py controls` lists every place the product's own code refuses a caller, by function, and which a probe has switched off, so which controls a run probes no longer depends on what it notices (two runs that chose their own probes each found a different two or three of ten untested controls). `gap.py probe --batch <csv>` runs many probes after one baseline run (two runs spent 14 to 17 minutes probing 38 and 42 controls, half of it on repeated baselines), and `inventory --mark --unreviewed` leaves earlier marks alone. `gap.py set --from <csv>` sets many rows in one call and writes nothing when a line is wrong (two runs reported setting 450 rows one call at a time). `inventory --mark` works on the saved inventory instead of rescanning the repository each time (a second run spent over an hour placing 3,140 lines at about 3 s a call), and `--match <regex>` marks lines by their text. `--lines` on a folder is refused instead of matching nothing, a boundary file missing from the profile is reported once with its line count, and an Access policy row may say `partial: <lines>` when it is checked, but not as the policy says.

security-gap-analysis gets rows for the build and release pipeline: `--select cicd:<level>` adds 18 controls written for this skill, one chapter per OWASP Top 10 CI/CD Security Risk (flow control, pipeline identities, dependency chain, poisoned pipeline execution, credentials, runners and caches, pinned third-party actions, artifact integrity, logging). Before, pipeline gaps lived only as prose in `gaps.md` and nothing reopened them when a workflow changed. `gap.py check --complete` now reads `gaps.md` by its headings: a missing or partial ID must stand in an entry, not only in the summary or under Not covered, and an unverifiable ID under Check outside the code. An existing `gaps.md` that named IDs only in its summary fails until they get an entry.

local-dast, from the friction of the blind runs of 2026-11-18 (all four skill runs reported the first point):

- `--only` no longer keeps every earlier write and every earlier case of a session; a reproduction was 36 of 37 and 43 of 44 cases. It keeps what a case names (`requires`, the new `after`, `same_as`, the cases its values come from) and the first case of each session it uses. A plan whose re-read relied on the old rule must name its write in `after`.
- New field `after`: run once the named cases have run, whatever their result. A case that shows a flaw's impact no longer becomes `not-run` because the case that showed the flaw failed, as `requires` makes it.
- A `Cookie` in `headers` is sent after a session's own cookies, so a planted cookie can travel with a victim's session.
- A taken value may be up to 4,096 characters, enough for a JWT.
- `review.md` names the header of a failed `expect_headers` or `forbid_headers`.
- The findings ledger: an assessment may name a failed case's root cause (`finding`) and its file (`path`). Cases with one root cause become one row at that file instead of one row per case without a place; two runs reported 58 rows for 34 findings. A row that gets a path gets a new fingerprint.
- The skill text: an effect read from the disposable copy's database, outbox or log in both runs counts as `confirmed`; the Routes list comes from the framework's route table; one assessment for many runs; Boundaries mention `.git/info/exclude`; a read-only MCP tool still needs `--allow-writes`.

## 0.3.0

Ships Cloudflare's security-audit skill in the bundle, unchanged from upstream commit `c1c8a8c`, under its own MIT licence. It is listed in the README under "Other security skills I use", apart from the skills written here. Install: copy `skills/security-audit` as well; its validators need Node.js.

## 0.2.0

Adds local-security-review: a scanner-backed review of a repository (SAST, SCA, secrets in files and local Git history), with investigation of every finding, a hunt for what scanners miss, a fix plan in three evidence tiers, and proof tests run twice before a finding counts as `confirmed`. It writes the same findings ledger as local-dast, so `ledger.py` is shared between the two and kept identical by a test. The security gate's last check now applies to its findings too.

Install: copy `skills/local-security-review` and run `security.py --setup` once; it downloads and pins the scanners.

## 0.1.0

First release as its own repository. local-dast, security-gap-analysis, the findings ledger and the security gate were developed in a private skill collection before this; the history starts here.

Changes since the last measured version (see [evaluation](docs/evaluation.md), 2026-11-18):

- local-dast: a case can send literal headers (`headers`), with a taken value anywhere in their text, so a CSRF token from the sign-in answer goes back as `X-CSRF-Token`. On loopback `Host` may be set. A taken value can fill a `multipart` field and be compared in `expect_json`, `expect_text`, `forbid_text`, `expect_headers` and `forbid_headers`. `take` reads a cookie the answer sets. `--only` keeps every earlier write and every earlier case of a session a kept case uses, and checks only the variables of the cases it keeps; a plan error names the case and the variable, never a value. `review.md` names which texts of `expect_text` and `forbid_text` failed, by position. An unexpected redirect is a failed assertion, no longer a coverage gap. `report.json` says why a run is incomplete (`incomplete_because`). The plan reference adds case shapes beyond access control.
- security-gap-analysis: a new inventory kind for file paths built from requests, the AI pattern no longer fires on the word "mcp" and finds model calls, the access policy accepts "public by design", and `inventory --mark` answers in one line.

Nothing to install. A plan that relied on an unexpected redirect making a run `incomplete` now gets `candidates` instead.
