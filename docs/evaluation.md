# Evaluation

How the skills are measured, and what the measurements showed. A number here was measured on the date given; nothing is estimated.

## Method

- **The arena.** A purpose-built multi-tenant application of about 11,000 lines (Flask API, an OAuth 2.1 server, an MCP server, enterprise SSO, an assistant with retrieval, an edge service, Terraform and CI workflows) with planted flaws and decoys. Answer key v3: 51 flaws and 11 decoys, each with an executable proof and a real fix. The arena and its key are private: a public answer key makes a benchmark worthless.
- **Blind runs.** Each run gets a fresh copy without Git history of the key, the same written rules, and no knowledge of other runs. A run with a skill and a run without one (the same model, told to do the same job its own way) get the same rules, so the difference is the skill.
- **Scoring.** A finding hits a flaw when its path matches and its lines overlap the flaw's enclosing function. Each finding counts for at most one flaw, so a vague finding cannot collect several. Decoys count as false alarms. With a run on the fixed twin, a flaw counts only when the tool reports it in the original and not in the fixed copy (paired scoring).
- **"Shown by request"** counts flaws that a request sent by the run demonstrated, not ones it inferred from code.

One run varies too much to say much: with 51 flaws, the standard error is about six percentage points before runs differ at all. Three runs per setup and one on the fixed twin is the target; the rows below say when fewer were made.

## Code review on the arena, 2026-11-16

Three blind runs per setup on the original and one on the fixed twin, the same model (Opus 5.5), scored against answer key v3. The twins were built before 14 of the key's entries existed, so those entries do not count in the twin on this date.

| | No skill | local-security-review |
| --- | --- | --- |
| Paired recall, median (min–max) | 74 % (72–74) | 84 % (78–94) |
| Code flaws, levels 2–5, median | 37 of 41 | 38 of 41 |
| Vulnerable dependencies (10) | 1–2 | 2–10 |
| Precision (lower bound) | 95 % | 94–96 % |
| Decoys flagged | 0 % | 0 % |
| Union over three runs | 80 % | 96 % |
| Time per run | 5–6 min | 13–16 min |

What it says: on code flaws the difference is one hit, inside the noise; the bare model already finds almost every flaw at levels 2 to 5. The skill's lead comes from dependencies and from steadier results. One run dismissed most advisories as unreachable, which is why the low end is 2 of 10. The skill missed a secret that exists only in Git history in all three runs, while the bare model found it each time with `git log`; full scans read local history since, and that change has not been measured.

## Runtime testing on the arena, 2026-11-18

Two series on the same day. The first ran before the runner changes and on a model that was not recorded, two runs per setup and no twin. The second ran the version in this repository at 0.3.0: three runs per setup on the original and one on the fixed twin, all eight on Opus 5.5 with the same rules, so its numbers can be compared with each other and not with the first series.

**Second series (Opus 5.5, paired against the twin).**

| | No skill, dynamic test | local-dast 0.3.0 |
| --- | --- | --- |
| Paired recall, median (min–max) | 63 % (63–65) | 67 % (65–69) |
| Paired recall, only findings shown by a request | 59 % (59–59) | 57 % (57–61) |
| What "shown by a request" demanded | one request that showed it | a case that failed, and failed again in a second run from reset data |
| Precision (lower bound), median | 90 % | 92 % |
| Still flagged in the fixed twin | 2 flaws (4 %) | 1 flaw (2 %) |
| Decoys flagged | 1 of 11, in one run | 1 of 11, in one run |
| Time per run | 10–12 min | 25–27 min |
| Tokens per run | about 255k | about 350k |

What it says: the skill finds and proves about as much as the bare model, a little more in total and a little less by request, and both differences are inside the noise of three runs (about six points). What it buys is a stricter kind of proof (every request-confirmed finding was reproduced from reset data, which the bare runs never did), fewer false alarms on the fixed twin, and a written plan and report that can be replayed after a fix. It costs two and a half times the time. Neither setup found the ten vulnerable dependencies or the secret in Git history, which are local-security-review's job.

One incident in the bare runs: a tester's own HTTP client followed a redirect to an identity provider's address under the reserved `.test` domain; the name lookup failed and no connection was made. The runner never follows redirects, so the skill runs cannot do this. The rules for testers now say not to follow redirects.

**First series (model not recorded, two runs per setup, no twin).**

| Setup | Flaws found | Shown by request | Minutes |
| --- | --- | --- | --- |
| No skill, dynamic test | 74 %, 67 % | 65 %, 59 % | 7, 9 |
| local-dast before the runner changes | 69 %, 71 % | 35 %, 39 % | 20, 20 |
| local-dast with forms, uploads, wider `take`, `--only` | 71 %, 71 % | 61 %, 53 % | 30, 29 |

The first version proved about half of what the bare model proved, because its runner could not express forms, uploads or values carried between requests. The friction notes of these runs drove the changes measured in the second series.

## Gap analysis on the arena, 2026-11-18

One blind run of security-gap-analysis, code reading only: 74 % of the key's flaws found (38 of 51) as missing or partial controls, plus 25 findings outside the key, which is the skill's actual job (controls that are absent rather than code that is wrong). One decoy flagged. 19 minutes. No twin run. Its friction notes (step order, inventory patterns that missed file-path sinks and model calls, `check --complete` accepting an ID anywhere in `gaps.md`, no rows for build, release and Terraform) are the next work.

## Design layer of the gap analysis, 2026-11-18

All runs blind, on Opus 5.5. "Before" is security-gap-analysis without the design layer; "with" adds the `design` catalog, the Security invariants table and `gap.py probe`. One run before and two with on the planted-flaw arena; one each on a public five-service practice API (about 41,000 own lines in Java, Go, Python and TypeScript, plus 129,000 vendored), judged by hand against its 18 published challenges.

| | Before | With the design layer |
| --- | --- | --- |
| Arena: flaws of the key found | 67 % | 74 %, 69 % |
| Arena: precision (lower bound) | 64 % | 73 %, 61 % |
| Arena: decoys flagged | 1 of 11 | 3 and 2 of 11 |
| Arena: critical and high flaws named by a broken or partial invariant | — | 20 and 21 of 24 |
| Arena: controls probed by `gap.py probe` | — | 6 and 10 |
| Practice API: challenges found | 16 of 18 | 16 of 18 |
| Practice API: own code read line by line | 36 % (server code 71 %) | 39 % (server code nearly all) |
| Time per run | 26 and 35 min | 30, 31 and 37 min |

What it says: the design layer does not find more flaws; the bare reading already found the critical ones, and the differences are inside the noise. What it adds is structure the reading did not have. The broken invariants are the design gaps, stated as rules of the product with their place in the code (an SSO key not owned by one tenant, a protocol session that does not carry the token's identity, a share link's permission outside its signature), and on the practice API they map almost one to one onto its published challenges. It costs about five minutes a run and a few more alarms on decoys.

**Do the tests test the controls?** Measured on the arena with a script that switches one correctly built control off at a time in a copy and runs the application's 180 tests: 10 of 20 controls can be removed with every test still passing, among them the sign-in requirement on views, the tenant filter on listings, the password check, the one-time-code check and all three checks on authorization codes. Where a run's probe and this measurement looked at the same line they agreed. The first two runs probed only their design invariants (6 and 10 probes) and found the three authorization-code checks untested. The skill then asked for a probe of each basic control that `met` authentication, authorization and session rows rely on; two more runs made 11 probes each, in about three and a half minutes, and each found four untested controls: the password check and the one-time-code check from the measurement, plus two the measurement had not looked at (session expiry, and the validity check of API keys). Together the four runs found 5 of the 10 untested controls and 2 more. Every verdict is the script's, from running the tests; what limits a run is which controls the agent chooses to probe, and each run chose differently. So `gap.py controls` now lists every function that refuses a caller, and the probe step starts from it. Two runs with the list probed 38 and 42 controls in 14 to 17 minutes and found 11 and 12 untested: three and two of the measured ten, and the rest outside the measurement, several in both runs (the validity check of API keys, a check in the OAuth flow, the file route of share links, the trusted-device cookie, the conversation check of the assistant). What the list cannot reach is a control that does not refuse in a recognisable way, such as a tenant filter inside a query or an OAuth error returned as a value; those of the measured ten stayed unprobed.

**Larger codebases.** On the practice API one agent without subagents read nearly all server code and swept the user interface by pattern. What slowed it was the tooling, not the reading: `gap.py` lost 1,215 marks when two calls ran at once, and marking rescanned the whole repository at about three seconds a call. Both are fixed. Tests of services that need a database or a build download could not be probed offline.

