# Evaluation

How the skills are measured, and what the measurements showed. A number here was measured on the date given; nothing is estimated.

## Method

- **The arena.** A purpose-built multi-tenant application of about 11,000 lines (Flask API, an OAuth 2.1 server, an MCP server, enterprise SSO, an assistant with retrieval, an edge service, Terraform and CI workflows) with planted flaws and decoys. Answer key v3: 51 flaws and 11 decoys, each with an executable proof and a real fix. The arena and its key are private: a public answer key makes a benchmark worthless.
- **Blind runs.** Each run gets a fresh copy without Git history of the key, the same written rules, and no knowledge of other runs. A run with a skill and a run without one (the same model, told to do the same job its own way) get the same rules, so the difference is the skill.
- **Scoring.** A finding hits a flaw when its path matches and its lines overlap the flaw's enclosing function. Each finding counts for at most one flaw, so a vague finding cannot collect several. Decoys count as false alarms. With a run on the fixed twin, a flaw counts only when the tool reports it in the original and not in the fixed copy (paired scoring).
- **"Shown by request"** counts flaws that a request sent by the run demonstrated, not ones it inferred from code.

One run varies too much to say much: with 51 flaws, the standard error is about six percentage points before runs differ at all. Three runs per setup and one on the fixed twin is the target; the rows below say when fewer were made.

## Runtime testing on the arena, 2026-11-18

| Setup | Runs | Flaws found | Shown by request | Decoys flagged | Minutes |
| --- | --- | --- | --- | --- | --- |
| No skill, dynamic test | 2 | 74 %, 67 % | 65 %, 59 % | 0, 2 | 7, 9 |
| local-dast before the runner changes | 2 | 69 %, 71 % | 35 %, 39 % | 0, 0 | 20, 20 |
| local-dast with forms, uploads, wider `take`, `--only` | 2 | 71 %, 71 % | 61 %, 53 % | 0, 1 | 30, 29 |

What it says: the first version proved about half of what the bare model proved, because its runner could not express forms, uploads or values carried between requests. With those added it reached the same level, at three to four times the time. It does not yet beat the bare model, and two runs per setup cannot show a difference smaller than the noise. The friction notes of those runs drove the next changes: a taken value in a header and an upload field, assertions against a taken value, cookies that can be taken and replayed, `--only` keeping the writes and sign-ins a case stands on, and case shapes beyond access control. That version is the one in this repository, and it has not been measured yet. No twin run was made on this date.

## Gap analysis on the arena, 2026-11-18

One blind run of security-gap-analysis, code reading only: 74 % of the key's flaws found (38 of 51) as missing or partial controls, plus 25 findings outside the key, which is the skill's actual job (controls that are absent rather than code that is wrong). One decoy flagged. 19 minutes. No twin run. Its friction notes (step order, inventory patterns that missed file-path sinks and model calls, `check --complete` accepting an ID anywhere in `gaps.md`, no rows for build, release and Terraform) are the next work.
