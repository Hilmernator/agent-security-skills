# Changelog

What changed in each version, newest first, and what an existing installation must do about it.

## 0.1.0

First release as its own repository. local-dast, security-gap-analysis, the findings ledger and the security gate were developed in a private skill collection before this; the history starts here.

Changes since the last measured version (see [evaluation](docs/evaluation.md), 2026-11-18):

- local-dast: a case can send literal headers (`headers`), with a taken value anywhere in their text, so a CSRF token from the sign-in answer goes back as `X-CSRF-Token`. On loopback `Host` may be set. A taken value can fill a `multipart` field and be compared in `expect_json`, `expect_text`, `forbid_text`, `expect_headers` and `forbid_headers`. `take` reads a cookie the answer sets. `--only` keeps every earlier write and every earlier case of a session a kept case uses, and checks only the variables of the cases it keeps; a plan error names the case and the variable, never a value. `review.md` names which texts of `expect_text` and `forbid_text` failed, by position. An unexpected redirect is a failed assertion, no longer a coverage gap. `report.json` says why a run is incomplete (`incomplete_because`). The plan reference adds case shapes beyond access control.
- security-gap-analysis: a new inventory kind for file paths built from requests, the AI pattern no longer fires on the word "mcp" and finds model calls, the access policy accepts "public by design", and `inventory --mark` answers in one line.

Nothing to install. A plan that relied on an unexpected redirect making a run `incomplete` now gets `candidates` instead.
