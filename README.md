# Agent security skills

Security skills for coding agents (Claude Code, Codex) that leave evidence behind instead of opinions. Each skill answers one question, says what it did not cover, and is measured blind against an application with a known answer key before a change is kept.

| Skill | The question it answers | It leaves behind |
| --- | --- | --- |
| [security-gap-analysis](skills/security-gap-analysis/SKILL.md) | Which security controls should this code have, and does not? | The repository's `security/` folder: a product profile, a ledger of every file read, an inventory of every way in, and a status with `file:line` evidence for each requirement |
| [local-dast](skills/local-dast/SKILL.md) | What does the running application actually do when one user asks for, or changes, another's data? | A fix plan and a private report of every request sent and every assertion checked; its rows in `security/findings.csv` |
| [Security gate](#security-gate) | Can the agent quietly weaken the checks that judge it? | Nothing; it asks a person first |

## How I build these

- **Evidence over claims.** A finding is `confirmed` only when a test or a request showed it twice, from reset state. What rests on reading code is `judged`, and says so. A model rereading its own finding is not verification.
- **Coverage is checked, not assumed.** The gap analysis lists every file and every entry point and refuses to finish while one is unread or unplaced. The DAST runner reports every route without a case and every case that did not run.
- **Measured before kept.** Changes are driven by blind runs against a test application with an answer key, compared with the same model without the skill. See [evaluation](docs/evaluation.md), including where the skills do not yet beat the bare model.
- **Small, bounded tools.** The runner sends only the requests its plan lists, to 127.0.0.1 or to one pre-production host named on the command line, with a request budget, a time limit and no redirects followed. Python standard library only.
- **Test first.** Every behaviour of the scripts has a test that failed before the code was written.

## security-gap-analysis

Use it to find controls that are missing rather than bugs in code that exists. It models the product, selects OWASP ASVS 5.0, AISVS 1.0 for LLM, agent, RAG and MCP features, and MASVS 2.1 for mobile apps, then records a status with `file:line` evidence for each requirement in the target repository's `security/` folder. Every file is listed and must be read, skimmed or skipped with a reason, and a fixed-pattern inventory of the ways in (servers, routes and serverless handlers, command lines, IPC, uploads, file paths), the effects outside the program (processes, network calls, data stores, model calls), the build and release pipeline, and the dangerous sinks must be placed in the profile or explained. A file that changes reopens itself and the rows that cite it. It also proposes an access policy (role × route × action) for the owner to confirm, which local-dast then tests. The requirement catalogs are bundled; `scripts/build_catalogs.py` rebuilds them from the pinned sources.

## local-dast

Use it to test a running application. The agent starts a disposable copy on 127.0.0.1 with synthetic data and outbound network denied, writes a plan of cases from the code (who may read, list, change and delete what), and `dast.py` sends exactly those requests, checks each response against its assertion and has ZAP read the recorded traffic passively.

A case can sign in and keep its session as a cookie or a bearer token, send JSON, form and multipart bodies, take a value from an answer (a JSON field, a header, a cookie, a regular expression over the page, or part of a link) and use it in a later path, header, body or assertion, compare two answers, and assert on response headers. State-changing cases run only with `--allow-writes`. `--only <case>` reruns a failed case with everything it rests on, for the reproduction a `confirmed` verdict needs. The skill lists the cases for apps that take bearer tokens from an identity provider or serve an MCP endpoint, and for injection through sort and filter parameters, stored markup, redirects, CORS, CSRF, password reset and server-side fetches.

It needs Python 3.10+, Java 17+ and the pinned ZAP archive, downloaded once as [its setup](skills/local-dast/references/setup.md) describes; ZAP is not bundled. It does not crawl, drive a browser or scan actively. In remote mode (`--remote https://<host>`) the same runner tests one pre-production host that you name yourself, over verified HTTPS, and never production. The wider design is in [the DAST proposal](docs/agent-powered-dast.md).

## Security gate

Coding agents tend to weaken the checks they can see and to install packages that do not exist. The security gate is a set of Claude Code hooks in [hooks/hooks.json](hooks/hooks.json) that run [hooks/security_gate.py](hooks/security_gate.py) (Python 3.9+, standard library only). Claude Code runs it on every matching tool call, so the agent cannot choose to skip it. It runs only when this repository is enabled as a Claude Code plugin.

- Before an edit, it asks you to approve when the edit adds a suppression marker (`# nosec`, `nosemgrep`, `eslint-disable`, `# noqa: S…`, `NOSONAR`), lowers the number of assertions in a test file, adds a skip or only marker, empties a test file, or writes under `tests/security/`, `.github/workflows/` or a scanner's configuration.
- Before a command that installs named packages with pip, uv, poetry, npm, pnpm, yarn or bun, it looks each name up on PyPI or npm. It refuses a name that does not exist and asks about one first published less than 30 days ago. Only the package name is sent.
- When the session stops, it blocks the stop once if the session edited a file that has a `confirmed` row in `security/findings.csv`, and asks the agent to run that finding's proof again.

Any error in the gate lets the tool run. `AGENT_TOOLS_SECURITY_GATE=off` turns it off.

## How the skills share work

Each skill makes its own findings first. They share two things only: before the work, the facts in `security/profile.md` and the inventory (what the product is, not anyone's verdict); after the work, the findings ledger `security/findings.csv`, which a skill opens only when it delivers, to say whether a finding is new, seen before, changed, or decided by you. A label never changes a verdict. The `security/` folder holds a fixed set of files and is kept out of commits through `.git/info/exclude` unless you track it yourself.

Not covered here: crawling, browser journeys and active scanning, scanner-based SAST, dependency and secret scanning, cloud configuration that is not reachable over HTTP, and standards that are not bundled (CIS, PCI DSS, ISO 27001, SOC 2).

## Install

Copy the skill folders you want into your agent's skill directory (`~/.claude/skills/<name>` for Claude Code, `~/.agents/skills/<name>` for Codex), or enable the repository as a Claude Code plugin to get the security gate as well. Each skill is self-contained.

## Verification

```sh
python3 scripts/validate_package.py
python3 -m unittest discover -s test -v
```

Tests that need ZAP, Java or `openssl` skip themselves when the tool is missing and say so.

## Sources and licence

The code is MIT-licensed ([LICENSE](LICENSE)). The bundled OWASP catalogs are CC BY-SA 4.0; see [SOURCES.md](SOURCES.md).
