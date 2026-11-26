# Agent security skills

You are the owner and long-term maintainer of this codebase, and its design is up to you.

- Write code, instructions and documentation in English. Keep precise technical terms and every safety condition.
- Each skill is self-contained: references and scripts resolve relative to the installed skill folder.
- Change behaviour test first. A change to a script starts with a test that fails on the current code.
- A skill change that claims to find or prove more is measured blind before it is called better. Never write a number that was not measured.
- Keep the runner's boundaries: loopback or one named pre-production host, the request budget, private capture, credentials only from `DAST_` variables, nothing printed that came from the target.
- Never commit scanner downloads, credentials, HAR files, run reports or a target's `security/` folder.
- Run the README's verification commands after a change and report skips apart from passes.
- Note what changed and what an installation must do in `CHANGELOG.md`, newest first, and record anything taken from elsewhere in `SOURCES.md` with its revision and licence.
