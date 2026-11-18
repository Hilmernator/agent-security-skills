# Catalog notice

The JSON files in this folder contain requirement text from OWASP standards, reformatted from the
pinned sources named in each file (`source`, `revision`). The text is unchanged.

- OWASP Application Security Verification Standard 5.0.0
- OWASP Artificial Intelligence Security Verification Standard 1.01
- OWASP Mobile Application Security Verification Standard 2.1.0

Copyright OWASP Foundation and the contributors to each standard. Licensed under Creative Commons
Attribution-ShareAlike 4.0 International: https://creativecommons.org/licenses/by-sa/4.0/. These
reformatted catalogs are shared under the same license. `scripts/build_catalogs.py` reproduces them.

`cicd.json` and `design.json` are not OWASP text. `design.json` was written for this skill under the repository's MIT licence; its chapters are the categories of the CWE view 1008, Architectural Concepts (MITRE), and each section names the NIST SP 800-53 Rev. 5 SA-8 principle it applies; no text of either is copied.

`cicd.json` is not OWASP text either. Its requirements were written for this skill under the repository's MIT licence; only its chapters follow the risk list of the OWASP Top 10 CI/CD Security Risks, and `build_catalogs.py` does not touch it.
