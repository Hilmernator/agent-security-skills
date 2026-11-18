"""Check the package without network access: manifests agree, every skill has its frontmatter, local links resolve, hook scripts exist."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = {"local-dast", "local-security-review", "security-gap-analysis"}


def problems(root):
    found = []
    manifest = json.loads((root / "plugin.json").read_text())
    if not re.fullmatch(r"\d+\.\d+\.\d+", manifest.get("version", "")):
        found.append("plugin.json: version is not MAJOR.MINOR.PATCH")
    for host in (".claude-plugin", ".codex-plugin"):
        overlay = json.loads((root / host / "plugin.json").read_text())
        found += [f"{host}/plugin.json: {key} differs from plugin.json" for key in ("name", "version", "description", "author") if overlay.get(key) != manifest.get(key)]
    present = {path.parent.name for path in (root / "skills").glob("*/SKILL.md")}
    if present != SKILLS:
        found.append(f"skills/: expected {sorted(SKILLS)}, found {sorted(present)}")
    for name in present:
        head = (root / "skills" / name / "SKILL.md").read_text().split("---")[1]
        if not re.search(rf"^name: {re.escape(name)}$", head, re.M) or not re.search(r"^description: \S", head, re.M):
            found.append(f"skills/{name}/SKILL.md: frontmatter needs name: {name} and a description")
    for path in root.rglob("*.md"):
        if ".git" in path.parts:
            continue
        text = path.read_text()
        if "/Users/" in text:
            found.append(f"{path.relative_to(root)}: machine-specific path")
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            local = target.split("#")[0]
            if local and not re.match(r"[a-z][a-z0-9+.-]*:", local) and not (path.parent / local).exists():
                found.append(f"{path.relative_to(root)}: broken link {target}")
    first = (root / "skills/local-dast/scripts/ledger.py").read_bytes()
    if first != (root / "skills/local-security-review/scripts/ledger.py").read_bytes():
        found.append("ledger.py differs between local-dast and local-security-review")
    for groups in json.loads((root / "hooks/hooks.json").read_text())["hooks"].values():
        for hook in (hook for group in groups for hook in group["hooks"]):
            found += [f"hooks.json: missing {script}" for script in re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\"\s]+)", hook["command"]) if not (root / script).is_file()]
    return found


if __name__ == "__main__":
    found = problems(ROOT)
    for problem in found:
        print("problem: " + problem)
    print(f"Package {'invalid' if found else 'valid'}: {len(SKILLS)} skills, manifests, links and hook scripts checked.")
    sys.exit(1 if found else 0)
