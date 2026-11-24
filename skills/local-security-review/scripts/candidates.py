#!/usr/bin/env python3
"""List a scan's candidates compactly: one line per rule with its count and severity, most severe first, and a few places.

  candidates.py <report.json> [--rule RULE] [--all] [--places N]

Read this instead of report.json: on a large repository the report holds thousands of candidates, and reading it whole
fills the reviewer's context with what one line per rule says. `--rule` lists one rule; `--all` shows every place.
"""
import argparse
import collections
import json
import sys
from pathlib import Path

RANK = {"CRITICAL": 0, "ERROR": 1, "HIGH": 1, "MEDIUM": 2, "WARNING": 2, "MODERATE": 2, "LOW": 3, "INFO": 4}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", type=Path)
    parser.add_argument("--rule", help="only this rule")
    parser.add_argument("--all", action="store_true", help="every place, not the first few")
    parser.add_argument("--places", type=int, default=5, help="places shown per rule without --all")
    args = parser.parse_args(argv)
    findings = [f for f in json.loads(args.report.read_text()).get("findings", []) if not f.get("duplicate_of")]
    groups = collections.defaultdict(list)
    for f in findings:
        if not args.rule or f.get("rule") == args.rule:
            groups[f.get("rule") or "?"].append(f)

    def severity(items):
        return min((RANK.get(str(f.get("scanner_severity", "")).upper(), 5) for f in items), default=5)

    print(f"{len(findings)} candidates, {len(groups)} rules" + (f"; rule {args.rule}" if args.rule else ""))
    for rule, items in sorted(groups.items(), key=lambda kv: (severity(kv[1]), -len(kv[1]), kv[0])):
        top = min(items, key=lambda f: RANK.get(str(f.get("scanner_severity", "")).upper(), 5))
        print(f"{rule}  {len(items)}  {top.get('scanner_severity', '?')}")
        shown = items if args.all else items[:args.places]
        for f in shown:
            package = (f.get("metadata") or {}).get("package")
            print(f"  {f['id']} {f.get('path')}:{f.get('line')}" + (f"  {package}" if package else ""))
        if len(items) > len(shown):
            print(f"  and {len(items) - len(shown)} more (--rule {rule} --all)")
    return 0


if __name__ == "__main__":
    __import__("_python").ensure()  # Python 3.10+ even when python3 is 3.9
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # `| head` stops reading; end quietly as other filters do
    sys.exit(main())
