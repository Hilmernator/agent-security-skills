#!/usr/bin/env python3
"""Run a finding's proof test twice, each time in a fresh copy of the prepared copy, and record the outcome in proofs.json.

The agent writes the test; this script decides whether it proves anything. A proof counts only when both
runs fail and both outputs contain the marker, a text that appears in the test's assertion message and
nowhere in the command, so a crash or a missing file does not pass for a crossed boundary.
render_review.py reads proofs.json beside the report and gives `confirmed` only to IDs proven here.

  prove.py <report.json> <ID> --copy <dir> --test <path in copy> --expect <marker> -- <command ...>
"""
import argparse
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys

from render_review import proven, write_private


def overlaps(a, b):
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", type=Path)
    parser.add_argument("id")
    parser.add_argument("--copy", type=Path, required=True, help="temporary copy of the repository; the command runs here")
    parser.add_argument("--test", required=True, help="the proof test, relative to the copy")
    parser.add_argument("--expect", required=True, help="marker from the test's assertion message")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--same-copy", action="store_true",
                        help="run both attempts in the copy itself instead of a fresh copy each (for a copy too large to duplicate)")
    parser.add_argument("--reset", help="with --same-copy: how the state of the first attempt is undone before the second")
    argv = sys.argv[1:] if argv is None else list(argv)
    split = argv.index("--") if "--" in argv else len(argv)
    args, command = parser.parse_args(argv[:split]), argv[split + 1:]
    copy = args.copy.resolve()
    target = Path(json.loads(args.report.read_text())["target"]).resolve()
    test = (copy / args.test).resolve()
    if not command:
        parser.error("give the test command after --")
    if overlaps(copy, target):
        parser.error("--copy overlaps the reviewed repository; prove only in a temporary copy")
    if not test.is_relative_to(copy) or not test.is_file():
        parser.error("--test must name a file inside the copy")
    if not args.expect.strip() or args.expect not in test.read_text(errors="replace") or any(args.expect in part for part in command):
        parser.error("--expect must appear in the test file and not in the command")
    if args.same_copy and not (args.reset or "").strip():
        parser.error("--same-copy needs --reset saying how the first attempt's state is undone")

    runs = []
    for _ in range(2):
        # Each attempt starts from the prepared copy, so nothing the first attempt left (files, a database) decides the second.
        with tempfile.TemporaryDirectory() as scratch:
            where = copy if args.same_copy else Path(scratch) / "attempt"
            if not args.same_copy:
                shutil.copytree(copy, where, symlinks=True)
            argv = [part.replace(str(copy), str(where)) for part in command]
            try:
                done = subprocess.run(argv, cwd=where, capture_output=True, text=True, errors="replace",
                                      stdin=subprocess.DEVNULL, timeout=args.timeout)
                runs.append({"exit": done.returncode, "marker": args.expect in done.stdout + done.stderr})
            except subprocess.TimeoutExpired:
                runs.append({"exit": None, "marker": False})
    isolation = f"same copy; reset: {args.reset.strip()}" if args.same_copy else "fresh copy of the prepared copy for each attempt"
    record = {"test": args.test, "command": command, "expect": args.expect, "runs": runs, "isolation": isolation,
              "date": datetime.date.today().isoformat(), "source": test.read_text(errors="replace")}
    path = args.report.parent / "proofs.json"
    proofs = json.loads(path.read_text()) if path.is_file() else {}
    proofs[args.id] = record  # the latest attempt counts, so a stale success never outlives a failed rerun
    write_private(path, json.dumps(proofs, indent=2) + "\n")
    print(json.dumps({"id": args.id, "proven": proven(record), "runs": runs}))
    return 0 if proven(record) else 1


if __name__ == "__main__":
    __import__("_python").ensure()  # Python 3.10+ even when python3 is 3.9
    sys.exit(main())
