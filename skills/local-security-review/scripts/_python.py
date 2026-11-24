"""Run the skill's scripts on Python 3.10+ when `python3` is older (it is 3.9 on a stock Mac).

Every entry script calls ensure() first. On an older interpreter it finds a newer one (python3.14 down to python3.10
on PATH, else `uv python find`) and replaces the process with it, same arguments. If none is found it returns, and
`security.py --check` reports the interpreter as incompatible as before.
"""
import os
import shutil
import subprocess
import sys

MINIMUM = (3, 10)
NAMES = ("python3.14", "python3.13", "python3.12", "python3.11", "python3.10")


def _version(path):
    try:
        out = subprocess.run([path, "-c", "import sys; print(*sys.version_info[:2])"], capture_output=True, text=True, timeout=10)
        return tuple(int(n) for n in out.stdout.split())
    except (OSError, ValueError, subprocess.SubprocessError):
        return ()


def _uv_find():
    if not shutil.which("uv"):
        return None
    try:
        out = subprocess.run(["uv", "python", "find", "--no-project", ">=3.10"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    path = out.stdout.strip()
    return path if out.returncode == 0 and path and _version(path) >= MINIMUM else None


def ensure(argv=None):
    if tuple(sys.version_info[:2]) >= MINIMUM:
        return
    argv = list(sys.argv if argv is None else argv)
    found = next((path for path in map(shutil.which, NAMES) if path and _version(path) >= MINIMUM), None) or _uv_find()
    if found:
        os.execv(found, [found, *argv])
