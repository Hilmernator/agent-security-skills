#!/usr/bin/env python3
"""List the places a hunt must decide on one by one: where the server connects to an address, unpacks or decodes
something it was sent, writes raw HTML, or reads a security setting's default.

  sinks.py <repository-root> [--kind KIND] [--all] [--places N]

Scanners flag a pattern when its input looks tainted; most request forgery, decompression and unescaped-output flaws in
reviews were at places like these where no scanner fired, because the address or the size came from stored data or a
setting. This list is the hunt's checklist for those classes: each place gets a line in context.md saying who controls
the address, size or markup and what guards it. Test code, vendored code and minified bundles are left out.
"""
import argparse
import collections
import os
import re
import sys
from pathlib import Path

KINDS = {
    "outbound": ("the server connects to an address: who sets it, and is it checked against loopback, private and "
                 "metadata addresses when saved and when connected?", [
        r"(?<![.\w])requests\.(get|post|put|patch|delete|head|request|Session)\b", r"\bhttpx\.(get|post|put|request|Client|AsyncClient)\b",
        r"\baiohttp\.ClientSession\b", r"\burlopen\(", r"\burllib3\.PoolManager\b", r"\bendpoint_url\s*=",
        r"\bboto3\.(client|resource|session)\b", r"\b(Strict)?Redis\(|\bredis\.from_url\(", r"\bsocket\.create_connection\(",
        r"\bsmtplib\.SMTP", r"\bapprise\b", r"\bldap\.initialize\(|\bServer\(\s*[a-z_]+", r"\bpymongo\.MongoClient\(",
        r"\bfetch\(\s*[a-zA-Z_`$]", r"\baxios(\.(get|post|put|request))?\(\s*(?![\"'`]/)[\w`\"']", r"\bgot(\.(get|post))?\(\s*[a-zA-Z_`]",
        r"\bhttps?\.(get|request)\(", r"\bnew WebSocket\(", r"\bhttp\.(Get|Post|NewRequest(WithContext)?)\(",
        r"\bnet\.Dial(Timeout)?\(", r"\breqwest::", r"\bureq::", r"\bClient::new\(\)", r"\bTcpStream::connect\(",
        r"\bgit\.(Clone|clone_from|Repo\.clone_from)\b", r"\bdownload\w*\(\s*(url|uri|link)",
    ]),
    "unpack": ("something the server was sent is unpacked or decoded: is its size, count and output size limited "
               "before it is read, and do archive entries stay inside the target folder?", [
        r"\bZipFile\(", r"\.extractall\(", r"\btarfile\.open\(", r"\bgzip\.(open|decompress|GzipFile)\b",
        r"\bzlib\.decompress", r"\bbz2\.(open|decompress)", r"\blzma\.(open|decompress)", r"\bpy7zr\b", r"\bshutil\.unpack_archive\(",
        r"\bImage\.open\(", r"\bjson\.loads?\(\s*(request|await|body|data)", r"\byaml\.(load|safe_load)\(",
        r"\bAdmZip\b", r"\bunzipper\b", r"\btar\.(x|extract)\(", r"\bzlib\.(gunzip|inflate)", r"\bzip\.(OpenReader|NewReader)\(",
        r"\bgzip\.NewReader\(", r"\bflate2::", r"\bzip::ZipArchive\b",
    ]),
    "raw-html": ("markup is written without escaping: can a user put text here, and is it sanitized with an allowlist?", [
        r"\|\s*safe\b", r"\bmark_safe\(", r"\bMarkup\(", r"autoescape\s+(false|off)", r"\bv-html\b",
        r"\bdangerouslySetInnerHTML\b", r"\.(inner|outer)HTML\s*=", r"\binsertAdjacentHTML\(", r"\bdocument\.write\(",
        r"\brehype-raw\b|\brehypeRaw\b", r"\{\{\{", r"<%-", r"\bhtml\.unescape\(", r"\bformat_html\(", r"\bjinja2\.(Template|Environment)\(|\bTemplate\(\s*[a-z_]",
        r"<script[^>]*>\s*\{|</script>.*\bjson\.dumps|\bjson\.dumps\(.*</script>",
    ]),
    "serve-file": ("a stored or uploaded file is sent back: is a type the browser runs (HTML, SVG, XML) sent inline from "
                   "the app's own origin, and is the path checked against the caller's access?", [
        r"\bFileResponse\(", r"\bRangedFileResponse\(", r"\bsend_file\(", r"\bsend_from_directory\(", r"\bStreamingResponse\(",
        r"Content-Disposition.*inline", r"\bres\.(sendFile|download)\(", r"\bhttp\.ServeFile\(", r"\bX-Accel-Redirect\b",
    ]),
    "setting": ("a security setting and its default: is the protection on unless an operator turns it off?", [
        r"\b[A-Z0-9_]*(SSRF|ALLOW|BLOCK|VERIFY|PROTECT|SECURE|CSRF|CORS|DEBUG|SANDBOX|INSECURE|DISABLE|ENABLE|SIGNUP|"
        r"REGISTRATION|PUBLIC|TRUST)[A-Z0-9_]*\s*[:=]\s*.*\b(True|False|true|false|0|1|None)\b",
    ]),
}
SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "dist", "build", ".venv", "venv", "__pycache__", "target",
             "coverage", ".next", ".nuxt", "security", "migrations", "docs", "examples"}
TEST = re.compile(r"(^|/)(tests?|__tests__|spec|e2e|fixtures?|testdata)(/|$)|(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(test|spec)\.\w+|conftest\.py)$")
SOURCE = {".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".go", ".rs", ".rb", ".php", ".java", ".kt", ".html",
          ".jinja", ".j2", ".hbs", ".ejs", ".erb"}
SETTINGS = re.compile(r"(settings|config|conf|constants|defaults|env)[^/]*\.\w+$|(^|/)(settings|config)/", re.I)


def places(root):
    found = collections.defaultdict(list)
    compiled = {k: re.compile("|".join(f"(?:{p})" for p in pats)) for k, (_, pats) in KINDS.items()}
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            path = Path(folder, name)
            rel = path.relative_to(root).as_posix()
            if path.suffix not in SOURCE or TEST.search(rel) or name.endswith((".min.js", ".bundle.js")):
                continue
            try:
                lines = path.read_text(errors="replace").splitlines()
            except OSError:
                continue
            if any(len(line) > 1000 for line in lines[:5]):
                continue  # generated or minified
            for number, line in enumerate(lines, 1):
                for kind, pattern in compiled.items():
                    if kind == "setting" and not SETTINGS.search(rel):
                        continue
                    if pattern.search(line) and not line.lstrip().startswith(("#", "//", "*", "import ", "from ")):
                        found[kind].append((rel, number, line.strip()[:120]))
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", type=Path)
    parser.add_argument("--kind", choices=sorted(KINDS))
    parser.add_argument("--all", action="store_true", help="every place, not the first few per file")
    parser.add_argument("--places", type=int, default=40, help="places shown per kind without --all")
    args = parser.parse_args(argv)
    found = places(args.root.resolve())
    for kind, (question, _) in KINDS.items():
        if args.kind and kind != args.kind:
            continue
        items = found.get(kind, [])
        print(f"== {kind}: {len(items)} places in {len({p for p, _, _ in items})} files. {question}")
        shown = items if args.all or args.kind else items[:args.places]
        for rel, number, text in shown:
            print(f"  {rel}:{number}  {text}")
        if len(items) > len(shown):
            print(f"  and {len(items) - len(shown)} more (--kind {kind})")
    return 0


if __name__ == "__main__":
    __import__("_python").ensure()  # Python 3.10+ even when python3 is 3.9
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sys.exit(main())
