"""The security folder as one HTML page: what is assessed, which controls are in place and where, what is missing.

Called as `gap.py report REPO [--out FILE]`. It reads the files of security/ and the bundled catalogs, runs the
same gate as `gap.py check --complete`, and writes one self-contained page: no network, no external file, every
text from the repository escaped. The page is a view of the folder, not state, so it is written outside it (by
default to the temporary folder) and can be made again at any time.
"""
import contextlib
import datetime
import html
import io
import json
import re
from pathlib import Path

import gap

# Requirement statuses in reading order: what is in place, what is weak, what is absent, then what the code cannot show.
ORDER = ["met", "partial", "missing", "unverifiable", "risk-accepted", "not-applicable", "unassessed"]
LABEL = {"met": "Met", "partial": "Partial", "missing": "Missing", "unverifiable": "Check outside the code",
         "risk-accepted": "Risk accepted", "not-applicable": "Not applicable", "unassessed": "Not assessed"}
ICON = {"met": "✓", "partial": "◐", "missing": "✕", "unverifiable": "?", "risk-accepted": "≈", "not-applicable": "–",
        "unassessed": "·", "holds": "✓", "broken": "✕", "high": "▲", "medium": "■", "low": "▼", "unrated": "·"}
APPLY = [s for s in ORDER if s != "not-applicable"]  # a chapter's bar shows what applies; the rest is a count in the table view
INVARIANT_ORDER = ["holds", "partial", "broken", "unverifiable"]
RISKS = ["high", "medium", "low", "unrated"]
RISK_WORDS = {"high": r"high|critical", "medium": r"medium|moderate", "low": r"low"}
FILE_ORDER = ["read", "skimmed", "skipped", "unread"]
INV_ORDER = ["boundary", "internal", "test", "unreviewed"]
ID = re.compile(r"(?<![\w.:/-])((?:asvs|aisvs|aisvs-ac|masvs|cicd|design):[\w.-]*\w|V\d+(?:\.\d+){1,2}|I\d+|P\d+"
                r"|MASVS-[A-Z]+-\d+|[A-C]\d+\.\d+|AC\.\d+(?:\.\d+)*|C\d+(?:\.\d+)?)(?![\w])")


def esc(text) -> str:
    return html.escape(str(text), quote=True)


# --- Reading the folder -----------------------------------------------------------------------------------------

def gate(repo: Path) -> dict:
    """The result of `gap.py check --complete`, as the page states it."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = gap.check(type("Args", (), {"repo": str(repo), "complete": True})())
    lines = out.getvalue().splitlines()
    return {"passes": code == 0, "problems": [line[len("problem: "):] for line in lines if line.startswith("problem: ")],
            "coverage": next((line for line in lines if line.startswith("files: ")), "")}


def table(section: str) -> list[list[str]]:
    return [[c.strip() for c in line.strip().strip("|").split("|")] for line in section.splitlines() if line.lstrip().startswith("|")]


def section(text: str, heading: str) -> str:
    m = re.search(rf"^## {heading}[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m[1] if m else ""


def risk_of(heading: str, body: str) -> str:
    for line in [heading, *re.findall(r"^\W*(?:\*\*)?risk(?:\*\*)?\s*:?\s*(?:\*\*)?\s*(\w+)", body, re.I | re.M)]:
        for risk, words in RISK_WORDS.items():
            if re.search(rf"(^|[^\w])({words})([^\w]|$)", line.split(":")[-1] if line is heading else line, re.I):
                return risk
    return "unrated"


def gaps(text: str) -> tuple[str, list[dict], list[tuple[str, str]]]:
    """gaps.md as its summary, its entries (heading, risk, body) and its closing sections (Check outside the code, Not covered)."""
    parts = re.split(r"^(?=## (?!#))", text, flags=re.M)
    summary, entries, closing = re.sub(r"^# .*\n", "", parts[0], count=1), [], []
    for part in parts[1:]:
        heading, _, body = part.partition("\n")
        heading = heading[3:].strip()
        if re.match(r"(check outside the code|not covered)", heading, re.I):
            closing.append((heading, body))
        else:
            entries.append({"heading": heading, "risk": risk_of(heading, body), "body": body})
    return summary, entries, closing


def collect(repo: Path) -> dict:
    sec = repo / "security"
    read = lambda name: (sec / name).read_text(errors="replace") if (sec / name).exists() else ""
    cats = gap.catalogs()
    rows = gap.load(repo)
    for r in rows:
        entry = cats.get(r["standard"], {}).get(r["id"], {})
        r["text"], r["chapter"], r["section"] = entry.get("text", ""), entry.get("chapter", "?"), entry.get("section", "")
    chapters: dict = {}
    for r in rows:
        chapters.setdefault((r["standard"], r["chapter"]), {s: 0 for s in ORDER})[r["status"]] += 1
    profile = read("profile.md")
    rules, _, _ = gap.invariants(profile)
    policy = table(section(profile, "Access policy"))
    files = gap.read_csv(gap.files_path(repo), gap.FILE_FIELDS) or []
    inventory = gap.read_csv(gap.inventory_path(repo), gap.INV_FIELDS) or []
    summary, entries, closing = gaps(read("gaps.md"))
    levels: dict = {}
    for r in rows:
        levels[r["standard"]] = max(levels.get(r["standard"], 0), int(r["level"] or 0))
    return {"repo": repo, "name": repo.resolve().name, "revision": gap.revision(repo), "rows": rows,
            "chapters": chapters, "profile": profile, "invariants": rules or [], "policy": policy,
            "policy_status": (re.search(r"^Status: (.*)$", section(profile, "Access policy"), re.M) or [None, ""])[1],
            "files": files, "inventory": inventory, "summary": summary, "entries": entries, "closing": closing,
            "accepted": read("accepted-risks.md"), "gate": gate(repo), "levels": levels,
            "questions": [q | {"state": gap.question_state(repo, q, rows), "digest": gap.question_digest(repo, q, rows)}
                          for q in gap.load_questions(repo)]}


def probe_result(cell: str) -> str:
    if cell.startswith("no test fails"):
        return "unnoticed"
    if cell.startswith("fails without"):
        return "noticed"
    return "not probed"


# --- Markdown, enough for profile.md and gaps.md ------------------------------------------------------------------

def inline(text: str, ids: dict) -> str:
    """Escape, then code spans, bold, links shown as text, and known IDs as links into the page."""
    out = []
    for i, piece in enumerate(re.split(r"(`[^`]*`)", text)):
        if i % 2:
            out.append(f"<code>{esc(piece[1:-1])}</code>")
            continue
        piece = esc(piece)
        piece = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", piece)
        piece = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<span class="link" title="\2">\1</span>', piece)
        out.append(ID.sub(lambda m: link(m[1], ids), piece))
    return "".join(out)


def anchor(key: str) -> str:
    if key.startswith(("I", "P")) and key[1:].isdigit():
        return ("inv-" if key[0] == "I" else "policy-") + key
    standard, _, rid = key.partition(":")
    return f"req-{standard}-{rid}"


def link(key: str, ids: dict) -> str:
    return f'<a href="#{esc(ids[key])}">{key}</a>' if key in ids else key


def markdown(text: str, ids: dict) -> str:
    out, para, lst, rows, code = [], [], None, [], None

    def flush():
        nonlocal para, lst, rows
        if para:
            out.append(f"<p>{inline(' '.join(para), ids)}</p>")
        if lst:
            tag = lst[0]
            out.append(f"<{tag}>" + "".join(f"<li>{inline(item, ids)}</li>" for item in lst[1]) + f"</{tag}>")
        if rows:
            cells = [r for r in rows if not re.fullmatch(r"[\s|:-]+", "|".join(r))]
            head, body = cells[0], cells[1:]
            out.append('<div class="scroll"><table class="md"><thead><tr>' + "".join(f"<th>{inline(c, ids)}</th>" for c in head)
                       + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{inline(c, ids)}</td>" for c in r) + "</tr>"
                                                         for r in body) + "</tbody></table></div>")
        para, lst, rows = [], None, []

    for line in text.splitlines():
        if code is not None:
            if line.strip().startswith("```"):
                out.append(f"<pre><code>{esc(chr(10).join(code))}</code></pre>")
                code = None
            else:
                code.append(line)
            continue
        if line.strip().startswith("```"):
            flush()
            code = []
        elif not line.strip():
            flush()
        elif m := re.match(r"^(#{1,6})\s+(.*)", line):
            flush()
            level = min(len(m[1]) + 2, 6)
            out.append(f"<h{level}>{inline(m[2], ids)}</h{level}>")
        elif line.lstrip().startswith("|"):
            if para or lst:
                flush()
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
        elif m := re.match(r"^\s*([-*+]|\d+[.)])\s+(.*)", line):
            tag = "ol" if m[1][0].isdigit() else "ul"
            if para or rows or (lst and lst[0] != tag):
                flush()
            lst = lst or (tag, [])
            if line.startswith(("  ", "\t")) and lst[1]:
                lst[1][-1] += " · " + m[2]  # ponytail: nested items fold into their parent; a tree renderer if gaps.md nests deeply
            else:
                lst[1].append(m[2])
        elif lst and line.startswith((" ", "\t")):
            lst[1][-1] += " " + line.strip()
        else:
            if lst or rows:
                flush()
            para.append(line.strip())
    if code is not None:
        out.append(f"<pre><code>{esc(chr(10).join(code))}</code></pre>")
    flush()
    return "\n".join(out)


# --- Pieces of the page ------------------------------------------------------------------------------------------

def badge(kind: str, text: str | None = None) -> str:
    return f'<span class="badge {esc(kind)}">{ICON.get(kind, "")} {esc(text or LABEL.get(kind, kind))}</span>'


def segmented(counts: dict, order: list[str], name: str, tall: bool = False, labels: dict | None = None) -> str:
    """One whole split into parts: a bar of blocks, each part its own block, with its name, count and share on hover."""
    total = sum(counts.get(k, 0) for k in order)
    if not total:
        return '<div class="bar empty">nothing yet</div>'
    blocks = []
    for k in order:
        n = counts.get(k, 0)
        if not n:
            continue
        share = 100 * n / total
        tip = f"{(labels or LABEL).get(k, k)}: {n} of {total} ({share:.0f} %)"
        text = f"{n}" if tall and share >= 6 else ""
        blocks.append(f'<span class="seg s-{esc(k)}" style="flex-grow:{n}" tabindex="0" data-tip="{esc(tip)}"'
                      f' aria-label="{esc(tip)}">{text}</span>')
    return f'<div class="bar{" tall" if tall else ""}" role="img" aria-label="{esc(name)}">{"".join(blocks)}</div>'


def legend(order: list[str], counts: dict | None = None, labels: dict | None = None) -> str:
    items = [k for k in order if counts is None or counts.get(k)]
    return '<ul class="legend">' + "".join(
        f'<li><span class="sw s-{esc(k)}"></span>{esc((labels or LABEL).get(k, k))}'
        + (f' <span class="num">{counts[k]}</span>' if counts else "") + "</li>" for k in items) + "</ul>"


def tile(value, label: str, note: str = "", kind: str = "") -> str:
    return (f'<div class="tile {esc(kind)}"><div class="value">{esc(value)}</div><div class="label">{esc(label)}</div>'
            + (f'<div class="note">{esc(note)}</div>' if note else "") + "</div>")


def evidence(cell: str) -> str:
    items = [e.strip() for e in re.split(r";", cell.removeprefix("partial:")) if e.strip()]
    return " ".join(f"<code>{esc(e)}</code>" for e in items)


def requirements_section(d: dict, ids: dict) -> str:
    rows = d["rows"]
    out = ['<section id="requirements"><h2>Requirements by chapter</h2>',
           '<p class="lede">Each bar is one chapter of a selected standard, made of the requirements that apply to this product: '
           'how many the code meets, meets in part or lacks. The count is met of those that apply. Hover a block for its count.</p>',
           legend(APPLY, {s: sum(r["status"] == s for r in rows) for s in APPLY})]
    for standard in sorted({r["standard"] for r in rows}):
        out.append(f'<h3>{esc(standard.upper())} <span class="muted">level {d["levels"].get(standard, "?")}</span></h3><div class="chapters">')
        chapters = sorted(((c, n) for (s, c), n in d["chapters"].items() if s == standard), key=lambda kv: gap.natural(kv[0]))
        for chapter, counts in chapters:
            total = sum(counts.values())
            applies = total - counts["not-applicable"]
            bar = segmented(counts, APPLY, chapter) if applies else '<div class="bar none">not applicable</div>'
            out.append(f'<div class="chapter{"" if applies else " na"}"><div class="name" title="{esc(chapter)}">{esc(chapter)}</div>'
                       f'{bar}<div class="count">{counts["met"]}/{applies or "–"}</div></div>')
        out.append("</div>")
    head = "".join(f"<th>{esc(LABEL[s])}</th>" for s in ORDER)
    body = "".join(f'<tr><td>{esc(s)}</td><td>{esc(c)}</td>' + "".join(f"<td>{n[k]}</td>" for k in ORDER) + "</tr>"
                   for (s, c), n in sorted(d["chapters"].items(), key=lambda kv: (kv[0][0], gap.natural(kv[0][1]))))
    out.append(f'<details class="tableview"><summary>Table view</summary><div class="scroll"><table><thead><tr><th>Standard</th>'
               f'<th>Chapter</th>{head}</tr></thead><tbody>{body}</tbody></table></div></details></section>')
    return "\n".join(out)


def controls_section(d: dict, ids: dict) -> str:
    chips = "".join(f'<button type="button" class="chip" data-filter="{s}" aria-pressed="{"true" if s in ("met", "partial") else "false"}">'
                    f'<span class="sw s-{s}"></span>{esc(LABEL[s])} <span class="num">{sum(r["status"] == s for r in d["rows"])}</span></button>'
                    for s in ORDER if any(r["status"] == s for r in d["rows"]))
    asked = {}
    for q in d["questions"]:
        for key in q["requirements"].split():
            asked.setdefault(key, []).append(q)
    waiting = sum(1 for qs in asked.values() if any(q["state"] in ("open", "review") for q in qs))
    if asked:
        chips += (f'<button type="button" class="chip verify" data-filter="verify" aria-pressed="false">? Needs verification '
                  f'<span class="num">{waiting}</span></button>')
    body = []
    for r in sorted(d["rows"], key=lambda r: (r["standard"], gap.natural(r["id"]))):
        key = f'{r["standard"]}:{r["id"]}'
        notes = '<div class="notes">' + inline(r["notes"], ids) + "</div>" if r["notes"] else ""
        mine = asked.get(key, [])
        verify = ("open" if any(q["state"] == "open" for q in mine) else "review" if any(q["state"] == "review" for q in mine)
                  else "answered" if mine else "")
        notes += "".join(question_line(q) for q in mine)
        search = " ".join([key, r["chapter"], r["section"], r["text"], r["evidence"], r["notes"]] + [q["question"] for q in mine]).lower()
        body.append(f'<tr id="{esc(anchor(key))}" data-status="{esc(r["status"])}" data-verify="{verify}" data-search="{esc(search)}">'
                    f'<td>{badge(r["status"])}</td><td class="id">{esc(key)}<div class="muted small">{esc(r["chapter"])}'
                    f'{" › " + esc(r["section"]) if r["section"] else ""}</div></td>'
                    f'<td>{esc(r["text"])}{notes}</td>'
                    f'<td class="ev">{evidence(r["evidence"]) or "<span class=muted>–</span>"}</td></tr>')
    return (f'<section id="controls"><h2>Controls and requirements</h2><p class="lede">Every assessed requirement with the '
            f'lines that enforce it. It opens on the controls in place (met and partial); choose other statuses or search.</p>'
            f'<div class="filters"><input type="search" id="search" placeholder="Search id, text, file or note" aria-label="Search requirements">'
            f'<div class="chips" role="group" aria-label="Status">{chips}</div><span id="shown" class="muted small"></span></div>'
            f'<div class="scroll"><table class="reqs"><thead><tr><th>Status</th><th>Requirement</th><th>What it asks, and the assessor\'s note</th>'
            f'<th>Enforced at</th></tr></thead><tbody>{"".join(body)}</tbody></table></div></section>')


STATE_LABEL = {"open": "Needs verification", "review": "Answer to review", "yes": "Answered yes", "no": "Answered no"}
STATE_KIND = {"open": "unverifiable", "review": "partial", "yes": "met", "no": "missing"}


def provenance(q: dict, with_answer: bool = True) -> str:
    if not q["answer"]:
        return ""
    basis = gap.BASES.get(q["basis"], q["basis"])
    return ((f'{esc(q["answer"])} · ' if with_answer else "") + f'{esc(basis)} · {esc(q["answered_by"])}, {esc(q["answered_at"])}'
            + (f' · {esc(q["note"])}' if q["note"] else ""))


def question_line(q: dict) -> str:
    """A question in the row of a requirement it serves: what is still to be verified, by whom, and any answer so far."""
    who = esc(q["owner"]) + (f' ({esc(q["environment"])})' if q["environment"] else "")
    answer = f'<div class="muted small">Answer: {provenance(q)}</div>' if q["answer"] else ""
    return (f'<div class="ask s-border-{q["state"]}">{badge(STATE_KIND[q["state"]], STATE_LABEL[q["state"]])} '
            f'<a href="#question-{esc(q["id"])}">{esc(q["id"])}</a> {esc(q["question"])} <span class="muted small">Ask: {who}</span>{answer}</div>')


def questions_section(d: dict, ids: dict) -> str:
    qs = d["questions"]
    if not qs:
        return ""
    by_key = {f'{r["standard"]}:{r["id"]}': r for r in d["rows"]}
    counts = {k: sum(q["state"] == k for q in qs) for k in ("open", "review", "yes", "no")}
    labels = {"open": "Open", "review": "To review", "yes": "Yes", "no": "No"}
    cards = []
    for q in sorted(qs, key=lambda q: (["open", "review", "no", "yes"].index(q["state"]), gap.natural(q["id"]))):
        rows = "".join(f'<li>{link(k, ids)} {badge(by_key[k]["status"]) if k in by_key else ""} '
                       f'{evidence(by_key[k]["evidence"]) if k in by_key else ""}</li>' for k in q["requirements"].split())
        radios = "".join(f'<label><input type="radio" name="answer-{esc(q["id"])}" value="{v}"> {v.capitalize()}</label>'
                         for v in gap.ANSWERS)
        where = f' · {esc(q["environment"])}' if q["environment"] else ""
        said = {"yes": "met", "no": "missing"}.get(q["answer"], "unverifiable")
        recorded = (f'<p class="recorded">Recorded: {badge(said, "Answered " + q["answer"])} {provenance(q, with_answer=False)}'
                    + (" The question or the code it rests on changed since this answer; answer again." if q["state"] == "review" else "")
                    + "</p>") if q["answer"] else ""
        cards.append(f'<article class="question q-{q["state"]}" id="question-{esc(q["id"])}" data-id="{esc(q["id"])}" data-digest="{esc(q["digest"])}">'
                     f'<header><span class="id">{esc(q["id"])}</span> {badge(STATE_KIND[q["state"]], STATE_LABEL[q["state"]])}'
                     f'<span class="muted small">Ask: {esc(q["owner"])}{where}</span></header><h3>{esc(q["question"])}</h3>{recorded}'
                     f'<ul class="rows">{rows}</ul><fieldset><legend>Your answer</legend><div class="radios">{radios}</div>'
                     f'<input type="text" class="note" maxlength="500" placeholder="Short note or a reference to evidence (no secrets)" aria-label="Note for {esc(q["id"])}">'
                     f'</fieldset></article>')
    return (f'<section id="verification"><h2>Questions for owners</h2><p class="lede">What the code cannot show: each question asks '
            f'one fact someone outside the repository knows, and lists the requirements its answer settles with the evidence the code '
            f'already gives. An answer is recorded with who gave it, when and on what basis; an owner\'s word stays an owner statement, '
            f'apart from code and from configuration someone has seen. A no leaves the gap open; unknown keeps the question open.</p>'
            f'{segmented(counts, ["open", "review", "no", "yes"], "Questions by state", True, labels)}'
            f'{legend(["open", "review", "no", "yes"], counts, labels)}'
            f'<div class="answerbar"><label>Answered by <input type="text" id="answered-by" maxlength="120" placeholder="Name and role"></label>'
            f'<button type="button" id="export-answers">Export answers</button><span id="answer-count" class="muted small"></span></div>'
            f'<p class="muted small">Answers stay in this browser until exported. Import them with '
            f'<code>gap.py answer {esc(d["name"])} --from &lt;the exported file&gt;</code>, then make the page again.</p>'
            f'{"".join(cards)}</section>')


def invariants_section(d: dict, ids: dict) -> str:
    rules = d["invariants"]
    if not rules:
        return ('<section id="invariants"><h2>Security invariants</h2><p class="muted">profile.md has no Security invariants table, '
                'so the product\'s design rules were not stated or probed.</p></section>')
    states = {s: sum(r.get("Status") == s for r in rules) for s in INVARIANT_ORDER}
    probes = {p: sum(probe_result(r.get("Test", "")) == p for r in rules) for p in ("noticed", "unnoticed", "not probed")}
    probe_label = {"noticed": "A test notices", "unnoticed": "No test notices", "not probed": "Not probed"}
    body = []
    for r in rules:
        state, result = r.get("Status", ""), probe_result(r.get("Test", ""))
        test = {"noticed": badge("met", "a test fails"), "unnoticed": badge("missing", "no test fails"),
                "not probed": badge("unassessed", "not probed")}[result]
        enforced = r.get("Enforced at", "")
        body.append(f'<tr id="inv-{esc(r["ID"])}"><td class="id">{esc(r["ID"])}</td><td>{inline(r.get("Invariant", ""), ids)}'
                    f'<div class="muted small">{esc(r.get("Tactic", ""))}</div></td>'
                    f'<td>{badge(state if state in ICON else "unassessed", state)}</td>'
                    f'<td><span class="strength {esc(r.get("Strength", ""))}">{esc(r.get("Strength", ""))}</span></td>'
                    f'<td class="ev">{badge("missing", "no check found") if enforced == "no check found" else evidence(enforced)}</td>'
                    f'<td>{test}<div class="muted small">{esc(r.get("Test", "").removeprefix("not probed: "))}</div></td></tr>')
    return (f'<section id="invariants"><h2>Security invariants</h2><p class="lede">The product\'s own design rules, '
            f'where each is enforced, how strongly, and whether a test fails when the enforcement is switched off '
            f'(<code>gap.py probe</code>). A control no test notices can be removed by the next change without a red test.</p>'
            f'<div class="pair"><div><h3>Do they hold?</h3>{segmented(states, INVARIANT_ORDER, "Invariants by status", True, {s: s for s in INVARIANT_ORDER})}'
            f'{legend(INVARIANT_ORDER, states, {s: s.capitalize() for s in INVARIANT_ORDER})}</div>'
            f'<div><h3>Does a test notice?</h3>{segmented({"met": probes["noticed"], "missing": probes["unnoticed"], "unassessed": probes["not probed"]}, ["met", "missing", "unassessed"], "Probe results", True, {"met": probe_label["noticed"], "missing": probe_label["unnoticed"], "unassessed": probe_label["not probed"]})}'
            f'{legend(["met", "missing", "unassessed"], {"met": probes["noticed"], "missing": probes["unnoticed"], "unassessed": probes["not probed"]}, {"met": probe_label["noticed"], "missing": probe_label["unnoticed"], "unassessed": probe_label["not probed"]})}</div></div>'
            f'<div class="scroll"><table><thead><tr><th>ID</th><th>Invariant</th><th>Status</th><th>Strength</th><th>Enforced at</th>'
            f'<th>Probe</th></tr></thead><tbody>{"".join(body)}</tbody></table></div></section>')


def policy_section(d: dict, ids: dict) -> str:
    rows = d["policy"]
    if len(rows) < 3:
        return ""
    head, body = rows[0], rows[2:]
    roles = head[4:-1]

    def cell(value: str) -> str:
        kind = "deny" if value == "deny" else "allow" if value == "allow" else "cond"
        return f'<td class="perm {kind}">{esc(value)}</td>'

    def enforced(value: str) -> str:
        if value == "no check found":
            return badge("critical", "no check found")
        if value == "public by design":
            return badge("not-applicable", "public by design")
        if value.startswith("partial:"):
            return badge("partial", "partial") + " " + evidence(value)
        return evidence(value)

    lines = "".join(f'<tr id="policy-{esc(r[0])}"><td class="id">{esc(r[0])}</td><td><code>{esc(r[1])}</code></td><td>{esc(r[2])}</td>'
                    f'<td>{esc(r[3])}</td>{"".join(cell(c) for c in r[4:-1])}<td class="ev">{enforced(r[-1])}</td></tr>'
                    for r in body if len(r) == len(head))
    unchecked = sum(r[-1] == "no check found" for r in body)
    return (f'<section id="policy"><h2>Access policy</h2><p class="lede">Who may do what to which resource, as the profile states it '
            f'({esc(d["policy_status"] or "no status line")}). local-dast tests the running app against this table. '
            f'{unchecked} of {len(body)} rows have no check in the code.</p><div class="scroll"><table class="policy"><thead><tr>'
            f'<th>ID</th><th>Route</th><th>Resource</th><th>Action</th>{"".join(f"<th>{esc(r)}</th>" for r in roles)}<th>Enforced at</th>'
            f'</tr></thead><tbody>{lines}</tbody></table></div></section>')


def gaps_section(d: dict, ids: dict) -> str:
    entries = d["entries"]
    counts = {k: sum(e["risk"] == k for e in entries) for k in RISKS}
    labels = {"high": "High", "medium": "Medium", "low": "Low", "unrated": "Not rated"}
    cards = []
    for e in sorted(entries, key=lambda e: RISKS.index(e["risk"])):
        title = inline(re.sub(r"^[0-9]+[.)]\s*", "", e["heading"]), ids)
        cards.append(f'<article class="gap r-{e["risk"]}"><header>{badge(e["risk"], labels[e["risk"]] + " risk")}'
                     f'<h3>{title}</h3></header>{markdown(e["body"], ids)}</article>')
    cards = "".join(cards)
    closing = "".join(f'<details class="closing" open><summary>{esc(h)}</summary>{markdown(b, ids)}</details>' for h, b in d["closing"])
    if not entries and not d["summary"].strip():
        return '<section id="gaps"><h2>Gaps</h2><p class="muted">security/gaps.md is not written yet.</p></section>'
    return (f'<section id="gaps"><h2>Gaps</h2><p class="lede">One entry per root cause, highest risk first, as gaps.md states them.</p>'
            f'{segmented(counts, RISKS, "Gaps by risk", True, labels)}{legend(RISKS, counts, labels)}'
            f'<div class="summary">{markdown(d["summary"], ids)}</div>{cards}{closing}</section>')


def coverage_section(d: dict) -> str:
    files, inventory = d["files"], d["inventory"]
    lines = {s: sum(int(r["lines"] or 0) for r in files if r["status"] == s) for s in FILE_ORDER}
    flabels = {"read": "Read", "skimmed": "Skimmed", "skipped": "Skipped", "unread": "Unread"}
    dirs: dict = {}
    for r in files:
        top = r["path"].split("/")[0] if "/" in r["path"] else "(root)"
        dirs.setdefault(top, {s: 0 for s in FILE_ORDER})[r["status"]] += int(r["lines"] or 0)
    dir_rows = "".join(f'<div class="chapter"><div class="name">{esc(name)}</div>{segmented(c, FILE_ORDER, name, labels=flabels)}'
                       f'<div class="count">{sum(c.values())}</div></div>'
                       for name, c in sorted(dirs.items(), key=lambda kv: -sum(kv[1].values()))[:15])
    kinds: dict = {}
    for r in inventory:
        kinds.setdefault(r["kind"], {s: 0 for s in INV_ORDER})[r["status"]] += 1
    ilabels = {"boundary": "Boundary", "internal": "Internal", "test": "Test", "unreviewed": "Unreviewed"}
    kind_rows = "".join(f'<div class="chapter"><div class="name">{esc(k)}</div>{segmented(c, INV_ORDER, k, labels=ilabels)}'
                        f'<div class="count">{c["boundary"]}/{sum(c.values())}</div></div>'
                        for k, c in sorted(kinds.items(), key=lambda kv: -kv[1]["boundary"]))
    boundary = "".join(f'<tr><td>{esc(r["kind"])}</td><td><code>{esc(r["path"])}:{esc(r["line"])}</code></td>'
                       f'<td><code>{esc(r["text"][:160])}</code></td><td>{esc(r["notes"])}</td></tr>'
                       for r in inventory if r["status"] == "boundary")
    return (f'<section id="coverage"><h2>Coverage</h2><p class="lede">What the assessment rests on: every file was read, skimmed '
            f'or skipped with a reason, and every line where input can enter or code acts outside the program was placed. '
            f'{esc(d["gate"]["coverage"])}</p><div class="pair"><div><h3>Lines of code by how they were looked at</h3>'
            f'{segmented(lines, FILE_ORDER, "Lines by file status", True, flabels)}{legend(FILE_ORDER, lines, flabels)}'
            f'<div class="chapters">{dir_rows}</div></div><div><h3>Signal lines by kind</h3>'
            f'{legend(INV_ORDER, {s: sum(r["status"] == s for r in inventory) for s in INV_ORDER}, ilabels)}'
            f'<div class="chapters">{kind_rows}</div><p class="muted small">Count: boundary lines / all lines of that kind.</p></div></div>'
            f'<details class="tableview"><summary>Every boundary line ({sum(r["status"] == "boundary" for r in inventory)})</summary>'
            f'<div class="scroll"><table><thead><tr><th>Kind</th><th>Where</th><th>Line</th><th>Note</th></tr></thead>'
            f'<tbody>{boundary}</tbody></table></div></details></section>')


def page(d: dict) -> str:
    rows = d["rows"]
    ids = {f'{r["standard"]}:{r["id"]}': anchor(f'{r["standard"]}:{r["id"]}') for r in rows}
    ids.update({r["ID"]: "inv-" + r["ID"] for r in d["invariants"]})
    ids.update({r[0]: "policy-" + r[0] for r in d["policy"][2:]})
    ids.update({q["id"]: "question-" + q["id"] for q in d["questions"]})
    # gaps.md often names a requirement by its bare id (V6.3.1, A3.1): link it when exactly one selected standard has it.
    bare = {}
    for r in rows:
        bare.setdefault(r["id"], []).append(f'{r["standard"]}:{r["id"]}')
    for rid, keys in bare.items():
        if len(keys) == 1 and rid not in ids:
            ids[rid] = anchor(keys[0])
    totals = {s: sum(r["status"] == s for r in rows) for s in ORDER}
    applies = len(rows) - totals["not-applicable"]
    assessed = len(rows) - totals["unassessed"]
    rules = d["invariants"]
    inv_states = {s: sum(r.get("Status") == s for r in rules) for s in INVARIANT_ORDER}
    probes = {p: sum(probe_result(r.get("Test", "")) == p for r in rules) for p in ("noticed", "unnoticed", "not probed")}
    gap_counts = {k: sum(e["risk"] == k for e in d["entries"]) for k in RISKS}
    files_read = sum(int(r["lines"] or 0) for r in d["files"] if r["status"] in ("read", "skimmed"))
    files_total = sum(int(r["lines"] or 0) for r in d["files"]) or 1
    states = {k: sum(q["state"] == k for q in d["questions"]) for k in ("open", "yes", "no", "review")}
    data = {"totals": totals, "invariants": inv_states, "probes": probes, "gaps": gap_counts, "questions": states,
            "question_list": [{"id": q["id"], "digest": q["digest"]} for q in d["questions"]], "repo": d["name"],
            "gate": {"passes": d["gate"]["passes"], "problems": d["gate"]["problems"]}}
    blob = json.dumps(data).replace("<", "\\u003c")
    selection = ", ".join(f"{s.upper()} L{lvl}" for s, lvl in sorted(d["levels"].items()))
    gate_html = (badge("met", "gap.py check --complete passes") if d["gate"]["passes"] else
                 f'<details class="gate"><summary>{badge("missing", "gap.py check --complete does not pass")} '
                 f'{len(d["gate"]["problems"])} problems</summary><ul>'
                 + "".join(f"<li>{esc(p)}</li>" for p in d["gate"]["problems"][:200]) + "</ul></details>")
    tiles = "".join([
        tile(f"{totals['met']}/{applies}", "requirements met", "of those that apply", "good"),
        tile(totals["partial"], "partly met", "", "warning"),
        tile(totals["missing"], "missing", "", "critical"),
        tile(states["open"] + states["review"], "questions for owners",
             f'{totals["unverifiable"]} requirements to check outside the code', "warning" if states["open"] + states["review"] else "")
        if d["questions"] else tile(totals["unverifiable"], "to check outside the code"),
        tile(f"{inv_states['broken'] + inv_states['partial']}/{len(rules)}", "invariants broken or partial", "",
             "critical" if inv_states["broken"] else "") if rules else
        tile("–", "security invariants", "profile.md states none"),
        (tile(f"{probes['unnoticed']}/{probes['noticed'] + probes['unnoticed']}", "probed controls no test notices",
              f"{probes['not probed']} not probed", "warning" if probes["unnoticed"] else "")
         if probes["noticed"] + probes["unnoticed"] else
         tile("–", "controls probed", f"none of {len(rules)} invariants: see their Test cells", "warning")) if rules else
        tile("–", "controls probed", "nothing to probe without invariants"),
        tile(f"{100 * files_read // files_total} %", "of the code read or skimmed", f"{len(d['files'])} files"),
        tile(gap_counts["high"], "high-risk gaps", f"{len(d['entries'])} gaps in all", "critical" if gap_counts["high"] else ""),
    ])
    overview = (f'<section id="overview"><div class="tiles">{tiles}'
                f'</div><h3>All {len(rows)} requirements</h3>{segmented(totals, ORDER, "All requirements by status", True)}'
                f'{legend(ORDER, totals)}<p class="muted small">{assessed} of {len(rows)} assessed.</p></section>')
    profile_md = markdown(re.sub(r"^# .*\n", "", d["profile"], count=1), ids)
    profile = (f'<section id="profile"><h2>Product profile</h2><details><summary>The model of the product the assessment rests on '
               f'(profile.md)</summary><div class="md">{profile_md}</div></details></section>'
               if d["profile"].strip() else "")
    accepted = (f'<section id="accepted"><h2>Accepted risks</h2><div class="md">{markdown(d["accepted"], ids)}</div></section>'
                if d["accepted"].strip() else "")
    sections = [overview, gaps_section(d, ids), questions_section(d, ids), controls_section(d, ids), requirements_section(d, ids), invariants_section(d, ids),
                policy_section(d, ids), coverage_section(d), accepted, profile]
    nav = [("overview", "Overview"), ("gaps", "Gaps"), ("verification", "Questions"), ("controls", "Controls"), ("requirements", "Chapters"),
           ("invariants", "Invariants"), ("policy", "Access policy"), ("coverage", "Coverage"), ("accepted", "Accepted risks"),
           ("profile", "Profile")]
    body = "\n".join(s for s in sections if s)
    nav_html = "".join(f'<a href="#{k}">{v}</a>' for k, v in nav if f'id="{k}"' in body)
    return TEMPLATE.format(title=esc(f"Security gap analysis: {d['name']}"), name=esc(d["name"]),
                           meta=esc(f"commit {d['revision']} · {selection} · {len(rows)} requirements · made "
                                    f"{datetime.date.today().isoformat()} by gap.py report"),
                           gate=gate_html, nav=nav_html, body=body, data=blob, css=CSS, js=JS)


def write(repo: Path, out: Path) -> Path:
    d = collect(repo)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page(d), encoding="utf-8")
    return out


CSS = """
.viz-root{color-scheme:light;--surface:#fcfcfb;--plane:#f9f9f7;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;
--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;
--blue:#2a78d6;--magenta:#e87ba4;--na:#c3c2b7;--none:#e1e0d9;--link:#256abf}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--surface:#1a1a19;--plane:#0d0d0d;
--ink:#f0efec;--ink2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--blue:#3987e5;--magenta:#d55181;
--na:#52514e;--none:#2c2c2a;--link:#86b6ef}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--surface:#1a1a19;--plane:#0d0d0d;--ink:#f0efec;--ink2:#c3c2b7;--grid:#2c2c2a;
--axis:#383835;--ring:rgba(255,255,255,.10);--blue:#3987e5;--magenta:#d55181;--na:#52514e;--none:#2c2c2a;--link:#86b6ef}
*{box-sizing:border-box}body{margin:0}
.viz-root{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--plane);color:var(--ink);min-height:100vh}
header.top{position:sticky;top:0;z-index:5;background:var(--surface);border-bottom:1px solid var(--ring);padding:14px 28px 0}
header.top h1{font-size:20px;margin:0}header.top .meta{color:var(--ink2);font-size:13px;margin:2px 0 8px}
header.top .row{display:flex;gap:16px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap}
nav{display:flex;gap:2px;flex-wrap:wrap;margin-top:6px}nav a{color:var(--ink2);text-decoration:none;padding:8px 10px;font-size:14px;border-bottom:2px solid transparent}
nav a:hover,nav a:focus-visible{color:var(--ink);border-bottom-color:var(--blue)}
main{max-width:1240px;margin:0 auto;padding:8px 28px 64px}
section{background:var(--surface);border:1px solid var(--ring);border-radius:12px;padding:20px 24px;margin:20px 0;scroll-margin-top:120px}
h2{font-size:18px;margin:0 0 4px}h3{font-size:15px;margin:18px 0 8px}h4,h5,h6{font-size:14px;margin:14px 0 6px}
.lede{color:var(--ink2);margin:0 0 14px;max-width:80ch}.muted{color:var(--muted)}.small{font-size:12px}
a{color:var(--link)}code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--plane);border:1px solid var(--ring);border-radius:4px;padding:0 4px;white-space:pre-wrap;word-break:break-word}
pre{background:var(--plane);border:1px solid var(--ring);border-radius:8px;padding:10px;overflow:auto}pre code{border:0;padding:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px}
.tile{border:1px solid var(--ring);border-radius:10px;padding:12px 14px;border-left:4px solid var(--axis)}
.tile.good{border-left-color:var(--good)}.tile.warning{border-left-color:var(--warning)}.tile.critical{border-left-color:var(--critical)}
.tile .value{font-size:30px;font-weight:650;font-variant-numeric:tabular-nums;line-height:1.1}.tile .label{color:var(--ink2);font-size:13px}.tile .note{color:var(--muted);font-size:12px}
.bar{display:flex;gap:2px;height:8px;border-radius:4px;overflow:hidden;min-width:60px;flex:1}
.bar.none{background:none;color:var(--muted);font-size:12px;height:auto}.chapter.na .name{color:var(--muted)}
.bar.tall{height:28px;border-radius:4px;margin:6px 0}.bar.empty{color:var(--muted);font-size:12px;height:auto}
.seg{min-width:3px;display:flex;align-items:center;padding-left:6px;font-size:12px;font-weight:600;color:#fff;cursor:default;outline-offset:2px}
.bar.tall .seg{border-radius:4px}.seg:hover,.seg:focus-visible{filter:brightness(1.12)}
.s-met{background:var(--good)}.s-partial{background:var(--warning);color:#0b0b0b}.s-missing{background:var(--critical)}
.s-unverifiable{background:var(--blue)}.s-risk-accepted{background:var(--magenta)}.s-not-applicable{background:var(--na);color:var(--ink)}
.s-unassessed{background:var(--none);color:var(--ink)}
.s-holds{background:var(--good)}.s-broken{background:var(--critical)}.s-high{background:var(--critical)}.s-medium{background:var(--serious)}
.s-low{background:var(--warning);color:#0b0b0b}.s-unrated{background:var(--na);color:var(--ink)}
.s-read{background:var(--good)}.s-skimmed{background:var(--blue)}.s-skipped{background:var(--na);color:var(--ink)}.s-unread{background:var(--critical)}
.s-open{background:var(--blue)}.s-review{background:var(--warning);color:#0b0b0b}.s-yes{background:var(--good)}.s-no{background:var(--critical)}
.s-boundary{background:var(--blue)}.s-internal{background:var(--na);color:var(--ink)}.s-test{background:var(--magenta)}.s-unreviewed{background:var(--critical)}
.legend{list-style:none;display:flex;flex-wrap:wrap;gap:6px 16px;padding:0;margin:4px 0 10px;font-size:13px;color:var(--ink2)}
.legend li{display:flex;align-items:center;gap:6px}.sw{width:10px;height:10px;border-radius:3px;display:inline-block;flex:none}
.num{font-variant-numeric:tabular-nums;color:var(--ink)}
.chapters{display:grid;gap:6px}.chapter{display:grid;grid-template-columns:minmax(140px,260px) 1fr 64px;gap:12px;align-items:center;font-size:13px}
.chapter .name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink2)}.chapter .count{text-align:right;font-variant-numeric:tabular-nums;color:var(--ink2)}
.pair{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:28px}
table{border-collapse:collapse;width:100%;font-size:13.5px}th{text-align:left;font-weight:600;color:var(--ink2);border-bottom:1px solid var(--axis);padding:6px 8px;position:sticky;top:0;background:var(--surface)}
td{border-bottom:1px solid var(--grid);padding:7px 8px;vertical-align:top}.scroll{overflow:auto;max-height:none}
td.id{white-space:nowrap;font-variant-numeric:tabular-nums;font-weight:600}td.id .small{white-space:normal;font-weight:400;min-width:160px;max-width:230px}td.ev{min-width:270px;max-width:380px}
td.ev code{display:inline-block;margin:0 4px 4px 0;overflow-wrap:anywhere;vertical-align:top}
.notes{color:var(--ink2);margin-top:4px;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:4px;white-space:nowrap;font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px;border:1px solid var(--ring);background:var(--plane)}
.badge.met,.badge.holds{color:var(--good);border-color:var(--good)}.badge.partial,.badge.low{color:var(--ink);border-color:var(--warning);background:color-mix(in srgb,var(--warning) 18%,transparent)}
.badge.missing,.badge.broken,.badge.critical,.badge.high{color:var(--critical);border-color:var(--critical)}.badge.medium{color:var(--ink);border-color:var(--serious);background:color-mix(in srgb,var(--serious) 18%,transparent)}
.badge.unverifiable{color:var(--blue);border-color:var(--blue)}.badge.risk-accepted{border-color:var(--magenta)}
.strength.central{font-weight:600}.strength.none{color:var(--critical)}
table.policy td:nth-child(2) code{white-space:nowrap}td.perm{font-size:12.5px}td.perm.allow{color:var(--good);font-weight:600}td.perm.deny{color:var(--muted)}td.perm.cond{color:var(--ink)}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
input[type=search]{font:inherit;padding:7px 10px;border-radius:8px;border:1px solid var(--axis);background:var(--surface);color:var(--ink);min-width:280px}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{font:inherit;font-size:13px;display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid var(--axis);background:var(--surface);color:var(--ink2);cursor:pointer}
.chip[aria-pressed="true"]{background:var(--plane);color:var(--ink);border-color:var(--ink2);font-weight:600}
.gap{border:1px solid var(--ring);border-left:4px solid var(--na);border-radius:10px;padding:10px 16px;margin:12px 0}
.gap.r-high{border-left-color:var(--critical)}.gap.r-medium{border-left-color:var(--serious)}.gap.r-low{border-left-color:var(--warning)}
.gap header{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.gap h3{margin:4px 0}
details summary{cursor:pointer;color:var(--ink2);font-weight:600;margin:8px 0}details.gate summary{font-weight:400}
details.gate ul{max-height:280px;overflow:auto;font-size:13px;color:var(--ink2)}
.link{text-decoration:underline dotted}
.ask{margin-top:6px;padding:6px 8px;border-radius:6px;background:var(--plane);border-left:3px solid var(--blue);font-size:13px}
.ask.s-border-review{border-left-color:var(--warning)}.ask.s-border-no{border-left-color:var(--critical)}.ask.s-border-yes{border-left-color:var(--good)}
.question{border:1px solid var(--ring);border-left:4px solid var(--blue);border-radius:10px;padding:10px 16px;margin:12px 0}
.question.q-review{border-left-color:var(--warning)}.question.q-no{border-left-color:var(--critical)}.question.q-yes{border-left-color:var(--good)}
.question header{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.question .id{font-weight:700}.question h3{margin:6px 0}
.question ul.rows{margin:6px 0 8px;padding-left:18px;font-size:13px}.question ul.rows li{margin:3px 0}
.question fieldset{border:1px solid var(--grid);border-radius:8px;padding:8px 10px;margin:6px 0 2px}
.question legend{font-size:12px;color:var(--ink2)}.radios{display:flex;gap:16px;margin-bottom:6px}
.question input.note,.answerbar input{font:inherit;font-size:13px;padding:6px 8px;border-radius:6px;border:1px solid var(--axis);background:var(--surface);color:var(--ink);width:100%}
.answerbar{display:flex;gap:12px;align-items:end;flex-wrap:wrap;margin:8px 0}.answerbar label{font-size:13px;color:var(--ink2);flex:1;min-width:240px}
#export-answers{font:inherit;font-size:13px;padding:7px 14px;border-radius:8px;border:1px solid var(--ink2);background:var(--ink);color:var(--surface);cursor:pointer}
.recorded{font-size:13px;color:var(--ink2);margin:4px 0}.chip.verify{border-style:dashed}
.tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:5px 8px;border-radius:6px;z-index:10;display:none;max-width:320px}
.theme{font:inherit;font-size:12px;border:1px solid var(--axis);background:var(--surface);color:var(--ink2);border-radius:8px;padding:4px 8px}
tr:target,article:target{outline:2px solid var(--blue);outline-offset:-2px}
@media print{header.top{position:static}details{display:block}details>*{display:block}.filters,.theme{display:none}tr[hidden]{display:table-row}section{break-inside:avoid-page}}
@media (forced-colors:active){.seg{border:1px solid CanvasText}}
"""

JS = """
(function(){
  var tip=document.querySelector('.tip');
  function show(e){var t=e.target.closest('[data-tip]');if(!t){tip.style.display='none';return;}
    tip.textContent=t.getAttribute('data-tip');tip.style.display='block';
    var r=t.getBoundingClientRect(),x=(e.clientX||r.left+r.width/2)+12,y=(e.clientY||r.top)+14;
    tip.style.left=Math.min(x,innerWidth-tip.offsetWidth-8)+'px';tip.style.top=Math.min(y,innerHeight-tip.offsetHeight-8)+'px';}
  document.addEventListener('mousemove',show);document.addEventListener('focusin',show);
  document.addEventListener('mouseleave',function(){tip.style.display='none';});
  var rows=[].slice.call(document.querySelectorAll('table.reqs tbody tr')),chips=[].slice.call(document.querySelectorAll('.chip')),
      q=document.getElementById('search'),shown=document.getElementById('shown');
  function apply(){var on=chips.filter(function(c){return c.getAttribute('aria-pressed')==='true';}).map(function(c){return c.dataset.filter;}),
      verify=on.indexOf('verify')>=0,term=(q&&q.value||'').toLowerCase().trim(),n=0;
    rows.forEach(function(r){var ok=(verify?(r.dataset.verify==='open'||r.dataset.verify==='review'):(on.length===0||on.indexOf(r.dataset.status)>=0))
      &&(!term||r.dataset.search.indexOf(term)>=0);r.hidden=!ok;if(ok)n++;});if(shown)shown.textContent=n+' of '+rows.length+' shown';}
  chips.forEach(function(c){c.addEventListener('click',function(){var press=c.getAttribute('aria-pressed')!=='true';
    chips.forEach(function(o){if((c.dataset.filter==='verify')!==(o.dataset.filter==='verify'))o.setAttribute('aria-pressed','false');});
    c.setAttribute('aria-pressed',press?'true':'false');apply();});});
  if(q)q.addEventListener('input',apply);
  function reveal(){var id=location.hash.slice(1),el=id&&document.getElementById(id);
    if(el&&el.hidden){chips.forEach(function(c){if(c.dataset.filter===el.dataset.status)c.setAttribute('aria-pressed','true');});apply();el.scrollIntoView();}}
  addEventListener('hashchange',reveal);apply();reveal();
  var data=JSON.parse(document.getElementById('report-data').textContent),key='gap-answers:'+data.repo,store={};
  try{store=JSON.parse(localStorage.getItem(key)||'{}');}catch(e){store={};}
  var cards=[].slice.call(document.querySelectorAll('article.question')),by=document.getElementById('answered-by'),
      count=document.getElementById('answer-count');
  function save(){try{localStorage.setItem(key,JSON.stringify(store));}catch(e){}
    var n=Object.keys(store).filter(function(k){return store[k].answer;}).length;if(count)count.textContent=n+' answered in this browser';}
  if(by){by.value=store.__by||'';by.addEventListener('input',function(){store.__by=by.value;save();});}
  cards.forEach(function(card){var id=card.dataset.id,digest=card.dataset.digest,mine=store[id];
    if(mine&&mine.digest!==digest){delete store[id];mine=null;}
    var note=card.querySelector('input.note');
    card.querySelectorAll('input[type=radio]').forEach(function(r){if(mine&&mine.answer===r.value)r.checked=true;
      r.addEventListener('change',function(){store[id]={digest:digest,answer:r.value,note:note.value,at:new Date().toISOString().slice(0,10)};save();});});
    if(mine&&note)note.value=mine.note||'';
    if(note)note.addEventListener('input',function(){if(store[id]){store[id].note=note.value;save();}});});
  var ex=document.getElementById('export-answers');
  if(ex)ex.addEventListener('click',function(){var who=(by&&by.value||'').trim();
    if(!who){by.focus();by.setAttribute('aria-invalid','true');return;}
    var out=Object.keys(store).filter(function(k){return k!=='__by'&&store[k].answer;}).map(function(k){
      return {id:k,digest:store[k].digest,answer:store[k].answer,note:store[k].note||'',by:who,at:store[k].at};});
    var blob=new Blob([JSON.stringify({format:'security-gap-analysis answers 1',repo:data.repo,answers:out},null,2)],{type:'application/json'}),
        a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='answers-'+data.repo+'.json';
    document.body.appendChild(a);a.click();a.remove();});
  save();
  var b=document.querySelector('.theme');if(b){b.addEventListener('click',function(){var d=document.documentElement,
    t=d.getAttribute('data-theme');t=t==='dark'?'light':t==='light'?null:'dark';
    if(t)d.setAttribute('data-theme',t);else d.removeAttribute('data-theme');b.textContent='Theme: '+(t||'auto');});}
})();
"""

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<div class="viz-root">
<header class="top"><div class="row"><div><h1>Security gap analysis: {name}</h1><div class="meta">{meta}</div></div>
<div>{gate} <button type="button" class="theme">Theme: auto</button></div></div><nav aria-label="Sections">{nav}</nav></header>
<main>
{body}
<p class="muted small">Made from the repository's security/ folder by security-gap-analysis. It reads source, so it says nothing about how the running application behaves or what is deployed; see Not covered under Gaps.</p>
</main>
<div class="tip" role="tooltip"></div>
</div>
<script type="application/json" id="report-data">{data}</script>
<script>{js}</script>
</body>
</html>
"""
