"""Text, JSON, Markdown and GitHub-annotation output."""
import json
import os
import sys

from .probe import SEVERITIES

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def use_color(stream):
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _c(s, code, on):
    return f"\033[{code}m{s}\033[0m" if on else s


def _sorted(findings):
    return sorted(findings, key=lambda f: (-SEVERITIES.index(f.severity), f.resource, f.id))


def _cell(v, letter, on):
    if v is None:
        return _c("-", "2", on)
    v = str(v)
    if v == "ALLOWED":
        return _c(letter, "1;31", on)
    if v.startswith("denied"):
        return _c("\u00b7", "32", on)
    return _c("?", "33", on)


def _seen(v, on):
    if v is None:
        return _c("-", "2", on)
    if isinstance(v, int):
        return _c(str(v), "1;31", on) if v else _c("0", "32", on)
    return _c("denied", "32", on) if str(v).startswith("denied") else _c("?", "33", on)


def _matrix(result, w, on):
    tables = {k: v for k, v in result.coverage.items() if not k.startswith("storage")}
    if tables:
        width = max(12, max(len(k) for k in tables) + 1)
        w(_c(f"{'table':<{width}}{'rows':>6}   anon: sees  B's row   user A: sees  B's row", "1", on) + "\n")
        notes = []
        for name in sorted(tables):
            c = tables[name]
            rows = c.get("rows")
            line = f"{name:<{width}}{('-' if rows is None else str(rows)):>6}   "
            for actor in ("anon", "user A"):
                seen = _seen(c.get(f"{actor} read"), on)
                vis = len(str(c.get(f"{actor} read"))) if isinstance(c.get(f"{actor} read"), int) else (
                    6 if str(c.get(f"{actor} read", "")).startswith("denied") else 1)
                cells = "".join(_cell(c.get(f"{actor} {k}"), L, on) for k, L in
                                (("read B's row", "R"), ("insert as B", "I"), ("update B's row", "U"),
                                 ("delete B's row", "D")))
                pad = (6 if actor == "anon" else 8) + 6 - vis
                line += " " * pad + seen + "  " + cells + "    "
            if c.get("public"):
                line += _c("public by config", "2", on)
            tu = str(c.get("two-user", ""))
            if tu.startswith("skipped"):
                notes.append(f"{name}: two-user test {tu}")
            w(line.rstrip() + "\n")
        w(_c("sees = existing rows visible (a new user owns none) \u00b7 B's row: R read I insert-as-B U update "
             "D delete \u00b7 \u00b7 = denied \u00b7 - = not tested", "2", on) + "\n")
        for n in notes:
            w(_c("  " + n, "2", on) + "\n")
    for k in sorted(x for x in result.coverage if x.startswith("storage")):
        c = result.coverage[k]
        w(f"{k:<20} " + " \u00b7 ".join(f"{a}: {b}" for a, b in c.items()) + "\n")
    w("\n")


VIEW_NOTE = "-- If a table here is a view: views ignore RLS unless `security_invoker = on`."


def merged_fix(items):
    """Fix SQL for several findings on one resource, deduplicated line by line."""
    out, seen = [], set()
    for f in items:
        if not f.fix or f.severity == "info":
            continue
        for line in f.fix.splitlines():
            if line.startswith("-- If ") and "is a view" in line:
                continue
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out


def text(result, stream=sys.stdout, show_fix=True, show_coverage=True):
    on = use_color(stream)
    w = stream.write
    if show_coverage and result.coverage:
        _matrix(result, w, on)
    for n in result.notes:
        w(_c("note: ", "33", on) + n + "\n")
    if result.notes:
        w("\n")
    fs = _sorted(result.findings)
    groups = {}
    for f in fs:
        groups.setdefault(f.resource, []).append(f)
    for res, items in groups.items():
        w(_c(res, "1", on) + "\n")
        for f in items:
            sev = _c(f"{f.severity.upper():<8}", COLORS[f.severity], on)
            w(f"  {sev} {f.id} [{f.actor}] {f.title}\n")
            if f.detail:
                w(_c(f"           {f.detail}", "2", on) + "\n")
        if show_fix:
            lines = merged_fix(items)
            if lines:
                w(_c("  fix:", "36", on) + "\n")
                for line in lines:
                    w(_c("    " + line, "36", on) + "\n")
        w("\n")
    counts = {s: sum(1 for f in fs if f.severity == s) for s in SEVERITIES}
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
    w((_c(f"{len(fs)} finding{'' if len(fs) == 1 else 's'}: {summary}", "1", on) if fs else _c("No findings.", "32", on)) + "\n")


def as_json(result, extra=None):
    d = result.to_dict()
    if extra:
        d.update(extra)
    return json.dumps(d, indent=2, default=str)


def markdown(result):
    out = ["## authzprobe", ""]
    fs = _sorted(result.findings)
    if not fs:
        out.append("No findings.")
    else:
        out += ["| Severity | ID | Resource | As | Finding |", "|---|---|---|---|---|"]
        for f in fs:
            out.append(f"| {f.severity} | {f.id} | `{f.resource}` | {f.actor} | {f.title} |")
        for f in fs:
            if f.fix and f.severity != "info":
                out += ["", f"<details><summary>Fix for {f.id} on {f.resource}</summary>", "", "```sql", f.fix,
                        "```", "", "</details>"]
    if result.notes:
        out += [""] + [f"> note: {n}" for n in result.notes]
    return "\n".join(out) + "\n"


def github(result, stream=sys.stdout):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "notice", "info": "notice"}
    for f in _sorted(result.findings):
        msg = (f.detail or "").replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        stream.write(f"::{level[f.severity]} title={f.id} {f.resource}: {f.title}::{msg}\n")


def sql_file(result):
    out = [f"-- authzprobe fix suggestions (run {result.run_id}). Review before applying!", VIEW_NOTE, ""]
    groups = {}
    for f in _sorted(result.findings):
        groups.setdefault(f.resource, []).append(f)
    for res, items in groups.items():
        lines = merged_fix(items)
        if not lines:
            continue
        out += [f"-- {res}: " + "; ".join(f"{f.id} [{f.actor}] {f.title}" for f in items if f.severity != "info")]
        out += lines + [""]
    return "\n".join(out)
