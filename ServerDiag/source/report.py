"""HTML / TXT / JSON reports for one host or a whole fleet."""
import json
import os
import re
from datetime import datetime
from html import escape

from .common import VERSION, sort_findings, all_findings, cell, section_lines

CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#f3f5f9;color:#1b2230}
header{background:#141a26;color:#fff;padding:22px 32px}header h1{margin:0;font-size:24px}header p{margin:4px 0 0;opacity:.7}
main{padding:18px 32px 60px;max-width:1500px}
.card{background:#fff;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:14px 18px;margin:12px 0}
.score{font-size:40px;font-weight:700;margin-right:14px}
h2{margin:28px 0 8px;border-bottom:2px solid #141a26;padding-bottom:4px}h3{margin:16px 0 6px;font-size:15px;color:#243b63}
table{border-collapse:collapse;width:100%;font-size:13px;background:#fff}th,td{border:1px solid #dde2ea;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#eef1f6}pre{background:#fff;border:1px solid #dde2ea;padding:10px;font-size:12px;white-space:pre-wrap}
.note{color:#687085;font-size:12px;margin:0 0 6px}
tr.CRITICAL td{background:#fde3e3}tr.WARNING td{background:#fff3d6}tr.OK td{background:#e2f4e6}
.b{display:inline-block;padding:1px 9px;border-radius:10px;color:#fff;font-weight:600;font-size:12px}
.HIGH,.CRITICAL{background:#d64545}.MEDIUM,.WARNING{background:#e69b1e}.LOW,.INFO{background:#3b7ddd}.OK{background:#2f9e5b}
.prob{border-left:6px solid #3b7ddd}.prob.HIGH{border-color:#d64545}.prob.MEDIUM{border-color:#e69b1e}
.ev{font-family:Consolas,Menlo,monospace;font-size:12px;color:#444}
details{background:#fff;border-radius:10px;margin:10px 0;padding:6px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
summary{cursor:pointer;font-weight:600;padding:8px 0}
.s-good{color:#2f9e5b}.s-mid{color:#e69b1e}.s-bad{color:#d64545}
"""


def _score_cls(s):
    return "s-good" if s >= 85 else ("s-mid" if s >= 60 else "s-bad")


def _table(rows, cols):
    h = "<table><tr>" + "".join("<th>%s</th>" % escape(str(c)) for c in cols) + "</tr>"
    for r in rows:
        h += "<tr>" + "".join("<td>%s</td>" % escape(cell(r.get(c), 0)) for c in cols) + "</tr>"
    return h + "</table>"


def _section(sec):
    out = "<h3>%s</h3>" % escape(sec["title"])
    if sec.get("note"):
        out += '<p class="note">%s</p>' % escape(sec["note"])
    data = sec.get("data") or []
    if not data:
        return out + '<p class="note">(nothing found)</p>'
    if all(isinstance(d, str) for d in data):
        return out + "<pre>%s</pre>" % escape("\n".join(data))
    rows = [d for d in data if isinstance(d, dict)]
    if sec.get("list"):
        return out + "".join(_table([{"Item": k, "Value": v} for k, v in r.items()], ["Item", "Value"]) for r in rows)
    cols = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    return out + _table(rows, cols)


def _host_html(r):
    h = []
    h.append('<div class="card"><span class="score %s">%s/100</span> %d critical &middot; %d warnings &middot; %s &middot; %s%s</div>' % (
        _score_cls(r["score"]), r["score"], r["critical"], r["warnings"], escape(r.get("os", "")), escape(r.get("virt") or ""),
        "" if r.get("admin") else " &middot; <b>not run as root/admin (limited)</b>"))
    h.append("<h3>Findings</h3><table><tr><th>Status</th><th>Area</th><th>Finding</th><th>Suggested action</th></tr>")
    for f in sort_findings(all_findings(r)):
        st = f.get("Status", "")
        h.append('<tr class="%s"><td><span class="b %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            st, st, st, escape(f.get("Area") or ""), escape(f.get("Finding") or ""), escape(f.get("Advice") or "")))
    h.append("</table>")
    a = r.get("analysis")
    if a:
        h.append("<h2>%s (%s events, %s)</h2>" % (escape(r.get("analysis_title", "Log Analyzer")), a.get("total_events", 0), escape(str(a.get("source", "")))))
        for ins in a.get("insights", []):
            h.append('<div class="card"><b>Insight:</b> %s</div>' % escape(ins))
        if not a.get("problems"):
            h.append('<p class="note">No problem patterns found.</p>')
        for p in a.get("problems", []):
            h.append('<div class="card prob %s"><span class="b %s">%s</span> <b>%s</b><p>%s</p><b>Evidence</b><ul>%s</ul><b>What to do</b><ol>%s</ol></div>' % (
                p["likelihood"], p["likelihood"], p["likelihood"], escape(p["name"]), escape(p["why"]),
                "".join('<li class="ev">%s</li>' % escape(e) for e in p["evidence"]), "".join("<li>%s</li>" % escape(x) for x in p["fix"])))
        if a.get("boots"):
            h.append("<h3>Boot history</h3>" + _table([{"Boot": b["boot"], "Start": b["start"], "End": b["end"],
                                                          "Shutdown": "clean" if b["clean"] else ("CRASH (panic)" if b["panic"] else "UNCLEAN")} for b in a["boots"]],
                                                        ["Boot", "Start", "End", "Shutdown"]))
        h.append("<h3>Recognised events</h3>" + _table(a.get("matched", []), ["count", "last", "category", "source", "meaning"]))
        h.append("<h3>Timeline</h3>" + _table(a.get("timeline", [])[:120], ["time", "kind", "source", "what"]))
        h.append('<h3>Unrecognised errors</h3><p class="note">Search the message online.</p>' + _table(a.get("unknown", []), ["count", "last", "source", "msg"]))
        h.append("<h3>Known harmless noise (ignored)</h3>" + _table(a.get("noise", []), ["count", "last", "meaning"]))
    for key in r.get("order", []):
        c = r["checks"].get(key)
        if not c:
            continue
        h.append("<h2>%s</h2>" % escape(c["title"]))
        if c.get("error"):
            h.append('<p class="note">Check error: %s</p>' % escape(c["error"]))
        for s in c.get("sections", []):
            h.append(_section(s))
    return "\n".join(h)


def html_report(results, title=None):
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    fleet = len(results) > 1
    title = title or ("ServerDiag fleet report (%d hosts)" % len(results) if fleet else "ServerDiag - %s" % results[0]["host"])
    h = ['<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>%s</style></head><body>' % (escape(title), CSS),
         "<header><h1>%s</h1><p>Generated %s &middot; ServerDiag %s</p></header><main>" % (escape(title), when, VERSION)]
    if fleet:
        rows = []
        for r in sorted(results, key=lambda r: (r["error"] is None, r["score"])):
            probs = (r.get("analysis") or {}).get("problems") or []
            top = sorted(all_findings(r), key=lambda f: {"CRITICAL": 0, "WARNING": 1}.get(f.get("Status"), 5))
            rows.append("<tr><td><a href='#%s'>%s</a></td><td>%s</td><td class='%s'><b>%s</b></td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>" % (
                escape(re.sub(r"\W", "_", r["host"])), escape(r["host"]), escape(r.get("os", "")), _score_cls(r["score"]), r["score"],
                r["critical"], r["warnings"], escape(top[0]["Finding"] if top and top[0]["Status"] in ("CRITICAL", "WARNING") else "-"),
                escape(", ".join("%s (%s)" % (p["name"], p["likelihood"]) for p in probs[:2]) or "-")))
        h.append("<h2>Overview</h2><table><tr><th>Host</th><th>OS</th><th>Score</th><th>Critical</th><th>Warnings</th><th>Top finding</th><th>Likely causes (logs)</th></tr>%s</table>" % "".join(rows))
        for r in sorted(results, key=lambda r: r["score"]):
            h.append("<details id='%s'%s><summary>%s &mdash; <span class='%s'>%s/100</span> &mdash; %s</summary>%s</details>" % (
                escape(re.sub(r"\W", "_", r["host"])), " open" if r["score"] < 60 else "", escape(r["host"]), _score_cls(r["score"]), r["score"],
                escape(r.get("os", "")), _host_html(r)))
    else:
        h.append(_host_html(results[0]))
    h.append("</main></body></html>")
    return "\n".join(h)


def text_report(r):
    t = ["ServerDiag report - %s - %s" % (r["host"], r["generated"]), "%s | %s" % (r.get("os"), r.get("virt")),
         "Health score: %d/100 (%d critical, %d warnings)" % (r["score"], r["critical"], r["warnings"]), "", "FINDINGS"]
    for f in sort_findings(all_findings(r)):
        t.append("  [%-8s] %-14s %s" % (f.get("Status"), f.get("Area"), f.get("Finding")))
        if f.get("Advice"):
            t.append("                            -> %s" % f["Advice"])
    a = r.get("analysis")
    if a:
        t += ["", "=" * 90, "%s - LIKELY CAUSES" % r.get("analysis_title", "Log Analyzer").upper(), "=" * 90]
        for ins in a.get("insights", []):
            t.append("  * " + ins)
        for p in a.get("problems", []):
            t += ["", "  [%s] %s" % (p["likelihood"], p["name"]), "    " + p["why"]] + ["      - " + e for e in p["evidence"]]
            t += ["    What to do:"] + ["      %d. %s" % (i + 1, x) for i, x in enumerate(p["fix"])]
    for key in r.get("order", []):
        c = r["checks"].get(key)
        if not c:
            continue
        t += ["", "=" * 90, c["title"].upper(), "=" * 90]
        for s in c.get("sections", []):
            t += ["", "-- " + s["title"]] + section_lines(s, 0)
    return "\n".join(t) + "\n"


def save(results, out_dir):
    fleet = len(results) > 1
    name = ("fleet_%s" % datetime.now().strftime("%Y-%m-%d_%H%M")) if fleet else ("%s_%s" % (re.sub(r"[^\w.-]", "_", results[0]["host"]), datetime.now().strftime("%Y-%m-%d_%H%M")))
    path = os.path.join(out_dir, name)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "report.html"), "w", encoding="utf-8") as f:
        f.write(html_report(results))
    with open(os.path.join(path, "report.json"), "w", encoding="utf-8") as f:
        json.dump(results if fleet else results[0], f, default=str, indent=1)
    for r in results:
        fn = "report.txt" if not fleet else "%s.txt" % re.sub(r"[^\w.-]", "_", r["host"])
        with open(os.path.join(path, fn), "w", encoding="utf-8") as f:
            f.write(text_report(r))
    return path
