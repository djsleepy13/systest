"""HTML / TXT report generation."""
import os
from datetime import datetime
from html import escape

from core import APP_VERSION, section_text, sort_findings, health_score, cell

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f9;color:#1d2433}
header{background:#1a2233;color:#fff;padding:22px 32px}header h1{margin:0;font-size:24px}header p{margin:4px 0 0;opacity:.75}
main{padding:20px 32px;max-width:1400px}
.card{background:#fff;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:16px 20px;margin:14px 0}
.score{font-size:42px;font-weight:700;margin-right:16px}
h2{margin:30px 0 8px;border-bottom:2px solid #1a2233;padding-bottom:4px}h3{margin:18px 0 6px;font-size:15px;color:#1a2233}
table{border-collapse:collapse;width:100%;font-size:13px;background:#fff}th,td{border:1px solid #dde2ea;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#eef1f6}pre{background:#fff;border:1px solid #dde2ea;padding:10px;font-size:12px;white-space:pre-wrap}
.note{color:#6b7385;font-size:12px;margin:0 0 6px}
tr.CRITICAL td{background:#fde2e2}tr.WARNING td{background:#fff4d6}tr.OK td{background:#e3f5e6}
.lk{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-weight:600;font-size:12px;margin-right:8px}
.HIGH{background:#d9534f}.MEDIUM{background:#f0ad4e}.LOW{background:#5bc0de}
.prob{border-left:6px solid #ccc}.prob.HIGH{border-color:#d9534f;background:#fff}.prob.MEDIUM{border-color:#f0ad4e;background:#fff}.prob.LOW{border-color:#5bc0de;background:#fff}
.prob ul{margin:6px 0}.ev{font-family:Consolas,monospace;font-size:12px;color:#444}
details.ev-d{background:#fff;border-radius:8px;margin:6px 0;padding:6px 14px;border-left:5px solid #f0ad4e;cursor:help}
details.ev-d.CRITICAL{border-left-color:#d9534f}details.ev-d summary{cursor:pointer;padding:4px 0}.evbody p{margin:6px 0}
.b{display:inline-block;padding:1px 8px;border-radius:9px;color:#fff;font-size:11px;font-weight:600}.b.CRITICAL{background:#d9534f}.b.WARNING{background:#f0ad4e}
"""


def _table(rows, cols):
    h = "<table><tr>" + "".join("<th>%s</th>" % escape(c) for c in cols) + "</tr>"
    for r in rows:
        h += "<tr>" + "".join("<td>%s</td>" % escape(cell(r.get(c), 0)) for c in cols) + "</tr>"
    return h + "</table>"


def _sec_html(sec):
    out = "<h3>%s</h3>" % escape(sec["title"])
    if sec.get("note"):
        out += '<p class="note">%s</p>' % escape(sec["note"])
    data = sec["data"]
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


def _fmt_t(t):
    return t.strftime("%Y-%m-%d %H:%M") if t else ""


def export(report_dir, checks, results, findings, analysis, is_admin, security=None, drives=None, ram=None):
    score, crit, warn = health_score(findings)
    pc = os.environ.get("COMPUTERNAME", "PC")
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    h = ['<!DOCTYPE html><html><head><meta charset="utf-8"><title>WinDiag - %s</title><style>%s</style></head><body>' % (escape(pc), CSS),
         "<header><h1>WinDiag report - %s</h1><p>Generated %s &middot; WinDiag %s &middot; Admin: %s</p></header><main>" % (escape(pc), when, APP_VERSION, is_admin),
         '<div class="card"><span class="score">%d/100</span> %d critical &middot; %d warnings</div>' % (score, crit, warn),
         "<h2>Summary</h2><table><tr><th>Status</th><th>Area</th><th>Finding</th><th>Suggested action</th></tr>"]
    t = ["WinDiag report - %s - %s" % (pc, when), "Health score: %d/100 (%d critical, %d warnings)" % (score, crit, warn), "", "SUMMARY"]
    for f in sort_findings(findings):
        h.append('<tr class="%s"><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            escape(str(f.get("Status") or "")), escape(str(f.get("Status") or "")), escape(str(f.get("Area") or "")), escape(str(f.get("Finding") or "")),
            escape(str(f.get("Advice") or ""))))
        t.append("  [%-8s] %-10s %s" % (f.get("Status"), f.get("Area"), f.get("Finding")))
        if f.get("Advice"):
            t.append("              -> %s" % f["Advice"])
    h.append("</table>")

    # Event analysis
    if analysis:
        h.append("<h2>Event Analyzer - likely causes</h2>")
        t += ["", "=" * 90, "EVENT ANALYZER - LIKELY CAUSES (%d events analysed)" % analysis["total_events"], "=" * 90]
        for ins in analysis["insights"]:
            h.append('<div class="card"><b>Insight:</b> %s</div>' % escape(ins))
            t.append("  * " + ins)
        if not analysis["problems"]:
            h.append('<p class="note">No problem patterns found in the event logs.</p>')
            t.append("  No problem patterns found.")
        for p in analysis["problems"]:
            h.append('<div class="card prob %s"><span class="lk %s">%s</span><b>%s</b><p>%s</p><b>Evidence</b><ul>%s</ul><b>What to do</b><ol>%s</ol></div>' % (
                p["likelihood"], p["likelihood"], p["likelihood"], escape(p["name"]), escape(p["why"] + ((" If ignored: " + p["impact"]) if p.get("impact") else "")),
                "".join('<li class="ev">%s</li>' % escape(e) for e in p["evidence"]),
                "".join("<li>%s</li>" % escape(x) for x in p["fix"])))
            t += ["", "  [%s] %s (score %s)" % (p["likelihood"], p["name"], p["score"]), "    " + p["why"], "    Evidence:"]
            t += ["      - " + e for e in p["evidence"]]
            t += ["    What to do:"] + ["      %d. %s" % (i + 1, x) for i, x in enumerate(p["fix"])]
        insts = analysis.get("instances") or []
        if insts:
            h.append('<h3>Critical events</h3><p class="note">Hover an event for a quick explanation, click it for full details.</p>')
            t += ["", "  CRITICAL EVENTS"]
            for i in insts[:80]:
                tip = "%s | Means: %s | If ignored: %s" % (i["meaning"], i["explain"], i["impact"])
                cls = "CRITICAL" if i["severity"] == "CRITICAL" else "WARNING"
                h.append('<details class="ev-d %s" title="%s"><summary><span class="b %s">%s</span> %s &nbsp; <b>%s</b> &nbsp; <span class="note">%s</span></summary>'
                         '<div class="evbody"><p><b>What happened:</b> %s</p><p><b>What this event means:</b> %s</p>'
                         '<p><b>Correlates with:</b></p><ul>%s</ul><p><b>Points to:</b> %s</p>'
                         '<p><b>What is likely to happen:</b> %s</p><p><b>How to fix:</b></p><ol>%s</ol><p class="note">%s</p></div></details>' % (
                    cls, escape(tip), cls, i["severity"], _fmt_t(i["time"]), escape(i["title"]), escape((i.get("categories") or [""])[0]),
                    escape(i["meaning"]), escape(i["explain"]),
                    "".join("<li>%s</li>" % escape(x) for x in ([i["verdict"]] if i.get("verdict") else []) + list(i.get("related") or [])) or "<li>No other events around the same time.</li>",
                    escape(", ".join(i.get("categories") or [])), escape(i["impact"]),
                    "".join("<li>%s</li>" % escape(x) for x in i.get("fix") or []), escape(i.get("recurrence", ""))))
                t.append("    %s  [%s] %s -> %s" % (_fmt_t(i["time"]), i["severity"], i["title"], i.get("verdict") or (i.get("categories") or [""])[0]))
        rows = [{"Count": g["count"], "Last": _fmt_t(g["last"]), "Source": g["source"], "ID": g["id"], "Meaning": g["meaning"]} for g in analysis["matched"]]
        h.append("<h3>Recognised events</h3>" + _table(rows, ["Count", "Last", "Source", "ID", "Meaning"]))
        rows = [{"Time": _fmt_t(x["time"]), "Source": x["source"], "ID": x["id"], "What happened": x["what"]} for x in analysis["timeline"][:80]]
        h.append("<h3>Timeline (crashes, shutdowns, updates)</h3>" + _table(rows, ["Time", "Source", "ID", "What happened"]))
        rows = [{"Count": u["count"], "Last": _fmt_t(u["last"]), "Source": u["source"], "ID": u["id"], "Message": (u["msg"] or "")[:200]} for u in analysis["unknown"]]
        h.append('<h3>Errors not in the knowledge base</h3><p class="note">Search "&lt;source&gt; event &lt;id&gt;" online for these.</p>' + _table(rows, ["Count", "Last", "Source", "ID", "Message"]))
        rows = [{"Count": n["count"], "Source": n["source"], "ID": n["id"], "Meaning": n["meaning"]} for n in analysis["noise"]]
        h.append("<h3>Known harmless noise (ignored)</h3>" + _table(rows, ["Count", "Source", "ID", "Meaning"]))

    if drives:
        h.append("<h2>Drive Health</h2>")
        t += ["", "=" * 90, "DRIVE HEALTH", "=" * 90]
        for d in drives:
            v = d["verdict"]
            hl = "" if v["health"] is None else " - health %d%%" % v["health"]
            cls = {"CRITICAL": "CRITICAL", "CAUTION": "WARNING"}.get(v["status"], "OK")
            h.append('<div class="card"><b>Disk %s: %s</b> (%s, %s) &nbsp; <span class="b %s">%s%s</span><br>%s</div>' % (
                escape(str(d.get("number"))), escape(d.get("model") or ""), escape(v["kind"]), escape(d.get("serial") or ""), cls, v["status"], hl,
                " &middot; ".join("%s: %s" % (escape(k), escape(str(x))) for k, x in v["metrics"].items())))
            if v["findings"]:
                h.append("<ul>" + "".join("<li><b>%s</b> %s %s</li>" % (f["severity"], escape(f["title"]), escape(f.get("why") or "")) for f in v["findings"]) + "</ul>")
            t.append("  Disk %s %s (%s): %s%s" % (d.get("number"), d.get("model"), v["kind"], v["status"], hl))
            t += ["    [%s] %s" % (f["severity"], f["title"]) for f in v["findings"]]
            if v["fixes"] and v["status"] in ("CRITICAL", "CAUTION"):
                t.append("    What to do: " + "; ".join(v["fixes"][:5]))

    if ram and ram.get("info"):
        i, r = ram["info"], ram.get("test")
        h.append("<h2>Memory (RAM)</h2>")
        t += ["", "=" * 90, "MEMORY (RAM)", "=" * 90]
        rows = [{"Slot": (s or {}).get("slot") or "Slot %d" % (k + 1), "Size": "%g GB" % round(((s or {}).get("size") or 0) / (1 << 30), 1) if s else "empty",
                 "Speed": "%s / %s MT/s" % (s.get("configured"), s.get("speed")) if s else "", "Maker": (s or {}).get("maker") or "", "Part": (s or {}).get("part") or ""}
                for k, s in enumerate(i["slots"])]
        h.append(_table(rows, ["Slot", "Size", "Speed", "Maker", "Part"]))
        t += ["  %-12s %-8s %-18s %s %s" % (x["Slot"], x["Size"], x["Speed"], x["Maker"], x["Part"]) for x in rows]
        for f in i["findings"]:
            h.append("<p><b>%s</b> %s</p>" % (f["severity"], escape(f["title"])))
            t.append("  [%s] %s" % (f["severity"], f["title"]))
        if r:
            h.append('<div class="card"><b>RAM test: %s</b> - %s</div>' % (escape(r.get("verdict", "")), escape(r.get("text", ""))))
            t.append("  RAM test: %s - %s" % (r.get("verdict"), r.get("text")))

    if security:
        c = security["counts"]
        h.append("<h2>Security Scan</h2><p class=\"note\">%d critical &middot; %d warnings &middot; %d info. 'Suspicious' means worth checking, not confirmed malware.</p>" % (c["CRITICAL"], c["WARNING"], c["INFO"]))
        t += ["", "=" * 90, "SECURITY SCAN (%d critical, %d warnings, %d info)" % (c["CRITICAL"], c["WARNING"], c["INFO"]), "=" * 90]
        rows = [{"Severity": f["severity"], "Area": f["category"], "Finding": f["title"], "Why": f.get("why", ""), "What to do": f.get("advice", "")} for f in security["findings"]]
        h.append(_table(rows, ["Severity", "Area", "Finding", "Why", "What to do"]))
        for f in security["findings"]:
            t.append("  [%-8s] %-22s %s" % (f["severity"], f["category"], f["title"]))
            if f.get("advice"):
                t.append("              -> %s" % f["advice"])
        rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in security["entries"] if r["Verdict"] != "OK"]
        if rows:
            h.append("<h3>Flagged startup / persistence entries</h3>" + _table(rows, ["Verdict", "Type", "Name", "Program", "Signature", "Why"]))
            t += ["", "  FLAGGED STARTUP ENTRIES"] + ["    [%s] %s %s -> %s (%s)" % (r["Verdict"], r["Type"], r["Name"], r["Program"], r["Why"]) for r in rows]

    for ck in checks:
        key, title = (ck, ck) if isinstance(ck, str) else (ck[0], ck[1])
        secs = results.get(key)
        if isinstance(secs, dict):          # a whole check result instead of its section list
            secs = secs.get("sections")
        secs = [x for x in (secs or []) if isinstance(x, dict)]
        if not secs:
            continue
        h.append("<h2>%s</h2>" % escape(title))
        t += ["", "=" * 90, title.upper(), "=" * 90]
        for s in secs:
            h.append(_sec_html(s))
            t += ["", "-- " + s["title"], section_text(s, 0)]
    h.append("</main></body></html>")

    html_path = os.path.join(report_dir, "WinDiag-Report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(h))
    with open(os.path.join(report_dir, "WinDiag-Report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(t))
    return html_path
