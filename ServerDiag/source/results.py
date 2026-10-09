"""Build the common result structure for Linux (local) and Windows (remote) hosts."""
import json
import os
import socket
from datetime import datetime

from .common import VERSION, health_score, all_findings

LK_STATUS = {"HIGH": "CRITICAL", "MEDIUM": "WARNING", "LOW": "INFO"}
WIN_TITLES = [("System", "System"), ("Disks", "Disks"), ("Errors", "Errors & Crashes"), ("Network", "Network"),
              ("Startup", "Startup & Processes"), ("Security", "Security & Updates"), ("Server", "Server Roles"), ("Virt", "Virtualization")]


def analysis_findings(analysis, area="Log analyzer"):
    out = []
    if not analysis:
        return out
    for p in analysis.get("problems", []):
        out.append({"Status": LK_STATUS[p["likelihood"]], "Area": area,
                    "Finding": "Likely cause: %s (%s likelihood)" % (p["name"], p["likelihood"]),
                    "Advice": "See Log Analyzer. First step: " + (p["fix"][0] if p.get("fix") else "")})
    if not analysis.get("problems"):
        out.append({"Status": "OK", "Area": area, "Finding": "No problem patterns in the logs (%s days)" % analysis.get("days", "?"), "Advice": ""})
    return out


def finalize(result):
    for k, v in (result.get("checks") or {}).items():
        if v.get("error") and not v.get("_errflag"):
            v.setdefault("findings", []).append({"Status": "WARNING", "Area": v.get("title", k), "Finding": "Check could not run: %s" % str(v["error"]).strip().splitlines()[0][:150],
                                                 "Advice": "Run as root/Administrator; some tools may be missing on this host."})
            v["_errflag"] = True
    score, c, w = health_score(all_findings(result))
    if result.get("error"):
        score = 0
    result["score"], result["critical"], result["warnings"] = score, c, w
    failed = [k for k, v in result.get("checks", {}).items() if v.get("error")]
    result["failed_checks"] = failed
    return result


def build_linux_result(days=7, progress=None, target=None):
    from . import linux_collect, log_kb
    ctx, checks = linux_collect.collect(progress)
    if progress:
        progress("Analyzing logs (%d days)..." % days)
    try:
        logs = log_kb.collect_logs(days, progress)
        analysis = log_kb.analyze(logs, ctx)
    except Exception as e:
        analysis = {"total_events": 0, "problems": [], "insights": ["Log analysis failed: %s" % e], "matched": [], "unknown": [],
                    "noise": [], "timeline": [], "boots": [], "days": days, "source": "error"}
    osr = ctx["os"]
    res = {
        "tool": "ServerDiag %s" % VERSION, "os_family": "linux", "host": target or socket.gethostname(),
        "hostname": socket.gethostname(), "os": osr.get("PRETTY_NAME", "Linux"), "virt": ctx["virt"],
        "admin": hasattr(os, "geteuid") and os.geteuid() == 0, "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "order": [k for k, _, _ in linux_collect.CHECKS], "checks": checks,
        "analysis": analysis, "analysis_title": "Log Analyzer", "analysis_findings": analysis_findings(analysis), "error": None,
    }
    return finalize(res)


def _t(x):
    if hasattr(x, "strftime"):
        return x.strftime("%Y-%m-%d %H:%M")
    return x or ""


def convert_windows(raw, target):
    """raw = JSON from the PowerShell collector in 'All' mode."""
    from . import win_kb
    checks = {}
    for key, title in WIN_TITLES:
        c = (raw.get("checks") or {}).get(key) or {}
        secs = c.get("sections") or []
        if isinstance(secs, dict):
            secs = [secs]
        norm = []
        for s in secs:
            d = s.get("data")
            if d is None:
                d = []
            if not isinstance(d, list):
                d = [d]
            norm.append({"title": s.get("title", ""), "note": s.get("note") or "", "list": bool(s.get("list")), "data": d})
        f = c.get("findings") or []
        if isinstance(f, dict):
            f = [f]
        checks[key] = {"title": title, "sections": norm, "findings": f, "error": c.get("error")}
    events = raw.get("events") or []
    if isinstance(events, dict):
        events = events.get("value", [events])
    is_server = "Server" in (raw.get("os") or "")
    a = win_kb.analyze(events, server=is_server)
    analysis = {
        "total_events": a["total_events"], "source": "Windows event logs", "days": raw.get("days"),
        "problems": a["problems"], "insights": a["insights"],
        "matched": [{"count": g["count"], "last": _t(g["last"]), "source": "%s %s" % (g["source"], g["id"]), "meaning": g["meaning"],
                     "category": win_kb.CATEGORIES.get(max(g["cats"], key=g["cats"].get), {}).get("name", "info") if g["cats"] else "info",
                     "weight": max(g["cats"].values()) if g["cats"] else 0, "sample": ""} for g in a["matched"]],
        "unknown": [{"count": u["count"], "last": _t(u["last"]), "source": "%s %s" % (u["source"], u["id"]), "msg": u.get("msg") or ""} for u in a["unknown"]],
        "noise": [{"count": n["count"], "last": _t(n.get("last")), "meaning": "%s %s: %s" % (n["source"], n["id"], n["meaning"])} for n in a["noise"]],
        "timeline": [{"time": _t(x["time"]), "kind": x.get("kind"), "source": "%s %s" % (x["source"], x["id"]), "what": x["what"]} for x in a["timeline"]],
        "boots": [],
    }
    res = {
        "tool": "ServerDiag %s" % VERSION, "os_family": "windows", "host": target, "hostname": raw.get("hostname") or target,
        "os": raw.get("os") or "Windows", "virt": "", "admin": bool(raw.get("admin")), "generated": raw.get("generated") or datetime.now().strftime("%Y-%m-%d %H:%M"),
        "order": [k for k, _ in WIN_TITLES], "checks": checks, "analysis": analysis, "analysis_title": "Event Analyzer",
        "analysis_findings": analysis_findings(analysis, "Event log"), "error": None,
    }
    for sec in checks.get("Virt", {}).get("sections", []):
        for row in sec.get("data", []):
            if isinstance(row, dict) and row.get("Platform"):
                res["virt"] = row["Platform"]
    return finalize(res)


def error_result(target, family, message):
    return finalize({"tool": "ServerDiag %s" % VERSION, "os_family": family, "host": target, "hostname": target, "os": "?", "virt": "",
                     "admin": False, "generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "order": [], "checks": {},
                     "analysis": None, "analysis_findings": [{"Status": "CRITICAL", "Area": "Connection", "Finding": message,
                                                              "Advice": "Check SSH access (key auth, BatchMode) and that python3 / PowerShell is available."}],
                     "error": message})


def dumps(result):
    return json.dumps(result, default=str)
