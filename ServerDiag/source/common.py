"""Shared helpers for ServerDiag (stdlib only, Python 3.6+)."""
import json
import os
import shutil
import subprocess

VERSION = "1.0"
ENV = dict(os.environ, LC_ALL="C", LANG="C", SYSTEMD_COLORS="0", SYSTEMD_PAGER="")

ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2, "OK": 3}


def run(cmd, timeout=25, input_text=None):
    """Run a command; returns (returncode, stdout). Never raises."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                             env=ENV, universal_newlines=True)
    except (OSError, ValueError):
        return 127, ""
    try:
        out, _ = p.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            out, _ = p.communicate(timeout=3)
        except Exception:
            out = ""
        return 124, out or ""
    return p.returncode, out or ""


def which(name):
    return shutil.which(name) or (os.path.exists("/usr/sbin/" + name) and "/usr/sbin/" + name) \
        or (os.path.exists("/sbin/" + name) and "/sbin/" + name) or None


def read(path, default=""):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return default


def section(title, data, as_list=False, note=""):
    if data is None:
        data = []
    if not isinstance(data, list):
        data = [data]
    return {"title": title, "note": note, "list": bool(as_list), "data": [d for d in data if d is not None]}


class Findings(object):
    def __init__(self):
        self.items = []

    def add(self, status, area, finding, advice=""):
        self.items.append({"Status": status, "Area": area, "Finding": finding, "Advice": advice})


def fmt_size(b):
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "?"
    for unit, div in (("TB", 1024 ** 4), ("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if b >= div:
            return "%.1f %s" % (b / div, unit)
    return "%d B" % b


def sort_findings(findings):
    return sorted(findings, key=lambda f: (ORDER.get(f.get("Status"), 9), f.get("Area") or ""))


def health_score(findings):
    c = sum(1 for f in findings if f.get("Status") == "CRITICAL")
    w = sum(1 for f in findings if f.get("Status") == "WARNING")
    return max(0, 100 - 20 * c - 6 * w), c, w


def all_findings(result):
    out = []
    for key in result.get("order", list(result.get("checks", {}).keys())):
        chk = result["checks"].get(key) or {}
        out.extend(chk.get("findings") or [])
    out.extend(result.get("analysis_findings") or [])
    return out


def cell(v, maxlen=70):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, list):
        v = ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        v = json.dumps(v)
    s = str(v).replace("\r", " ").replace("\n", " ")
    if maxlen and len(s) > maxlen:
        s = s[: maxlen - 3] + "..."
    return s


def section_lines(sec, maxlen=70):
    """Render a section's data as plain text lines."""
    data = sec.get("data") or []
    if not data:
        return ["  (nothing found)"]
    if all(isinstance(d, str) for d in data):
        return ["  " + d for d in data]
    rows = [d for d in data if isinstance(d, dict)]
    if not rows:
        return ["  " + cell(d, 0) for d in data]
    if sec.get("list"):
        out = []
        for r in rows:
            w = max(len(k) for k in r) if r else 0
            for k, v in r.items():
                out.append("  %s : %s" % (k.ljust(w), cell(v, 0)))
            out.append("")
        while out and not out[-1]:
            out.pop()
        return out
    cols = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    table = [[cell(r.get(c), maxlen) for c in cols] for r in rows]
    widths = [max([len(c)] + [len(t[i]) for t in table]) for i, c in enumerate(cols)]

    def line(vals):
        return ("  " + "  ".join(v.ljust(widths[i]) for i, v in enumerate(vals))).rstrip()
    out = [line(cols), "  " + "  ".join("-" * w for w in widths)]
    out += [line(t) for t in table]
    return out
