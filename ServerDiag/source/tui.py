"""Full-screen terminal UI (curses, stdlib). Works over SSH, in tmux/screen and on VM consoles."""
import curses
import textwrap
import threading
import time

from .common import VERSION, sort_findings, all_findings, section_lines

SPIN = "|/-\\"
STATUS_ABBR = {"CRITICAL": "CRIT", "WARNING": "WARN", "INFO": "INFO", "OK": " OK "}


class Colors(object):
    def __init__(self):
        self.ok = curses.has_colors()
        if self.ok:
            curses.start_color()
            try:
                curses.use_default_colors()
                bg = -1
            except curses.error:
                bg = curses.COLOR_BLACK
            pairs = {1: (curses.COLOR_RED, bg), 2: (curses.COLOR_YELLOW, bg), 3: (curses.COLOR_CYAN, bg), 4: (curses.COLOR_GREEN, bg),
                     5: (curses.COLOR_WHITE, curses.COLOR_BLUE), 6: (curses.COLOR_BLACK, curses.COLOR_CYAN), 7: (curses.COLOR_MAGENTA, bg),
                     8: (curses.COLOR_WHITE, curses.COLOR_RED), 9: (curses.COLOR_BLACK, curses.COLOR_YELLOW), 10: (curses.COLOR_BLACK, curses.COLOR_GREEN),
                     11: (curses.COLOR_WHITE, curses.COLOR_BLUE), 12: (curses.COLOR_BLUE, bg)}
            for k, (f, b) in pairs.items():
                try:
                    curses.init_pair(k, f, b)
                except curses.error:
                    pass

    def p(self, n, extra=0):
        return (curses.color_pair(n) if self.ok else 0) | extra

    @property
    def red(self): return self.p(1, curses.A_BOLD)
    @property
    def yellow(self): return self.p(2, curses.A_BOLD)
    @property
    def cyan(self): return self.p(3, curses.A_BOLD)
    @property
    def green(self): return self.p(4, curses.A_BOLD)
    @property
    def header(self): return self.p(5, curses.A_BOLD)
    @property
    def tab_on(self): return self.p(6, curses.A_BOLD)
    @property
    def dim(self): return curses.A_DIM
    @property
    def bold(self): return curses.A_BOLD

    def status(self, st):
        return {"CRITICAL": self.p(8, curses.A_BOLD), "WARNING": self.p(9, curses.A_BOLD), "OK": self.p(10, curses.A_BOLD),
                "INFO": self.p(11, curses.A_BOLD), "HIGH": self.p(8, curses.A_BOLD), "MEDIUM": self.p(9, curses.A_BOLD),
                "LOW": self.p(11, curses.A_BOLD)}.get(st, 0)

    def score(self, s):
        return self.green if s >= 85 else (self.yellow if s >= 60 else self.red)


def _wrap(text, width, indent=0):
    width = max(20, width - indent)
    return textwrap.wrap(text or "", width) or [""]


# ---------------------------------------------------------------------------------
#  Build page content (list of lines; each line = list of (text, attr))
# ---------------------------------------------------------------------------------
def page_summary(r, C, W):
    L = []
    L.append([("Host: ", C.dim), (r["host"], C.bold), ("   OS: ", C.dim), (r.get("os", ""), 0), ("   Platform: ", C.dim), (r.get("virt") or "-", 0)])
    L.append([("Generated: ", C.dim), (r.get("generated", ""), 0), ("   Privileges: ", C.dim),
              ("root/admin" if r.get("admin") else "LIMITED (run with sudo / as admin)", C.green if r.get("admin") else C.yellow)])
    L.append([])
    L.append([("  HEALTH SCORE  ", C.header), ("  ", 0), ("%3d / 100" % r["score"], C.score(r["score"])),
              ("    %d critical   %d warnings" % (r["critical"], r["warnings"]), C.bold)])
    if r.get("error"):
        L.append([("  " + r["error"], C.red)])
    if r.get("failed_checks"):
        L.append([("  Checks that could not run: " + ", ".join(r["failed_checks"]), C.yellow)])
    L.append([])
    for f in sort_findings(all_findings(r)):
        st = f.get("Status", "INFO")
        lines = _wrap(f.get("Finding", ""), W, 22)
        L.append([(" %s " % STATUS_ABBR.get(st, st[:4]), C.status(st)), (" %-14s " % (f.get("Area") or "")[:14], C.dim), (lines[0], C.bold)])
        for x in lines[1:]:
            L.append([(" " * 22, 0), (x, C.bold)])
        if f.get("Advice"):
            for i, x in enumerate(_wrap(f["Advice"], W, 25)):
                L.append([(" " * 22, 0), ("-> " if i == 0 else "   ", C.dim), (x, 0)])
        L.append([])
    return L


def page_check(c, C, W):
    L = []
    if c.get("error"):
        L.append([("Check error: " + c["error"].replace("\n", " ")[:W * 2], C.red)])
        L.append([])
    for f in sort_findings(c.get("findings") or []):
        st = f.get("Status", "INFO")
        L.append([(" %s " % STATUS_ABBR.get(st, st[:4]), C.status(st)), (" " + f.get("Finding", ""), C.bold)])
    if c.get("findings"):
        L.append([])
    for s in c.get("sections", []):
        L.append([("> " + s["title"], C.cyan)])
        if s.get("note"):
            for x in _wrap(s["note"], W, 2):
                L.append([("  " + x, C.dim)])
        for line in section_lines(s, 60):
            L.append([(line, 0)])
        L.append([])
    return L


LOG_VIEWS = [("p", "Problems"), ("m", "Recognised"), ("t", "Timeline"), ("u", "Unrecognised"), ("n", "Noise"), ("b", "Boots")]


def page_logs(r, C, W, view):
    a = r.get("analysis")
    L = []
    if not a:
        return [[("No log analysis available.", C.yellow)]]
    bar = [("View: ", C.dim)]
    for k, name in LOG_VIEWS:
        bar.append((" [%s] %s " % (k, name), C.tab_on if k == view else C.dim))
    L.append(bar)
    L.append([("%s events analysed from %s over %s days" % (a.get("total_events", 0), a.get("source", "?"), a.get("days", "?")), C.dim)])
    L.append([])
    if view == "p":
        for ins in a.get("insights", []):
            for i, x in enumerate(_wrap(ins, W, 11)):
                L.append([(" INSIGHT " if i == 0 else "         ", C.p(11, curses.A_BOLD) if i == 0 else 0), ("  " + x, 0)])
            L.append([])
        if not a.get("problems"):
            L.append([("  No problem patterns found in the logs.", C.green)])
        for p in a.get("problems", []):
            L.append([(" %-6s " % p["likelihood"], C.status(p["likelihood"])), ("  " + p["name"], C.bold), ("   score %s" % p["score"], C.dim)])
            for x in _wrap(p["why"], W, 4):
                L.append([("    " + x, 0)])
            L.append([("    Evidence:", C.cyan)])
            for e in p["evidence"]:
                for i, x in enumerate(_wrap(e, W, 8)):
                    L.append([("      " + ("- " if i == 0 else "  ") + x, C.dim)])
            L.append([("    What to do:", C.cyan)])
            for n, fx in enumerate(p["fix"]):
                for i, x in enumerate(_wrap(fx, W, 9)):
                    L.append([("      " + ("%d. " % (n + 1) if i == 0 else "   ") + x, 0)])
            L.append([])
    elif view == "m":
        L.append([("  %5s  %-16s  %-26s  %s" % ("Count", "Last", "Category", "Meaning"), C.bold)])
        for g in a.get("matched", []):
            attr = C.red if g.get("weight", 0) >= 8 else (C.yellow if g.get("weight", 0) >= 4 else 0)
            L.append([("  %5d  %-16s  %-26s  " % (g["count"], g["last"], g["category"][:26]), 0), (g["meaning"], attr)])
            L.append([("         %s" % g["source"], C.dim)])
    elif view == "t":
        for x in a.get("timeline", []):
            attr = C.red if x["kind"] == "crash" else (C.cyan if x["kind"] == "update" else 0)
            L.append([("  %-16s  %-6s " % (x["time"], x["kind"]), C.dim), (x["what"], attr)])
    elif view == "u":
        L.append([("  Errors that are not in the knowledge base (search them online):", C.dim)])
        for u in a.get("unknown", []):
            L.append([("  %5dx  %-16s  %s" % (u["count"], u["last"], u["source"]), C.bold)])
            for x in _wrap(u["msg"], W, 10)[:3]:
                L.append([("          " + x, 0)])
    elif view == "n":
        L.append([("  Known harmless messages (not counted):", C.dim)])
        for n in a.get("noise", []):
            L.append([("  %6dx  " % n["count"], C.dim), (n["meaning"], 0)])
    elif view == "b":
        if not a.get("boots"):
            L.append([("  No boot history (journal not persistent, or Windows host).", C.dim)])
        for b in a.get("boots", []):
            st = "clean" if b["clean"] else ("CRASH" if b["panic"] else "UNCLEAN")
            L.append([("  boot %4s  %s -> %s  " % (b["boot"], b["start"], b["end"]), 0), (st, C.green if b["clean"] else C.red)])
    return L


# ---------------------------------------------------------------------------------
#  Viewer
# ---------------------------------------------------------------------------------
class Viewer(object):
    def __init__(self, scr, results, rerun=None, save=None, fleet=False):
        self.scr, self.results, self.rerun, self.save, self.fleet = scr, results, rerun, save, fleet
        self.C = Colors()
        self.msg = ""
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        self.scr.keypad(True)

    # drawing helpers
    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        try:
            self.scr.addnstr(y, x, text, max(0, w - x - (1 if y == h - 1 else 0)), attr)
        except curses.error:
            pass

    def line(self, y, segs):
        x = 0
        h, w = self.scr.getmaxyx()
        for text, attr in segs:
            if x >= w:
                break
            self.put(y, x, text, attr)
            x += len(text)

    def bar(self, y, text, attr):
        h, w = self.scr.getmaxyx()
        self.put(y, 0, text.ljust(w), attr)

    # host view
    def host(self, r):
        tabs = [("summary", "Summary")] + [(k, r["checks"][k]["title"]) for k in r.get("order", []) if k in r["checks"]] + [("logs", r.get("analysis_title", "Logs"))]
        cur, scroll, view = 0, {}, "p"
        while True:
            h, w = self.scr.getmaxyx()
            key = tabs[cur][0]
            if key == "summary":
                content = page_summary(r, self.C, w - 2)
            elif key == "logs":
                content = page_logs(r, self.C, w - 2, view)
            else:
                content = page_check(r["checks"][key], self.C, w - 2)
            self.scr.erase()
            self.bar(0, " ServerDiag %s  |  %s  |  %s  |  score %d/100" % (VERSION, r["host"], r.get("os", ""), r["score"]), self.C.header)
            x = 0
            for i, (k, name) in enumerate(tabs):
                label = " %d %s " % ((i + 1) % 10, name) if i < 10 else " %s " % name
                fs = r["checks"].get(k, {}).get("findings", []) if k not in ("summary", "logs") else []
                bad = any(f.get("Status") == "CRITICAL" for f in fs)
                warn = any(f.get("Status") == "WARNING" for f in fs)
                attr = self.C.tab_on if i == cur else (self.C.red if bad else (self.C.yellow if warn else 0))
                self.put(1, x, label, attr)
                x += len(label) + 1
            body_h = h - 3
            top = max(0, min(scroll.get(key + view, 0), max(0, len(content) - body_h)))
            scroll[key + view] = top
            for i, segs in enumerate(content[top:top + body_h]):
                self.line(2 + i, [(" ", 0)] + segs)
            more = "" if len(content) <= body_h else "  [%d-%d of %d]" % (top + 1, min(len(content), top + body_h), len(content))
            help_ = " <-/-> tabs  up/dn/PgUp/PgDn scroll  s save report%s%s  q %s " % (
                "  r rerun" if self.rerun else "", "  p/m/t/u/n/b views" if key == "logs" else "", "back" if self.fleet else "quit")
            self.bar(h - 1, (self.msg + "  " if self.msg else "") + help_ + more, self.C.header)
            self.scr.refresh()
            c = self.scr.getch()
            self.msg = ""
            if c in (ord("q"), 27, curses.KEY_BACKSPACE, 127) and (self.fleet or c == ord("q")):
                return "back"
            if c in (curses.KEY_RIGHT, 9, ord("l")):
                cur = (cur + 1) % len(tabs)
            elif c in (curses.KEY_LEFT, curses.KEY_BTAB, ord("h")):
                cur = (cur - 1) % len(tabs)
            elif ord("1") <= c <= ord("9") and c - ord("1") < len(tabs):
                cur = c - ord("1")
            elif c == ord("0") and len(tabs) >= 10:
                cur = 9
            elif c in (curses.KEY_DOWN, ord("j")):
                scroll[key + view] = top + 1
            elif c in (curses.KEY_UP, ord("k")):
                scroll[key + view] = max(0, top - 1)
            elif c in (curses.KEY_NPAGE, ord(" ")):
                scroll[key + view] = top + body_h - 1
            elif c == curses.KEY_PPAGE:
                scroll[key + view] = max(0, top - body_h + 1)
            elif c in (curses.KEY_HOME, ord("g")):
                scroll[key + view] = 0
            elif c in (curses.KEY_END, ord("G")):
                scroll[key + view] = len(content)
            elif key == "logs" and c in [ord(k) for k, _ in LOG_VIEWS]:
                view = chr(c)
            elif c == ord("s") and self.save:
                self.msg = self.save()
            elif c == ord("r") and self.rerun:
                return "rerun"
            elif c == curses.KEY_RESIZE:
                pass

    # fleet view
    def fleet_view(self):
        sel, top = 0, 0
        while True:
            rs = sorted(self.results, key=lambda r: (r["score"], r["host"]))
            h, w = self.scr.getmaxyx()
            self.scr.erase()
            crit = sum(1 for r in rs if r["score"] < 60)
            self.bar(0, " ServerDiag %s  |  FLEET: %d hosts  |  %d need attention" % (VERSION, len(rs), crit), self.C.header)
            self.put(2, 1, "%-28s %-30s %6s %5s %5s  %s" % ("HOST", "OS", "SCORE", "CRIT", "WARN", "TOP ISSUE / LIKELY CAUSE"), self.C.bold)
            body = h - 5
            if sel < top:
                top = sel
            if sel >= top + body:
                top = sel - body + 1
            for i, r in enumerate(rs[top:top + body]):
                idx = top + i
                probs = (r.get("analysis") or {}).get("problems") or []
                fs = [f for f in sort_findings(all_findings(r)) if f.get("Status") in ("CRITICAL", "WARNING")]
                issue = r.get("error") or (fs[0]["Finding"] if fs else (probs[0]["name"] if probs else "no issues"))
                y = 3 + i
                base = curses.A_REVERSE if idx == sel else 0
                self.put(y, 1, "%-28s %-30s " % (r["host"][:28], (r.get("os") or "")[:30]), base)
                self.put(y, 61, "%6s" % (("%d" % r["score"]) if not r.get("error") else "ERR"), self.C.score(r["score"]) | base)
                self.put(y, 67, " %5d %5d  " % (r["critical"], r["warnings"]), base)
                self.put(y, 81, issue[: max(0, w - 83)], (self.C.red if r["critical"] else (self.C.yellow if r["warnings"] else 0)) | base)
            self.bar(h - 1, (self.msg + "  " if self.msg else "") + " up/dn select  Enter open host  s save fleet report  q quit ", self.C.header)
            self.scr.refresh()
            c = self.scr.getch()
            self.msg = ""
            if c == ord("q"):
                return
            if c in (curses.KEY_DOWN, ord("j")):
                sel = min(len(rs) - 1, sel + 1)
            elif c in (curses.KEY_UP, ord("k")):
                sel = max(0, sel - 1)
            elif c == curses.KEY_NPAGE:
                sel = min(len(rs) - 1, sel + body)
            elif c == curses.KEY_PPAGE:
                sel = max(0, sel - body)
            elif c in (10, 13, curses.KEY_ENTER, curses.KEY_RIGHT):
                self.host(rs[sel])
            elif c == ord("s") and self.save:
                self.msg = self.save()


def loading(scr, title, worker):
    """Run worker(progress_cb) in a thread while showing a spinner. Returns worker result."""
    C = Colors()
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    state = {"msg": "Starting...", "done": False, "res": None, "err": None, "log": []}

    def prog(*a):
        if len(a) == 1:
            state["msg"] = a[0]
        else:
            done, total, r = a
            state["msg"] = "%d / %d hosts done" % (done, total)
            state["log"].append("%-30s score %s%s" % (r["host"], r["score"], ("  ERROR: " + r["error"][:60]) if r.get("error") else ""))

    def run():
        try:
            state["res"] = worker(prog)
        except Exception as e:
            import traceback
            state["err"] = traceback.format_exc()
        state["done"] = True
    th = threading.Thread(target=run)
    th.daemon = True
    th.start()
    scr.nodelay(True)
    i = 0
    t0 = time.time()
    while not state["done"]:
        h, w = scr.getmaxyx()
        scr.erase()
        try:
            scr.addnstr(0, 0, (" ServerDiag %s  |  %s" % (VERSION, title)).ljust(w), w - 1, C.header)
            scr.addnstr(2, 2, "%s  %s   (%ds)" % (SPIN[i % 4], state["msg"], time.time() - t0), w - 3, C.bold)
            for j, l in enumerate(state["log"][-(h - 6):]):
                scr.addnstr(4 + j, 4, l, w - 5)
            scr.addnstr(h - 1, 0, " q = abort ".ljust(w - 1), w - 1, C.header)
        except curses.error:
            pass
        scr.refresh()
        c = scr.getch()
        if c == ord("q"):
            scr.nodelay(False)
            return None
        time.sleep(0.12)
        i += 1
    scr.nodelay(False)
    if state["err"]:
        raise RuntimeError(state["err"])
    return state["res"]
