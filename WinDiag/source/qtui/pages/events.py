"""Event Analyzer page + the event/finding explanation content used by other pages."""
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QTabWidget, QVBoxLayout, QWidget

import core
import event_kb
import guided
from .. import theme as T
from .. import widgets as W

CAT_TO_PLAYBOOK = {"DRIVER": "drivers", "USB": "drivers", "NETWORK": "drivers", "RAM": "hw", "CPU": "hw", "PCIE": "hw",
                   "GPU": "gpu", "NVME": "disk", "DISK": "disk", "FS": "disk", "SPACE": "disk", "POWER": "power",
                   "THERMAL": "power", "UPDATE": "wu", "SYSTEM": "bsod", "KERNEL": "bsod", "APP": "drivers", "BIOS": "hw"}
AREA_CATS = {"Hardware": ["CPU", "RAM", "PCIE", "THERMAL"], "Disks": ["NVME", "DISK", "FS"], "Storage": ["SPACE", "DISK", "FS"],
             "Drivers": ["DRIVER"], "Graphics": ["GPU"], "Apps": ["APP"], "Updates": ["UPDATE"], "Network": ["NETWORK"],
             "Memory": ["RAM"], "Active Directory": ["AD"], "Hyper-V": ["HYPERV"], "Cluster": ["CLUSTER"], "IIS": ["IIS"],
             "Backup": ["BACKUP"], "Server": ["AD", "IIS", "HYPERV", "CLUSTER", "SQL"], "Security": ["SECURITY"]}
LK = {"HIGH": "CRITICAL", "MEDIUM": "WARNING", "LOW": "INFO"}


def fmt_t(t):
    return t.strftime("%Y-%m-%d %H:%M") if hasattr(t, "strftime") else (t or "")


class EventsPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.analysis = None
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        self.lbl = W.label("Reads the System & Application event logs (7, 30 or 90 days).", "Body")
        bar.addWidget(self.lbl, 1)
        self.days = QComboBox()
        self.days.addItems(["7 days", "30 days", "90 days"])
        self.days.setCurrentIndex(1)
        bar.addWidget(self.days)
        self.btn = W.button("Analyze", self.analyze, "primary", icon="play")
        bar.addWidget(self.btn)
        v.addLayout(bar)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        v.addWidget(self.tabs, 1)
        self.sp_prob = W.ScrollPage(spacing=T.S4)
        self.tabs.addTab(self.sp_prob, "Likely problems")
        self.t_crit = W.DataTable(["Time", "Severity", "Event", "Likely cause", "What happened"], [140, 90, 280, 230, 500],
                                  on_open=self.event_popup, mono=("Time",), max_rows_visible=200)
        self.t_match = W.DataTable(["Count", "Last seen", "Category", "Source", "ID", "Meaning"], [70, 140, 170, 220, 70, 500],
                                   on_open=self.event_popup, mono=("Count", "Last seen", "ID"), max_rows_visible=200)
        self.t_time = W.DataTable(["Time", "Type", "Source", "ID", "What happened"], [140, 80, 240, 70, 600], on_open=self.event_popup,
                                  mono=("Time", "ID"), max_rows_visible=200)
        self.t_unknown = W.DataTable(["Count", "Last seen", "Source", "ID", "Message"], [70, 140, 240, 70, 600], on_open=self.event_popup,
                                     mono=("Count", "Last seen", "ID"), max_rows_visible=200)
        self.t_noise = W.DataTable(["Count", "Source", "ID", "Why it is ignored"], [70, 280, 70, 600], on_open=self.event_popup,
                                   mono=("Count", "ID"), max_rows_visible=200)
        for t, name, note in ((self.t_crit, "Critical events", "Every blue screen, crash and serious event, newest first. Double-click a row for what it means."),
                              (self.t_match, "Recognised events", ""), (self.t_time, "Timeline", ""), (self.t_unknown, "Unrecognised errors", ""),
                              (self.t_noise, "Harmless noise", "Events that look scary but are normal (e.g. DCOM 10016) - listed so you can ignore them.")):
            w = QWidget()
            lay = QVBoxLayout(w)
            lay.setContentsMargins(T.S5, T.S4, T.S5, T.S4)
            lay.setSpacing(T.S3)
            if note:
                lay.addWidget(W.label(note, "Muted", wrap=True))
            t.setMinimumHeight(200)
            t.setMaximumHeight(16777215)
            lay.addWidget(t, 1)
            self.tabs.addTab(w, name)

    def open_tab(self, name):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == name:
                self.tabs.setCurrentIndex(i)

    def analyze(self):
        d = int(self.days.currentText().split()[0])
        self.app.run_events(d)

    def set_analysis(self, a):
        self.analysis = a
        rows = self._crit_rows()
        crit = [r for r in rows if r["Severity"] == "CRITICAL"] or rows
        self.app.page("Errors").show_errors_table(crit)
        self.request_render()

    def _crit_rows(self):
        a = self.analysis or {}
        return [{"Time": fmt_t(i["time"]), "Severity": i["severity"], "Event": i["title"], "Likely cause": (i.get("categories") or ["-"])[0],
                 "What happened": i["meaning"], "_info": self.instance_content(i)} for i in a.get("instances", [])]

    # ------------------------------------------------------------------ render
    def render(self):
        a = self.analysis
        lay = self.sp_prob.lay
        W.clear_layout(lay)
        if not a:
            lay.addWidget(W.label("Not analysed yet - the scan fills this in, or click Analyze.", "Muted"))
            lay.addStretch(1)
            for t in (self.t_crit, self.t_match, self.t_time, self.t_unknown, self.t_noise):
                t.set_rows([])
            return
        self.lbl.setText("%d events analysed  ·  %d likely problem area(s)  ·  double-click any row for details" % (a["total_events"], len(a["problems"])))
        for ins in a.get("insights", []):
            lay.addWidget(W.Banner("Insight", ins, "INFO"))
        if not a["problems"]:
            lay.addWidget(W.Banner("No problem patterns found in the event logs for this period.", "", "OK"))
        for pr in a["problems"]:
            lay.addWidget(self._problem_panel(pr))
        lay.addStretch(1)
        rows, tags = [], []
        for g in a["matched"]:
            top = max(g["cats"].items(), key=lambda kv: kv[1])[0] if g["cats"] else ""
            rows.append({"Count": g["count"], "Last seen": fmt_t(g["last"]), "Category": event_kb.CATEGORIES.get(top, {}).get("name", "info") if top else "info",
                         "Source": g["source"], "ID": g["id"], "Meaning": g["meaning"], "_info": self.group_content(g)})
            w = max(g["cats"].values()) if g["cats"] else 0
            tags.append("CRITICAL" if w >= 8 else "WARNING" if w >= 4 else None)
        self.t_match.set_rows(rows, tags)
        rows = [{"Time": fmt_t(x["time"]), "Type": x["kind"], "Source": x["source"], "ID": x["id"], "What happened": x["what"],
                 "_info": self.timeline_content(x)} for x in a["timeline"]]
        self.t_time.set_rows(rows, ["CRITICAL" if r["Type"] == "crash" else None for r in rows])
        rows = self._crit_rows()
        self.t_crit.set_rows(rows, [r["Severity"] for r in rows])
        self.t_unknown.set_rows([{"Count": u["count"], "Last seen": fmt_t(u["last"]), "Source": u["source"], "ID": u["id"], "Message": u["msg"]}
                                 for u in a["unknown"]])
        self.t_noise.set_rows([{"Count": n["count"], "Source": n["source"], "ID": n["id"], "Why it is ignored": n["meaning"]} for n in a["noise"]])

    def _problem_panel(self, pr):
        st = LK.get(pr["likelihood"], "INFO")
        badge = W.Badge("%s LIKELIHOOD" % pr["likelihood"], st)
        p = W.Panel(pr["name"], actions=[W.label("score %s" % pr["score"], "Muted"), badge])
        p.add(W.label(pr["why"], "Value", wrap=True, sel=True))
        p.add(W.label("EVIDENCE", "Label"))
        ev = QLabel("\n".join("- " + e for e in pr["evidence"]))
        ev.setFont(T.mono(11))
        ev.setStyleSheet("color:%s;" % T.TEXT2)
        ev.setWordWrap(True)
        ev.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.add(ev)
        p.add(W.label("WHAT TO DO", "Label"))
        p.add(W.label("\n".join("%d. %s" % (i + 1, x) for i, x in enumerate(pr["fix"])), "Value", wrap=True, sel=True))
        if pr.get("impact"):
            p.add(W.colored("If ignored: " + pr["impact"], T.STATUS[st], 12))
        pid = CAT_TO_PLAYBOOK.get(pr["cat"])
        if pid and pid in guided.PLAYBOOK_BY_ID:
            p.add(W.hbox(W.button("Guided fix: %s" % guided.PLAYBOOK_BY_ID[pid]["title"], lambda p_=pid: self._guide(p_), icon="wand"), "stretch"))
        return p

    def _guide(self, pid):
        self.app.show_page("guided")
        self.app.guided.open_playbook(pid)

    # ------------------------------------------------------------------ explanation content
    def instance_content(self, i):
        return {"title": i["title"], "badge": i["severity"], "sub": "%s   |   %s  event %s" % (fmt_t(i["time"]), i["source"], i["id"]),
                "sections": [("What happened", i["meaning"]), ("What this event means", i["explain"]),
                             ("Correlates with", ([i["verdict"]] if i.get("verdict") else []) + list(i.get("related") or [])[:5]
                              or ["No other events were logged around the same time."]),
                             ("Points to", ", ".join(i.get("categories") or [])), ("What is likely to happen", i["impact"]),
                             ("How to fix", (i.get("fix") or [])[:5]), ("How often", i.get("recurrence", ""))]}

    def group_content(self, g):
        w = max(g["cats"].values()) if g.get("cats") else 0
        return {"title": g.get("label") or "%s %s" % (g["source"], g["id"]), "badge": "CRITICAL" if w >= 8 else ("WARNING" if w >= 4 else "INFO"),
                "sub": "%s event %s   |   %d time(s), last %s" % (g["source"], g["id"], g["count"], fmt_t(g["last"])),
                "sections": [("What happened", g["meaning"]), ("What this event means", g.get("explain", "")),
                             ("Points to", ", ".join(g.get("categories") or [])), ("What is likely to happen", g.get("impact", "")),
                             ("How to fix", (g.get("fix") or [])[:5]), ("How often", g.get("trend", ""))]}

    def timeline_content(self, x):
        if not x.get("explain"):
            return None
        return {"title": x["what"][:120], "badge": "CRITICAL" if x.get("kind") == "crash" else "INFO",
                "sub": "%s   |   %s event %s" % (fmt_t(x["time"]), x["source"], x["id"]),
                "sections": [("What this event means", x.get("explain", "")), ("Points to", ", ".join(x.get("categories") or [])),
                             ("What is likely to happen", x.get("impact", "")), ("How to fix", (x.get("fix") or [])[:5])]}

    def problem_content(self, p):
        a = self.analysis or {}
        ex = [i for i in a.get("instances", []) if {p["name"]} & set(i.get("categories") or [])][:5]
        return {"title": p["name"], "badge": p["likelihood"], "sub": "Likelihood %s (score %s)" % (p["likelihood"], p["score"]),
                "sections": [("Why", p["why"]), ("What is likely to happen", p.get("impact", "")),
                             ("Key events", ["%s  %s" % (fmt_t(i["time"]), i["title"]) for i in ex] or p["evidence"][:4]),
                             ("How to fix", p["fix"][:5])]}

    def finding_content(self, f):
        a = self.analysis
        if not a:
            return None
        area = f.get("Area") or ""
        if area == "Event log":
            for p in a.get("problems", []):
                if p["name"] in (f.get("Finding") or ""):
                    return self.problem_content(p)
            return None
        insts = a.get("instances", [])
        txt = (f.get("Finding") or "").lower()
        if area == "Crashes" and "blue screen" in txt:
            ex = [i for i in insts if i["title"].startswith("Blue screen")]
        elif area == "Crashes" and ("shutdown" in txt or "restart" in txt):
            ex = [i for i in insts if re.match(r"(Sudden power loss|Frozen|Crash restart)", i["title"])]
        elif area == "Crashes":
            ex = [i for i in insts if i["severity"] == "CRITICAL" and re.search(r"(Blue screen|Crash|power loss|Frozen|Memory test)", i["title"], re.I)]
        elif area in AREA_CATS:
            names = {event_kb.CATEGORIES[c]["name"] for c in AREA_CATS[area] if c in event_kb.CATEGORIES}
            ex = [i for i in insts if names & set(i.get("categories") or [])]
        else:
            return None
        if not ex:
            return None
        first = ex[0]
        return {"title": f.get("Finding", ""), "badge": f.get("Status"), "sub": "%d related event(s) in the event log" % len(ex),
                "sections": [("Events found", ["%s  %s%s" % (fmt_t(i["time"]), i["title"], ("  -  " + i["verdict"]) if i.get("verdict") else "") for i in ex[:5]]),
                             ("What it means", first["explain"]), ("What is likely to happen", first["impact"]),
                             ("How to fix", (first.get("fix") or [])[:5])],
                "foot": "Event Analyzer > Critical events has every event with full details."}

    def event_popup(self, row):
        if not row:
            return
        if row.get("_info"):
            text = self.app.content_text(row["_info"])
            text += "\n\nSearch online: the stop code, or \"<source> event <id>\" shown above."
        else:
            text = "\n".join("%s:\n  %s\n" % (k, core.cell(v, 0)) for k, v in row.items() if not str(k).startswith("_"))
            if row.get("Source") and row.get("ID"):
                text += "\nSearch online:  \"%s\" event %s\n" % (row["Source"], row["ID"])
        self.app.text_popup("Event details", text)
