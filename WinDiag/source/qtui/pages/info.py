"""Pages for the classic checks (System, Disks, Errors, Network, Startup, Security, Server, Virt)."""
import re
import time

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

import core
from .. import theme as T
from .. import widgets as W

BAD = re.compile(r"(?i)^(failed|unhealthy|not installed|error|degraded|lost communication|critical|no reply)$")
WARNISH = re.compile(r"(?i)^(warning|stopped|disabled|off|never|not activated.*)$")
STATUS_COLS = {"Status", "Result", "Health", "State", "Enabled", "Verdict", "Protection", "Up to date"}
MONO_HINT = re.compile(r"(?i)(size|free|%|ms|mhz|gb|mb|time|date|id$|build|version|count|speed|temp|hours|ip|mac|pid|port|serial|kb)")


class InfoPage(W.Page):
    def __init__(self, app, key, title):
        super().__init__(app)
        self.key, self.title = key, title
        self.res = None
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, 0)
        self.lbl_state = W.label("Waiting for the scan...", "Body")
        bar.addWidget(self.lbl_state, 1)
        bar.addWidget(W.button("Re-run", lambda: app.run_one(key), icon="refresh"))
        bar.addWidget(W.button("Copy text", self.copy, icon="copy"))
        v.addLayout(bar)
        self.sp = W.ScrollPage()
        v.addWidget(self.sp, 1)
        self.err_rows = []

    # data in -----------------------------------------------------------------------------------
    def set_result(self, res):
        self.res = res if isinstance(res, dict) else None
        self.request_render()

    def set_waiting(self, text):
        self.res = None
        self.lbl_state.setText(text)
        self.request_render()

    def show_errors_table(self, rows):
        """Errors page: critical events from the Event Analyzer (rows already formatted)."""
        self.err_rows = list(rows or [])
        self.request_render()

    # drawing -----------------------------------------------------------------------------------
    def render(self):
        lay = self.sp.lay
        W.clear_layout(lay)
        res = self.res
        if self.key == "Errors" and self.err_rows:
            p = W.Panel("Critical events", "Newest first. Double-click a row for what it means and how to fix it.")
            t = W.DataTable(["Time", "Severity", "Event", "Likely cause"], [140, 100, 360, 300], on_open=self.app.page("events").event_popup,
                            mono=("Time",), max_rows_visible=6)
            t.set_rows(self.err_rows[:50], [r.get("Severity") for r in self.err_rows[:50]])
            p.add(t)
            lay.addWidget(p)
        if res is None:
            lay.addWidget(W.label("Not checked yet - this page fills in when the scan reaches it (or click Re-run).", "Muted"))
            lay.addStretch(1)
            return
        secs = res.get("sections") or []
        finds = [f for f in res.get("findings") or [] if f.get("Status") in ("CRITICAL", "WARNING")]
        self.lbl_state.setText("%d section(s)   ·   %s   ·   checked at %s" % (
            len(secs), ("%d issue(s) found" % len(finds)) if finds else "no issues found", time.strftime("%H:%M")))
        if res.get("error"):
            lay.addWidget(W.Banner("This check could not run", str(res["error"])[:400], "CRITICAL"))
        if finds:
            p = W.Panel("Findings")
            p.add(W.FindingsList([(f["Status"], f.get("Finding") or "", f.get("Advice") or "") for f in core.sort_findings(finds)]))
            lay.addWidget(p)
        for s in secs:
            try:
                lay.addWidget(self._section(s))
            except Exception as e:
                core.log_error("info section %s" % s.get("title"), e)
        if not secs and not res.get("error"):
            lay.addWidget(W.label("Nothing to show for this PC.", "Muted"))
        lay.addStretch(1)

    def _section(self, s):
        data = s.get("data") or []
        rows = [d for d in data if isinstance(d, dict)]
        p = W.Panel(s.get("title") or "", s.get("note") or None)
        if rows and not s.get("list"):
            p.add_action(W.label("%d item(s)" % len(rows), "Muted"))
        if not data:
            p.add(W.Dot("OK", "Nothing found", 12))
            return p
        if all(isinstance(d, str) for d in data):
            from PySide6.QtWidgets import QPlainTextEdit
            t = QPlainTextEdit("\n".join(data))
            t.setReadOnly(True)
            t.setFont(T.mono(12))
            t.setFixedHeight(min(260, 20 * len(data) + 20))
            p.add(t)
            return p
        if s.get("list"):
            for r in rows:
                pairs = []
                for k, v in r.items():
                    val = core.cell(v, 0).strip()
                    col = T.CRIT if BAD.match(val) else (T.WARN if WARNISH.match(val) else None)
                    pairs.append((k, val, {"color": col, "mono": bool(MONO_HINT.search(k))} if (col or MONO_HINT.search(k)) else {}))
                g = W.KeyValueGrid(cols=3 if len(pairs) > 6 else 2)
                g.set(pairs)
                p.add(g)
            return p
        cols = []
        for r in rows:
            for k in r:
                if k not in cols and not str(k).startswith("_"):
                    cols.append(k)
        widths = []
        for k in cols:
            mx = max([len(k)] + [len(core.cell(r.get(k), 80)) for r in rows[:50]])
            widths.append(max(80, min(440, max(len(k) * 8 + 36, mx * 8 + 36))))
        t = W.DataTable(cols, widths, mono=[c for c in cols if MONO_HINT.search(c)], max_rows_visible=10,
                        on_open=lambda r: self.app.text_popup(s.get("title") or self.title,
                                                              "\n".join("%s: %s" % (k, core.cell(v, 0)) for k, v in r.items() if not str(k).startswith("_"))))
        tags = []
        for r in rows:
            vals = [core.cell(v, 0).strip() for v in r.values()]
            tags.append("CRITICAL" if any(BAD.match(v) for v in vals) else ("WARNING" if any(r.get(k) is not None and WARNISH.match(core.cell(r.get(k), 0).strip())
                                                                                         for k in STATUS_COLS) else None))
        t.set_rows(rows, tags)
        p.body.setContentsMargins(0, 0, 0, 0)
        p.add(t)
        return p

    def copy(self):
        if not self.res:
            return
        import appsettings as S
        txt = "\n\n".join(core.section_text(s) for s in self.res.get("sections") or [])
        self.app.copy_text(S.redact(txt, self.app))
