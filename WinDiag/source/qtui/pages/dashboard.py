"""Dashboard (home page): health overview, top issues, live performance, issue breakdown, component health, event activity.

Performance (same rules as 3.3):
  * render() compares a signature of everything the page shows - identical data -> nothing is redrawn.
  * During a scan the data-dependent parts are rebuilt at most every REBUILD_EVERY seconds; in between only the stat tiles,
    the severity donut and the progress are updated in place (no widgets created or destroyed).
  * Live CPU / memory are sampled in a worker thread; a 1 s QTimer (stopped in on_hide) draws them.
"""
import html
import os
import threading
import time
from datetime import datetime, timedelta

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QBoxLayout, QFrame, QGridLayout, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

import baseline as bl
import core
import facts as fx
import guided
from .. import tasks
from .. import theme as T
from .. import widgets as W

TILE_AREAS = {
    "windows": {"System", "Windows", "Updates", "Startup", "Services", "Apps", "Drivers", "Graphics", "Crashes", "Time"},
    "cpu": {"CPU", "Hardware"},
    "memory": {"Memory"},
    "storage": {"Disks", "Storage", "Drive health"},
    "security": {"Security", "Security scan", "Certificates"},
    "network": {"Network"},
}
REBUILD_EVERY = 6.0          # seconds between full rebuilds while a scan is running
ISSUES_SHOWN = 6
VCOL = {"better": T.OK, "worse": T.CRIT, "same": T.TEXT2, "n/a": T.MUTED}
VTXT = {"better": "better", "worse": "worse", "same": "no change", "n/a": ""}


# ---------------------------------------------------------------------------------
#  Private layout helpers (candidates for widgets.py - see the porting report)
# ---------------------------------------------------------------------------------
class _Reflow(QWidget):
    """Equal-width columns that re-flow (3 -> 2 -> 1) when the page gets narrow. Widgets are only re-placed, never rebuilt."""

    def __init__(self, min_w=250, max_cols=3, spacing=T.S4):
        super().__init__()
        self.min_w, self.max_cols, self.sp = min_w, max_cols, spacing
        self.g = QGridLayout(self)
        self.g.setContentsMargins(0, 0, 0, 0)
        self.g.setHorizontalSpacing(spacing)
        self.g.setVerticalSpacing(spacing)
        self.items, self.cols = [], 0
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)    # never force the page wider than the window

    def set_items(self, items):
        while self.g.count():
            self.g.takeAt(0)
        self.items = [w for w in items if w is not None]
        self.cols = 0
        self._place()

    def _ncols(self):
        w = self.width()
        n = max(1, (w + self.sp) // (self.min_w + self.sp)) if w > 60 else self.max_cols
        return max(1, min(self.max_cols, n, len(self.items) or 1))

    def _place(self):
        n = self._ncols()
        if n == self.cols:
            return
        while self.g.count():
            self.g.takeAt(0)
        self.cols = n
        for c in range(self.max_cols):
            self.g.setColumnStretch(c, 1 if c < n else 0)
        for i, w in enumerate(self.items):
            self.g.addWidget(w, i // n, i % n)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.items and self._ncols() != self.cols:
            self._place()


class _Split(QWidget):
    """Main column (2/3) + side column (1/3); stacks vertically when the page is narrow."""

    def __init__(self, min_w=880, spacing=T.S4):
        super().__init__()
        self.min_w = min_w
        self.box = QBoxLayout(QBoxLayout.LeftToRight, self)
        self.box.setContentsMargins(0, 0, 0, 0)
        self.box.setSpacing(spacing)
        self.left, self.right = QWidget(), QWidget()
        self.lv, self.rv = QVBoxLayout(self.left), QVBoxLayout(self.right)
        for v in (self.lv, self.rv):
            v.setContentsMargins(0, 0, 0, 0)
            v.setSpacing(spacing)
        self.box.addWidget(self.left, 2)
        self.box.addWidget(self.right, 1)
        self._vertical = False
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        vert = self.width() < self.min_w
        if vert != self._vertical:
            self._vertical = vert
            self.box.setDirection(QBoxLayout.TopToBottom if vert else QBoxLayout.LeftToRight)
            self.box.setStretch(0, 0 if vert else 2)
            self.box.setStretch(1, 0 if vert else 1)


class _StackedBars(QWidget):
    """Daily stacked bars (warnings below, critical on top) with date ticks every 7 days."""

    def __init__(self, height=130):
        super().__init__()
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.days, self.note = [], ""

    def set(self, days, note=""):
        """days = [(date, critical, warnings)]"""
        self.days, self.note = list(days), note
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.setFont(T.mono(10))
        if not self.days:
            p.setPen(QColor(T.MUTED))
            p.setFont(T.ui(12))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignCenter | Qt.TextWordWrap, self.note)
            p.end()
            return
        x0, x1, y0, y1 = 30, w - 4, 8, h - 20
        mx = max([c + wn for _, c, wn in self.days] + [1])
        for f in (0.5, 1.0):
            y = y1 - (y1 - y0) * f
            p.setPen(QPen(QColor(T.LINE_HEX), 1))
            p.drawLine(QPointF(x0, y), QPointF(x1, y))
            p.setPen(QColor(T.MUTED))
            p.drawText(QRectF(0, y - 8, x0 - 6, 16), Qt.AlignRight | Qt.AlignVCenter, str(int(round(mx * f))))
        n = len(self.days)
        bw = (x1 - x0) / float(n)
        gap = max(1.0, min(3.0, bw * 0.2))
        for k, (d, c, wn) in enumerate(self.days):
            x = x0 + k * bw
            hw = (y1 - y0) * wn / mx
            hc = (y1 - y0) * c / mx
            if wn:
                p.fillRect(QRectF(x + gap / 2, y1 - hw, bw - gap, hw), QColor(T.WARN))
            if c:
                p.fillRect(QRectF(x + gap / 2, y1 - hw - hc, bw - gap, hc), QColor(T.CRIT))
            if k % 7 == 0:
                p.setPen(QColor(T.MUTED))
                p.drawText(QRectF(x - 20, h - 17, 60, 16), Qt.AlignLeft | Qt.AlignVCenter, d.strftime("%d %b"))
        p.setPen(QPen(QColor(T.LINE_HEX), 1))
        p.drawLine(QPointF(x0, y1), QPointF(x1, y1))
        p.end()


def _vis(w, on):
    """setVisible only when the state changes (showing a child re-runs its size hint / parent layout - ~1 ms each)."""
    on = bool(on)
    if w.isHidden() == on:
        w.setVisible(on)


def _rich(text, color):
    return '<span style="color:%s">%s</span>' % (color, html.escape(str(text)))


class _IssueRow(QFrame):
    """Clickable issue row: dot · finding · area + advice · (Details) · chevron. Click opens the page that owns it.
    Rows are pooled and updated in place (set) - no widgets are created while a scan delivers results."""

    def __init__(self):
        super().__init__()
        self.setObjectName("IssueRow")
        self.setCursor(Qt.PointingHandCursor)
        self.on_open = self.on_details = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.div = W.divider()
        outer.addWidget(self.div)
        inner = QWidget()
        h = QHBoxLayout(inner)
        h.setContentsMargins(T.S2, T.S2, T.S2, T.S2)
        h.setSpacing(T.S3)
        self.dot = QLabel()
        self.dot.setTextFormat(Qt.RichText)
        self.dot.setFont(T.ui(10))
        self.dot.setContentsMargins(0, 3, 0, 0)
        h.addWidget(self.dot, 0, Qt.AlignTop)
        col = QWidget()
        cv = QVBoxLayout(col)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(2)
        self.title = W.label("", "Value", wrap=True)
        self.title.setStyleSheet("font-weight: 600;")
        cv.addWidget(self.title)
        self.sub = W.label("", "Body", wrap=True)
        cv.addWidget(self.sub)
        h.addWidget(col, 1)
        self.btn = W.button("Details", lambda: self.on_details and self.on_details(), "link")
        h.addWidget(self.btn, 0, Qt.AlignTop)
        ch = QLabel()
        ch.setPixmap(T.icon("chevron", T.MUTED, 14).pixmap(14, 14))
        h.addWidget(ch, 0, Qt.AlignVCenter)
        outer.addWidget(inner)

    def set(self, f, first, on_open, on_details=None):
        self.on_open, self.on_details = on_open, on_details
        _vis(self.div, not first)
        self.dot.setText(_rich("●", T.STATUS.get(f.get("Status"), T.INFO)))
        self.title.setText(f.get("Finding") or "")
        sub = f.get("Area") or ""
        if f.get("Advice"):
            sub += "  ·  " + f["Advice"]
        self.sub.setText(sub[:220])
        _vis(self.btn, on_details is not None)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton and self.rect().contains(e.position().toPoint()) and self.on_open:
            self.on_open()
        super().mouseReleaseEvent(e)


class _KV(QWidget):
    """Label-above-value grid like widgets.KeyValueGrid, but with fixed slots updated in place (setText / show / hide)."""

    def __init__(self, cols=2, slots=6):
        super().__init__()
        self.g = QGridLayout(self)
        self.g.setContentsMargins(0, 0, 0, 0)
        self.g.setHorizontalSpacing(T.S5)
        self.g.setVerticalSpacing(T.S3)
        self.slots = []
        for c in range(cols):
            self.g.setColumnStretch(c, 1)
        for i in range(slots):
            box = QWidget()
            v = QVBoxLayout(box)
            v.setContentsMargins(0, 0, 0, 0)
            v.setSpacing(2)
            k = W.label("", "Label")
            val = W.label("", "Value", wrap=True, sel=True)
            mono = W.label("", "ValueMono", wrap=True, sel=True)
            for x in (k, val, mono):
                v.addWidget(x)
            v.addStretch(1)
            self.g.addWidget(box, i // cols, i % cols)
            box.hide()
            self.slots.append((box, k, val, mono))

    def set(self, rows):
        """rows = [(label, value, mono, color or None)]"""
        for i, (box, k, val, mono) in enumerate(self.slots):
            if i >= len(rows):
                _vis(box, False)
                continue
            r = rows[i]
            txt = "--" if r[1] in (None, "") else str(r[1])
            k.setText(str(r[0]))
            use, other = (mono, val) if r[2] else (val, mono)
            _vis(other, False)
            col = r[3] if len(r) > 3 else None
            if col:
                use.setTextFormat(Qt.RichText)
                use.setText(_rich(txt, T.STATUS.get(col, col)))
            else:
                use.setTextFormat(Qt.PlainText)
                use.setText(txt)
            _vis(use, True)
            _vis(box, True)


class _CompPanel(W.Panel):
    """Component health panel (Windows, Processor, ...): status word + Open link, key/value slots, worst finding. Updated in place."""

    def __init__(self, title, page, open_page):
        self.dot = W.Dot(T.MUTED, "No data", 12)
        super().__init__(title, actions=[self.dot, W.button("Open", lambda: open_page(page), "link")])
        self.kv = _KV(2, 6)
        self.add(self.kv)
        self.hit = W.label("", "Body", wrap=True)
        self.hit.setTextFormat(Qt.RichText)
        self.add(self.hit)
        self.heat = W.label("", "Body", wrap=True)
        self.heat.setTextFormat(Qt.RichText)
        self.add(self.heat)
        self.body.addStretch(1)
        self._sig = None

    def update_(self, word, color, rows, hit, heat):
        sig = (word, color, repr(rows), repr(hit), repr(heat))
        if sig == self._sig:
            return
        self._sig = sig
        self.dot.set(color, word, 12)
        self.kv.set(rows)
        _vis(self.hit, bool(hit))
        if hit:
            self.hit.setText(_rich(hit[1], hit[0]))
        _vis(self.heat, bool(heat))
        if heat:
            self.heat.setText(_rich(heat, T.INFO))


def _legend_row(color, text):
    """Dot + label + right-aligned mono count; returns (row widget, count label)."""
    row = QWidget()
    h = QHBoxLayout(row)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(T.S2)
    h.addWidget(W.Dot(color, text, 12), 1)
    n = W.label("0", "ValueMono")
    n.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
    h.addWidget(n)
    return row, n


# ---------------------------------------------------------------------------------
#  Page
# ---------------------------------------------------------------------------------
class DashboardPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.perf = fx.Perf()
        self.perf_last = (None, None, None, None)
        self.expanded = False
        self._sig = None
        self._built_at = 0.0
        self._was_running = None
        self.F = None
        self._lk = threading.Lock()
        self._want_perf = False
        self._perf_alive = False
        self._quit = threading.Event()
        self._perf_task = None

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        self.sp = W.ScrollPage(spacing=T.S4)
        v.addWidget(self.sp, 1)
        lay = self.sp.lay

        # ---- row: stat tiles ----
        self.t_health = QFrame()
        self.t_health.setObjectName("Panel")
        hh = QHBoxLayout(self.t_health)
        hh.setContentsMargins(T.S4, T.S4, T.S4, T.S4)
        hh.setSpacing(T.S3)
        self.ring = W.Ring(64, 6)
        hh.addWidget(self.ring, 0, Qt.AlignVCenter)
        hv = QVBoxLayout()
        hv.setSpacing(2)
        hv.addWidget(W.label("Health score", "Label"))
        self.l_verdict = W.label("", "Value", wrap=True)
        self.l_verdict.setStyleSheet("font-size: 15px; font-weight: 700;")
        hv.addWidget(self.l_verdict)
        self.l_vsub = W.label("", "Body", wrap=True)
        hv.addWidget(self.l_vsub)
        hv.addStretch(1)
        hh.addLayout(hv, 1)
        self.t_crit = W.StatTile("Critical issues", "0", "None found")
        self.t_warn = W.StatTile("Warnings", "0", "None found")
        self.t_checks = W.StatTile("Checks completed", "--", "")
        self.meter = W.Meter(3)
        self.t_checks.layout().insertWidget(2, self.meter)
        self.stats = _Reflow(min_w=190, max_cols=4)
        self.stats.set_items([self.t_health, self.t_crit, self.t_warn, self.t_checks])
        lay.addWidget(self.stats)

        # ---- banners (security check before scanning, recommended fix) ----
        self.banners = QWidget()
        self.bv = QVBoxLayout(self.banners)
        self.bv.setContentsMargins(0, 0, 0, 0)
        self.bv.setSpacing(T.S2)
        lay.addWidget(self.banners)

        # ---- row: live performance · issues by severity · problem events ----
        self.p_perf = W.Panel("Live performance")
        self.l_cpu = W.label("--", "ValueMono", wrap=True)
        self.l_ram = W.label("--", "ValueMono", wrap=True)
        for x in (self.l_cpu, self.l_ram):
            x.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.cpu_chart = W.LineChart(64, "%")
        self.ram_chart = W.LineChart(64, "%")
        for name, val, ch in (("CPU", self.l_cpu, self.cpu_chart), ("Memory", self.l_ram, self.ram_chart)):
            hb = W.hbox(W.label(name, "Label"), val)
            hb.layout().setStretch(1, 1)
            self.p_perf.add(hb)
            ch.mark_gaps = False
            ch.set([([], T.ACCENT if name == "CPU" else T.TEXT2, name)], top=100)
            self.p_perf.add(ch)
        self.p_perf.add(W.label("Last 60 seconds, updated every second", "Muted", wrap=True))
        self.p_perf.body.addStretch(1)

        self.p_sev = W.Panel("Issues by severity")
        row = QWidget()
        rh = QHBoxLayout(row)
        rh.setContentsMargins(0, 0, 0, 0)
        rh.setSpacing(T.S4)
        self.donut = W.Donut(112, 12)
        rh.addWidget(self.donut, 0, Qt.AlignVCenter)
        lg = QVBoxLayout()
        lg.setSpacing(T.S2)
        lg.addStretch(1)
        self.lg = {}
        for key, col, txt in (("crit", T.CRIT, "Critical"), ("warn", T.WARN, "Warnings"), ("fail", T.MUTED, "Could not run")):
            r, n = _legend_row(col, txt)
            self.lg[key] = n
            lg.addWidget(r)
        lg.addStretch(1)
        rh.addLayout(lg, 1)
        self.p_sev.add(row)
        self.l_sev_note = W.label("", "Muted", wrap=True)
        self.p_sev.add(self.l_sev_note)
        self.p_sev.body.addStretch(1)

        self.p_ev = W.Panel("Problem events - last 30 days", actions=[W.button("Event Analyzer", lambda: self.app.show_page("events"), "link")])
        self.ev_chart = _StackedBars(130)
        self.p_ev.add(self.ev_chart)
        leg = W.label("", "Body", wrap=True)
        leg.setTextFormat(Qt.RichText)
        leg.setText("%s&nbsp;&nbsp;Critical (crashes, blue screens, power loss) &nbsp;&nbsp;&nbsp; %s&nbsp;&nbsp;Warnings&nbsp;/&nbsp;errors"
                    % (_rich("●", T.CRIT), _rich("●", T.WARN)))
        self.p_ev.add(leg)
        self.p_ev.body.addStretch(1)

        self.charts = _Reflow(min_w=250, max_cols=3)
        self.charts.set_items([self.p_perf, self.p_sev, self.p_ev])
        lay.addWidget(self.charts)

        # ---- row: top issues (2/3) + this PC / scan / before-after / quick actions (1/3) ----
        self.split = _Split()
        self.btn_more = W.button("View all", self._toggle, "link")
        self.btn_more.hide()
        self.p_issues = W.Panel("Top issues", actions=[self.btn_more], spacing=0)
        self.p_issues.setStyleSheet("QFrame#IssueRow { border-radius: 3px; } QFrame#IssueRow:hover { background: %s; }" % T.SURFACE2)
        self.p_issues.body.setContentsMargins(T.S2, T.S2, T.S2, T.S2)
        self.issues_box = QWidget()
        self.iv = QVBoxLayout(self.issues_box)
        self.iv.setContentsMargins(0, 0, 0, 0)
        self.iv.setSpacing(0)
        self.l_empty = W.Dot(T.MUTED, "", 13)
        self.l_empty.setContentsMargins(T.S2, T.S2, T.S2, T.S2)
        self.iv.addWidget(self.l_empty)
        self.rows = []                    # pooled _IssueRow widgets
        self.p_issues.add(self.issues_box)
        self.split.lv.addWidget(self.p_issues)
        self.comp_title = W.label("Component health", "SectionTitle")
        self.split.lv.addWidget(self.comp_title)
        self.comps = _Reflow(min_w=230, max_cols=2)
        self.comp_panels = {}
        for title, key, page in (("Windows", "windows", "System"), ("Processor", "cpu", "System"), ("Memory", "memory", "ram"),
                                 ("Storage", "storage", "drives"), ("Security", "security", "Security"), ("Network", "network", "Network")):
            self.comp_panels[key] = _CompPanel(title, page, self.app.show_page)
        self.comps.set_items(list(self.comp_panels.values()))
        self.split.lv.addWidget(self.comps)
        self.split.lv.addStretch(1)

        self.p_pc = W.Panel("This PC")
        self.kv_pc = _KV(2, 4)
        self.p_pc.add(self.kv_pc)
        self.split.rv.addWidget(self.p_pc)
        self.p_scan = W.Panel("Scanning activity")
        self.kv_scan = _KV(2, 4)
        self.p_scan.add(self.kv_scan)
        self.split.rv.addWidget(self.p_scan)
        self.p_base = W.Panel("Before / after", actions=[W.button("Tune-up", lambda: self.app.show_page("tuneup"), "link")])
        self.base_box = QWidget()
        self.bbv = QVBoxLayout(self.base_box)
        self.bbv.setContentsMargins(0, 0, 0, 0)
        self.bbv.setSpacing(T.S2)
        self.p_base.add(self.base_box)
        self.p_base.hide()
        self.split.rv.addWidget(self.p_base)
        self.p_quick = W.Panel("Quick actions", spacing=T.S2)
        for text, ic, cmd in (("Security scan", "lock", self._security_scan),
                              ("Check drive health", "drivehealth", lambda: self.app.show_page("drives")),
                              ("Test memory (RAM)", "ram", lambda: self.app.show_page("ram")),
                              ("Tune-up & before/after", "gauge", lambda: self.app.show_page("tuneup")),
                              ("Check for updates online", "update", lambda: self.app.show_page("updates")),
                              ("System spec sheet", "specs", lambda: self.app.show_page("specs")),
                              ("Open HTML report", "report", self.app.open_report)):
            b = W.button(text, cmd, icon=ic)
            b.setStyleSheet("text-align:left; padding-left:10px;")
            self.p_quick.add(b)
        self.split.rv.addWidget(self.p_quick)
        self.split.rv.addStretch(1)
        lay.addWidget(self.split)
        self.sp.finish()

        for _ in range(ISSUES_SHOWN):                # pre-create the issue rows ...
            r = _IssueRow()
            r.hide()
            self.rows.append(r)
            self.iv.addWidget(r)
        self.ensurePolished()                        # ... and polish everything now, so a render during a scan only sets text
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1000)
        self._poll_timer.timeout.connect(self._poll)
        self._later = QTimer(self)
        self._later.setSingleShot(True)
        self._later.timeout.connect(self._render_later)

    # ------------------------------------------------------------------ data helpers
    def _all_findings(self):
        fb = self.app.findings_by
        return [f for k in list(fb) for f in (fb.get(k) or [])]

    def _running(self):
        sc = getattr(self.app, "scanner", None)
        return bool(self.app.running or self.app.batch or (sc is not None and sc.running))

    def _guided_page(self):
        g = self.app.pages.get("guided")          # never create the Guided Fix page just to draw the dashboard
        return g if g is not None and hasattr(g, "state") else None

    def _signature(self, allf):
        """Everything the page shows that can change. Same signature -> nothing to redraw."""
        app = self.app
        g = self._guided_page()
        try:
            act = g.state.data.get("active") if g else None
            gp = g.state.progress(act) if act else None
        except Exception:
            act, gp = None, None
        sc = getattr(app, "scanner", None)
        drv = tuple((d.get("number"), (d.get("verdict") or {}).get("status")) for d in (getattr(app, "drive_result", None) or []) if isinstance(d, dict))
        ram = getattr(app, "ram_result", None) or {}
        upd = getattr(app, "update_result", None)
        sec = getattr(app, "security_result", None)
        try:
            nbase = len(app.baselines.items)
        except Exception:
            nbase = 0
        return (tuple((f.get("Status"), f.get("Finding"), f.get("Area"), bool(f.get("CheckError"))) for f in allf), self._running(),
                sc.counts() if (sc is not None and sc.running) else None, getattr(app, "_scan_stopped", False), getattr(app, "_scan_counts", None),
                getattr(app, "_last_scan_at", None), getattr(app, "_scanned_once", False), repr(getattr(app, "prescan_result", None)), act, gp, drv,
                self.expanded, tuple(sorted(app.results)), id(getattr(app, "analysis", None)), id(ram.get("info")), repr((ram.get("test") or {}).get("verdict")),
                repr(upd.get("counts") if isinstance(upd, dict) else None), repr(sec.get("counts") if isinstance(sec, dict) else None), nbase,
                id(getattr(app, "battery_result", None)))

    def _stats(self, allf):
        """Values of the stat tiles (cheap)."""
        app = self.app
        score, crit, warn = core.health_score(allf)
        failed = sum(1 for f in allf if f.get("CheckError"))
        running = self._running()
        done, total = app.done_count, len(app.CHECK_KEYS) + 1
        sc = getattr(app, "scanner", None)
        if sc is not None and sc.running:
            done, total = sc.counts()
        never = not allf and not running and not getattr(app, "_scanned_once", False)
        stopped = (not running) and getattr(app, "_scan_stopped", False)
        unknown = (running and not crit and not warn) or failed >= 4 or never
        verdict = ("Scanning..." if running and not allf else "Needs attention" if crit else "Check warnings" if warn else "Healthy")
        if running and allf and not crit:
            verdict = "Scanning..."                       # never call a PC "Healthy" before every check has reported
        if failed >= 4:
            verdict = "Results incomplete"
        if never:
            verdict = "Not scanned yet"
        elif stopped:
            verdict = "Scan stopped"
        sub = ("%d check(s) could not run" % failed) if failed else ("Start with the red items below" if crit else "Based on %d findings" % len(allf))
        if running:
            sub = "Provisional - %d issue(s) found so far" % (crit + warn) if allf else "Waiting for the first results"
        if never:
            sub = "Click 'Run all checks'"
        elif stopped:
            sub = "Partial results - run all checks again for the full picture"
        sc_done = getattr(app, "_scan_counts", None)
        if not running and sc_done:
            total, failed_steps = sc_done[1], sc_done[1] - sc_done[0]
        else:
            failed_steps = failed
        checks = "%d / %d" % (min(done, total), total) if running else ("--" if never else "%d / %d" % (max(0, total - failed_steps), total))
        pbv = min(1.0, done / float(total or 1)) if running else (0.0 if never else 1.0)
        last = getattr(app, "_last_scan_at", None)
        when = "Running..." if running else ("No scan yet" if never else "%s %s" % ("Stopped at" if stopped else "Last scan", last or datetime.now().strftime("%H:%M")))
        return {"score": score, "crit": crit, "warn": warn, "failed": failed, "unknown": unknown, "verdict": verdict, "sub": sub, "checks": checks,
                "pb": pbv, "when": when, "running": running, "never": never, "stopped": stopped, "n": len(allf)}

    # ------------------------------------------------------------------ in-place updates (cheap, no widgets created)
    def _update_stats(self, st):
        self.ring.set(None if st["unknown"] else st["score"], T.MUTED if st["unknown"] else None)
        self.l_verdict.setText(st["verdict"])
        self.l_vsub.setText(st["sub"])
        c, w = st["crit"], st["warn"]
        self.t_crit.set(str(c), "Fix these first" if c else "None found", "CRITICAL" if c else None)
        self.t_warn.set(str(w), "Worth a look" if w else "None found", "WARNING" if w else None)
        self.t_checks.set(st["checks"], st["when"])
        self.meter.set(st["pb"], T.ACCENT)
        self.donut.set([("Critical", c, T.CRIT), ("Warnings", w, T.WARN), ("Could not run", st["failed"], T.MUTED)], str(c + w) if not st["never"] else "--")
        self.lg["crit"].setText(str(c))
        self.lg["warn"].setText(str(w))
        self.lg["fail"].setText(str(st["failed"]))
        self.l_sev_note.setText("Provisional - the scan is still running." if st["running"] else
                                ("No scan yet - click 'Run all checks'." if st["never"] else
                                 "Same problem reported by two checks counts once." if (c or w) else "No problems found."))

    # ------------------------------------------------------------------ render
    def render(self, force=False):
        allf = self._all_findings()
        sig = self._signature(allf)
        if not force and sig == self._sig:
            return
        st = self._stats(allf)
        self._update_stats(st)
        flipped = st["running"] != self._was_running            # scan started / ended: redraw the wording right away
        self._was_running = st["running"]
        if not force and not flipped and self._sig is not None and self.app.batch:
            # During a scan the page is rebuilt at most every REBUILD_EVERY s; in between only the numbers change.
            wait = REBUILD_EVERY - (time.time() - self._built_at)
            if wait > 0:
                if not self._later.isActive():
                    self._later.start(int(wait * 1000) + 50)
                return
        self._later.stop()
        self._sig = sig
        self._built_at = time.time()
        self.F = fx.gather(self.app)
        # Showing a widget inside a visible window re-runs every ancestor layout synchronously (~1-2 ms each time). With the
        # container hidden while rows/slots are shown or hidden, the whole update costs one layout pass.
        self.setUpdatesEnabled(False)
        hid = self.split.isVisible()
        if hid:
            self.split.hide()
        try:
            self._build_banners()
            self._build_issues(allf, st)
            self._build_components(allf, st)
            self._build_side(st)
            self._draw_events()
        finally:
            if hid:
                self.split.show()
            # word-wrapped labels need one more pass of the event loop (posted LayoutRequests) to settle their heights:
            # paint again only after that, so the half-laid-out frame is never shown
            QTimer.singleShot(0, self, lambda: self.setUpdatesEnabled(True))
        self._draw_perf()

    def _render_later(self):
        self.request_render()

    # ---------- banners ----------
    def _build_banners(self):
        pre = getattr(self.app, "prescan_result", None)
        try:
            bad = [i for i in (pre[0] if pre else []) if i[0] in ("CRITICAL", "WARNING")]
        except Exception:
            bad = []
        rec = self._recommendation()
        sig = (repr(bad[:2]), rec[:3] if rec else None)
        if sig == getattr(self, "_ban_sig", None):
            return
        self._ban_sig = sig
        W.clear_layout(self.bv)
        if bad:
            crit_pre = any(i[0] == "CRITICAL" for i in bad)
            self.bv.addWidget(W.Banner("Security check: results may not be trustworthy" if crit_pre else "Security check: worth a look",
                                       "; ".join("%s - %s" % (i[1], i[2]) for i in bad[:2])[:300], "CRITICAL" if crit_pre else "WARNING",
                                       W.button("Security Scan", lambda: self.app.show_page("security"))))
        if rec:
            self.bv.addWidget(W.Banner(rec[0], rec[1], "INFO", W.button(rec[2], rec[3], "primary", icon="wand", min_w=140)))
        _vis(self.banners, self.bv.count() > 0)

    def _recommendation(self):
        g = self._guided_page()
        if g is not None:
            try:
                act = g.state.data.get("active")
                if act and act in guided.PLAYBOOK_BY_ID and g.state.next_step(act):
                    done, total = g.state.progress(act)
                    return ("Guided Fix in progress: %s" % guided.PLAYBOOK_BY_ID[act]["title"],
                            "%d of %d steps done. Next: %s" % (done, total, g.state.next_step(act)["title"]), "Continue", lambda: self._open_playbook(act))
            except Exception as e:
                core.log_error("dashboard guided state", e)
        if self._running():
            return None
        recs = guided.recommend(self.app.analysis, security=getattr(self.app, "security_result", None))
        if recs:
            pb = recs[0][0]
            return ("Recommended: %s" % pb["title"], "Why: %s. Step-by-step fix following Microsoft's procedure." % recs[0][1], "Start guide",
                    lambda p=pb["id"]: self._open_playbook(p))
        bad = [d for d in self.F["drives"] if isinstance(d, dict) and (d.get("verdict") or {}).get("status") == "CRITICAL"]
        if bad:
            return ("A drive is failing: %s" % bad[0].get("model"), "Back up your files now. The Drive Health page shows what to do.", "Open Drive Health",
                    lambda: self.app.show_page("drives"))
        return None

    def _open_playbook(self, pid):
        self.app.show_page("guided")
        g = self.app.pages.get("guided")
        if g is not None and hasattr(g, "open_playbook"):
            g.open_playbook(pid)

    def _security_scan(self):
        self.app.show_page("security")
        p = self.app.pages.get("security")
        if p is not None and hasattr(p, "scan"):
            p.scan()

    # ---------- top issues ----------
    def _build_issues(self, allf, st):
        issues = [f for f in core.sort_findings(allf) if f.get("Status") in ("CRITICAL", "WARNING")]
        running = st["running"]
        if not issues:
            txt = (("Nothing found so far - still checking..." if running else "No problems found") if allf else
                   ("Waiting for results..." if running else "No scan yet - click 'Run all checks'."))
            self.l_empty.set("OK" if allf else T.MUTED, txt, 13)
        _vis(self.l_empty, not issues)
        shown = issues if self.expanded else issues[:ISSUES_SHOWN]
        while len(self.rows) < len(shown):
            r = _IssueRow()
            self.rows.append(r)
            self.iv.addWidget(r)
        has_events = "events" in self.app.pages
        for n, r in enumerate(self.rows):
            if n >= len(shown):
                _vis(r, False)
                continue
            f = shown[n]
            det = (lambda f=f: self._details(f)) if (f.get("_sec") or has_events) else None     # explanation content exists only for these
            r.set(f, n == 0, lambda f=f: self.app.show_page(self.app.target_page(f)), det)
            _vis(r, True)
        more = len(issues) > ISSUES_SHOWN
        _vis(self.btn_more, more)
        self.btn_more.setText("Show less" if self.expanded else "View all (%d)" % len(issues))
        self.p_issues.title_lbl.setText("Top issues" + ("  -  provisional" if running and issues else ""))

    def _details(self, f):
        c = None
        try:
            c = self.app.finding_content(f)
        except Exception as e:
            core.log_error("dashboard finding details", e)
        if c:
            txt = self.app.content_text(c)
        else:
            txt = "%s\n\n%s: %s\n\n%s" % (f.get("Finding") or "", f.get("Status") or "", f.get("Area") or "", f.get("Advice") or "")
        self.app.text_popup(f.get("Finding") or "Details", txt)

    def _toggle(self):
        self.expanded = not self.expanded
        self.render(force=True)

    # ---------- component health ----------
    def _build_components(self, allf, st):
        app = self.app
        heat = [hf for hf in (app.findings_by.get("Heat") or []) if hf.get("Status") not in ("CRITICAL", "WARNING")]
        for title, key, rows, page in self._tiles():
            stt, hits = fx.worst(allf, TILE_AREAS[key])
            ready = {"ram": bool((getattr(app, "ram_result", None) or {}).get("info")) or "System" in app.results,
                     "drives": bool(getattr(app, "drive_result", None)) or "Disks" in app.results}.get(page, page in app.results)
            word = {"OK": "Good", "WARNING": "Check", "CRITICAL": "Problem"}[stt] if (ready or hits) else ("Checking..." if st["running"] else "No data")
            color = T.STATUS.get(stt, T.OK) if word not in ("No data", "Checking...") else T.MUTED
            hit = None
            if hits:
                ft = hits[0].get("Finding") or ""
                hit = (T.STATUS.get(hits[0].get("Status"), T.WARN), "▸ " + (ft if len(ft) <= 110 else ft[:107].rstrip() + "..."))
            ht = None
            if key == "storage" and heat:                           # heat / drive-error correlation (the INFO note too)
                ht = "Heat: " + (heat[0].get("Finding") or "")[:160]
            self.comp_panels[key].update_(word, color, [(k, v, mono) for k, v, mono in rows if k][:6], hit, ht)

    def _tiles(self):
        """[(title, area key, [(label, value, mono)], page)] - same facts as the 3.x tiles, as label/value pairs."""
        F = self.F
        o = F["overview"]
        tiles = []
        # Windows
        rows = [("Windows", o.get("Windows"), False), ("Build", o.get("Build"), True), ("Uptime", o.get("Uptime"), True)]
        act = o.get("Activation") or ""
        if act:
            rows.append(("Activation", "Activated" if "activated" in act.lower() and "not" not in act.lower() else act, False))
        upd = getattr(self.app, "update_result", None)
        if isinstance(upd, dict) and upd.get("ok"):
            c = upd.get("counts") or {}
            rows.insert(1, ("Updates", "%d missing (checked online)" % c.get("missing", 0) if c.get("missing") else "up to date (checked online)", False))
        if "Restart pending" in F["pending"]:
            rows.append(("Restart", "Restart pending", False))
        tiles.append(("Windows", "windows", rows, "System"))
        # Processor
        cpu = (o.get("CPU") or "").replace("(R)", "").replace("(TM)", "").replace("  ", " ")
        tiles.append(("Processor", "cpu", [("CPU", cpu or "--", False), ("Cores / threads", o.get("Cores / threads"), True),
                                           ("Load at scan", o.get("CPU load now"), True)], "System"))
        # Memory
        ram = F["ram"]
        rows = [("Installed", o.get("RAM") or ("%s installed" % fx.fmt_bytes(ram["total"]) if ram else "--"), True)]
        if ram:
            used = sum(1 for s in ram["slots"] if s)
            rows.append(("Slots", "%d of %d used  ·  %s" % (used, ram["nslots"], "/".join(ram["types"]) or ""), True))
        t = F["ramtest"]
        rows.append(("RAM test", (t.get("verdict") or "").lower() if t else "not run yet", False))
        tiles.append(("Memory", "memory", rows, "ram"))
        # Storage
        drv = [d for d in F["drives"] if isinstance(d, dict)]
        rows = []
        if drv:
            g = sum(1 for d in drv if (d.get("verdict") or {}).get("status") == "GOOD")
            unk = sum(1 for d in drv if (d.get("verdict") or {}).get("status") == "UNKNOWN")
            bad = len(drv) - g - unk
            rows.append(("Drives", "%d drive(s): %d good%s" % (len(drv), g, ", %d need attention" % bad if bad else ""), False))
        vols = [v for v in F["volumes"] if v.get("Type") in ("Fixed", None)]
        for v in vols[:2]:
            rows.append(("Drive %s" % (v.get("Drive") or ""), "%s free of %s" % (v.get("Free") or v.get("Free space") or "?", v.get("Size")), True))
        tiles.append(("Storage", "storage", rows or [("Drives", "--", False)], "drives"))
        # Security
        d = F["defender"]
        rows = []
        if d:
            rows.append(("Defender real-time", "on" if str(d.get("Real-time protection")) == "True" else "OFF", False))
        fw = F["firewall"]
        if fw:
            on = sum(1 for x in fw if str(x.get("Enabled")) == "True")
            rows.append(("Firewall", "%d of %d profiles on" % (on, len(fw)), False))
        blk = F["bitlocker"]
        if blk:
            rows.append(("BitLocker", ", ".join("%s %s" % (x.get("Drive"), x.get("Protection")) for x in blk[:2]), False))
        ss = F["security_scan"]
        cnt = ss.get("counts") if isinstance(ss, dict) else None
        rows.append(("Security scan", "%d critical, %d warnings" % (cnt.get("CRITICAL", 0), cnt.get("WARNING", 0)) if cnt else "not run yet", False))
        tiles.append(("Security", "security", rows, "Security"))
        # Network
        rows = []
        net = [x for x in F["conn"] if "internet" in (x.get("Test") or "").lower()]
        if net:
            ok = all(x.get("Result") == "OK" for x in net)
            lat = next((x.get("Detail") for x in net if "ms" in str(x.get("Detail"))), "")
            rows.append(("Internet", "%s%s" % ("connected" if ok else "PROBLEM", (" (%s)" % lat.split(",")[0]) if lat else ""), False))
        for c in F["ipconf"][:1]:
            rows.append((c.get("Interface") or "IP address", c.get("IPv4"), True))
        up = [a for a in F["adapters"] if a.get("Status") == "Up"]
        if up:
            rows.append(("Adapter", "%s at %s" % (up[0].get("Name"), up[0].get("Speed")), False))
        tiles.append(("Network", "network", rows or [("Internet", "--", False)], "Network"))
        return tiles

    # ---------- side column ----------
    def _build_side(self, st):
        o = self.F["overview"]
        self.kv_pc.set([("Computer name", o.get("Computer name") or os.environ.get("COMPUTERNAME") or "--", True),
                        ("Model", ("%s %s" % (o.get("Manufacturer") or "", o.get("Model") or "")).strip() or None, False),
                        ("Windows", o.get("Windows"), False), ("Uptime", o.get("Uptime"), True)])
        status = "Running..." if st["running"] else ("Stopped" if st["stopped"] else ("Not run" if st["never"] else "Finished"))
        self.kv_scan.set([("Status", status, False, T.ACCENT if st["running"] else None), ("Checks completed", st["checks"], True),
                          ("Findings", str(st["n"]), True),
                          ("Mode", "Administrator" if self.app.is_admin else "Limited mode", False, None if self.app.is_admin else "WARNING")])
        self._build_baseline()

    def _build_baseline(self):
        try:
            snaps = list(self.app.baselines.items)
        except Exception:
            snaps = []
        sig = tuple(x.get("id") for x in snaps if isinstance(x, dict))
        if sig == getattr(self, "_base_sig", None):
            return
        self._base_sig = sig
        W.clear_layout(self.bbv)
        if not snaps:
            self.p_base.hide()
            return
        self.p_base.show()
        if len(snaps) < 2:
            self.bbv.addWidget(W.label("1 measurement saved (%s). Take another after a change to see the real difference." % bl.snap_name(snaps[-1]),
                                       "Body", wrap=True))
            return
        before, after = snaps[0], snaps[-1]
        try:
            rows = bl.compare(before, after)
        except Exception as e:
            core.log_error("dashboard baseline compare", e)
            return
        better = sum(1 for r in rows if r[3] == "better")
        worse = sum(1 for r in rows if r[3] == "worse")
        self.bbv.addWidget(W.label("%s  ->  %s" % (bl.snap_name(before), bl.snap_name(after)), "Muted", wrap=True))
        self.bbv.addWidget(W.hbox(W.colored("%d better" % better, T.OK if better else T.TEXT2, 12, True, wrap=False),
                                  W.colored("%d worse" % worse, T.CRIT if worse else T.TEXT2, 12, True, wrap=False), "stretch", spacing=T.S4))
        changed = [r for r in rows if r[3] in ("better", "worse")][:5]
        if not changed:
            self.bbv.addWidget(W.label("No measurable change yet (some values need a restart or a few days).", "Body", wrap=True))
        for label, a, b, v, note in changed:
            r = QWidget()
            h = QHBoxLayout(r)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(T.S2)
            h.addWidget(W.label(label, "Body", wrap=True), 1)
            val = W.label("%s -> %s" % (a, b), "ValueMono")
            val.setStyleSheet("color:%s; font-size: 11px;" % VCOL[v])
            val.setToolTip("%s  %s" % (VTXT[v], note))
            h.addWidget(val, 0, Qt.AlignTop)
            self.bbv.addWidget(r)

    # ---------- charts ----------
    def _draw_events(self):
        a = self.app.analysis
        if not a:
            self.ev_chart.set([], "Event data appears after the Event Analyzer has run.")
            return
        today = datetime.now().date()
        days = [today - timedelta(days=29 - i) for i in range(30)]
        crit = dict.fromkeys(days, 0)
        warn = dict.fromkeys(days, 0)
        for i in a.get("instances", []) or []:
            t = i.get("time")
            if not hasattr(t, "date"):
                continue
            d = t.date()
            if d in crit:
                if i.get("severity") == "CRITICAL":
                    crit[d] += 1
                else:
                    warn[d] += 1
        self.ev_chart.set([(d, crit[d], warn[d]) for d in days])

    def _draw_perf(self):
        cpu, load, tot, used = self.perf_last
        ch, rh = list(self.perf.cpu_hist), list(self.perf.ram_hist)
        self.cpu_chart.set([(ch, T.ACCENT, "CPU")], top=100)
        self.ram_chart.set([(rh, T.TEXT2, "Memory")], top=100)
        if cpu is not None:
            self.l_cpu.setText("%d%%" % cpu)
        if load is not None:
            self.l_ram.setText("%d%%   (%s of %s)" % (load, fx.fmt_bytes(used), fx.fmt_bytes(tot)))

    # ------------------------------------------------------------------ live sampling (worker) + polling (GUI)
    def _sampler(self):
        """Worker thread: sample CPU / memory once a second while the dashboard is visible. Touches no widgets."""
        while True:
            with self._lk:
                if not self._want_perf or self._quit.is_set():
                    self._perf_alive = False
                    return None
            r = self.perf.sample()
            if r[0] is not None or r[1] is not None:
                self.perf_last = r
            self._quit.wait(1.0)

    def _start_sampler(self):
        with self._lk:
            self._want_perf = True
            if self._perf_alive or self._quit.is_set():
                return
            self._perf_alive = True
        self._perf_task = tasks.run_task(self._sampler, on_error=lambda m: setattr(self, "_perf_alive", False), name="dash-perf")

    def _poll(self):
        if not self.isVisible():
            return
        try:
            self._draw_perf()
            if self._running():                              # live progress in the stat tiles while scanning
                self._update_stats(self._stats(self._all_findings()))
        except Exception as e:
            self._poll_timer.stop()
            core.log_error("dashboard poll", e)

    def on_show(self):
        self._start_sampler()
        self._poll_timer.start()

    def on_hide(self):
        with self._lk:
            self._want_perf = False
        self._poll_timer.stop()

    def shutdown(self):
        with self._lk:
            self._want_perf = False
        self._quit.set()
        self._poll_timer.stop()
        self._later.stop()
        # tasks.run_task connects worker.finished -> thread.quit through the GUI event loop, which is blocked while
        # MainWindow.closeEvent waits for the threads - so end the sampler thread's event loop directly (thread-safe).
        t = getattr(self, "_perf_task", None)
        if t is not None:
            try:
                t.thread.quit()
            except RuntimeError:
                pass
