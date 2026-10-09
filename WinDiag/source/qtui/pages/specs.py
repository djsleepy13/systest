"""System spec sheet: everything about the hardware and Windows on one page + printable HTML / text export."""
import os
import re
from datetime import datetime
from html import escape

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

import appsettings as S
import core
from specdata import build_specs
from .. import tasks
from .. import theme as T
from .. import widgets as W

MONO = re.compile(r"(?i)^(serial number|build|uptime|installed on|last boot|cores / threads|load at scan|bios|definitions)$")
GENERAL = ("Device", "Operating system")


def _value_widget(v, st, mono=False):
    """Value label: optional coloured status dot + text (mono for data). Fonts come from the QSS object names."""
    txt = "--" if v in (None, "") else str(v)
    w = QLabel()
    w.setObjectName("ValueMono" if mono else "Value")
    w.setWordWrap(True)
    w.setTextInteractionFlags(Qt.TextSelectableByMouse)
    w.setTextFormat(Qt.RichText)
    dot = '<span style="color:%s">●</span>&nbsp;&nbsp;' % T.STATUS[st] if st in T.STATUS else ""
    w.setText(dot + escape(txt))
    return w


class SpecPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self._sig = None
        self._cols = None
        self.sections = []
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, 0)
        bar.setSpacing(T.S2)
        hb = QVBoxLayout()
        hb.setSpacing(2)
        self.l_model = W.label("This PC", "Value", wrap=True, sel=True)
        self.l_model.setStyleSheet("font-size: 17px; font-weight: 700;")
        hb.addWidget(self.l_model)
        self.l_sub = W.label("", "Body", wrap=True, sel=True)
        hb.addWidget(self.l_sub)
        bar.addLayout(hb, 1)
        self.btn_copy = W.button("Copy as text", self.copy, icon="copy")
        bar.addWidget(self.btn_copy, 0, Qt.AlignVCenter)
        self.btn_export = W.button("Export spec sheet", self.export, "primary", icon="download")
        bar.addWidget(self.btn_export, 0, Qt.AlignVCenter)
        v.addLayout(bar)
        self.sp = W.ScrollPage(spacing=T.S4)
        v.addWidget(self.sp, 1)
        self._rs = QTimer(self)
        self._rs.setSingleShot(True)
        self._rs.setInterval(120)
        self._rs.timeout.connect(self._reflow)

    # ------------------------------------------------------------------ data
    def _data(self):
        try:
            return build_specs(self.app)          # pure dict work on data already in memory (< 1 ms) - no I/O
        except Exception as e:
            core.log_error("spec sheet", e)
            return None

    def render(self, force=False):
        """Called whenever a check finishes (results arrive in the background) - redraws only when the sheet changed."""
        d = self._data()
        if d is None:
            return
        head, secs = d
        has = bool(self.app.results.get("System"))
        sig = repr((head, secs, has))
        if sig == self._sig and not force:
            return
        self._sig = sig
        self.sections = secs if has else []
        self.l_model.setText(head["model"] or "This PC")
        self.l_sub.setText("  ·  ".join(x for x in (head["name"], head["os"], ("S/N " + head["serial"]) if head.get("serial") else "") if x))
        self._cols = None
        self._build()

    def _ncols(self):
        w = self.sp.viewport().width() or self.width()
        return 1 if w < 760 else 2

    def _build(self):
        lay = self.sp.lay
        self.setUpdatesEnabled(False)
        try:
            W.clear_layout(lay)
            if not self.sections:
                lay.addWidget(W.label("The spec sheet fills in when the checks have finished.", "Muted", wrap=True))
                lay.addStretch(1)
                return
            w = self.sp.viewport().width() or self.width()
            ncols = self._ncols()
            self._cols = ncols
            self._layout_key = (ncols, 4 if w >= 1200 else 3 if w >= 900 else 2 if w >= 520 else 1)
            gen = [s for s in self.sections if s[0] in GENERAL]
            rest = [s for s in self.sections if s[0] not in GENERAL]
            if gen:
                p = W.Panel("General information")
                kcols = 4 if w >= 1200 else 3 if w >= 900 else 2 if w >= 520 else 1
                for title, _ic, rows in gen:
                    p.add(W.label(title, "SectionTitle"))
                    p.add(self._grid(rows, kcols))
                lay.addWidget(p)
            # masonry: two columns, each section goes to the shorter column (by row count)
            box = QWidget()
            g = QGridLayout(box)
            g.setContentsMargins(0, 0, 0, 0)
            g.setHorizontalSpacing(T.S4)
            cols, heights = [], [0] * ncols
            for c in range(ncols):
                cw = QWidget()
                cv = QVBoxLayout(cw)
                cv.setContentsMargins(0, 0, 0, 0)
                cv.setSpacing(T.S4)
                cols.append(cv)
                g.addWidget(cw, 0, c, Qt.AlignTop)
                g.setColumnStretch(c, 1)
            for title, _ic, rows in rest:
                c = heights.index(min(heights))
                long_vals = sum(len(str(v or "")) for _k, v, _s in rows) / float(max(1, len(rows))) > 34
                kcols = 1 if (long_vals or ncols == 1 and w < 520) else 2
                p = W.Panel(title)
                p.add(self._grid(rows, kcols))
                cols[c].addWidget(p)
                heights[c] += (len(rows) + 1) // kcols + 2
            for cv in cols:
                cv.addStretch(1)
            lay.addWidget(box)
            lay.addStretch(1)
        finally:
            self.setUpdatesEnabled(True)

    def _grid(self, rows, cols):
        g = W.KeyValueGrid(cols)
        pairs = []
        for k, v, st in rows:
            vw = _value_widget(v, st, bool(MONO.search(str(k or ""))))
            pairs.append((str(k or ""), vw))
        g.set(pairs, cols)
        return g

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.sections:
            self._rs.start()

    def _reflow(self):
        """Window resized / moved to another monitor: rebuild only when the column layout changes."""
        if not self.isVisible() or not self.sections:
            return
        w = self.sp.viewport().width() or self.width()
        key = (self._ncols(), 4 if w >= 1200 else 3 if w >= 900 else 2 if w >= 520 else 1)
        if key != getattr(self, "_layout_key", None):
            self._layout_key = key
            self._build()

    # ------------------------------------------------------------------ export
    def text(self):
        d = self._data()
        if d is None:
            return ""
        head, secs = d
        out = ["SYSTEM SPEC SHEET - %s" % (head["model"] or head["name"]), "Generated %s by WinDiag" % datetime.now().strftime("%Y-%m-%d %H:%M"), ""]
        for title, _ic, rows in secs:
            out += [title.upper()] + ["  %-26s %s" % (k, "--" if v in (None, "") else v) for k, v, _s in rows] + [""]
        return "\n".join(out)

    def copy(self):
        hidden = S.get("privacy_mode")
        self.app.copy_text(S.redact(self.text(), self.app))      # privacy mode applies to the clipboard too
        self.app.set_status("Spec sheet copied to the clipboard%s." % (" (serials and user names hidden)" if hidden else ""), hold=4)

    def _html(self, head, secs):
        css = ("body{font-family:'Segoe UI',Inter,Arial,sans-serif;background:#0D1117;color:#F3F4F6;margin:0;padding:32px}"
               "h1{font-size:24px;margin:0}.sub{color:#9CA3AF;font-size:13px;margin:4px 0 24px}"
               ".grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.card{background:#151C26;border:1px solid #273241;border-radius:12px;padding:16px 20px;break-inside:avoid}"
               ".card h2{font-size:15px;margin:0 0 8px}table{width:100%;border-collapse:collapse;font-size:13px}td{padding:7px 0;border-top:1px solid #202A36;vertical-align:top}"
               "tr:first-child td{border-top:0}td.k{color:#9CA3AF;width:36%;padding-right:12px}.d{font-size:9px;margin-right:6px}"
               "@media print{body{background:#fff;color:#111}.card{background:#fff;border-color:#ccc}td.k,.sub{color:#555}td{border-color:#e5e7eb}}")
        dcol = {"OK": "#22C55E", "WARNING": "#F59E0B", "CRITICAL": "#EF4444"}
        h = ['<!DOCTYPE html><html><head><meta charset="utf-8"><title>Spec sheet - %s</title><style>%s</style></head><body>' % (escape(head["name"] or ""), css),
             "<h1>%s</h1><div class='sub'>%s &middot; Generated %s by WinDiag</div><div class='grid'>" % (
                 escape(head["model"] or head["name"] or ""),
                 escape("  |  ".join(x for x in (head["name"], head["os"], ("S/N " + head["serial"]) if head.get("serial") else "") if x)),
                 datetime.now().strftime("%Y-%m-%d %H:%M"))]
        for title, _ic, rows in secs:
            h.append("<div class='card'><h2>%s</h2><table>" % escape(title))
            for k, v, st in rows:
                dot = "<span class='d' style='color:%s'>&#9679;</span>" % dcol[st] if st in dcol else ""
                h.append("<tr><td class='k'>%s</td><td>%s%s</td></tr>" % (escape(str(k or "")), dot, escape("--" if v in (None, "") else str(v))))
            h.append("</table></div>")
        h.append("</div></body></html>")
        return "\n".join(h)

    def export(self):
        d = self._data()
        if d is None:
            return W.error(self, "Could not build the spec sheet - details were saved to Reports\\windiag_errors.log.")
        head, secs = d
        html_txt = S.redact(self._html(head, secs), self.app)
        txt = S.redact(self.text(), self.app)
        path = os.path.join(self.app.report_dir, "Spec-Sheet-%s.html" % re.sub(r'[\\/:*?"<>|]+', "_", head["name"] or "PC"))
        self.btn_export.setEnabled(False)

        def work():
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_txt)
            with open(path[:-5] + ".txt", "w", encoding="utf-8") as f:
                f.write(txt)
            try:
                os.startfile(path)
            except Exception:
                pass
            return path

        def done(p):
            self.btn_export.setEnabled(True)
            self.app.set_status("Spec sheet saved: %s" % p, hold=6)

        def fail(msg):
            self.btn_export.setEnabled(True)
            W.error(self, "Could not save the spec sheet:\n%s" % msg)
        tasks.run_task(work, done, fail, name="spec-export")
