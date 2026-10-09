"""Guided Fix page: step-by-step playbooks (logic + data in guided.py) with automatic checks."""
import html
import json
import os
import re
import sys
import threading
import uuid
from datetime import datetime, timedelta

from PySide6.QtCore import QPoint, QRect, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QFrame, QHBoxLayout, QLabel, QLayout, QScrollArea, QSizePolicy, QVBoxLayout,
                               QWidget)

import core
import event_kb
import guided
from .. import tasks
from .. import theme as T
from .. import widgets as W

CAT_TO_PLAYBOOK = {"DRIVER": "drivers", "USB": "drivers", "NETWORK": "drivers", "RAM": "hw", "CPU": "hw", "PCIE": "hw",
                   "GPU": "gpu", "NVME": "disk", "DISK": "disk", "FS": "disk", "SPACE": "disk", "POWER": "power",
                   "THERMAL": "power", "UPDATE": "wu", "SYSTEM": "bsod", "KERNEL": "bsod", "APP": "drivers", "BIOS": "hw"}
DONE = ("pass", "fixed", "done", "skipped")
ST_COLOR = {"todo": T.MUTED, "running": T.INFO, "waiting": T.INFO, "pending": T.INFO, "pass": T.OK, "fixed": T.OK,
            "done": T.OK, "skipped": T.MUTED, "fail": T.CRIT, "review": T.WARN, "error": T.CRIT}


def state_path(report_dir):
    base = os.path.join(core.app_dir(), "Reports")
    try:
        os.makedirs(base, exist_ok=True)
        probe = os.path.join(base, ".w")
        open(probe, "w").close()
        os.remove(probe)
    except Exception:
        base = os.path.dirname(report_dir)
    return os.path.join(base, "guided_%s.json" % os.environ.get("COMPUTERNAME", "PC"))


def set_runonce(enable):
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0, winreg.KEY_SET_VALUE)
        if enable:
            if getattr(sys, "frozen", False):
                cmd = '"%s" --resume' % sys.executable
            else:
                cmd = '"%s" "%s" --resume' % (sys.executable, os.path.abspath(sys.argv[0]))
            winreg.SetValueEx(k, "WinDiagResume", 0, winreg.REG_SZ, cmd)
        else:
            try:
                winreg.DeleteValue(k, "WinDiagResume")
            except OSError:
                pass
        winreg.CloseKey(k)
        return True
    except Exception:
        return False


def open_url(url):
    """Non-blocking (QDesktopServices hands the URL to the shell)."""
    try:
        QDesktopServices.openUrl(QUrl(url))
    except Exception as e:
        core.log_error("guided open url", e)


# ---------------------------------------------------------------------------------
#  Small private widgets (candidates for qtui/widgets.py)
# ---------------------------------------------------------------------------------
class _Flow(QLayout):
    """Left-to-right layout that wraps to the next line when out of width (buttons / tags never clip at narrow sizes)."""

    def __init__(self, parent=None, spacing=T.S2):
        super().__init__(parent)
        self._items = []
        self._sp = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, i):
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i):
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, w):
        return self._do(QRect(0, 0, w, 0), True)

    def setGeometry(self, r):
        super().setGeometry(r)
        self._do(r, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        s = QSize()
        for it in self._items:
            s = s.expandedTo(it.minimumSize())
        m = self.contentsMargins()
        return s + QSize(m.left() + m.right(), m.top() + m.bottom())

    def _do(self, r, test):
        m = self.contentsMargins()
        x, y = r.x() + m.left(), r.y() + m.top()
        right = r.right() - m.right()
        line_h = 0
        for it in self._items:
            if it.widget() is not None and not it.widget().isVisibleTo(it.widget().parentWidget()):
                continue
            hint = it.sizeHint()
            nx = x + hint.width() + self._sp
            if nx - self._sp > right and line_h > 0:
                x = r.x() + m.left()
                y += line_h + self._sp
                nx = x + hint.width() + self._sp
                line_h = 0
            if not test:
                it.setGeometry(QRect(QPoint(x, y), hint))
            x = nx
            line_h = max(line_h, hint.height())
        return y + line_h - r.y() + m.bottom()


def _flow_widget(widgets, spacing=T.S2):
    w = QWidget()
    f = _Flow(w, spacing)
    for x in widgets:
        f.addWidget(x)
    return w


def _css(size=None, weight=None, mono=False, color=None):
    """Font via style sheet: the global QSS rule `* { font-family; font-size }` overrides QWidget.setFont()."""
    out = []
    if mono:
        out.append("font-family:'%s';" % T.FONT_MONO)
    if size:
        out.append("font-size:%dpx;" % size)
    if weight:
        out.append("font-weight:%d;" % weight)
    if color:
        out.append("color:%s;" % color)
    return " ".join(out)


def _wl(text, role="Body", color=None, size=None, weight=None, mono=False, sel=True):
    """Wrapped label that never forces its parent wider (very long words are clipped instead of overflowing)."""
    w = QLabel(str(text))
    w.setObjectName(role)
    w.setWordWrap(True)
    w.setMinimumWidth(1)
    w.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
    css = _css(size, weight, mono, color)
    if css:
        w.setStyleSheet(css)
    if sel:
        w.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return w


def _mono(text, size=12, weight=None, color=T.TEXT2):
    w = QLabel(str(text))
    w.setStyleSheet(_css(size, weight, True, color))
    return w


def _link(text, url):
    w = QLabel('<a href="%s" style="color:%s; text-decoration:none;">%s</a>' % (html.escape(url, True), T.ACCENT, html.escape(text)))
    w.setTextFormat(Qt.RichText)
    w.setWordWrap(True)
    w.setMinimumWidth(1)
    w.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
    w.setTextInteractionFlags(Qt.LinksAccessibleByMouse)
    w.linkActivated.connect(open_url)
    w.setCursor(Qt.PointingHandCursor)
    w.setToolTip(url)
    return w


class _PbRow(QFrame):
    """One playbook in the left list (click to open)."""

    def __init__(self, pb, active, on_click):
        super().__init__()
        self.setObjectName("GRow")
        self.setCursor(Qt.PointingHandCursor)
        self._click = on_click
        self.setStyleSheet("QFrame#GRow{background:%s; border:0; border-left:2px solid %s; border-radius:0;}"
                           "QFrame#GRow:hover{background:%s;}" % (T.SURFACE2 if active else "transparent",
                                                                  T.ACCENT if active else "transparent", T.SURFACE2))
        v = QVBoxLayout(self)
        v.setContentsMargins(T.S3, T.S2, T.S3, T.S2)
        v.setSpacing(3)
        t = _wl(pb["title"], "Value", weight=700 if active else 600, sel=False)
        v.addWidget(t)
        self.sub = _wl("", "Muted", sel=False)
        v.addWidget(self.sub)
        h = QHBoxLayout()
        h.setSpacing(T.S2)
        self.meter = W.Meter(3)
        h.addWidget(self.meter, 1)
        self.count = _mono("", 11)
        h.addWidget(self.count)
        v.addLayout(h)

    def set_progress(self, why, done, total):
        self.sub.setText(why or "")
        self.sub.setVisible(bool(why))
        self.count.setText("%d / %d" % (done, total))
        self.meter.set(done / float(total or 1), T.OK if total and done >= total else T.ACCENT)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._click()
        super().mousePressEvent(e)


# ---------------------------------------------------------------------------------
#  Page
# ---------------------------------------------------------------------------------
class GuidedPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.state = guided.State(state_path(app.report_dir))
        self.sel = self.state.data.get("active") or None
        self.busy = {}          # step key -> True while a check runs
        self.polls = {}         # step key -> Task waiting for a repair's status file
        self.dump_result = self.state.data.get("dump")
        self._sig = None        # what the page was last drawn from (skip identical redraws)
        self._cards = {}        # step key -> (widget, signature) for in-place updates
        self._rows = {}         # playbook id -> _PbRow
        self._recs = {}
        self._detail_pb = None
        self._prog = None
        self._done_lbl = None
        self._closed = False

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        self.lbl_top = W.label("Step-by-step guides. Each step explains why, runs the built-in Windows tool and checks the result.", "Body", wrap=True)
        bar.addWidget(self.lbl_top, 1)
        self.reopen = QCheckBox("Reopen WinDiag after restart")
        self.reopen.setChecked(bool(self.state.data.get("reopen", True)))
        self.reopen.toggled.connect(self._reopen_toggled)
        bar.addWidget(self.reopen)
        v.addLayout(bar)

        body = QHBoxLayout()
        body.setContentsMargins(T.S5, 0, T.S5, T.S5)
        body.setSpacing(T.S4)
        # left: playbook list
        self.left_panel = W.Panel("Guides")
        self.left_panel.body.setContentsMargins(0, 0, 0, 0)
        self.left_panel.setMinimumWidth(250)
        self.left_scroll = QScrollArea()
        self.left_scroll.setWidgetResizable(True)
        self.left_scroll.setFrameShape(QFrame.NoFrame)
        self.left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        self.left_lay = QVBoxLayout(inner)
        self.left_lay.setContentsMargins(0, T.S1, 0, T.S2)
        self.left_lay.setSpacing(1)
        self.left_scroll.setWidget(inner)
        self.left_panel.add(self.left_scroll, 1)
        self.left_panel.layout().setStretch(1, 1)
        body.addWidget(self.left_panel, 2)
        # right: the selected playbook
        self.right = W.ScrollPage(margins=(0, 0, T.S1, 0), spacing=T.S4)
        body.addWidget(self.right, 5)
        v.addLayout(body, 1)

    # ------------------------------------------------------------------ public API (app / scan / other pages)
    def open_playbook(self, pid):
        if pid in guided.PLAYBOOK_BY_ID:
            self.sel = pid
        if self.app.current != "guided":
            self.app.show_page("guided")
        self.request_render()

    def recommendations(self):
        return guided.recommend(self.app.analysis, security=getattr(self.app, "security_result", None))

    def shutdown(self):
        self._closed = True
        for t, stop in list(self.polls.values()):
            stop.set()

    # ------------------------------------------------------------------ rendering
    def render(self, force=False):
        """Full redraw, skipped when nothing it depends on changed (results arrive in the background at any time)."""
        try:
            recs = self.recommendations()
        except Exception as e:
            core.log_error("guided recommend", e)
            recs = []
        rec_ids = {pb["id"]: (why, sc) for pb, why, sc in recs}
        if not self.sel or self.sel not in guided.PLAYBOOK_BY_ID:
            self.sel = recs[0][0]["id"] if recs else guided.PLAYBOOKS[0]["id"]
        try:
            sig = (self.sel, tuple((pb["id"], why) for pb, why, _ in recs), json.dumps(self.state.data, sort_keys=True, default=str),
                   tuple(sorted(k for k, v in self.busy.items() if v)), bool(self.app.is_admin), tuple(sorted(self._focus_cats())))
        except Exception:
            sig = None
        if sig is not None and sig == self._sig and not force:
            return
        self._sig = sig
        self._recs = rec_ids
        self.lbl_top.setText(("%d guide(s) recommended from this PC's scan results - start with the first one." % len(recs)) if recs else
                             "No problems detected yet that match a guide. Run the scan, or pick a guide yourself.")
        self._render_left(recs, rec_ids)
        self.render_detail(rec_ids.get(self.sel))

    def _render_left(self, recs, rec_ids):
        W.clear_layout(self.left_lay)
        self._rows = {}
        self.left_lay.addWidget(self._section_lbl("Recommended for this PC" if recs else "No problems detected yet"))
        order = [pb for pb, _, _ in recs] + [pb for pb in guided.PLAYBOOKS if pb["id"] not in rec_ids]
        for i, pb in enumerate(order):
            if i == len(recs) and recs:
                self.left_lay.addWidget(self._section_lbl("Other guides", top=T.S3))
            row = _PbRow(pb, pb["id"] == self.sel, lambda p=pb["id"]: self._select(p))
            done, total = self.state.progress(pb["id"])
            row.set_progress(rec_ids[pb["id"]][0] if pb["id"] in rec_ids else "", done, total)
            self._rows[pb["id"]] = row
            self.left_lay.addWidget(row)
        self.left_lay.addStretch(1)

    @staticmethod
    def _section_lbl(text, top=T.S2):
        w = W.label(text, "Label")
        w.setContentsMargins(T.S3, top, T.S3, T.S1)
        return w

    def _select(self, pid):
        if pid == self.sel:
            return
        self.sel = pid
        self.render()
        self.right.verticalScrollBar().setValue(0)

    def render_detail(self, rec):
        lay = self.right.lay
        W.clear_layout(lay)
        pb = guided.PLAYBOOK_BY_ID[self.sel]
        st = self.state.pb(pb["id"])
        # ---- hero panel
        hero = W.Panel(None)
        hv = hero.body
        hv.setSpacing(T.S2)
        top = QHBoxLayout()
        top.setSpacing(T.S2)
        title = _wl(pb["title"], "Value", size=17, weight=700, sel=False)
        top.addWidget(title, 1)
        if not st.get("started"):
            top.addWidget(W.button("Start this guide", lambda p=pb: (self._start(p), self.render(force=True)), "primary", icon="play"), 0, Qt.AlignTop)
        top.addWidget(W.button("Reset progress", lambda p=pb: self._reset(p), icon="refresh"), 0, Qt.AlignTop)
        hv.addLayout(top)
        if rec:
            hv.addWidget(_wl("Why this guide: " + rec[0], color=T.WARN))
        hv.addWidget(_wl(pb["intro"], "Value"))
        src = guided.DOCS.get(pb["source"])
        if src:
            hv.addWidget(_link("Based on: " + src[0], src[1]))
        done, total = self.state.progress(pb["id"])
        hv.addSpacing(T.S1)
        meter = W.Meter(4)
        meter.set(done / float(total or 1), T.OK if done >= total else T.ACCENT)
        hv.addWidget(meter)
        plbl = _wl(self._progress_text(pb), "Muted", size=11, mono=True, color=T.TEXT2)
        hv.addWidget(plbl)
        lay.addWidget(hero)
        self._prog = (meter, plbl)
        # ---- steps
        steps = W.Panel("Steps", "Work from the top. The highlighted step is the next one to do.")
        steps.body.setContentsMargins(0, 0, 0, 0)
        steps.body.setSpacing(0)
        self._steps_panel = steps
        self._detail_pb = pb["id"]
        self._cards = {}
        self._done_lbl = None
        nxt = self.state.next_step(pb["id"])
        focus = self._focus_cats()
        for n, s in enumerate(pb["steps"], 1):
            cur = nxt is not None and s["id"] == nxt["id"]
            w = self.render_step(pb, s, n, cur, focus)
            steps.body.addWidget(w)
            self._cards[pb["id"] + "/" + s["id"]] = (w, self._step_sig(pb, s, cur, focus))
        lay.addWidget(steps)
        self._sync_done_label(pb, nxt)
        lay.addStretch(1)

    def _progress_text(self, pb):
        done, total = self.state.progress(pb["id"])
        st = self.state.pb(pb["id"])
        return "%d of %d steps done%s" % (done, total, ("   |   started %s" % st["started"].replace("T", " ")) if st.get("started") else "")

    def _sync_done_label(self, pb, nxt):
        if nxt is None and self._done_lbl is None:
            self._done_lbl = W.Banner("All steps done. Run 'Confirm the fix' again in a few days to make sure the problem has not come back.", "", "OK")
            self.right.lay.insertWidget(1, self._done_lbl)
        elif nxt is not None and self._done_lbl is not None:
            self._done_lbl.hide()
            self._done_lbl.deleteLater()
            self._done_lbl = None

    def _step_sig(self, pb, s, current, focus):
        key = pb["id"] + "/" + s["id"]
        try:
            ss = json.dumps(self.state.step(pb["id"], s["id"]), sort_keys=True, default=str)
        except Exception:
            ss = str(self.state.step(pb["id"], s["id"]))
        return (current, ss, bool(self.busy.get(key)), bool(s.get("focus") and focus & set(s["focus"])), tuple(self._step_extra(pb, s)),
                bool(self.app.is_admin))

    def refresh_steps(self):
        """Redraw only the step rows that changed (plus progress) - a click doesn't rebuild the whole page."""
        if not self.isVisible():
            self._sig = None
            self.request_render()
            return
        pb = guided.PLAYBOOK_BY_ID.get(self.sel)
        if not pb or self._detail_pb != pb["id"] or not self._cards or not self._prog:
            return self.render(force=True)
        try:
            nxt = self.state.next_step(pb["id"])
            focus = self._focus_cats()
            body = self._steps_panel.body
            for n, s in enumerate(pb["steps"], 1):
                key = pb["id"] + "/" + s["id"]
                cur = nxt is not None and s["id"] == nxt["id"]
                sig = self._step_sig(pb, s, cur, focus)
                old = self._cards.get(key)
                if old and old[1] == sig:
                    continue
                w = self.render_step(pb, s, n, cur, focus)
                if old:
                    idx = body.indexOf(old[0])
                    body.insertWidget(idx if idx >= 0 else body.count(), w)
                    old[0].hide()
                    old[0].deleteLater()
                else:
                    body.addWidget(w)
                self._cards[key] = (w, sig)
            done, total = self.state.progress(pb["id"])
            self._prog[0].set(done / float(total or 1), T.OK if done >= total else T.ACCENT)
            self._prog[1].setText(self._progress_text(pb))
            self._sync_done_label(pb, nxt)
            for pid, row in self._rows.items():
                d, t = self.state.progress(pid)
                row.set_progress(self._recs[pid][0] if pid in self._recs else "", d, t)
        except Exception as e:
            core.log_error("guided refresh", e)
            return self.render(force=True)
        self._sig = None        # the next full render() must not be skipped

    def _reset(self, pb):
        if not W.confirm(self, "Forget all results and progress of '%s'?\n\nNothing on the PC is changed - "
                         "only WinDiag's notes for this guide are cleared." % pb["title"], "WinDiag - Reset progress"):
            return
        self.state.reset(pb["id"])
        self.render(force=True)

    def _focus_cats(self):
        a = self.app.analysis or {}
        return {p["cat"] for p in a.get("problems", [])}

    def render_step(self, pb, s, n, current, focus):
        ss = self.state.step(pb["id"], s["id"])
        status = ss.get("status", "todo")
        col = ST_COLOR.get(status, T.MUTED)
        card = QFrame()
        card.setObjectName("GStep")
        card.setStyleSheet("QFrame#GStep{background:%s; border:0; border-top:1px solid %s; border-left:2px solid %s;}"
                           % (T.tint(T.ACCENT, 0.06) if current else "transparent", T.LINE, T.ACCENT if current else "transparent"))
        outer = QHBoxLayout(card)
        outer.setContentsMargins(T.S4 - 2, T.S3, T.S4, T.S4)
        outer.setSpacing(T.S3)
        num = _mono("%02d" % n, 12, 600, T.TEXT if current else T.MUTED)
        num.setContentsMargins(0, 2, 0, 0)
        outer.addWidget(num, 0, Qt.AlignTop)
        main = QVBoxLayout()
        main.setSpacing(T.S2)
        outer.addLayout(main, 1)
        head = QHBoxLayout()
        head.setSpacing(T.S2)
        dot = QLabel("●")
        dot.setStyleSheet("color:%s; font-size:11px;" % col)
        dot.setContentsMargins(0, 1, 0, 0)
        head.addWidget(dot, 0, Qt.AlignTop)
        tl = _wl(s["title"], "Value", weight=700, sel=False)
        head.addWidget(tl, 1)
        head.addWidget(W.Badge(guided.STATUS_TEXT.get(status, status.upper()), col), 0, Qt.AlignTop)
        main.addLayout(head)
        tags = []
        if s.get("focus") and focus & set(s["focus"]):
            tags.append(W.Badge("RECOMMENDED FOR YOUR CASE", T.WARN))
        if s.get("reboot"):
            tags.append(W.Badge("NEEDS RESTART", T.INFO))
        if s.get("advanced"):
            tags.append(W.Badge("ADVANCED", T.MUTED))
        if tags:
            main.addWidget(_flow_widget(tags, T.S1))
        if s["why"]:
            main.addWidget(_wl(s["why"], "Body"))
        for m in s.get("manual", []):
            main.addWidget(_wl("\u2022 " + m, "Body"))
        for line, url in self._step_extra(pb, s):
            main.addWidget(_link(line, url) if url else _wl(line, color=T.WARN))
        if s.get("cmd"):
            main.addWidget(_wl("Technical (what WinDiag runs):  " + s["cmd"], "Muted", size=11, mono=True))
        docs = list(s.get("docs", []))
        vd = guided.VERIFY_DOC.get(s.get("verify") or "")
        if vd and vd not in docs:
            docs.append(vd)
        for d in docs:
            if d in guided.DOCS:
                main.addWidget(_link(guided.DOCS[d][0], guided.DOCS[d][1]))
        if ss.get("detail"):
            main.addWidget(_wl("Result: " + ss["detail"], color=col, weight=700))
        smp = [str(x) for x in (ss.get("sample") or [])[:8]]
        if smp:
            main.addWidget(_wl("\n".join(smp), "Muted", size=11, mono=True, color=T.TEXT2))
        key = pb["id"] + "/" + s["id"]
        busy = self.busy.get(key)
        btns = []
        a = s.get("action")
        if a:
            label = self._action_label(a)
            if label:
                admin_only = a.get("type") == "repair" and core.REPAIR_BY_NAME.get(a["target"], {}).get("admin") and not self.app.is_admin
                b = W.button(label, lambda p=pb, x=s: self.do_action(p, x), "primary" if current else "secondary",
                             tip="Needs administrator rights" if admin_only else None)
                b.setEnabled(not admin_only and not busy)
                btns.append(b)
        if s.get("verify"):
            b = W.button("Checking..." if busy else "Check result", lambda p=pb, x=s: self.do_verify(p, x), icon="check")
            b.setEnabled(not busy)
            btns.append(b)
        btns.append(W.button("Mark done", lambda p=pb, x=s: self._set(p, x, status="done", detail=self.state.step(p["id"], x["id"]).get("detail", "")), "ghost"))
        btns.append(W.button("Skip", lambda p=pb, x=s: self._set(p, x, status="skipped"), "ghost"))
        fw = _flow_widget(btns)
        fw.setContentsMargins(0, T.S1, 0, 0)
        main.addWidget(fw)
        return card

    def _action_label(self, a):
        t = a.get("type")
        if t == "repair":
            return "Run: " + a["target"]
        if t in ("launch", "page", "netfix"):
            return a.get("label") or "Open"
        return {"stopcodes": "Show my stop codes", "wucodes": "Show my update errors", "dump": "Analyse crash dumps",
                "kp41": "Show my shutdowns", "catalog": "Search failed KBs in the Update Catalog"}.get(t)

    def _step_extra(self, pb, s):
        """Extra dynamic info for a step (links / notes)."""
        out = []
        if s["id"] == "drivers" and self.dump_result:
            for r in self.dump_result.get("results", [])[:3]:
                if r.get("culprit"):
                    out.append(("Crash dump points to: %s - %s" % (r["culprit"], r.get("hint", "")), None))
        if s["id"] == "dump" and not self.app.is_admin:
            out.append(("Needs administrator rights to read C:\\Windows\\Minidump.", None))
        if s["id"] == "dump":
            out.append(("Needs Microsoft's free debugger: ", None))
            out.append(("Install WinDbg (winget install Microsoft.WinDbg)", "https://aka.ms/windbg/download"))
        return out

    # ------------------------------------------------------------------ state changes
    def _reopen_toggled(self, on):
        self.state.data["reopen"] = bool(on)
        self.state.save()

    def _set(self, pb, s, **kw):
        if self._closed:
            return
        started = bool(self.state.pb(pb["id"]).get("started"))
        if not started:
            self._start(pb)
        self.state.data["reopen"] = bool(self.reopen.isChecked())
        self.state.set(pb["id"], s["id"], **kw)
        if started and pb["id"] == self.sel:
            self.refresh_steps()
        else:
            self._sig = None
            self.request_render()

    def _start(self, pb):
        """Start a playbook; the first time, record a 'before' measurement for the before/after comparison."""
        d = self.state.pb(pb["id"])
        first = not d.get("baseline_id") and not d.get("baseline_pending")
        self.state.start(pb["id"])
        if first and getattr(self.app, "baselines", None) is not None:
            d["baseline_pending"] = True
            self.state.save()
            import baseline as bl

            def done(snap):
                d.pop("baseline_pending", None)
                if snap:
                    d["baseline_id"] = snap["id"]
                self.state.save()

            def failed(msg):
                d.pop("baseline_pending", None)
                self.state.save()
            tasks.run_task(bl.take_snapshot, done, failed, args=(self.app, "Before Guided Fix: %s" % pb["title"]), name="guided-baseline")

    def _since(self, pb, s):
        ss = self.state.step(pb["id"], s["id"])
        if s.get("verify") == "monitor":
            return self.state.pb(pb["id"]).get("started") or datetime.now().isoformat(timespec="seconds")
        return ss.get("since") or self.state.pb(pb["id"]).get("started") or (datetime.now() - timedelta(days=1)).isoformat(timespec="seconds")

    # ------------------------------------------------------------------ actions
    def do_action(self, pb, s):
        a = s["action"]
        t = a.get("type")
        # same PIN rule as the Repairs page: anything that changes the PC or opens admin tools asks first
        if t in ("repair", "launch", "netfix") and not self.app.pin.require("Guided Fix: " + (self._action_label(a) or s["title"])):
            return
        now = datetime.now().isoformat(timespec="seconds")
        if t == "repair":
            rep = core.REPAIR_BY_NAME.get(a["target"])
            if not rep:
                return
            if rep.get("confirm") and not W.confirm(self, rep["confirm"], "WinDiag - " + rep["name"], danger=True):
                return
            self._start(pb)
            sdir = os.path.join(os.path.dirname(self.state.path), ".status")
            try:
                os.makedirs(sdir, exist_ok=True)
            except Exception:
                sdir = core._work
            status_path = os.path.join(sdir, "st_%s.json" % uuid.uuid4().hex[:8])
            try:
                core.start_repair(rep, self.app.report_dir, status_path=status_path)
            except Exception as e:
                core.log_error("guided repair " + rep["name"], e)
                self._set(pb, s, status="error", detail="Could not start: %s" % core.friendly_error(e))
                return
            self._set(pb, s, status="waiting" if s.get("reboot") else "running", since=now, status_file=status_path,
                      detail=("Restart the PC to run it. WinDiag checks the result when it is opened again." if s.get("reboot")
                              else "Running in its own window - the result is checked automatically when it finishes."))
            self.app.set_status("Started: %s (runs in its own window, logged to the Reports folder)" % rep["name"])
            if s.get("reboot") and self.reopen.isChecked():
                set_runonce(True)
            if not s.get("reboot"):
                self._poll_status(pb, s, status_path)
            return
        self._start(pb)
        if t == "launch":
            try:
                core.open_tool(a["target"])
            except Exception as e:
                core.log_error("guided launch", e)
                self._set(pb, s, status="error", detail="Could not open: %s" % core.friendly_error(e))
                return
            self._set(pb, s, status="running", since=now, detail="Opened. Follow the instructions, then click 'Check result' or 'Mark done'.")
            if s.get("reboot") and self.reopen.isChecked():
                set_runonce(True)
        elif t == "page":
            page, _, tab = a["target"].partition(":")
            self._set(pb, s, status="running", since=now, detail="Opened %s. Come back here and click 'Check result' or 'Mark done'." % (tab or "the page"))
            self.app.open_page(page, tab or None)
        elif t == "netfix":
            self._set(pb, s, status="running", since=now, detail="Running in Network Tools > Fixes - the before/after measurements appear there. "
                                                                 "Then click 'Check result' or 'Mark done'.")
            self.app.open_page("nettools", "Fixes")
            nt = self.app.page("nettools")
            if hasattr(nt, "run_fix"):
                nt.run_fix(a["target"])
            else:
                self._set(pb, s, status="error", detail="Network Tools could not be opened - details in Reports\\windiag_errors.log.")
        elif t == "stopcodes":
            self._show_stopcodes(pb, s)
        elif t == "wucodes":
            self._show_wucodes(pb, s)
        elif t == "kp41":
            self._show_kp41(pb, s)
        elif t == "catalog":
            kbs = self._failed_kbs()
            for kb in kbs[:3]:
                open_url("https://www.catalog.update.microsoft.com/Search.aspx?q=%s" % kb)
            if not kbs:
                open_url(guided.DOCS["catalog"][1])
            self._set(pb, s, status="running", since=now, detail=("Opened the catalog for: " + ", ".join(kbs[:3])) if kbs else
                      "Opened the Microsoft Update Catalog - search the KB number of the failing update.")
        elif t == "dump":
            self._run_dump(pb, s)
        elif t == "manual":
            self._set(pb, s, status="running", since=now, detail="Follow the instructions above, then click 'Mark done'.")

    def _poll_status(self, pb, s, path):
        """Wait (in a worker, up to ~2 h) for the repair window to write its status file, then check the result."""
        key = pb["id"] + "/" + s["id"]
        old = self.polls.get(key)
        if old is not None and old[0].running():
            return

        stop = threading.Event()

        def wait():
            for _ in range(2400):
                if os.path.exists(path):
                    stop.wait(0.5)
                    return not stop.is_set()
                if stop.wait(3):
                    return False
            return False

        def done(found):
            self.polls.pop(key, None)
            if found and not self._closed:
                QTimer.singleShot(1000, lambda: None if self._closed else self.do_verify(pb, s))
        t = tasks.run_task(wait, done, lambda m: self.polls.pop(key, None), name="guided-poll")
        self.polls[key] = (t, stop)

    # ------------------------------------------------------------------ analysis-based actions
    def _stopcodes(self):
        a = self.app.analysis or {}
        codes = {}
        for i in a.get("instances", []):
            m = re.search(r"0x([0-9A-Fa-f]{8})\s+(\w+)", i.get("meaning", ""))
            if m:
                c = int(m.group(1), 16)
                d = codes.setdefault(c, {"name": m.group(2), "count": 0, "last": i["time"]})
                d["count"] += 1
        return codes

    def _show_stopcodes(self, pb, s):
        codes = self._stopcodes()
        if not codes:
            self._set(pb, s, status="review", detail="No blue-screen stop codes found in the event log for this period.", sample=[])
            return
        lines = []
        for c, d in sorted(codes.items(), key=lambda kv: -kv[1]["count"]):
            nm, cats, hint = event_kb.describe_stop(c)
            lines.append("0x%08X %s  (x%d)  - %s" % (c, d["name"], d["count"], hint))
        for c in list(codes)[:4]:
            open_url(guided.bugcheck_url(c))
        self._set(pb, s, status="review", detail="%d stop code(s) found - Microsoft's reference page for each was opened in your browser." % len(codes),
                  sample=lines, since=datetime.now().isoformat(timespec="seconds"))

    def _wu_fails(self):
        a = self.app.analysis or {}
        out = []
        for g in a.get("matched", []):
            m = re.match(r"Update FAILED \(([^)]*)\): (.*)", g.get("meaning", ""))
            if m:
                out.append((m.group(1), m.group(2), g.get("count", 1)))
        return out

    def _failed_kbs(self):
        kbs = []
        for _, title, _ in self._wu_fails():
            for kb in re.findall(r"KB\d{6,8}", title):
                if kb not in kbs:
                    kbs.append(kb)
        return kbs

    def _show_wucodes(self, pb, s):
        fails = self._wu_fails()
        if not fails:
            self._set(pb, s, status="review", detail="No failed updates found in the event log for this period.", sample=[])
            return
        lines = []
        for code, title, n in fails[:8]:
            info = guided.wu_error_info(code) or {}
            lines.append("%s %s (x%d): %s" % (info.get("code", code), info.get("name") or "(not in Microsoft's common list)", n, title[:70]))
            if info.get("fix"):
                lines.append("      Microsoft's fix: " + info["fix"])
        open_url(guided.DOCS["wu_errors"][1])
        self._set(pb, s, status="review", detail="%d failed update(s). Microsoft's error table was opened in your browser." % len(fails), sample=lines,
                  since=datetime.now().isoformat(timespec="seconds"))

    def _show_kp41(self, pb, s):
        a = self.app.analysis or {}
        kinds = {}
        for i in a.get("instances", []):
            if i["title"].startswith(("Sudden power loss", "Frozen", "Crash restart")):
                k = i["title"].split(" (")[0]
                kinds[k] = kinds.get(k, 0) + 1
        if not kinds:
            self._set(pb, s, status="review", detail="No unexpected shutdowns found in this period.", sample=[])
            return
        expl = {"Sudden power loss": "no stop code, nothing logged before it -> power cut, PSU/battery, loose cable or overheating",
                "Frozen - power button held": "the PC hung and was forced off -> driver, GPU, RAM or storage hang",
                "Crash restart": "a blue screen happened -> follow the Blue screens guide"}
        lines = ["%dx %s: %s" % (n, k, expl.get(k, "")) for k, n in kinds.items()]
        self._set(pb, s, status="review", detail="Breakdown of the unexpected shutdowns:", sample=lines, since=datetime.now().isoformat(timespec="seconds"))

    def _run_dump(self, pb, s):
        key = pb["id"] + "/" + s["id"]
        if self.busy.get(key):
            return
        self.busy[key] = True
        self._set(pb, s, status="running", detail="Analysing crash dumps with Microsoft's debugger...")
        report_dir = self.app.report_dir

        def work(progress=None):
            try:
                res = core.analyze_dumps(progress=progress)
            except Exception as e:
                core.log_error("guided dump analysis", e)
                return {"error": "Analysis failed - " + core.friendly_error(e), "results": []}
            if not res.get("error"):
                try:
                    with open(os.path.join(report_dir, "crash_dump_analysis.txt"), "w", encoding="utf-8") as fh:
                        for r in res.get("results") or []:
                            fh.write("===== %s =====\n%s\n\n" % (r.get("file"), r.get("raw", "")))
                except Exception:
                    pass
            return res

        tasks.run_task(work, lambda res: self._dump_done(pb, s, res if isinstance(res, dict) else {"error": "No result", "results": []}),
                       lambda m: self._dump_done(pb, s, {"error": "Analysis failed - " + m, "results": []}),
                       on_progress=lambda m: self.app.set_status(str(m)), name="guided-dump")

    def _dump_done(self, pb, s, res):
        self.busy.pop(pb["id"] + "/" + s["id"], None)
        if self._closed:
            return
        if res.get("error"):
            self._set(pb, s, status="fail", detail=res["error"], sample=[])
            return
        results = res.get("results") or []
        slim = {"results": [{k: v for k, v in r.items() if k != "raw"} for r in results]}
        self.dump_result = slim
        self.state.data["dump"] = slim
        lines = []
        for r in results:
            code = r.get("bugcheck", "")
            lines.append("%s  %s  %s (0x%s)" % (r.get("time", "")[:16].replace("T", " "), r.get("file", ""), r.get("name") or "?", code))
            lines.append("      Caused by: %s  -  %s" % (r.get("culprit") or "unknown", r.get("hint", "")))
            if r.get("process"):
                lines.append("      Process: %s   Bucket: %s" % (r["process"], r.get("bucket", "")))
        cul = [r.get("culprit") for r in results if r.get("culprit")]
        top = max(set(cul), key=cul.count) if cul else None
        detail = ("Most dumps point to %s. Update or remove it (see the drivers step)." % top) if top else \
            "Analysed, but no clear culprit - see the raw result in the report folder."
        self._set(pb, s, status="review", detail=detail, sample=lines)

    # ------------------------------------------------------------------ verification
    def do_verify(self, pb, s):
        kind = s.get("verify")
        if not kind or self._closed:
            return
        key = pb["id"] + "/" + s["id"]
        if self.busy.get(key):
            return
        self.busy[key] = True
        self.refresh_steps()
        ss = self.state.step(pb["id"], s["id"])
        since = self._since(pb, s)
        status_file = ss.get("status_file") or ""
        # everything the worker needs is captured here, on the GUI thread
        bid = self.state.pb(pb["id"]).get("baseline_id")
        server = False
        if kind == "monitor":
            try:
                server = bool(self.app._is_server())
            except Exception:
                server = False
        app = self.app
        title = pb["title"]

        def work():
            if kind == "monitor":
                res = self._monitor(pb["id"], since, server)
                try:
                    extra = self._before_after(app, bid, title)
                    if extra:
                        res["sample"] = list(res.get("sample") or []) + extra
                except Exception:
                    pass
            elif kind == "security":
                res = self._security_check()
            else:
                script = guided.VERIFY_PS[kind].replace("{since}", since).replace("{status}", status_file.replace("'", "''"))
                res = core.run_ps_json(script, 240, "Guided Fix check: " + s["title"])
                res = self._interpret(s, res if isinstance(res, dict) else {})
            if not isinstance(res, dict):
                res = {"status": "error", "detail": "No result"}
            return res

        def failed(msg):          # the worker already logged the traceback
            self._verified(pb, s, {"status": "error", "detail": "Check failed - " + msg})
        tasks.run_task(work, lambda res: self._verified(pb, s, res), failed, name="guided-verify")

    @staticmethod
    def _before_after(app, bid, title):
        """Blocking (worker): take an 'after' measurement and compare with the playbook's 'before'."""
        import baseline as bl
        before = app.baselines.get(bid) if bid else None
        if not before:
            return []
        after = bl.take_snapshot(app, "After Guided Fix: %s" % title)
        if not after:
            return []
        return ["Before/after (%s -> now):" % (before.get("time") or "")[:16].replace("T", " ")] + ["  " + x for x in bl.summary_lines(before, after)]

    @staticmethod
    def _interpret(s, res):
        if s.get("verify") != "status_exit" or res.get("status") != "done":
            if s.get("verify") == "wu_history" and res.get("fails"):
                fails = res["fails"] if isinstance(res["fails"], list) else [res["fails"]]
                res["sample"] = []
                for fl in fails[:5]:
                    if not isinstance(fl, dict):
                        continue
                    info = guided.wu_error_info(fl.get("code", "")) or {}
                    res["sample"].append("%s %s: %s" % (info.get("code", ""), info.get("name") or "", (fl.get("title") or "")[:70]))
                    if info.get("fix"):
                        res["sample"].append("   Microsoft's fix: " + info["fix"])
            return res
        ex = res.get("exit")
        target = (s.get("action") or {}).get("target", "")
        try:
            ex = int(ex)
        except (TypeError, ValueError):
            ex = None
        if "CHKDSK scan" in target:
            m = {0: ("pass", "No file-system errors found."), 2: ("pass", "No errors (cleanup done)."),
                 1: ("fixed", "Errors were found and fixed."), 3: ("fail", "Errors found that need 'CHKDSK repair at restart' (next step).")}
            st, d = m.get(ex, ("review", "CHKDSK finished with exit code %s." % ex))
        elif ex in (0, None):
            st, d = "pass", "Finished successfully."
        else:
            st, d = "fail", "Finished with exit code %s (0x%08X)." % (ex, ex & 0xFFFFFFFF)
            if ex & 0xFFFFFFFF == 0x800F081F:
                d += " DISM could not find repair files - use 'In-place repair' or a Windows ISO as source."
        res.update({"status": st, "detail": d + " " + res.get("detail", "")})
        return res

    def _security_check(self):
        """Worker. The full result is handed to the app on the GUI thread (Security Scan page + recommendations)."""
        import security
        raw = core.run_ps_json(security.TRIAGE_PS, 1200)
        if raw.get("status") == "error":
            return raw
        a = security.analyze(raw)
        self.app.q.put(("guided_cb", None, lambda: self.app.set_security_result(a)))
        c = a["counts"]
        active = [f["title"] for f in a["findings"] if f["title"].startswith("ACTIVE threat")]
        smp = [f["title"] for f in a["findings"] if f["severity"] == "CRITICAL"][:8]
        if c["CRITICAL"]:
            return {"status": "fail", "detail": "%d critical item(s) still present%s." % (c["CRITICAL"], " including an ACTIVE threat" if active else ""), "sample": smp}
        if c["WARNING"]:
            return {"status": "review", "detail": "No critical items. %d warning(s) to review on the Security Scan page." % c["WARNING"],
                    "sample": [f["title"] for f in a["findings"] if f["severity"] == "WARNING"][:8]}
        return {"status": "pass", "detail": "No critical items or warnings - looks clean."}

    @staticmethod
    def _monitor(pid, since, server):
        t0 = datetime.fromisoformat(since)
        days = max(2, (datetime.now() - t0).days + 2)
        r = core.run_check("Events", days=days)
        a = event_kb.analyze(r.get("events", []), server=server)
        cats = guided.MONITOR_CATS.get(pid)
        names = {event_kb.CATEGORIES[c]["name"] for c in (cats or []) if c in event_kb.CATEGORIES}
        new = []
        for i in a.get("instances", []):
            if not i["time"] or i["time"] < t0:
                continue
            if cats is None:
                if i["title"].startswith("Blue screen"):
                    new.append(i)
            elif names & set(i.get("categories") or []):
                new.append(i)
        hours = (datetime.now() - t0).total_seconds() / 3600
        if new:
            return {"status": "fail", "detail": "%d new event(s) since %s - the problem is still happening." % (len(new), t0.strftime("%Y-%m-%d %H:%M")),
                    "sample": ["%s  %s" % (i["time"].strftime("%Y-%m-%d %H:%M"), i["title"]) for i in new[:8]]}
        if hours < 48:
            return {"status": "pending", "detail": "No new events in the %.0f hour(s) since you started. Keep using the PC normally and check again after a day or two." % hours}
        return {"status": "pass", "detail": "No new events in the %.0f days since you started - looks fixed." % (hours / 24)}

    def _verified(self, pb, s, res):
        self.busy.pop(pb["id"] + "/" + s["id"], None)
        if self._closed:
            return
        st = res.get("status", "review")
        if st == "done":
            st = "pass"
        if st == "pending" and s.get("reboot"):
            st = "waiting"
        smp = res.get("sample") or []
        if isinstance(smp, str):
            smp = [smp]
        self._set(pb, s, status=st, detail=res.get("detail", ""), sample=smp)
        tone = {"pass": "OK", "fixed": "OK", "fail": "CRITICAL", "error": "CRITICAL", "review": "WARNING"}.get(st)
        self.app.set_status("Guided Fix: %s - %s" % (s["title"], guided.STATUS_TEXT.get(st, st)), tone, hold=4)

    def resume_checks(self):
        """Called when WinDiag starts: re-check steps that were waiting (e.g. after a restart)."""
        waiting = self.state.waiting()
        if waiting:
            set_runonce(False)
        for pid, sid, st in waiting:
            pb = guided.PLAYBOOK_BY_ID.get(pid)
            s = next((x for x in (pb or {}).get("steps", []) if x["id"] == sid), None)
            if s and s.get("verify"):
                self.do_verify(pb, s)
            elif s and st.get("status_file"):
                self._poll_status(pb, s, st["status_file"])
        return len(waiting)
