"""Drive-wipe wizard (Qt): contents preview -> safety checks -> confirmations -> final summary + countdown -> wipe -> verify -> certificate.

All drive access (safety check, identity, launch, verify, certificate) runs in workers (tasks.run_task); the dialog only polls.
The safety logic lives unchanged in wipesafe.py / drivehealth.py.
"""
import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QScrollArea, QVBoxLayout, QWidget)

import core
import drivehealth as dh
import wipesafe as ws
from .. import tasks
from .. import theme as T
from .. import widgets as W
from .drives import mono_css, mono_label

STEPS = ["Contents", "Safety checks", "Confirm", "Final check", "Wipe"]
LOCK_SECONDS = 10
COUNTDOWN = 10
RUNNING_PHASES = ("wiping", "verifying", "launching")


def _rule_panel(title=None, status=None):
    """Panel with an optional coloured left rule. Returns (panel, body layout)."""
    f = QFrame()
    f.setObjectName("WipeCard")
    if status:
        col = T.STATUS.get(status, status)
        f.setStyleSheet("QFrame#WipeCard{background:%s; border:1px solid %s; border-left:3px solid %s; border-radius:4px;}"
                        % (T.tint(col, 0.06, T.SURFACE), T.LINE, col))
    else:
        f.setStyleSheet("QFrame#WipeCard{background:%s; border:1px solid %s; border-radius:4px;}" % (T.SURFACE, T.LINE))
    v = QVBoxLayout(f)
    v.setContentsMargins(T.S4, T.S4, T.S4, T.S4)
    v.setSpacing(T.S2)
    if title:
        v.addWidget(W.label(title, "PanelTitle", wrap=True))
    return f, v


def _mono(text, color=None, size=12, wrap=True, weight=400):
    return mono_label(text, color or T.TEXT2, size, weight, wrap)


class WipeWizard(QDialog):
    def __init__(self, app, d, page):
        super().__init__(app)
        self.app, self.d, self.page = app, dict(d), page
        self.setWindowTitle("WinDiag - wipe disk %s" % d.get("number"))
        self.setWindowModality(Qt.ApplicationModal)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.resize(820, 700)
        self.setMinimumSize(640, 520)
        self.step = 0
        self.chk = None
        self.power = (False, True)
        self.rep_disk = None
        self.block, self.warn = [], []
        self.replug = {"state": "idle"}
        self.replug_cancel = threading.Event()
        self.cancel_ev = threading.Event()
        self.phase = "check"      # check / confirm / countdown / launching / wiping / verifying / done / closed
        self.paths = {}
        self.t_launch = None
        self.wst = None
        self.cert = None
        self.est = 60
        self._status_busy = False
        # confirmation state survives Back / Next (re-created widgets read these)
        self.cb1 = self.cb2 = False
        self.newpart = True
        self.typed = ""
        self.lock_until = None
        self.want = ""
        self.ent = None
        self.ent_msg = None
        self.btn_replug = self.lbl_replug = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        top = QFrame()
        top.setObjectName("Header")
        tl = QVBoxLayout(top)
        tl.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        tl.setSpacing(2)
        t = QLabel("Wipe entire drive")
        t.setObjectName("PageTitle")            # Syne via the app QSS (setFont alone is overridden by the '*' rule)
        tl.addWidget(t)
        tl.addWidget(_mono("%s  ·  %s  ·  disk %s" % (d.get("model") or "Drive", ws.fmt_bytes(d.get("size")), d.get("number")), T.TEXT2, 12))
        self.stepbar = QHBoxLayout()
        self.stepbar.setContentsMargins(0, T.S3, 0, 0)
        self.stepbar.setSpacing(T.S5)
        tl.addLayout(self.stepbar)
        root.addWidget(top)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("Root")
        self.body = QVBoxLayout(inner)
        self.body.setContentsMargins(T.S5, T.S4, T.S5, T.S4)
        self.body.setSpacing(T.S3)
        self.scroll.setWidget(inner)
        root.addWidget(self.scroll, 1)
        foot = QFrame()
        foot.setObjectName("StatusBar")
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(T.S5, T.S3, T.S5, T.S3)
        self.btn_cancel = W.button("Cancel", self._close)
        fl.addWidget(self.btn_cancel)
        fl.addStretch(1)
        self.btn_back = W.button("Back", self._back, "ghost")
        fl.addWidget(self.btn_back)
        self.btn_next = W.button("Next", self._next, "primary", min_w=170)
        fl.addWidget(self.btn_next)
        for b in (self.btn_cancel, self.btn_back, self.btn_next):
            b.setAutoDefault(False)
            b.setDefault(False)
        root.addWidget(foot)

        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(250)
        self._lock_timer.timeout.connect(self._lock_tick)
        self._cd_timer = QTimer(self)
        self._cd_timer.setInterval(1000)
        self._cd_timer.timeout.connect(self._cd_tick)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(2000)
        self._poll_timer.timeout.connect(self._poll)

        self._render_steps()
        self._loading("Checking what's on the drive and whether it's safe to erase...")
        self._run_check(0)

    # ------------------------------------------------------------------ app contract
    def is_running(self):
        return self.phase in RUNNING_PHASES

    def shutdown(self):
        """App is closing (only possible when no wipe runs): stop timers and background pollers."""
        self.replug_cancel.set()
        self.cancel_ev.set()
        for t in (self._lock_timer, self._cd_timer, self._poll_timer):
            t.stop()

    # ------------------------------------------------------------------ keyboard / closing
    def keyPressEvent(self, e):
        if e.key() in (Qt.Key_Return, Qt.Key_Enter):
            # Enter never starts the wipe countdown (step 3) - that needs a deliberate click / Space on the red button
            if self.phase in ("check", "confirm") and self.step in (0, 1, 2) and self.btn_next.isEnabled():
                self._next()
            e.accept()
            return
        super().keyPressEvent(e)

    def reject(self):
        """Esc / window close: cancel the countdown, or close (never during the wipe)."""
        if self.phase == "countdown":
            self._abort_countdown()
            return
        self._close()

    def closeEvent(self, e):
        if self.phase in RUNNING_PHASES:
            e.ignore()
            W.warn(self, "The wipe is running. Keep this window open until it finishes - it verifies the drive and writes the certificate.")
            return
        if self.phase == "countdown":
            self._abort_countdown()
            e.ignore()
            return
        self._teardown()
        e.accept()          # not QDialog.closeEvent: that would call reject() -> _close() again

    def _close(self):
        if self.phase in RUNNING_PHASES:
            W.warn(self, "The wipe is running. Keep this window open until it finishes - it verifies the drive and writes the certificate.")
            return
        self._teardown()
        self.done(0)

    def _teardown(self):
        self.phase = "closed"
        self.shutdown()

    def _alive(self):
        return self.phase != "closed"

    # ------------------------------------------------------------------ plumbing
    def _clear(self):
        W.clear_layout(self.body)
        self.ent = self.ent_msg = None
        self.btn_replug = self.lbl_replug = None
        self.scroll.verticalScrollBar().setValue(0)

    def _render_steps(self):
        W.clear_layout(self.stepbar)
        for i, name in enumerate(STEPS):
            done, cur = i < self.step, i == self.step
            col = T.OK if done else (T.ACCENT if cur else T.MUTED)
            lb = QLabel('<span style="font-family:\'%s\'; color:%s; font-weight:600">%s</span>&nbsp;&nbsp;<span style="color:%s">%s</span>'
                        % (T.FONT_MONO, col, "✓" if done else str(i + 1), T.TEXT if cur else T.TEXT2, name))
            lb.setTextFormat(Qt.RichText)
            lb.setFont(T.ui(12, 700 if cur else 500))
            if cur:
                lb.setStyleSheet("border-bottom:2px solid %s; padding-bottom:4px;" % T.ACCENT)
            else:
                lb.setStyleSheet("border-bottom:2px solid transparent; padding-bottom:4px;")
            self.stepbar.addWidget(lb)
        self.stepbar.addStretch(1)

    def _loading(self, text):
        self._clear()
        self.body.addSpacing(48)
        self.body.addWidget(W.label(text, "Body", wrap=True), 0, Qt.AlignHCenter)
        bar = W.Meter(3)
        bar.set(0.35, T.ACCENT)
        bar.setMaximumWidth(360)
        self.body.addWidget(bar, 0, Qt.AlignHCenter)
        self.body.addStretch(1)
        self.btn_next.setEnabled(False)
        self.btn_back.setEnabled(False)

    def _add(self, w):
        self.body.addWidget(w)
        return w

    def _card(self, title=None, status=None):
        f, v = _rule_panel(title, status)
        self.body.addWidget(f)
        return v

    @staticmethod
    def _rows(lay, status, items):
        lay.addWidget(W.FindingsList([(status, t, dt) for t, dt in items]))

    def _set_next(self, text, enabled, kind="primary"):
        self.btn_next.setText(text)
        self.btn_next.setEnabled(enabled)
        if self.btn_next.property("kind") != kind:
            W.set_kind(self.btn_next, kind)

    # ------------------------------------------------------------------ step 0: safety check + contents
    def _run_check(self, step):
        n = self.d.get("number")
        drives = list(getattr(self.page, "drives", None) or [])
        report_dir = self.app.report_dir
        try:
            self.rep_disk = dh.disk_of_path(drives, report_dir) if drives else None
        except Exception as e:
            core.log_error("wipe.check (reports drive)", e)
            self.rep_disk = None

        def work():
            """Any failure becomes a 'Safety check failed' block - the wizard never stays on 'Checking...'."""
            power = (False, True)
            try:
                chk = ws.check(n)
            except Exception as e:
                core.log_error("wipe.check", e)
                chk = {"status": "error", "detail": core.friendly_error(e)}
            try:
                power = ws.power_state()
            except Exception as e:
                core.log_error("wipe.check (power)", e)
            return chk, power
        tasks.run_task(work, lambda r: self._checked(r[0], r[1], step),
                       lambda m: self._checked({"status": "error", "detail": m}, (False, True), step), name="wipe-check")

    def _checked(self, chk, power, step=0):
        if not self._alive():
            return
        try:
            self.chk, self.power = chk, power
            self.block = ws.blockers(self.d, chk, getattr(self.page, "windiag_disk", None), self.rep_disk, power)
            self.warn = ws.warnings(self.d, chk)
        except Exception as e:
            core.log_error("wipe.checked", e)
            self.chk = chk if isinstance(chk, dict) else {}
            self.block = [("Safety check failed", "Couldn't evaluate the safety check (%s). Wiping is blocked." % core.friendly_error(e))]
            self.warn = []
        self.show_step(step)

    def show_step(self, i):
        if not self._alive():
            return
        self.step = i
        self._render_steps()
        self._clear()
        self.btn_back.setEnabled(0 < i < 4)
        self.btn_back.setText("Back")
        if i < 3 and self.phase not in ("wiping", "verifying", "launching", "done"):
            self.phase = "check" if i < 2 else "confirm"
        if i != 2:
            self._lock_timer.stop()
        [self._contents, self._safety, self._confirm, self._final, self._wiping][i]()
        self.body.addStretch(1)

    def _next(self):
        if self.step == 1 and self.block:
            return
        if self.step == 2:
            if not self._confirm_ok():
                return
            if not self.app.pin.require("the drive wipe"):
                return
        if self.step == 3:
            return self._start_countdown()
        self.show_step(self.step + 1)

    def _back(self):
        if self.phase == "countdown":
            return self._abort_countdown()
        if 0 < self.step < 4:
            self.show_step(self.step - 1)

    def _contents(self):
        chk, d = self.chk or {}, self.d
        c = self._card("This is the drive that would be erased")
        g = W.KeyValueGrid(cols=3)
        g.set([("Model", chk.get("model") or d.get("model")),
               ("Serial number", chk.get("serial") or d.get("serial") or "(none reported)", {"mono": True}),
               ("Capacity", ws.fmt_bytes(chk.get("size") or d.get("size")), {"mono": True}),
               ("Connection", "%s  ·  %s" % (chk.get("bus") or d.get("bus"), chk.get("media") or "")),
               ("Disk number", d.get("number"), {"mono": True}),
               ("Data on it", ws.fmt_bytes(ws.used_bytes(chk)) if chk.get("contents") else "no readable volumes", {"mono": True})])
        c.addWidget(g)
        if not chk.get("contents"):
            c.addWidget(W.colored("No drive letters on this disk, so its files can't be listed. Check it in Disk Management if you're not sure what it is.",
                                  T.WARN, 12))
        for v in chk.get("contents", []):
            cc = self._card("%s:  %s  -  %s used of %s  ·  %s files%s" % (v.get("letter"), v.get("label") or "(no label)", ws.fmt_bytes(v.get("used")),
                                                                         ws.fmt_bytes(v.get("size")), format(ws._i(v.get("files")), ","),
                                                                         "+" if v.get("partial") else ""))
            if v.get("windows") or v.get("users"):
                cc.addWidget(W.colored(("Contains a Windows installation. " if v.get("windows") else "") +
                                       ("User folders: %s" % ", ".join(v.get("users")[:8]) if v.get("users") else ""), T.CRIT, 13, bold=True))
            cols = QWidget()
            gl = QGridLayout(cols)
            gl.setContentsMargins(0, T.S1, 0, 0)
            gl.setHorizontalSpacing(T.S5)
            gl.setColumnStretch(0, 1)
            gl.setColumnStretch(1, 1)
            left = QVBoxLayout()
            left.setSpacing(2)
            left.addWidget(W.label("TOP-LEVEL FOLDERS AND FILES", "Label"))
            for it in v.get("top", [])[:12]:
                left.addWidget(_mono("%s  %s   %s" % ("▸" if it.get("dir") else "·", it.get("name"), it.get("time") or "")))
            if not v.get("top"):
                left.addWidget(W.label("(empty)", "Muted"))
            left.addStretch(1)
            right = QVBoxLayout()
            right.setSpacing(2)
            right.addWidget(W.label("MOST RECENTLY CHANGED FILES", "Label"))
            for it in v.get("recent", [])[:10]:
                p = it.get("path") or ""
                p = p if len(p) < 52 else "..." + p[-49:]
                right.addWidget(_mono("%s   %s" % (it.get("time"), p)))
            if not v.get("recent"):
                right.addWidget(W.label("(no files)", "Muted"))
            right.addStretch(1)
            gl.addLayout(left, 0, 0)
            gl.addLayout(right, 0, 1)
            cc.addWidget(cols)
            if v.get("letter"):
                cc.addWidget(W.hbox(W.button("Open %s: in Explorer" % v["letter"], lambda l=v["letter"]: self._explore(l), icon="folder"), "stretch"))
        self._set_next("Next: safety checks", True)

    def _explore(self, letter):
        if not QDesktopServices.openUrl(QUrl.fromLocalFile("%s:\\" % letter)):
            W.error(self, "Could not open %s:" % letter)

    # ------------------------------------------------------------------ step 1: safety checks
    def _safety(self):
        chk = self.chk or {}
        if self.block:
            c = self._card("Wiping is blocked on this drive", "CRITICAL")
            c.addWidget(W.label("WinDiag won't erase this drive. Fix the items below (or pick another drive) and run the check again.", "Body", wrap=True))
            self._rows(c, "CRITICAL", self.block)
        c = self._card("Safety checks")
        passed = [("Identity locked", "Serial %s  ·  %s  ·  %s. Checked again right before erasing - if disk %s turns out to be a different drive, nothing is erased." % (
                      chk.get("serial") or "--", ws.fmt_bytes(chk.get("size")), chk.get("model"), self.d.get("number"))),
                  ("Not Windows / boot / WinDiag / Reports drive", ""), ("No page file, hibernation file or crash-dump location", ""),
                  ("Not Windows Recovery, Hyper-V, Storage Spaces, RAID or cluster storage", ""), ("No programs or services running from it", "")]
        titles = " ".join(t for t, _ in self.block)
        keys = {"Identity locked": ["changed", "not found", "failed"],
                "Not Windows / boot / WinDiag / Reports drive": ["Windows is", "System drive", "WinDiag"],
                "No page file, hibernation file or crash-dump location": ["Page file", "Hibernation", "Crash-dump"],
                "Not Windows Recovery, Hyper-V, Storage Spaces, RAID or cluster storage": ["Recovery", "Hyper-V", "Virtual disks", "Storage Spaces", "RAID", "Cluster"],
                "No programs or services running from it": ["In use"]}
        ok = [(t, dt) for t, dt in passed if not any(k in titles for k in keys[t])]
        hb, ac = self.power
        if hb and ac:
            ok.append(("Laptop is plugged in", "Keep the charger connected until the wipe finishes."))
        elif not hb:
            ok.append(("Mains powered PC", ""))
        self._rows(c, "OK", ok)
        if self.warn:
            w = self._card("Read before you continue", "WARNING")
            self._rows(w, "WARNING", self.warn)
        self._add(W.hbox(W.button("Run checks again", self._recheck, icon="refresh"), "stretch"))
        self._set_next("Next: confirm", not self.block)

    def _recheck(self):
        self._loading("Running the safety checks again...")
        self._run_check(1)

    # ------------------------------------------------------------------ step 2: confirmations
    def _confirm(self):
        chk = self.chk or {}
        want, what = ws.serial_code(chk)
        self.want = want
        self.phase = "confirm"
        c = self._card("Confirm", "CRITICAL")
        c.addWidget(W.label("Everything on %s (serial %s, %s) will be overwritten with zeros. The files can't be recovered afterwards - not by WinDiag, "
                            "not by recovery software." % (chk.get("model"), chk.get("serial") or "--", ws.fmt_bytes(chk.get("size"))), "Body", wrap=True))
        c.addSpacing(T.S2)
        cb1 = QCheckBox("I have copied everything I need from this drive")
        cb1.setChecked(self.cb1)
        cb1.toggled.connect(lambda on: (setattr(self, "cb1", on), self._upd()))
        c.addWidget(cb1)
        cb2 = QCheckBox("I understand this can't be undone")
        cb2.setChecked(self.cb2)
        cb2.toggled.connect(lambda on: (setattr(self, "cb2", on), self._upd()))
        c.addWidget(cb2)
        c.addSpacing(T.S2)
        row = QHBoxLayout()
        row.setSpacing(T.S2)
        row.addWidget(W.label("Type %s:" % what, "Value"))
        row.addWidget(W.label("(printed on the drive's label, and shown above)", "Muted", wrap=True), 1)
        c.addLayout(row)
        self.ent = QLineEdit()
        self.ent.setStyleSheet(mono_css(T.TEXT, 16))
        self.ent.setPlaceholderText("- - - -")
        self.ent.setMaximumWidth(260)
        self.ent.setText(self.typed)
        self.ent.textChanged.connect(self._typed)        # also catches a mouse paste
        c.addWidget(self.ent)
        self.ent_msg = W.label("", "Muted")
        c.addWidget(self.ent_msg)
        cb3 = QCheckBox("Afterwards, create one empty NTFS partition so the drive is ready to use")
        cb3.setChecked(self.newpart)
        cb3.toggled.connect(lambda on: setattr(self, "newpart", on))
        c.addWidget(cb3)
        if (chk.get("bus") or "").upper() in ("USB", "SD", "MMC", "1394"):
            u = self._card("Optional: unplug / re-plug check")
            u.addWidget(W.label("Proves this is the drive in your hand: click Start, unplug the drive, then plug it back in.", "Body", wrap=True))
            self.btn_replug = W.button("Start re-plug check", self._replug_start)
            self.btn_replug.setAutoDefault(False)
            self.lbl_replug = W.label("", "Body", wrap=True)
            st = self.replug.get("state")
            if st == "done":
                self.btn_replug.setEnabled(False)
                self._replug_label("✓ Confirmed - it's the drive you unplugged (disk %s)." % self.d["number"], T.OK)
            elif st in ("waiting_out", "waiting_in"):
                self.btn_replug.setEnabled(False)
                self._replug_label("Unplug the drive now..." if st == "waiting_out" else "Unplugged. Now plug it back in...", T.WARN)
            u.addWidget(W.hbox(self.btn_replug, self.lbl_replug, "stretch", spacing=T.S3))
        if self.lock_until is None:              # the 10-second lock runs once, not again after Back
            self.lock_until = time.time() + LOCK_SECONDS
        self._upd()
        if time.time() < self.lock_until:
            self._lock_timer.start()
        self.ent.setFocus()

    def _typed(self, text):
        self.typed = text
        self._upd()

    def _lock_tick(self):
        if self.step != 2 or not self._alive():
            self._lock_timer.stop()
            return
        self._upd()
        if time.time() >= (self.lock_until or 0):
            self._lock_timer.stop()

    def _confirm_ok(self):
        if self.step == 2 and self.ent is not None:
            try:
                self.typed = self.ent.text()
            except RuntimeError:
                pass
        typed = ws.norm(self.typed)
        return (bool(self.cb1 and self.cb2) and bool(typed) and typed == ws.norm(self.want) and time.time() >= (self.lock_until or 0)
                and self.replug.get("state") not in ("waiting_out", "waiting_in"))

    def _upd(self):
        if self.step != 2 or self.ent is None:
            return
        try:
            typed = ws.norm(self.ent.text())
            if typed:
                ok = typed == ws.norm(self.want)
                self.ent_msg.setText("Matches" if ok else "Doesn't match yet")
                self.ent_msg.setStyleSheet("color:%s;" % (T.OK if ok else T.MUTED))
            else:
                self.ent_msg.setText("")
        except RuntimeError:
            return
        left = int((self.lock_until or 0) - time.time() + 0.99)
        if left > 0:
            self._set_next("Wait %ds..." % left, False)
        else:
            self._set_next("Next: final check", self._confirm_ok())

    def _replug_label(self, text, color):
        if self.lbl_replug is not None:
            try:
                self.lbl_replug.setText(text)
                self.lbl_replug.setStyleSheet("color:%s;" % color)
            except RuntimeError:
                pass

    def _replug_start(self):
        chk = self.chk or {}
        self.replug = {"state": "waiting_out", "t": time.time()}
        self.replug_cancel.clear()
        if self.btn_replug is not None:
            self.btn_replug.setEnabled(False)
        self._replug_label("Unplug the drive now...", T.WARN)
        key = ws.norm(chk.get("serial")) + ":%s" % chk.get("size")
        cancel = self.replug_cancel

        def work(progress):
            state, t0 = "waiting_out", time.time()
            while state in ("waiting_out", "waiting_in") and time.time() - t0 < 180 and not cancel.is_set():
                s = ws.present_serials()
                if s is not None:
                    if state == "waiting_out" and key not in s:
                        state = "waiting_in"
                        progress("waiting_in")
                    elif state == "waiting_in" and key in s:
                        return "done"
                if cancel.wait(1.5):
                    break
            return "timeout"

        def step(state):
            if self._alive() and self.replug.get("state") in ("waiting_out", "waiting_in"):
                self.replug["state"] = state
                self._replug_label("Unplugged. Now plug it back in...", T.WARN)

        def done(state):
            if not self._alive():
                return
            if state == "done":
                self.replug["state"] = "done"
                self._replug_done()
            else:
                self._replug_fail("Timed out - try again.")

        def fail(msg):
            if self._alive():
                self._replug_fail("Re-plug check failed - try again.")
        tasks.run_task(work, done, fail, on_progress=step, name="wipe-replug")
        self._upd()

    def _replug_fail(self, text):
        self.replug["state"] = "timeout"
        self._replug_label(text, T.MUTED)
        if self.btn_replug is not None:
            try:
                self.btn_replug.setEnabled(True)
            except RuntimeError:
                pass
        self._upd()

    def _replug_done(self):
        self._replug_label("✓ Confirmed - it's the drive you unplugged.", T.OK)
        # disk numbers can change after a re-plug: find it again by serial
        self._loading("Drive re-connected - locating it again...")
        d, chk0 = dict(self.d), dict(self.chk or {})

        def work():
            try:
                r = core.run_ps_json(ws.IDENTITY_PS, 60, "Drive identity check")
                hit = next((x for x in ws._l(r.get("disks")) if isinstance(x, dict) and ws.same_drive(x, chk0)), None)
                num = d.get("number")
                if hit and ws._i(hit.get("number"), -1) >= 0 and ws._i(hit.get("number")) != num:
                    num = ws._i(hit.get("number"))
                chk = ws.check(num)
                power = ws.power_state()
            except Exception as e:
                core.log_error("wipe.relocate", e)
                num, chk, power = d.get("number"), {"status": "error", "detail": core.friendly_error(e)}, (False, True)
            return num, chk, power
        tasks.run_task(work, self._relocated, lambda m: self._relocated((self.d.get("number"), {"status": "error", "detail": m}, (False, True))),
                       name="wipe-relocate")

    def _relocated(self, r):
        if not self._alive():
            return
        num, chk, power = r
        if num != self.d.get("number"):
            self.d = dict(self.d, number=num)
        self.chk, self.power = chk, power
        self.block = ws.blockers(self.d, chk, getattr(self.page, "windiag_disk", None), self.rep_disk, power)
        if self.block:
            return self.show_step(1)
        self.show_step(2)
        self._replug_label("✓ Confirmed - it's the drive you unplugged (disk %s)." % self.d["number"], T.OK)
        if self.btn_replug is not None:
            self.btn_replug.setEnabled(False)

    # ------------------------------------------------------------------ step 3: final summary + countdown
    def _final(self):
        chk = self.chk or {}
        c = self._card("Final check", "CRITICAL")
        rows = [("Drive", "%s  (disk %s)" % (chk.get("model"), self.d.get("number")), False), ("Serial", chk.get("serial") or "--", True),
                ("Capacity", ws.fmt_bytes(chk.get("size")), True),
                ("Data that will be destroyed", ws.fmt_bytes(ws.used_bytes(chk)) + (
                    "  on " + ", ".join("%s:" % v["letter"] for v in chk.get("contents", [])) if chk.get("contents") else ""), True),
                ("Method", "diskpart clean all - every sector overwritten with zeros", False),
                ("Estimated time", "about %s (keep the PC on and the drive connected)" % ws.fmt_dur(ws.estimate_seconds(chk.get("size"), chk.get("bus"), chk.get("media"))), False),
                ("Afterwards", "Verify zeros (random samples)  ·  " + ("new empty NTFS partition" if self.newpart else "leave empty") + "  ·  erasure certificate", False),
                ("Re-plug check", "passed" if self.replug.get("state") == "done" else "not done (optional)", False)]
        gw = QWidget()
        g = QGridLayout(gw)
        g.setContentsMargins(0, 0, 0, 0)
        g.setHorizontalSpacing(T.S5)
        g.setVerticalSpacing(T.S2)
        g.setColumnStretch(1, 1)
        for i, (k, v, mono) in enumerate(rows):
            g.addWidget(W.label(k, "Label"), i, 0, Qt.AlignTop)
            val = _mono(v, T.TEXT, 12) if mono else W.label(v, "Value", wrap=True, sel=True)
            g.addWidget(val, i, 1)
        c.addWidget(gw)
        self.cd_box = QWidget()
        self.cd_lay = QVBoxLayout(self.cd_box)
        self.cd_lay.setContentsMargins(0, T.S2, 0, 0)
        self.cd_lay.setSpacing(T.S2)
        self._add(self.cd_box)
        self._set_next("Wipe drive", True, "danger")

    def _start_countdown(self):
        if self.phase not in ("confirm", "check") or self.step != 3:
            return
        chk = self.chk or {}
        if not W.confirm(self, "Erase EVERYTHING on %s (serial %s, %s)?\n\nThis can't be undone. A %d-second countdown starts next - you can still "
                               "cancel during it." % (chk.get("model"), chk.get("serial") or "--", ws.fmt_bytes(chk.get("size")), COUNTDOWN),
                         "WinDiag - wipe disk %s" % self.d.get("number"), danger=True):
            return
        if not self._alive() or self.step != 3:
            return
        self.phase = "countdown"
        self.cd_left = COUNTDOWN
        self._set_next("Wipe drive", False, "danger")
        self.btn_back.setEnabled(True)
        self.btn_back.setText("Cancel wipe")
        W.clear_layout(self.cd_lay)
        self.cd_lbl = mono_label("", T.CRIT, 44, 600, wrap=False)
        self.cd_lbl.setAlignment(Qt.AlignCenter)
        self.cd_lay.addWidget(self.cd_lbl)
        t = W.label("Starting the wipe. Press Cancel to stop - nothing has been changed yet.", "Body", wrap=True)
        t.setAlignment(Qt.AlignCenter)
        self.cd_lay.addWidget(t)
        b = W.button("CANCEL", self._abort_countdown, min_w=220)
        b.setAutoDefault(False)
        self.cd_lay.addWidget(b, 0, Qt.AlignHCenter)
        QTimer.singleShot(0, self, lambda: self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum()))
        self._cd_tick()
        self._cd_timer.start()

    def _cd_tick(self):
        if self.phase != "countdown":
            self._cd_timer.stop()
            return
        if self.cd_left <= 0:
            self._cd_timer.stop()
            return self._launch()
        self.cd_lbl.setText(str(self.cd_left))
        self.cd_left -= 1

    def _abort_countdown(self):
        if self.phase != "countdown":
            return
        self._cd_timer.stop()
        self.phase = "confirm"
        self.app.set_status("Wipe cancelled - nothing was changed.", hold=5)
        self.show_step(2)

    # ------------------------------------------------------------------ step 4: wipe
    def _launch(self):
        self.phase = "launching"
        self._loading("Checking the drive's identity one last time...")
        self.btn_cancel.setEnabled(False)
        self.btn_back.setText("Back")
        n, chk, report_dir = self.d["number"], dict(self.chk or {}), self.app.report_dir

        def work():
            now = ws.identity(n)
            if not now or not ws.same_drive(now, chk) or now.get("is_boot") or now.get("is_system"):
                return {"fail": "Stopped: disk %s is not the drive you confirmed any more (it was unplugged, swapped or renumbered). "
                                "Nothing was erased. Refresh the drive list and start again." % n}
            base = tempfile.mkdtemp(prefix="windiag_wipe_")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            paths = {"status": os.path.join(base, "status.json"), "dp": os.path.join(base, "clean.txt"), "ps": os.path.join(base, "wipe.ps1"),
                     "log": os.path.join(report_dir, "wipe_disk%s_%s.log" % (n, stamp))}
            with open(paths["dp"], "w") as f:
                f.write(ws.diskpart_clean(n))
            with open(paths["ps"], "w", encoding="utf-8-sig") as f:
                f.write(ws.runner_script(dict(chk, number=n), paths["status"], paths["log"], paths["dp"]))
            try:
                subprocess.Popen([core.POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", paths["ps"]],
                                 creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10))
            except Exception as e:
                core.log_error("wipe.launch (Popen)", e)
                return {"fail": "Couldn't start the wipe: %s. Nothing was erased." % core.friendly_error(e)}
            return {"paths": paths, "t": time.time()}

        def done(r):
            if r.get("fail"):
                return self._fail(r["fail"])
            self.paths, self.t_launch = r["paths"], r["t"]
            self.show_step(4)

        tasks.run_task(work, done, lambda m: self._fail("Couldn't start the wipe: %s. Nothing was erased." % m), name="wipe-launch")

    def _fail(self, text):
        self.phase = "done"
        self._poll_timer.stop()
        self.step = 4
        self._render_steps()
        self._clear()
        c = self._card("Not wiped", "CRITICAL")
        c.addWidget(W.label(text, "Body", wrap=True, sel=True))
        self.body.addStretch(1)
        self.btn_cancel.setEnabled(True)
        self.btn_cancel.setText("Close")
        self._set_next("Wipe drive", False)
        self.btn_back.setEnabled(False)

    def _wiping(self):
        self.phase = "wiping"
        self.btn_back.setEnabled(False)
        self._set_next("Wiping...", False)
        self.btn_cancel.setEnabled(False)
        c = self._card("Erasing disk %s" % self.d["number"])
        c.addWidget(W.label("The wipe runs in its own window. Don't unplug the drive, sleep or shut down the PC. Keep this window open - "
                            "it checks the result and writes the certificate when the wipe ends.", "Body", wrap=True))
        c.addSpacing(T.S2)
        self.w_state = W.label("Starting...", "PanelTitle", wrap=True)
        self.w_state.setFont(T.ui(15, 700))
        c.addWidget(self.w_state)
        self.w_bar = W.Meter(6)
        c.addWidget(self.w_bar)
        self.w_time = _mono("", T.TEXT2, 12)
        c.addWidget(self.w_time)
        chk = self.chk or {}
        self.est = max(60, ws.estimate_seconds(chk.get("size"), chk.get("bus"), chk.get("media")))
        self._poll()
        self._poll_timer.start()

    def _poll(self):
        """Reads the wipe script's small JSON status file in a worker; never on the GUI thread."""
        if not self._alive() or self.phase != "wiping" or self._status_busy:
            return
        self._status_busy = True

        def fail(msg):
            self._status_busy = False
        tasks.run_task(ws.read_status, self._on_status, fail, args=(self.paths["status"],), name="wipe-status")

    def _on_status(self, st):
        self._status_busy = False
        if not self._alive() or self.phase != "wiping":
            return
        st = st if isinstance(st, dict) else {}
        s = st.get("state")
        el = time.time() - (self.t_launch or time.time())
        if s == "aborted":
            return self._fail(st.get("reason") or "The wipe script stopped. Nothing was erased.")
        if s == "failed":
            self._poll_timer.stop()
            self._finish_record(st, {"checked": 0, "nonzero": [], "errors": [], "bytes": 0}, failed="diskpart reported error code %s" % st.get("rc"))
            return
        if s == "cleaned":
            self._poll_timer.stop()
            self.wst = st
            return self._verify()
        try:
            if s == "wiping":
                try:
                    t0 = datetime.fromisoformat(st["start"][:19]).timestamp()
                    el = time.time() - t0
                except Exception:
                    pass
                self.w_state.setText("Overwriting with zeros...")
                self.w_bar.set(min(0.97, el / self.est), T.ACCENT)
                self.w_time.setText("Elapsed %s  ·  estimated total about %s (diskpart doesn't report progress, so this is an estimate)" % (
                    ws.fmt_dur(el), ws.fmt_dur(self.est)))
            else:
                self.w_state.setText("Waiting for the wipe window to confirm the drive...")
                if el > 120 and not st:
                    return self._fail("The wipe window didn't start (was it closed or blocked?). Nothing was erased.")
        except RuntimeError:
            pass

    def _verify(self):
        self.phase = "verifying"
        self.w_state.setText("Checking the drive reads back zeros...")
        self.w_bar.set(0, T.ACCENT)
        newpart = bool(self.newpart)
        n, chk, paths, cancel = self.d["number"], dict(self.chk or {}), dict(self.paths), self.cancel_ev

        def work(progress):
            try:
                return _work(progress)
            except Exception as e:
                core.log_error("wipe.verify", e)
                return {"checked": 0, "nonzero": [], "errors": [], "bytes": 0, "skipped": "Verification failed: %s" % core.friendly_error(e)}, None

        def _work(progress):
            size = ws._i(chk.get("size"))
            now = ws.identity(n)
            if not now or not ws.same_drive(now, chk):
                res = {"checked": 0, "nonzero": [], "errors": [], "bytes": 0, "skipped": "drive not found after the wipe"}
            else:
                try:
                    rd = dh.WinDiskReader(n, size)
                    try:
                        res = ws.verify_zeros(rd, rd.size, progress=lambda a, b: progress((a, b)), cancel=cancel)
                    finally:
                        rd.close()
                except Exception as e:
                    core.log_error("wipe.verify (read)", e)
                    res = {"checked": 0, "nonzero": [], "errors": [], "bytes": 0, "skipped": "Couldn't read the drive back: %s" % core.friendly_error(e)}
            after = None
            if newpart and res.get("checked") and not res["nonzero"] and not cancel.is_set():
                now = ws.identity(n)
                if now and ws.same_drive(now, chk):
                    p = os.path.join(os.path.dirname(paths["dp"]), "part.txt")
                    with open(p, "w") as f:
                        f.write(ws.diskpart_partition(n))
                    try:
                        rc, out, err = core.tracked_run([core.sys32("diskpart"), "/s", p], 300, "diskpart new partition", track=False)
                        after = "New empty NTFS partition created" if rc == 0 else "Creating the new partition failed (code %s) - use Disk Management" % rc
                        with open(paths["log"], "a", encoding="utf-8") as fh:
                            fh.write("\n=== new partition\n" + (out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out or "")))
                    except Exception as e:
                        core.log_error("wipe.new partition", e)
                        after = "Creating the new partition failed: %s" % core.friendly_error(e)
            return res, after

        def prog(ab):
            a, b = ab
            try:
                self.w_bar.set(a / float(max(1, b)), T.ACCENT)
                self.w_time.setText("%d / %d samples checked" % (a, b))
            except RuntimeError:
                pass

        def done(r):
            res, after = r
            if self._alive():
                self._finish_record(self.wst or {}, res, after=after)

        def fail(msg):
            if self._alive():
                self._finish_record(self.wst or {}, {"checked": 0, "nonzero": [], "errors": [], "bytes": 0, "skipped": "Verification failed: %s" % msg})
        tasks.run_task(work, done, fail, on_progress=prog, name="wipe-verify")

    def _finish_record(self, st, res, failed=None, after=None):
        """Builds the erasure record and saves the certificate (file writes in a worker), then shows the result."""
        self.phase = "verifying"           # still busy until the certificate is written
        chk = self.chk or {}
        ok = not failed and res.get("checked", 0) > 0 and not res.get("nonzero") and not res.get("errors")
        try:
            t0, t1 = datetime.fromisoformat(st["start"][:19]), datetime.fromisoformat(st["end"][:19])
            dur = ws.fmt_dur((t1 - t0).total_seconds())
        except Exception:
            t0 = t1 = None
            dur = "--"
        rec = {"model": chk.get("model"), "serial": chk.get("serial"), "size": chk.get("size"), "bus": chk.get("bus"), "media": chk.get("media"),
               "number": self.d["number"], "start": t0.strftime("%Y-%m-%d %H:%M:%S") if t0 else None, "end": t1.strftime("%Y-%m-%d %H:%M:%S") if t1 else None,
               "duration": dur, "checked": res.get("checked"), "vbytes": res.get("bytes"), "nonzero": len(res.get("nonzero", [])),
               "errors": len(res.get("errors", [])), "result": "PASSED" if ok else "FAILED", "after": after, "failed": failed, "skipped": res.get("skipped"),
               "pc": os.environ.get("COMPUTERNAME"), "user": os.environ.get("USERNAME"), "log": self.paths.get("log")}
        report_dir = self.app.report_dir

        def work():
            try:
                return ws.save_certificate(report_dir, rec), None
            except Exception as e:
                core.log_error("wipe.certificate", e)
                return None, str(e)

        def done(r):
            cert, err = r
            if err:
                rec["cert_error"] = err
            self._show_result(ok, rec, res, failed, after, cert)
        tasks.run_task(work, done, lambda m: self._show_result(ok, rec, res, failed, after, None), name="wipe-certificate")

    def _show_result(self, ok, rec, res, failed, after, cert):
        self.phase = "done"
        self.cert = cert
        if self.step != 4:
            self.step = 4
            self._render_steps()
        self._clear()
        c = self._card("Drive erased and verified" if ok else "Wipe finished - NOT verified", "OK" if ok else "CRITICAL")
        if ok:
            txt = "%d random samples across the whole drive read back as zeros. %s" % (rec["checked"], after or "The drive is left empty (initialise it in Disk Management).")
        else:
            txt = failed or res.get("skipped") or "%d sample(s) weren't zero and %d couldn't be read. Run the wipe again or physically destroy the drive." % (
                rec["nonzero"], rec["errors"])
        c.addWidget(W.label(txt, "Body", wrap=True, sel=True))
        if rec.get("cert_error"):
            c.addWidget(W.colored("The certificate could not be saved: %s" % rec["cert_error"], T.WARN, 12))
        btns = []
        if cert:
            btns.append(W.button("Open certificate", lambda: self._open(cert), "primary", icon="report"))
        if self.paths.get("log"):
            btns.append(W.button("Open wipe log", lambda: self._open(self.paths.get("log")), icon="folder"))
        if btns:
            c.addWidget(W.hbox(*(btns + ["stretch"])))
        self.body.addStretch(1)
        self.btn_cancel.setEnabled(True)
        self.btn_cancel.setText("Close")
        self._set_next("Done", False)
        self.btn_back.setEnabled(False)
        self.app.set_status("Wipe %s - certificate saved in the Reports folder." % ("verified" if ok else "NOT verified"), "OK" if ok else "CRITICAL", hold=10)
        try:
            self.page.check()
        except Exception as e:
            core.log_error("wipe.refresh drives", e)

    def _open(self, p):
        if not p or not QDesktopServices.openUrl(QUrl.fromLocalFile(p)):
            W.error(self, "Could not open %s" % (p or "the file"))
