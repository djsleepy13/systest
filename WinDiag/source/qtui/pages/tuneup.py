"""Tune-up page: before/after measurements + safe, measurable tune-up items + startup apps (port of tuneup_ui.py)."""
from datetime import datetime

from PySide6.QtWidgets import QAbstractItemView, QComboBox, QGridLayout, QHBoxLayout, QSizePolicy, QVBoxLayout, QWidget

import baseline as bl
import core
import filetools
import tuneup as tu
from .. import tasks
from .. import theme as T
from .. import widgets as W

VCOL = {"better": T.OK, "worse": T.CRIT, "same": T.TEXT2, "n/a": T.MUTED}
# Words, not arrows: a lower boot time is "better" but an up-arrow for a decrease confused people. The signed
# change ("-4.2 s") next to the word shows the direction.
VTXT = {"better": "better", "worse": "worse", "same": "no change", "n/a": ""}
PIN_ACTIONS = ("recycle", "trim", "faststart_off", "faststart_on", "clear_temp")


def take_snapshot(app, label):
    """Blocking (worker thread). Returns the stored snapshot, or None. Never raises."""
    return bl.take_snapshot(app, label)


snap_name = bl.snap_name


def _tinted(text, color, bold=False, mono=False):
    """Coloured label. Font via stylesheet: the app-wide '* { font-family }' rule overrides setFont()."""
    w = W.label(text, "ValueMono" if mono else "Value", wrap=not mono, sel=True)
    w.setStyleSheet("color:%s;%s" % (color, " font-weight:700;" if bold else ""))
    return w


class _FlowGrid(QWidget):
    """2-column grid of panels that drops to 1 column when narrow (high DPI / small window)."""

    def __init__(self, max_cols=2, min_w=380, spacing=T.S4):
        super().__init__()
        self.max_cols, self.min_w = max_cols, min_w
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(spacing)
        self.items, self.cols = [], 0

    def set_widgets(self, widgets):
        W.clear_layout(self.grid)
        self.items, self.cols = list(widgets), 0
        self._flow(self.width())

    def _flow(self, width):
        if not self.items:
            return
        cols = max(1, min(self.max_cols, width // self.min_w if width > 0 else self.max_cols))
        if cols == self.cols:
            return
        self.cols = cols
        for w in self.items:
            self.grid.removeWidget(w)
        for c in range(self.max_cols):
            self.grid.setColumnStretch(c, 1 if c < cols else 0)
        for i, w in enumerate(self.items):
            self.grid.addWidget(w, i // cols, i % cols)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._flow(e.size().width())


class TunePage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.raw = None
        self.busy = False
        self.snapping = False
        self.before_id = None
        self.tr_su = None
        self.su_panel = None
        self._alive = True
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, 0)
        bar.setSpacing(T.S2)
        self.lbl = W.label("Safe changes only - every one is reversible and measured before/after.", "Body", wrap=True)
        bar.addWidget(self.lbl, 1)
        self.btn_snap = W.button("Take measurement", self.snapshot, icon="activity")
        bar.addWidget(self.btn_snap)
        self.btn = W.button("Check again", self.check, "primary", icon="refresh")
        bar.addWidget(self.btn)
        v.addLayout(bar)
        self.sp = W.ScrollPage()
        v.addWidget(self.sp, 1)

    # ------------------------------------------------------------------ data
    def check(self):
        if self.busy:
            return
        self.busy = True
        self.btn.setEnabled(False)
        self.btn.setText("Checking...")

        def work():
            try:
                return core.run_ps_json(tu.TUNE_PS, 180, "Tune-up check")
            except Exception as e:
                core.log_error("tune-up check", e)
                return {"status": "error", "detail": core.friendly_error(e)}
        tasks.run_task(work, self._checked, lambda m: self._checked({"status": "error", "detail": m}), name="tune-check")

    def _checked(self, raw):
        """Also called by the background scan (scanner 'tune' step) with the raw TUNE_PS output."""
        self.busy = False
        if not self._alive:
            return
        self.btn.setEnabled(True)
        self.btn.setText("Check again")
        if not isinstance(raw, dict):
            raw = {"status": "error", "detail": "no data"}
        if raw.get("status") == "error" and "startup" not in raw:
            self.lbl.setText("Check failed: %s" % (raw.get("detail") or "")[:120])
            return
        if raw.get("blocked"):
            self.lbl.setText((raw.get("detail") or "")[:160])
            return
        if raw is self.raw:                     # double delivery of the same data
            return
        self.raw = raw
        self.lbl.setText("Settings read at %s  ·  %d measurement(s) saved" % (datetime.now().strftime("%H:%M"), len(self.app.baselines.items)))
        self.request_render()                   # hidden page: drawn when opened (no freeze mid-scan)

    def refresh_items(self):
        if self.raw:
            self.request_render()

    def snapshot(self, label=None, done=None):
        if self.snapping:
            return
        self.snapping = True
        self.btn_snap.setEnabled(False)
        self.btn_snap.setText("Measuring (~15 s)...")
        lab = label or "Manual %s" % datetime.now().strftime("%Y-%m-%d %H:%M")
        app = self.app
        tasks.run_task(lambda: bl.take_snapshot(app, lab), lambda s: self._snapped(s, done), lambda m: self._snapped(None, done),
                       name="tune-snapshot")

    def _snapped(self, s, done):
        self.snapping = False
        if self._alive:
            self.btn_snap.setEnabled(True)
            self.btn_snap.setText("Take measurement")
            if s is None:
                self.app.set_status("Measurement failed - " + core.friendly_error(None), "WARNING")
            elif self.raw:
                self.lbl.setText("Settings read at %s  \u00B7  %d measurement(s) saved" % (datetime.now().strftime("%H:%M"), len(self.app.baselines.items)))
            self.request_render()
        if done:
            try:
                done(s)
            except Exception as e:
                core.log_error("snapshot done", e)

    # ------------------------------------------------------------------ render
    def render(self):
        lay = self.sp.lay
        W.clear_layout(lay)
        self.tr_su = self.su_panel = None
        lay.addWidget(self._compare_panel())
        if not self.raw:
            p = W.Panel()
            p.add(W.label("Click 'Check again' to read the current settings (a few seconds).", "Body", wrap=True))
            lay.addWidget(p)
            lay.addStretch(1)
            return
        items = tu.assess(self.raw, getattr(self.app, "update_result", None))
        sec = QWidget()
        sv = QVBoxLayout(sec)
        sv.setContentsMargins(0, 0, 0, 0)
        sv.setSpacing(T.S3)
        sv.addWidget(W.label("Tune-up items", "SectionTitle"))
        fg = _FlowGrid(2, 380)
        fg.set_widgets([self._item(it) for it in items])
        sv.addWidget(fg)
        lay.addWidget(sec)
        self.su_panel = self._startup_panel()
        lay.addWidget(self.su_panel)
        lay.addStretch(1)

    def _compare_panel(self):
        snaps = list(self.app.baselines.items)
        p = W.Panel("Before / after")
        if len(snaps) < 1:
            p.add(W.label("No measurements yet. 'Take measurement' records boot time, disk response, idle CPU, memory, startup apps, free space, errors "
                          "and missing updates. Take one before a change and one after to see the real difference. A full scan and each Guided Fix take one "
                          "automatically.", "Body", wrap=True))
            return p
        names = []
        for s in snaps:                 # combo values must be unique
            n = bl.snap_name(s)
            names.append(n if n not in names else "%s  #%d" % (n, len(names) + 1))
        ids = [s["id"] for s in snaps]
        if self.before_id not in ids:
            self.before_id = snaps[0]["id"] if len(snaps) > 1 else snaps[-1]["id"]
        before = self.app.baselines.get(self.before_id) or snaps[0]
        after = snaps[-1]
        sel = QComboBox()
        sel.addItems(names)
        sel.setCurrentIndex(ids.index(before["id"]) if before.get("id") in ids else 0)
        sel.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        sel.setMinimumContentsLength(16)
        sel.setMaximumWidth(460)
        sel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sel.activated.connect(lambda i, ids_=ids: self._pick(ids_[i]) if 0 <= i < len(ids_) else None)
        p.add(W.hbox(W.label("Compare latest with:", "Body"), sel, "stretch"))
        p.add(W.label("Latest: %s" % bl.snap_name(after), "Body", wrap=True))
        tw = QWidget()
        g = QGridLayout(tw)
        g.setContentsMargins(0, T.S1, 0, 0)
        g.setHorizontalSpacing(T.S5)
        g.setVerticalSpacing(T.S2)
        for j, h in enumerate(["Measurement", "Before", "Now", "Change"]):
            g.addWidget(W.label(h.upper(), "Label"), 0, j)
        for i, (label, a, b, v, note) in enumerate(bl.compare(before, after), start=1):
            g.addWidget(W.label(label, "Body", wrap=True), i, 0)
            g.addWidget(W.label(a, "ValueMono", sel=True), i, 1)
            nb = W.label(b, "ValueMono", sel=True)
            nb.setStyleSheet("font-weight:600;")
            g.addWidget(nb, i, 2)
            row = QHBoxLayout()
            row.setSpacing(T.S2)
            if v != "n/a":
                row.addWidget(_tinted(VTXT.get(v, ""), VCOL.get(v, T.TEXT2), bold=v in ("better", "worse")))
                if note:
                    row.addWidget(_tinted(note, VCOL.get(v, T.TEXT2), mono=True))
            else:
                row.addWidget(_tinted(note or "--", VCOL["n/a"]))
            row.addStretch(1)
            g.addLayout(row, i, 3)
        g.setColumnStretch(0, 2)
        g.setColumnStretch(3, 2)
        p.add(tw)
        return p

    def _pick(self, sid):
        if sid == self.before_id:
            return
        self.before_id = sid
        self.request_render()

    def _item(self, it):
        word = {"OK": "Good", "WARNING": "Improve", "INFO": "Check"}.get(it["status"], "Check")
        p = W.Panel(it["title"], actions=[W.Dot(it["status"], word, 12)])
        val = str(it["value"])
        p.add(W.label(val, "ValueMono" if any(ch.isdigit() for ch in val) and it["id"] != "power" else "Value", wrap=True, sel=True))
        p.add(W.label(it["why"], "Body", wrap=True))
        bar = QHBoxLayout()
        bar.setContentsMargins(0, T.S1, 0, 0)
        bar.setSpacing(T.S2)
        for label, act in it["actions"]:
            if act == "power":
                plans = [x for x in (self.raw.get("power_plans") or []) if isinstance(x, dict) and x.get("name")]
                if plans:
                    om = QComboBox()
                    om.addItems([x["name"] for x in plans])
                    act_name = (self.raw.get("power_active") or {}).get("name") if isinstance(self.raw.get("power_active"), dict) else None
                    names = [x["name"] for x in plans]
                    om.setCurrentIndex(names.index(act_name) if act_name in names else 0)
                    om.setMinimumWidth(180)
                    om.activated.connect(lambda i, pl=plans, cb=om: self._power_pick(pl, i, cb))
                    bar.addWidget(om)
                continue
            bar.addWidget(W.button(label, lambda a=act: self.action(a)))
        bar.addStretch(1)
        w = QWidget()
        w.setLayout(bar)
        p.add(w)
        p.body.addStretch(1)
        return p

    def _power_pick(self, plans, i, combo):
        if not (0 <= i < len(plans)):
            return
        active = (self.raw.get("power_active") or {}) if isinstance(self.raw.get("power_active"), dict) else {}
        if plans[i].get("guid") == active.get("guid"):
            return
        if not self.set_power(plans[i]):
            names = [x["name"] for x in plans]
            combo.setCurrentIndex(names.index(active.get("name")) if active.get("name") in names else 0)     # refused: put it back

    def _startup_panel(self):
        su = [s for s in (self.raw.get("startup") or []) if isinstance(s, dict)]
        p = W.Panel("Startup apps",
                    "Disabling only stops the app starting automatically - nothing is uninstalled, and you can enable it again here or in Task Manager. "
                    "Keep security software, touchpad/audio drivers and cloud sync you rely on.",
                    actions=[W.button("Disable selected", lambda: self.toggle(False)), W.button("Enable selected", lambda: self.toggle(True))])
        rows = [{"State": "Enabled" if s.get("enabled") else "Disabled", "App": s.get("name"), "For": s.get("scope"), "Command": s.get("command"), "_s": s}
                for s in su]
        if not rows:
            p.add(W.label("No startup apps found.", "Muted"))
            return p
        p.add(W.label("Select one or more apps (Ctrl / Shift + click), then Disable or Enable.", "Muted", wrap=True))
        self.tr_su = W.DataTable(["State", "App", "For", "Command"], [120, 220, 170, 600], max_rows_visible=10)
        self.tr_su.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tr_su.set_rows(rows, [None if r["State"] == "Enabled" else "UNKNOWN" for r in rows])
        p.add(self.tr_su)
        return p

    def _selected_rows(self):
        t = self.tr_su
        if t is None:
            return []
        out = []
        for idx in t.selectionModel().selectedRows():
            r = t.model_.row(t.proxy.mapToSource(idx).row())
            if r:
                out.append(r)
        return out

    # ------------------------------------------------------------------ actions
    def _run(self, script, args, msg, done_text):
        self.app.set_status(msg)

        def work():
            try:
                return filetools.run_with_args(script, args, 600, track=False) if args is not None else core.run_ps_json(script, 900, msg, track=False)
            except Exception as e:
                core.log_error("tune-up action", e)
                return {"ok": False, "error": core.friendly_error(e)}
        tasks.run_task(work, lambda r: self._after(r, done_text), lambda m: self._after({"ok": False, "error": m}, done_text), name="tune-action")

    def _after(self, r, done_text):
        r = r if isinstance(r, dict) else {}
        if r.get("ok"):
            self.app.set_status(done_text, "OK", hold=5)
        else:
            W.error(self.app, "That didn't work: %s" % (r.get("error") or r.get("detail") or "unknown error"))
        if self._alive:
            self.check()

    def _need_admin(self):
        if not self.app.is_admin:
            W.info(self.app, "This needs administrator rights.")
            return True
        return False

    def toggle(self, enable):
        sel = [x["_s"] for x in self._selected_rows() if x.get("_s")]
        if not sel:
            W.info(self.app, "Select one or more apps first.")
            return
        if not self.app.pin.require("changing startup apps"):
            return
        if any(str(s.get("approved") or "").startswith("HKLM") for s in sel) and self._need_admin():
            return
        self.app.set_status("Updating startup apps...")

        def work():
            try:
                res = [filetools.run_with_args(tu.SET_STARTUP_PS, {"approved": s["approved"], "value": s["value"], "enable": enable}, 60, track=False)
                       for s in sel]
            except Exception as e:
                core.log_error("startup toggle", e)
                res = [{"ok": False, "error": core.friendly_error(e)}]
            bad = [r for r in res if not (isinstance(r, dict) and r.get("ok"))]
            return {"ok": not bad, "error": "; ".join(str((r or {}).get("error", "")) for r in bad)}
        done_text = "%s %d startup app(s). Restart to measure the new boot time." % ("Enabled" if enable else "Disabled", len(sel))
        tasks.run_task(work, lambda r: self._after(r, done_text), lambda m: self._after({"ok": False, "error": m}, done_text), name="startup-toggle")

    def set_power(self, plan):
        """Returns False if refused (PIN)."""
        if not self.app.pin.require("changing the power plan"):
            return False
        self._run(tu.SET_POWER_PS, {"guid": plan["guid"]}, "Switching power plan...", "Power plan set to %s." % plan["name"])
        return True

    def action(self, a):
        if a in PIN_ACTIONS and not self.app.pin.require("tune-up changes"):
            return
        if a == "page_updates":
            self.app.show_page("updates")
        elif a == "scroll_startup":
            if self.su_panel is not None:
                self.sp.ensureWidgetVisible(self.su_panel, 0, 0)
                self.sp.verticalScrollBar().setValue(self.sp.verticalScrollBar().maximum())
        elif a == "clear_temp":
            rep = core.REPAIR_BY_NAME.get("Clear temp files")
            if rep:
                self.app._repair(rep)
        elif a == "recycle":
            if W.confirm(self.app, "Empty the Recycle Bin on all drives? Files in it can't be restored afterwards.", danger=True):
                self._run(tu.EMPTY_RECYCLE_PS, None, "Emptying Recycle Bin...", "Recycle Bin emptied.")
        elif a == "storagesense":
            try:
                core.open_tool("ms-settings:storagesense")
            except Exception as e:
                W.error(self.app, str(e))
        elif a == "trim":
            if not self._need_admin():
                self._run(tu.TRIM_PS, None, "Turning TRIM on and trimming SSDs (up to a few minutes)...", "TRIM is on and SSDs were trimmed.")
        elif a in ("faststart_off", "faststart_on"):
            if not self._need_admin():
                self._run(tu.SET_FASTSTART_PS, {"enable": a == "faststart_on"}, "Changing Fast Startup...",
                          "Fast Startup is now %s." % ("on" if a == "faststart_on" else "off"))

    def shutdown(self):
        self._alive = False
