"""Settings page (port of the CTk settings.py page). Logic: appsettings (get/put, PIN hash, privacy redaction)."""
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QVBoxLayout, QWidget

import appsettings as S
import core
from .. import tasks
from .. import theme as T
from .. import widgets as W
from ..pin import PinDialog

KEYS = ("auto_full_scan", "consent_required", "privacy_mode", "public_ip", "pin_startup", "pin_risky", "wipe_enabled")


class SettingsPage(W.Page):
    # switching these OFF lowers protection, so it needs the current PIN
    PIN_GUARDED = {"pin_startup": "turning off the PIN at start-up", "pin_risky": "turning off the PIN for risky actions"}

    def __init__(self, app):
        super().__init__(app)
        self._sig = None
        self._pin_busy = False
        self.boxes = {}
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        self.sp = W.ScrollPage()
        v.addWidget(self.sp)

    def _state(self):
        try:
            s = S.load_settings()
        except Exception:
            s = {}
        return tuple(bool(s.get(k, S.DEFAULTS.get(k))) for k in KEYS) + (bool(s.get("pin_hash")), self._pin_busy, self.app.report_dir)

    def on_show(self):
        # settings can change elsewhere (start popup, PIN prompts) - redraw only if something differs
        if self._state() != self._sig:
            self.request_render()

    # ------------------------------------------------------------------ building blocks
    def _switch(self, panel, key, text, desc, on_change=None):
        row = QWidget()
        v = QVBoxLayout(row)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        cb = QCheckBox(text)
        cb.setStyleSheet("QCheckBox { font-weight:600; }")
        cb.setChecked(bool(S.get(key)))
        cb.setCursor(Qt.PointingHandCursor)
        cb.clicked.connect(lambda checked, k=key, c=cb, f=on_change: self._changed(k, c, checked, f))
        v.addWidget(cb)
        if desc:
            d = W.label(desc, "Body", wrap=True)
            d.setContentsMargins(22, 0, 0, 0)          # line up with the checkbox text
            v.addWidget(d)
        panel.add(row)
        self.boxes[key] = cb
        return cb

    def _changed(self, key, cb, checked, on_change):
        if key in self.PIN_GUARDED and not checked and not self.app.pin.verify(self.PIN_GUARDED[key]):
            cb.blockSignals(True)
            cb.setChecked(True)              # refused: put the switch back
            cb.blockSignals(False)
            return
        S.put(**{key: bool(checked)})
        self._sig = self._state()
        if on_change:
            try:
                on_change(bool(checked))
            except Exception as e:
                core.log_error("setting %s" % key, e)
        self.app.set_status("Setting saved.", hold=3)

    # ------------------------------------------------------------------ render
    def render(self):
        self._sig = self._state()
        lay = self.sp.lay
        W.clear_layout(lay)
        self.boxes = {}
        has_pin = S.pin_set()

        p = W.Panel("Scanning", "How WinDiag starts and scans.")
        self._switch(p, "auto_full_scan", "Start a full scan automatically", "Skip the start popup and scan as soon as WinDiag opens "
                     "(the popup still appears when 'Ask for permission' is on).")
        self._switch(p, "consent_required", "Ask for permission before scanning", "The start popup asks you to confirm you're allowed to check this PC "
                     "(recommended when working on other people's computers).")
        lay.addWidget(p)

        p = W.Panel("Privacy", "Nothing is uploaded unless you use Windows Update checks, VirusTotal, the speed test or the public-IP lookup.")
        self._switch(p, "privacy_mode", "Hide serial numbers and user names in saved reports",
                     "Reports and spec sheets replace serial numbers, MAC addresses and the user name with •••• - useful before sharing them.")
        self._switch(p, "public_ip", "Allow public IP / provider lookup (Network Tools)",
                     "Asks an online service (ipify / ipinfo) for this network's public IP and provider.")
        lay.addWidget(p)

        p = W.Panel("Technician PIN", "Optional. Protects WinDiag on a shared USB stick. Stored as a salted hash next to WinDiag.exe - it can't be read back.")
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(T.S2)
        row.addWidget(W.Dot("OK" if has_pin else "UNKNOWN", "PIN is set" if has_pin else "No PIN set", 13))
        row.addStretch(1)
        if has_pin:
            b = W.button("Remove PIN", self._clear_pin, "stop")
            b.setEnabled(not self._pin_busy)
            row.addWidget(b)
        b = W.button("Saving..." if self._pin_busy else ("Change PIN" if has_pin else "Set PIN"), self._set_pin)
        b.setEnabled(not self._pin_busy)
        row.addWidget(b)
        rw = QWidget()
        rw.setLayout(row)
        p.add(rw)
        self._switch(p, "pin_startup", "Ask for the PIN when WinDiag opens", "")
        self._switch(p, "pin_risky", "Ask for the PIN before risky actions", "Repairs, quarantine/restore, secure delete, drive wipe and tune-up changes. "
                     "A correct PIN is remembered for 10 minutes.")
        lay.addWidget(p)

        p = W.Panel("Drive wipe", "Wiping erases a whole drive permanently. It's switched off by default so it can't be used by accident.")
        self._switch(p, "wipe_enabled", "Enable 'Wipe entire drive' on the Drive Health page", "Even when enabled, the Windows drive, WinDiag's own drive and "
                     "in-use drives can never be wiped, and every wipe goes through the safety checks.", self._wipe_changed)
        lay.addWidget(p)

        p = W.Panel("Reports", "Every scan saves an HTML + text report here. Privacy mode (above) applies to these files.")
        d = self.app.report_dir or ""
        g = W.KeyValueGrid(1)
        g.set([("Report folder", d, {"mono": True}), ("Settings file", S.settings_path(), {"mono": True})])
        p.add(g)
        p.add(W.hbox(W.button("Open report folder", self._open_reports, icon="folder"),
                     W.button("Copy path", lambda: self.app.copy_text(d), icon="copy"), "stretch"))
        lay.addWidget(p)
        lay.addStretch(1)

    # ------------------------------------------------------------------ actions
    def _wipe_changed(self, v):
        dp = self.app.pages.get("drives")              # don't create the Drive Health page just for this
        if dp is None:
            return
        if hasattr(dp, "render_detail"):
            dp.render_detail()
        else:
            dp.request_render()

    def _open_reports(self):
        d = self.app.report_dir
        try:
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            core.open_tool(d)
        except Exception as e:
            W.error(self.app, "Could not open the report folder:\n%s" % e)

    def _set_pin(self):
        if self._pin_busy:
            return
        if S.pin_set() and not self.app.pin.verify("changing the PIN"):
            return
        p = PinDialog.ask(self.app, "WinDiag - set PIN", "Choose a technician PIN (4-12 digits).", confirm=True)
        if not p:
            return
        self._pin_busy = True                          # PBKDF2 (200k rounds) runs in a worker, not on the GUI thread
        self.request_render()

        def done(_=None):
            self._pin_busy = False
            self.app.set_status("PIN saved.", "OK", hold=3)
            self.request_render()

        def fail(msg):
            self._pin_busy = False
            W.error(self.app, "Could not save the PIN:\n%s" % msg)
            self.request_render()
        tasks.run_task(S.set_pin, done, fail, args=(p,), name="set-pin")

    def _clear_pin(self):
        if not self.app.pin.verify("removing the PIN"):
            return
        S.clear_pin()
        self.app.set_status("PIN removed.", hold=3)
        self.request_render()
