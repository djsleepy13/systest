"""Start popup: this PC, the security check before scanning, the permission tick box, scan options."""
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QLabel, QVBoxLayout

import appsettings as S
import core
import prescan
import scanner
import sysfacts
from . import tasks
from . import theme as T
from . import widgets as W


def run_prescan(app, done=None):
    """Security check in a QThread worker; result -> app.prescan_result (Dashboard banner) and done(res) on the GUI thread."""
    def work():
        try:
            return prescan.run()
        except Exception as e:
            core.log_error("prescan", e)
            return ([("WARNING", "Security check", "Could not run - %s" % core.friendly_error(e))], "")

    def finished(res):
        app.prescan_result = res
        app.render_summary()
        if done:
            done(res)
    tasks.run_task(work, finished, name="prescan")


class StartDialog(QDialog):
    def __init__(self, app, on_done):
        super().__init__(app)
        self.app, self.on_done = app, on_done
        self.finished_ = False
        self.setWindowTitle("WinDiag %s" % core.APP_VERSION)
        self.setModal(True)
        self.need_consent = bool(S.get("consent_required"))
        o = scanner.Scanner.options()
        f = sysfacts.quick_facts()
        v = QVBoxLayout(self)
        v.setContentsMargins(T.S5, T.S5, T.S5, T.S5)
        v.setSpacing(T.S4)
        hd = QHBoxLayout()
        tb = QVBoxLayout()
        tb.setSpacing(2)
        t = QLabel((f.get("model") or f.get("name") or "This PC")[:60])
        t.setFont(T.display(18, 700))
        tb.addWidget(t)
        tb.addWidget(W.label("  ·  ".join(x for x in (f.get("name"), f.get("os"), f.get("cpu"), f.get("ram")) if x)[:110], "Body", wrap=True))
        hd.addLayout(tb, 1)
        hd.addWidget(W.Dot("OK" if app.is_admin else "WARNING", "Administrator" if app.is_admin else "Limited mode", 11), 0, Qt.AlignTop)
        v.addLayout(hd)

        self.sec = W.Panel("Security check before scanning", actions=[])
        self.sec_state = W.label("checking...", "Muted")
        self.sec.add_action(self.sec_state)
        self.sec_list = W.FindingsList([("INFO", "Checking WinDiag's own files, PowerShell and the antivirus...", "")])
        self.sec.add(self.sec_list)
        v.addWidget(self.sec)

        self.cb_consent = QCheckBox("I own this PC or have permission to check it")
        self.cb_consent.toggled.connect(self._upd)
        if self.need_consent:
            v.addWidget(self.cb_consent)
        self.cb_upd = QCheckBox("Check Windows Update online  (+1-2 min, runs alongside)")
        self.cb_upd.setChecked(o["updates"])
        v.addWidget(self.cb_upd)
        self.cb_sec = QCheckBox("Include the Security Scan  (+1-3 min)")
        self.cb_sec.setChecked(o["secscan"])
        v.addWidget(self.cb_sec)
        v.addWidget(W.label("Scanning only reads information - nothing is changed. You can use WinDiag while it runs; Esc stops it.", "Muted", wrap=True))
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(W.button("Skip - go to tools", lambda: self._finish(None), "ghost"))
        self.btn_go = W.button("Start scan", lambda: self._finish("full"), "primary", icon="play", min_w=140)
        self.btn_go.setDefault(True)
        row.addWidget(self.btn_go)
        v.addLayout(row)
        self.setFixedWidth(580)
        self._upd()
        self._fit()
        run_prescan(app, self._prescan_done)

    def _upd(self):
        self.btn_go.setEnabled((not self.need_consent) or self.cb_consent.isChecked())

    def _prescan_done(self, res):
        if self.finished_:
            return
        items = res[0]
        worst = "CRITICAL" if any(i[0] == "CRITICAL" for i in items) else "WARNING" if any(i[0] == "WARNING" for i in items) else "OK"
        self.sec_state.setText({"OK": "All good", "WARNING": "Check", "CRITICAL": "Problem found"}[worst])
        self.sec_state.setStyleSheet("color:%s;" % T.STATUS[worst])
        shown = [i for i in items if i[0] != "OK"][:4] + [(i[0], i[1], "") for i in items if i[0] == "OK"]
        if worst == "CRITICAL":
            shown.append(("CRITICAL", "Malware can hide or fake results", "The scan still runs - fix this first if you can (Dashboard banner)."))
        self.sec_list.set(shown[:7])
        self._fit()

    def _fit(self):
        # Top-level windows ignore height-for-width of wrapped labels when computing their minimum size,
        # so measure after the event loop has laid things out and pin the minimum height explicitly.
        QTimer.singleShot(0, self._fit_now)

    def _fit_now(self):
        try:
            lay = self.layout()
            lay.invalidate()
            lay.activate()
            w = self.width()
            h = lay.totalHeightForWidth(w) if lay.hasHeightForWidth() else lay.totalSizeHint().height()
            h = max(h, lay.totalSizeHint().height(), 300)
            self.setMinimumHeight(h)
            self.resize(w, h)
        except RuntimeError:
            pass

    def _finish(self, mode):
        if self.finished_:
            return
        if mode and self.need_consent and not self.cb_consent.isChecked():
            return
        self.finished_ = True
        scanner.Scanner.save_options(updates=self.cb_upd.isChecked(), secscan=self.cb_sec.isChecked())
        self.accept()
        self.on_done(mode)

    def reject(self):                        # Esc / window X = skip
        if not self.finished_:
            self.finished_ = True
            super().reject()
            self.on_done(None)
