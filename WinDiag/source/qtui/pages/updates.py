"""Updates & Drivers page: online Windows Update check + driver age report (port of updates_ui.py)."""
from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QHeaderView, QVBoxLayout, QWidget

import core
import updates as up
from .. import tasks
from .. import theme as T
from .. import widgets as W


class _FlowGrid(QWidget):
    """Grid that drops to fewer columns when narrow (4 tiles -> 2 -> 1), so nothing clips at high DPI / small windows."""

    def __init__(self, max_cols=4, min_w=200, spacing=T.S3):
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
        n = len(self.items)
        if not n:
            return
        cols = max(1, min(self.max_cols, n, width // self.min_w if width > 0 else self.max_cols))
        if cols > 1 and self.max_cols % cols:        # 4 -> 2 -> 1 (never 3 + 1 orphan)
            cols = 2 if cols >= 2 else 1
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


def _stretch(table, cols):
    """Let the long text columns take the free width (no horizontal scrollbar at 1100 px / high DPI)."""
    h = table.horizontalHeader()
    h.setStretchLastSection(False)
    for c in cols:
        h.setSectionResizeMode(c, QHeaderView.Stretch)


def _open_url(url):
    if url:
        QDesktopServices.openUrl(QUrl(url))


class UpdatesPage(W.Page):
    IDLE_TEXT = "Not checked yet - asks Windows Update online what this PC is missing (1-3 minutes)."

    def __init__(self, app):
        super().__init__(app)
        self.result = None
        self.busy = False
        self._waiters = []
        self._sig = None
        self.tr_drv = None
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, 0)
        bar.setSpacing(T.S2)
        self.lbl = W.label(self.IDLE_TEXT, "Body", wrap=True)
        bar.addWidget(self.lbl, 1)
        bar.addWidget(W.button("Open Windows Update", lambda: self._open("ms-settings:windowsupdate")))
        self.btn = W.button("Check online now", self.check, "primary", icon="refresh")
        bar.addWidget(self.btn)
        v.addLayout(bar)
        self.sp = W.ScrollPage()
        v.addWidget(self.sp, 1)
        self._poll = QTimer(self)                       # while visible with no result: notice the scan's search starting
        self._poll.setInterval(1000)
        self._poll.timeout.connect(self._tick)

    def on_show(self):
        if self.result is None:
            self._poll.start()
            self._tick()

    def on_hide(self):
        self._poll.stop()

    def _tick(self):
        if self.result is not None or not self.isVisible():
            self._poll.stop()
            return
        self.request_render()                           # cheap: render() skips when nothing changed

    def _open(self, t):
        try:
            core.open_tool(t)
        except Exception as e:
            W.error(self, str(e))

    # ------------------------------------------------------------------ data
    def check(self, on_done=None):
        """GUI thread only. A second click (or the background scan's check) shares the running search (updates.fetch)."""
        if on_done:
            self._waiters.append(on_done)
        if self.busy:
            return
        self.busy = True
        self._set_btn()
        self.lbl.setText("Asking Windows Update which updates this PC is missing...")
        self.request_render()
        tasks.run_task(up.fetch, self._fetched, self._failed, name="updates-check")

    def _fetched(self, res):
        if not isinstance(res, dict):
            res = {"error": "Stopped by user"} if core.ABORT.is_set() else {"error": "no result"}
        if res.get("error") == "Stopped by user":
            return self._stopped()
        self._finish(res)

    def _failed(self, msg):                    # fetch never raises, but keep the button usable whatever happens
        if core.ABORT.is_set():
            return self._stopped()
        self._stopped("Online check failed: " + str(msg))

    def _finish(self, res):
        self.set_result(res)
        self.busy = False
        self._set_btn()
        waiters, self._waiters = self._waiters, []
        for fn in waiters:
            try:
                fn(res)
            except Exception as e:
                core.log_error("updates on_done", e)

    def _stopped(self, text="Online check stopped."):
        self.busy = False
        self._waiters = []
        self._set_btn()
        self.lbl.setText(text)
        self.request_render()

    def _set_btn(self):
        self.btn.setEnabled(not self.busy)
        self.btn.setText("Checking..." if self.busy else "Check online now")

    def fetch(self):
        """Compat: old callers used app.updates.fetch(). Worker-thread safe; never raises."""
        return up.fetch()

    def set_result(self, res):
        if not isinstance(res, dict) or res is self.result:
            return
        if not isinstance(res.get("counts"), dict):
            res = dict(res)
            res["counts"] = {"missing": 0, "security": 0, "definitions": 0, "optional": 0, "drivers": 0}
        self.busy = False
        self._set_btn()
        self.result = res
        self.app.update_result = res
        self.app.findings_by["Updates"] = list(res.get("findings") or [])
        self.request_render()
        self.app.render_summary()
        tune = self.app.pages.get("tuneup")             # don't create the Tune-up page just for this
        if tune is not None and hasattr(tune, "refresh_items"):
            tune.refresh_items()

    # ------------------------------------------------------------------ render
    def render(self):
        r = self.result
        sig = (id(r), self.busy if not r else None, up._inflight["ev"] is not None if not r else None, self.app.is_admin)
        if sig == self._sig:
            return
        self._sig = sig
        lay = self.sp.lay
        W.clear_layout(lay)
        self.tr_drv = None
        if not r:
            p = W.Panel()
            if self.busy or up._inflight["ev"] is not None:
                p.add(W.label("Windows Update is being asked right now (1-3 minutes). The results appear here by themselves.", "Body", wrap=True))
            else:
                p.add(W.label("Click 'Check online now'. WinDiag asks Microsoft's Windows Update service (or your company's update server) "
                              "which updates and drivers are available for THIS PC - the same list Settings shows.", "Body", wrap=True))
            lay.addWidget(p)
            lay.addStretch(1)
            return
        c = r["counts"]
        g = lambda k: int(c.get(k) or 0)
        if not self.busy:
            self.lbl.setText(("Checked %s  ·  source: %s" % ((r.get("searched") or "")[:16].replace("T", " "), r.get("server") or "?")) if r.get("ok")
                             else "Online check failed: %s" % (r.get("error") or "")[:120])
        # stat tiles
        tiles = [("Missing updates", g("missing"), "CRITICAL" if g("security") else ("WARNING" if g("missing") else "OK"),
                  "%d security" % g("security") if g("security") else "up to date" if not g("missing") else "important"),
                 ("Optional updates", g("optional"), "INFO" if g("optional") else "UNKNOWN", "you choose"),
                 ("Driver updates (Windows Update)", g("drivers"), "WARNING" if g("drivers") else "OK", "offered for this PC"),
                 ("Restart needed", "Yes" if r.get("reboot") else "No", "WARNING" if r.get("reboot") else "OK",
                  "to finish updates" if r.get("reboot") else "")]
        ws = []
        for lab, val, st, sub in tiles:
            t = W.StatTile(lab, str(val), sub, st)
            t.lbl.setWordWrap(True)
            if val in (0, "No"):
                t.sub.setStyleSheet("")                   # only a non-zero value colours the sub line
            ws.append(t)
        fg = _FlowGrid(4, 190)
        fg.set_widgets(ws)
        lay.addWidget(fg)
        if not r.get("ok"):
            lay.addWidget(W.Banner("Windows Update could not be reached: %s" % (r.get("error") or ""),
                                   "Check the internet connection and that the Windows Update service isn't disabled (Guided Fix > Windows Update failures).",
                                   "CRITICAL"))
        # updates table
        rep = core.REPAIR_BY_NAME.get("Install available Windows updates")
        b_inst = W.button("Install important updates", lambda: rep and self.app._repair(rep), "primary")
        b_inst.setEnabled(bool(self.app.is_admin and rep and g("missing")))
        if not self.app.is_admin:
            b_inst.setToolTip("Needs administrator rights.")
        p = W.Panel("Available Windows updates",
                    actions=[W.button("Optional updates", lambda: self._open("ms-settings:windowsupdate-optionalupdates")), b_inst])
        ups = [u for u in list(r.get("updates") or []) + list(r.get("driver_updates") or []) if isinstance(u, dict)]
        rows = [{"Status": "Optional" if u.get("optional") else ("Pending (auto)" if (u.get("kind") == "Definition") else "Missing"),
                 "Type": u.get("kind") or ("Driver" if str(u.get("type")) == "2" else "Update"),
                 "Update": u.get("title"), "KB": ("KB" + str(u["kb"])) if u.get("kb") else "",
                 "Size": "%.0f MB" % ((u.get("size") or 0) / 1048576.0) if isinstance(u.get("size"), (int, float)) and u.get("size") else "",
                 "_url": u.get("url")} for u in ups]
        if rows:
            p.add(W.label("Double-click an update to open Microsoft's page about it.", "Muted", wrap=True))
            t = W.DataTable(["Status", "Type", "Update", "KB", "Size"], [130, 100, 560, 110, 90], on_open=lambda x: _open_url(x.get("_url")),
                            mono=("KB", "Size"), max_rows_visible=8)
            _stretch(t, (2,))
            t.set_rows(rows, ["WARNING" if x["Status"] == "Missing" else None for x in rows])
            p.add(t)
        else:
            p.add(W.Dot("OK", "Nothing missing - Windows Update has no updates for this PC right now.", 13))
        lay.addWidget(p)
        # driver report
        drv = [d for d in (r.get("drivers") or []) if isinstance(d, dict)]
        p = W.Panel("Driver age report",
                    "Important drivers with their date. 'Update on Windows Update' = Microsoft has a newer driver for this exact device. 'Old' is a hint, "
                    "not proof - for graphics, network and storage it's worth checking the maker's site. Double-click a row to open the maker's page.",
                    actions=[W.button("Open maker's download page", self._open_link)])
        self.tr_drv = W.DataTable(["Status", "Device", "Type", "Version", "Date", "Age", "Provider"], [230, 260, 140, 120, 100, 64, 160],
                                  on_open=lambda x: _open_url(x.get("_link")), mono=("Version", "Date", "Age"), max_rows_visible=12)
        _stretch(self.tr_drv, (1, 6))
        self.tr_drv.set_rows(drv, [{"WARNING": "WARNING"}.get(x.get("_sev")) for x in drv])
        if not drv:
            p.add(W.label("No driver information was returned.", "Muted"))
        else:
            p.add(self.tr_drv)
        lay.addWidget(p)
        lay.addStretch(1)

    def _open_link(self):
        sel = self.tr_drv.selected() if self.tr_drv is not None else None
        if not sel or not sel.get("_link"):
            W.info(self, "Select a driver in the list first.")
            return
        _open_url(sel["_link"])

    def shutdown(self):
        self._waiters = []
        self._poll.stop()
