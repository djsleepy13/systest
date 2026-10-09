"""Drive Health page: SMART / NVMe health, read-only tests, drive map, full-drive wipe (wizard in pages/wipe.py)."""
import os
import shutil
import threading
import time

from PySide6.QtCore import QPoint, QRect, QRectF, QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QLayout, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
                               QWidgetItem)

import appsettings as S
import core
import drivehealth as dh
import filetools
from .. import tasks
from .. import theme as T
from .. import widgets as W

MAP_COLS, MAP_ROWS = 60, 20
ST_TONE = {"GOOD": "OK", "CAUTION": "WARNING", "CRITICAL": "CRITICAL", "UNKNOWN": "UNKNOWN"}
ST_COL = {"GOOD": T.OK, "CAUTION": T.WARN, "CRITICAL": T.CRIT, "UNKNOWN": T.MUTED}
SEV_TONE = {"CRITICAL": "CRITICAL", "WARNING": "WARNING", "INFO": "INFO"}
VERDICT_COL = {"FAIL": T.CRIT, "WARN": T.WARN, "ERROR": T.WARN, "PASS": T.OK}
# read-test classes (flat, no purple)
READ_COL = {"ok": T.OK, "slow": "#C9B53A", "veryslow": "#E07B39", "bad": T.CRIT}
UNTESTED = T.SURFACE3
UNPART = "#3A3F46"
UNKNOWN_FS = T.tint(T.WARN, 0.30, T.SURFACE)
PART_PAL = [T.ACCENT, "#3FA7A0", T.OK, T.WARN, "#C97B5A", T.TEXT2]
UNITS = {"Temperature": " C", "Life left": " %"}


def mono_css(color=T.TEXT2, size=12, weight=400):
    """Stylesheet for a mono data label. setFont() alone is overridden by the app-wide '* { font-family }' QSS rule."""
    return "font-family:'%s'; font-size:%dpx; font-weight:%d; color:%s;" % (T.FONT_MONO, size, weight, color)


def mono_label(text="", color=T.TEXT2, size=12, weight=400, wrap=True):
    lb = QLabel(str(text))
    lb.setStyleSheet(mono_css(color, size, weight))
    lb.setWordWrap(wrap)
    lb.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lb


def _usage_col(u):
    """free -> dark blue-grey, used -> accent blue."""
    if u is None:
        return UNKNOWN_FS
    lo, hi = QColor(T.tint(T.ACCENT, 0.16, T.SURFACE2)), QColor(T.ACCENT)
    u = max(0.0, min(1.0, u))
    return "#%02X%02X%02X" % tuple(int(a + (b - a) * u) for a, b in ((lo.red(), hi.red()), (lo.green(), hi.green()), (lo.blue(), hi.blue())))


def _letters(d):
    return ", ".join("%s:" % p["letter"] for p in d.get("partitions") or [] if p.get("letter"))


def life_source(d):
    """Where the 'Life left' figure came from - mirrors the order drivehealth.assess() applies them (last one wins)."""
    v = d.get("verdict") or {}
    if "Life left" not in (v.get("metrics") or {}):
        return None
    src = None
    nv = d.get("nvme_log") or {}
    if nv.get("percentage_used") is not None:
        src = "the drive's NVMe health log ('percentage used' %s%%)" % nv.get("percentage_used")
    attrs = {a.get("id"): a for a in (d.get("attrs") or []) if isinstance(a, dict)}
    if "SSD" in (v.get("kind") or ""):
        lid = next((i for i in dh.LIFE_ATTRS if i in attrs and 0 < (attrs[i].get("value") or 0) <= 100), None)
        if lid is not None:
            src = "SMART attribute %d (%s)" % (lid, attrs[lid].get("name") or dh.ATA_NAMES.get(lid, ""))
    rel = d.get("rel") or {}
    if src is None and rel.get("wear") is not None:
        src = "Windows' wear counter (%s%% used) - the same figure Windows Settings shows as estimated remaining life" % rel.get("wear")
    return src


# ---------------------------------------------------------------------------------
#  Small private widgets
# ---------------------------------------------------------------------------------
class _Flow(QLayout):
    """Left-to-right flow layout that wraps (button rows that must fit 1100 px windows and 200 % scaling)."""

    def __init__(self, parent=None, spacing=T.S2):
        super().__init__(parent)
        self._items = []
        self._sp = spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def addWidget(self, w):
        self.addChildWidget(w)
        self.addItem(QWidgetItem(w))

    def count(self):
        return len(self._items)

    def itemAt(self, i):
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i):
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientations(0)

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
        return s

    def _do(self, r, test):
        x, y, lh = r.x(), r.y(), 0
        for it in self._items:
            if it.widget() is not None and it.widget().isHidden():
                continue
            sh = it.sizeHint()
            if x + sh.width() > r.right() + 1 and lh > 0:
                x, y, lh = r.x(), y + lh + self._sp, 0
            if not test:
                it.setGeometry(QRect(QPoint(x, y), sh))
            x += sh.width() + self._sp
            lh = max(lh, sh.height())
        return y + lh - r.y()


def _flow(*widgets):
    w = QWidget()
    f = _Flow(w)
    for x in widgets:
        if x is not None:
            f.addWidget(x)
    return w


class DriveMap(QWidget):
    """60 x 20 squares, one per 1/1200 of the disk. Width follows the layout, height follows the width."""
    hovered = Signal(int)

    def __init__(self):
        super().__init__()
        self.cols = [UNTESTED] * dh.CELLS
        self.setMouseTracking(True)
        sp = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sp.setHeightForWidth(True)
        self.setSizePolicy(sp)
        self.setMinimumWidth(MAP_COLS * 5)
        self.setMaximumWidth(MAP_COLS * 16)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, w):
        return int(min(w, self.maximumWidth()) * MAP_ROWS / MAP_COLS)

    def sizeHint(self):
        return QSize(MAP_COLS * 13, MAP_ROWS * 13)

    def set_colors(self, cols):
        if cols != self.cols:
            self.cols = list(cols)
            self.update()

    def _cell(self):
        return max(1.0, min(self.width() / float(MAP_COLS), self.height() / float(MAP_ROWS)))

    def paintEvent(self, e):
        p = QPainter(self)
        c = self._cell()
        gap = 2.0 if c >= 8 else 1.0
        cache = {}
        for i, col in enumerate(self.cols):
            r, k = divmod(i, MAP_COLS)
            q = cache.get(col)
            if q is None:
                q = cache[col] = QColor(col)
            p.fillRect(QRectF(k * c, r * c, c - gap, c - gap), q)
        p.end()

    def mouseMoveEvent(self, e):
        c = self._cell()
        k, r = int(e.position().x() // c), int(e.position().y() // c)
        if 0 <= k < MAP_COLS and 0 <= r < MAP_ROWS:
            self.hovered.emit(r * MAP_COLS + k)


class PartStrip(QWidget):
    """Partition layout of the disk as one flat bar."""

    def __init__(self):
        super().__init__()
        self.d = None
        self.setFixedHeight(22)
        self.setMinimumWidth(MAP_COLS * 5)
        self.setMaximumWidth(MAP_COLS * 16)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    def set_drive(self, d):
        self.d = d
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(UNPART))
        d = self.d
        if d:
            size = float(d.get("size") or 1)
            p.setFont(T.mono(10, 600))
            for i, pt in enumerate(d.get("partitions") or []):
                x0 = w * (pt.get("offset") or 0) / size
                x1 = w * ((pt.get("offset") or 0) + (pt.get("size") or 0)) / size
                rr = QRectF(x0, 0, max(2.0, x1 - x0 - 1), h)
                p.fillRect(rr, QColor(PART_PAL[i % len(PART_PAL)]))
                lbl = "%s: %s" % (pt["letter"], pt.get("fs") or "") if pt.get("letter") else (pt.get("type") or "")[:12]
                if x1 - x0 > 60 and lbl:
                    p.setPen(QColor(T.BG))
                    p.drawText(rr, Qt.AlignCenter, lbl)
        p.end()


def _swatch(col):
    s = QLabel()
    s.setFixedSize(12, 12)
    s.setStyleSheet("background:%s; border-radius:2px;" % col)
    return s


def _rule_box(status):
    """Flat tinted box with a coloured left rule (like W.Banner, but with free content). Returns (frame, layout)."""
    col = T.STATUS.get(status, status)
    f = QFrame()
    f.setObjectName("DriveRule")
    f.setStyleSheet("QFrame#DriveRule{background:%s; border:1px solid %s; border-left:3px solid %s; border-radius:4px;}"
                    % (T.tint(col, 0.08, T.BG), T.tint(col, 0.25, T.BG), col))
    v = QVBoxLayout(f)
    v.setContentsMargins(T.S4, T.S3, T.S4, T.S3)
    v.setSpacing(T.S2)
    return f, v


# ---------------------------------------------------------------------------------
#  Page
# ---------------------------------------------------------------------------------
class DrivePage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.drives, self.sel = [], None
        self.loaded = False                 # set_drives() has been called at least once
        self.maps, self.tests, self.running = {}, {}, {}
        self.view = "Usage"
        self.busy = False
        self.smartctl = None
        self.windiag_disk = None
        self._wizard = None
        self._map_loading = set()
        self._alive = True
        self._ver = 0                       # bumped on every state change that needs a redraw
        self._lver = 0                      # bumped when the drive list itself changes
        self._sig_list = None
        self._sig_detail = None
        self._selecting = False
        self._w = {}                         # live widgets of the detail view (progress, map...) - reset on rebuild

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, 0)
        bar.setSpacing(T.S3)
        self.lbl_state = W.label("Not checked yet - the scan fills this in, or click Check drives.", "Body", wrap=True)
        bar.addWidget(self.lbl_state, 1)
        self.lbl_smart = W.label("smartctl: looking...", "Muted")
        bar.addWidget(self.lbl_smart)
        self.btn_check = W.button("Check drives", self.check, "primary", icon="refresh", min_w=140)
        bar.addWidget(self.btn_check)
        v.addLayout(bar)
        self.sp = W.ScrollPage()
        v.addWidget(self.sp, 1)
        self.sp.add(W.label("Reads each drive's own health data (SMART / NVMe log). Every test on this page is READ-ONLY - nothing on the drive is written, "
                            "moved or deleted. Tests are offered for healthy drives (and SSDs that are only worn); drives showing signs of failure get fixes "
                            "instead of tests.", "Body", wrap=True))
        self.p_list = W.Panel("Drives", "Click a drive for details. Double-click opens every SMART / NVMe value.")
        self.table = W.DataTable(["Disk", "Model", "Type", "Size", "Status", "Health %", "Life left", "Temp C", "Letters"],
                                 [50, 240, 130, 90, 110, 80, 80, 70, 90], on_open=self._open_row,
                                 mono=("Disk", "Size", "Health %", "Life left", "Temp C", "Letters"), max_rows_visible=8)
        self.table.selectionModel().selectionChanged.connect(self._table_sel)
        self.p_list.body.setContentsMargins(0, 0, 0, 0)
        self.p_list.add(self.table)
        self.lbl_empty = W.label("", "Muted", wrap=True)
        self.lbl_empty.setContentsMargins(T.S4, T.S3, T.S4, T.S3)
        self.p_list.add(self.lbl_empty)
        self.sp.add(self.p_list)
        self.detail = QWidget()
        self.dlay = QVBoxLayout(self.detail)
        self.dlay.setContentsMargins(0, 0, 0, 0)
        self.dlay.setSpacing(T.S5)
        self.sp.add(self.detail)
        self.sp.finish()

        self._tick = QTimer(self)
        self._tick.setInterval(400)
        self._tick.timeout.connect(self._on_tick)
        self._find_smartctl()

    # ------------------------------------------------------------------ app contract
    def wipe_running(self):
        w = self._wizard
        try:
            return bool(w is not None and w.is_running())
        except RuntimeError:            # dialog already deleted
            return False

    def stop_all(self):
        for n in list(self.running):
            self.stop(n)

    def shutdown(self):
        self._alive = False
        self._tick.stop()
        for st in list(self.running.values()):
            ev = st.get("cancel")
            if ev is not None:
                ev.set()
            t = st.get("test")
            if t is not None:
                t.cancel.set()
        # Let the read-test threads end before tasks.shutdown() waits for them:
        #  - thread.quit() now: tasks.run_task connects worker.finished -> thread.quit with an AUTO (= queued, the QThread object
        #    lives on the GUI thread) connection, so without this the thread never leaves its event loop while the GUI thread waits;
        #    quit() is thread-safe and only takes effect after the worker function has returned.
        #  - time.sleep releases the GIL (QThread.wait() does not), so the worker can finish its last Python lines.
        own = [st["task"] for st in self.running.values() if st.get("task") is not None]
        for t in own:
            try:
                t.thread.quit()
            except RuntimeError:
                pass
        deadline = time.time() + 3.0
        while time.time() < deadline and any(t.running() for t in own):
            time.sleep(0.02)
        w = self._wizard
        if w is not None:
            try:
                w.shutdown()
            except RuntimeError:
                pass

    def on_show(self):
        if self.running:
            self._tick.start()

    def on_hide(self):
        self._tick.stop()

    # ------------------------------------------------------------------ smartctl
    def _find_smartctl(self):
        def done(exe):
            self.smartctl = exe
            self.lbl_smart.setText("smartctl: found" if exe else "smartctl: not found (self-tests off)")
            self._bump()
        tasks.run_task(dh.find_smartctl, done, lambda m: done(None), args=(core.app_dir(),), name="find-smartctl")

    def get_smartctl(self):
        def work():
            filetools.open_console("winget install --id smartmontools.smartmontools -e --accept-package-agreements --accept-source-agreements",
                                   "Install smartmontools")
        tasks.run_task(work, None, lambda m: W.error(self, "Could not start the installer:\n%s" % m), name="get-smartctl")
        W.info(self, "smartmontools is installing in the console window.\nWhen it finishes, click 'Check drives' again.\n\n"
                     "Tip: 'Copy smartctl to USB' then keeps a portable copy next to WinDiag for other PCs.")

    def copy_smartctl(self):
        def work():
            src = dh.find_smartctl(core.app_dir())
            if not src:
                return None
            dst = os.path.join(core.app_dir(), "tools")
            os.makedirs(dst, exist_ok=True)
            shutil.copy2(src, os.path.join(dst, "smartctl.exe"))
            return dst

        def done(dst):
            if not dst:
                W.info(self, "smartctl isn't installed on this PC yet - use 'Get smartctl' first.")
            else:
                W.info(self, "Copied to %s\nWinDiag will use it on every PC from now on." % dst)
        tasks.run_task(work, done, lambda m: W.error(self, m), name="copy-smartctl")

    # ------------------------------------------------------------------ data
    def check(self):
        if self.busy:
            return
        sc = getattr(self.app, "scanner", None)
        if sc is not None and sc.running and any(x["key"] == "drives" and x["state"] in ("wait", "run") for x in sc.steps):
            self.app.set_status("Drive health is being read by the running scan - this page fills in when it's done.", hold=4)
            return
        self.busy = True
        self.btn_check.setEnabled(False)
        self.btn_check.setText("Checking...")
        self.app.set_status("Reading drive health data...")
        app_dir = core.app_dir()

        def work():
            drives, raw = None, {}
            exe = dh.find_smartctl(app_dir)
            try:
                raw = core.run_ps_json(dh.DRIVES_PS, 240)
                if not isinstance(raw, dict):
                    raw = {"detail": "unexpected output from PowerShell"}
                smart = None
                if exe:
                    try:
                        smart = dh.smartctl_all(exe)
                    except Exception as e:
                        core.log_error("smartctl scan", e)
                        smart = None
                drives = dh.build(raw, smart) if raw.get("drives") is not None else None
            except Exception as e:
                core.log_error("drive check", e)
                drives, raw = None, {"detail": "Could not read drive data: %s" % core.friendly_error(e)}
            return drives, raw, exe
        tasks.run_task(work, self._checked, lambda m: self._checked((None, {"detail": m}, self.smartctl)), name="drive-check")

    def _checked(self, out):
        drives, raw, exe = out
        self.busy = False
        self.btn_check.setEnabled(True)
        self.btn_check.setText("Check drives")
        self.smartctl = exe
        self.lbl_smart.setText("smartctl: found" if exe else "smartctl: not found (self-tests off)")
        if drives is None:
            self.app.set_status("Drive check failed: %s" % (str((raw or {}).get("detail") or "no data returned"))[:150], "WARNING", hold=6)
            return
        self.set_drives(drives)
        self.app.set_status("Drive check finished: %d drive(s)." % len(drives))

    def set_drives(self, drives):
        """Called by the scan (GUI thread, page may be hidden) and by Check drives."""
        drives = [d for d in (drives or []) if isinstance(d, dict) and isinstance(d.get("verdict"), dict)]
        for d in drives:
            d.setdefault("partitions", [])
        self.drives = drives
        self.loaded = True
        self.windiag_disk = dh.disk_of_path(drives, core.app_dir())
        self.app.findings_by["Drives"] = dh.summary_findings(drives)
        self.app.drive_result = drives
        nums = [d.get("number") for d in drives]
        if self.sel is None or self.sel not in nums:
            bad = [d for d in drives if d["verdict"].get("status") in ("CRITICAL", "CAUTION")]
            self.sel = (bad or drives or [{"number": None}])[0].get("number")
        # tests that belong to a disk that vanished stay in self.running until their worker returns; results of gone disks are dropped
        self.tests = {n: t for n, t in self.tests.items() if n in nums}
        self.maps = {n: m for n, m in self.maps.items() if n in nums}
        self._lver += 1
        self._bump()
        self.app.render_summary()

    def drive(self, n=None):
        n = self.sel if n is None else n
        return next((d for d in self.drives if d.get("number") == n), None)

    def _bump(self):
        self._ver += 1
        self.request_render()

    # ------------------------------------------------------------------ render
    def render(self):
        sig = (id(self.drives), len(self.drives), self._lver, self.loaded)
        if sig != self._sig_list:
            self._sig_list = sig
            self._render_list()
        dsig = (id(self.drives), self.sel, self._ver)
        if dsig != self._sig_detail:
            self._sig_detail = dsig
            self._render_detail()

    def _render_list(self):
        if not self.loaded:
            self.lbl_state.setText("Not checked yet - the scan fills this in, or click Check drives.")
        else:
            bad = sum(1 for d in self.drives if d["verdict"].get("status") in ("CRITICAL", "CAUTION"))
            self.lbl_state.setText("%d drive(s)  ·  %s  ·  checked at %s" % (len(self.drives), ("%d need attention" % bad) if bad else "no problems found",
                                                                         time.strftime("%H:%M")))
        rows, tags = [], []
        for d in self.drives:
            v = d["verdict"]
            m = v.get("metrics") or {}
            rows.append({"Disk": d.get("number") if d.get("number") is not None else "--", "Model": d.get("model") or "?", "Type": v.get("kind") or "",
                         "Size": dh.fmt_bytes(d.get("size")), "Status": v.get("status"),
                         "Health %": "--" if v.get("health") is None else v["health"],
                         "Life left": ("%s %%" % m["Life left"]) if m.get("Life left") is not None else "--",
                         "Temp C": m.get("Temperature") if m.get("Temperature") is not None else "--",
                         "Letters": _letters(d) or "--", "_n": d.get("number")})
            tags.append(None)
        self._selecting = True
        try:
            self.table.set_rows(rows, tags)
            self._select_row(self.sel)
        finally:
            self._selecting = False
        self.table.setVisible(bool(rows))
        if not self.loaded:
            self.lbl_empty.setText("Not checked yet - the scan fills this in, or click Check drives.")
        elif not rows:
            self.lbl_empty.setText("Windows didn't report any drives. Run WinDiag as administrator and click Check drives again.")
        self.lbl_empty.setVisible(not rows)

    def _select_row(self, n):
        px = self.table.proxy
        for r in range(px.rowCount()):
            src = px.mapToSource(px.index(r, 0)).row()
            if self.table.model_.row(src).get("_n") == n:
                self.table.selectRow(r)
                return

    def _table_sel(self, *a):
        if self._selecting:
            return
        row = self.table.selected()
        if row and row.get("_n") != self.sel:
            self.select(row.get("_n"))

    def _open_row(self, row):
        d = self.drive(row.get("_n"))
        if d:
            self.app.text_popup("Disk %s - %s" % (d.get("number"), d.get("model")), self.details_text(d))

    def select(self, n):
        self.sel = n
        if (self.table.selected() or {}).get("_n") != n:
            self._selecting = True
            try:
                self._select_row(n)
            finally:
                self._selecting = False
        self.request_render()

    def _render_detail(self):
        W.clear_layout(self.dlay)
        self._w = {}
        d = self.drive()
        if not d:
            return
        v = d["verdict"]
        self.dlay.addWidget(self._head_panel(d))
        if v.get("findings"):
            p = W.Panel("What was found")
            p.add(W.FindingsList([(SEV_TONE.get(f.get("severity"), "INFO"), f.get("title") or "", f.get("why") or "") for f in v["findings"]]))
            self.dlay.addWidget(p)
        if v.get("can_test"):
            self.dlay.addWidget(self._tests_panel(d))
        else:
            w = self._fix_section(d)
            if w is not None:
                self.dlay.addWidget(w)
        self.dlay.addWidget(self._map_panel(d))
        self.dlay.addWidget(self._wipe_panel(d))
        self._show_test(d.get("number"))

    # ---------- header: identity, health ring, metrics, NVMe life ----------
    def _head_panel(self, d):
        v = d["verdict"]
        st = v.get("status") or "UNKNOWN"
        badge = W.Badge(st if v.get("health") is None else "%s  ·  HEALTH %d%%" % (st, v["health"]), ST_TONE.get(st, "UNKNOWN"))
        btn = W.button("All SMART / NVMe values", lambda: self.app.text_popup("Disk %s - %s" % (d.get("number"), d.get("model")), self.details_text(d)),
                       icon="info")
        p = W.Panel(d.get("model") or "?", actions=[btn, badge])
        p.add(mono_label("Disk %s  |  %s  |  %s  |  %s  |  serial %s  |  firmware %s%s" % (
            d.get("number") if d.get("number") is not None else "--", v.get("kind"), d.get("bus") or "?", dh.fmt_bytes(d.get("size")),
            d.get("serial") or "?", d.get("firmware") or "?", "  |  data via smartctl" if d.get("smartctl") else ""), T.TEXT2, 11))
        if d.get("is_system") or d.get("is_boot"):
            p.add(W.label("This is the Windows drive.", "Muted"))
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, T.S2, 0, 0)
        h.setSpacing(T.S5)
        ring = W.Ring(96, 7)
        ring.set(v.get("health"), ST_COL.get(st, T.MUTED), "health")
        h.addWidget(ring, 0, Qt.AlignTop)
        right = QVBoxLayout()
        right.setSpacing(T.S4)
        m = v.get("metrics") or {}
        if m:
            g = W.KeyValueGrid(cols=4)
            g.set([(k, "%s%s" % (val, UNITS.get(k, "")), {"mono": True}) for k, val in m.items()])
            right.addWidget(g)
        else:
            right.addWidget(W.label("The drive didn't report any health counters.", "Muted", wrap=True))
        life = m.get("Life left")
        if life is not None:
            right.addWidget(self._life_block(d, life))
        right.addStretch(1)
        h.addLayout(right, 1)
        p.add(row)
        return p

    def _life_block(self, d, life):
        try:
            life = int(life)
        except (TypeError, ValueError):
            life = 0
        box = QWidget()
        lv = QVBoxLayout(box)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(T.S1)
        top = QHBoxLayout()
        top.addWidget(W.label("SSD life left (rated write endurance)", "Label"))
        top.addStretch(1)
        col = T.CRIT if life <= 10 else T.WARN if life <= 30 else T.OK
        top.addWidget(mono_label("%d %%" % life, col, 12, 600, wrap=False))
        lv.addLayout(top)
        mt = W.Meter(6)
        mt.set(life / 100.0, col)
        lv.addWidget(mt)
        src = life_source(d)
        txt = "Life left = 100% minus the wear the drive reports"
        txt += (", read from %s." % src) if src else "."
        txt += " Wear is normal - it only becomes a concern below 30%."
        if d.get("nvme_error") and "disagrees with Windows" in str(d.get("nvme_error")):
            txt += " The drive's own NVMe log disagreed with Windows by more than 10% and was ignored."
        lv.addWidget(W.label(txt, "Muted", wrap=True))
        return box

    # ---------- failing drive: fixes, no tests ----------
    def _fix_section(self, d):
        v = d["verdict"]
        st = v.get("status")
        if st in ("GOOD", "UNKNOWN"):
            # no Windows disk number (virtual / storage-pool disk): nothing to test, nothing wrong
            p = W.Panel("Tests")
            p.add(W.label("Tests aren't available for this disk (Windows doesn't give it a disk number - virtual or pooled storage).", "Muted", wrap=True))
            return p
        crit = st == "CRITICAL"
        f, lay = _rule_box("CRITICAL" if crit else "WARNING")
        why = {"CRITICAL": "it shows signs of failing", "CAUTION": "it shows warning signs (see above)"}.get(st, "of the findings above")
        lay.addWidget(W.label("Tests are turned OFF for this drive because %s." % why, "PanelTitle", wrap=True))
        lay.addWidget(W.label("Read tests and self-tests make a weak drive work hard for hours - that can finish it off and lose the data that is still readable. "
                              "Get your data off first, then replace the drive.", "Value", wrap=True))
        lay.addWidget(W.label("WHAT TO DO", "Label"))
        lay.addWidget(W.label("\n".join("%d. %s" % (i + 1, x) for i, x in enumerate((v.get("fixes") or [])[:8])), "Value", wrap=True, sel=True))
        letter = next((p["letter"] for p in d.get("partitions") or [] if p.get("letter")), None)
        b_open = W.button("Open drive to copy files", lambda: self._open_letter(letter), "primary", icon="folder")
        b_open.setEnabled(bool(letter))
        lay.addWidget(_flow(b_open, W.button("Recover deleted files", lambda: self._recover(d)),
                            W.button("Guided Fix: disk", self._guided_disk, icon="wand"),
                            W.button("Warranty / maker tool", lambda: QDesktopServices.openUrl(QUrl("https://www.bing.com/search?q=%s" % (
                                (d.get("model") or "") + " warranty check").replace(" ", "+"))))))
        lay.addWidget(W.label("Cloning: tools like Macrium Reflect or Clonezilla (with 'ignore bad sectors' / rescue mode) copy the whole drive to a new one. "
                              "Clone BEFORE running CHKDSK - CHKDSK can make more data unreadable on a failing disk.", "Body", wrap=True))
        return f

    def _guided_disk(self):
        self.app.show_page("guided")
        g = self.app.page("guided")
        if hasattr(g, "open_playbook"):
            g.open_playbook("disk")

    # ---------- healthy drive: tests ----------
    def _tests_panel(self, d):
        n = d.get("number")
        running = n in self.running
        p = W.Panel("Tests (read-only)", "Self-tests run inside the drive. The read test and surface scan read the disk through a READ-ONLY handle - "
                                         "Windows refuses any write on it, so your files are never changed. You can keep using the PC.")
        st_ok = bool(self.smartctl and d.get("smart_args")) and not running
        rt_ok = bool(self.app.is_admin) and not running
        b1 = W.button("Short self-test (~2 min)", lambda: self.selftest(d, "short"))
        b2 = W.button("Long self-test", lambda: self.selftest(d, "long"))
        b3 = W.button("Quick read test", lambda: self.read_test(d, "quick"), "primary", icon="play")
        b4 = W.button("Full surface scan", lambda: self.read_test(d, "full"))
        for b, ok in ((b1, st_ok), (b2, st_ok), (b3, rt_ok), (b4, rt_ok)):
            b.setEnabled(ok)
        stop = W.button("Stop", lambda: self.stop(n), "stop", icon="stop") if running else None
        p.add(_flow(b1, b2, b3, b4, stop))
        if not self.smartctl:
            p.add(_flow(W.label("Self-tests need smartctl (free, smartmontools).", "Muted"), W.button("Get smartctl", self.get_smartctl, icon="download"),
                        W.button("Copy smartctl to USB", self.copy_smartctl, icon="copy")))
        elif not d.get("smart_args"):
            p.add(W.label("smartctl can't reach this drive (USB/virtual/RAID) - self-tests unavailable; the read test still works.", "Muted", wrap=True))
        if not self.app.is_admin:
            p.add(W.colored("Read tests need administrator rights.", T.WARN, 12))
        prog = W.Meter(6)
        lbl = mono_label("", T.TEXT, 12)
        show = running or n in self.tests
        prog.setVisible(show)
        lbl.setVisible(show)
        p.add(prog)
        p.add(lbl)
        self._w.update(prog=prog, lbl_test=lbl)
        return p

    def _show_test(self, n):
        if n != self.sel:
            return
        info = self.running.get(n) or self.tests.get(n) or {}
        prog, lbl = self._w.get("prog"), self._w.get("lbl_test")
        if prog is None or lbl is None:
            return
        try:
            pct = info.get("pct", 1.0) or 0.0
            prog.set(pct, VERDICT_COL.get(info.get("verdict"), T.ACCENT))
            lbl.setText(info.get("text", ""))
            lbl.setStyleSheet(mono_css(VERDICT_COL.get(info.get("verdict"), T.TEXT), 12))
        except RuntimeError:
            pass

    def _progress_text(self, st):
        t = st.get("test")
        p = st.get("pct", 0.0) or 0.0
        if t is None:
            return st.get("text", "")
        now = time.time()
        el = max(1, now - (t.t0 or now))
        eta = el / p - el if p > 0.01 else 0
        bad = sum(t.err)
        return "%s: %d%%  |  %s read  |  %s  |  ~%d min left" % ("Quick read test" if t.mode == "quick" else "Surface scan", p * 100,
                                                               dh.fmt_bytes(t.done_bytes), ("%d bad block(s)" % bad) if bad else "no errors", eta / 60)

    def _on_tick(self):
        """Polls running read tests (the worker only stores numbers; nothing is pushed per read)."""
        if not self._alive or not self.isVisible():
            self._tick.stop()
            return
        if not self.running:
            self._tick.stop()
            return
        for n, st in list(self.running.items()):
            if st.get("kind") == "read" and st.get("test") is not None:
                st["text"] = self._progress_text(st)
        n = self.sel
        if n in self.running:
            self._show_test(n)
            if self.view == "Read test" and self.running[n].get("test") is not None:
                self._draw_map(self.drive(n))

    def read_test(self, d, mode):
        n = d.get("number")
        if n is None or n in self.running:
            return
        if mode == "full":
            hrs = (d.get("size") or 0) / (150e6 if "Hard" in (d["verdict"].get("kind") or "") else 1000e6) / 3600
            if not W.confirm(self, "Read every sector of %s (%s)?\n\nEstimated time: %.1f hour(s). Read-only - nothing is written.\n"
                                   "The PC can be used meanwhile but the drive will be slower. You can stop at any time." % (
                                       d.get("model"), dh.fmt_bytes(d.get("size")), max(0.1, hrs)), "WinDiag - Full surface scan"):
                return
        st = {"kind": "read", "mode": mode, "test": None, "cancel": threading.Event(), "pct": 0.0,
              "text": "Starting %s..." % ("quick read test" if mode == "quick" else "surface scan")}
        self.running[n] = st
        self.tests.pop(n, None)
        self.view = "Read test"
        size = d.get("size") or 0

        def work():
            try:
                reader = dh.WinDiskReader(n, size)
            except Exception as e:
                return {"open_error": str(e)}

            def prog(t, p):
                st["pct"] = p           # plain float; the GUI timer reads it
            test = dh.ReadTest(reader, mode, dh.CELLS, progress=prog)
            st["test"] = test
            if st["cancel"].is_set():
                test.cancel.set()
            try:
                return test.run()
            except Exception as e:
                core.log_error("read test disk %s" % n, e)
                return {"verdict": "ERROR", "mode": mode, "text": "The test stopped because of an error (%s) - this is not a drive fault. "
                                                                  "Try again; details are in the error log." % core.friendly_error(e)}

        def fail(msg):
            self._read_done(n, st, {"verdict": "ERROR", "mode": mode, "text": "The test stopped because of an error (%s) - this is not a drive fault. "
                                                                               "Try again; details are in the error log." % msg})
        st["task"] = tasks.run_task(work, lambda res: self._read_done(n, st, res), fail, name="read-test-%s" % n)
        if self.isVisible():
            self._tick.start()
        self._bump()

    def _read_done(self, n, st, res):
        if self.running.get(n) is st:
            self.running.pop(n, None)
        if not self._alive:
            return
        if res.get("open_error"):
            self._bump()
            W.error(self, res["open_error"])
            return
        test = st.get("test")
        extra = ""
        if res.get("avg_mbs"):
            extra = "\nAverage %.0f MB/s (slowest area %.0f MB/s), slowest single read %.0f ms." % (res["avg_mbs"], res["min_mbs"], res["max_latency_ms"])
        if res.get("errors"):
            extra += "\nFirst unreadable spots: " + ", ".join("%s (%s)" % (dh.fmt_bytes(o), e) for o, e in res["errors"][:4])
        self.tests[n] = {"kind": "read", "test": test, "res": res, "pct": 1.0, "verdict": res.get("verdict"),
                         "text": "%s%s: %s%s" % ("Quick read test" if res.get("mode") == "quick" else "Surface scan", " (stopped)" if res.get("cancelled") else "",
                                                 res.get("text", ""), extra)}
        d = self.drive(n)
        if d and res.get("verdict") == "FAIL":
            v = d["verdict"]
            v["findings"].insert(0, dh._f("CRITICAL", "Read test found unreadable sectors", res.get("text", ""), ["Back up now", "Replace the drive"]))
            v.update(status="CRITICAL", health=min(v.get("health") or 29, 29), can_test=False)
            v["fixes"] = ["Copy important files off FIRST", "Replace the drive"] + list(v.get("fixes") or [])
            self.app.findings_by["Drives"] = dh.summary_findings(self.drives)
            self.app.render_summary()
            self._lver += 1
        self._bump()
        self.app.set_status("Disk %s: %s" % (n, res.get("text", "")[:120]), {"FAIL": "CRITICAL", "WARN": "WARNING", "ERROR": "WARNING"}.get(res.get("verdict")),
                            hold=6)

    def selftest(self, d, kind):
        n = d.get("number")
        if n is None or n in self.running or not self.smartctl or not d.get("smart_args"):
            return
        st = {"kind": "self", "pct": 0.0, "text": "Starting %s self-test..." % kind}
        self.running[n] = st
        exe, args = self.smartctl, list(d["smart_args"])

        def work():
            try:
                return dh.selftest_start(exe, args, kind)
            except Exception as e:
                core.log_error("self-test start", e)
                return {"ok": False, "messages": [core.friendly_error(e)]}
        tasks.run_task(work, lambda r: self._self_started(n, st, kind, r), lambda m: self._self_started(n, st, kind, {"ok": False, "messages": [m]}),
                       name="selftest-%s" % n)
        self._bump()

    def _self_started(self, n, st, kind, r):
        if self.running.get(n) is not st or not self._alive:
            return
        if not r.get("ok"):
            self.running.pop(n, None)
            self.tests[n] = {"kind": "self", "pct": 0, "verdict": "WARN", "text": "The drive didn't accept the self-test: %s" % (
                "; ".join(str(m) for m in (r.get("messages") or []) if m) or "not supported")}
            self._bump()
            return
        st["text"] = "%s self-test running inside the drive%s..." % (kind.capitalize(), (" (about %s min)" % r["minutes"]) if r.get("minutes") else "")
        self._show_test(n)
        QTimer.singleShot(15000, self, lambda: self._poll_self(n, st, kind))

    def _poll_self(self, n, st, kind):
        if not self._alive or self.running.get(n) is not st:
            return
        d = self.drive(n)
        if not d or not d.get("smart_args") or not self.smartctl:
            self.running.pop(n, None)
            self._bump()
            return
        exe, args = self.smartctl, list(d["smart_args"])

        def work():
            try:
                return dh.selftest_status(exe, args)
            except Exception as e:
                core.log_error("self-test status", e)
                return (True, None, None)        # keep polling; a single failed poll is not a result
        tasks.run_task(work, lambda res: self._self_status(n, st, kind, res), lambda m: self._self_status(n, st, kind, (True, None, None)),
                       name="selftest-poll-%s" % n)

    def _self_status(self, n, st, kind, res):
        if not self._alive or self.running.get(n) is not st:
            return
        running, pct, last = res
        if running:
            if pct is not None:
                st.update(pct=(pct or 0) / 100.0, text="%s self-test running: %s%% done" % (kind.capitalize(), pct))
            self._show_test(n)
            QTimer.singleShot(30000, self, lambda: self._poll_self(n, st, kind))
            return
        self.running.pop(n, None)
        ok = (last or {}).get("passed")
        self.tests[n] = {"kind": "self", "pct": 1.0, "verdict": {True: "PASS", False: "FAIL"}.get(ok, "WARN"),
                         "text": "%s self-test finished: %s" % (kind.capitalize(), (last or {}).get("result") or "no result reported")}
        self._bump()

    def stop(self, n):
        st = self.running.get(n)
        if not st:
            return
        if st["kind"] == "read":
            st["cancel"].set()
            t = st.get("test")
            if t is not None:
                t.cancel.set()
            st["text"] = "Stopping..."
            self._show_test(n)
        else:
            d = self.drive(n)
            if d and d.get("smart_args") and self.smartctl:
                exe, args = self.smartctl, list(d["smart_args"])
                tasks.run_task(self._abort_selftest, None, None, args=(exe, args), name="selftest-abort")
            self.running.pop(n, None)
            self._bump()

    @staticmethod
    def _abort_selftest(exe, args):
        try:
            dh.smartctl_json(exe, "-X", *args)
        except Exception as e:
            core.log_error("self-test abort", e)

    # ---------- drive map ----------
    def _map_panel(self, d):
        seg = QWidget()
        sl = QHBoxLayout(seg)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)
        seg.setStyleSheet("QPushButton{border-radius:0; padding:6px 12px;} QPushButton:checked{background:%s; color:%s; border-bottom:2px solid %s;}"
                          % (T.SURFACE3, T.TEXT, T.ACCENT))
        grp = QButtonGroup(seg)
        for name in ("Usage", "Read test"):
            b = QPushButton(name)
            b.setCheckable(True)
            b.setChecked(self.view == name)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda checked=False, v=name: self._set_view(v))
            grp.addButton(b)
            sl.addWidget(b)
        btn_load = W.button("Load usage map", lambda: self.load_map(d), icon="refresh")
        p = W.Panel("Drive map", actions=[seg, btn_load])
        ssd = "SSD" in (d["verdict"].get("kind") or "")
        p.add(W.label(("Each square = 1/%d of the disk (%s), in order from the start of the drive. " % (dh.CELLS, dh.fmt_bytes((d.get("size") or 0) / dh.CELLS))) +
                      ("SSDs move data around internally (wear levelling), so this shows the drive's logical blocks as Windows sees them - the physical NAND "
                       "chips are hidden behind the SSD controller." if ssd else "On a hard drive the start is the fast outer edge of the platter."),
                      "Body", wrap=True))
        strip = PartStrip()
        strip.set_drive(d)
        p.add(strip)
        mp = DriveMap()
        mp.hovered.connect(self._map_hover)
        p.add(mp)
        legend = QWidget()
        self._legend_lay = _Flow(legend, T.S3)
        p.add(legend)
        lbl = mono_label("Hover a square for details.", T.TEXT2, 11)
        p.add(lbl)
        self._w.update(map=mp, strip=strip, legend=legend, lbl_cell=lbl, legend_key=None)
        self._draw_map(d)
        n = d.get("number")
        if n not in self.maps and self.app.is_admin and n not in self._map_loading:
            self.load_map(d)
        return p

    def _set_view(self, v):
        self.view = v
        self._draw_map(self.drive())

    def load_map(self, d):
        n = d.get("number")
        if n in self._map_loading:
            return
        self._map_loading.add(n)

        def fail(msg):
            self._map_loaded(n, None)
        tasks.run_task(dh.usage_map, lambda m: self._map_loaded(n, m), fail, args=(d,), name="usage-map-%s" % n)

    def _map_loaded(self, n, m):
        self._map_loading.discard(n)
        if not self._alive:
            return
        if m:
            self.maps[n] = m
        if n == self.sel:
            self._draw_map(self.drive(n))

    def _test_for(self, n):
        return (self.running.get(n) or self.tests.get(n) or {}).get("test")

    def _draw_map(self, d):
        mp = self._w.get("map")
        if not d or mp is None:
            return
        n = d.get("number")
        um = self.maps.get(n)
        t = self._test_for(n)
        cls = t.classify() if (t and self.view == "Read test") else None
        cols = []
        for i in range(dh.CELLS):
            if cls:
                col = READ_COL.get(cls[i]) or UNTESTED
            elif um and i < len(um):
                if um[i]["part"] is None:
                    col = UNPART
                else:
                    col = _usage_col(um[i]["used"])
            else:
                col = UNTESTED
            cols.append(col)
        try:
            mp.set_colors(cols)
        except RuntimeError:
            return
        items = ([("Normal", READ_COL["ok"]), ("Slower", READ_COL["slow"]), ("Very slow (weak)", READ_COL["veryslow"]), ("Unreadable", READ_COL["bad"]),
                  ("Not tested yet", UNTESTED)] if cls else
                 [("Used", T.ACCENT), ("Partly used", _usage_col(0.45)), ("Free", _usage_col(0)), ("Not partitioned", UNPART),
                  ("Unknown (locked/other FS)", UNKNOWN_FS)])
        if not cls and not um:
            items = [("Loading the usage map..." if n in self._map_loading else "Click 'Load usage map' (needs admin)", UNTESTED)]
        if self.view == "Read test" and not cls:
            items = [("Run a read test to fill this view", UNTESTED)]
        key = tuple(items)
        if key == self._w.get("legend_key"):
            return
        self._w["legend_key"] = key
        lay = self._legend_lay
        while lay.count():
            it = lay.takeAt(0)
            if it.widget() is not None:
                it.widget().deleteLater()
        for name, col in items:
            lay.addWidget(W.hbox(_swatch(col), W.label(name, "Body"), spacing=T.S1))
        self._w["legend"].updateGeometry()

    def _map_hover(self, i):
        d = self.drive()
        lbl = self._w.get("lbl_cell")
        if not d or lbl is None:
            return
        size = d.get("size") or 0
        a, b = size * i // dh.CELLS, size * (i + 1) // dh.CELLS
        parts = ["Square %d: %s - %s" % (i + 1, dh.fmt_bytes(a), dh.fmt_bytes(b))]
        um = self.maps.get(d.get("number"))
        if um and i < len(um) and um[i]["part"] is not None and um[i]["part"] < len(d.get("partitions") or []):
            p = d["partitions"][um[i]["part"]]
            parts.append("partition %s%s%s" % (p.get("number"), (" (%s:)" % p["letter"]) if p.get("letter") else "",
                                               (" " + p["fs"]) if p.get("fs") else " " + (p.get("type") or "")))
            if um[i]["used"] is not None:
                parts.append("%d%% used" % round(um[i]["used"] * 100))
        elif um:
            parts.append("not partitioned")
        t = self._test_for(d.get("number"))
        if t:
            if t.err[i]:
                parts.append("%d UNREADABLE block(s)" % t.err[i])
            elif t.speed[i]:
                parts.append("read %.0f MB/s, slowest read %.0f ms" % (t.speed[i], t.lat[i]))
        try:
            lbl.setText("   |   ".join(parts))
        except RuntimeError:
            pass

    # ---------- details / attributes ----------
    def details_text(self, d):
        v = d.get("verdict") or {}
        out = ["%s  (disk %s, %s, serial %s)" % (d.get("model"), d.get("number"), v.get("kind"), d.get("serial")), ""]
        nv = d.get("nvme_log")
        if nv:
            out.append("NVMe SMART / HEALTH LOG")
            for k, val in nv.items():
                out.append("  %-28s %s" % (str(k).replace("_", " "), val))
        if d.get("nvme_error"):
            out.append("NVMe log could not be read: %s (needs admin; some RAID/Intel RST drivers hide it)" % d["nvme_error"])
        if d.get("attrs"):
            out += ["", "ATA SMART ATTRIBUTES", "  %-4s %-32s %5s %5s %6s  %s" % ("ID", "Name", "Value", "Worst", "Thresh", "Raw")]
            for a in d["attrs"]:
                out.append("  %-4s %-32s %5s %5s %6s  %s" % (a.get("id"), str(a.get("name") or "")[:32], a.get("value", ""), a.get("worst", ""),
                                                           a.get("thresh", ""), dh._raw(a)))
        if d.get("selftests"):
            out += ["", "SELF-TEST LOG (newest first)"] + ["  %s: %s (at %s h)" % (t.get("type"), t.get("result"), t.get("hours")) for t in d["selftests"][:10]]
        out += ["", "PARTITIONS"] + ["  #%s %s %s %s at %s, %s" % (p.get("number"), ("%s:" % p["letter"]) if p.get("letter") else "--", p.get("fs") or p.get("type"),
                                                                 p.get("label") or "", dh.fmt_bytes(p.get("offset")), dh.fmt_bytes(p.get("size")))
                                     for p in d.get("partitions") or []]
        rel = d.get("rel") or {}
        out += ["", "WINDOWS RELIABILITY COUNTERS"] + ["  %-12s %s" % (k, val) for k, val in rel.items()]
        return "\n".join(out)

    # ---------- wipe ----------
    def _wipe_panel(self, d):
        p = W.Panel("Wipe this entire drive")
        if not S.get("wipe_enabled"):
            p.add(W.label("Drive wipe is switched off (the default), so it can't be used by accident. Turn it on in Settings > Drive wipe.", "Body", wrap=True))
            p.add(W.hbox(W.button("Open Settings", lambda: self.app.show_page("settings"), icon="gear"), "stretch"))
            return p
        blockers = dh.wipe_blockers(d, self.windiag_disk)
        if d.get("number") is None:
            blockers = ["Windows doesn't give it a disk number"] + blockers
        p.add(W.label("Erases EVERYTHING on the drive: every sector is overwritten with zeros (Microsoft diskpart 'clean all'). "
                      "A guided wizard shows what's on the drive, runs safety checks (page file, recovery, Hyper-V, Storage Spaces, RAID, "
                      "in-use, power...), locks onto the drive's serial number, verifies the result and writes an erasure certificate.", "Body", wrap=True))
        ok = not blockers and bool(self.app.is_admin)
        b = W.button("Wipe entire drive...", lambda: self.wipe(d), "danger")
        b.setEnabled(ok)
        p.add(W.hbox(b, "stretch"))
        if blockers:
            p.add(W.colored("Not allowed on this drive: " + "; ".join(blockers) + ".", T.WARN, 12))
        elif not self.app.is_admin:
            p.add(W.colored("Needs WinDiag to run as administrator.", T.WARN, 12))
        return p

    def wipe(self, d):
        if not S.get("wipe_enabled") or d.get("number") is None or dh.wipe_blockers(d, self.windiag_disk) or not self.app.is_admin:
            return
        w = self._wizard
        if w is not None:
            try:
                if w.isVisible():
                    w.raise_()
                    w.activateWindow()
                    return
            except RuntimeError:
                pass
            self._wizard = None
        if self.running:
            return self.app._say_busy("start a drive wipe")
        if not self.app.pin.require("the drive wipe"):
            return
        from .wipe import WipeWizard
        self._wizard = WipeWizard(self.app, d, self)
        self._wizard.finished.connect(self._wizard_closed)
        self._wizard.show()

    def _wizard_closed(self, *a):
        self._wizard = None

    # ---------- links ----------
    def _open_letter(self, letter):
        if letter:
            if not QDesktopServices.openUrl(QUrl.fromLocalFile("%s:\\" % letter)):
                W.error(self, "Could not open %s:" % letter)

    def _recover(self, d):
        self.app.open_page("files", "Recover deleted files")
        letter = next((p["letter"] for p in d.get("partitions") or [] if p.get("letter")), None)
        files = self.app.pages.get("files")
        src = getattr(files, "wf_src", None) if files is not None else None
        if letter and src is not None:
            try:
                for m in ("setCurrentText", "setText", "set"):
                    if hasattr(src, m):
                        getattr(src, m)("%s:" % letter)
                        break
            except Exception:
                pass
