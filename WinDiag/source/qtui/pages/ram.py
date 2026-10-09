"""Memory (RAM) page: summary tiles, slot picture + module table, findings, in-Windows RAM test with a block grid."""
import time

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import QComboBox, QGridLayout, QHBoxLayout, QLabel, QLayout, QSizePolicy, QVBoxLayout, QWidget

import core
import ramtest as rt
from .. import tasks
from .. import theme as T
from .. import widgets as W

MAP_COLS, MAP_ROWS = 60, 20
PASS_OPTIONS = [("1 pass (quick)", 1), ("3 passes", 3), ("Until I stop it", 0)]


def _gb(b):
    return "%g GB" % round((b or 0) / (1 << 30), 1)


def _state_col(s):
    return {"ok": T.OK, "bad": T.CRIT, "run": T.ACCENT}.get(s, T.SURFACE3)


# ---------------------------------------------------------------------------------
#  Private helper widgets
# ---------------------------------------------------------------------------------
class TileRow(QWidget):
    """Row of StatTiles that reflows to fewer columns when the page is narrow (no fixed widths)."""

    def __init__(self, tiles, min_tile=150, spacing=T.S3, natural=False):
        super().__init__()
        self.tiles, self.min_tile, self.cols, self.natural = list(tiles), min_tile, 0, natural
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(spacing)
        self.grid.setSizeConstraint(QLayout.SetNoConstraint)     # may shrink below the current row's width; resizeEvent reflows
        self._reflow(len(self.tiles))

    def minimumSizeHint(self):
        h = super().minimumSizeHint()
        return QSize(max([t.minimumSizeHint().width() for t in self.tiles] + [0]), h.height())

    def _reflow(self, cols):
        cols = max(1, min(len(self.tiles), cols))
        if cols == self.cols:
            return
        self.cols = cols
        for t in self.tiles:
            self.grid.removeWidget(t)
        for c in range(len(self.tiles) + 1):
            self.grid.setColumnStretch(c, 0 if self.natural else (1 if c < cols else 0))
        if self.natural:                          # buttons keep their natural width, left aligned
            self.grid.setColumnStretch(cols, 1)
        for i, t in enumerate(self.tiles):
            self.grid.addWidget(t, i // cols, i % cols)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        n = len(self.tiles)
        w = max(1, self.width())
        for cols in [n] + [c for c in (3, 2) if c < n and n % c == 0] + [1]:
            if w / cols >= self.min_tile:
                break
        self._reflow(cols)


def tile(label_text, value="--", sub="", status=None, small=False):
    t = W.StatTile(label_text, value, sub, status)
    t.val.setWordWrap(True)
    if small:
        t.val.setStyleSheet("font-size:19px;")
    return t


class SlotView(QWidget):
    """Flat picture of the RAM slots. Hover reports the stick under the mouse."""

    def __init__(self, on_hover):
        super().__init__()
        self.on_hover = on_hover
        self.slots, self.bad = [], False
        self._boxes = []
        self.setMouseTracking(True)
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set(self, slots, bad):
        self.slots, self.bad = list(slots or []), bool(bad)
        self.update()

    def set_bad(self, bad):
        if bool(bad) != self.bad:
            self.bad = bool(bad)
            self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        n = max(1, len(self.slots))
        w = max(200, self.width())
        gap = 14.0
        sw = min(200.0, (w - gap * (n - 1)) / n)
        top, bot = 22.0, 128.0
        self._boxes = []
        for k, s in enumerate(self.slots or [None]):
            x0 = k * (sw + gap)
            r = QRectF(x0 + 0.5, top, sw - 1, bot - top)
            if s:
                col = T.CRIT if self.bad else T.OK
                p.setPen(QPen(QColor(T.tint(col, 0.55)), 1))
                p.setBrush(QColor(T.tint(col, 0.16)))
                p.drawRoundedRect(r, 3, 3)
                cw = (sw - 20) / 6.0
                p.setPen(Qt.NoPen)
                p.setBrush(QColor(T.SURFACE3))
                for j in range(6):
                    p.drawRect(QRectF(x0 + 10 + j * cw, top + 10, max(2.0, cw - 6), 14))
                p.setPen(QPen(QColor(T.tint(T.WARN, 0.55)), 2))
                for j in range(int((sw - 8) // 6)):
                    x = x0 + 5 + j * 6
                    p.drawLine(QPointF(x, bot + 2), QPointF(x, bot + 9))
                p.setPen(QColor(T.TEXT))
                p.setFont(T.mono(12, 600))
                p.drawText(QRectF(x0, top + 30, sw, 20), Qt.AlignCenter,
                           ("%s  %s" % (_gb(s.get("size")), rt.MEM_TYPES.get(s.get("type"), ""))).strip())
                p.setFont(T.mono(10))
                p.setPen(QColor(T.TEXT2))
                p.drawText(QRectF(x0, top + 52, sw, 16), Qt.AlignCenter, "%s MT/s" % (s.get("configured") or s.get("speed") or "?"))
                p.setFont(T.ui(10, 500))
                p.drawText(QRectF(x0 + 4, top + 70, sw - 8, 16), Qt.AlignCenter,
                           p.fontMetrics().elidedText(rt.maker_name(s.get("maker")) or "", Qt.ElideRight, int(sw - 8)))
            elif self.slots:
                p.setPen(QPen(QColor(T.MUTED), 1, Qt.DashLine))
                p.setBrush(Qt.NoBrush)
                p.drawRoundedRect(r, 3, 3)
                p.setFont(T.ui(11, 500))
                p.drawText(r, Qt.AlignCenter, "empty")
            if self.slots:
                lab = (s or {}).get("slot") or "Slot %d" % (k + 1)
                p.setPen(QColor(T.TEXT2))
                p.setFont(T.mono(10, 600))
                p.drawText(QRectF(x0, 0, sw, 18), Qt.AlignCenter, p.fontMetrics().elidedText(str(lab), Qt.ElideRight, int(sw)))
                self._boxes.append((x0, x0 + sw, s))
        p.end()

    def mouseMoveEvent(self, e):
        x = e.position().x()
        for x0, x1, s in self._boxes:
            if x0 <= x <= x1:
                if s:
                    txt = "%s (%s): %s %s, rated %s MT/s, running %s MT/s, %s %s, serial %s" % (
                        s.get("slot"), s.get("bank"), _gb(s.get("size")), rt.MEM_TYPES.get(s.get("type"), ""), s.get("speed"), s.get("configured"),
                        rt.maker_name(s.get("maker")), s.get("part") or "", s.get("serial") or "?")
                else:
                    txt = "Empty slot"
                self.on_hover(txt)
                return


class CellGrid(QWidget):
    """60 x 20 squares, one per 1/1200 of the tested memory. Cell size follows the width (scales with the window/DPI)."""

    def __init__(self, on_hover):
        super().__init__()
        self.on_hover = on_hover
        self.states = [None] * rt.CELLS
        self.cell = 12
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(MAP_ROWS * self.cell)

    def set_states(self, states):
        st = list(states) if states else [None] * rt.CELLS
        if st != self.states:
            self.states = st
            self.update()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        c = max(5, min(14, self.width() // MAP_COLS))
        if c != self.cell:
            self.cell = c
            self.setFixedHeight(MAP_ROWS * c)

    def paintEvent(self, e):
        p = QPainter(self)
        c = self.cell
        g = 2 if c >= 8 else 1
        cols = {}
        for i, s in enumerate(self.states[:MAP_COLS * MAP_ROWS]):
            r, k = divmod(i, MAP_COLS)
            col = cols.get(s)
            if col is None:
                col = cols[s] = QColor(_state_col(s))
            p.fillRect(k * c, r * c, c - g, c - g, col)
        p.end()

    def mouseMoveEvent(self, e):
        c = self.cell
        k, r = int(e.position().x()) // c, int(e.position().y()) // c
        if 0 <= k < MAP_COLS and 0 <= r < MAP_ROWS:
            self.on_hover(r * MAP_COLS + k)


def _swatch(color, text):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(T.S1 + 2)
    sq = QLabel()
    sq.setFixedSize(12, 12)
    sq.setStyleSheet("background:%s; border-radius:2px;" % color)
    h.addWidget(sq)
    h.addWidget(W.label(text, "Body"))
    return w


# ---------------------------------------------------------------------------------
#  Page
# ---------------------------------------------------------------------------------
class RamPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.info, self.test, self.result, self.running = None, None, None, False
        self._frac = 0.0
        self._sig = None
        self._checking = False
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        self.lbl_top = W.label("Click 'Check RAM' (runs automatically after the main checks).", "Body", wrap=True)
        bar.addWidget(self.lbl_top, 1)
        self.btn_check = W.button("Check RAM", self.check, "primary", icon="refresh")
        bar.addWidget(self.btn_check, 0, Qt.AlignTop)
        v.addLayout(bar)
        self.sp = W.ScrollPage(margins=(T.S5, T.S2, T.S5, T.S5))
        v.addWidget(self.sp, 1)

        # data-dependent part (rebuilt by render)
        self.info_box = QWidget()
        self.info_lay = QVBoxLayout(self.info_box)
        self.info_lay.setContentsMargins(0, 0, 0, 0)
        self.info_lay.setSpacing(T.S6)
        self.sp.add(self.info_box)
        self.slot_view = None
        self.lbl_slot = None

        # RAM test panel (static skeleton, updated in place)
        tp = W.Panel("RAM test (inside Windows)")
        tp.add(W.label("WinDiag takes most of the FREE memory, locks it into physical RAM and writes test patterns (00, FF, 55, AA, an address pattern "
                       "and random data) into it, then reads them back. Only WinDiag's own memory is used - your files and other programs are not "
                       "touched. Close big programs first to test more. Memory Windows is using can't be tested from inside Windows (about 15-30%), "
                       "and the grid shows WinDiag's memory in order, not physical chip positions.", "Body", wrap=True))
        self.passes = QComboBox()
        for name, _n in PASS_OPTIONS:
            self.passes.addItem(name)
        self.btn_start = W.button("Start RAM test", self.start, "primary", icon="play")
        self.btn_stop = W.button("Stop", self.stop, "stop", icon="stop")
        self.btn_stop.setVisible(False)
        tp.add(W.hbox(self.passes, self.btn_start, self.btn_stop, "stretch"))
        self.meter = W.Meter(6)
        tp.add(self.meter)
        self.lbl_test = QLabel("Not run yet.")
        self.lbl_test.setWordWrap(True)
        self.lbl_test.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tp.add(self.lbl_test)
        self.grid = CellGrid(self._cell_hover)
        tp.add(self.grid)
        tp.add(W.hbox(_swatch(T.OK, "Passed"), _swatch(T.ACCENT, "Testing"), _swatch(T.CRIT, "ERROR"), _swatch(T.SURFACE3, "Not tested"), "stretch",
                      spacing=T.S4))
        self.lbl_cell = W.label("Hover a square for details.", "Muted", wrap=True)
        tp.add(self.lbl_cell)
        self.sp.add(tp)

        # guide panel
        self.guide = W.Panel("If the RAM test (or blue screens) point to RAM")
        steps = ["Turn OFF XMP / EXPO and any overclock in the BIOS ('Load optimized defaults'), then run the test again - unstable settings cause most RAM errors.",
                 "Still errors: shut down, unplug, and leave ONE stick in the slot your motherboard manual calls first (often A2). Run the test.",
                 "Repeat with each stick on its own. The stick that fails alone is faulty - replace it (RAM often has a lifetime warranty).",
                 "If every stick passes alone but they fail together, try another slot or a matching kit - the slot or mixing is the problem.",
                 "For a test of ALL memory with physical locations, boot MemTest86 from a USB stick (runs outside Windows)."]
        self.guide.add(W.label("\n".join("%d. %s" % (k + 1, s) for k, s in enumerate(steps)), "Value", wrap=True, sel=True))
        self.guide.add(TileRow([W.button("Windows Memory Diagnostic (restart)", self._mdsched, icon="wrench"),
                                W.button("MemTest86 (bootable, free)", lambda: QDesktopServices.openUrl(QUrl("https://www.memtest86.com/download.htm")),
                                         icon="download"),
                                W.button("Guided Fix: hardware errors", self._guided, icon="wand")], min_tile=270, spacing=T.S2, natural=True))
        self.sp.add(self.guide)
        self.sp.finish()

        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self._poll)
        self._apply_test_ui()

    # ------------------------------------------------------------------ data
    def check(self):
        if self._checking:
            return
        self._checking = True
        self.btn_check.setEnabled(False)
        self.btn_check.setText("Checking...")

        def work():
            info, raw = None, {}
            try:
                raw = core.run_ps_json(rt.RAM_PS, 120)
                if not isinstance(raw, dict):
                    raw = {"detail": "unexpected output from PowerShell"}
                info = rt.assess(raw) if raw.get("sticks") is not None or raw.get("total") else None
            except Exception as e:
                core.log_error("RAM check", e)
                info, raw = None, {"detail": core.friendly_error(e)}
            return info, raw
        tasks.run_task(work, lambda r: self._checked(*r), lambda m: self._checked(None, {"detail": m}), name="ram-check")

    def _checked(self, info, raw):
        self._checking = False
        self.btn_check.setEnabled(True)
        self.btn_check.setText("Check RAM")
        if not info:
            self.app.set_status("Couldn't read memory details: %s" % str((raw or {}).get("detail") or "no data")[:150], "WARNING")
            return
        self.set_info(info)

    def set_info(self, info):
        self.info = info if isinstance(info, dict) and isinstance(info.get("slots"), list) else None
        self._update_findings()
        self.request_render()

    def _update_findings(self):
        out = []
        for fd in (self.info or {}).get("findings") or []:
            if isinstance(fd, dict) and fd.get("severity") in ("CRITICAL", "WARNING"):
                out.append({"Status": fd["severity"], "Area": "Memory", "Finding": fd.get("title") or "",
                            "Advice": "; ".join((fd.get("fix") or [])[:3])})
        r = self.result
        if r and r.get("verdict") == "FAIL":
            out.insert(0, {"Status": "CRITICAL", "Area": "Memory", "Finding": "RAM test: %d error(s) found" % r.get("errors", 0),
                           "Advice": "Turn off XMP/overclocks; test one stick at a time (Memory page)"})
        elif r and r.get("verdict") == "PASS":
            out.append({"Status": "OK", "Area": "Memory", "Finding": "RAM test passed (%s tested)" % rt._fmt(r.get("tested") or 0), "Advice": ""})
        self.app.findings_by["RAM"] = out
        self.app.ram_result = {"info": self.info, "test": self.result}
        self.app.render_summary()

    # ------------------------------------------------------------------ render (info part)
    def render(self):
        sig = id(self.info)
        if sig == self._sig and self.info_lay.count():
            self._apply_result_ui()
            return
        self._sig = sig
        lay = self.info_lay
        W.clear_layout(lay)
        self.slot_view, self.lbl_slot = None, None
        i = self.info
        if not i:
            self.lbl_top.setText("Click 'Check RAM' (runs automatically after the main checks).")
            lay.addWidget(W.label("No memory details yet.", "Muted"))
            self._apply_result_ui()
            return
        sticks = [s for s in i.get("sticks") or [] if isinstance(s, dict)]
        slots = [s if isinstance(s, dict) else None for s in i.get("slots") or []]
        nslots = i.get("nslots") or len(slots)
        used = sum(1 for s in slots if s)
        spd = max([s.get("configured") or s.get("speed") or 0 for s in sticks] or [0])
        self.lbl_top.setText("%s installed in %d of %d slot(s). Hover a stick for details." % (_gb(i.get("total")), used, nslots))
        tiles = [tile("Installed", _gb(i.get("total"))), tile("Type", "/".join(i.get("types") or []) or "?"),
                 tile("Slots used", "%d of %d" % (used, nslots)), tile("Speed", "%s MT/s" % spd if spd else "?"),
                 tile("Error correction", i.get("ecc") or "Unknown", small=True), tile("Free now", _gb(i.get("free")))]
        if i.get("free") and i.get("total"):
            m = W.Meter(4)
            used_frac = 1.0 - min(1.0, float(i["free"]) / float(i.get("visible") or i["total"]))
            m.set(used_frac, T.WARN if used_frac > 0.85 else T.ACCENT)
            tiles[-1].layout().addWidget(m)
            tiles[-1].sub.setText("%d%% in use" % round(used_frac * 100))
        lay.addWidget(TileRow(tiles))

        sp = W.Panel("RAM slots", ("Motherboard: %s" % i["model"]) if i.get("model") else None)
        self.slot_view = SlotView(self._slot_hover)
        self.slot_view.set(slots, False)
        sp.add(self.slot_view)
        self.lbl_slot = W.label("Hover a stick for details.", "Muted", wrap=True)
        sp.add(self.lbl_slot)
        rows = []
        for k, s in enumerate(slots):
            if s:
                rows.append({"Slot": s.get("slot") or "Slot %d" % (k + 1), "Bank": s.get("bank") or "", "Size": _gb(s.get("size")),
                             "Type": rt.MEM_TYPES.get(s.get("type"), ""), "Rated": "%s MT/s" % s["speed"] if s.get("speed") else "",
                             "Running": "%s MT/s" % s["configured"] if s.get("configured") else "", "Maker": rt.maker_name(s.get("maker")),
                             "Part number": s.get("part") or "", "Serial": s.get("serial") or ""})
            else:
                rows.append({"Slot": "Slot %d" % (k + 1), "Size": "empty"})
        if rows:
            t = W.DataTable(["Slot", "Bank", "Size", "Type", "Rated", "Running", "Maker", "Part number", "Serial"],
                            [110, 90, 80, 70, 100, 100, 110, 170, 100], mono=("Size", "Rated", "Running", "Part number", "Serial"),
                            max_rows_visible=8)
            t.set_rows(rows)
            sp.add(t)
        lay.addWidget(sp)

        finds = [fd for fd in i.get("findings") or [] if isinstance(fd, dict)]
        if finds:
            fp = W.Panel("What was found")
            fp.add(W.FindingsList([(fd.get("severity") or "INFO", fd.get("title") or "", fd.get("why") or "") for fd in finds]))
            lay.addWidget(fp)
        self._apply_result_ui()

    def _apply_result_ui(self):
        """Parts that depend on the test result (cheap, in place)."""
        fail = bool(self.result and self.result.get("verdict") == "FAIL")
        if self.slot_view is not None:
            self.slot_view.set_bad(fail)
        if self.lbl_slot is not None:
            if fail:
                self.lbl_slot.setText("Red = suspect: the test found errors, but Windows can't tell which stick they are on - "
                                      "use the one-stick-at-a-time steps below.")
                self.lbl_slot.setStyleSheet("color:%s;" % T.CRIT)
            elif self.lbl_slot.styleSheet():
                self.lbl_slot.setText("Hover a stick for details.")
                self.lbl_slot.setStyleSheet("")
        self.guide.title_lbl.setText("Found errors? Find the bad stick" if fail else "If the RAM test (or blue screens) point to RAM")

    def _slot_hover(self, txt):
        if self.lbl_slot is not None:
            self.lbl_slot.setText(txt)

    # ------------------------------------------------------------------ test
    def _status_text(self):
        r = self.result
        if self.running and self.test:
            t = self.test
            el = int(time.time() - (t.t0 or time.time()))
            nerr = sum(t.cell_err)
            return "Pass %d, pattern '%s'  |  testing %s (%d%% of RAM)  |  %s  |  %d:%02d elapsed" % (
                t.pass_no, t.pattern, rt._fmt(t.tested) if t.tested else "reserving memory...", round(t.tested * 100 / max(1, t.total_ram)),
                ("%d ERROR(S)" % nerr) if nerr else "no errors", el // 60, el % 60)
        if r:
            s = r.get("text") or ""
            if r.get("samples"):
                s += "\nFirst errors: " + "; ".join("at %s: %s" % tuple(x) for x in r["samples"][:3])
            if not r.get("locked", True):
                s += "\nNote: Windows would not lock more memory, so the test used less than planned."
            return s
        return "Not run yet."

    def _apply_test_ui(self):
        self.btn_start.setEnabled(not self.running)
        self.passes.setEnabled(not self.running)
        self.btn_stop.setVisible(self.running)
        r = self.result
        if self.running:
            self.meter.set(self._frac, T.ACCENT)
        else:
            col = {"FAIL": T.CRIT, "PASS": T.OK, "ERROR": T.WARN, "STOPPED": T.MUTED}.get((r or {}).get("verdict"), T.ACCENT)
            self.meter.set(1.0 if r else 0.0, col)
        self.lbl_test.setText(self._status_text())
        tone = {"FAIL": T.CRIT, "PASS": T.OK}.get((r or {}).get("verdict")) if not self.running else None
        self.lbl_test.setStyleSheet("color:%s; font-family:'%s'; font-size:12px;" % (tone or T.TEXT, T.FONT_MONO))
        self.grid.set_states(self.test.cell_state if self.test else None)

    def _cell_hover(self, i):
        t = self.test
        if not t or not t.tested or i >= len(t.cell_state):
            return
        a, b = t.tested * i // rt.CELLS, t.tested * (i + 1) // rt.CELLS
        st = {"ok": "passed all patterns", "bad": "%d ERROR(S)" % t.cell_err[i], "run": "testing", None: "not tested yet"}.get(t.cell_state[i], "")
        self.lbl_cell.setText("Square %d: test memory %s - %s  |  %s" % (i + 1, rt._fmt(a), rt._fmt(b), st))

    def start(self):
        if self.running:
            return
        passes = dict(PASS_OPTIONS).get(self.passes.currentText(), 1)
        try:
            t = rt.RamTest(passes=passes, progress=self._progress)
        except Exception as e:
            core.log_error("RAM test setup", e)
            W.error(self, "Couldn't prepare the RAM test: %s" % core.friendly_error(e))
            return
        if t.target < (256 << 20):
            W.info(self, "Less than 256 MB of RAM is free - close some programs and try again.")
            return
        if not W.confirm(self, "Test about %s of RAM (%d%%)?\n\nThe PC will feel slow while it runs (it uses almost all free memory). "
                         "Save your work first. You can stop it at any time." % (rt._fmt(t.target), t.target * 100 // max(1, t.total_ram)),
                         "WinDiag - RAM test"):
            return
        self.test, self.running, self.result, self._frac = t, True, None, 0.0
        self.lbl_cell.setText("Hover a square for details.")
        self._apply_test_ui()
        self._apply_result_ui()
        self.app.set_status("RAM test running - the PC may feel slow. Stop it any time (Stop button or Esc).")

        def work():
            try:
                return t.run()
            except Exception as e:
                core.log_error("RAM test", e)
                return {"verdict": "ERROR", "text": "The test stopped because of an error (%s) - this is not a RAM fault. Try again." % core.friendly_error(e),
                        "errors": 0, "tested": 0}
        tasks.run_task(work, lambda res: self._done(t, res),
                       lambda m: self._done(t, {"verdict": "ERROR", "text": "The test stopped because of an error (%s) - this is not a RAM fault. Try again." % m,
                                                "errors": 0, "tested": 0}), name="ram-test")
        if self.isVisible():
            self.timer.start()

    def _progress(self, t, p):
        """Worker thread: only stores the fraction; the GUI polls it with a QTimer."""
        self._frac = p

    def _poll(self):
        if not self.running or not self.isVisible():
            self.timer.stop()
            return
        self._apply_test_ui()

    def _done(self, t, res):
        if t is not self.test:
            return
        self.running = False
        self.timer.stop()
        self.result = res if isinstance(res, dict) else {"verdict": "ERROR", "text": "No result.", "errors": 0, "tested": 0}
        self._apply_test_ui()
        self._apply_result_ui()
        self._update_findings()
        v = self.result.get("verdict")
        self.app.set_status("RAM test: %s" % (self.result.get("text") or "")[:140], {"FAIL": "CRITICAL", "PASS": "OK"}.get(v), hold=8)

    def stop(self):
        if self.test is not None and self.running:
            self.test.cancel.set()
            self.app.set_status("Stopping the RAM test...")

    def stop_all(self):
        self.stop()

    def shutdown(self):
        self.timer.stop()
        if self.test is not None:
            self.test.cancel.set()

    def on_show(self):
        if self.running:
            self._apply_test_ui()
            self.timer.start()

    def on_hide(self):
        self.timer.stop()

    # ------------------------------------------------------------------ guide buttons
    def _mdsched(self):
        rep = core.REPAIR_BY_NAME.get("Memory (RAM) test")
        if rep:
            self.app._repair(rep)

    def _guided(self):
        self.app.show_page("guided")
        g = self.app.page("guided")
        if hasattr(g, "open_playbook"):
            g.open_playbook("hw")
