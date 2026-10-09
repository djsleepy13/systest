"""Battery page: health / capacity / wear tiles, capacity history chart, live charge + power draw, powercfg reports."""
import os
import time

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout

import battery as bt
import core
from .. import tasks
from .. import theme as T
from .. import widgets as W
from .ram import TileRow, tile

NO_HISTORY = "Not enough history yet (Windows builds it up over days/weeks)."


def _mwh(v):
    return "%.1f Wh" % (v / 1000.0) if isinstance(v, (int, float)) and v else "--"


def _hm(v):
    return "%dh %02dm" % (v // 60, v % 60) if isinstance(v, (int, float)) and v else "--"


def _health_status(h):
    return "UNKNOWN" if h is None else ("OK" if h >= 80 else "WARNING" if h >= 50 else "CRITICAL")


def _verdict(h):
    return "Unknown" if h is None else ("Good" if h >= 80 else "Worn - plan a replacement" if h >= 50 else "Replace the battery")


def _hist_points(hist):
    """[(datetime, full, design)] -> [(datetime, % of design)] (bad rows skipped)."""
    out = []
    for row in hist or []:
        try:
            d, f, ds = row
            if ds and f is not None and hasattr(d, "timestamp"):
                out.append((d, f * 100.0 / ds))
        except (TypeError, ValueError, ZeroDivisionError):
            continue
    out.sort(key=lambda x: x[0])
    return out


def _resample(pts, n=160):
    """Evenly spaced (in time) series from irregular points, so the chart's x axis is real time. Linear interpolation."""
    t0, t1 = pts[0][0].timestamp(), pts[-1][0].timestamp()
    if t1 <= t0:
        return [v for _, v in pts], [pts[0][0]] * len(pts)
    ts = [d.timestamp() for d, _ in pts]
    vals, when = [], []
    j = 0
    for k in range(n):
        t = t0 + (t1 - t0) * k / (n - 1)
        while j < len(ts) - 2 and ts[j + 1] < t:
            j += 1
        a, b = ts[j], ts[j + 1]
        f = 0.0 if b <= a else min(1.0, max(0.0, (t - a) / (b - a)))
        vals.append(pts[j][1] + (pts[j + 1][1] - pts[j][1]) * f)
        when.append(t)
    return vals, when


class BatteryPage(W.Page):
    REPORT_NAMES = {"energy": "energy report", "sleepstudy": "sleep drain report", "batteryreport": "battery report"}

    def __init__(self, app):
        super().__init__(app)
        self.info = None
        self._sig = None
        self._last_live_ps = 0
        self._live_busy = False
        self._report_busy = False
        self._checking = False
        self.live_tile = None
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        bar.setSpacing(T.S2)
        self.lbl = W.label("Reads the battery's own capacity data and Windows' battery report.", "Body", wrap=True)
        bar.addWidget(self.lbl, 1)
        self.report_btns = []
        for kind, text in (("energy", "Energy report"), ("sleepstudy", "Sleep drain report"), ("batteryreport", "Full battery report")):
            self.report_btns.append(W.button(text, lambda k=kind: self._report(k), icon="report" if kind == "batteryreport" else None))
        self.btn = W.button("Check battery", self.check, "primary", icon="refresh")
        btns = TileRow(self.report_btns + [self.btn], min_tile=150, spacing=T.S2)
        btns.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        bar.addWidget(btns, 0, Qt.AlignTop)
        v.addLayout(bar)
        self.sp = W.ScrollPage(margins=(T.S5, T.S2, T.S5, T.S5))
        v.addWidget(self.sp, 1)
        self.timer = QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self._tick)

    # ------------------------------------------------------------------ data
    def check(self):
        if self._checking:
            return
        self._checking = True
        self.btn.setEnabled(False)
        self.btn.setText("Checking...")

        def work():
            info, err = None, None
            try:
                raw = core.run_ps_json(bt.BATTERY_PS, 120, "Battery check")
                if not isinstance(raw, dict) or raw.get("status") == "error":
                    err = (raw or {}).get("detail") if isinstance(raw, dict) else None
                    info = {"present": False, "error": err}
                else:
                    info = bt.assess(raw)
            except Exception as e:
                core.log_error("battery check", e)
                err = core.friendly_error(e)
            return info, err
        tasks.run_task(work, self._checked, self._check_failed, name="battery-check")

    def _checked(self, r):
        info, err = r
        if info is None:
            self._check_failed(err)
        else:
            self.set_info(info)

    def _check_failed(self, err):
        self._checking = False
        self.btn.setEnabled(True)
        self.btn.setText("Check battery")
        self.app.set_status("Couldn't read battery data - %s" % (err or "please try again"), "WARNING")

    def set_info(self, info):
        self._checking = False
        self.btn.setEnabled(True)
        self.btn.setText("Check battery")
        if not isinstance(info, dict):
            info = {"present": False}
        self.info = info
        self.app.battery_result = info
        self.app.findings_by["Battery"] = list(info.get("findings") or []) if info.get("present") else []
        self.request_render()
        self.app.render_summary()
        if self.isVisible():
            self._start_live()

    # ------------------------------------------------------------------ reports (powercfg)
    def _report(self, kind):
        if self._report_busy:
            return
        if kind != "batteryreport" and not self.app.is_admin:
            W.info(self, "This report needs administrator rights.")
            return
        path = os.path.join(self.app.report_dir, "%s.html" % kind)
        secs = {"energy": " /duration 60", "sleepstudy": "", "batteryreport": ""}[kind]
        self._report_busy = True
        for b in self.report_btns:
            b.setEnabled(False)
        self.app.set_status("Creating the %s%s..." % (self.REPORT_NAMES[kind], " (takes about 60 seconds)" if kind == "energy" else ""), hold=5)

        def work():
            try:
                if os.path.exists(path):
                    os.remove(path)         # so an old copy isn't mistaken for a new report
            except OSError:
                pass
            try:
                core.tracked_run([core.sys32("powercfg"), "/%s" % kind, "/output", path] + secs.split(), 180, "powercfg %s" % kind)
            except Exception as e:
                core.log_error("battery %s" % kind, e)
            return os.path.exists(path)
        tasks.run_task(work, lambda ok: self._opened(path, ok), lambda m: self._opened(path, False), name="battery-report")

    def _opened(self, path, ok):
        self._report_busy = False
        for b in self.report_btns:
            b.setEnabled(True)
        if ok:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
            self.app.set_status("Report saved: %s" % path, hold=5)
        else:
            self.app.set_status("Windows couldn't create that report on this PC.", "WARNING", hold=5)

    # ------------------------------------------------------------------ render
    def render(self):
        if self.info is self._sig and self.sp.lay.count():
            return
        self._sig = self.info
        lay = self.sp.lay
        W.clear_layout(lay)
        self.live_tile = None
        i = self.info
        if not i:
            p = W.Panel()
            p.add(W.label("Click 'Check battery' (runs automatically after a scan on laptops).", "Body", wrap=True))
            lay.addWidget(p)
            lay.addStretch(1)
            return
        bats = [b for b in i.get("batteries") or [] if isinstance(b, dict)]
        if not i.get("present") or not bats:
            p = W.Panel()
            ic = QLabel()
            ic.setPixmap(T.icon("battery", T.MUTED, 28).pixmap(28, 28))
            ic.setAlignment(Qt.AlignCenter)
            p.add(ic)
            t = QLabel("No battery found")
            t.setStyleSheet("font-family:'%s'; font-size:17px; font-weight:700;" % T.FONT_DISPLAY)
            t.setAlignment(Qt.AlignCenter)
            p.add(t)
            s = W.label("This is a desktop, a virtual machine, or the battery isn't connected / reporting.", "Body", wrap=True)
            s.setAlignment(Qt.AlignCenter)
            p.add(s)
            if i.get("error"):
                e = W.label(str(i["error"])[:300], "Muted", wrap=True)
                e.setAlignment(Qt.AlignCenter)
                p.add(e)
            p.body.setContentsMargins(T.S5, T.S6, T.S5, T.S6)
            lay.addWidget(p)
            lay.addStretch(1)
            return
        for k, b in enumerate(bats):
            lay.addWidget(self._battery_panel(b, live=(k == 0)))
        lay.addWidget(self._history_panel())
        rt = i.get("runtime") or {}
        if isinstance(rt, dict) and rt:
            p = W.Panel("Estimated battery life", "Windows' own estimate from your recent usage.")
            p.add(TileRow([tile("Now (at full charge)", _hm(rt.get("FullChargeCapacity"))),
                           tile("When new (design capacity)", _hm(rt.get("DesignCapacity")))], min_tile=180))
            lay.addWidget(p)
        tips = [t for t in i.get("tips") or [] if t]
        if tips:
            p = W.Panel("Looking after the battery")
            p.add(W.label("\n".join("•  " + t for t in tips), "Value", wrap=True, sel=True))
            lay.addWidget(p)
        lay.addStretch(1)
        self._update_live()

    def _battery_panel(self, b, live=False):
        h = b.get("health")
        h = h if isinstance(h, (int, float)) else None
        st = _health_status(h)
        p = W.Panel(b.get("name") or "Battery", actions=[W.Badge(_verdict(h), st)])
        t_health = tile("Health", "--" if h is None else "%.0f%%" % h, _verdict(h), None if h is None else st)
        m = W.Meter(4)
        m.set(0 if h is None else min(1.0, h / 100.0), T.STATUS[st])
        t_health.layout().addWidget(m)
        full, design = b.get("full"), b.get("design")
        t_cap = tile("Capacity at full charge", _mwh(full), "Holds %s of the %s it was designed for." % (_mwh(full), _mwh(design)))
        m = W.Meter(4)
        m.set(min(1.0, full / float(design)) if isinstance(full, (int, float)) and isinstance(design, (int, float)) and design > 0 else 0,
              T.STATUS[st] if h is not None else T.MUTED)
        t_cap.layout().addWidget(m)
        wpy = (self.info or {}).get("wear_per_year")
        wpy_txt = ("%.1f %% of design" % wpy) if isinstance(wpy, (int, float)) else "needs 30+ days of history"
        t_wear = tile("Wear", "--" if h is None else "%.0f%%" % max(0.0, 100.0 - h), "Wear per year: " + wpy_txt)
        m = W.Meter(4)
        m.set(0 if h is None else max(0.0, min(1.0, (100.0 - h) / 100.0)), T.STATUS[st] if h is not None else T.MUTED)
        t_wear.layout().addWidget(m)
        tiles = [t_health, t_cap, t_wear]
        if live:
            t_now = tile("Right now", "--", "")
            self.live_meter = W.Meter(4)
            t_now.layout().addWidget(self.live_meter)
            self.live_tile = t_now
            self.live_bat = b
            tiles.append(t_now)
        else:
            tiles.append(tile("Charge", "%s%%" % b["charge"] if b.get("charge") is not None else "--", self._live_text(b)))
        p.add(TileRow(tiles, min_tile=170))
        g = W.KeyValueGrid(cols=3)
        cyc = b.get("cycles")
        g.set([("Charge cycles", cyc if cyc else "not reported", {"mono": bool(cyc)}), ("Chemistry", b.get("chemistry") or "--"),
               ("Maker", b.get("maker") or "--"), ("Manufactured", b.get("made") or "--", {"mono": True}),
               ("Serial", b.get("serial") or "--", {"mono": True}), ("Wear per year", wpy_txt, {"mono": isinstance(wpy, (int, float))})])
        p.add(g)
        return p

    @staticmethod
    def _live_text(b):
        parts = []
        if b.get("online"):
            parts.append("Plugged in" + (", charging" if b.get("charging") else ""))
        else:
            parts.append("On battery")
        w = b.get("watts")
        if isinstance(w, (int, float)) and w:
            parts.append("%s %.1f W" % ("charging at" if w > 0 else "using", abs(w)))
        rm = b.get("runtime_min")
        if isinstance(rm, (int, float)) and rm and not b.get("online"):
            parts.append("~%dh %02dm left" % (rm // 60, rm % 60))
        return "  ·  ".join(parts)

    def _history_panel(self):
        p = W.Panel("Capacity over time", "How much the battery can hold compared with new, from Windows' battery report. "
                                          "A steady slow slope is normal; a sudden drop means a problem.")
        pts = _hist_points((self.info or {}).get("history"))
        if len(pts) < 2:
            p.add(W.label(NO_HISTORY, "Muted", wrap=True))
            return p
        vals, when = _resample(pts)
        n = len(vals)
        xl = [""] * n
        for k in (0, n // 2, n - 1):
            d = when[k]
            xl[k] = (d if hasattr(d, "strftime") else _dt(d)).strftime("%d %b %Y")
        lo = max(0.0, min(v for _, v in pts) - 10)
        hi = max(100.0, max(v for _, v in pts) + 2)
        ch = W.LineChart(height=200, y_suffix="%")
        ch.mark_gaps = False
        ch.set([(vals, T.ACCENT, "Capacity")], xl, refs=[(80, T.WARN, "80%"), (50, T.CRIT, "50%")], top=hi, bottom=lo)
        p.add(ch)
        first, last = pts[0], pts[-1]
        note = W.label("%s: %.0f%%   ->   %s: %.0f%%   (%d readings)" % (first[0].strftime("%d %b %Y"), first[1], last[0].strftime("%d %b %Y"),
                                                                    last[1], len(pts)), "Body", wrap=True, sel=True)
        note.setStyleSheet("font-family:'%s'; font-size:11px;" % T.FONT_MONO)
        p.add(note)
        return p

    # ------------------------------------------------------------------ live (QTimer, only while visible)
    def _update_live(self):
        t, b = self.live_tile, getattr(self, "live_bat", None)
        if t is None or b is None:
            return
        c = b.get("charge")
        t.set("%s%%" % c if c is not None else "--", self._live_text(b))
        if isinstance(c, (int, float)):
            self.live_meter.set(c / 100.0, T.CRIT if c < 10 else T.WARN if c < 20 else T.OK)

    def _start_live(self):
        if self.info and self.info.get("present") and self.info.get("batteries"):
            if not self.timer.isActive():
                self.timer.start()
            self._tick()

    def _tick(self):
        if not self.isVisible():
            self.timer.stop()
            return
        info = self.info
        try:
            if not (info and info.get("present") and info.get("batteries")):
                return
            b = info["batteries"][0]
            ls = bt.live_status()          # GetSystemPowerStatus: instant
            if ls:
                b["online"], b["charge"] = ls[0], ls[1] if ls[1] is not None else b.get("charge")
                if ls[2]:
                    b["runtime_min"] = ls[2] // 60
            if time.time() - self._last_live_ps > 15 and not self._live_busy:
                self._last_live_ps = time.time()
                self._live_busy = True
                tasks.run_task(self._live_ps, lambda r: self._apply_live(info, r), lambda m: self._apply_live(info, None), name="battery-live")
            self._update_live()
        except (AttributeError, IndexError, KeyError, TypeError, RuntimeError):
            pass
        except Exception as e:          # never let the live loop die
            core.log_error("battery live tick", e)

    @staticmethod
    def _live_ps():
        """Worker thread: only reads PowerShell; the result is applied on the GUI thread."""
        try:
            r = bt.ps_clean(core.run_ps_json(bt.LIVE_PS, 30, "Battery live", track=False))
            st = [x for x in bt._l(r.get("status") if isinstance(r, dict) else None) if isinstance(x, dict)]
            if not st:
                return None
            return bt.watts_of(st[0]), st[0].get("charging") is True
        except Exception as e:
            core.log_error("battery live", e)
            return None

    def _apply_live(self, info, r):
        self._live_busy = False
        if r and self.info is info and info.get("batteries"):
            b = info["batteries"][0]
            b["watts"], b["charging"] = r
            self._update_live()

    def on_show(self):
        self._start_live()

    def on_hide(self):
        self.timer.stop()

    def shutdown(self):
        self.timer.stop()


def _dt(ts):
    from datetime import datetime
    return datetime.fromtimestamp(ts)
