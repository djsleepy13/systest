"""Network Tools page (Qt port of net_ui.py): live ping monitor, speed test, DNS benchmark / hijack check, public IP, traceroute,
MTU, outgoing port check, Wi-Fi analyzer, adapters, listening ports & firewall review, local network map, shares/time sync and
network fixes measured before and after.

Threading: every tool runs through tasks.run_task (QThread worker). The live monitor is netdiag.LiveMonitor (its own pinging
thread); the page only polls it with a QTimer, which is stopped (and the monitor paused) whenever the page is hidden."""
import html
import ipaddress
import threading
import time

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QComboBox, QGridLayout, QHBoxLayout, QLineEdit, QProgressBar, QSizePolicy, QTabWidget, QVBoxLayout,
                               QWidget)

import appsettings as S
import core
import netdiag as nd
from .. import theme as T
from .. import widgets as W
from ..tasks import run_task

TABS = ["Connection", "Speed & DNS", "Route & ports", "Wi-Fi", "Adapters", "Ports & firewall", "Local network", "Fixes"]
SCOL = {"OK": T.OK, "WARNING": T.WARN, "CRITICAL": T.CRIT, "INFO": T.INFO, "REVIEW": T.REVIEW}
CHAN_IDLE = "#3A4048"          # channel bars that are neither yours nor the quietest


# ---------------------------------------------------------------------------------
#  small private helpers (mono text must be set through a style sheet - the app QSS overrides setFont())
# ---------------------------------------------------------------------------------
def _m(text):
    """Inline mono span for rich-text labels (IPs, ms, numbers)."""
    return "<span style=\"font-family:'%s';\">%s</span>" % (T.FONT_MONO, html.escape(str(text)))


def _e(text):
    return html.escape(str(text))


def _rich(role="Body", wrap=True):
    lb = W.label("", role, wrap=wrap, sel=True)
    lb.setTextFormat(Qt.RichText)
    return lb


def _set_color(lbl, color=None):
    lbl.setStyleSheet("color:%s;" % color if color else "")


def _num(v):
    return ("%.0f" % v) if v >= 10 else "%.1f" % v


def _progress():
    b = QProgressBar()
    b.setRange(0, 1000)
    b.setValue(0)
    b.setTextVisible(False)
    return b


def _row(*items, spacing=T.S2):
    """Horizontal row; items are widgets, 'stretch', or (widget, stretch)."""
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(spacing)
    for it in items:
        if it == "stretch":
            h.addStretch(1)
        elif isinstance(it, tuple):
            h.addWidget(it[0], it[1])
        elif it is not None:
            h.addWidget(it)
    return w


class _Table(W.DataTable):
    """DataTable whose height also makes room for the horizontal scroll bar when the columns are wider than the view
    (otherwise the last row hides behind it and a vertical scroll bar appears for a 3-row table)."""

    def _fit(self):
        super()._fit()
        if self.horizontalHeader().length() > self.width() - 4:
            self.setFixedHeight(self.height() + max(10, self.horizontalScrollBar().sizeHint().height()))

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._fit()


class NetToolsPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.info = None
        self.mon = None
        self.busy = {}
        self.cancels = {}
        self._gen = {}
        self._btn_state = {}
        self.fix_log = []
        self.wifi = None
        self.last_speed = None
        self.pc_hist = []
        self._loaded = False
        self._closed = False
        self._mon_paused = False
        self._user_paused = False
        self._pending_fix = None
        self._rendered = None
        self._tasks = []

        self.m_timer = QTimer(self)
        self.m_timer.setInterval(1000)
        self.m_timer.timeout.connect(self._mon_tick)
        self.resume_timer = QTimer(self)                 # debounces monitor restarts while the user flips through pages
        self.resume_timer.setSingleShot(True)
        self.resume_timer.setInterval(300)
        self.resume_timer.timeout.connect(self._resume_monitor)

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        self.lbl = _rich("Body")
        self.lbl.setText("Reading network settings...")
        bar.addWidget(self.lbl, 1)
        self.btn_refresh = W.button("Refresh", self.load, icon="refresh")
        bar.addWidget(self.btn_refresh, 0, Qt.AlignTop)
        v.addLayout(bar)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        v.addWidget(self.tabs, 1)
        self.tf = {}
        for t in TABS:
            sp = W.ScrollPage()
            self.tabs.addTab(sp, t.replace("&", "&&"))      # '&' would become a keyboard mnemonic
            self.tf[t] = sp
        self._build_connection()
        self._build_speed()
        self._build_route()
        self._build_wifi()
        self._build_adapters()
        self._build_ports()
        self._build_lan()
        self._build_fixes()
        for sp in self.tf.values():
            sp.finish()
        self.tabs.currentChanged.connect(self._tab_changed)

    # ------------------------------------------------------------------ page hooks
    def on_show(self):
        if self._closed:
            return
        self._pub_state()
        if not self._loaded:
            self._loaded = True
            self.load()
        elif self.info and self._mon_paused and not self._user_paused:
            self.resume_timer.start()

    def on_hide(self):
        self.resume_timer.stop()
        self.m_timer.stop()
        if self.mon and not self.mon.stop.is_set():
            self.mon.stop.set()             # don't ping in the background while another page is open
            self._mon_paused = True

    def shutdown(self):
        self._closed = True
        self.resume_timer.stop()
        self.m_timer.stop()
        for ev in list(self.cancels.values()):
            ev.set()
        # tasks.run_task quits a worker's QThread through a queued call on the GUI thread; MainWindow.closeEvent blocks that thread
        # in tasks.shutdown() -> a finished worker would never quit and the wait times out. QThread.quit() is thread-safe, so ask
        # each of our threads to end as soon as its function returns (results are ignored now that _closed is set).
        for t in self._tasks:
            try:
                t.thread.quit()
            except RuntimeError:            # already deleted
                pass
        mon, self.mon = self.mon, None
        if mon:
            mon.stop.set()
            try:
                mon.t.join(1.5)
            except Exception:
                pass

    def open_tab(self, name):
        for i in range(self.tabs.count()):
            if TABS[i].lower() == str(name).lower():
                self.tabs.setCurrentIndex(i)
                return True
        return False

    def _tab_changed(self, i):
        t = TABS[i] if 0 <= i < len(TABS) else ""
        if t == "Wi-Fi" and self.wifi is None and not self.busy.get("wifi"):
            self.scan_wifi()
        elif t == "Connection":
            self._mon_tick()

    def render(self):
        info = self.info
        if info is None or info is self._rendered:
            return
        self._rendered = info
        gw, dns, ip, ad = self._gw_dns()
        self.lbl.setText("%s  ·  %s  ·  gateway %s  ·  DNS %s" % (
            _e(ip.get("alias") or "No connection"), _m(ip.get("ipv4")) if ip.get("ipv4") else "no address",
            _m(gw) if gw else "none", _m(", ".join(dns[:2])) if dns else "none"))
        self.c_kv.set([("Connection", ip.get("alias")), ("Type", "Wi-Fi" if nd.is_wifi(ad) else ("Ethernet" if ad else "--")),
                       ("IP address", "%s/%s" % (ip.get("ipv4"), ip.get("prefix")) if ip.get("ipv4") else None, {"mono": True}),
                       ("Router (gateway)", gw, {"mono": True}), ("DNS servers", ", ".join(dns[:2]), {"mono": True}),
                       ("Address from", "router (DHCP)" if ip.get("dhcp") == "Enabled" else "fixed (manual)" if ip else None),
                       ("Link speed", ad.get("speed"), {"mono": True}), ("Adapter", (ad.get("desc") or "")[:40])], 4)
        self.c_find.set(nd.adapter_findings(info), "No problems found in the adapter settings.")
        self._fill_adapters()
        names = [a["name"] for a in info.get("adapters", []) if a.get("hw") or a.get("status") == "Up"] or ["(none)"]
        keep = self.fix_adapter.currentText()
        self.fix_adapter.blockSignals(True)
        self.fix_adapter.clear()
        self.fix_adapter.addItems(names)
        want = keep if keep in names else (ip.get("alias") if ip.get("alias") in names else names[0])
        self.fix_adapter.setCurrentIndex(names.index(want))
        self.fix_adapter.blockSignals(False)

    # ------------------------------------------------------------------ background helper
    def _bg(self, key, work, done, btn=None, text=None, stop_btn=None, progress=None, cancel=None):
        """Run work() in a worker; done(result) on the GUI thread. Exceptions become {"error": text} (like the old page).
        progress(obj) runs on the GUI thread for each work(progress)-reported value. cancel = threading.Event for Stop."""
        if self._closed or self.busy.get(key):
            return False
        self.busy[key] = True
        gen = self._gen[key] = self._gen.get(key, 0) + 1
        if cancel is not None:
            self.cancels[key] = cancel
        self._btn_state[key] = (btn, btn.text() if btn else None, stop_btn)
        if btn:
            btn.setEnabled(False)
            btn.setText(text or "Working...")
        if stop_btn:
            stop_btn.setEnabled(True)
            stop_btn.setVisible(True)

        def fin(res):
            if self._closed or self._gen.get(key) != gen:
                return                                  # abandoned (Stop) or page closing
            self._release(key)
            try:
                done(res)
            except Exception as e:
                core.log_error("nettools.%s (show result)" % key, e)
                self.app.set_status("Couldn't show the result: %s" % core.friendly_error(e), "WARNING", hold=5)

        def prog(v):
            if not self._closed and self._gen.get(key) == gen and progress:
                progress(v)

        def fn(progress=None):
            try:
                return work(progress) if progress is not None else work()
            except Exception as e:
                core.log_error("nettools.%s" % key, e)
                return {"error": core.friendly_error(e)}
        task = run_task(fn, fin, lambda msg: fin({"error": msg}), on_progress=prog if progress else None, name="nettools-" + key)
        self._tasks = [t for t in self._tasks if t.running()] + [task]
        return True

    def _release(self, key):
        self.busy[key] = False
        self.cancels.pop(key, None)
        btn, old, stop_btn = self._btn_state.pop(key, (None, None, None))
        if btn is not None:
            btn.setEnabled(True)
            btn.setText(old)
        if stop_btn is not None:
            stop_btn.setVisible(False)

    def _stop(self, key):
        """Stop button: tools with a cancel flag finish early (partial result); others are abandoned (result ignored)."""
        ev = self.cancels.get(key)
        btn = self._btn_state.get(key, (None, None, None))[2]
        if btn is not None:
            btn.setEnabled(False)
        if ev is not None:
            ev.set()
            return False
        if self.busy.get(key):
            self._gen[key] = self._gen.get(key, 0) + 1
            self._release(key)
            return True
        return False

    def _need_admin(self):
        if not self.app.is_admin:
            W.info(self, "This needs WinDiag to run as administrator.")
            return True
        return False

    def _gw_dns(self):
        ip, ad = nd.primary(self.info or {})
        return ip.get("gateway") or None, ip.get("dns") or [], ip, ad

    def _show_table(self, t, ph, rows, tags=None):
        t.set_rows(rows, tags)
        t.setVisible(bool(rows))
        if ph is not None:
            ph.setVisible(not rows)

    def _table(self, cols, widths, mono=(), on_open=None, rows=8):
        t = _Table(cols, widths, on_open=on_open, mono=mono, max_rows_visible=rows)
        t.setVisible(False)
        return t

    # ------------------------------------------------------------------ load
    def load(self):
        self.lbl.setText("Reading network settings...")
        self._bg("load", nd.net_info, self._loaded_info, self.btn_refresh, "Reading...")

    def _loaded_info(self, info):
        info = info if isinstance(info, dict) else {}
        if (info.get("status") == "error" or info.get("error")) and not info.get("adapters"):
            self.lbl.setText(_e("Couldn't read network settings: %s" % nd._s(info.get("detail") or info.get("error"))[:120]))
            self.m_verdict.setText("Couldn't read the network settings - press Refresh to try again.")
            return
        self.info = info
        self.request_render()
        gw = self._gw_dns()[0]
        if self.mon and not self.mon.stop.is_set() and self.mon.gw == gw:
            pass                                    # same router - keep the monitor and its 2-minute history
        elif self.isVisible() and not self._user_paused:
            self._start_monitor()
        else:
            self._stop_monitor()
            self._mon_paused = not self._user_paused
        pend = self._pending_fix
        if pend:
            self._pending_fix = None
            QTimer.singleShot(200, lambda: None if self._closed else self.run_fix(*pend))

    # ------------------------------------------------------------------ Connection
    def _build_connection(self):
        sp = self.tf["Connection"]
        p = W.Panel("This connection")
        self.c_kv = W.KeyValueGrid(cols=4)
        self.c_kv.set([("Connection", None)], 4)
        p.add(self.c_kv)
        self.c_find = W.FindingsList()
        p.add(self.c_find)
        sp.add(p)

        self.btn_mon = W.button("Pause", self._toggle_monitor, icon="activity")
        p = W.Panel("Live ping monitor", "Pings your router and the internet (1.1.1.1) every second. If the router line fails the problem is in your home "
                                         "(Wi-Fi, cable, router); if only the internet line fails it's the modem or your provider.", actions=[self.btn_mon])
        tw = QWidget()
        g = QGridLayout(tw)
        g.setContentsMargins(0, 0, 0, 0)
        g.setHorizontalSpacing(T.S3)
        self.m_tiles = {}
        for i, (k, lab, col) in enumerate([("r", "Router", T.OK), ("i", "Internet", T.ACCENT)]):
            t = W.StatTile(lab, "--", "")
            t.lbl.setTextFormat(Qt.RichText)
            t.lbl.setText('<span style="color:%s">●</span>&nbsp;&nbsp;%s' % (col, lab))
            self.m_tiles[k] = t
            g.addWidget(t, 0, i)
            g.setColumnStretch(i, 1)
        p.add(tw)
        p.add(_row(W.Dot(T.OK, "Router", 11), W.Dot(T.ACCENT, "Internet", 11), W.label("ms, one ping per second, last 2 minutes", "Muted"), "stretch",
                   W.colored("red ticks = lost packets", T.CRIT, 11, wrap=False),
                   spacing=T.S4))
        self.m_chart = W.LineChart(height=170, min_top=20.0)
        p.add(self.m_chart)
        self.m_verdict = W.label("Starts when the network settings are loaded.", "Body", wrap=True, sel=True)
        p.add(self.m_verdict)
        sp.add(p)

    def _set_tile_sub(self, t, text):
        t.sub.setText(text)

    def _start_monitor(self):
        self._stop_monitor()
        if self._closed:
            return
        gw, _, _, _ = self._gw_dns()
        self.mon = nd.LiveMonitor(gw)
        self._mon_paused = False
        self.btn_mon.setText("Pause")
        self.m_timer.start()
        QTimer.singleShot(150, self._mon_tick)

    def _stop_monitor(self):
        self.m_timer.stop()
        if self.mon:
            self.mon.stop.set()

    def _resume_monitor(self):
        if not self._closed and self.isVisible() and self.info and self._mon_paused and not self._user_paused:
            self._start_monitor()

    def _toggle_monitor(self):
        if self.mon and not self.mon.stop.is_set():
            self._stop_monitor()
            self._user_paused = True
            self.btn_mon.setText("Resume")
        elif self.info:
            self._user_paused = False
            self._start_monitor()

    def _mon_tick(self):
        mon = self.mon
        if self._closed or not mon or not self.isVisible():
            return
        if self.tabs.currentIndex() != 0:                       # only draw while the Connection tab is open
            return
        rs, ist, rr, ii = mon.read()
        for k, st in (("r", rs), ("i", ist)):
            t = self.m_tiles[k]
            if k == "r" and not mon.gw:
                t.val.setText("no router")
                _set_color(t.val, T.TEXT2)
                self._set_tile_sub(t, "No default gateway on this connection.")
                continue
            bad = st["n"] >= nd.MIN_SAMPLES and st.get("lost", 0) >= nd.MIN_LOST
            t.val.setText(("%s ms" % st["avg"]) if st["avg"] is not None else ("no reply" if st["n"] else "--"))
            _set_color(t.val, T.CRIT if bad and st["loss"] >= 20 else (T.WARN if bad and st["loss"] >= 5 else None))
            self._set_tile_sub(t, "jitter %s ms  ·  loss %.0f%%  ·  max %s ms  ·  %d samples" % (
                st["jitter"] if st["jitter"] is not None else "--", st["loss"], st["max"] if st["max"] is not None else "--", st["n"]))
        stt, txt = nd.monitor_verdict(rs, ist, bool(mon.gw))
        router_quiet = stt == "INFO" and mon.gw and rs["n"] and rs["avg"] is None       # router ignores ping - not an error colour
        if router_quiet:
            self.m_tiles["r"].val.setText("no ping reply")
            _set_color(self.m_tiles["r"].val, T.TEXT2)
        self.m_verdict.setText(txt)
        _set_color(self.m_verdict, SCOL.get(stt) if stt not in ("OK", "INFO") else None)
        series = []
        if mon.gw and not router_quiet:
            series.append((rr, T.OK, "Router"))
        series.append((ii, T.ACCENT, "Internet"))
        n = max(len(rr), len(ii))
        if n >= 2:
            span = "-2 min" if n >= nd.LiveMonitor.KEEP else "-%d s" % n
            xl = [span, "now"]
        else:
            xl = []
        self.m_chart.set(series, xl)

    # ------------------------------------------------------------------ Speed & DNS
    def _build_speed(self):
        sp = self.tf["Speed & DNS"]
        self.btn_speed = W.button("Run speed test", self.run_speed, "primary", icon="gauge")
        self.btn_speed_stop = W.button("Stop", lambda: self._stop("speed"), "stop", icon="stop")
        self.btn_speed_stop.setVisible(False)
        p = W.Panel("Speed test", "Downloads and uploads test data to Cloudflare's speed-test servers (speed.cloudflare.com) - about 50-200 MB. "
                                  "For a fair result, pause downloads and streaming on other devices.", actions=[self.btn_speed_stop, self.btn_speed])
        tw = QWidget()
        g = QGridLayout(tw)
        g.setContentsMargins(0, 0, 0, 0)
        g.setHorizontalSpacing(T.S3)
        self.sp = {}
        for i, (k, lab, unit) in enumerate([("down", "Download", "Mbps"), ("up", "Upload", "Mbps"), ("ping", "Latency", "ms"), ("jitter", "Jitter", "ms")]):
            t = W.StatTile(lab, "--", unit)
            self.sp[k] = t
            g.addWidget(t, 0, i)
            g.setColumnStretch(i, 1)
        p.add(tw)
        self.sp_bar = _progress()
        p.add(self.sp_bar)
        self.sp_tips = W.FindingsList()
        p.add(self.sp_tips)
        sp.add(p)

        self.btn_dnsb = W.button("Run benchmark", self.run_dnsbench, icon="play")
        self.btn_dnsb_stop = W.button("Stop", lambda: self._stop("dnsb"), "stop", icon="stop")
        self.btn_dnsb_stop.setVisible(False)
        p = W.Panel("DNS benchmark", "Times how fast each DNS server answers 10 popular names (asked twice: first and cached). DNS speed affects how fast "
                                     "pages START loading, not download speed.", actions=[self.btn_dnsb_stop, self.btn_dnsb])
        self.dnsb_bar = _progress()
        self.dnsb_bar.setVisible(False)
        p.add(self.dnsb_bar)
        self.t_dns = self._table(["Server", "IP", "Median ms", "Failed", "Note"], [220, 150, 110, 90, 400], mono=("IP", "Median ms", "Failed"), rows=6)
        self.t_dns_ph = W.label("Not run yet.", "Muted")
        p.add(self.t_dns_ph)
        p.add(self.t_dns)
        self.dns_note = W.label("", "Body", wrap=True, sel=True)
        p.add(self.dns_note)
        sp.add(p)

        self.btn_hij = W.button("Check DNS", self.run_hijack, icon="search")
        p = W.Panel("DNS hijack check", "Asks your DNS for a name that doesn't exist and for a name with a known address. Honest DNS says "
                                        "'no such name' and returns the right address.", actions=[self.btn_hij])
        self.hij = W.FindingsList((), "Not checked yet.")
        p.add(self.hij)
        sp.add(p)

        self.btn_pub = W.button("Show public IP", self.run_public, icon="cloud")
        p = W.Panel("Public IP address", "The address websites see. Asks Cloudflare (1.1.1.1/cdn-cgi/trace).", actions=[self.btn_pub])
        self.pub = _rich("Body")
        p.add(self.pub)
        sp.add(p)

    def _pub_state(self):
        on = bool(S.get("public_ip"))
        if not self.busy.get("pub"):
            self.btn_pub.setEnabled(on)
        if not on:
            self.pub.setText("Off - turn on 'Allow public IP lookup' in Settings (it contacts an outside server).")
            _set_color(self.pub)
        elif self.pub.text().startswith("Off - "):
            self.pub.setText("")

    def run_speed(self):
        for t in self.sp.values():
            t.set("--")
        self.sp_bar.setValue(0)
        self.sp_tips.set([])
        phase_w = {"ping": (0, 0.1), "down": (0.1, 0.55), "up": (0.55, 0.45)}
        ev = threading.Event()

        def on_prog(v):
            phase, val, frac = v
            a, b = phase_w.get(phase, (0, 0))
            if phase in self.sp and isinstance(val, (int, float)):
                self.sp[phase].set(_num(val))
            self.sp_bar.setValue(int(1000 * min(1.0, a + b * frac)))

        def work(progress):
            return nd.speed_test(lambda phase, val, frac: progress((phase, val, frac)), cancel=ev)
        self._bg("speed", work, self._speed_done, self.btn_speed, "Testing...", self.btn_speed_stop, progress=on_prog, cancel=ev)

    def _speed_done(self, r):
        r = r if isinstance(r, dict) else {"error": "No result"}
        self.sp_bar.setValue(1000)
        for k, t in self.sp.items():
            if isinstance(r.get(k), (int, float)):
                t.set(_num(r[k]))
        items = []
        if r.get("error") == "Stopped":
            self.sp_tips.set([("INFO", "Speed test stopped", "Run it again for a full result.")])
            self.app.set_status("Speed test stopped.")
            return
        if r.get("error"):
            items.append(("CRITICAL", "Speed test failed", r["error"]))
        if r.get("up_error"):
            items.append(("WARNING", "Upload test failed", r["up_error"]))
        cur = (self.wifi or {}).get("current")
        for t in nd.speed_advice(r, cur):
            items.append(("INFO", t, ""))
        self.sp_tips.set(items)
        self.last_speed = r
        self.app.set_status("Speed test: %s Mbps down, %s Mbps up, %s ms." % (r.get("down", "--"), r.get("up", "--"), r.get("ping", "--")), hold=5)

    def run_dnsbench(self):
        _, dns, _, _ = self._gw_dns()
        dns = [d for d in dns if ":" not in d]
        ev = threading.Event()
        self.dnsb_bar.setValue(0)
        self.dnsb_bar.setVisible(True)
        self.dns_note.setText("Asking each server 20 times...")

        def on_prog(v):
            a, b = v
            self.dnsb_bar.setValue(int(1000 * a / float(max(1, b))))

        def work(progress):
            return nd.dns_benchmark(dns, progress=lambda a, b: progress((a, b)), cancel=ev)
        self._bg("dnsb", work, lambda rows: self._dnsb_done(rows, ev.is_set()), self.btn_dnsb, "Testing...", self.btn_dnsb_stop,
                 progress=on_prog, cancel=ev)

    def _dnsb_done(self, rows, stopped=False):
        self.dnsb_bar.setVisible(False)
        if isinstance(rows, dict):
            self.dns_note.setText(rows.get("error", ""))
            return
        rows = list(rows or [])
        best = rows[0] if rows else None
        if best and best["fails"] > best.get("queries", 20) // 2:
            best = None
        out = []
        for r in rows:
            note = "your current DNS" if r["current"] else ""
            if r is best and r["median"] is not None:
                note = (note + " - " if note else "") + "fastest"
            if r["fails"]:
                note += (" - " if note else "") + ("%d of %d failed" % (r["fails"], r["queries"]) if r.get("queries") else "%d failed" % r["fails"]) + \
                    ((" (%s)" % ", ".join(r["errors"])) if r.get("errors") else "")
            out.append({"Server": r["name"], "IP": r["ip"], "Median ms": r["median"] if r["median"] is not None else "no answer", "Failed": r["fails"], "Note": note})
        self._show_table(self.t_dns, self.t_dns_ph, out, ["WARNING" if r["fails"] > 2 else None for r in rows])
        pre = "Stopped - partial results. " if stopped else ""
        if not rows:
            self.dns_note.setText("Stopped before any server was tested." if stopped else "No DNS server answered reliably - check the connection.")
            return
        if best is None:
            self.dns_note.setText(pre + "No DNS server answered reliably - check the connection.")
            return
        cur = [r for r in rows if r["current"] and r["median"] is not None]
        if best["median"] is None:
            self.dns_note.setText(pre + "No DNS server answered - check the connection.")
        elif cur and not best["current"] and cur[0]["median"] - best["median"] > 15:
            self.dns_note.setText(pre + "%s answers %.0f ms faster than your DNS. You can switch in the Fixes tab (undo any time with 'DNS back to automatic')." % (
                best["name"], cur[0]["median"] - best["median"]))
        else:
            self.dns_note.setText(pre + "Your DNS is about as fast as the public ones - no need to change it.")

    def run_hijack(self):
        _, dns, _, _ = self._gw_dns()
        dns = [d for d in dns if ":" not in d]
        self._bg("hij", lambda: nd.hijack_check(dns),
                 lambda items: self.hij.set(items if isinstance(items, list) else [("WARNING", "Check failed", (items or {}).get("error"))],
                                            "No DNS servers configured."), self.btn_hij, "Checking...")

    def run_public(self):
        if not S.get("public_ip"):
            return self._pub_state()

        def done(r):
            r = r if isinstance(r, dict) else {}
            if r.get("ip"):
                self.pub.setText("Public IP %s  ·  country %s  ·  Cloudflare location %s%s" % (
                    _m(r.get("ip")), _e(r.get("loc")), _m(r.get("colo")), "  ·  WARP/VPN on" if r.get("warp") == "on" else ""))
            else:
                self.pub.setText(_e("Couldn't reach Cloudflare: %s" % r.get("error")))
            _set_color(self.pub, T.TEXT)
        self._bg("pub", nd.public_ip, done, self.btn_pub, "Asking...")

    # ------------------------------------------------------------------ Route & ports
    def _build_route(self):
        sp = self.tf["Route & ports"]
        self.tr_host = QLineEdit("1.1.1.1")
        self.tr_host.setPlaceholderText("host name or IP")
        self.tr_host.setMinimumWidth(160)
        self.tr_host.returnPressed.connect(self.run_trace)
        self.btn_tr = W.button("Trace", self.run_trace, icon="play")
        self.btn_tr_stop = W.button("Stop", lambda: self._stop_trace(), "stop", icon="stop")
        self.btn_tr_stop.setVisible(False)
        p = W.Panel("Traceroute", "Shows every router between this PC and a server, and how long each takes to answer.",
                    actions=[self.tr_host, self.btn_tr_stop, self.btn_tr])
        self.t_tr = self._table(["Hop", "Address", "Avg ms", "Replies", "Note"], [70, 200, 100, 200, 400], mono=("Hop", "Address", "Avg ms", "Replies"), rows=12)
        self.t_tr_ph = W.label("Not run yet.", "Muted")
        p.add(self.t_tr_ph)
        p.add(self.t_tr)
        self.tr_note = W.label("", "Body", wrap=True, sel=True)
        p.add(self.tr_note)
        sp.add(p)

        self.btn_mtu = W.button("Check MTU", self.run_mtu, icon="play")
        p = W.Panel("MTU check", "Finds the largest packet that gets through without being split. A wrong MTU makes some websites or VPNs hang.",
                    actions=[self.btn_mtu])
        self.mtu = _rich("Body")
        self.mtu.setText("Not checked yet.")
        p.add(self.mtu)
        sp.add(p)

        p = W.Panel("Port check (outgoing)", "Tests whether this PC can open a connection to a server's port - e.g. can it reach the mail server? "
                                             "It does not test ports on this PC from outside.")
        self.pc_preset = QComboBox()
        self.pc_preset.addItems(["Custom..."] + [x[0] for x in nd.PORT_PRESETS])
        self.pc_preset.setMinimumWidth(180)
        self.pc_preset.activated.connect(lambda i: self._preset(self.pc_preset.itemText(i)))
        self.pc_host = QLineEdit()
        self.pc_host.setPlaceholderText("host name or IP")
        self.pc_host.setMinimumWidth(160)
        self.pc_host.returnPressed.connect(self.run_port)
        self.pc_port = QLineEdit()
        self.pc_port.setPlaceholderText("port")
        self.pc_port.setMinimumWidth(70)
        self.pc_port.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.pc_port.returnPressed.connect(self.run_port)
        for e in (self.tr_host, self.pc_host, self.pc_port):
            e.setStyleSheet("font-family:'%s';" % T.FONT_MONO)
        self.btn_pc = W.button("Check", self.run_port, icon="play")
        p.add(_row(self.pc_preset, (self.pc_host, 3), (self.pc_port, 1), self.btn_pc))
        self.pc_res = W.FindingsList()
        p.add(self.pc_res)
        sp.add(p)

    def _preset(self, v):
        for name, host, port in nd.PORT_PRESETS:
            if name == v:
                self.pc_host.setText(host)
                self.pc_port.setText(str(port))

    def run_trace(self):
        if self.busy.get("tr"):
            return
        host = self.tr_host.text().strip() or "1.1.1.1"
        self.tr_note.setText("Tracing (up to a minute)...")
        self._bg("tr", lambda: nd.traceroute(host), self._trace_done, self.btn_tr, "Tracing...", self.btn_tr_stop)

    def _stop_trace(self):
        if self._stop("tr"):
            self.tr_note.setText("Stopped.")

    def _trace_done(self, r):
        r = r if isinstance(r, dict) else {}
        if r.get("error"):
            self.tr_note.setText(r["error"])
            return
        hops = r.get("hops") or []
        _, _, ip, _ = self._gw_dns()
        rows = []
        for h in hops:
            note = "your router" if h["ip"] and h["ip"] == ip.get("gateway") else ("no reply (many routers ignore traceroute)" if h["timeout"] else "")
            rows.append({"Hop": h["hop"], "Address": h["ip"] or "*", "Avg ms": h["avg"] if h["avg"] is not None else "--",
                         "Replies": "  ".join("*" if t is None else ("<1" if t <= 1 else "%.0f" % t) for t in h["times"]), "Note": note})
        self._show_table(self.t_tr, self.t_tr_ph, rows)
        self.tr_note.setText(nd.trace_advice(hops))

    def run_mtu(self):
        self.mtu.setText("Testing packet sizes...")

        def done(r):
            r = r if isinstance(r, dict) else {}
            self.mtu.setText(("MTU %s  -  %s" % (_m(r["mtu"]), _e(r["note"]))) if r.get("mtu") else _e(r.get("error") or "Couldn't measure."))
        self._bg("mtu", nd.mtu_check, done, self.btn_mtu, "Testing...")

    def run_port(self):
        host, port = self.pc_host.text().strip(), self.pc_port.text().strip()
        if not host or not port.isdigit():
            W.info(self, "Enter a host name or IP and a port number.")
            return

        def done(r):
            r = r if isinstance(r, dict) else {}
            self.pc_hist.insert(0, ("OK" if r.get("ok") else "WARNING", "%s port %s" % (host, port), r.get("detail") or r.get("error") or ""))
            self.pc_res.set(self.pc_hist[:6])
        self._bg("pc", lambda: nd.port_check(host, int(port)), done, self.btn_pc, "...")

    # ------------------------------------------------------------------ Wi-Fi
    def _build_wifi(self):
        sp = self.tf["Wi-Fi"]
        self.btn_wscan = W.button("Scan again", self.scan_wifi, icon="refresh")
        self.btn_wrep = W.button("WLAN report", self.wlan_report, icon="report")
        p = W.Panel("Your Wi-Fi connection", actions=[self.btn_wrep, self.btn_wscan])
        top = QWidget()
        h = QHBoxLayout(top)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(T.S5)
        self.w_ring = W.Ring(size=96, width=8)
        self.w_ring.set(None, T.MUTED, "signal")
        self.w_ring.setVisible(False)
        h.addWidget(self.w_ring, 0, Qt.AlignTop)
        kvw = QWidget()
        kvl = QVBoxLayout(kvw)
        kvl.setContentsMargins(0, 0, 0, 0)
        kvl.setSpacing(T.S2)
        self.w_kv = W.KeyValueGrid(cols=4)
        self.w_kv.set([("Wi-Fi", "Not scanned yet - open this tab or click Scan again.")], 1)
        kvl.addWidget(self.w_kv)
        self.w_raw = W.label("", "Muted", wrap=True, sel=True)
        self.w_raw.setStyleSheet("font-family:'%s'; font-size:11px;" % T.FONT_MONO)
        self.w_raw.setVisible(False)
        kvl.addWidget(self.w_raw)
        h.addWidget(kvw, 1)
        p.add(top)
        self.w_find = W.FindingsList()
        p.add(self.w_find)
        sp.add(p)

        p = W.Panel("Channel congestion", "How crowded each channel is with nearby networks (stronger networks count more). "
                                          "On 2.4 GHz only channels 1, 6 and 11 don't overlap.")
        self.w_band = W.label("", "SectionTitle")
        p.add(self.w_band)
        self.w_chart = W.BarChart(height=180)
        self.w_chart.set([], note="Scan to see channel congestion.")
        p.add(self.w_chart)
        self.w_adv = W.label("", "Body", wrap=True, sel=True)
        p.add(self.w_adv)
        sp.add(p)

        p = W.Panel("Nearby networks")
        self.t_wn = self._table(["Network", "Signal", "Band", "Channel", "Security", "Radio", "BSSID"], [240, 90, 90, 90, 160, 110, 180],
                                mono=("Signal", "Channel", "BSSID"), rows=12)
        self.t_wn_ph = W.label("Not scanned yet.", "Muted")
        p.add(self.t_wn_ph)
        p.add(self.t_wn)
        sp.add(p)

    def scan_wifi(self):
        self._bg("wifi", nd.wifi_scan, self._wifi_done, self.btn_wscan, "Scanning...")

    def _wifi_done(self, r):
        r = r if isinstance(r, dict) else {}
        ifs = r.get("interfaces") or []
        cur = next((i for i in ifs if i.get("connected")), None)
        r["current"] = cur
        self.wifi = r
        if not cur:
            self.w_ring.setVisible(False)
            self.w_kv.set([("Wi-Fi", "Not connected to Wi-Fi" if ifs else (r.get("error") or "No Wi-Fi adapter found"))], 1)
            raw = (r.get("raw") or "")[:300]
            self.w_raw.setText(raw)
            self.w_raw.setVisible(bool(raw))
        else:
            s = cur.get("signal") or 0
            col = T.OK if s >= 60 else (T.WARN if s >= 40 else T.CRIT)
            self.w_ring.set(s, col, "signal")
            self.w_ring.setVisible(True)
            self.w_raw.setVisible(False)
            self.w_kv.set([("Network", cur.get("ssid")), ("Band / channel", "%s  ·  ch %s" % (cur.get("band"), cur.get("channel_n")), {"mono": True}),
                           ("Standard", cur.get("radio type")), ("Security", cur.get("authentication")),
                           ("Receive rate", "%s Mbps" % cur.get("receive rate (mbps)") if cur.get("receive rate (mbps)") else None, {"mono": True}),
                           ("Send rate", "%s Mbps" % cur.get("transmit rate (mbps)") if cur.get("transmit rate (mbps)") else None, {"mono": True}),
                           ("Access point", cur.get("bssid"), {"mono": True}), ("Adapter", (cur.get("description") or "")[:34])], 4)
        self.w_find.set(nd.wifi_findings(cur))
        nets = r.get("networks") or []
        adv = nd.channel_advice(nets, cur)
        self.w_adv.setText(adv.get("text") or ("%d network(s) nearby." % len(nets)))
        self._draw_channels(nets, cur, adv)
        rows = sorted(nets, key=lambda n: -(n.get("signal") or 0))
        my = ((cur or {}).get("bssid") or "").lower()
        self._show_table(self.t_wn, self.t_wn_ph,
                         [{"Network": (n.get("ssid") or "") + ("  (you)" if cur and my and (n.get("bssid") or "").lower() == my else ""),
                           "Signal": "%d%%" % (n.get("signal") or 0), "Band": n.get("band"), "Channel": n.get("channel"), "Security": n.get("auth"),
                           "Radio": n.get("radio"), "BSSID": n.get("bssid")} for n in rows],
                         ["WARNING" if (n.get("auth") or "").lower() in ("open", "wep") else None for n in rows])
        if not rows:
            self.t_wn_ph.setText("No networks found.")

    def _draw_channels(self, nets, cur, adv):
        band5 = adv.get("band5")
        self.w_band.setText("")
        if adv.get("band6"):
            self.w_chart.set([], note="6 GHz: wide, non-overlapping channels - no congestion chart needed.")
            return
        if not cur:
            self.w_chart.set([], note="Connect to Wi-Fi to see channel congestion.")
            return
        chans = sorted({n["channel"] for n in nets if n.get("channel") and n.get("band") == "5 GHz"} | {cur.get("channel_n")}) if band5 else list(range(1, 14))
        chans = [c for c in chans if c]
        if not chans:
            self.w_chart.set([], note="No networks found on this band.")
            return
        load = adv.get("load") or {}
        top = max([load.get(c, 0) for c in chans] + [1.0])
        curc = cur.get("channel_n")
        items = [(str(c), load.get(c, 0), T.ACCENT if c == curc else (T.OK if c == adv.get("best") else CHAN_IDLE)) for c in chans]
        self.w_band.setText("5 GHz" if band5 else "2.4 GHz")
        self.w_chart.set(items, top=top * 1.08, note="blue = your channel   green = quietest")

    def wlan_report(self):
        if self._need_admin():
            return

        def done(r):
            r = r if isinstance(r, dict) else {}
            if r.get("path"):
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(r["path"])))
                self.app.set_status("WLAN report: %s" % r["path"], hold=8)
            else:
                W.info(self, "Windows didn't create a WLAN report (no Wi-Fi adapter, or the WLAN service is off).")
        self._bg("wrep", lambda: core.run_ps_json(nd.WLAN_REPORT_PS, 120, "WLAN report"), done, self.btn_wrep, "Creating...")

    # ------------------------------------------------------------------ Adapters
    def _build_adapters(self):
        sp = self.tf["Adapters"]
        p = W.Panel("Network adapters", "Errors and dropped packets count since the adapter was last started. Double-click a row for all details.")
        self.t_ad = _Table(["Adapter", "Status", "Speed", "Errors", "Dropped", "Power saving", "Driver", "Description"],
                                [170, 110, 110, 90, 90, 160, 190, 300], on_open=self._ad_detail, mono=("Speed", "Errors", "Dropped", "Driver"),
                                max_rows_visible=10)
        p.add(self.t_ad)
        self.ad_find = W.FindingsList((), "Loading...")
        p.add(self.ad_find)
        sp.add(p)

    def _fill_adapters(self):
        rows, tags = [], []
        for a in (self.info or {}).get("adapters", []):
            e = nd._i(a.get("rx_err")) + nd._i(a.get("tx_err"))
            d = nd._i(a.get("rx_drop")) + nd._i(a.get("tx_drop"))
            rows.append({"Adapter": a.get("name"), "Status": a.get("status"), "Speed": a.get("speed"), "Errors": e, "Dropped": d,
                         "Power saving": "Windows may turn off" if a.get("power_off_allowed") == "Enabled" else ("off" if a.get("power_off_allowed") else "--"),
                         "Driver": "%s  %s" % (a.get("driver") or "", (a.get("driver_date") or "")[:10]), "Description": a.get("desc"), "_a": a})
            tags.append("WARNING" if e > 100 else None)
        self.t_ad.set_rows(rows, tags)
        self.ad_find.set(nd.adapter_findings(self.info), "No adapter problems found.")

    def _ad_detail(self, row):
        a = row.get("_a") or {}
        self.app.text_popup("Adapter - %s" % a.get("name"), "\n".join("%-20s %s" % (k, v) for k, v in a.items()))

    # ------------------------------------------------------------------ Ports & firewall
    def _build_ports(self):
        sp = self.tf["Ports & firewall"]
        self.btn_ports = W.button("Load", self.load_ports, icon="refresh")
        p = W.Panel("Listening ports", "Programs waiting for incoming connections. 'all networks' means other devices can try to connect "
                                       "(if the firewall lets them). Remote-access ports you don't use are flagged.", actions=[self.btn_ports])
        self.t_listen = self._table(["Proto", "Port", "Address", "Program", "Service", "What", "Path"], [80, 80, 130, 160, 180, 220, 360],
                                    mono=("Port", "Address"), rows=10)
        self.t_listen_ph = W.label("Not loaded yet - click Load.", "Muted")
        p.add(self.t_listen_ph)
        p.add(self.t_listen)
        sp.add(p)
        p = W.Panel("Programs talking to the internet right now")
        self.t_est = self._table(["Program", "Connections", "Examples", "Service", "Path"], [180, 110, 380, 160, 300], mono=("Connections", "Examples"), rows=10)
        self.t_est_ph = W.label("Not loaded yet - click Load above.", "Muted")
        p.add(self.t_est_ph)
        p.add(self.t_est)
        sp.add(p)
        self.btn_fw = W.button("Review rules", self.load_fw, icon="shield")
        p = W.Panel("Firewall rule review", "Profiles, plus inbound 'Allow' rules that look risky: programs in user/temp folders, remote-access ports "
                                            "open to everyone on public networks, allow-everything rules. Built-in Windows rules without issues are hidden.",
                    actions=[self.btn_fw])
        self.fw_find = W.FindingsList((), "Not reviewed yet.")
        p.add(self.fw_find)
        self.t_fw = self._table(["Rule", "Profile", "Program", "Port", "From", "Why flagged"], [260, 110, 300, 110, 110, 360], mono=("Port", "From"), rows=12)
        p.add(self.t_fw)
        p.add(W.hbox(W.button("Open Windows Firewall (advanced)", lambda: self.app._tool("Windows Firewall", "wf.msc"), "ghost", icon="shield"), "stretch"))
        sp.add(p)

    def load_ports(self):
        def done(r):
            L, E = nd.ports_view(r if isinstance(r, dict) else {})
            self._show_table(self.t_listen, self.t_listen_ph, L, [x.get("_st") for x in L])
            self._show_table(self.t_est, self.t_est_ph, E)
            if not L:
                self.t_listen_ph.setText("No listening ports found." if not (r or {}).get("error") else "Couldn't read ports: %s" % r.get("error"))
            if not E:
                self.t_est_ph.setText("No programs are connected to the internet right now.")
        self._bg("ports", lambda: core.run_ps_json(nd.PORTS_PS, 90, "Listening ports"), done, self.btn_ports, "Loading...")

    def load_fw(self):
        def done(r):
            r = r if isinstance(r, dict) else {}
            F, rows = nd.firewall_view(r)
            prof = [nd._s(x) for x in nd._l(r.get("active_profile")) if nd._s(x)]
            if prof:
                F.insert(0, ("INFO", "Current network: " + "; ".join(prof), "Public = strict (cafés, hotels). Private = home/office where you trust other devices."))
            self.fw_find.set(F[:12], "No risky rules found.")
            self._show_table(self.t_fw, None, rows, [x.get("_st") for x in rows])
        self._bg("fw", lambda: core.run_ps_json(nd.FIREWALL_PS, 180, "Firewall rules"), done, self.btn_fw, "Reading rules...")

    # ------------------------------------------------------------------ Local network
    def _build_lan(self):
        sp = self.tf["Local network"]
        self.btn_lan = W.button("Map my network", self.map_lan, icon="network")
        self.btn_lan_stop = W.button("Stop", lambda: self._stop("lan"), "stop", icon="stop")
        self.btn_lan_stop.setVisible(False)
        p = W.Panel("Devices on your network", "Finds devices on THIS PC's own local network only (pings each address once, then reads Windows' "
                                               "neighbour table). Use it only on networks you own or manage.", actions=[self.btn_lan_stop, self.btn_lan])
        self.lan_bar = _progress()
        p.add(self.lan_bar)
        self.lan_note = W.label("", "Body", wrap=True, sel=True)
        p.add(self.lan_note)
        self.t_lan = self._table(["Address", "Name", "Role", "Ping ms", "MAC", "Note"], [140, 260, 130, 90, 170, 320], mono=("Address", "Ping ms", "MAC"), rows=12)
        self.t_lan_ph = W.label("Not mapped yet.", "Muted")
        p.add(self.t_lan_ph)
        p.add(self.t_lan)
        sp.add(p)
        self.btn_sh = W.button("Load", self.load_shares, icon="refresh")
        p = W.Panel("Shares, mapped drives and time sync", actions=[self.btn_sh])
        self.sh_find = W.FindingsList((), "Not loaded yet.")
        p.add(self.sh_find)
        self.btn_sync = W.button("Sync time now", self.sync_time, icon="refresh")
        self.btn_sync.setVisible(False)
        p.add(W.hbox(self.btn_sync, "stretch"))
        sp.add(p)

    def map_lan(self):
        self.lan_bar.setValue(0)
        self.lan_note.setText("Pinging your network...")
        ev = threading.Event()

        def on_prog(v):
            a, b = v
            self.lan_bar.setValue(int(1000 * a / float(max(1, b))))

        def work(progress):
            base = core.run_ps_json(nd.LAN_PS, 60, "Local network")
            if not base.get("ipv4"):
                return {"error": "No connected network (%s)." % (base.get("detail") or "")}
            if ev.is_set():
                return {"error": "Stopped."}
            sw = nd.lan_sweep(base, progress=lambda a, b: progress((a, b)), cancel=ev)
            if sw.get("error"):
                return sw
            if ev.is_set():
                return {"error": "Stopped."}
            nb = core.run_ps_json(nd.LAN_PS, 60, "Local network")
            ips = {nd._s(n.get("ip")): n for n in nd._dl(nb.get("neighbors")) if n.get("ip")}
            net = ipaddress.ip_network(sw["subnet"])

            def inside(i):
                try:
                    return ipaddress.ip_address(i) in net
                except ValueError:
                    return False
            allips = sorted(set([i for i in ips if inside(i)]) | set(sw["alive"]) | {base["ipv4"]}, key=lambda x: ipaddress.ip_address(x))
            names = nd.names_for(allips)
            return {"base": base, "sw": sw, "ips": ips, "all": allips, "names": names}

        def done(r):
            r = r if isinstance(r, dict) else {}
            self.lan_bar.setValue(1000)
            if r.get("error"):
                self.lan_note.setText(r["error"])
                return
            base, sw = r["base"], r["sw"]
            rows = []
            for ip in r["all"]:
                n = r["ips"].get(ip, {})
                role = "this PC" if ip == base["ipv4"] else ("router" if ip == base.get("gateway") else "")
                mac = base.get("mac") if role == "this PC" else n.get("mac", "")
                rows.append({"Address": ip, "Name": r["names"].get(ip, ""), "Role": role, "Ping ms": sw["alive"].get(ip, "--" if role != "this PC" else ""),
                             "MAC": mac, "Note": nd.mac_kind(mac or "") or ("doesn't answer ping (still seen on the network)" if ip not in sw["alive"] and not role else "")})
            self._show_table(self.t_lan, self.t_lan_ph, rows)
            self.lan_note.setText("%s%d device(s) found on %s. %s Unknown devices? Check the router's client list and change the Wi-Fi password if needed." % (
                "Stopped early - partial list. " if ev.is_set() else "", len(rows), sw["subnet"], sw.get("note") or ""))
        self._bg("lan", work, done, self.btn_lan, "Mapping...", self.btn_lan_stop, progress=on_prog, cancel=ev)

    def load_shares(self):
        def done(r):
            r = r if isinstance(r, dict) else {}
            self.btn_sync.setVisible(False)
            items = []
            if (r.get("status") == "error" or r.get("error")) and not r.get("w32"):
                self.sh_find.set([("WARNING", "Couldn't read shares and time sync", nd._s(r.get("detail") or r.get("error"))[:200])])
                return
            shares = [s for s in nd._dl(r.get("shares")) if not s.get("special")]
            items.append(("INFO" if shares else "OK", "Folders this PC shares: %d" % len(shares),
                          ", ".join("%s (%s)" % (nd._s(s.get("name")), nd._s(s.get("path"))) for s in shares[:6])))
            if r.get("smb1"):
                items.append(("WARNING", "SMB1 file sharing is ON", "An old, insecure protocol (used by WannaCry). Turn it off unless an old device needs it."))
            mp = nd._dl(r.get("mapped"))
            for m in mp:
                mst = nd._s(m.get("status"))
                items.append(("OK" if mst in ("OK", "0", "") else "WARNING", "Mapped drive %s -> %s" % (nd._s(m.get("local")), nd._s(m.get("remote"))),
                              "status: %s" % (mst or "OK")))
            if not mp:
                items.append(("OK", "No mapped network drives", ""))
            ses = [nd._s(x) for x in nd._l(r.get("sessions")) if nd._s(x)]
            if ses:
                items.append(("INFO", "Connected to this PC's shares right now", "; ".join(ses[:5])))
            tst, ttl, tdt, ok = nd.time_sync(r.get("w32"))
            items.append((tst, ttl, tdt))
            self.sh_find.set(items)
            self.btn_sync.setVisible(not ok)
        self._bg("sh", lambda: core.run_ps_json(nd.SHARES_PS, 90, "Shares & time"), done, self.btn_sh, "Loading...")

    def sync_time(self):
        if self._need_admin():
            return
        ps = ("$ErrorActionPreference='SilentlyContinue'; Start-Service W32Time; $o = (w32tm /resync /force) -join ' '; "
              "@{ ok = ($LASTEXITCODE -eq 0); detail = $o } | ConvertTo-Json -Compress")

        def done(r):
            r = r if isinstance(r, dict) else {}
            W.info(self, (r.get("detail") or r.get("error") or "")[:300] or "Done.")
            self.load_shares()
        self._bg("sync", lambda: core.run_ps_json(ps, 60, "Time sync", track=False), done, self.btn_sync, "Syncing...")

    # ------------------------------------------------------------------ Fixes
    def _build_fixes(self):
        sp = self.tf["Fixes"]
        p = W.Panel("Network fixes", "Each fix measures the connection first (router, internet, DNS, web test), applies the change, then measures again "
                                     "so you can see whether it helped. Fixes are not stopped by the Stop button.")
        self.fix_adapter = QComboBox()
        self.fix_adapter.addItem("(loading)")
        self.fix_adapter.setMinimumWidth(220)
        p.add(_row(W.label("Adapter:", "Body"), self.fix_adapter, "stretch"))
        self.fix_rows = {}
        for i, f in enumerate(nd.FIXES):
            p.add(W.divider())
            row = QWidget()
            h = QHBoxLayout(row)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(T.S4)
            col = QVBoxLayout()
            col.setSpacing(2)
            t = W.label(f["title"], "PanelTitle", wrap=True)
            col.addWidget(t)
            col.addWidget(W.label(f["desc"], "Body", wrap=True))
            h.addLayout(col, 1)
            b = W.button("Run", lambda fid=f["id"]: self.run_fix(fid), icon="wrench", min_w=96)
            h.addWidget(b, 0, Qt.AlignVCenter)
            self.fix_rows[f["id"]] = b
            p.add(row)
        sp.add(p)
        p = self.fx_panel = W.Panel("Before / after")
        self.fx_title = W.label("Run a fix to see its effect.", "Body", wrap=True, sel=True)
        p.add(self.fx_title)
        self.t_fx = self._table(["Measurement", "Before", "After", "Change"], [220, 200, 200, 200], mono=("Before", "After"), rows=8)
        p.add(self.t_fx)
        sp.add(p)

    def _show_fix_result(self):
        """The result panel sits under the fix list - scroll it into view (after layout) so the user sees progress."""
        if self.isVisible() and self.tabs.currentIndex() == TABS.index("Fixes"):
            QTimer.singleShot(0, lambda: None if self._closed else self.tf["Fixes"].ensureWidgetVisible(self.fx_panel, 0, T.S4))

    def run_fix(self, fid, on_done=None):
        f = nd.FIX_BY_ID.get(fid)
        if f is None or self._closed:
            return
        if self.busy.get("fix"):
            self.app.set_status("A network fix is still running - wait for it to finish.", "WARNING", hold=5)
            return
        if self._need_admin():
            return
        if not self.info:
            self._pending_fix = (fid, on_done)
            if not self.busy.get("load"):
                self.load()
            return
        adapter = self.fix_adapter.currentText()
        ad = next((a for a in (self.info or {}).get("adapters", []) if a.get("name") == adapter), {})
        profile = ""
        if f["needs"] == "wifi":
            cur = (self.wifi or {}).get("current") or {}
            if not nd.is_wifi(ad) and cur.get("name"):
                adapter = cur["name"]
            profile = cur.get("profile") or cur.get("ssid") or ""
            if not profile:
                W.info(self, "Not connected to a Wi-Fi network (open the Wi-Fi tab to scan first).")
                return
        if f["needs"] and (not adapter or adapter.startswith("(")):
            W.info(self, "Pick an adapter first.")
            return
        if f.get("confirm") and not W.confirm(self, f["confirm"] + ("\n\nAdapter: %s" % adapter if f["needs"] else "") +
                                              ("\nNetwork: %s" % profile if profile else ""), "WinDiag - %s" % f["title"],
                                              danger=f["id"] in ("winsock", "wifi_forget")):
            return
        if f["id"] != "flush" and not self.app.pin.require(f["title"]):      # every fix that changes a setting
            return
        gw, dns, _, _ = self._gw_dns()
        dns4 = [d for d in dns if ":" not in d]
        self.fx_title.setText("%s: measuring before..." % f["title"])
        _set_color(self.fx_title)
        self._show_fix_result()

        def work(progress):
            before = nd.measure(gw, dns4)
            progress("%s: applying..." % f["title"])
            res = nd.run_fix(f, adapter, profile)
            time.sleep(4 if f["id"] in ("renew", "restart", "wifi_rejoin") else 1)
            progress("%s: measuring after..." % f["title"])
            after = nd.measure(gw, dns4 if not f["id"].startswith("dns_") else None)
            if f["id"].startswith("dns_"):
                info = nd.net_info()
                ip2, _ = nd.primary(info)
                d2 = [d for d in (ip2.get("dns") or []) if ":" not in d]
                if d2:
                    ms, rc, _ = nd.dns_query(d2[0], "www.microsoft.com")
                    after["dns_ms"] = ms
            return {"before": before, "after": after, "res": res}

        def done(r):
            r = r if isinstance(r, dict) else {"error": "No result"}
            if r.get("error"):
                self.fx_title.setText("%s failed: %s" % (f["title"], r["error"]))
                _set_color(self.fx_title, T.WARN)
                return
            res = r["res"] if isinstance(r.get("res"), dict) else {}
            ok = res.get("ok", res.get("status") != "error")
            rows = nd.compare(r["before"], r["after"])
            self._show_table(self.t_fx, None, [{"Measurement": a, "Before": b, "After": c, "Change": d} for a, b, c, d in rows],
                             ["WARNING" if d == "worse" else None for a, b, c, d in rows])
            txt = "%s - %s. %s" % (f["title"], "done" if ok else "Windows reported a problem", (nd._s(res.get("detail")) or "")[:200])
            if res.get("restart"):
                txt += " Restart the PC to finish."
            self.fx_title.setText(txt)
            _set_color(self.fx_title, T.TEXT if ok else T.WARN)
            self._show_fix_result()
            self.fix_log.append({"fix": f["title"], "time": time.strftime("%H:%M"), "ok": ok, "rows": rows})
            self.app.set_status(txt[:150], None if ok else "WARNING", hold=8)
            if on_done:
                on_done(r)
            self.load()
        self._bg("fix", work, done, self.fix_rows[fid], "Running...", progress=lambda t: self.fx_title.setText(t))
