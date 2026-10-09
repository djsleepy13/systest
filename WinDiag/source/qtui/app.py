"""
WinDiag 4 main window (PySide6).

The window object is also the "app" the logic modules talk to (same attribute names as the old Tk app):
  results, findings_by, analysis, report_dir, is_admin, q (.put), drive_result, ram_result, battery_result,
  security_result, update_result, prescan_result, baselines, pin, scanner, render_summary(), set_status(),
  _on_result(), scan_finished(), _is_server(), set_security_result(), show()/open_page(), export(), _repair().
Pages: qtui/pages/*.py, registered in PAGES below. A page is created the first time it is needed and is only
redrawn while visible (widgets.Page.request_render).
"""
import importlib
import os
import re
import sys
import time
import traceback

from PySide6.QtCore import QEvent, QSize, Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCompleter, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
                               QProgressBar, QPushButton, QScrollArea, QSizePolicy, QStackedWidget, QVBoxLayout, QWidget)

import appsettings as settings
import core
import event_kb
import guided
import report
import scanner as scanner_mod
from . import tasks
from . import theme as T
from . import widgets as W

CHECKS = [("System", "System"), ("Disks", "Disks"), ("Errors", "Errors & Crashes"),
          ("Network", "Network"), ("Startup", "Startup & Processes"), ("Security", "Security & Updates"),
          ("Server", "Server Roles"), ("Virt", "Virtualization")]
CHECK_KEYS = [k for k, _ in CHECKS]

NAV = [("OVERVIEW", [("summary", "Dashboard", "dashboard"), ("specs", "Spec Sheet", "specs"), ("events", "Event Analyzer", "activity"),
                     ("guided", "Guided Fix", "wand")]),
       ("HARDWARE", [("System", "System", "cpu"), ("Disks", "Storage", "disk"), ("drives", "Drive Health", "drivehealth"),
                     ("ram", "Memory (RAM)", "ram"), ("battery", "Battery", "battery")]),
       ("WINDOWS", [("Errors", "Errors & Crashes", "alert"), ("Network", "Network", "network"), ("nettools", "Network Tools", "wifi"),
                    ("Startup", "Startup & Apps", "startup"), ("Security", "Windows Security", "shield"), ("updates", "Updates & Drivers", "update")]),
       ("TOOLS", [("tuneup", "Tune-up", "gauge"), ("security", "Security Scan", "lock"), ("files", "Files & Recovery", "folder"),
                  ("repairs", "Repairs & Tools", "wrench")]),
       ("SERVERS & VMS", [("Server", "Server Roles", "server"), ("Virt", "Virtualization", "cloud")]),
       ("APP", [("settings", "Settings", "gear")])]

PAGE_INFO = {
    "summary": ("Dashboard", "Overall health, top issues and live performance for this PC."),
    "specs": ("Spec Sheet", "Every hardware and Windows detail on one page - export it for inventory, resale or support."),
    "events": ("Event Analyzer", "Matches event IDs and stop codes against a knowledge base and ranks the most likely causes."),
    "guided": ("Guided Fix", "Step-by-step fixes that follow Microsoft's documented procedures, with automatic checks."),
    "System": ("System", "Windows version, hardware, drivers and Device Manager problems."),
    "Disks": ("Storage", "Drive health counters, temperatures and free space."),
    "drives": ("Drive Health", "SMART / NVMe health per drive, read-only tests, drive map and wipe."),
    "ram": ("Memory (RAM)", "RAM slots and sticks, plus an in-Windows memory test."),
    "battery": ("Battery", "Battery health, capacity history, live power draw and sleep-drain reports."),
    "Errors": ("Errors & Crashes", "Blue screens, crash dumps, unexpected shutdowns and crashing apps."),
    "Network": ("Network", "Adapters, IP settings and live connectivity tests."),
    "nettools": ("Network Tools", "Ping, speed, DNS, Wi-Fi, ports and local devices - plus fixes measured before and after."),
    "Startup": ("Startup & Processes", "What starts with Windows and what is using resources."),
    "Security": ("Windows Security", "Antivirus, firewall, BitLocker and Windows Update."),
    "security": ("Security Scan", "Defender, persistence, certificates and boot security - read-only triage."),
    "updates": ("Updates & Drivers", "What Windows Update says is missing on this PC (checked online), plus driver ages."),
    "tuneup": ("Tune-up", "Safe, reversible improvements - each one measured before and after."),
    "settings": ("Settings", "Start-up, privacy, technician PIN and drive-wipe options."),
    "files": ("Files & Recovery", "Quarantine, recover deleted files and secure delete."),
    "repairs": ("Repairs & Tools", "Built-in Windows repairs and tools. Nothing runs until you click it."),
    "Server": ("Server Roles", "Windows Server roles, AD, IIS, Hyper-V, clusters and backups."),
    "Virt": ("Virtualization", "Hypervisor / cloud detection, guest tools and time sync."),
}
LK_STATUS = {"HIGH": "CRITICAL", "MEDIUM": "WARNING", "LOW": "INFO"}

# key -> (module in qtui.pages, class name, attribute on the app). Info pages (CHECK_KEYS) use pages.info.InfoPage.
PAGES = {
    "summary": ("dashboard", "DashboardPage", "dash"),
    "specs": ("specs", "SpecPage", "specs"),
    "events": ("events", "EventsPage", "events_page"),
    "guided": ("guided", "GuidedPage", "guided"),
    "drives": ("drives", "DrivePage", "drives"),
    "ram": ("ram", "RamPage", "ram"),
    "battery": ("battery", "BatteryPage", "battery"),
    "nettools": ("nettools", "NetToolsPage", "nettools"),
    "updates": ("updates", "UpdatesPage", "updates"),
    "tuneup": ("tuneup", "TunePage", "tune"),
    "security": ("security", "SecurityPage", "security"),
    "files": ("files", "FilesPage", "files"),
    "repairs": ("repairs", "RepairsPage", "repairs"),
    "settings": ("settings", "SettingsPage", "settings_page"),
}
NAV_FINDINGS = {"events": "Events", "security": "SecScan", "drives": "Drives", "ram": "RAM", "battery": "Battery", "updates": "Updates",
                "summary": "_none"}


class StatusProxy(object):
    """Compat shim: old page code calls app.status.configure(text=..., text_color=...)."""

    def __init__(self, win):
        self.win = win

    def configure(self, text=None, text_color=None, **kw):
        if text is not None:
            self.win.set_status(text)

    def cget(self, k):
        return self.win.status_lbl.text() if k == "text" else ""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setObjectName("Root")
        self.is_admin = core.is_admin()
        self.report_dir = core.make_report_dir()
        self.results, self.findings_by, self.analysis = {}, {}, None
        self.drive_result = self.ram_result = self.battery_result = self.security_result = self.update_result = None
        self.prescan_result = None
        self.running = False            # a check (not the scan) is running
        self.batch = False              # the background scan is running
        self.done_count = 0
        self.CHECK_KEYS = CHECK_KEYS
        self.q = tasks.MainQueue(self)
        self.status = StatusProxy(self)
        self.pages, self.nav = {}, {}
        self.current = None
        self._closing = False
        self._scanned_once = False
        self._scan_stopped = False
        self._scan_counts = None
        self._last_scan_at = None
        self._status_hold = 0.0
        self.days = 30
        tasks.bridge().on_error = lambda e: self.set_status("Something went wrong in the last action - details were saved to Reports\\windiag_errors.log.",
                                                             "WARNING")
        import baseline
        base = os.path.join(core.app_dir(), "Reports")
        try:
            os.makedirs(base, exist_ok=True)
        except Exception:
            base = os.path.dirname(self.report_dir)
        self.baselines = baseline.Store(os.path.join(base, "baseline_%s.json" % os.environ.get("COMPUTERNAME", "PC")))
        from .pin import PinGate
        self.pin = PinGate(self)
        self.scanner = scanner_mod.Scanner(self)
        self.scanner.runner = lambda fn: tasks.run_task(fn, name="scan")

        self.setWindowTitle("WinDiag %s  -  %s%s" % (core.APP_VERSION, os.environ.get("COMPUTERNAME", ""),
                                                     "" if self.is_admin else "   [limited mode - not administrator]"))
        ico = core.resource_path("windiag.ico")
        if os.path.exists(ico):
            from PySide6.QtGui import QIcon
            self.setWindowIcon(QIcon(ico))
        self._build()
        self._size_to_screen()
        self.show_page("summary")
        self._scan_timer = QTimer(self)
        self._scan_timer.setInterval(500)
        self._scan_timer.timeout.connect(self._scan_tick)
        self._busy_timer = QTimer(self)
        self._busy_timer.setInterval(500)
        self._busy_timer.timeout.connect(self._busy_poll)
        self._busy_timer.start()
        self._notice_timer = QTimer(self)
        self._notice_timer.setInterval(700)
        self._notice_timer.timeout.connect(self._notices)
        self._notice_timer.start()
        self._sum_timer = QTimer(self)
        self._sum_timer.setSingleShot(True)
        self._sum_timer.timeout.connect(self._render_summary_now)
        QShortcut(QKeySequence(Qt.Key_Escape), self, activated=self._on_escape, context=Qt.WindowShortcut)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=lambda: self.search.setFocus(), context=Qt.WindowShortcut)
        QTimer.singleShot(250, self._startup)

    # ------------------------------------------------------------------ geometry / DPI
    def _size_to_screen(self):
        scr = self.screen() or QGuiApplication.primaryScreen()
        g = scr.availableGeometry()
        w, h = min(1440, g.width() - 40), min(900, g.height() - 60)
        self.resize(max(960, w), max(620, h))
        self.setMinimumSize(min(1100, g.width() - 40), min(640, g.height() - 60))
        self.move(g.x() + (g.width() - self.width()) // 2, g.y() + max(0, (g.height() - self.height()) // 3))

    # ------------------------------------------------------------------ layout
    def _build(self):
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._build_rail())
        main = QWidget()
        mv = QVBoxLayout(main)
        mv.setContentsMargins(0, 0, 0, 0)
        mv.setSpacing(0)
        mv.addWidget(self._build_header())
        self.stack = QStackedWidget()
        mv.addWidget(self.stack, 1)
        mv.addWidget(self._build_statusbar())
        h.addWidget(main, 1)

    def _build_rail(self):
        rail = QFrame()
        rail.setObjectName("Rail")
        rail.setFixedWidth(232)
        v = QVBoxLayout(rail)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        brand = QWidget()
        bl = QVBoxLayout(brand)
        bl.setContentsMargins(18, 18, 18, 12)
        bl.setSpacing(0)
        b = QLabel("WinDiag")
        b.setObjectName("Brand")
        bl.addWidget(b)
        s = QLabel("Diagnostics toolkit  ·  v%s" % core.APP_VERSION)
        s.setObjectName("BrandSub")
        bl.addWidget(s)
        v.addWidget(brand)
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("Rail")
        nv = QVBoxLayout(inner)
        nv.setContentsMargins(0, 0, 0, 8)
        nv.setSpacing(0)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for group, items in NAV:
            sec = QLabel(group)
            sec.setObjectName("NavSection")
            nv.addWidget(sec)
            for key, title, ic in items:
                row = QWidget()
                rl = QHBoxLayout(row)
                rl.setContentsMargins(0, 0, 10, 0)
                rl.setSpacing(4)
                btn = QPushButton("  " + title.replace("&", "&&"))
                btn.setObjectName("Nav")
                btn.setCheckable(True)
                btn.setIcon(T.icon(ic, T.TEXT2, 16))
                btn.setIconSize(QSize(16, 16))
                btn.setCursor(Qt.PointingHandCursor)
                btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
                btn.clicked.connect(lambda checked=False, k=key: self.show_page(k))
                self.nav_group.addButton(btn)
                rl.addWidget(btn, 1)
                cnt = QLabel("")
                cnt.setObjectName("NavCount")
                cnt.hide()
                rl.addWidget(cnt, 0, Qt.AlignVCenter)
                nv.addWidget(row)
                self.nav[key] = {"btn": btn, "cnt": cnt, "title": title, "icon": ic, "row": row}
        nv.addStretch(1)
        sa.setWidget(inner)
        self._nav_scroll = sa
        v.addWidget(sa, 1)
        foot = QFrame()
        foot.setObjectName("RailFoot")
        fl = QVBoxLayout(foot)
        fl.setContentsMargins(18, 12, 18, 14)
        fl.setSpacing(2)
        pc = QLabel(os.environ.get("COMPUTERNAME") or "This PC")
        pc.setFont(T.ui(12, 700))
        fl.addWidget(pc)
        if self.is_admin:
            fl.addWidget(W.Dot("OK", "Administrator", 11))
        else:
            row = QHBoxLayout()
            row.addWidget(W.Dot("WARNING", "Limited mode", 11))
            row.addStretch(1)
            row.addWidget(W.button("Restart as admin", self._elevate, "link"))
            fl.addLayout(row)
        v.addWidget(foot)
        return rail

    def _build_header(self):
        hd = QFrame()
        hd.setObjectName("Header")
        h = QHBoxLayout(hd)
        h.setContentsMargins(T.S5, T.S4, T.S5, T.S4)
        h.setSpacing(T.S3)
        tb = QVBoxLayout()
        tb.setSpacing(2)
        self.title_lbl = QLabel("")
        self.title_lbl.setObjectName("PageTitle")
        self.title_lbl.setFont(T.display(22, 700))
        tb.addWidget(self.title_lbl)
        self.desc_lbl = QLabel("")
        self.desc_lbl.setObjectName("PageDesc")
        self.desc_lbl.setWordWrap(True)
        tb.addWidget(self.desc_lbl)
        h.addLayout(tb, 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search pages, issues, repairs   Ctrl+F")
        self.search.setMinimumWidth(220)
        self.search.setMaximumWidth(340)
        self.search.setClearButtonEnabled(True)
        self._search_map = {}
        self._completer = QCompleter([], self)
        self._completer.setCaseSensitivity(Qt.CaseInsensitive)
        self._completer.setFilterMode(Qt.MatchContains)
        self._completer.setMaxVisibleItems(10)
        self.search.setCompleter(self._completer)
        self._completer.activated.connect(self._search_open)
        self.search.textEdited.connect(self._search_changed)
        self.search.returnPressed.connect(self._search_go)
        h.addWidget(self.search, 0, Qt.AlignVCenter)
        self.btn_report = W.button("Report", self.open_report, "secondary", icon="report")
        h.addWidget(self.btn_report, 0, Qt.AlignVCenter)
        self.btn_stop = W.button("Stop", self.stop_all, "stop", icon="stop", tip="Stop every running check (Esc)")
        self.btn_stop.hide()
        h.addWidget(self.btn_stop, 0, Qt.AlignVCenter)
        self.btn_run = W.button("Run all checks", self.run_all, "primary", icon="play", min_w=150)
        h.addWidget(self.btn_run, 0, Qt.AlignVCenter)
        return hd

    def _build_statusbar(self):
        sb = QFrame()
        sb.setObjectName("StatusBar")
        v = QVBoxLayout(sb)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        self.prog = QProgressBar()
        self.prog.setRange(0, 1000)
        self.prog.setValue(0)
        self.prog.setTextVisible(False)
        v.addWidget(self.prog)
        row = QHBoxLayout()
        row.setContentsMargins(T.S5, 6, T.S5, 7)
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setObjectName("StatusText")
        self.status_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        row.addWidget(self.status_lbl, 1)
        v.addLayout(row)
        return sb

    # ------------------------------------------------------------------ status
    def set_status(self, text, tone=None, hold=0):
        """Status bar text. tone: None/'WARNING'/'CRITICAL'/'OK'. hold = seconds the scan ticker must not overwrite it."""
        self.status_lbl.setText(str(text))
        self.status_lbl.setStyleSheet("color:%s;" % T.STATUS[tone] if tone in T.STATUS else "")
        if hold:
            self._status_hold = time.time() + hold

    def _say_busy(self, what):
        b = self._busy_text() or "another task"
        self.set_status("Can't %s yet - %s is still running. Wait for it to finish, or press Stop (Esc)." % (what, b), "WARNING", hold=5)

    def _busy_text(self):
        parts = []
        if self.scanner.running:
            parts.append("the scan")
        elif self.running:
            parts.append("a check")
        for key, name in (("drives", "a drive test"), ("ram", "the RAM test")):
            p = self.pages.get(key)
            if p is not None and getattr(p, "running", None):
                parts.append(name)
        names = sorted(set(core.busy()))
        if names and not parts:
            parts.append(", ".join(names[:3]))
        return " and ".join(parts)

    def _is_busy(self):
        if core.busy() or self.running or self.scanner.running:
            return True
        for key, p in list(self.pages.items()):
            if p is not None and getattr(p, "running", None):
                return True
        return False

    def _busy_poll(self):
        b = self._is_busy()
        if b != self.btn_stop.isVisible():
            self.btn_stop.setVisible(b)

    def _notices(self):
        try:
            for txt in core.pop_notices():
                self.set_status(txt, "WARNING", hold=10)
                W.warn(self, txt)
        except Exception as e:
            core.log_error("notices", e)

    # ------------------------------------------------------------------ pages
    def page(self, key):
        """Get (creating on first use) the page object for key."""
        p = self.pages.get(key)
        if p is not None:
            return p
        try:
            if key in CHECK_KEYS:
                from .pages.info import InfoPage
                p = InfoPage(self, key, dict(CHECKS)[key])
                attr = None
            elif key in PAGES:
                mod, cls, attr = PAGES[key]
                p = getattr(importlib.import_module("qtui.pages." + mod), cls)(self)
            else:
                return None
        except Exception as e:
            core.log_error("create page %s" % key, e)
            from .pages.placeholder import PlaceholderPage
            p, attr = PlaceholderPage(self, key, str(e)), None
        self.pages[key] = p
        if key in PAGES and PAGES[key][2]:
            setattr(self, PAGES[key][2], p)
        self.stack.addWidget(p)
        return p

    def __getattr__(self, name):
        # pages referenced by attribute (app.drives, app.ram, ...) are created on first access - GUI thread only
        for key, (_, _, attr) in PAGES.items():
            if attr == name:
                import threading
                if threading.current_thread() is not threading.main_thread():
                    raise RuntimeError("page '%s' accessed from a worker thread - post a callback with app.q.put instead" % key)
                return self.page(key)
        raise AttributeError(name)

    @property
    def info_pages(self):
        return {k: self.page(k) for k in CHECK_KEYS}

    def show_page(self, key, tab=None):
        p = self.page(key) or self.page("summary")
        if key not in PAGE_INFO:
            key = "summary"
        self.current = key
        title, desc = PAGE_INFO.get(key, (key, ""))
        self.title_lbl.setText(title)
        self.desc_lbl.setText(desc)
        n = self.nav.get(key)
        if n:
            n["btn"].setChecked(True)
            self._nav_scroll.ensureWidgetVisible(n["row"], 0, 20)
        self.stack.setCurrentWidget(p)
        if tab and hasattr(p, "open_tab"):
            p.open_tab(tab)

    def show(self, key=None, tab=None):
        """show() = show the window (Qt); show(key) = open a page (old page code uses app.show(key))."""
        if key is None:
            return super().show()
        self.show_page(key, tab)

    def open_page(self, key, tab=None):
        self.show_page(key, tab)

    # ------------------------------------------------------------------ search
    def _search_items(self, q):
        q = q.lower().strip()
        out = []
        if len(q) < 2:
            return out
        for key, (title, desc) in PAGE_INFO.items():
            if q in title.lower() or q in desc.lower():
                out.append(("Page", title, key))
        for k, fs in self.findings_by.items():
            for f in fs:
                if f.get("Status") in ("CRITICAL", "WARNING") and q in ("%s %s" % (f.get("Finding"), f.get("Area"))).lower():
                    out.append(("Issue", f.get("Finding") or "", self.target_page(f)))
        for pb in guided.PLAYBOOKS:
            if q in pb["title"].lower():
                out.append(("Guided Fix", pb["title"], "guide:" + pb["id"]))
        for r in core.REPAIRS:
            if q in r["name"].lower():
                out.append(("Repair", r["name"], "repairs"))
        return out[:12]

    def _search_changed(self, text):
        items = self._search_items(text)
        self._search_map = {}
        labels = []
        for kind, title, key in items:
            lab = "%s  -  %s" % (title[:70], kind)
            self._search_map[lab] = key
            labels.append(lab)
        self._completer.model().setStringList(labels) if hasattr(self._completer.model(), "setStringList") else None
        if not hasattr(self._completer.model(), "setStringList"):
            from PySide6.QtCore import QStringListModel
            self._completer.setModel(QStringListModel(labels, self._completer))
        if labels:
            self._completer.complete()

    def _search_go(self):
        items = self._search_items(self.search.text())
        if items:
            self._open_key(items[0][2])

    def _search_open(self, lab):
        key = self._search_map.get(lab)
        if key:
            QTimer.singleShot(0, lambda: (self.search.clear(), self._open_key(key)))

    def _open_key(self, key):
        self.search.clear()
        if key.startswith("guide:"):
            self.show_page("guided")
            self.guided.open_playbook(key[6:])
        else:
            self.show_page(key)

    def target_page(self, f):
        a = f.get("Area") or ""
        return {"Event log": "events", "Security scan": "security", "Drive health": "drives", "Memory": "ram", "Crashes": "Errors", "Disks": "Disks",
                "Storage": "Disks", "Network": "Network", "Startup": "Startup", "Security": "Security", "Updates": "updates", "Battery": "battery",
                "CPU": "System", "System": "System", "Windows": "System", "Drivers": "System", "Graphics": "System", "Hardware": "Errors"}.get(
            a, "Server" if a in ("Active Directory", "IIS", "Cluster", "Hyper-V", "Backup", "Certificates", "Server", "Time") else
            "Virt" if a == "Virtualization" else "summary")

    # ------------------------------------------------------------------ summary / nav counts
    def render_summary(self, now=False):
        """Debounced: results arrive in bursts. During a scan at most every 2 s."""
        if now:
            self._sum_timer.start(10)
        elif not self._sum_timer.isActive():
            self._sum_timer.start(2000 if self.batch else 120)

    def _render_summary_now(self):
        try:
            self.page("summary").request_render()
        except Exception as e:
            core.log_error("dashboard render", e)
        for key, n in self.nav.items():
            fs = self.findings_by.get(NAV_FINDINGS.get(key, key), [])
            c = sum(1 for f in fs if f.get("Status") == "CRITICAL" and not f.get("CheckError"))
            w = sum(1 for f in fs if f.get("Status") == "WARNING" and not f.get("CheckError"))
            lab = n["cnt"]
            if c or w:
                col = T.CRIT if c else T.WARN
                lab.setText(str(c + w))
                lab.setStyleSheet("color:%s; background:%s; border:1px solid %s;" % (col, T.tint(col, 0.12, T.RAIL), T.tint(col, 0.35, T.RAIL)))
                lab.show()
            else:
                lab.hide()
        if "specs" in self.pages:
            self.pages["specs"].request_render()

    # ------------------------------------------------------------------ results from checks
    def _on_result(self, key, res):
        self.done_count += 1
        if not self.batch:
            self.prog.setValue(int(1000 * min(1.0, self.done_count / float(len(CHECKS) + 1))))
        finds = list(res.get("findings") or [])
        if res.get("error"):
            finds.append({"Status": "WARNING", "Area": key, "Finding": "Check could not run: %s" % str(res["error"])[:150], "CheckError": True,
                          "Advice": "Restart WinDiag as administrator." if not self.is_admin else
                          "PowerShell may be blocked on this PC (company policy / antivirus). Try Re-run."})
        if key == "Events":
            self.analysis = res.get("analysis")
            a = self.analysis or {"problems": []}
            finds = [f for f in finds if f.get("Area") != "Event log"]
            for p in a["problems"]:
                finds.append({"Status": LK_STATUS[p["likelihood"]], "Area": "Event log",
                              "Finding": "Likely cause: %s (%s likelihood)" % (p["name"], p["likelihood"]),
                              "Advice": "See Event Analyzer. First step: " + (p["fix"][0] if p["fix"] else "")})
            if not a["problems"] and self.analysis:
                finds.append({"Status": "OK", "Area": "Event log", "Finding": "No problem patterns found in the event logs", "Advice": ""})
            self.page("events").set_analysis(self.analysis)
        else:
            self.results[key] = res.get("sections") or []
            self.page(key).set_result(res)
        self.findings_by[key] = finds
        if not self.batch:
            self.set_status("Finished: %s" % dict(CHECKS + [("Events", "Event Analyzer")]).get(key, key))
        self.render_summary(now=self.batch and self.done_count == 1)

    def set_security_result(self, res):
        self.security_result = res
        self.page("security").set_result(res)
        finds = [{"Status": f["severity"], "Area": "Security scan", "Finding": f["title"], "Advice": f.get("advice", ""), "_sec": f}
                 for f in res["findings"] if f["severity"] in ("CRITICAL", "WARNING")]
        if not finds:
            finds = [{"Status": "OK", "Area": "Security scan", "Finding": "Security scan found nothing suspicious", "Advice": ""}]
        self.findings_by["SecScan"] = finds
        self.render_summary()
        if self.batch:
            return
        self.page("guided").request_render()
        self.set_status("Security scan finished: %d critical, %d warnings." % (res["counts"]["CRITICAL"], res["counts"]["WARNING"]))
        self._export_quiet()

    def _is_server(self):
        for sec in self.results.get("System", []):
            for row in sec.get("data", []):
                if isinstance(row, dict) and "Server" in str(row.get("Windows", "")):
                    return True
        return False

    def heat_correlation(self):
        a = self.analysis or {}
        nv = next((p for p in a.get("problems", []) if p["cat"] in ("NVME", "DISK")), None)
        if not nv:
            return []
        hot, readings = [], []
        for sec in self.results.get("Disks", []):
            for row in sec.get("data", []) or []:
                if not isinstance(row, dict) or "Temp C" not in row:
                    continue
                try:
                    t = float(row.get("Temp C"))
                except (TypeError, ValueError):
                    continue
                try:
                    lim = float(row.get("Temp limit C"))
                except (TypeError, ValueError):
                    lim = None
                name = "%s (%s)" % (row.get("Model"), row.get("Bus"))
                readings.append("%s %.0f C" % (name, t))
                if t >= 60 or (lim and t >= lim - 8):
                    hot.append("%s at %.0f C%s" % (name, t, (" (drive limit %.0f C)" % lim) if lim else ""))
        if hot:
            return [{"Status": "WARNING", "Area": "Disks", "Finding": "Drive errors + high drive temperature: %s" % "; ".join(hot),
                     "Advice": "Heat is a likely cause of the drive errors (%s). Add/refit the NVMe heatsink, improve airflow, then use the "
                               "'Disk / NVMe' Guided Fix to confirm." % nv["name"]}]
        if readings:
            return [{"Status": "INFO", "Area": "Disks", "Finding": "Drive temperature is normal right now (%s)" % ", ".join(readings),
                     "Advice": "Heat is less likely to explain the drive errors (%s) - this is only the current reading." % nv["name"]}]
        return []

    # ------------------------------------------------------------------ single checks (Re-run / Analyze)
    def run_one(self, key, days=None):
        if self.running or self.scanner.running:
            return self._say_busy("re-run this check")
        self.running = True
        self.set_status("Re-running %s..." % dict(CHECKS + [("Events", "Event Analyzer")]).get(key, key))
        d = days or self.days

        def work():
            res = core.run_check(key, days=d)
            if key == "Events":
                res["analysis"] = event_kb.analyze(res.get("events") or [], server=self._is_server())
                res["events"] = []
            return res

        def done(res):
            self.running = False
            self._on_result(key, res)
            if key == "Events":
                self.findings_by["Heat"] = self.heat_correlation()
                self.page("guided").request_render()

        def fail(msg):
            self.running = False
            self._on_result(key, {"sections": [], "findings": [], "events": [], "error": msg})
        tasks.run_task(work, done, fail, name="check-%s" % key)

    def run_events(self, days=None):
        if days:
            self.days = days
        self.run_one("Events", days or self.days)

    # ------------------------------------------------------------------ background scan
    def _warm_pages(self):
        """Build the not-yet-opened pages one at a time while the app is idle, so the first click on a heavy page
        (Guided Fix, Network Tools, Files) is instant. Pauses while a mouse button is held (dragging/resizing)."""
        if getattr(self, "_closing", False):
            return
        todo = [k for k in PAGE_INFO if k not in self.pages]
        if not todo:
            return
        busy = QApplication.mouseButtons() != Qt.NoButton or QApplication.activeModalWidget() is not None
        if not busy:
            try:
                self.page(todo[0])
            except Exception as e:
                core.log_error("warm page %s" % todo[0], e)
        QTimer.singleShot(400 if busy else 150, self._warm_pages)

    def _startup(self):
        if not self.pin.startup():
            self.close()
            return
        QTimer.singleShot(1500, self._warm_pages)
        auto = "--resume" in sys.argv or settings.get("auto_full_scan")
        from .startdialog import StartDialog, run_prescan
        if auto and not settings.get("consent_required"):
            run_prescan(self)
            self._start_choice("full")
        else:
            StartDialog(self, self._start_choice).open()

    def _start_choice(self, mode):
        if mode:
            self.run_all()
        else:
            self.show_page("repairs")
            self.after_scan(scanned=False)

    def run_all(self):
        if self.running or core.busy() or self.scanner.running:
            return self._say_busy("start a new scan")
        self.begin_batch()
        if not self.scanner.start("full"):
            self.end_batch()
            return
        self._scan_timer.start()
        self._scan_tick()

    def begin_batch(self):
        self._scan_stopped = False
        self._scan_counts = None
        self.batch = True
        self.done_count = 0
        keep = {k: v for k, v in self.findings_by.items() if k in ("SecScan", "Updates")}
        self.results, self.findings_by, self.analysis = {}, {}, None
        self.findings_by.update(keep)
        self.btn_run.setEnabled(False)
        self.btn_run.setText("Scanning 0%")
        self.prog.setValue(0)
        self.set_status("Scanning - pages fill in as results arrive. Esc stops the scan.")
        self.render_summary(now=True)

    def _scan_tick(self):
        if not self.scanner.running and not self.batch:
            self._scan_timer.stop()
            return
        try:
            frac = self.scanner.estimate()[0]
            self.prog.setValue(int(frac * 1000))
            self.btn_run.setText("Scanning %d%%" % (frac * 100))
            if time.time() >= self._status_hold:
                self.set_status(self.scanner.status_text())
        except Exception as e:
            core.log_error("scan tick", e)

    def scan_finished(self, stopped):
        self._scan_timer.stop()
        self._scanned_once = True
        self._last_scan_at = time.strftime("%H:%M")
        self._scan_stopped = bool(stopped)
        self._scan_counts = (sum(1 for x in self.scanner.steps if x["state"] == "done"), len(self.scanner.steps))
        try:
            self.end_batch()
        finally:
            core.reset_abort()
        self.after_scan(scanned=True, stopped=stopped)

    def end_batch(self):
        self.batch = False
        self.running = False
        try:
            self.findings_by["Heat"] = self.heat_correlation()
        except Exception:
            traceback.print_exc()
        self.btn_run.setEnabled(True)
        self.btn_run.setText("Run all checks")
        self.prog.setValue(1000)
        self.render_summary(now=True)

    def after_scan(self, scanned=True, stopped=False):
        try:
            g = self.page("guided")
            g.request_render()
            if not getattr(self, "_resumed", False):
                self._resumed = True
                n = g.resume_checks() if hasattr(g, "resume_checks") else 0
                if "--resume" in sys.argv or n:
                    self.show_page("guided")
                    self.set_status("Resumed Guided Fix - re-checking %d step(s) that were waiting for a restart." % n)
        except Exception as e:
            core.log_error("after_scan guided", e)
        if not scanned:
            self.set_status("Ready - no scan run. Use 'Run all checks' any time.")
            try:
                self.tune.check()
            except Exception as e:
                core.log_error("tune check", e)
            return
        head = "Scan stopped - results incomplete." if stopped else "Scan finished."
        path = self._export_quiet()
        self.set_status("%s %s saved: %s" % (head, "Partial report" if stopped else "Report", path) if path else
                        "%s (Could not save the report - details in Reports\\windiag_errors.log)" % head)

    def stop_all(self):
        """Stop every running check, scan and test. Repairs and wipes run in their own windows and are not touched."""
        names = core.busy()
        self.scanner.stop()
        core.ABORT.set()
        self.set_status("Stopping...")
        for key, p in list(self.pages.items()):
            if p is not None and hasattr(p, "stop_all"):
                try:
                    p.stop_all()
                except Exception as e:
                    core.log_error("stop %s" % key, e)

        def done(n):
            if self.scanner.running:
                self.set_status("Stopping the scan - waiting for the running checks to end...")
            else:
                self.set_status("Stopped %d running task(s)%s." % (max(n or 0, len(names)), (": " + ", ".join(sorted(set(names))[:4])) if names else ""))
                QTimer.singleShot(2500, lambda: None if self.scanner.running else core.reset_abort())
        tasks.run_task(core.abort_all, done, lambda m: done(0), name="stop-all")

    def _on_escape(self):
        if QApplication.activeModalWidget() is not None or QApplication.activePopupWidget() is not None:
            return
        if self.search.hasFocus() and self.search.text():
            self.search.clear()
            return
        if self._is_busy():
            self.stop_all()

    # ------------------------------------------------------------------ report / repairs / tools
    def export(self):
        allf = [f for k in self.findings_by for f in self.findings_by[k]]
        path = report.export(self.report_dir, CHECKS, self.results, allf, self.analysis, self.is_admin, self.security_result,
                             self.drive_result, self.ram_result)
        if settings.get("privacy_mode"):
            for fp in (path, path[:-5] + ".txt"):
                try:
                    with open(fp, "r", encoding="utf-8") as fh:
                        t = fh.read()
                    with open(fp, "w", encoding="utf-8") as fh:
                        fh.write(settings.redact(t, self))
                except Exception:
                    pass
        return path

    def _export_quiet(self):
        try:
            return self.export()
        except Exception as e:
            core.log_error("export report", e)
            return None

    def open_report(self):
        try:
            p = self.export()
            core.open_tool(p) if hasattr(core, "open_tool") else os.startfile(p)
        except Exception as e:
            W.error(self, "Could not create the report:\n%s" % e)

    def _repair(self, rep):
        if not self.pin.require("repairs"):
            return
        if rep.get("confirm") and not W.confirm(self, rep["confirm"], "WinDiag - " + rep["name"], danger=True):
            return
        try:
            core.start_repair(rep, self.report_dir)
            self.set_status("Started: %s (runs in its own window, logged to the Reports folder)" % rep["name"])
        except Exception as e:
            W.error(self, "Could not start %s:\n%s" % (rep["name"], e))

    def _tool(self, name, target):
        try:
            core.open_tool(target)
        except Exception as e:
            W.error(self, "Could not open %s:\n%s" % (name, e))

    def _elevate(self):
        if core.relaunch_as_admin():
            self._closing = True
            self.close()
        else:
            W.info(self, "Administrator rights were not granted.")

    def text_popup(self, title, text):
        W.text_dialog(self, title, text)

    def copy_text(self, text):
        QGuiApplication.clipboard().setText(text)
        self.set_status("Copied to clipboard.", hold=3)

    # ------------------------------------------------------------------ hover / detail content (used by several pages)
    @staticmethod
    def fmt_t(t):
        return t.strftime("%Y-%m-%d %H:%M") if hasattr(t, "strftime") else (t or "")

    def finding_content(self, f):
        """Rich explanation for a finding (event-log based), or None."""
        if f.get("_sec") and "security" in self.pages and hasattr(self.pages["security"], "finding_content"):
            return self.pages["security"].finding_content(f["_sec"])
        ev = self.page("events")
        return ev.finding_content(f) if hasattr(ev, "finding_content") else None

    @staticmethod
    def content_text(c):
        out = [c.get("title", "")]
        if c.get("badge"):
            out[0] = "[%s] %s" % (c["badge"], out[0])
        if c.get("sub"):
            out.append(c["sub"])
        for head, body in c.get("sections", []):
            if not body:
                continue
            out += ["", head.upper()]
            if isinstance(body, (list, tuple)):
                numbered = head.lower().startswith("how to fix")
                out += [("  %d. " % (i + 1) if numbered else "  - ") + str(b) for i, b in enumerate(body)]
            else:
                out.append("  " + str(body))
        if c.get("foot"):
            out += ["", c["foot"]]
        return "\n".join(out)

    # ------------------------------------------------------------------ closing
    def _risky_running(self):
        out = []
        for key, name in (("ram", "the RAM test"), ("drives", "a drive test")):
            p = self.pages.get(key)
            if p is not None and getattr(p, "running", None):
                out.append(name)
        return out

    def _wipe_running(self):
        p = self.pages.get("drives")
        return bool(p is not None and getattr(p, "wipe_running", lambda: False)())

    def closeEvent(self, e):
        if self._closing:
            e.accept()
            return
        if self._wipe_running():
            W.warn(self, "A drive wipe is running. Keep WinDiag open until it finishes - it verifies the drive and writes the certificate.")
            e.ignore()
            return
        risky = self._risky_running()
        if risky and not W.confirm(self, "%s is still running. Closing WinDiag stops it and its result is lost.\n\nClose anyway?"
                                   % " and ".join(risky).capitalize(), danger=True):
            e.ignore()
            return
        self._closing = True
        self.hide()
        try:
            self.scanner.stop()
            for key in ("drives", "ram"):
                p = self.pages.get(key)
                if p is not None and hasattr(p, "stop_all"):
                    p.stop_all()
            for p in self.pages.values():
                if hasattr(p, "shutdown"):
                    p.shutdown()
        except Exception as ex:
            core.log_error("close", ex)
        tasks.shutdown(4000)
        e.accept()
