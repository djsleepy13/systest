"""Security Scan page (read-only triage: Defender, persistence, processes, certificates, boot security, optional VirusTotal).
Nothing is removed unless the user clicks Quarantine (PIN + confirmation, restore point, reversible from Files > Quarantine)."""
import os
import subprocess
import urllib.parse

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLineEdit, QTabWidget, QVBoxLayout, QWidget

import appsettings as S
import core
import filetools
import security
from .. import theme as T
from .. import widgets as W
from ._ops import BusyStrip, FillTable, Ops, bottom, field, flow, mono_input, scroll_fill

TABS = ("Overview", "Startup & persistence", "Processes", "Certificates", "Defender", "Boot & drivers", "VirusTotal")
SEV = {"CRITICAL": "CRITICAL", "WARNING": "WARNING", "INFO": "INFO", "OK": "OK", "REVIEW": "REVIEW"}
INTRO = ("Read-only check of Microsoft Defender, everything that starts automatically, running programs, trusted certificates and boot security. "
         "'Suspicious' means worth checking - not confirmed malware. Nothing is removed unless you click Quarantine, and quarantine can be undone "
         "(Files > Quarantine).")
NOT_RUN = "Click 'Run security scan' to start. It takes 1-5 minutes (every program's digital signature is checked)."
Q_WHAT = {"entry": "disable/remove the startup entry and move its program file into quarantine",
          "file": "stop the program and move the file into quarantine", "ifeo": "remove the IFEO 'Debugger' redirect",
          "wmi": "remove the WMI subscription (filter, consumer and binding)", "cert": "remove the certificate from the trusted store"}
VT_DELAY = 15.5          # seconds between lookups: the free VirusTotal key allows 4 per minute


def _tab(*widgets, note=None):
    """Plain tab body: optional note, widgets (stretch for tables)."""
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(T.S5, T.S4, T.S5, T.S4)
    v.setSpacing(T.S3)
    for x in widgets:
        if x is None:
            continue
        v.addWidget(x, 1 if isinstance(x, W.DataTable) else 0)
    if note:
        v.addWidget(W.label(note, "Muted", wrap=True))
    return scroll_fill(w)


class SecurityPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.result = None
        self._drawn = None
        self.vt = {}
        self.vt_files = {}
        self._closed = False
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        top = QWidget()
        tv = QVBoxLayout(top)
        tv.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        tv.setSpacing(T.S3)
        self.btn_scan = W.button("Run security scan", self.scan, "primary", icon="play", min_w=170)
        self.b_crit, self.b_warn, self.b_info = W.Badge("- CRITICAL", "CRITICAL", True), W.Badge("- WARNING", "WARNING", True), W.Badge("- INFO", "INFO", True)
        tv.addWidget(flow(self.btn_scan, self.b_crit, self.b_warn, self.b_info))
        self.lbl_state = W.label("Not scanned yet.", "Body", wrap=True)
        tv.addWidget(self.lbl_state)
        tv.addWidget(W.label(INTRO, "Muted", wrap=True))
        self.strip = BusyStrip(lambda: self.ops.cancel())
        tv.addWidget(self.strip)
        v.addWidget(top)
        self.ops = Ops(self, self.strip)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        v.addWidget(self.tabs, 1)
        self._build_overview()
        self._build_entries()
        self._build_processes()
        self._build_certs()
        self._build_defender()
        self._build_boot()
        self._build_vt()

    # ------------------------------------------------------------------ building
    def _build_overview(self):
        self.sp_ov = W.ScrollPage(spacing=T.S4)
        self._add_tab(self.sp_ov, "Overview")

    def _bar(self, *buttons):
        return flow(*buttons)

    def _build_entries(self):
        self.t_entries = FillTable(["Verdict", "Type", "Name", "Program", "Signature", "Why"], [100, 150, 170, 320, 200, 340],
                                   on_open=lambda r: self._row_popup("entry", r), mono=("Program",))
        self.show_all = QCheckBox("Show Microsoft-signed / OK items too")
        self.show_all.toggled.connect(lambda _=None: self._render_entries())
        self.btn_q_entry = W.button("Quarantine selected", self._q_entry, icon="lock")
        bar = self._bar(self.btn_q_entry, W.button("Open file location", lambda: self._open_loc(self.t_entries), icon="folder"),
                        W.button("Search online", lambda: self._search(self.t_entries), icon="search"),
                        W.button("Details", lambda: self._details(self.t_entries, "entry"), icon="info"))
        self._add_tab(_tab(self.show_all, self.t_entries, bar, note="Double-click a row for details. 'REVIEW' = unusual but often legitimate."),
                         "Startup & persistence")

    def _build_processes(self):
        self.t_proc = FillTable(["Verdict", "Process", "PID", "Path", "Signature", "Connections", "Why"], [100, 150, 70, 320, 180, 200, 300],
                                on_open=lambda r: self._row_popup("proc", r), mono=("PID", "Path", "Connections"))
        self.btn_q_proc = W.button("Quarantine selected", self._q_proc, icon="lock")
        bar = self._bar(self.btn_q_proc, W.button("Open file location", lambda: self._open_loc(self.t_proc), icon="folder"),
                        W.button("Search online", lambda: self._search(self.t_proc), icon="search"),
                        W.button("Details", lambda: self._details(self.t_proc, "proc"), icon="info"))
        self._add_tab(_tab(self.t_proc, bar, note="Only unsigned/suspicious programs and programs with internet connections are listed. "
                                                     "Signed Windows processes are skipped."), "Processes")

    def _build_certs(self):
        self.t_cert = FillTable(["Verdict", "Store", "Subject", "Expires", "In Microsoft list", "Private key"], [100, 170, 420, 100, 130, 100],
                                on_open=lambda r: self._row_popup("cert", r), mono=("Expires",))
        self.show_all_certs = QCheckBox("Show all roots (not only flagged ones)")
        self.show_all_certs.toggled.connect(lambda _=None: self._render_certs())
        self.btn_q_cert = W.button("Quarantine selected", self._q_cert, icon="lock")
        bar = self._bar(self.btn_q_cert, W.button("Open certificate manager", lambda: self._launch("certlm.msc"), icon="shield"),
                        W.button("Details", lambda: self._details(self.t_cert, "cert"), icon="info"))
        self._add_tab(_tab(self.show_all_certs, self.t_cert, bar), "Certificates")

    def _build_defender(self):
        self.sp_def = W.ScrollPage(spacing=T.S4)
        btns = []
        for name in ("Update Defender definitions", "Defender quick scan", "Defender full scan", "Defender Offline scan"):
            rep = core.REPAIR_BY_NAME.get(name)
            ok = bool(rep) and (self.app.is_admin or not rep.get("admin"))
            b = W.button(name, (lambda r=rep: self.app._repair(r)), "primary" if name.endswith("full scan") else "secondary",
                         tip=None if ok else "Needs administrator rights")
            b.setEnabled(ok)
            btns.append(b)
        btns.append(W.button("Open Windows Security", lambda: self._launch("windowsdefender:"), icon="shield"))
        btns.append(W.button("Defender quarantine", lambda: self.app.show_page("files", "Quarantine"), icon="folder"))
        self.sp_def.add(flow(*btns))
        self.def_box = QWidget()
        self.def_lay = QVBoxLayout(self.def_box)
        self.def_lay.setContentsMargins(0, 0, 0, 0)
        self.def_lay.setSpacing(T.S4)
        self.def_lay.addWidget(W.label("Run the security scan first.", "Muted"))
        self.sp_def.add(self.def_box)
        self.sp_def.finish()
        self._add_tab(self.sp_def, "Defender")

    def _build_boot(self):
        self.sp_boot = W.ScrollPage(spacing=T.S4)
        self.boot_panel = W.Panel("Boot & driver security")
        self.boot_list = W.FindingsList([], "Run the security scan first.")
        self.boot_panel.add(self.boot_list)
        self.sp_boot.add(self.boot_panel)
        self.sp_boot.finish()
        self._add_tab(self.sp_boot, "Boot & drivers")

    def _build_vt(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(T.S5, T.S4, T.S5, T.S4)
        v.setSpacing(T.S3)
        v.addWidget(W.label("Optional: ask VirusTotal whether ~70 antivirus engines know a file. OFF by default.\n"
                            "Only the file's SHA-256 fingerprint is sent - never the file itself. You need a free API key from virustotal.com "
                            "(Profile > API key). The free key allows 4 lookups per minute, so this is slow on purpose.\n"
                            "Only unsigned / flagged programs from the scan are looked up.", "Body", wrap=True))
        key = S.get("vt_key") or ""
        self.vt_key = QLineEdit(key)
        self.vt_key.setEchoMode(QLineEdit.Password)
        mono_input(self.vt_key)
        self.vt_key.setPlaceholderText("VirusTotal API key")
        self.vt_remember = QCheckBox("Remember key (saved next to WinDiag on this USB)")
        self.vt_remember.setChecked(bool(key))
        self.btn_vt = W.button("Look up flagged files", self.vt_lookup, "primary", icon="search")
        v.addWidget(flow(field("API key", self.vt_key, 300), bottom(self.vt_remember), bottom(self.btn_vt)))
        self.t_vt = FillTable(["Result", "File", "Detections", "Label", "SHA-256"], [110, 360, 100, 200, 300],
                              on_open=lambda r: r.get("_link") and QDesktopServices.openUrl(QUrl(r["_link"])),
                              mono=("File", "Detections", "SHA-256"), min_h=160)
        v.addWidget(self.t_vt, 1)
        v.addWidget(W.label("Double-click a row to open the full VirusTotal report. 1-2 detections are often false positives; "
                            "many detections = treat as malware.", "Muted", wrap=True))
        self._add_tab(scroll_fill(w), "VirusTotal")

    def _add_tab(self, w, name):
        self.tabs.addTab(w, name.replace("&", "&&"))          # '&' would become a mnemonic underline

    def open_tab(self, name):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i).replace("&&", "&") == name:
                self.tabs.setCurrentIndex(i)

    @property
    def running(self):
        return self.ops.running("scan")

    # ------------------------------------------------------------------ scanning
    def _scanner_secscan(self):
        sc = getattr(self.app, "scanner", None)
        return bool(sc and sc.running and any(s.get("key") == "secscan" and s.get("state") == "run" for s in sc.steps))

    def scan(self):
        if self.ops.running("scan"):
            return
        if self._scanner_secscan():
            self.app.set_status("The full scan is running the security scan right now - the results appear here when it finishes.", "WARNING", hold=5)
            return

        def work():
            try:
                raw = core.run_ps_json(security.TRIAGE_PS, 1200, "Security scan")
                raw = raw if isinstance(raw, dict) else {}
                if raw.get("aborted"):
                    return {"error": "Stopped by user", "aborted": True}
                if (raw.get("status") == "error" or not raw) and "entries" not in raw:
                    return {"error": str(raw.get("detail") or "PowerShell returned no data")}
                return security.analyze(raw)
            except Exception as e:
                core.log_error("security page scan", e)
                return {"error": "Analysis failed: %s" % core.friendly_error(e)}
        self.btn_scan.setText("Scanning...")
        self.lbl_state.setText("Checking Defender, startup items, processes, certificates... (1-5 min)")
        self.ops.start("scan", work, self._scan_done, "Security scan running...", cancellable=True,
                       kill=lambda: () if self._scanner_secscan() else ("Security scan",), buttons=[self.btn_scan],
                       on_cancel=self._scan_cancelled)

    def _scan_cancelled(self):
        self.btn_scan.setText("Run security scan")
        self.lbl_state.setText("Scan stopped" if not self.result else self._state_text(self.result))

    def _scan_done(self, res):
        self.btn_scan.setText("Run security scan")
        if res.get("aborted"):
            self.lbl_state.setText("Scan stopped")
            self.app.set_status("Security scan stopped.")
            return
        if res.get("error") or "findings" not in res:
            self.lbl_state.setText("Scan failed")
            self.app.set_status("Security scan failed.", "WARNING")
            W.error(self, "Security scan failed:\n%s" % str(res.get("error") or "no result")[:500])
            return
        self.app.set_security_result(res)

    # ------------------------------------------------------------------ data in
    def set_result(self, res):
        """Called by app.set_security_result (scan page button or the background full scan)."""
        if not isinstance(res, dict):
            return
        self.result = res
        self.request_render()

    @staticmethod
    def _counts(res):
        c = (res or {}).get("counts") or {}
        return {k: c.get(k, 0) for k in ("CRITICAL", "WARNING", "INFO")}

    def _state_text(self, res):
        c = self._counts(res)
        return "Last scan: %d critical, %d warnings, %d info" % (c["CRITICAL"], c["WARNING"], c["INFO"])

    # ------------------------------------------------------------------ rendering
    def render(self):
        res = self.result
        if res is None:
            if self._drawn is None:
                self._render_empty()
                self._drawn = False
            return
        if res is self._drawn:
            return
        self._drawn = res
        if not self.ops.running("scan"):
            self.lbl_state.setText(self._state_text(res))
        c = self._counts(res)
        self.b_crit.set("%d CRITICAL" % c["CRITICAL"], "CRITICAL", True)
        self.b_warn.set("%d WARNING" % c["WARNING"], "WARNING", True)
        self.b_info.set("%d INFO" % c["INFO"], "INFO", True)
        for name, fn in (("overview", self._render_overview), ("entries", self._render_entries), ("processes", self._render_procs),
                         ("certs", self._render_certs), ("defender", self._render_defender), ("boot", self._render_boot)):
            try:
                fn()
            except Exception as e:
                core.log_error("security page render %s" % name, e)

    def _render_empty(self):
        lay = self.sp_ov.lay
        W.clear_layout(lay)
        lay.addWidget(W.label(NOT_RUN, "Muted", wrap=True))
        lay.addStretch(1)

    def _render_overview(self):
        lay = self.sp_ov.lay
        W.clear_layout(lay)
        F = self.result.get("findings") or []
        if self._counts(self.result)["CRITICAL"]:
            lay.addWidget(W.Banner("Critical items found.", "Follow the step-by-step 'Suspected malware' guide (Microsoft's procedure).", "CRITICAL",
                                   action=W.button("Open guide", self._open_guide, icon="wand")))
        if not F:
            lay.addWidget(W.Banner("Nothing suspicious found.", "", "OK"))
        if F:
            p = W.Panel("Findings", "Most serious first. 'Details' explains each item; Quarantine is reversible (Files > Quarantine > Restore).",
                        actions=[W.label("%d item(s)" % len(F), "Muted")])
            for i, fd in enumerate(F):
                if i:
                    p.add(W.divider())
                p.add(self._finding_row(fd))
            lay.addWidget(p)
        lay.addStretch(1)

    def _finding_row(self, fd):
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(T.S4)
        col = QVBoxLayout()
        col.setSpacing(T.S1)
        top = QHBoxLayout()
        top.setSpacing(T.S2)
        sev = fd.get("severity") or "INFO"
        top.addWidget(W.Badge(sev, SEV.get(sev, "INFO")))
        top.addWidget(W.label(fd.get("category") or "", "Muted"))
        top.addStretch(1)
        col.addLayout(top)
        col.addWidget(W.label(fd.get("title") or "", "Value", wrap=True, sel=True))
        if fd.get("advice"):
            col.addWidget(W.label(fd["advice"], "Body", wrap=True, sel=True))
        h.addLayout(col, 1)
        acts = QVBoxLayout()
        acts.setSpacing(T.S1)
        acts.addWidget(W.button("Details", lambda fd=fd: self._finding_popup(fd), "ghost", icon="info"))
        if (fd.get("item") or {}).get("kind") in Q_WHAT:
            b = W.button("Quarantine", lambda fd=fd: self.quarantine_finding(fd), icon="lock",
                         tip=None if self.app.is_admin else "Needs administrator rights")
            b.setEnabled(bool(self.app.is_admin))
            acts.addWidget(b)
        acts.addStretch(1)
        h.addLayout(acts)
        return row

    def _open_guide(self):
        self.app.show_page("guided")
        g = self.app.pages.get("guided")
        if g is not None and hasattr(g, "open_playbook"):
            g.open_playbook("malware")

    def _finding_popup(self, fd):
        c = self.finding_content(fd)
        self.app.text_popup(c["title"], self.app.content_text(c))

    def finding_content(self, fd):
        secs = [("What this means", fd.get("why")), ("What to do", fd.get("advice"))]
        if fd.get("detail"):
            secs.append(("Details", fd["detail"][:400]))
        sha = (fd.get("item") or {}).get("sha256")
        if sha and sha in self.vt:
            secs.append(("VirusTotal", self._vt_text(self.vt[sha])))
        return {"title": fd.get("title", ""), "badge": fd.get("severity"), "sub": fd.get("category", ""), "sections": secs,
                "foot": "Quarantine is reversible: Files > Quarantine > Restore." if fd.get("item") else ""}

    def _render_entries(self):
        if not self.result:
            return
        rows = self.result.get("entries") or []
        if not self.show_all.isChecked():
            rows = [r for r in rows if r.get("Verdict") != "OK"]
        self.t_entries.set_rows(rows, [r.get("Verdict") if r.get("Verdict") != "OK" else None for r in rows])

    def _render_procs(self):
        rows = self.result.get("processes") or []
        self.t_proc.set_rows(rows, [r.get("Verdict") if r.get("Verdict") != "OK" else None for r in rows])

    def _render_certs(self):
        if not self.result:
            return
        rows = self.result.get("certs") or []
        if not self.show_all_certs.isChecked():
            rows = [r for r in rows if r.get("Verdict") != "OK"]
        self.t_cert.set_rows(rows, [r.get("Verdict") if r.get("Verdict") in ("CRITICAL", "WARNING") else None for r in rows])

    def _render_defender(self):
        W.clear_layout(self.def_lay)
        d = self.result.get("defender") or {}
        L = security._l

        def yn(v):
            return "yes" if v else ("no" if v is False else "unknown")

        def dt(v, empty="?"):
            return (v or empty).replace("T", " ")
        pol = security._int(d.get("policy_disable")) == 1 or security._int(d.get("policy_rt_off")) == 1
        p = W.Panel("Microsoft Defender")
        g = W.KeyValueGrid(cols=3)
        bad = lambda v: {"color": "CRITICAL"} if v is False else {}
        g.set([("Present", yn(d.get("present")), bad(d.get("present"))), ("Real-time protection", yn(d.get("realtime")), bad(d.get("realtime"))),
               ("Tamper protection", yn(d.get("tamper")), {"color": "WARNING"} if d.get("tamper") is False else {}),
               ("Mode", d.get("mode") or "?"), ("Definitions dated", dt(d.get("sig_updated")), {"mono": True}),
               ("Last quick scan", dt(d.get("quick_scan"), "never"), {"mono": True}), ("Last full scan", dt(d.get("full_scan"), "never"), {"mono": True}),
               ("Disabled by policy", "YES" if pol else "no", {"color": "CRITICAL"} if pol else {})])
        p.add(g)
        self.def_lay.addWidget(p)

        prods = L(d.get("products"))
        p = W.Panel("Antivirus products (Security Center)")
        if prods:
            t = W.DataTable(["Product", "Protection", "Definitions"], [320, 120, 200], max_rows_visible=6)
            t.set_rows([{"Product": x.get("name"), "Protection": "enabled" if x.get("enabled") else "off",
                         "Definitions": "up to date" if x.get("uptodate") else "OUT OF DATE"} for x in prods],
                       [None if (x.get("enabled") and x.get("uptodate")) else "WARNING" for x in prods])
            p.body.setContentsMargins(0, 0, 0, 0)
            p.add(t)
        else:
            p.add(W.label("No antivirus products reported.", "Muted"))
        self.def_lay.addWidget(p)

        ex = [("folder", x) for x in L(d.get("excl_path"))] + [("process", x) for x in L(d.get("excl_process"))] + \
             [("extension", x) for x in L(d.get("excl_ext"))] + [("IP", x) for x in L(d.get("excl_ip"))]
        hidden = any(str(x).upper().startswith("N/A") for _, x in ex)     # "N/A: Must be an administrator to view exclusions"
        ex = [e for e in ex if not str(e[1]).upper().startswith("N/A")]
        p = W.Panel("Exclusions (Defender does not scan these)")
        if ex:
            t = W.DataTable(["Type", "Excluded"], [110, 600], mono=("Excluded",), max_rows_visible=8)
            t.set_rows([{"Type": a, "Excluded": b} for a, b in ex])
            p.body.setContentsMargins(0, 0, 0, 0)
            p.add(t)
        else:
            p.add(W.label("none" if not hidden and self.app.is_admin else "(exclusions are only visible to administrators)", "Muted"))
        self.def_lay.addWidget(p)

        th = L(d.get("threats"))
        p = W.Panel("Detection history (newest first)")
        if th:
            rows = [{"Time": (x.get("time") or "")[:16].replace("T", " "), "Threat": x.get("name"),
                     "Outcome": security.THREAT_STATUS.get(security._int(x.get("status")), x.get("status")),
                     "Files": "; ".join(str(r) for r in L(x.get("resources"))[:3])} for x in th[:30]]
            t = W.DataTable(["Time", "Threat", "Outcome", "Files"], [140, 260, 110, 480], mono=("Time", "Files"), max_rows_visible=8,
                            on_open=lambda r: self.app.text_popup("Detection", "\n".join("%s: %s" % (k, v) for k, v in r.items())))
            t.set_rows(rows, [None if r["Outcome"] in ("quarantined", "removed", "cleaned", "blocked") else "WARNING" for r in rows])
            p.body.setContentsMargins(0, 0, 0, 0)
            p.add(t)
        else:
            p.add(W.label("no detections", "Muted"))
        self.def_lay.addWidget(p)

    def _render_boot(self):
        F = [f for f in self.result.get("findings") or [] if f.get("category") in ("Boot security", "Drivers")]
        if not F:
            self.boot_list.set([("OK", "No problems: Secure Boot, driver signing, test-signing and kernel debugging checks passed.")])
            return
        items = []
        for f in F:
            detail = "\n".join(x for x in (f.get("why") or "", ("Fix: " + f["advice"]) if f.get("advice") else "") if x)
            items.append((f.get("severity") or "INFO", "[%s] %s" % (f.get("severity"), f.get("title")), detail))
        self.boot_list.set(items)

    # ------------------------------------------------------------------ row details
    def _entry_content(self, r):
        e = r.get("_entry") or {}
        if not e:
            return None
        sig = e.get("sig") or {}
        tgt = e.get("target") or {}
        secs = [("Why flagged", r.get("Why") or "Nothing unusual."), ("Command", (e.get("command") or "")[:400]),
                ("Where it is registered", e.get("location") or e.get("key") or ""),
                ("Signature", "%s  |  created %s  |  %s" % (security._sig_text(sig), (sig.get("created") or "?").replace("T", " "),
                                                            filetools.fmt_size(sig.get("size"))))]
        if tgt:
            secs.append(("DLL it loads", "%s  (%s)" % (tgt.get("path"), security._sig_text(tgt))))
        sha = (tgt or sig).get("sha256")
        if sha:
            secs.append(("SHA-256", sha))
            if sha in self.vt:
                secs.append(("VirusTotal", self._vt_text(self.vt[sha])))
        return {"title": "%s: %s" % (r.get("Type"), r.get("Name")), "badge": r.get("Verdict") if r.get("Verdict") in SEV else None, "sections": secs,
                "foot": "'REVIEW' = unusual but often legitimate."}

    def _proc_content(self, r):
        secs = [("Why flagged", r.get("Why") or "Listed because it has internet connections."), ("Command line", (r.get("_cmd") or "")[:400]),
                ("Connections", r.get("Connections")), ("Signature", r.get("Signature"))]
        if r.get("_sha"):
            secs.append(("SHA-256", r["_sha"]))
            if r["_sha"] in self.vt:
                secs.append(("VirusTotal", self._vt_text(self.vt[r["_sha"]])))
        return {"title": "%s (PID %s)" % (r.get("Process"), r.get("PID")), "badge": r.get("Verdict") if r.get("Verdict") != "OK" else None, "sections": secs}

    def _cert_content(self, r):
        c = r.get("_cert") or {}
        why = {"CRITICAL": "This root has a PRIVATE KEY on this PC - whoever has that key can impersonate any website to you.",
               "WARNING": "Not part of Microsoft's Trusted Root Program. Company PCs and some security products add their own roots; on a home PC this is suspicious.",
               "INFO": "Added by a known security/proxy product for HTTPS scanning."}.get(r.get("Verdict"), "Part of Microsoft's trusted root list.")
        return {"title": c.get("subject") or r.get("Subject") or "Certificate", "badge": r.get("Verdict") if r.get("Verdict") != "OK" else "OK",
                "sections": [("What this means", why), ("Issuer", c.get("issuer")),
                             ("Valid", "%s  to  %s" % ((c.get("notbefore") or "")[:10], (c.get("notafter") or "")[:10])),
                             ("Thumbprint", c.get("thumb")), ("Algorithm", "%s, %s-bit" % (c.get("alg"), c.get("keysize")))]}

    def _row_popup(self, kind, r):
        if not r:
            return
        c = {"entry": self._entry_content, "proc": self._proc_content, "cert": self._cert_content}[kind](r)
        if c:
            self.app.text_popup(c["title"], self.app.content_text(c))

    def _details(self, table, kind):
        r = table.selected()
        if not r:
            W.info(self, "Select a row first.")
            return
        self._row_popup(kind, r)

    # ------------------------------------------------------------------ actions
    def _open_loc(self, table):
        r = table.selected()
        if not r:
            W.info(self, "Select a row first.")
            return
        p = (r.get("_entry") or {}).get("path") or r.get("_path") or r.get("Program") or r.get("Path")
        if not p:
            return
        try:
            subprocess.Popen(["explorer.exe", "/select,", p])
        except Exception as e:
            W.error(self, "Could not open the file location:\n%s" % e)

    def _search(self, table):
        r = table.selected()
        if not r:
            W.info(self, "Select a row first.")
            return
        p = (r.get("_entry") or {}).get("path") or r.get("_path") or ""
        name = os.path.basename(p.replace("\\", "/")) or r.get("Name") or r.get("Process") or ""
        QDesktopServices.openUrl(QUrl("https://www.bing.com/search?q=%s" % urllib.parse.quote('"%s" %s' % (name, "what is this process"))))

    def _launch(self, target):
        try:
            core.open_tool(target)
        except Exception as e:
            W.error(self, "Could not open %s:\n%s" % (target, e))

    def _q_entry(self):
        r = self.t_entries.selected()
        if not r or not r.get("_entry"):
            W.info(self, "Select a startup item first.")
            return
        self.quarantine_item({"kind": "entry", "entry": r["_entry"]}, "%s: %s" % (r.get("Type"), r.get("Name")), r.get("Why") or "Chosen by user")

    def _q_proc(self):
        r = self.t_proc.selected()
        if not r or not r.get("_path"):
            W.info(self, "Select a program first.")
            return
        self.quarantine_item({"kind": "file", "path": r.get("_path")}, "Program: %s" % r.get("Process"), r.get("Why") or "Chosen by user")

    def _q_cert(self):
        r = self.t_cert.selected()
        if not r or not r.get("_cert"):
            W.info(self, "Select a certificate first.")
            return
        self.quarantine_item({"kind": "cert", "cert": r["_cert"]}, "Certificate: %s" % (r.get("Subject") or "")[:80],
                             "Root certificate flagged: %s" % r.get("Verdict"))

    def quarantine_finding(self, fd):
        self.quarantine_item(fd["item"], fd.get("title") or "", fd.get("why") or fd.get("title") or "")

    def quarantine_item(self, item, title, reason):
        if self.ops.running("quarantine"):
            self.app.set_status("A quarantine is still running - wait for it to finish.", "WARNING", hold=4)
            return
        if not self.app.pin.require("quarantine"):
            return
        if not self.app.is_admin:
            W.info(self, "Quarantine needs administrator rights.")
            return
        kind = item.get("kind")
        if kind not in Q_WHAT:
            return
        if not W.confirm(self, "%s\n\nWinDiag will %s.\n\n"
                               "A restore point is created first, and everything is saved so you can put it back with Files > Quarantine > Restore.\n\n"
                               "Continue?" % (title, Q_WHAT[kind]), "WinDiag - Quarantine", danger=True):
            return
        payload = {k: v for k, v in item.items() if k not in ("kind", "sha256")}

        def work():
            return filetools.quarantine(kind, title, reason, **payload)
        # not cancellable: a quarantine must not be cut off half-way (filetools runs it untracked)
        self.ops.start("quarantine", work, lambda res: self._q_done(title, res), "Quarantining %s..." % title,
                       buttons=[self.btn_q_entry, self.btn_q_proc, self.btn_q_cert], guard=True)

    def _q_done(self, title, res):
        errs = res.get("errors") or ([res["error"]] if res.get("error") else [])
        if isinstance(errs, str):
            errs = [errs]
        if res.get("ok"):
            msg = "Quarantined: %s" % title
            if res.get("pending_reboot"):
                msg += "\n\nThe file was in use - it will be removed at the next restart."
            if errs:
                msg += "\n\nNotes:\n" + "\n".join(str(e) for e in errs)
            msg += "\n\nIf something stops working, restore it from Files > Quarantine."
            W.info(self, msg)
        else:
            W.error(self, "Could not quarantine %s:\n%s" % (title, "\n".join(str(e) for e in errs) or res.get("detail", "unknown error")))
        self.app.set_status("Quarantine: %s" % ("done" if res.get("ok") else "failed"), None if res.get("ok") else "WARNING")
        fp = self.app.pages.get("files")
        if fp is not None and hasattr(fp, "refresh_quarantine"):
            fp.refresh_quarantine()

    # ------------------------------------------------------------------ VirusTotal
    @staticmethod
    def _vt_text(v):
        if v.get("error"):
            return v["error"]
        return "%d of %d engines flag it as malicious%s" % (v["malicious"], v["malicious"] + v["undetected"] + v["harmless"] + v["suspicious"],
                                                            (" (%s)" % v["label"]) if v.get("label") else "")

    def vt_lookup(self):
        key = self.vt_key.text().strip()
        if not key:
            W.info(self, "Enter your VirusTotal API key first (free account at virustotal.com).")
            return
        if not self.result:
            W.info(self, "Run the security scan first.")
            return
        if self.vt_remember.isChecked():
            S.put(vt_key=key)
        elif S.get("vt_key"):
            s = S.load_settings()
            s.pop("vt_key", None)
            S.save_settings(s)
        files = {}
        for r in self.result.get("entries") or []:
            e = r.get("_entry") or {}
            sig = e.get("target") or e.get("sig") or {}
            if r.get("Verdict") != "OK" and sig.get("sha256"):
                files[sig["sha256"]] = sig.get("path")
        for r in self.result.get("processes") or []:
            if r.get("_sha"):
                files[r["_sha"]] = r.get("_path")
        files = {h: p for h, p in files.items() if h not in self.vt}
        if not files:
            W.info(self, "No flagged unsigned files to look up.")
            return
        if len(files) > 3 and not W.confirm(self, "Look up %d files? With a free key this takes about %d minutes." % (len(files), len(files) // 4 + 1)):
            return
        hashes = list(files)

        def work(cancel, progress):
            out = {}
            try:
                for i, h in enumerate(hashes):
                    if cancel.is_set():
                        break
                    progress((i, len(hashes), "VirusTotal: checking %d of %d (free API allows 4 per minute)..." % (i + 1, len(hashes))))
                    r = security.vt_lookup(key, [h], None, delay=0)
                    out.update(r)
                    if (r.get(h) or {}).get("error") == "invalid API key":
                        break
                    if i < len(hashes) - 1 and cancel.wait(VT_DELAY):
                        break
            except Exception as e:
                core.log_error("security page vt_lookup", e)
                out["_err"] = {"error": core.friendly_error(e)}
            return out
        self.vt_files.update(files)
        self.ops.start("vt", work, self._vt_done, "Looking up %d file(s) on VirusTotal..." % len(hashes), cancellable=True, progress=True,
                       buttons=[self.btn_vt])

    def _vt_done(self, res):
        if res.get("error") and "_err" not in res:
            res = {"_err": {"error": res["error"]}}
        self.vt.update({h: v for h, v in res.items() if h != "_err" and isinstance(v, dict)})
        self._vt_table()
        self.app.set_status("VirusTotal lookup finished (%d files)." % len(self.vt))
        if res.get("_err"):
            W.error(self, "VirusTotal lookup failed: %s" % res["_err"].get("error"))

    def _vt_table(self):
        rows, tags = [], []
        for h, v in self.vt.items():
            if v.get("error"):
                verdict, det = "UNKNOWN", v["error"]
            else:
                m = v.get("malicious", 0)
                verdict = "MALICIOUS" if m >= 5 else ("SUSPICIOUS" if m >= 1 else "CLEAN")
                det = "%d / %d" % (m, m + v.get("undetected", 0) + v.get("harmless", 0) + v.get("suspicious", 0))
            rows.append({"Result": verdict, "File": self.vt_files.get(h, ""), "Detections": det, "Label": v.get("label", ""), "SHA-256": h,
                         "_link": v.get("link")})
            tags.append("CRITICAL" if verdict == "MALICIOUS" else ("WARNING" if verdict == "SUSPICIOUS" else ("OK" if verdict == "CLEAN" else None)))
        self.t_vt.set_rows(rows, tags)

    # ------------------------------------------------------------------ lifecycle
    def on_show(self):
        self.ops.on_show()

    def on_hide(self):
        self.ops.on_hide()

    def shutdown(self):
        self._closed = True
        self.ops.shutdown()
