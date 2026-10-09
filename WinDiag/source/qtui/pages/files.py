"""Files & Recovery page: Quarantine (restore), Recover deleted files, Secure delete. Logic: filetools.py (unchanged)."""
import os

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QLineEdit, QPlainTextEdit, QTabWidget, QVBoxLayout, QWidget

import core
import filetools as ft
from .. import theme as T
from .. import widgets as W
from ._ops import BusyStrip, Ops, bottom, field, flow, mono_input, selected_rows

TABS = ("Quarantine", "Recover deleted files", "Secure delete")
DQ_DAYS = ["1 day", "7 days", "30 days", "90 days (Windows default)", "Never"]
WINFR_HELP = "https://support.microsoft.com/windows/recover-lost-files-on-windows-10-61f5b28a-f5b8-3cc2-0f8e-a63cb4e1d4c4"


def _as_list(x):
    if x is None or x == "":
        return []
    return x if isinstance(x, list) else [x]


def _errs(res):
    e = res.get("errors") or res.get("error") or []
    return [str(x) for x in ([e] if isinstance(e, str) else list(e))]


def _list_drives():
    """Worker: drive letters + this app's own drive (os.path.exists on A:-Z: can hang on empty card readers)."""
    return {"drives": ft.drives(), "app": core.app_dir()[:2].upper()}


def default_dest(src, drives, app_drive):
    """winfr must save to a DIFFERENT drive than the one searched: the USB stick if WinDiag runs from one, else any other drive."""
    src = (src or "C:")[:2].upper()
    cands = [app_drive] + [d.upper() for d in drives if d.upper() not in ("A:", "B:")]
    other = next((d for d in cands if len(d) == 2 and d[1] == ":" and d != src), None)
    return os.path.join(other + "\\", "Recovered") if other else ""


class FilesPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        self.shadows, self.recycle, self.del_paths = [], [], []
        self.winfr_installed = None
        self.drive_list, self.app_drive = [], ""
        self._loaded = False
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        top = QWidget()
        tv = QVBoxLayout(top)
        tv.setContentsMargins(T.S5, T.S4, T.S5, T.S3)
        tv.setSpacing(T.S3)
        tv.addWidget(W.label("Undo quarantines, get deleted files back, or delete files so they can't be recovered.", "Body", wrap=True))
        self.strip = BusyStrip(lambda: self.ops.cancel())
        tv.addWidget(self.strip)
        v.addWidget(top)
        self.ops = Ops(self, self.strip)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        v.addWidget(self.tabs, 1)
        self._build_quarantine()
        self._build_recover()
        self._build_secdel()

    def open_tab(self, name):
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == name:
                self.tabs.setCurrentIndex(i)

    # ------------------------------------------------------------------ helpers
    def _run(self, key, fn, done, msg=None, cancellable=False, kill=(), buttons=(), guard=False):
        return self.ops.start(key, fn, done, msg or "", cancellable=cancellable, kill=kill, buttons=buttons, guard=guard)

    def _need_admin(self):
        if not self.app.is_admin:
            W.info(self, "This needs administrator rights. Use 'Restart as admin'.")
            return True
        return False

    def _tool(self, target):
        try:
            core.open_tool(target)
        except Exception as e:
            W.error(self, "Could not open %s:\n%s" % (target, e))

    def _url(self, url):
        QDesktopServices.openUrl(QUrl(url))

    def _open_folder(self, path):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            W.error(self, str(e))
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(path)):
            W.error(self, "Could not open %s" % path)

    @staticmethod
    def _note(text, color=None):
        return W.colored(text, color, 12) if color else W.label(text, "Body", wrap=True)

    # ------------------------------------------------------------------ Quarantine tab
    def _build_quarantine(self):
        sp = W.ScrollPage(spacing=T.S5)
        self.tabs.addTab(sp, "Quarantine")
        p = W.Panel("WinDiag quarantine",
                    "Items removed with WinDiag's 'Quarantine' button. Files are stored neutralised (they can't run) together with everything needed "
                    "to put them back (startup entry, task, service, certificate, permissions, timestamps). Double-click a row for details.")
        p.add(W.label(ft.QROOT, "ValueMono", sel=True))
        self.t_q = W.DataTable(["Time", "What", "Items", "State", "Reason"], [140, 360, 60, 110, 360], on_open=self._q_popup,
                               mono=("Time", "Items"), max_rows_visible=8)
        p.add(self.t_q)
        self.btn_restore = W.button("Restore selected", self.restore_selected, "primary", icon="refresh")
        self.btn_qrefresh = W.button("Refresh", self.refresh_quarantine, icon="refresh")
        self.btn_purge = W.button("Delete items older than 30 days", self.purge, "danger")
        p.add(flow(self.btn_restore, self.btn_qrefresh, W.button("Open quarantine folder", lambda: self._open_folder(ft.QROOT), icon="folder"),
                   W.button("Details", lambda: self._q_popup(self.t_q.selected()), icon="info"), self.btn_purge))
        sp.add(p)

        p = W.Panel("Microsoft Defender quarantine",
                    "Files Microsoft Defender removed. Only restore something if you are SURE it is safe (for example a known false positive) - "
                    "Defender may need an exclusion or it will quarantine it again.")
        self.btn_dq_load = W.button("Load Defender quarantine", self.load_defender, "primary", icon="download")
        self.btn_dq_restore = W.button("Restore selected threat", self.restore_defender, icon="refresh")
        p.add(flow(self.btn_dq_load, self.btn_dq_restore, W.button("Protection history", lambda: self._tool("windowsdefender://threat"), icon="shield")))
        self.t_dq = W.DataTable(["Threat", "Files"], [300, 700], mono=("Files",), max_rows_visible=6,
                                on_open=lambda r: r and self.app.text_popup("Defender quarantine", "Threat: %s\n\nFiles:\n%s" % (
                                    r.get("Threat"), "\n".join(_as_list(r.get("_files"))))))
        p.add(self.t_dq)
        sp.add(p)

        p = W.Panel("Permanently delete Defender's quarantined files",
                    "Quarantined files are already locked away and harmless. Windows has three supported ways to remove them for good - WinDiag uses "
                    "only these (it never touches Defender's protected quarantine folder directly):")
        self.btn_dq_remove = W.button("Remove active threats", self.defender_remove_active, "danger")
        self.dq_days = QComboBox()
        self.dq_days.addItems(DQ_DAYS)
        self.dq_days.setCurrentText("90 days (Windows default)")
        self.btn_dq_apply = W.button("Apply", self.defender_set_purge)
        p.add(flow(W.button("Delete one item...", self.defender_delete_one), self.btn_dq_remove))
        p.add(flow(field("Auto-delete quarantine after", self.dq_days, 220), bottom(self.btn_dq_apply)))
        self.dq_now = W.label("Current setting: load the quarantine to see it.", "Muted", wrap=True)
        p.add(self.dq_now)
        sp.add(p)
        sp.finish()

    def refresh_quarantine(self):
        self._run("qlist", ft.list_quarantine, self._q_listed, None, buttons=[self.btn_qrefresh])

    def _q_listed(self, res):
        if isinstance(res, dict):            # error
            self.app.set_status("Could not read the quarantine folder: %s" % res.get("error"), "WARNING")
            res = []
        rows, tags = [], []
        for m in res:
            items = _as_list(m.get("items"))
            rows.append({"Time": (m.get("time") or "").replace("T", " ")[:16], "What": m.get("title"), "Items": len(items),
                         "State": m.get("state"), "Reason": m.get("reason"), "_m": m})
            tags.append(None if m.get("state") == "restored" else "WARNING")
        if not rows:
            rows, tags = [{"Time": "", "What": "Nothing quarantined", "Items": "", "State": "", "Reason": ""}], [None]
        self.t_q.set_rows(rows, tags)

    def _q_content(self, r):
        m = (r or {}).get("_m")
        if not m:
            return None
        errs = m.get("errors") or []
        return {"title": m.get("title") or "", "badge": "INFO" if m.get("state") == "restored" else "WARNING",
                "sub": "Quarantined %s  |  ID %s" % (r.get("Time"), m.get("id")),
                "sections": [("What was removed", ft.item_summary(m)), ("Reason", m.get("reason")),
                             ("Notes", [str(e) for e in (errs if isinstance(errs, list) else [errs])]),
                             ("Restored", (m.get("restored") or "").replace("T", " "))],
                "foot": "Restore puts every item back. A file that already exists again is restored as <name>.restored."}

    def _q_popup(self, r):
        c = self._q_content(r)
        if c:
            self.app.text_popup(c["title"], self.app.content_text(c))
        elif r is None:
            W.info(self, "Select an item first.")

    def restore_selected(self):
        if self._need_admin() or not self.app.pin.require("restoring from quarantine"):
            return
        r = self.t_q.selected()
        if not r or not r.get("_m"):
            W.info(self, "Select an item to restore.")
            return
        m = r["_m"]
        if m.get("state") == "restored" and not W.confirm(self, "This item was already restored. Restore again?"):
            return
        if not W.confirm(self, "Put back:\n\n- %s\n\nOnly do this if you are sure it is safe." % "\n- ".join(str(x) for x in ft.item_summary(m)),
                         "WinDiag - Restore", danger=True):
            return
        self._run("qrestore", lambda: ft.restore(m["id"]), self._restored, "Restoring %s..." % m.get("title"), buttons=[self.btn_restore], guard=True)

    def _restored(self, res):
        if res.get("ok"):
            W.info(self, "Restored %s item(s)." % res.get("restored"))
        else:
            W.error(self, "Restore finished with problems:\n%s" % "\n".join(_errs(res)))
        self.app.set_status("Restore finished.")
        self.refresh_quarantine()

    def purge(self):
        if not self.app.pin.require("deleting quarantined items"):
            return
        if not W.confirm(self, "Permanently delete quarantined items older than 30 days? They can't be restored afterwards.", danger=True):
            return

        def done(n):
            if not isinstance(n, int):
                W.error(self, "Could not delete: %s" % (n.get("error") if isinstance(n, dict) else n))
                n = 0
            self.app.set_status("Deleted %d old quarantine item(s)." % n)
            self.refresh_quarantine()
        self._run("qpurge", lambda: ft.purge(30), done, "Deleting old quarantine items...",
                  buttons=[self.btn_purge], guard=True)

    def load_defender(self):
        if self._need_admin():
            return
        self._run("dq", lambda: core.run_ps_json(ft.DEFENDER_Q_PS, 120, "Defender quarantine"), self._dq_loaded, "Reading Defender quarantine...",
                  cancellable=True, kill=("Defender quarantine",), buttons=[self.btn_dq_load])

    def _dq_loaded(self, res):
        items = _as_list(res.get("items"))
        rows = [{"Threat": i.get("threat"), "Files": "; ".join(str(x) for x in _as_list(i.get("files"))), "_files": _as_list(i.get("files"))}
                for i in items if isinstance(i, dict)]
        self.t_dq.set_rows(rows)
        err = res.get("detail") or res.get("error")
        self.app.set_status("Defender quarantine: %d item(s)." % len(rows) if not err else str(err)[:150], "WARNING" if err and not rows else None)
        pdays = res.get("purge_days")
        txt, col = self.dq_now.text(), None
        if pdays is not None:
            try:
                txt = "Current setting: quarantined items are deleted after %s." % ("never (kept forever)" if int(pdays) == 0 else "%s day(s)" % pdays)
            except (TypeError, ValueError):
                pass
        act = _as_list(res.get("active"))
        if act:
            txt += "   Active (not yet removed) threats: " + ", ".join(str(a) for a in act[:3])
            col = T.CRIT
        self.dq_now.setText(txt)
        self.dq_now.setStyleSheet("color:%s;" % col if col else "")

    def defender_delete_one(self):
        W.info(self, "Windows Security will open on Protection history.\n\n"
                     "1. Click the item (\"Threat quarantined\").\n2. Click Actions > Remove.\n\n"
                     "Remove = permanently delete the file.  Restore = put it back (only for false positives).", "WinDiag - delete one quarantined item")
        self._tool("windowsdefender://threat")

    def defender_remove_active(self):
        if self._need_admin() or not self.app.pin.require("removing Defender threats"):
            return
        if not W.confirm(self, "Ask Microsoft Defender to remove all ACTIVE threats it has detected (Remove-MpThreat)?\n\n"
                               "Items already in quarantine are not affected - use Auto-delete or Protection history for those.", danger=True):
            return

        def done(r):
            if not r.get("ok"):
                W.error(self, "Defender said: %s" % str(r.get("detail") or r.get("error") or "unknown error")[:300])
                return
            b, a = _as_list(r.get("before")), _as_list(r.get("after"))
            W.info(self, "No active threats - nothing to remove." if not b else
                   "Active threats before: %d, after: %d.%s" % (len(b), len(a), " Run a Defender Offline scan for the rest." if a else ""))
            self.load_defender()
        self._run("dqremove", lambda: core.run_ps_json(ft.DEFENDER_REMOVE_ACTIVE_PS, 180, "Remove Defender threats"), done,
                  "Asking Defender to remove active threats...", buttons=[self.btn_dq_remove], guard=True)

    def defender_set_purge(self):
        if self._need_admin() or not self.app.pin.require("changing Defender quarantine settings"):
            return
        v = self.dq_days.currentText()
        days = 0 if v.startswith("Never") else int(v.split()[0])
        extra = ("\n\nItems already older than %d day(s) are deleted the next time Defender runs its clean-up (usually within a day). "
                 "They can't be restored after that." % days) if days else "\n\nNothing will be deleted automatically."
        if not W.confirm(self, "Set Defender to keep quarantined items for %s?%s" % (v, extra), danger=bool(days)):
            return

        def done(r):
            if r.get("ok"):
                self.dq_now.setText("Current setting: quarantined items are deleted after %s." % ("never" if not days else "%d day(s)" % days))
                self.dq_now.setStyleSheet("")
                self.app.set_status("Defender quarantine auto-delete set to %s." % v)
            else:
                W.error(self, "Not changed: %s" % str(r.get("detail") or r.get("error") or "unknown error")[:300])
        self._run("dqpurge", lambda: ft.run_with_args(ft.DEFENDER_PURGE_PS, {"days": days}, 60, track=False), done, "Changing Defender setting...",
                  buttons=[self.btn_dq_apply], guard=True)

    def restore_defender(self):
        if not self.app.pin.require("restoring from Defender quarantine"):
            return
        r = self.t_dq.selected()
        if not r or not r.get("Threat"):
            W.info(self, "Load the list and select a threat first.")
            return
        name = r["Threat"]
        if not W.confirm(self, "Restore everything Defender quarantined as:\n\n%s\n\n"
                               "Defender thought this was malware. Only continue if you are CERTAIN it is a false positive." % name,
                         "WinDiag - Restore from Defender", danger=True):
            return
        self._run("dqrestore", lambda: ft.run_with_args(ft.DEFENDER_RESTORE_PS, {"threat": name}, 120, track=False),
                  lambda res: W.info(self, ("Restored." if res.get("ok") else "Defender said: ") + str(res.get("detail") or res.get("error") or "")[:400]),
                  "Restoring %s from Defender quarantine..." % name, buttons=[self.btn_dq_restore], guard=True)

    # ------------------------------------------------------------------ Recover tab
    def _build_recover(self):
        sp = W.ScrollPage(spacing=T.S5)
        self.tabs.addTab(sp, "Recover deleted files")
        sp.add(W.Banner("IMPORTANT: stop saving/installing things on the drive the file was on - new data can overwrite it.", "Try these in order.",
                        "WARNING"))

        p = W.Panel("1. Recycle Bin (all users, all drives)")
        self.btn_rb_load = W.button("Load Recycle Bin", self.load_recycle, "primary", icon="download")
        self.rb_filter = QLineEdit()
        self.rb_filter.setPlaceholderText("Filter by name...")
        self.rb_filter.setMinimumWidth(220)
        self.rb_filter.textChanged.connect(lambda _=None: self._show_recycle())
        self.btn_rb_restore = W.button("Restore selected", self.restore_recycle, icon="refresh")
        p.add(flow(self.btn_rb_load, self.rb_filter, self.btn_rb_restore))
        self.t_rb = W.DataTable(["Original location", "Size", "Deleted", "User"], [520, 90, 140, 200], mono=("Original location", "Size", "Deleted"),
                                max_rows_visible=8)
        self.t_rb.setSelectionMode(QAbstractItemView.ExtendedSelection)
        p.add(self.t_rb)
        p.add(W.label("Select one or more files (Ctrl/Shift-click).", "Muted"))
        sp.add(p)

        p = W.Panel("2. Previous Versions (shadow copies / restore points)",
                    "Windows keeps snapshots of the drive with restore points. Older versions of a file - or deleted files - can be copied out of them.")
        self.btn_sh_list = W.button("List snapshots", self.load_shadows, "primary", icon="search")
        self.sh_path = QLineEdit()
        self.sh_path.setPlaceholderText(r"File or folder that was lost, e.g. C:\Users\me\Documents\report.docx")
        mono_input(self.sh_path)
        self.btn_sh_find = W.button("Find in snapshots", self.find_shadow, icon="search")
        p.add(flow(self.btn_sh_list))
        p.add(flow(field("Lost file or folder", self.sh_path, 440), bottom(W.button("Browse...", self._browse_sh, icon="folder")),
                   bottom(self.btn_sh_find)))
        self.lbl_sh = W.label("", "Body", wrap=True)
        p.add(self.lbl_sh)
        self.t_sh = W.DataTable(["Snapshot", "Drive", "Found"], [160, 70, 700], mono=("Snapshot", "Drive", "Found"), max_rows_visible=6)
        p.add(self.t_sh)
        self.btn_sh_copy = W.button("Copy selected version to...", self.copy_shadow, icon="copy")
        self.btn_sh_mount = W.button("Open snapshot as folder", self.mount_shadow, icon="folder")
        self.btn_sh_unmount = W.button("Remove snapshot folders", self.unmount_shadow)
        p.add(flow(self.btn_sh_copy, self.btn_sh_mount, self.btn_sh_unmount))
        sp.add(p)

        p = W.Panel("3. Backups")
        p.add(flow(W.button("File History - restore", lambda: self._tool("FileHistory.exe")),
                   W.button("OneDrive recycle bin", lambda: self._url("https://onedrive.live.com/?v=recyclebin"), icon="cloud"),
                   W.button("Backup and Restore (Win 7)", lambda: self._tool("sdclt.exe"))))
        p.add(self._note("OneDrive keeps deleted files for 30 days (93 for work/school accounts). File History only works if it was turned on before."))
        sp.add(p)

        p = W.Panel("4. Windows File Recovery (Microsoft's undelete tool - last resort)",
                    "Scans the drive for deleted files. Works well on hard drives and USB sticks; on SSDs deleted files are usually wiped by TRIM within "
                    "seconds, so chances are low. Results MUST be saved to a different drive (e.g. this USB stick).")
        self.wf_src = QComboBox()
        self.wf_src.addItems(["C:"])
        self.wf_src.activated.connect(lambda _=None: self._check_media(self.wf_src.currentText()))
        self.wf_dest = QLineEdit()
        mono_input(self.wf_dest)
        self.wf_mode = QComboBox()
        self.wf_mode.addItems(["regular", "extensive"])
        self.wf_pat = QLineEdit()
        mono_input(self.wf_pat)
        self.wf_pat.setPlaceholderText(r"e.g. \Users\me\Documents\  or  *.docx")
        p.add(flow(field("Search drive", self.wf_src, 80), field("Save to", self.wf_dest, 240), field("Mode", self.wf_mode, 120),
                   field("File name / folder (optional)", self.wf_pat, 240)))
        self.btn_winfr = W.button("Run winfr", self.run_winfr, "primary", icon="play")
        p.add(flow(self.btn_winfr, W.button("Install winfr (winget)", self._install_winfr, icon="download"),
                   W.button("Microsoft Store page", lambda: self._tool(ft.WINFR_STORE)), W.button("How winfr works", lambda: self._url(WINFR_HELP), "link")))
        self.lbl_media = W.label("", "Body", wrap=True)
        p.add(self.lbl_media)
        p.add(self._note("Regular mode: recently deleted files on NTFS. Extensive: formatted/corrupted drives, FAT/exFAT, files deleted long ago."))
        sp.add(p)
        sp.finish()

    def _install_winfr(self):
        try:
            ft.open_console(ft.winfr_install_cmd(), "Install Windows File Recovery")
        except Exception as e:
            W.error(self, "Could not start winget:\n%s" % e)

    def load_recycle(self):
        self._run("rb", lambda: core.run_ps_json(ft.RECYCLE_LIST_PS, 180, "Recycle Bin"), self._recycle_loaded, "Reading Recycle Bins...",
                  cancellable=True, kill=("Recycle Bin",), buttons=[self.btn_rb_load])

    def _recycle_loaded(self, res):
        if res.get("status") == "error" and "items" not in res:
            self.app.set_status("Could not read the Recycle Bin: %s" % str(res.get("detail") or res.get("error"))[:150], "WARNING")
            return
        self.recycle = [i for i in _as_list(res.get("items")) if isinstance(i, dict)]
        self._show_recycle()
        self.app.set_status("Recycle Bin: %d item(s)%s." % (len(self.recycle), "" if self.app.is_admin else " (only yours - run as admin to see all users)"))

    def _show_recycle(self):
        q = self.rb_filter.text().strip().lower()
        rows = [{"Original location": i.get("original"), "Size": ft.fmt_size(i.get("size")), "Deleted": (i.get("deleted") or "").replace("T", " ")[:16],
                 "User": i.get("user"), "_i": i} for i in self.recycle if not q or q in (i.get("original") or "").lower()]
        self.t_rb.set_rows(rows[:2000])

    def restore_recycle(self):
        sel = [r["_i"] for r in selected_rows(self.t_rb) if r.get("_i")]
        if not sel:
            W.info(self, "Select one or more files (Ctrl/Shift-click).")
            return
        if not W.confirm(self, "Restore %d item(s) to their original location?\n(Existing files are not overwritten - a '(restored)' copy is made.)" % len(sel)):
            return
        self._run("rbrestore", lambda: ft.run_with_args(ft.RECYCLE_RESTORE_PS, {"items": sel}, 600, track=False), self._recycle_restored,
                  "Restoring from Recycle Bin...", buttons=[self.btn_rb_restore], guard=True)

    def _recycle_restored(self, res):
        errs = _errs(res)
        where = [str(x) for x in _as_list(res.get("restored_to"))]
        n = res.get("ok", 0)
        W.info(self, "Restored %s item(s).%s%s" % (n if not isinstance(n, bool) else int(n), ("\n\n" + "\n".join(where[:10])) if where else "",
                                                   ("\n\nProblems:\n" + "\n".join(errs[:10])) if errs else ""))
        self.load_recycle()

    def load_shadows(self):
        self._run("shlist", lambda: core.run_ps_json(ft.SHADOW_LIST_PS, 120, "Snapshots"), self._shadows_loaded, "Listing snapshots...",
                  cancellable=True, kill=("Snapshots",), buttons=[self.btn_sh_list])

    def _shadows_loaded(self, res):
        if res.get("status") == "error" and "shadows" not in res:
            self.lbl_sh.setText("Could not list snapshots: %s" % str(res.get("detail") or res.get("error"))[:200])
            return
        self.shadows = [s for s in _as_list(res.get("shadows")) if isinstance(s, dict)]
        self.winfr_installed = res.get("winfr")
        self.t_sh.set_rows([{"Snapshot": (x.get("time") or "").replace("T", " ")[:16], "Drive": x.get("drive"), "Found": x.get("device"), "_s": x}
                            for x in self.shadows])
        txt = "%d snapshot(s)." % len(self.shadows)
        if not self.shadows:
            txt = "No snapshots found. System Protection may be off (Control Panel > System > System Protection)." + ("" if self.app.is_admin else " Run as admin to see them.")
        txt += "   File History: %s.   winfr: %s." % ("set up" if res.get("filehistory_configured") else "not set up", "installed" if res.get("winfr") else "not installed")
        self.lbl_sh.setText(txt)

    def _browse_sh(self):
        p, _ = QFileDialog.getOpenFileName(self, "File that was changed/deleted (pick any file in the folder if it's gone)")
        if p:
            self.sh_path.setText(os.path.normpath(p))

    def find_shadow(self):
        p = self.sh_path.text().strip().strip('"')
        if len(p) < 3 or p[1] != ":":
            W.info(self, "Enter the full path of the lost file or folder (e.g. C:\\Users\\me\\Documents\\report.docx).")
            return
        if not self.shadows:
            W.info(self, "Click 'List snapshots' first.")
            return
        shadows = list(self.shadows)
        self._run("shfind", lambda: ft.run_with_args(ft.SHADOW_FIND_PS, {"path": p, "shadows": shadows}, 300), self._found, "Searching snapshots...",
                  cancellable=True, kill=("File tools",), buttons=[self.btn_sh_find])

    def _found(self, res):
        if res.get("error") and "hits" not in res:
            self.lbl_sh.setText("Search failed: %s" % str(res.get("error"))[:200])
            return
        h = [x for x in _as_list(res.get("hits")) if isinstance(x, dict)]
        self.t_sh.set_rows([{"Snapshot": (x.get("snapshot") or "").replace("T", " ")[:16], "Drive": "", "Found": x.get("listing") or x.get("source"), "_h": x}
                            for x in h])
        self.lbl_sh.setText("Found in %d snapshot(s). Select one and click 'Copy selected version to...'." % len(h) if h else "Not found in any snapshot.")

    def copy_shadow(self):
        r = self.t_sh.selected()
        if not r or not r.get("_h"):
            W.info(self, "Use 'Find in snapshots' and select a version first.")
            return
        h = r["_h"]
        dest = QFileDialog.getExistingDirectory(self, "Where should the recovered copy go?", os.path.join(os.path.expanduser("~"), "Desktop"))
        if not dest:
            return
        dest = os.path.normpath(dest)
        stamp = (h.get("snapshot") or "")[:16].replace(":", "").replace("T", "_").replace("-", "")
        self._run("shcopy", lambda: ft.run_with_args(ft.SHADOW_COPY_PS, {"source": h["source"], "dest": dest, "stamp": stamp}, 900, track=False),
                  lambda res: W.info(self, ("Copied to:\n%s" % res.get("target")) if res.get("ok") else "Copy failed: %s" % (res.get("detail") or res.get("error"))),
                  "Copying from snapshot...", buttons=[self.btn_sh_copy], guard=True)

    def mount_shadow(self):
        r = self.t_sh.selected()
        s = (r or {}).get("_s")
        if not s:
            if not r or not r.get("_h"):
                W.info(self, "Click 'List snapshots' and select a snapshot.")
                return
            s = {"device": r["_h"].get("device"), "time": r["_h"].get("snapshot"), "drive": ""}
        name = "%s_%s" % ((s.get("drive") or "X").strip(":"), (s.get("time") or "")[:16].replace(":", "").replace("T", "_"))

        def done(res):
            if res.get("ok") and res.get("link"):
                if not QDesktopServices.openUrl(QUrl.fromLocalFile(res["link"])):
                    W.error(self, "Could not open: %s" % res["link"])
            else:
                W.error(self, "Could not open: %s" % (res.get("detail") or res.get("error")))
        self._run("shmount", lambda: ft.run_with_args(ft.SHADOW_MOUNT_PS, {"root": ft.SNAPROOT, "name": name, "device": s["device"]}, 60, track=False),
                  done, "Opening snapshot...", buttons=[self.btn_sh_mount])

    def unmount_shadow(self):
        self._run("shunmount", lambda: ft.run_with_args(ft.SHADOW_UNMOUNT_PS, {"root": ft.SNAPROOT}, 60, track=False),
                  lambda res: self.app.set_status("Removed %s snapshot folder link(s)." % res.get("removed", 0)), "Removing snapshot folders...",
                  buttons=[self.btn_sh_unmount])

    def _check_media(self, drive):
        if not drive:
            return
        cur = self.wf_dest.text().strip()
        if not cur or cur[:2].upper() == drive[:2].upper():
            self.wf_dest.setText(default_dest(drive, self.drive_list, self.app_drive))

        def done(r):
            if r.get("media") == "SSD":
                self.lbl_media.setText("%s is an SSD (%s) - deleted files are usually erased by TRIM; recovery chances are low." % (drive, r.get("model")))
                self.lbl_media.setStyleSheet("color:%s;" % T.WARN)
            elif r.get("media"):
                self.lbl_media.setText("%s is %s (%s)." % (drive, r.get("media"), r.get("model")))
                self.lbl_media.setStyleSheet("")
        self.ops.cancel("media")            # only the newest drive choice matters
        self._run("media", lambda: ft.run_with_args(ft.MEDIA_PS, {"drive": drive}, 30), done, None)

    def run_winfr(self):
        if self._need_admin():
            return
        try:
            cmd = ft.winfr_command(self.wf_src.currentText(), self.wf_dest.text().strip(), self.wf_mode.currentText(), self.wf_pat.text().strip())
        except ValueError as e:
            W.error(self, str(e))
            return
        if self.winfr_installed is False and not W.confirm(self, "winfr doesn't seem to be installed. Try anyway?"):
            return
        try:
            ft.open_console(cmd, "Windows File Recovery")
        except Exception as e:
            W.error(self, "Could not start winfr:\n%s" % e)
            return
        self.app.set_status("Started: %s" % cmd)

    # ------------------------------------------------------------------ Secure delete tab
    def _build_secdel(self):
        sp = W.ScrollPage(spacing=T.S5)
        self.tabs.addTab(sp, "Secure delete")
        p = W.Panel("Delete files so they can't be recovered")
        p.add(W.Banner("This is permanent - there is NO undo and it bypasses the Recycle Bin.",
                       "Overwrites each file with random data, renames it and deletes it.\n"
                       "Honest limits: on hard drives this works well. On SSDs/USB sticks the drive may keep old copies in spare areas, so overwriting is not "
                       "guaranteed - use BitLocker, or 'Reset this PC' with 'Clean data' / the maker's Secure Erase tool when getting rid of an SSD. "
                       "Copies in OneDrive, backups, shadow copies or e-mail are not touched.", "WARNING"))
        self.passes = QComboBox()
        self.passes.addItems(["1", "3"])
        self.btn_add_files = W.button("Add files...", self._add_files, icon="report")
        self.btn_add_folder = W.button("Add folder...", self._add_folder, icon="folder")
        self.btn_clear_del = W.button("Clear list", self._clear_del, "ghost")
        p.add(flow(bottom(self.btn_add_files), bottom(self.btn_add_folder), bottom(self.btn_clear_del), field("Passes", self.passes, 70)))
        self.del_box = QPlainTextEdit()
        self.del_box.setReadOnly(True)
        mono_input(self.del_box)
        self.del_box.setMinimumHeight(110)
        self.del_box.setMaximumHeight(180)
        p.add(self.del_box)
        self.del_ok = QCheckBox("I understand these files will be gone for good")
        p.add(self.del_ok)
        self.btn_secdel = W.button("Securely delete", self.secure_delete, "danger")
        p.add(flow(self.btn_secdel))
        p.add(W.label("Windows, Program Files, whole drives and user-profile roots are refused.", "Muted", wrap=True))
        sp.add(p)

        p = W.Panel("Wipe free space (already-deleted files)",
                    "Microsoft's 'cipher /w' overwrites all FREE space on a drive so files deleted earlier can't be recovered. Takes a long time on big drives. "
                    "On SSDs, Windows' TRIM (Optimize Drives) already discards freed space - cipher adds little there.")
        self.cw_drive = QComboBox()
        self.cw_drive.addItems(["C:"])
        p.add(flow(field("Drive", self.cw_drive, 80), bottom(W.button("Wipe free space (cipher /w)", self.cipher_wipe)),
                   bottom(W.button("Run TRIM (Optimize Drives)", lambda: self._tool("dfrgui.exe")))))
        sp.add(p)

        p = W.Panel("Giving away / selling the PC",
                    "Use Windows' own reset: Settings > System > Recovery > Reset this PC > Remove everything > Change settings > 'Clean data' = On. "
                    "This is the method Microsoft recommends before handing a PC to someone else.")
        p.add(flow(W.button("Open Recovery settings", lambda: self._tool("ms-settings:recovery"), icon="gear")))
        sp.add(p)
        sp.finish()
        self._refresh_del()

    def _refresh_del(self):
        self.del_box.setPlainText("\n".join(self.del_paths) or "(nothing selected)")

    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Files to securely delete")
        for p in files:
            p = os.path.normpath(p)
            if p not in self.del_paths:
                self.del_paths.append(p)
        self._refresh_del()

    def _add_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Folder to securely delete (everything inside it)")
        if p:
            p = os.path.normpath(p)
            if p not in self.del_paths:
                self.del_paths.append(p)
        self._refresh_del()

    def _clear_del(self):
        if self.ops.running("secdel"):
            return
        self.del_paths = []
        self._refresh_del()

    def secure_delete(self):
        if self.ops.running("secdel"):
            self.app.set_status("Secure delete is still running.", "WARNING", hold=4)
            return
        if not self.app.pin.require("secure delete"):
            return
        if not self.del_paths:
            W.info(self, "Add files or a folder first.")
            return
        if not self.del_ok.isChecked():
            W.info(self, "Tick 'I understand...' first.")
            return
        if not W.confirm(self, "Permanently destroy %d item(s)?\n\n%s\n\nThis cannot be undone." % (len(self.del_paths), "\n".join(self.del_paths[:8])),
                         "WinDiag - PERMANENT delete", danger=True):
            return
        paths, passes = list(self.del_paths), int(self.passes.currentText())
        # not cancellable on purpose: stopping half-way would leave files partly overwritten (filetools runs it untracked)
        self._run("secdel", lambda: ft.run_with_args(ft.SECDEL_PS, {"paths": paths, "passes": passes}, 7200, track=False), self._deleted,
                  "Securely deleting %d item(s) - this can take a while and can't be interrupted safely..." % len(paths),
                  buttons=[self.btn_secdel, self.btn_add_files, self.btn_add_folder, self.btn_clear_del], guard=True)

    def _deleted(self, res):
        errs = _errs(res)
        W.info(self, "Securely deleted %s file(s).%s" % (res.get("files", 0), ("\n\nProblems:\n" + "\n".join(errs[:10])) if errs else ""))
        self.del_ok.setChecked(False)
        self._clear_del()
        self.app.set_status("Secure delete finished.")

    def cipher_wipe(self):
        if not self.app.pin.require("wiping free space"):
            return
        d = self.cw_drive.currentText()
        if not W.confirm(self, "Overwrite all free space on %s? This can take hours and the drive will be busy. Existing files are NOT touched." % d):
            return
        try:
            ft.open_console("cipher /w:%s\\" % d, "Wipe free space %s" % d)
        except Exception as e:
            W.error(self, "Could not start cipher:\n%s" % e)

    # ------------------------------------------------------------------ lifecycle
    def render(self):
        if self._loaded:
            return
        self._loaded = True
        self.refresh_quarantine()
        self._run("drives", _list_drives, self._drives_loaded, None)

    def _drives_loaded(self, res):
        if not isinstance(res, dict) or res.get("error"):
            return
        self.drive_list = list(res.get("drives") or [])
        self.app_drive = res.get("app") or ""
        ds = self.drive_list or ["C:"]
        for cb in (self.wf_src, self.cw_drive):
            cur = cb.currentText()
            cb.clear()
            cb.addItems(ds)
            if cur in ds:
                cb.setCurrentText(cur)
        if not self.wf_dest.text().strip():
            self.wf_dest.setText(default_dest(self.wf_src.currentText(), self.drive_list, self.app_drive))

    def on_show(self):
        self.ops.on_show()

    def on_hide(self):
        self.ops.on_hide()

    def shutdown(self):
        self.ops.shutdown()
