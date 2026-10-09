"""Small helpers shared by the Security Scan and Files & Recovery pages (private to those two pages).

FlowLayout   - wrapping row of buttons/inputs (bars never force the window wider at 150-200 % scaling)
FillTable    - DataTable that fills the free height of a tab instead of sizing to its row count
selected_rows- every selected row (DataTable.selected() only returns the first)
Ops          - background operations of a page: QThread worker per op, busy strip with elapsed time / progress / Cancel,
               late results of cancelled ops are dropped, shutdown() cancels everything.
"""
import threading
import time

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, QSize, Qt, QTimer
from PySide6.QtWidgets import QAbstractItemView, QFrame, QHBoxLayout, QLayout, QProgressBar, QSizePolicy, QVBoxLayout, QWidget

import core
from .. import tasks
from .. import theme as T
from .. import widgets as W


# ---------------------------------------------------------------------------------
#  Flow layout (Qt's standard example, trimmed)
# ---------------------------------------------------------------------------------
class FlowLayout(QLayout):
    def __init__(self, parent=None, hspacing=T.S2, vspacing=T.S2):
        super().__init__(parent)
        self._items = []
        self.hs, self.vs = hspacing, vspacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

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
        m = self.contentsMargins()
        return s + QSize(m.left() + m.right(), m.top() + m.bottom())

    def _do(self, rect, test):
        m = self.contentsMargins()
        r = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        x, y, line_h = r.x(), r.y(), 0
        for it in self._items:
            w = it.widget()
            if w is not None and w.isHidden():
                continue
            hint = it.sizeHint()
            if it.hasHeightForWidth():                    # wrapped labels: never wider than the row
                hint = QSize(min(hint.width(), r.width()), it.heightForWidth(min(hint.width(), r.width())))
            nx = x + hint.width() + self.hs
            if nx - self.hs > r.right() + 1 and line_h > 0:
                x, y = r.x(), y + line_h + self.vs
                nx = x + hint.width() + self.hs
                line_h = 0
            if not test:
                it.setGeometry(QRect(QPoint(x, y), QSize(min(hint.width(), r.width()), hint.height())))
            x = nx
            line_h = max(line_h, hint.height())
        return y + line_h - rect.y() + m.bottom()


def flow(*widgets):
    """QWidget with a FlowLayout holding widgets (None skipped)."""
    w = QWidget()
    fl = FlowLayout(w)
    for x in widgets:
        if x is not None:
            fl.addWidget(x)
    w.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
    return w


def field(label_text, widget, min_w=None):
    """Label-above-input block for forms inside a flow row."""
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(2)
    v.addWidget(W.label(label_text, "Label"))
    if min_w:
        widget.setMinimumWidth(min_w)
    v.addWidget(widget)
    return w


def bottom(w):
    """Align a button/checkbox with the input of a label-above field next to it in a flow row."""
    box = QWidget()
    v = QVBoxLayout(box)
    v.setContentsMargins(0, 0, 0, 0)
    v.setSpacing(0)
    v.addStretch(1)
    v.addWidget(w)
    return box


def mono_input(w, size=12):
    """Monospaced text in an input. setFont() loses against the global QSS '* { font-family }' rule, a widget style sheet wins."""
    w.setStyleSheet('font-family: "%s"; font-size: %dpx;' % (T.FONT_MONO, size))
    return w


# ---------------------------------------------------------------------------------
#  Tables
# ---------------------------------------------------------------------------------
class FillTable(W.DataTable):
    """DataTable for a tab of its own: takes the free height (min_h at least) instead of following the row count."""

    def __init__(self, columns, widths=None, on_open=None, mono=(), min_h=180, multi=False):
        self._min_h = min_h
        super().__init__(columns, widths, on_open=on_open, mono=mono, max_rows_visible=1000)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        if multi:
            self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._fit()

    def _fit(self):
        self.setMinimumHeight(getattr(self, "_min_h", 180))
        self.setMaximumHeight(16777215)


def scroll_fill(inner):
    """Tab body that fills the tab (tables stretch) but scrolls instead of squeezing when the window is very small."""
    from PySide6.QtWidgets import QFrame as _F, QScrollArea
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(_F.NoFrame)
    sa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    inner.setObjectName("Root")
    sa.setWidget(inner)
    return sa


def selected_rows(table):
    try:
        idx = sorted(table.selectionModel().selectedRows(), key=lambda i: i.row())
        return [table.model_.row(table.proxy.mapToSource(i).row()) for i in idx]
    except RuntimeError:
        return []


def kill_labels(labels):
    """Kill tracked PowerShell processes with one of these labels (worker thread only: taskkill may take seconds)."""
    labels = set(labels or ())
    if not labels:
        return 0
    with core._active_lock:
        procs = [p for (p, lbl) in core.ACTIVE.values() if lbl in labels]
    for p in procs:
        core._kill_tree(p)
    return len(procs)


# ---------------------------------------------------------------------------------
#  Background operations + busy strip
# ---------------------------------------------------------------------------------
class BusyStrip(QFrame):
    """Thin progress bar + '<what> - 12 s' + Cancel. Hidden while nothing runs."""

    def __init__(self, on_cancel):
        super().__init__()
        self.setObjectName("BusyStrip")
        self.setStyleSheet("QFrame#BusyStrip{background:%s; border:1px solid %s; border-radius:4px;}" % (T.SURFACE, T.LINE))
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 0)
        v.addWidget(self.bar)
        row = QHBoxLayout()
        row.setContentsMargins(T.S4, T.S2, T.S2, T.S2)
        row.setSpacing(T.S3)
        self.lbl = W.label("", "Body", wrap=True)
        row.addWidget(self.lbl, 1)
        self.time = W.label("", "ValueMono")
        row.addWidget(self.time, 0, Qt.AlignVCenter)
        self.btn = W.button("Cancel", on_cancel, "stop", icon="stop")
        row.addWidget(self.btn, 0, Qt.AlignVCenter)
        v.addLayout(row)
        self.hide()


class _CloseGuard(QObject):
    """Event filter on the main window: refuses to close while a change that must not be cut off half-way is running
    (secure delete, quarantine, restore...). Those run untracked, so a forced exit would leave the QThread running."""

    def __init__(self, ops):
        super().__init__(ops.page)
        self.ops = ops

    def eventFilter(self, obj, ev):
        if ev.type() == QEvent.Close and obj is self.ops.page.app:
            busy = [o["msg"] for o in self.ops.ops.values() if o.get("guard")]
            if busy and not self.ops.closed:
                ev.ignore()
                W.warn(self.ops.page.app, "Keep WinDiag open until this finishes - stopping it half-way is not safe:\n\n- %s"
                       % "\n- ".join(m.rstrip(".") for m in busy))
                return True
        return False


class Ops(object):
    """Runs a page's background operations (one per key). fn runs in a QThread; done(res) runs on the GUI thread.
    An exception in fn becomes done({"error": text}) (like the old pages). Cancelled ops: result is dropped, and tracked
    PowerShell processes with the given labels are killed (only read-only ones are tracked, never changes)."""

    def __init__(self, page, strip):
        self.page, self.strip = page, strip
        self.ops = {}
        self.closed = False
        self.timer = QTimer(page)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)
        # tasks.run_task drops its references when QThread.finished arrives - the thread may still be exiting then, and a
        # very short task can be garbage-collected (deleted) under the running thread -> segfault. Keep our own reference
        # to every task until its thread has really stopped.
        self._keep = []
        self._reaper = QTimer(page)
        self._reaper.setInterval(500)
        self._reaper.timeout.connect(self._reap)
        self._guard = _CloseGuard(self)
        try:
            page.app.installEventFilter(self._guard)
        except Exception as e:
            core.log_error("close guard", e)

    def running(self, key=None):
        return bool(self.ops) if key is None else key in self.ops

    def start(self, key, fn, done, msg, cancellable=False, kill=(), progress=False, buttons=(), on_cancel=None, guard=False):
        """fn(cancel=Event, progress=callable) if progress else fn(). Returns False if `key` is already running.
        guard=True: a change that must finish - the window refuses to close while it runs."""
        if self.closed:
            return False
        if key in self.ops:
            self.page.app.set_status("%s is already running - wait for it to finish%s." % (self.ops[key]["msg"].rstrip("."),
                                                                                         " or click Cancel" if self.ops[key]["cancellable"] else ""),
                                     "WARNING", hold=4)
            return False
        ev = threading.Event()
        op = {"key": key, "msg": msg, "t0": time.time(), "cancel": ev, "cancellable": cancellable, "kill": kill, "buttons": list(buttons),
              "prog": None, "on_cancel": on_cancel, "dead": False, "done": done, "guard": guard}
        self.ops[key] = op
        for b in op["buttons"]:
            b.setEnabled(False)
        if msg:
            self.page.app.set_status(msg)

        want_progress = bool(progress)

        def work(progress=None):
            return fn(cancel=ev, progress=progress or (lambda v: None)) if want_progress else fn()

        def ok(res):
            self._finish(op, res)

        def err(text):
            self._finish(op, {"error": text})

        def prog(v):
            if op["dead"] or self.closed:
                return
            op["prog"] = v
            self.refresh()
        self._hold(tasks.run_task(work, ok, err, prog if progress else None, name="page-%s" % key))
        self.refresh()
        return True

    def _hold(self, task):
        self._keep.append(task)
        if not self._reaper.isActive():
            self._reaper.start()

    def _reap(self):
        self._keep = [t for t in self._keep if t.running()]
        if not self._keep:
            self._reaper.stop()

    def _release(self, op):
        op["dead"] = True
        if self.ops.get(op["key"]) is op:
            del self.ops[op["key"]]
        for b in op["buttons"]:
            try:
                b.setEnabled(True)
            except RuntimeError:
                pass
        self.refresh()

    def _finish(self, op, res):
        if op["dead"] or self.closed:
            return
        self._release(op)
        if res is None:
            res = {"error": "no result"}
        try:
            op_done = op.get("done")
            if op_done:
                op_done(res)
        except Exception as e:
            core.log_error("%s result" % type(self.page).__name__, e)
            self.page.app.set_status("Something went wrong - " + core.friendly_error(e), "WARNING")

    def cancel(self, key=None):
        """Cancel one op (key) or every cancellable op."""
        for op in list(self.ops.values()):
            if (key is None and op["cancellable"]) or op["key"] == key:
                op["cancel"].set()
                self._release(op)
                labels = op["kill"]() if callable(op["kill"]) else op["kill"]
                if labels:
                    self._hold(tasks.run_task(kill_labels, None, None, args=(tuple(labels),), name="kill-%s" % op["key"]))
                if op["on_cancel"]:
                    try:
                        op["on_cancel"]()
                    except Exception as e:
                        core.log_error("cancel %s" % op["key"], e)
                if op["msg"]:
                    self.page.app.set_status("Cancelled: %s" % op["msg"].rstrip(". "), hold=3)

    def refresh(self):
        if self.closed:
            return
        st = self.strip
        try:
            ops = sorted((o for o in self.ops.values() if o["msg"]), key=lambda o: o["t0"])      # quiet ops (no msg) show no strip
            if not ops:
                st.hide()
                self.timer.stop()
                return
            st.lbl.setText("   ·   ".join(o["msg"] for o in ops))
            st.time.setText("%d s" % int(time.time() - ops[0]["t0"]))
            st.btn.setVisible(any(o["cancellable"] for o in ops))
            pr = next((o["prog"] for o in ops if isinstance(o["prog"], (tuple, list)) and len(o["prog"]) >= 2), None)
            if pr and pr[1]:
                st.bar.setRange(0, int(pr[1]))
                st.bar.setValue(int(pr[0]))
                if len(pr) > 2 and pr[2]:
                    st.lbl.setText(str(pr[2]))
            else:
                st.bar.setRange(0, 0)
            st.show()
            if self.page.isVisible() and not self.timer.isActive():
                self.timer.start()
        except RuntimeError:          # widgets already deleted (closing)
            self.timer.stop()

    def on_show(self):
        if self.ops:
            self.refresh()

    def on_hide(self):
        self.timer.stop()

    def shutdown(self):
        self.closed = True
        self.timer.stop()
        for op in list(self.ops.values()):
            op["cancel"].set()
            op["dead"] = True
        self.ops.clear()
