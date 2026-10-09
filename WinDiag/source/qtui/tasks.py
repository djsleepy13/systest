"""
Threading rules for the Qt UI (WinDiag 4):

  * NOTHING slow runs on the GUI thread - no PowerShell, file I/O, sleeps, network, parsing of big data.
  * Background work runs in a QThread with a QObject worker (run_task). Results come back through Qt signals with a
    QueuedConnection, so callbacks always execute on the GUI thread and may touch widgets.
  * Worker and thread are deleteLater()'d when the thread finishes; running tasks are tracked so the app can wait for
    them (or abandon them safely) on exit.
  * Code written for the old UI posts callbacks with   app.q.put(("guided_cb", None, fn))   from any thread.
    MainQueue keeps that API but marshals the call through a signal onto the GUI thread.
"""
import threading
import time
import traceback

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot

import core


class _Bridge(QObject):
    """Lives on the GUI thread. call.emit(fn) from ANY thread -> fn() runs on the GUI thread."""
    call = Signal(object)

    def __init__(self):
        super().__init__()
        self.call.connect(self._run, Qt.QueuedConnection)

    @Slot(object)
    def _run(self, fn):
        try:
            fn()
        except Exception as e:
            core.log_error("ui callback", e)
            if self.on_error:
                try:
                    self.on_error(e)
                except Exception:
                    pass

    on_error = None


_bridge = None


def bridge():
    global _bridge
    if _bridge is None:
        _bridge = _Bridge()
    return _bridge


def ui(fn):
    """Run fn() on the GUI thread (safe to call from any thread)."""
    bridge().call.emit(fn)


class MainQueue(object):
    """Drop-in for the old Tk app.q (queue.Queue polled by the main loop)."""

    def __init__(self, app):
        self.app = app

    def put(self, item):
        kind, key, res = item
        if kind == "guided_cb":
            ui(res)
        elif kind == "result":
            ui(lambda: self.app._on_result(key, res))
        elif kind == "done":
            ui(self.app._on_done)
        elif kind == "guided_msg":
            ui(lambda: self.app.set_status(res))


# ---------------------------------------------------------------------------------
#  QThread + QObject worker
# ---------------------------------------------------------------------------------
class Worker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(object)

    def __init__(self, fn, args=(), kwargs=None, with_progress=False):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, dict(kwargs or {})
        self.with_progress = with_progress
        self.cancel = threading.Event()

    @Slot()
    def run(self):
        try:
            if self.with_progress:
                self.kwargs["progress"] = self.progress.emit
            res = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            core.log_error("task %s" % getattr(self.fn, "__name__", "?"), e)
            self.failed.emit(core.friendly_error(e) if hasattr(core, "friendly_error") else str(e))
            return
        self.finished.emit(res)


class _Receiver(QObject):
    """GUI-thread object whose slots call the user's callbacks (QueuedConnection guarantees the GUI thread)."""

    def __init__(self, on_done, on_error, on_progress):
        super().__init__()
        self.on_done, self.on_error, self.on_progress = on_done, on_error, on_progress

    @Slot(object)
    def done(self, res):
        if self.on_done:
            try:
                self.on_done(res)
            except Exception as e:
                core.log_error("task callback", e)

    @Slot(str)
    def error(self, msg):
        if self.on_error:
            try:
                self.on_error(msg)
            except Exception as e:
                core.log_error("task error callback", e)

    gone = None

    @Slot()
    def thread_finished(self):
        if self.gone:
            self.gone()

    @Slot(object)
    def progress(self, v):
        if self.on_progress:
            try:
                self.on_progress(v)
            except Exception as e:
                core.log_error("task progress callback", e)


_ALIVE = {}          # id -> (thread, worker, receiver): keeps Python wrappers alive until the thread is done
_lock = threading.Lock()


class Task(object):
    def __init__(self, thread, worker):
        self.thread, self.worker = thread, worker

    @property
    def cancel(self):
        return self.worker.cancel

    def running(self):
        try:
            return self.thread.isRunning()
        except RuntimeError:          # already deleted
            return False


def run_task(fn, on_done=None, on_error=None, on_progress=None, args=(), kwargs=None, name=None):
    """Run fn(*args, **kwargs) in a new QThread. Callbacks run on the GUI thread.
    If on_progress is given, fn receives progress=<callable> it may call from the worker thread."""
    thread = QThread()
    thread.setObjectName(name or getattr(fn, "__name__", "task"))
    worker = Worker(fn, args, kwargs, with_progress=on_progress is not None)
    rec = _Receiver(on_done, on_error, on_progress)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.finished.connect(rec.done, Qt.QueuedConnection)
    worker.failed.connect(rec.error, Qt.QueuedConnection)
    worker.progress.connect(rec.progress, Qt.QueuedConnection)
    # quit directly from the worker thread: a queued quit would need the GUI loop, which is blocked during shutdown()
    worker.finished.connect(thread.quit, Qt.DirectConnection)
    worker.failed.connect(thread.quit, Qt.DirectConnection)
    key = id(thread)
    with _lock:
        _ALIVE[key] = (thread, worker, rec)

    def _gone():
        # GUI thread. QThread.finished fires just BEFORE the OS thread exits and the Python wrappers own the C++
        # objects, so wait for the real exit, then drop the references on the next loop turn (not inside rec's slot).
        try:
            thread.wait()
        except RuntimeError:
            pass

        def _drop():
            with _lock:
                _ALIVE.pop(key, None)
        QTimer.singleShot(0, _drop)
    rec.gone = _gone
    thread.finished.connect(rec.thread_finished, Qt.QueuedConnection)
    thread.start()
    return Task(thread, worker)


def running_tasks():
    out = []
    with _lock:
        items = list(_ALIVE.values())
    for t, w, r in items:
        try:
            if t.isRunning():
                out.append(t)
        except RuntimeError:
            pass
    return out


_ABANDONED = []      # threads that did not stop on exit: never let Python destroy a running QThread


def shutdown(timeout_ms=3000):
    """Called on exit: cancel flags, kill tracked processes, wait for threads. Returns True if all stopped.
    Waits with short sleeps so the GIL is released and workers can finish their Python code."""
    with _lock:
        items = list(_ALIVE.values())
    for t, w, r in items:
        w.cancel.set()
    try:
        core.abort_all()
    except Exception:
        traceback.print_exc()
    end = time.monotonic() + timeout_ms / 1000.0
    ok = True
    for t, w, r in items:
        try:
            while t.isRunning() and time.monotonic() < end:
                time.sleep(0.02)
            if t.isRunning():
                ok = False
                _ABANDONED.append((t, w, r))
        except RuntimeError:
            pass
    return ok


def all_stopped():
    return not running_tasks() and not any(_t.isRunning() for _t, _w, _r in _ABANDONED if _alive(_t))


def _alive(t):
    try:
        t.isRunning()
        return True
    except RuntimeError:
        return False
