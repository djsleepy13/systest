"""WinDiag 4 - PySide6 user interface. Entry point."""
import os
import sys
import traceback

# High-DPI: must be set before QApplication exists. Qt 6 is per-monitor DPI aware; PassThrough keeps fractional
# scale factors (125 %, 150 %, 175 %) exact, so nothing jumps or clips when the window is dragged between monitors.
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

import core  # noqa: E402


def _crash_log(text):
    try:
        with open(os.path.join(core.app_dir(), "WinDiag-crash.log"), "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        pass


def main():
    if os.name == "nt" and not core.is_admin() and "--no-elevate" not in sys.argv:
        if core.relaunch_as_admin(["--no-elevate"]):
            return 0
    if os.name == "nt":
        try:       # own taskbar icon/group instead of python's
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WinDiag.Toolkit")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setApplicationName("WinDiag")
    from qtui import theme as T
    T.load_fonts()
    app.setFont(T.ui(13))
    app.setStyleSheet(T.qss())

    def hook(exc, val, tb):
        core.log_error("uncaught", val)
        _crash_log("".join(traceback.format_exception(exc, val, tb)))
    sys.excepthook = hook
    import threading

    def thook(args):
        if args.exc_type is not SystemExit:
            core.log_error("thread %s" % getattr(args.thread, "name", "?"), args.exc_value)
    threading.excepthook = thook

    from qtui.app import MainWindow
    w = MainWindow()
    w.show()
    rc = app.exec()
    from qtui import tasks
    if not tasks.all_stopped():
        # a worker is stuck in an uninterruptible call (e.g. a hung network/PowerShell read). Destroying a running
        # QThread aborts the process with an error dialog, so leave immediately instead - everything is saved by now.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(rc or 0)
    return rc


if __name__ == "__main__":
    try:
        rc = main()
    except Exception:
        _crash_log(traceback.format_exc())
        raise
    sys.exit(rc or 0)
