"""Build WinDiag.exe (WinDiag 4, PySide6 UI):  python build.py   (needs: pip install pyinstaller PySide6-Essentials)"""
import hashlib
import os

import PyInstaller.__main__

here = os.path.dirname(os.path.abspath(__file__))
work = os.path.join(here, "build_tmp")
os.makedirs(work, exist_ok=True)

SPEC = r'''
import os
from PyInstaller.utils.hooks import collect_submodules
here = %(here)r
UNUSED_QT = ["QtNetwork", "QtQml", "QtQuick", "QtQuickWidgets", "QtSql", "QtTest", "QtXml", "QtOpenGL", "QtOpenGLWidgets",
             "QtPdf", "QtPdfWidgets", "QtDBus", "QtConcurrent", "QtHelp", "QtDesigner", "QtUiTools", "QtPrintSupport",
             "QtSvgWidgets", "QtMultimedia", "QtWebEngineCore", "QtWebEngineWidgets", "Qt3DCore", "QtCharts"]
# Slim bundle: software OpenGL (20 MB, QWidget apps never use it), Qt translations, plugins WinDiag never loads.
DROP = ("opengl32sw", "qt_help_", "qtuiotouchplugin", "qdirect2d", "qminimal", "qoffscreen", "qgif", "qicns", "qjpeg",
        "qtga", "qtiff", "qwbmp", "qwebp", "qsvg", "Qt6Network", "Qt6Svg", "qtbase_", "qt_ar", "qt_bg", "qt_ca", "qt_cs",
        "qt_da", "qt_de", "qt_es", "qt_fa", "qt_fi", "qt_fr", "qt_gd", "qt_gl", "qt_he", "qt_hr", "qt_hu", "qt_it",
        "qt_ja", "qt_ko", "qt_lt", "qt_lv", "qt_nl", "qt_nn", "qt_pl", "qt_pt", "qt_ru", "qt_sk", "qt_sl", "qt_sv",
        "qt_tr", "qt_uk", "qt_zh", "qt_zh_TW")

a = Analysis([os.path.join(here, "WinDiagQt.py")], pathex=[here],
             datas=[(os.path.join(here, "windiag.ico"), "."), (os.path.join(here, "fonts"), "fonts")],
             hiddenimports=collect_submodules("qtui") + ["__future__"], excludes=["tkinter", "customtkinter"] + ["PySide6." + m for m in UNUSED_QT])
a.binaries = [b for b in a.binaries if not any(d in b[0] for d in DROP)]
a.datas = [d for d in a.datas if not any(x in d[0] for x in DROP)]
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="WinDiag", console=False, upx=False,
          icon=os.path.join(here, "windiag.ico"), version=os.path.join(here, "version_info.txt"))
'''
spec = os.path.join(work, "WinDiag.spec")
with open(spec, "w") as f:
    f.write(SPEC % {"here": here})
PyInstaller.__main__.run(["--noconfirm", "--clean", "--distpath", os.path.join(here, "dist"),
                          "--workpath", os.path.join(work, "wp"), spec])

# Release fingerprint checked by WinDiag's start-up security check (keep it next to the exe)
exe = os.path.join(here, "dist", "WinDiag.exe")
with open(exe, "rb") as f:
    digest = hashlib.sha256(f.read()).hexdigest()
with open(os.path.join(here, "dist", "WinDiag.sha256"), "w") as f:
    f.write("%s *WinDiag.exe\n" % digest)
print("WinDiag.sha256:", digest)
