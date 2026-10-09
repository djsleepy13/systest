"""
WinDiag 4 design system (Qt).

Look: flat, dense, IT-console style (deep neutral slate surfaces, sharp 1px low-alpha borders, no drop shadows, no gradients,
no glow). One cool accent for links / focus / selection; primary buttons are inverted (warm off-white on dark).
Type: Syne (display, page titles only) · Manrope (UI/body) · JetBrains Mono (every number, time, id, size - tabular figures).
All three are SIL Open Font License fonts bundled in fonts/ (see OFL-*.txt).
"""
import math
import os
import sys

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPainter, QPainterPath, QPen, QPixmap

# ---------------------------------------------------------------------------------
#  Tokens
# ---------------------------------------------------------------------------------
BG = "#121417"          # window
RAIL = "#0E1012"        # sidebar
SURFACE = "#181B1F"     # panels
SURFACE2 = "#1E2227"    # panel header rows, inputs, hover
SURFACE3 = "#252A30"    # pressed / selected
LINE = "rgba(255,255,255,0.075)"      # 1px borders (QSS)
LINE_STRONG = "rgba(255,255,255,0.13)"
LINE_HEX = "#24282D"    # same look as LINE on SURFACE, for QPainter
TEXT = "#E8E6E3"        # warm off-white
TEXT2 = "#A19E99"       # stone
MUTED = "#6E6B67"
ACCENT = "#5A9BD8"      # links, focus, selection (cool blue - no purple/indigo)
ACCENT_DIM = "#1D2B3A"

CRIT = "#EF5466"
WARN = "#E5A33B"
OK = "#45B07C"
INFO = "#5A9BD8"
REVIEW = "#B08AD6"

STATUS = {"CRITICAL": CRIT, "WARNING": WARN, "INFO": INFO, "OK": OK, "GOOD": OK, "PASS": OK, "CAUTION": WARN, "FAIL": CRIT,
          "HIGH": CRIT, "MEDIUM": WARN, "LOW": INFO, "REVIEW": REVIEW, "UNKNOWN": MUTED, "ERROR": CRIT}

# spacing system (px, before DPI scaling - Qt scales them)
S1, S2, S3, S4, S5, S6 = 4, 8, 12, 16, 24, 32

FONT_UI = "Manrope"
FONT_DISPLAY = "Syne"
FONT_MONO = "JetBrains Mono"


def tint(color, alpha=0.14, base=SURFACE):
    """Solid colour = `color` laid over `base` at `alpha` (flat tinted backgrounds for badges / banners)."""
    a = QColor(color)
    b = QColor(base)
    r = int(b.red() + (a.red() - b.red()) * alpha)
    g = int(b.green() + (a.green() - b.green()) * alpha)
    bl = int(b.blue() + (a.blue() - b.blue()) * alpha)
    return "#%02X%02X%02X" % (r, g, bl)


# ---------------------------------------------------------------------------------
#  Fonts
# ---------------------------------------------------------------------------------
_fonts_loaded = False


def font_dir():
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "fonts")


def load_fonts():
    """Register the bundled fonts (call once, after QApplication exists)."""
    global _fonts_loaded, FONT_UI, FONT_DISPLAY, FONT_MONO
    if _fonts_loaded:
        return
    _fonts_loaded = True
    fams = set()
    d = font_dir()
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.lower().endswith((".ttf", ".otf")):
                fid = QFontDatabase.addApplicationFont(os.path.join(d, f))
                if fid >= 0:
                    fams.update(QFontDatabase.applicationFontFamilies(fid))
    # fall back gracefully if a font file is missing (never Arial/Inter/Roboto on purpose - but never a crash either)
    if "Manrope" not in fams:
        FONT_UI = "Segoe UI"
    if "Syne" not in fams:
        FONT_DISPLAY = FONT_UI
    if "JetBrains Mono" not in fams:
        FONT_MONO = "Consolas"


def ui(size=13, weight=500):
    f = QFont(FONT_UI)
    f.setPixelSize(int(size))
    f.setWeight(QFont.Weight(weight))
    f.setHintingPreference(QFont.PreferNoHinting)
    return f


def display(size=24, weight=700):
    f = QFont(FONT_DISPLAY)
    f.setPixelSize(int(size))
    f.setWeight(QFont.Weight(weight))
    f.setLetterSpacing(QFont.PercentageSpacing, 98)      # tight tracking (-0.02em)
    return f


def mono(size=12, weight=400):
    f = QFont(FONT_MONO)
    f.setPixelSize(int(size))
    f.setWeight(QFont.Weight(weight))
    f.setStyleHint(QFont.Monospace)
    return f


# ---------------------------------------------------------------------------------
#  Style sheet
# ---------------------------------------------------------------------------------
def _check_png():
    """Tick image for checked checkboxes (QSS needs a file). Written once per run into the temp folder."""
    import tempfile
    path = os.path.join(tempfile.gettempdir(), "windiag_check_%d.png" % os.getpid())
    try:
        if not os.path.exists(path):
            icon("check", "#121417", 14).pixmap(28, 28).save(path, "PNG")
    except Exception:
        return ""
    return path.replace("\\", "/")


def qss():
    return """
* { color: %(text)s; outline: 0; }   /* font comes from QApplication.setFont so widget setFont() still works */
QMainWindow, #Root { background: %(bg)s; }
QToolTip { background: %(s2)s; color: %(text)s; border: 1px solid %(lines)s; padding: 6px 8px; }

/* ---- sidebar ---- */
#Rail { background: %(rail)s; border-right: 1px solid %(line)s; }
#Brand { font-family: "%(display)s"; font-size: 17px; font-weight: 700; color: %(text)s; }
#BrandSub { color: %(muted)s; font-size: 11px; }
#NavSection { color: %(muted)s; font-size: 10px; font-weight: 700; padding: 14px 14px 4px 14px; }
QPushButton#Nav { text-align: left; padding: 7px 10px 7px 12px; border: 0; border-left: 2px solid transparent; border-radius: 0;
                  color: %(text2)s; font-size: 13px; font-weight: 500; background: transparent; }
QPushButton#Nav:hover { background: %(s1)s; color: %(text)s; }
QPushButton#Nav:checked { background: %(s2)s; color: %(text)s; border-left: 2px solid %(accent)s; font-weight: 600; }
#NavCount { font-family: "%(mono)s"; font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: 3px; }
#RailFoot { border-top: 1px solid %(line)s; }

/* ---- header ---- */
#Header { background: %(bg)s; border-bottom: 1px solid %(line)s; }
#PageTitle { font-family: "%(display)s"; font-size: 22px; font-weight: 700; }
#PageDesc { color: %(text2)s; font-size: 12px; }
#StatusBar { background: %(rail)s; border-top: 1px solid %(line)s; }
#StatusText { color: %(text2)s; font-size: 12px; }

/* ---- surfaces ---- */
#Panel { background: %(s1)s; border: 1px solid %(line)s; border-radius: 4px; }
#PanelHead { border-bottom: 1px solid %(line)s; }
#PanelTitle { font-size: 13px; font-weight: 700; color: %(text)s; }
#PanelSub { color: %(text2)s; font-size: 12px; }
#SectionTitle { font-size: 13px; font-weight: 700; color: %(text)s; }
#Label { color: %(text2)s; font-size: 11px; font-weight: 500; }
#Value { color: %(text)s; font-size: 13px; }
#ValueMono { font-family: "%(mono)s"; color: %(text)s; font-size: 12px; }
#Muted { color: %(muted)s; font-size: 12px; }
#Body { color: %(text2)s; font-size: 12px; }
#Big { font-family: "%(mono)s"; font-size: 26px; font-weight: 500; color: %(text)s; }
#Link { color: %(accent)s; }
QFrame#Divider { background: %(lineh)s; max-height: 1px; min-height: 1px; border: 0; }
QFrame#Cell { background: %(bg)s; border: 1px solid %(line)s; border-radius: 3px; }

/* ---- buttons ---- */
QPushButton { background: %(s2)s; border: 1px solid %(lines)s; border-radius: 4px; padding: 6px 12px; color: %(text)s; font-weight: 600; }
QPushButton:hover { background: %(s3)s; }
QPushButton:pressed { background: %(bg)s; }
QPushButton:disabled { color: %(muted)s; background: %(s1)s; border-color: %(line)s; }
QPushButton[kind="primary"] { background: %(text)s; color: %(bg)s; border: 1px solid %(text)s; }
QPushButton[kind="primary"]:hover { background: #FFFFFF; }
QPushButton[kind="primary"]:disabled { background: %(s2)s; color: %(muted)s; border-color: %(line)s; }
QPushButton[kind="ghost"] { background: transparent; border: 1px solid transparent; color: %(text2)s; }
QPushButton[kind="ghost"]:hover { background: %(s2)s; color: %(text)s; }
QPushButton[kind="link"] { background: transparent; border: 0; color: %(accent)s; padding: 0; font-weight: 500; text-align: left; }
QPushButton[kind="link"]:hover { text-decoration: underline; }
QPushButton[kind="danger"] { background: %(crit)s; color: #FFFFFF; border: 1px solid %(crit)s; }
QPushButton[kind="danger"]:hover { background: #F36B7B; }
QPushButton[kind="danger"]:disabled { background: %(s2)s; color: %(muted)s; border-color: %(line)s; }
QPushButton[kind="stop"] { background: transparent; color: %(crit)s; border: 1px solid %(crit)s; }

/* ---- inputs ---- */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit { background: %(bg)s; border: 1px solid %(lines)s; border-radius: 4px; padding: 5px 8px;
    selection-background-color: %(accentdim)s; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border: 1px solid %(accent)s; }
QComboBox::drop-down { border: 0; width: 18px; }
QComboBox QAbstractItemView { background: %(s2)s; border: 1px solid %(lines)s; selection-background-color: %(s3)s; }
QCheckBox { spacing: 8px; color: %(text)s; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid %(lines)s; border-radius: 3px; background: %(bg)s; }
QCheckBox::indicator:checked { background: %(accent)s; border-color: %(accent)s; image: url("%(check)s"); }
QCheckBox::indicator:disabled { border-color: %(line)s; background: %(s1)s; }
QPushButton:checked { background: %(s3)s; border: 1px solid %(accent)s; color: %(text)s; }
QLineEdit[mono="true"], QPlainTextEdit[mono="true"], QTextEdit[mono="true"] { font-family: "%(mono)s"; font-size: 12px; }
QProgressBar { background: %(s2)s; border: 0; border-radius: 1px; max-height: 3px; min-height: 3px; }
QProgressBar::chunk { background: %(accent)s; border-radius: 1px; }

/* ---- tabs (underline style, like a console) ---- */
QTabWidget::pane { border: 0; border-top: 1px solid %(line)s; top: -1px; }
QTabBar { qproperty-drawBase: 0; background: transparent; border: 0; }
QTabWidget::tab-bar { left: 0; }
QTabBar::tab { background: transparent; color: %(text2)s; padding: 8px 14px; border: 0; border-bottom: 2px solid transparent; font-weight: 600; }
QTabBar::tab:hover { color: %(text)s; }
QTabBar::tab:selected { color: %(text)s; border-bottom: 2px solid %(accent)s; }

/* ---- tables ---- */
QTableView { background: %(s1)s; alternate-background-color: %(s1)s; border: 0; gridline-color: transparent;
             selection-background-color: %(s3)s; selection-color: %(text)s; }
QTableView::item { padding: 0 8px; border-bottom: 1px solid %(line)s; }
QTableView::item:hover { background: %(s2)s; }
QHeaderView::section { background: %(s1)s; color: %(muted)s; border: 0; border-bottom: 1px solid %(lines)s; padding: 6px 8px;
                       font-size: 10px; font-weight: 700; }

/* ---- scrollbars (thin, visible) ---- */
QScrollArea { border: 0; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #2B3036; min-height: 30px; border-radius: 4px; margin: 2px; }
QScrollBar::handle:vertical:hover { background: #3A4048; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: #2B3036; min-width: 30px; border-radius: 4px; margin: 2px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QMenu { background: %(s2)s; border: 1px solid %(lines)s; padding: 4px; }
QMenu::item { padding: 6px 18px; }
QMenu::item:selected { background: %(s3)s; }
QDialog { background: %(bg)s; }
QMessageBox { background: %(s1)s; }
""" % {"ui": FONT_UI, "display": FONT_DISPLAY, "mono": FONT_MONO, "text": TEXT, "text2": TEXT2, "muted": MUTED, "bg": BG, "rail": RAIL,
       "s1": SURFACE, "s2": SURFACE2, "s3": SURFACE3, "line": LINE, "lines": LINE_STRONG, "lineh": LINE_HEX, "accent": ACCENT, "check": _check_png(),
       "accentdim": ACCENT_DIM, "crit": CRIT}


# ---------------------------------------------------------------------------------
#  Line icons (vector, drawn with QPainter -> crisp at every DPI)
# ---------------------------------------------------------------------------------
_icon_cache = {}


def icon(name, color=TEXT2, size=18):
    """QIcon of a 24-unit line icon. Rendered at 3x so it stays sharp at 100-300 % scaling."""
    key = (name, color, size)
    if key in _icon_cache:
        return _icon_cache[key]
    dpr = 3
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    sc = size * dpr / 24.0
    p.scale(sc, sc)
    pen = QPen(QColor(color), 1.7)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    _draw_icon(p, name)
    p.end()
    pm.setDevicePixelRatio(dpr)
    ic = QIcon(pm)
    _icon_cache[key] = ic
    return ic


def _draw_icon(p, name):
    def L(*pts):
        path = QPainterPath(QPointF(pts[0], pts[1]))
        for i in range(2, len(pts), 2):
            path.lineTo(pts[i], pts[i + 1])
        p.drawPath(path)

    def R(x0, y0, x1, y1, r=2):
        p.drawRoundedRect(QRectF(x0, y0, x1 - x0, y1 - y0), r, r)

    def O(cx, cy, r):
        p.drawEllipse(QPointF(cx, cy), r, r)

    def A(cx, cy, r, a0, a1):
        # PIL angles: clockwise from 3 o'clock; Qt: counter-clockwise, 1/16 deg
        p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), int(-a0 * 16), int(-(a1 - a0) * 16))

    if name == "dashboard":
        R(3, 3, 10, 11); R(14, 3, 21, 8); R(14, 12, 21, 21); R(3, 15, 10, 21)
    elif name == "specs":
        R(5, 3, 19, 21); L(8, 8, 16, 8); L(8, 12, 16, 12); L(8, 16, 13, 16)
    elif name == "cpu":
        R(6, 6, 18, 18); R(9.5, 9.5, 14.5, 14.5, 1)
        for q in (9, 12, 15):
            L(q, 2, q, 6); L(q, 18, q, 22); L(2, q, 6, q); L(18, q, 22, q)
    elif name == "disk":
        R(3, 13, 21, 20); L(3, 13, 6, 5); L(21, 13, 18, 5); L(6, 5, 18, 5); O(17, 16.5, 0.6)
    elif name == "drivehealth":
        R(3, 6, 21, 18); L(6, 12, 9, 12, 11, 9, 13, 15, 15, 12, 18, 12)
    elif name == "ram":
        R(2, 7, 22, 16, 1); L(6, 10, 6, 13); L(10, 10, 10, 13); L(14, 10, 14, 13); L(18, 10, 18, 13); L(4, 16, 4, 19); L(20, 16, 20, 19)
    elif name == "alert":
        L(12, 3, 22, 20, 2, 20, 12, 3); L(12, 9, 12, 14); O(12, 17, 0.4)
    elif name == "network":
        O(12, 12, 9); L(3, 12, 21, 12); p.drawEllipse(QRectF(8, 3, 8, 18))
    elif name == "startup":
        L(12, 3, 12, 11); A(12, 13, 8, -60, 240)
    elif name == "shield":
        L(12, 3, 20, 6, 20, 12); L(12, 3, 4, 6, 4, 12); A(12, 12, 8, 0, 180); L(8.5, 12, 11, 14.5, 15.5, 9.5)
    elif name == "server":
        R(4, 3, 20, 10); R(4, 14, 20, 21); O(8, 6.5, 0.5); O(8, 17.5, 0.5)
    elif name == "cloud":
        A(9, 13, 5, 90, 270); A(14, 11, 6, 180, 360); A(18, 15, 4, 270, 450); L(9, 18, 18, 18)
    elif name == "activity":
        L(2, 12, 7, 12, 10, 4, 14, 20, 17, 12, 22, 12)
    elif name == "wand":
        L(4, 20, 15, 9); L(17, 3, 17, 7); L(15, 5, 19, 5); L(21, 9, 21, 12); L(19.5, 10.5, 22.5, 10.5)
    elif name == "lock":
        R(5, 10, 19, 21); A(12, 10, 5, 180, 360); L(7, 10, 7, 8); L(17, 10, 17, 8); L(12, 14, 12, 17)
    elif name == "folder":
        L(3, 6, 3, 19, 21, 19, 21, 8, 11, 8, 9, 5, 3, 5, 3, 6)
    elif name == "wrench":
        L(4, 20, 12, 12); A(16, 8, 5, 100, 350)
    elif name == "search":
        O(10.5, 10.5, 6.5); L(15.5, 15.5, 21, 21)
    elif name == "play":
        L(7, 4, 19, 12, 7, 20, 7, 4)
    elif name == "report":
        L(6, 3, 14, 3, 19, 8, 19, 21, 6, 21, 6, 3); L(14, 3, 14, 8, 19, 8); L(9, 13, 16, 13); L(9, 17, 14, 17)
    elif name == "refresh":
        A(12, 12, 8, 30, 320); L(20, 4, 20, 9, 15, 9)
    elif name == "user":
        O(12, 8, 4); A(12, 21, 8, 180, 360)
    elif name == "gpu":
        R(2, 6, 22, 17); O(9, 11.5, 3); O(16.5, 11.5, 2); L(5, 17, 5, 20)
    elif name == "battery":
        R(2, 7, 19, 17); L(22, 10, 22, 14); L(5, 10, 5, 14); L(8, 10, 8, 14)
    elif name == "windows":
        R(3, 3, 11, 11, 1); R(13, 3, 21, 11, 1); R(3, 13, 11, 21, 1); R(13, 13, 21, 21, 1)
    elif name == "chevron":
        L(9, 5, 16, 12, 9, 19)
    elif name == "download":
        L(12, 3, 12, 15); L(7, 10, 12, 15, 17, 10); L(4, 20, 20, 20)
    elif name == "gauge":
        A(12, 14, 9, 180, 360); L(12, 14, 16.5, 8.5); O(12, 14, 1); L(3, 14, 5, 14); L(19, 14, 21, 14)
    elif name == "update":
        O(12, 12, 9); L(12, 7, 12, 16); L(8.5, 12.5, 12, 16, 15.5, 12.5)
    elif name == "stop":
        R(6, 6, 18, 18, 2)
    elif name == "gear":
        O(12, 12, 3.5); O(12, 12, 8)
        for a in range(0, 360, 45):
            c, s = math.cos(math.radians(a)), math.sin(math.radians(a))
            L(12 + 8 * c, 12 + 8 * s, 12 + 10.5 * c, 12 + 10.5 * s)
    elif name == "wifi":
        A(12, 18, 15, 225, 315); A(12, 18, 10, 225, 315); A(12, 18, 5, 225, 315); O(12, 18, 0.8)
    elif name == "copy":
        R(8, 8, 21, 21); L(16, 8, 16, 3, 3, 3, 3, 16, 8, 16)
    elif name == "check":
        L(5, 12.5, 10, 17.5, 19, 7)
    elif name == "x":
        L(6, 6, 18, 18); L(18, 6, 6, 18)
    elif name == "info":
        O(12, 12, 9); L(12, 11, 12, 16); O(12, 8, 0.4)
    else:
        O(12, 12, 8)
