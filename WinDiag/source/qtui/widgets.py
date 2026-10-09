"""Reusable Qt widgets for WinDiag 4. Layout managers only (no absolute positioning) so everything scales across monitors."""
import math

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPointF, QRectF, QSize, QSortFilterProxyModel, QTimer, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QDialogButtonBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QTableView, QVBoxLayout,
                               QWidget)

from . import theme as T


# ---------------------------------------------------------------------------------
#  Small helpers
# ---------------------------------------------------------------------------------
def label(text="", role="Value", wrap=False, sel=False, mono=False):
    """role = QSS objectName: Value, ValueMono, Label, Muted, Body, Big, SectionTitle, PanelTitle..."""
    w = QLabel(str(text))
    w.setObjectName("ValueMono" if mono and role == "Value" else role)
    if wrap:
        w.setWordWrap(True)
    if sel:
        w.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return w


def colored(text, color, size=12, bold=False, mono=False, wrap=True):
    w = QLabel(str(text))
    w.setWordWrap(wrap)
    f = T.mono(size, 600 if bold else 400) if mono else T.ui(size, 700 if bold else 500)
    w.setFont(f)
    w.setStyleSheet("color: %s;" % color)
    return w


def button(text, slot=None, kind="secondary", icon=None, tip=None, min_w=None):
    b = QPushButton(str(text).replace("&", "&&"))          # '&' would become a keyboard mnemonic underline
    if kind != "secondary":
        b.setProperty("kind", kind)
    if icon:
        b.setIcon(T.icon(icon, T.BG if kind == "primary" else (T.CRIT if kind == "stop" else T.TEXT2), 16))
        b.setIconSize(QSize(16, 16))
    if slot:
        b.clicked.connect(lambda checked=False: slot())
    if tip:
        b.setToolTip(tip)
    if min_w:
        b.setMinimumWidth(min_w)
    b.setCursor(Qt.PointingHandCursor)
    return b


def set_kind(btn, kind):
    btn.setProperty("kind", kind)
    btn.style().unpolish(btn)
    btn.style().polish(btn)


def divider():
    f = QFrame()
    f.setObjectName("Divider")
    return f


def hbox(*widgets, spacing=T.S2, margins=(0, 0, 0, 0), stretch_at=None):
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    for i, x in enumerate(widgets):
        if x == "stretch":
            lay.addStretch(1)
        elif x is not None:
            lay.addWidget(x)
    return w


def clear_layout(lay):
    """Remove and delete every item of a layout (deleteLater - safe inside slots)."""
    while lay.count():
        it = lay.takeAt(0)
        w = it.widget()
        if w is not None:
            w.hide()
            w.deleteLater()
        elif it.layout() is not None:
            clear_layout(it.layout())


class Dot(QLabel):
    """'● Text' status indicator."""

    def __init__(self, status_or_color, text="", size=12):
        super().__init__()
        self.set(status_or_color, text, size)

    def set(self, status_or_color, text="", size=12):
        col = T.STATUS.get(status_or_color, status_or_color)
        self.setText('<span style="color:%s">●</span>&nbsp;&nbsp;%s' % (col, text) if text else '<span style="color:%s">●</span>' % col)
        self.setTextFormat(Qt.RichText)
        self.setFont(T.ui(size, 500))


class Badge(QLabel):
    """Flat tinted status tag (no pill gradients): e.g. CRITICAL, GOOD 88%."""

    def __init__(self, text, status="INFO", mono=False):
        super().__init__()
        self.set(text, status, mono)

    def set(self, text, status="INFO", mono=False):
        col = T.STATUS.get(status, status)
        self.setText(str(text))
        self.setFont(T.mono(10, 600) if mono else T.ui(10, 700))
        self.setStyleSheet("color:%s; background:%s; border:1px solid %s; border-radius:3px; padding:2px 6px;"
                           % (col, T.tint(col, 0.12), T.tint(col, 0.35)))
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)


# ---------------------------------------------------------------------------------
#  Panel (flat surface with a header row) and page scaffolding
# ---------------------------------------------------------------------------------
class Panel(QFrame):
    """Flat surface: optional title + subtitle + right-side actions, then .body (QVBoxLayout)."""

    def __init__(self, title=None, sub=None, actions=(), pad=T.S4, spacing=T.S3):
        super().__init__()
        self.setObjectName("Panel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.head = None
        if title or actions:
            self.head = QWidget()
            self.head.setObjectName("PanelHead")
            h = QHBoxLayout(self.head)
            h.setContentsMargins(pad, T.S3, pad - 4, T.S3)
            h.setSpacing(T.S2)
            tb = QVBoxLayout()
            tb.setSpacing(2)
            self.title_lbl = label(title or "", "PanelTitle")
            tb.addWidget(self.title_lbl)
            self.sub_lbl = None
            if sub:
                self.sub_lbl = label(sub, "PanelSub", wrap=True)
                tb.addWidget(self.sub_lbl)
            h.addLayout(tb, 1)
            self.actions = QHBoxLayout()
            self.actions.setSpacing(T.S2)
            for a in actions:
                self.actions.addWidget(a)
            h.addLayout(self.actions)
            lay.addWidget(self.head)
        inner = QWidget()
        self.body = QVBoxLayout(inner)
        self.body.setContentsMargins(pad, pad, pad, pad)
        self.body.setSpacing(spacing)
        lay.addWidget(inner)

    def add(self, w, stretch=0):
        self.body.addWidget(w, stretch)
        return w

    def add_action(self, w):
        if self.head is not None:
            self.actions.addWidget(w)
        return w


class KeyValueGrid(QWidget):
    """Label-above-value grid (like an asset sheet). set([(label, value, opts)], cols)."""

    def __init__(self, cols=3):
        super().__init__()
        self.cols = cols
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(T.S5)
        self.grid.setVerticalSpacing(T.S3)

    def set(self, pairs, cols=None):
        cols = cols or self.cols
        clear_layout(self.grid)
        for c in range(cols):
            self.grid.setColumnStretch(c, 1)
        for i, item in enumerate(pairs):
            k, v = item[0], item[1]
            opt = item[2] if len(item) > 2 else {}
            box = QVBoxLayout()
            box.setSpacing(2)
            box.addWidget(label(k, "Label"))
            if isinstance(v, QWidget):
                box.addWidget(v)
            else:
                txt = "--" if v in (None, "") else str(v)
                w = label(txt, "ValueMono" if opt.get("mono") else "Value", wrap=True, sel=True)
                if opt.get("color"):
                    w.setStyleSheet("color:%s;" % T.STATUS.get(opt["color"], opt["color"]))
                box.addWidget(w)
            self.grid.addLayout(box, i // cols, i % cols, Qt.AlignTop)


class ScrollPage(QScrollArea):
    """Vertical scrolling page body. Put content in .layout (QVBoxLayout); 32px between major blocks."""

    def __init__(self, margins=(T.S5, T.S5, T.S5, T.S5), spacing=T.S6):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.inner = QWidget()
        self.inner.setObjectName("Root")
        self.layout_ = QVBoxLayout(self.inner)
        self.layout_.setContentsMargins(*margins)
        self.layout_.setSpacing(spacing)
        self.setWidget(self.inner)

    @property
    def lay(self):
        return self.layout_

    def add(self, w, stretch=0):
        self.layout_.addWidget(w, stretch)
        return w

    def finish(self):
        self.layout_.addStretch(1)


class Banner(QFrame):
    """Flat tinted notice with a coloured left rule. Optional action button."""

    def __init__(self, title, text="", status="INFO", action=None):
        super().__init__()
        col = T.STATUS.get(status, status)
        self.setStyleSheet("QFrame#Banner{background:%s; border:1px solid %s; border-left:3px solid %s; border-radius:4px;}"
                           % (T.tint(col, 0.08, T.BG), T.tint(col, 0.25, T.BG), col))
        self.setObjectName("Banner")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(T.S4, T.S3, T.S4, T.S3)
        lay.setSpacing(T.S4)
        tb = QVBoxLayout()
        tb.setSpacing(2)
        t = label(title, "PanelTitle", wrap=True)
        tb.addWidget(t)
        if text:
            tb.addWidget(label(text, "Body", wrap=True))
        lay.addLayout(tb, 1)
        if action:
            lay.addWidget(action, 0, Qt.AlignVCenter)


class FindingsList(QWidget):
    """Vertical list of (status, title, detail) rows."""

    def __init__(self, items=(), empty=None):
        super().__init__()
        self.v = QVBoxLayout(self)
        self.v.setContentsMargins(0, 0, 0, 0)
        self.v.setSpacing(T.S2)
        self.set(items, empty)

    def set(self, items, empty=None):
        clear_layout(self.v)
        if not items and empty:
            self.v.addWidget(label(empty, "Muted", wrap=True))
        for it in items:
            st, title = it[0], it[1]
            detail = it[2] if len(it) > 2 else ""
            row = QWidget()                       # a widget per row: height-for-width of wrapped text propagates correctly
            h = QHBoxLayout(row)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(T.S2)
            d = QLabel("●")
            d.setStyleSheet("color:%s; font-size:10px;" % T.STATUS.get(st, T.INFO))
            d.setContentsMargins(0, 2, 0, 0)
            h.addWidget(d, 0, Qt.AlignTop)
            col = QWidget()
            cv = QVBoxLayout(col)
            cv.setContentsMargins(0, 0, 0, 0)
            cv.setSpacing(1)
            cv.addWidget(label(title, "Value", wrap=True, sel=True))
            if detail:
                cv.addWidget(label(detail, "Body", wrap=True, sel=True))
            h.addWidget(col, 1)
            self.v.addWidget(row)


# ---------------------------------------------------------------------------------
#  Data table (model/view - fast for thousands of rows)
# ---------------------------------------------------------------------------------
STATUS_COLS = ("Verdict", "Severity", "Status", "Result", "Health", "State", "Enabled")


class RowModel(QAbstractTableModel):
    def __init__(self, columns):
        super().__init__()
        self.columns = list(columns)
        self.rows, self.tags = [], []
        self.mono_cols = set()

    def set_rows(self, rows, tags=None):
        self.beginResetModel()
        self.rows = list(rows)
        self.tags = list(tags) if tags else [None] * len(self.rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def _val(self, r, c):
        v = self.rows[r].get(self.columns[c])
        if v is None:
            return ""
        if isinstance(v, bool):
            return "Yes" if v else "No"
        if isinstance(v, (list, tuple)):
            return ", ".join(str(x) for x in v)
        return str(v).replace("\r", " ").replace("\n", " ")

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid():
            return None
        r, c = idx.row(), idx.column()
        col = self.columns[c]
        if role == Qt.DisplayRole:
            v = self._val(r, c)
            if col in STATUS_COLS and v:
                return "●  " + v
            return v
        if role == Qt.UserRole:                         # sort key
            v = self.rows[r].get(col)
            if isinstance(v, (int, float)):
                return float(v)
            s = self._val(r, c)
            try:
                return float(s.replace(",", "").split()[0])
            except (ValueError, IndexError):
                return s.lower()
        if role == Qt.ForegroundRole:
            tag = self.tags[r] if r < len(self.tags) else None
            if col in STATUS_COLS:
                v = self._val(r, c).upper()
                for k in ("CRITICAL", "FAIL", "WARNING", "CAUTION", "OK", "GOOD", "PASS"):
                    if k in v:
                        return QBrush(QColor(T.STATUS[k]))
            if tag:
                return QBrush(QColor(T.STATUS.get(tag, T.TEXT)))
            return None
        if role == Qt.FontRole:
            if col in self.mono_cols:
                return T.mono(12)
            return None
        if role == Qt.ToolTipRole:
            v = self._val(r, c)
            return v if len(v) > 40 else None
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.columns[section].upper()
        return None

    def row(self, r):
        return self.rows[r] if 0 <= r < len(self.rows) else {}


class _SortProxy(QSortFilterProxyModel):
    def lessThan(self, a, b):
        x, y = a.data(Qt.UserRole), b.data(Qt.UserRole)
        try:
            return x < y
        except TypeError:
            return str(x) < str(y)


class DataTable(QTableView):
    """set_rows(list_of_dicts, tags) · column widths · double-click -> on_open(row_dict) · sortable · status colouring.
    mono=[column names] renders those columns in the monospaced data font (numbers, sizes, times)."""
    opened = Signal(object)

    def __init__(self, columns, widths=None, on_open=None, mono=(), max_rows_visible=12, stretch_last=True):
        super().__init__()
        self.model_ = RowModel(columns)
        self.model_.mono_cols = set(mono)
        self.proxy = _SortProxy()
        self.proxy.setSourceModel(self.model_)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.sortByColumn(-1, Qt.AscendingOrder)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(34)
        self.setShowGrid(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setWordWrap(False)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setMouseTracking(True)
        self.setFont(T.ui(12, 500))
        h = self.horizontalHeader()
        h.setHighlightSections(False)
        h.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        h.setStretchLastSection(stretch_last)
        h.setSectionResizeMode(QHeaderView.Interactive)
        for i, w in enumerate(widths or []):
            self.setColumnWidth(i, w)
        self.max_rows_visible = max_rows_visible
        self.on_open = on_open
        self.doubleClicked.connect(self._open)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._fit()

    def set_rows(self, rows, tags=None):
        self.model_.set_rows(rows, tags)
        self._fit()

    def _fit(self):
        """Height follows the row count (up to max_rows_visible) so pages don't show big empty tables."""
        n = max(1, min(self.model_.rowCount(), self.max_rows_visible))
        rh = self.verticalHeader().defaultSectionSize()
        hh = self.horizontalHeader().sizeHint().height()
        hs = self.horizontalScrollBar()
        extra = hs.sizeHint().height() if (hs.isVisible() or hs.maximum() > 0) else 0
        self.setFixedHeight(hh + n * rh + 4 + extra + (10 if self.model_.rowCount() > self.max_rows_visible else 0))

    def resizeEvent(self, e):
        super().resizeEvent(e)
        QTimer.singleShot(0, self._refit)

    def _refit(self):
        try:
            self._fit()
        except RuntimeError:
            pass

    def selected(self):
        idx = self.selectionModel().selectedRows()
        if not idx:
            return None
        return self.model_.row(self.proxy.mapToSource(idx[0]).row())

    def _open(self, idx):
        row = self.model_.row(self.proxy.mapToSource(idx).row())
        self.opened.emit(row)
        if self.on_open:
            self.on_open(row)

    @property
    def rows(self):
        return self.model_.rows


# ---------------------------------------------------------------------------------
#  Charts (QPainter, antialiased, flat)
# ---------------------------------------------------------------------------------
class Ring(QWidget):
    """Score ring: value 0..100 (None = unknown '--')."""

    def __init__(self, size=72, width=6):
        super().__init__()
        self.setFixedSize(size, size)
        self.value, self.color, self.w = None, T.MUTED, width
        self.caption = "/ 100"

    def set(self, value, color=None, caption=None):
        self.value = value
        self.color = color or (T.OK if (value or 0) >= 85 else T.WARN if (value or 0) >= 60 else T.CRIT)
        if caption is not None:
            self.caption = caption
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = min(self.width(), self.height())
        r = QRectF(self.w / 2 + 1, self.w / 2 + 1, s - self.w - 2, s - self.w - 2)
        pen = QPen(QColor(T.SURFACE3), self.w)
        pen.setCapStyle(Qt.FlatCap)
        p.setPen(pen)
        p.drawArc(r, 0, 360 * 16)
        if self.value is not None:
            pen.setColor(QColor(self.color))
            p.setPen(pen)
            p.drawArc(r, 90 * 16, int(-360 * 16 * max(0.0, min(1.0, self.value / 100.0))))
        p.setPen(QColor(T.TEXT))
        p.setFont(T.mono(int(s * 0.26), 500))
        p.drawText(QRectF(0, 0, s, s * 0.9), Qt.AlignCenter, "--" if self.value is None else str(int(self.value)))
        p.setPen(QColor(T.MUTED))
        p.setFont(T.mono(max(8, int(s * 0.12))))
        p.drawText(QRectF(0, s * 0.55, s, s * 0.3), Qt.AlignCenter, self.caption)
        p.end()


class Donut(QWidget):
    """Donut chart with a centre total: set([(label, value, color), ...], centre_text)."""

    def __init__(self, size=120, width=14):
        super().__init__()
        self.setFixedSize(size, size)
        self.parts, self.centre, self.w = [], "", width

    def set(self, parts, centre=""):
        self.parts, self.centre = [x for x in parts if x[1]], centre
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = min(self.width(), self.height())
        r = QRectF(self.w / 2 + 1, self.w / 2 + 1, s - self.w - 2, s - self.w - 2)
        tot = float(sum(v for _, v, _ in self.parts)) or 1.0
        pen = QPen(QColor(T.SURFACE3), self.w)
        pen.setCapStyle(Qt.FlatCap)
        if not self.parts:
            p.setPen(pen)
            p.drawArc(r, 0, 360 * 16)
        a = 90.0
        gap = 2.0 if len(self.parts) > 1 else 0
        for _, v, c in self.parts:
            span = 360.0 * v / tot
            pen.setColor(QColor(c))
            p.setPen(pen)
            p.drawArc(r, int((a - gap / 2) * 16), int(-(span - gap) * 16))
            a -= span
        p.setPen(QColor(T.TEXT))
        p.setFont(T.mono(int(s * 0.17), 500))
        p.drawText(QRectF(0, 0, s, s), Qt.AlignCenter, str(self.centre))
        p.end()


class LineChart(QWidget):
    """Flat line chart for one or more series. series=[(values, color, label)], x_labels optional, y max auto.
    None values break the line (lost samples) and are marked with a short red tick on the baseline."""

    def __init__(self, height=150, y_suffix="", min_top=1.0, show_points=False):
        super().__init__()
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.series, self.xl, self.suffix, self.min_top, self.points = [], [], y_suffix, min_top, show_points
        self.refs = []           # [(value, color, label)] horizontal reference lines
        self.fixed_top = None
        self.fixed_bottom = 0.0
        self.mark_gaps = True

    def set(self, series, x_labels=(), refs=(), top=None, bottom=0.0):
        self.series, self.xl, self.refs, self.fixed_top, self.fixed_bottom = list(series), list(x_labels), list(refs), top, bottom
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        W, H = self.width(), self.height()
        x0, x1, y0, y1 = 40, W - 8, 8, H - (20 if self.xl else 8)
        vals = [v for s, _, _ in self.series for v in s if isinstance(v, (int, float))]
        top = self.fixed_top if self.fixed_top is not None else max([self.min_top] + [v * 1.15 for v in vals])
        bot = self.fixed_bottom
        if top <= bot:
            top = bot + 1
        p.setFont(T.mono(10))
        for f in (0.0, 0.5, 1.0):
            y = y1 - (y1 - y0) * f
            p.setPen(QPen(QColor(T.LINE_HEX), 1))
            p.drawLine(QPointF(x0, y), QPointF(x1, y))
            p.setPen(QColor(T.MUTED))
            v = bot + (top - bot) * f
            p.drawText(QRectF(0, y - 8, x0 - 6, 16), Qt.AlignRight | Qt.AlignVCenter, ("%.0f" % v) + self.suffix)
        for v, c, lab in self.refs:
            if bot < v < top:
                y = y1 - (y1 - y0) * (v - bot) / (top - bot)
                pen = QPen(QColor(c), 1, Qt.DashLine)
                p.setPen(pen)
                p.drawLine(QPointF(x0, y), QPointF(x1, y))
                if lab:
                    p.drawText(QRectF(x1 - 120, y - 16, 116, 14), Qt.AlignRight, lab)
        for s, c, _ in self.series:
            n = len(s)
            if n < 1:
                continue
            path, started = QPainterPath(), False
            for i, v in enumerate(s):
                x = x0 + (x1 - x0) * (i / float(max(1, n - 1)))
                if isinstance(v, (int, float)):
                    y = y1 - (y1 - y0) * (min(max(v, bot), top) - bot) / (top - bot)
                    if started:
                        path.lineTo(x, y)
                    else:
                        path.moveTo(x, y)
                        started = True
                else:
                    started = False
                    if self.mark_gaps:
                        p.setPen(QPen(QColor(T.CRIT), 2))
                        p.drawLine(QPointF(x, y1 - 5), QPointF(x, y1))
            p.setPen(QPen(QColor(c), 1.8))
            p.setBrush(Qt.NoBrush)
            p.drawPath(path)
            if self.points:
                p.setBrush(QColor(c))
                for i, v in enumerate(s):
                    if isinstance(v, (int, float)):
                        x = x0 + (x1 - x0) * (i / float(max(1, n - 1)))
                        y = y1 - (y1 - y0) * (min(max(v, bot), top) - bot) / (top - bot)
                        p.drawEllipse(QPointF(x, y), 2.2, 2.2)
        if self.xl:
            p.setPen(QColor(T.MUTED))
            n = len(self.xl)
            for i, t in enumerate(self.xl):
                if not t:
                    continue
                x = x0 + (x1 - x0) * (i / float(max(1, n - 1)))
                al = Qt.AlignLeft if i == 0 else Qt.AlignRight if i == n - 1 else Qt.AlignHCenter
                rx = x if i == 0 else x - 120 if i == n - 1 else x - 60
                p.drawText(QRectF(rx, H - 18, 120, 16), al | Qt.AlignVCenter, t)
        p.end()


class BarChart(QWidget):
    """Simple vertical bars: set([(label, value, color)], top=None)."""

    def __init__(self, height=140):
        super().__init__()
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.items, self.top = [], None
        self.note = ""

    def set(self, items, top=None, note=""):
        self.items, self.top, self.note = list(items), top, note
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        W, H = self.width(), self.height()
        x0, x1, y0, y1 = 8, W - 8, 16, H - 20
        if not self.items:
            p.setPen(QColor(T.MUTED))
            p.drawText(self.rect(), Qt.AlignCenter, self.note or "No data")
            p.end()
            return
        top = self.top or max([v for _, v, _ in self.items] + [1])
        n = len(self.items)
        bw = (x1 - x0) / float(n)
        p.setFont(T.mono(10))
        for i, (lab, v, c) in enumerate(self.items):
            x = x0 + i * bw
            h = (y1 - y0) * min(1.0, v / float(top))
            p.fillRect(QRectF(x + bw * 0.2, y1 - h, bw * 0.6, h), QColor(c))
            p.setPen(QColor(T.MUTED))
            p.drawText(QRectF(x, y1 + 2, bw, 16), Qt.AlignHCenter, str(lab))
        if self.note:
            p.setPen(QColor(T.MUTED))
            p.drawText(QRectF(x0, 0, x1 - x0, 14), Qt.AlignRight, self.note)
        p.end()


class Meter(QWidget):
    """Thin horizontal bar 0..1."""

    def __init__(self, height=4):
        super().__init__()
        self.setFixedHeight(height)
        self.frac, self.color = 0.0, T.ACCENT

    def set(self, frac, color=None):
        self.frac = max(0.0, min(1.0, frac or 0.0))
        self.color = color or self.color
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(T.SURFACE3))
        r = self.rect()
        r.setWidth(int(r.width() * self.frac))
        p.fillRect(r, QColor(self.color))
        p.end()


class StatTile(QFrame):
    """Label · big mono number · sub line. update in place with set()."""

    def __init__(self, label_text, value="--", sub="", status=None):
        super().__init__()
        self.setObjectName("Panel")
        v = QVBoxLayout(self)
        v.setContentsMargins(T.S4, T.S4, T.S4, T.S4)
        v.setSpacing(T.S1)
        top = QHBoxLayout()
        self.lbl = label(label_text, "Label", wrap=True)
        top.addWidget(self.lbl)
        top.addStretch(1)
        self.dot = QLabel("")
        top.addWidget(self.dot)
        v.addLayout(top)
        self.val = label(value, "Big")
        v.addWidget(self.val)
        self.sub = label(sub, "Body", wrap=True)
        v.addWidget(self.sub)
        self.set(value, sub, status)

    def set(self, value, sub=None, status=None):
        self.val.setText(str(value))
        if sub is not None:
            self.sub.setText(sub)
        col = T.STATUS.get(status) if status else None
        self.dot.setText('<span style="color:%s">●</span>' % col if col else "")
        self.sub.setStyleSheet("color:%s;" % col if col else "")


# ---------------------------------------------------------------------------------
#  Dialogs (styled, modal, never block worker threads)
# ---------------------------------------------------------------------------------
def info(parent, text, title="WinDiag"):
    QMessageBox.information(parent, title, text)


def error(parent, text, title="WinDiag"):
    QMessageBox.critical(parent, title, text)


def warn(parent, text, title="WinDiag"):
    QMessageBox.warning(parent, title, text)


def confirm(parent, text, title="WinDiag", danger=False):
    box = QMessageBox(QMessageBox.Warning if danger else QMessageBox.Question, title, text, QMessageBox.Yes | QMessageBox.No, parent)
    box.setDefaultButton(QMessageBox.No if danger else QMessageBox.Yes)
    return box.exec() == QMessageBox.Yes


def ask_text(parent, title, prompt, password=False, placeholder=""):
    d = QDialog(parent)
    d.setWindowTitle(title)
    v = QVBoxLayout(d)
    v.setContentsMargins(T.S5, T.S5, T.S5, T.S5)
    v.setSpacing(T.S3)
    v.addWidget(label(prompt, "Value", wrap=True))
    e = QLineEdit()
    e.setPlaceholderText(placeholder)
    if password:
        e.setEchoMode(QLineEdit.Password)
    v.addWidget(e)
    bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    bb.accepted.connect(d.accept)
    bb.rejected.connect(d.reject)
    v.addWidget(bb)
    d.setMinimumWidth(360)
    e.setFocus()
    return e.text() if d.exec() == QDialog.Accepted else None


class TextDialog(QDialog):
    """Read-only text viewer (details, logs). Non-modal."""

    def __init__(self, parent, title, text):
        super().__init__(parent)
        self.setWindowTitle(title[:90])
        self.resize(820, 520)
        v = QVBoxLayout(self)
        v.setContentsMargins(T.S4, T.S4, T.S4, T.S4)
        t = QPlainTextEdit()
        t.setReadOnly(True)
        t.setFont(T.mono(12))
        t.setPlainText(text)
        v.addWidget(t)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.close)
        v.addWidget(bb)
        self.setAttribute(Qt.WA_DeleteOnClose)


def text_dialog(parent, title, text):
    d = TextDialog(parent, title, text)
    d.show()
    return d


# ---------------------------------------------------------------------------------
#  Page base class
# ---------------------------------------------------------------------------------
class Page(QWidget):
    """Base for every page. Data may arrive any time (background scan); call request_render() - the page is drawn now if
    visible, otherwise the first time it is shown. Keeps the GUI responsive: hidden pages never redraw."""

    def __init__(self, app):
        super().__init__()
        self.app = app
        self._dirty = True
        self._rendering = False

    def request_render(self):
        if self.isVisible():
            self._do_render()
        else:
            self._dirty = True

    def _do_render(self):
        if self._rendering:
            self._dirty = True
            return
        self._rendering = True
        try:
            self._dirty = False
            self.render()
        except Exception as e:
            import core
            core.log_error("render %s" % type(self).__name__, e)
            self.app.set_status("Couldn't draw this page - details saved to Reports\\windiag_errors.log.", "WARNING")
        finally:
            self._rendering = False

    def showEvent(self, e):
        super().showEvent(e)
        if self._dirty:
            self._do_render()
        self.on_show()

    def hideEvent(self, e):
        super().hideEvent(e)
        self.on_hide()

    def render(self):
        """Override: (re)build the page from current data."""

    def on_show(self):
        """Override: start timers etc."""

    def on_hide(self):
        """Override: stop timers etc."""
