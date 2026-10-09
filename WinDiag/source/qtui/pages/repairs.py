"""Repairs & Tools page."""
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QVBoxLayout, QWidget

import core
from .. import theme as T
from .. import widgets as W


class RepairsPage(W.Page):
    def __init__(self, app):
        super().__init__(app)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        self.sp = W.ScrollPage()
        v.addWidget(self.sp)
        self.sp.add(W.label("Each repair opens in its own window and is logged to the Reports folder. Nothing runs until you click it.  "
                            "Tip: create a restore point first. Typical order: Clear temp files, DISM + SFC, CHKDSK scan, restart.", "Body", wrap=True))
        groups = []
        for rep in core.REPAIRS:
            if not groups or groups[-1][0] != rep["group"]:
                groups.append((rep["group"], []))
            groups[-1][1].append(rep)
        for name, reps in groups:
            p = W.Panel(name)
            for rep in reps:
                ok = app.is_admin or not rep.get("admin")
                row = QWidget()
                h = QHBoxLayout(row)
                h.setContentsMargins(0, 0, 0, 0)
                h.setSpacing(T.S4)
                b = W.button(rep["name"], lambda r=rep: app._repair(r), icon="wrench", min_w=280)
                b.setStyleSheet("text-align:left;")
                b.setEnabled(ok)
                h.addWidget(b)
                h.addWidget(W.label(rep.get("desc", "") + ("" if ok else "   (needs administrator)"), "Body", wrap=True), 1)
                p.add(row)
            self.sp.add(p)
        tp = W.Panel("Windows tools", "Opens the built-in Windows tool.")
        gw = QWidget()
        g = QGridLayout(gw)
        g.setContentsMargins(0, 0, 0, 0)
        g.setSpacing(T.S2)
        for i, (name, target) in enumerate(core.TOOLS):
            g.addWidget(W.button(name, lambda t=target, n=name: app._tool(n, t)), i // 4, i % 4)
        tp.add(gw)
        self.sp.add(tp)
        self.sp.finish()
        self._dirty = False
