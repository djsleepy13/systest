"""Technician PIN prompt (Qt)."""
import re
import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLineEdit, QVBoxLayout

import appsettings as S
from . import theme as T
from . import widgets as W


class PinDialog(QDialog):
    def __init__(self, parent, title, text, confirm=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.result_pin = None
        v = QVBoxLayout(self)
        v.setContentsMargins(T.S5, T.S5, T.S5, T.S5)
        v.setSpacing(T.S3)
        v.addWidget(W.label(text, "Value", wrap=True))
        self.e1 = QLineEdit()
        self.e1.setEchoMode(QLineEdit.Password)
        self.e1.setPlaceholderText("PIN (4-12 digits)")
        self.e1.setFont(T.mono(14))
        v.addWidget(self.e1)
        self.e2 = None
        if confirm:
            self.e2 = QLineEdit()
            self.e2.setEchoMode(QLineEdit.Password)
            self.e2.setPlaceholderText("Repeat PIN")
            self.e2.setFont(T.mono(14))
            v.addWidget(self.e2)
        self.err = W.colored("", T.CRIT, 12)
        v.addWidget(self.err)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(W.button("Cancel", self.reject))
        ok = W.button("OK", self._ok, "primary")
        ok.setDefault(True)
        row.addWidget(ok)
        v.addLayout(row)
        self.setMinimumWidth(360)
        self.e1.setFocus()

    def _ok(self):
        p = self.e1.text().strip()
        if not re.fullmatch(r"\d{4,12}", p):
            self.err.setText("Use 4 to 12 digits.")
            return
        if self.e2 is not None and self.e2.text().strip() != p:
            self.err.setText("The two PINs don't match.")
            return
        self.result_pin = p
        self.accept()

    @staticmethod
    def ask(parent, title, text, confirm=False):
        d = PinDialog(parent, title, text, confirm)
        return d.result_pin if d.exec() == QDialog.Accepted else None


class PinGate(object):
    """Asks for the PIN before risky features; a correct PIN is remembered for 10 minutes."""

    def __init__(self, app):
        self.app = app
        self.until = 0

    def _ask(self, text):
        for _ in range(3):
            p = PinDialog.ask(self.app, "WinDiag - PIN", text)
            if p is None:
                return False
            if S.check_pin(p):
                self.until = time.time() + 600
                return True
            W.error(self.app, "Wrong PIN.")
        return False

    def require(self, what="this"):
        if not S.pin_set() or not S.get("pin_risky"):
            return True
        if time.time() < self.until:
            return True
        return self._ask("Enter the technician PIN to use %s." % what)

    def verify(self, what="this"):
        """Always asks when a PIN is set - for changing/removing the PIN and switching PIN protection off."""
        if not S.pin_set():
            return True
        return self._ask("Enter the current technician PIN to allow %s." % what)

    def startup(self):
        if not S.pin_set() or not S.get("pin_startup"):
            return True
        return self._ask("WinDiag is locked. Enter the technician PIN.")
