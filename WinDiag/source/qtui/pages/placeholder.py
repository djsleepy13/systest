from .. import widgets as W


class PlaceholderPage(W.Page):
    """Shown when a page failed to load (the error is in Reports\\windiag_errors.log)."""

    def __init__(self, app, key, err=""):
        super().__init__(app)
        from PySide6.QtWidgets import QVBoxLayout
        v = QVBoxLayout(self)
        sp = W.ScrollPage()
        v.addWidget(sp)
        sp.add(W.Banner("This page couldn't be loaded", "Details were saved to Reports\\windiag_errors.log. (%s)" % err[:200], "WARNING"))
        sp.finish()
