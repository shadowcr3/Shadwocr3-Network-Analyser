from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

THEMES = ("system", "light", "dark")


def apply_theme(app: QApplication, name: str) -> None:
    if name not in THEMES:
        raise ValueError(f"theme must be one of {THEMES}")
    app.setStyle("Fusion")
    if name == "dark":
        pal = QPalette()
        base, text = QColor(30, 30, 34), QColor(230, 230, 235)
        pal.setColor(QPalette.ColorRole.Window, QColor(45, 45, 50))
        pal.setColor(QPalette.ColorRole.WindowText, text)
        pal.setColor(QPalette.ColorRole.Base, base)
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(38, 38, 43))
        pal.setColor(QPalette.ColorRole.Text, text)
        pal.setColor(QPalette.ColorRole.Button, QColor(55, 55, 62))
        pal.setColor(QPalette.ColorRole.ButtonText, text)
        pal.setColor(QPalette.ColorRole.Mid, QColor(90, 90, 100))
        pal.setColor(QPalette.ColorRole.ToolTipBase, base)
        pal.setColor(QPalette.ColorRole.ToolTipText, text)
        pal.setColor(QPalette.ColorRole.Highlight, QColor(47, 127, 209))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        app.setPalette(pal)
    else:
        app.setPalette(app.style().standardPalette())
