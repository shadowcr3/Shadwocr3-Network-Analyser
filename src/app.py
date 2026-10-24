from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from core.errors import StorageError
from gui.main_window import MainWindow
from storage.db import connect


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Shadowcr3 Network Analyzer")
    app.setApplicationVersion("v0.2")
    try:
        conn = connect()
    except StorageError as exc:
        QMessageBox.critical(None, "History database", str(exc))
        return 1
    window = MainWindow(conn)
    window.show()
    code = app.exec()   
    conn.close()
    return code

if __name__ == "__main__":
    raise SystemExit(main())