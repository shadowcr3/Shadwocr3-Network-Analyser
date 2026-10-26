from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from shadowcr3_na.core.errors import StorageError
from shadowcr3_na.logging_setup import configure_logging
from shadowcr3_na.storage.db import connect

from .workstation import Workstation

log = logging.getLogger(__name__)


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Shadowcr3 Network Analyzer")
    try:
        configure_logging()
    except OSError:
        pass  # logging must never block startup
    try:
        conn = connect()
    except StorageError as exc:
        log.error("history database unavailable: %s", exc)
        QMessageBox.critical(None, "History database", str(exc))
        return 1
    window = Workstation(conn)
    window.show()
    code = app.exec()
    conn.close()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
