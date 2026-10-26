from __future__ import annotations

import json
import sqlite3

from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.storage.audit import list_events

HEADERS = ("Time", "Event", "Job", "Scan", "Details")


class AuditDialog(QDialog):
    def __init__(self, conn: sqlite3.Connection, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Audit log")
        self.resize(980, 460)
        events = list_events(conn, 500)
        self.table = QTableWidget(len(events), len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for row, e in enumerate(events):
            cells = (
                f"{e.ts.astimezone():%Y-%m-%d %H:%M:%S}",
                e.event,
                (e.job_id or "-")[:8],
                str(e.scan_id or "-"),
                json.dumps(e.details, sort_keys=True),
            )
            for col, text in enumerate(cells):
                self.table.setItem(row, col, QTableWidgetItem(text))  # plain text items
        self.table.resizeColumnsToContents()
        note = QLabel(
            "Append-only record of significant actions taken by this application on this "
            "computer. A privileged local user can still edit the database file directly."
        )
        note.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(note)
        layout.addWidget(self.table, 1)
        layout.addWidget(buttons)
