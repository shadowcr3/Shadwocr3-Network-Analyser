"""Small shared GUI helpers. Scan data is attacker-influenced: labels are plain text."""
from __future__ import annotations

import ipaddress
import logging
import sqlite3
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from shadowcr3_na.storage import audit
from shadowcr3_na.storage import investigations as inves

log = logging.getLogger(__name__)
_YES_NO = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No


def plain_label(text: str = "", wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    return label


def confirm(parent: QWidget | None, title: str, text: str) -> bool:
    answer = QMessageBox.question(parent, title, text, _YES_NO, QMessageBox.StandardButton.No)
    return answer == QMessageBox.StandardButton.Yes


def safe_audit(conn: sqlite3.Connection, event: str, **details: Any) -> bool:
    try:
        audit.record(conn, event, **details)
    except sqlite3.Error:
        log.exception("could not write audit event %s", event)
        return False
    return True


class IpItem(QTableWidgetItem):
    """Sorts IP addresses numerically instead of alphabetically."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        try:
            a, b = ipaddress.ip_address(self.text()), ipaddress.ip_address(other.text())
        except ValueError:
            return self.text() < other.text()
        return (a.version, int(a)) < (b.version, int(b))


class NumItem(QTableWidgetItem):
    def __init__(self, value: int | None, text: str | None = None) -> None:
        super().__init__(text if text is not None else ("" if value is None else str(value)))
        self._value = -1 if value is None else value

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, NumItem):
            return self._value < other._value
        return super().__lt__(other)


def make_table(headers: tuple[str, ...]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(list(headers))
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.setSortingEnabled(True)
    return table


def selected_data(table: QTableWidget, column: int = 0) -> Any:
    rows = table.selectionModel().selectedRows(column)
    return rows[0].data(Qt.ItemDataRole.UserRole) if rows else None


def choose_investigation(parent: QWidget | None, conn: sqlite3.Connection) -> int | None:
    """Pick an existing investigation or type a new title; returns its id."""
    titles = [i.title for i in inves.list_investigations(conn)]
    title, ok = QInputDialog.getItem(
        parent, "Add to investigation",
        "Choose an investigation, or type a new title to create one:", titles, 0, True)
    title = title.strip()
    if not ok or not title:
        return None
    existing = inves.find_by_title(conn, title)
    if existing is not None:
        return existing
    created = inves.create_investigation(conn, title)
    safe_audit(conn, "investigation_created", title=title[:200], investigation_id=created)
    return created
