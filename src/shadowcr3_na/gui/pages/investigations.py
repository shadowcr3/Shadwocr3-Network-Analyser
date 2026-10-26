from __future__ import annotations

import sqlite3

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.reports.investigation_report import build_investigation_pdf
from shadowcr3_na.storage import investigations as inves

from ..common import confirm, make_table, plain_label, safe_audit, selected_data

HEADERS = ("Kind", "Ref", "Evidence", "Added (UTC)", "Note")


class InvestigationsPage(QWidget):
    data_changed = Signal()

    def __init__(self, conn: sqlite3.Connection, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._conn = conn
        self._current: int | None = None
        self._list = QListWidget()
        self._new_btn = QPushButton("New...")
        self._delete_btn = QPushButton("Delete")
        self._title = plain_label("Select or create an investigation.")
        self._status_box = QComboBox()
        for s in inves.STATUSES:
            self._status_box.addItem(s, s)
        self._notes = QPlainTextEdit()
        self._notes.setPlaceholderText("Analyst notes: what you looked at, what you concluded and why.")
        self._save_btn = QPushButton("Save notes")
        self._items = make_table(HEADERS)
        self._remove_btn = QPushButton("Remove selected evidence")
        self._export_btn = QPushButton("Export report (PDF)...")
        self._info = plain_label()
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(self._list, 1)
        buttons = QHBoxLayout()
        buttons.addWidget(self._new_btn)
        buttons.addWidget(self._delete_btn)
        left_layout.addLayout(buttons)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.addWidget(self._title, 1)
        head.addWidget(self._status_box)
        right_layout.addLayout(head)
        right_layout.addWidget(self._notes, 1)
        right_layout.addWidget(self._save_btn, 0, Qt.AlignmentFlag.AlignRight)
        right_layout.addWidget(plain_label("Linked evidence (each item keeps its original source)"))
        right_layout.addWidget(self._items, 2)
        actions = QHBoxLayout()
        actions.addWidget(self._remove_btn)
        actions.addStretch(1)
        actions.addWidget(self._export_btn)
        right_layout.addLayout(actions)
        right_layout.addWidget(self._info)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(1, 3)
        layout = QVBoxLayout(self)
        layout.addWidget(split)
        self._list.currentItemChanged.connect(self._on_selected)
        self._new_btn.clicked.connect(self._create)
        self._delete_btn.clicked.connect(self._delete)
        self._save_btn.clicked.connect(self._save_notes)
        self._status_box.activated.connect(self._set_status)
        self._remove_btn.clicked.connect(self._remove_item)
        self._export_btn.clicked.connect(self._export)
        self.refresh()

    def refresh(self) -> None:
        keep = self._current
        self._list.blockSignals(True)
        self._list.clear()
        for inv_ in inves.list_investigations(self._conn):
            item = QListWidgetItem(f"{inv_.title}  [{inv_.status}]")
            item.setData(Qt.ItemDataRole.UserRole, inv_.id)
            self._list.addItem(item)
            if inv_.id == keep:
                self._list.setCurrentItem(item)
        self._list.blockSignals(False)
        self._load(keep if self._list.currentItem() else None)

    def _on_selected(self, current: QListWidgetItem | None, _previous: object) -> None:
        self._load(current.data(Qt.ItemDataRole.UserRole) if current else None)

    def _load(self, inv_id: int | None) -> None:
        self._current = inv_id
        investigation = inves.get_investigation(self._conn, inv_id) if inv_id else None
        for w in (self._status_box, self._notes, self._save_btn, self._export_btn,
                  self._remove_btn, self._delete_btn):
            w.setEnabled(investigation is not None)
        table = self._items
        table.setSortingEnabled(False)
        table.setRowCount(0)
        if investigation is None:
            self._title.setText("Select or create an investigation.")
            self._notes.clear()
            table.setSortingEnabled(True)
            return
        self._title.setText(investigation.title)
        self._status_box.setCurrentIndex(self._status_box.findData(investigation.status))
        self._notes.setPlainText(investigation.notes)
        items = inves.list_items(self._conn, investigation.id)
        table.setRowCount(len(items))
        for row, item in enumerate(items):
            first = QTableWidgetItem(item.kind)
            first.setData(Qt.ItemDataRole.UserRole, item.id)
            table.setItem(row, 0, first)
            for col, text in enumerate((str(item.ref_id), inves.item_summary(self._conn, item),
                                        f"{item.added_at:%Y-%m-%d %H:%M}", item.note), 1):
                table.setItem(row, col, QTableWidgetItem(text))
        table.setSortingEnabled(True)
        table.resizeColumnsToContents()

    def _create(self) -> None:
        title, ok = QInputDialog.getText(self, "New investigation", "Title:")
        if ok and title.strip():
            self.create_investigation(title)

    def create_investigation(self, title: str) -> int:
        inv_id = inves.create_investigation(self._conn, title)
        safe_audit(self._conn, "investigation_created", investigation_id=inv_id, title=title[:200])
        self._current = inv_id
        self.refresh()
        self.data_changed.emit()
        return inv_id

    def _delete(self) -> None:
        if self._current is None or not confirm(
                self, "Delete investigation",
                "Delete this investigation and its links? The underlying evidence is not deleted."):
            return
        inves.delete_investigation(self._conn, self._current)
        safe_audit(self._conn, "investigation_deleted", investigation_id=self._current)
        self._current = None
        self.refresh()
        self.data_changed.emit()

    def _save_notes(self) -> None:
        if self._current is not None:
            inves.update_investigation(self._conn, self._current, notes=self._notes.toPlainText())
            safe_audit(self._conn, "investigation_notes_saved", investigation_id=self._current)
            self._info.setText("Notes saved.")

    def _set_status(self) -> None:
        if self._current is not None:
            status = self._status_box.currentData()
            inves.update_investigation(self._conn, self._current, status=status)
            safe_audit(self._conn, "investigation_status_changed", investigation_id=self._current,
                       status=status)
            self.refresh()

    def _remove_item(self) -> None:
        item_id = selected_data(self._items)
        if item_id is not None:
            inves.remove_item(self._conn, item_id)
            self._load(self._current)

    def _export(self) -> None:
        if self._current is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export investigation report",
                                              "investigation-report.pdf", "PDF report (*.pdf)")
        if path:
            self.export_to(path)

    def export_to(self, path: str) -> None:
        if self._current is None:
            return
        try:
            info = build_investigation_pdf(self._conn, self._current, path)
        except (OSError, ValueError) as exc:
            self._info.setText(f"Export failed: {exc}")
            return
        safe_audit(self._conn, "report_exported", kind="investigation",
                   investigation_id=self._current, path=str(info.path), sha256=info.sha256,
                   size=info.size)
        self._info.setText(f"Report written to {info.path} (SHA-256 {info.sha256[:16]}...). It "
                           "contains network details: store it securely.")
