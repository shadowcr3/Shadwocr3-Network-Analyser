from __future__ import annotations

import sqlite3
from pathlib import Path

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.errors import TargetError
from core.export import write_report
from core.models import ScanResult
from core.profiles import PROFILES
from core.scope import validate_target
from storage.repository import delete_scan, get_scan, list_scans, save_scan

from .host_table import SORT_ROLE, HostTableModel
from .worker import ScanThread

DEFAULT_TIMEOUT_S = 120


def _plain_label(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class MainWindow(QMainWindow):
    def __init__(
        self,
        conn: sqlite3.Connection,
        nmap_path: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Shadowcr3 Network Analyzer")
        self.resize(1050, 650)
        self._conn = conn
        self._nmap_path = nmap_path
        self._thread: ScanThread | None = None
        self._result: ScanResult | None = None
        self._build_ui()
        self._refresh_history()
        self._update_controls()

    def _build_ui(self) -> None:
        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("e.g. 192.168.1.0/24")
        self._target_edit.setClearButtonEnabled(True)
        self._profile_box = QComboBox()
        for i, profile in enumerate(PROFILES.values()):
            self._profile_box.addItem(profile.name, profile.name)
            self._profile_box.setItemData(i, profile.description, Qt.ItemDataRole.ToolTipRole)
        self._timeout_box = QSpinBox()
        self._timeout_box.setRange(10, 3600)
        self._timeout_box.setValue(DEFAULT_TIMEOUT_S)
        self._timeout_box.setSuffix(" s")
        self._scan_btn = QPushButton("Scan")
        self._cancel_btn = QPushButton("Cancel")

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Target"))
        controls.addWidget(self._target_edit, 1)
        controls.addWidget(QLabel("Profile"))
        controls.addWidget(self._profile_box)
        controls.addWidget(QLabel("Timeout"))
        controls.addWidget(self._timeout_box)
        controls.addWidget(self._scan_btn)
        controls.addWidget(self._cancel_btn)

        self._auth_box = QCheckBox("I own this network or have explicit permission to scan it")
        scope_hint = _plain_label(
            "Allowed: private, loopback and link-local IPv4, up to 256 addresses."
        )
        self._status = _plain_label("Ready.")
        self._note = _plain_label()
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # busy indicator
        self._progress.setTextVisible(False)

        self._model = HostTableModel()
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(SORT_ROLE)
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._export_btn = QPushButton("Export report...")

        self._history = QListWidget()
        self._delete_btn = QPushButton("Delete selected")

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("History"))
        left_layout.addWidget(self._history, 1)
        left_layout.addWidget(self._delete_btn)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self._table, 1)
        right_layout.addWidget(self._export_btn, 0, Qt.AlignmentFlag.AlignRight)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 770])

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addLayout(controls)
        layout.addWidget(self._auth_box)
        layout.addWidget(scope_hint)
        layout.addWidget(self._status)
        layout.addWidget(self._note)
        layout.addWidget(self._progress)
        layout.addWidget(splitter, 1)
        self.setCentralWidget(root)

        self._scan_btn.clicked.connect(self._start_scan)
        self._cancel_btn.clicked.connect(self._cancel_scan)
        self._target_edit.returnPressed.connect(self._start_scan)
        self._target_edit.textChanged.connect(lambda *_: self._update_controls())
        self._auth_box.toggled.connect(lambda *_: self._update_controls())
        self._history.currentItemChanged.connect(self._on_history_selected)
        self._delete_btn.clicked.connect(self._delete_selected)
        self._export_btn.clicked.connect(self._export)

    def _can_scan(self) -> bool:
        return bool(self._target_edit.text().strip()) and self._auth_box.isChecked()

    def _update_controls(self) -> None:
        scanning = self._thread is not None
        self._scan_btn.setEnabled(self._can_scan() and not scanning)
        self._cancel_btn.setEnabled(scanning)
        for widget in (self._target_edit, self._profile_box, self._timeout_box, self._auth_box):
            widget.setEnabled(not scanning)
        self._progress.setVisible(scanning)
        self._export_btn.setEnabled(self._result is not None and not scanning)
        self._delete_btn.setEnabled(self._history.currentItem() is not None and not scanning)

    def _set_status(self, text: str) -> None:
        self._status.setText(text)

    def _start_scan(self) -> None:
        if self._thread is not None or not self._can_scan():
            return
        target = self._target_edit.text().strip()
        try:
            validate_target(target)  # instant feedback, no thread needed
        except TargetError as exc:
            self._set_status(f"Error: {exc}")
            return
        thread = ScanThread(
            target,
            self._profile_box.currentData(),
            self._timeout_box.value(),
            nmap_path=self._nmap_path,
            parent=self,
        )
        thread.succeeded.connect(self._on_succeeded)
        thread.failed.connect(self._on_failed)
        thread.cancelled.connect(self._on_cancelled)
        thread.finished.connect(self._on_thread_finished)
        self._thread = thread
        self._note.setText("")
        self._set_status(f"Scanning {target} ...")
        thread.start()
        self._update_controls()

    def _cancel_scan(self) -> None:
        if self._thread is not None:
            self._thread.cancel()
            self._cancel_btn.setEnabled(False)
            self._set_status("Cancelling ...")

    def _on_succeeded(self, result: ScanResult) -> None:
        self._show_result(result)
        try:
            scan_id = save_scan(self._conn, result, attested=self._auth_box.isChecked())
        except sqlite3.Error as exc:
            self._set_status(f"Scan finished, but it could not be saved to history: {exc}")
            return
        self._refresh_history(select_id=scan_id)

    def _on_failed(self, message: str) -> None:
        self._set_status(f"Error: {message}")

    def _on_cancelled(self) -> None:
        self._set_status("Scan cancelled.")

    def _on_thread_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.deleteLater()
        self._update_controls()

    def _show_result(self, result: ScanResult) -> None:
        self._result = result
        self._model.set_hosts(result.hosts)
        self._table.resizeColumnsToContents()
        self._set_status(
            f"{result.target} ({result.profile}): {len(result.hosts)} host(s) in "
            f"{result.duration_s:.1f}s, nmap {result.nmap_version or '?'}."
        )
        notes = []
        if not result.privileged:
            notes.append(
                "Scanned without Administrator/root privileges: MAC addresses and ARP "
                "discovery may be unavailable, and quiet hosts can be missed."
            )
        if not result.hosts:
            notes.append("No hosts responded. That is a valid result, not an error.")
        self._note.setText(" ".join(notes))
        self._update_controls()

    def _clear_result(self) -> None:
        self._result = None
        self._model.set_hosts(())
        self._note.setText("")

    def _refresh_history(self, select_id: int | None = None) -> None:
        self._history.blockSignals(True)
        self._history.clear()
        for summary in list_scans(self._conn):
            when = summary.started_at.astimezone().strftime("%Y-%m-%d %H:%M")
            item = QListWidgetItem(f"{when}  {summary.target}  ({summary.host_count} hosts)")
            item.setData(Qt.ItemDataRole.UserRole, summary.id)
            self._history.addItem(item)
            if summary.id == select_id:
                self._history.setCurrentItem(item)
        self._history.blockSignals(False)
        self._update_controls()


    def _on_history_selected(self, current: QListWidgetItem | None, _previous: object) -> None:
        if current is None or self._thread is not None:
            self._update_controls()
            return
        result = get_scan(self._conn, current.data(Qt.ItemDataRole.UserRole))
        if result is not None:
            self._show_result(result)
            self._set_status("Loaded from history: " + self._status.text())

    def _delete_selected(self) -> None:
        item = self._history.currentItem()
        if item is None or self._thread is not None:
            return
        answer = QMessageBox.question(
            self, "Delete scan", "Delete the selected scan from history?"
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        delete_scan(self._conn, item.data(Qt.ItemDataRole.UserRole))
        self._clear_result()
        self._refresh_history()
        self._set_status("Scan deleted.")

    def _export(self) -> None:
        if self._result is None:
            return
        path, selected = QFileDialog.getSaveFileName(
            self, "Export report", "scan.json", "JSON (*.json);;CSV (*.csv)"
        )
        if not path:
            return
        if not Path(path).suffix:
            path += ".csv" if "csv" in selected.lower() else ".json"
        try:
            written = write_report(self._result, path)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self._set_status(f"Report written to {written}")

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None:
            self._thread.cancel()
            self._thread.wait(10000)  # never destroy a running QThread
        super().closeEvent(event)
