from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

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

from shadowcr3_na.core.environment import check_environment
from shadowcr3_na.core.errors import TargetError
from shadowcr3_na.core.export import write_report
from shadowcr3_na.core.models import ScanResult
from shadowcr3_na.core.policy import DEFAULT_LIMITS, Impact, ScanGuard, ScanLimits, assess_impact
from shadowcr3_na.core.profiles import PROFILES
from shadowcr3_na.core.scope import validate_target
from shadowcr3_na.storage import audit
from shadowcr3_na.storage.repository import delete_scan, get_scan, list_scans, save_scan

from .audit_dialog import AuditDialog
from .host_table import SORT_ROLE, HostTableModel
from .worker import ScanThread

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 120
_YES_NO = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No


def _plain_label(text: str = "") -> QLabel:
    # Scan data is attacker-influenced; never let a label interpret it as rich text.
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    return label


class MainWindow(QMainWindow):
    def __init__(
        self,
        conn: sqlite3.Connection,
        nmap_path: str | None = None,
        guard: ScanGuard | None = None,
        limits: ScanLimits = DEFAULT_LIMITS,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Shadowcr3 Network Analyzer")
        self.resize(1080, 700)
        self._conn = conn
        self._nmap_path = nmap_path
        self._guard = guard
        self._limits = limits
        self._thread: ScanThread | None = None
        self._job_id: str | None = None
        self._result: ScanResult | None = None
        self._shown_scan_id: int | None = None
        self._env = check_environment(nmap_path)
        self._build_ui()
        self._show_environment()
        self._report_interrupted()
        self._refresh_history()
        self._update_controls()

    # ---- construction -------------------------------------------------

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
            "Allowed: private, loopback and link-local IPv4, up to 256 addresses. "
            "Large or intrusive scans ask for confirmation."
        )
        self._env_label = _plain_label()
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
        self._audit_btn = QPushButton("Audit log...")

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("History"))
        left_layout.addWidget(self._history, 1)
        left_layout.addWidget(self._delete_btn)
        left_layout.addWidget(self._audit_btn)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self._table, 1)
        right_layout.addWidget(self._export_btn, 0, Qt.AlignmentFlag.AlignRight)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([290, 790])

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addLayout(controls)
        layout.addWidget(self._auth_box)
        layout.addWidget(scope_hint)
        layout.addWidget(self._env_label)
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
        self._audit_btn.clicked.connect(self._show_audit)

    def _show_environment(self) -> None:
        env = self._env
        if env.ready:
            who = (
                "Administrator/root"
                if env.privileged
                else "a standard user (MAC addresses and ARP discovery may be unavailable)"
            )
            text = f"Nmap {env.nmap_version or '?'} found. Running as {who}."
        else:
            text = "Scanning is disabled. " + " ".join(env.problems)
        self._env_label.setText(text)

    def _report_interrupted(self) -> None:
        try:
            stale = audit.mark_interrupted(self._conn)
        except sqlite3.Error:
            log.exception("could not check for interrupted scans")
            return
        if stale:
            self._note.setText(
                f"{len(stale)} earlier scan(s) were interrupted by a shutdown and were not "
                "restarted. See the audit log."
            )

    # ---- state --------------------------------------------------------

    def _can_scan(self) -> bool:
        return (
            self._env.ready
            and bool(self._target_edit.text().strip())
            and self._auth_box.isChecked()
        )

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

    def _audit(self, event: str, *, scan_id: int | None = None, **details: Any) -> bool:
        try:
            audit.record(self._conn, event, job_id=self._job_id, scan_id=scan_id, **details)
        except sqlite3.Error:
            log.exception("could not write audit event %s", event)
            return False
        return True

    def _finish_job(self, event: str, *, scan_id: int | None = None, **details: Any) -> None:
        """Record the single terminal event of a job, exactly once."""
        if self._job_id is None:
            return
        self._audit(event, scan_id=scan_id, **details)
        log.info(event, extra={"job_id": self._job_id, "event": event})
        self._job_id = None

    # ---- scanning -----------------------------------------------------

    def _confirm_high_impact(self, impact: Impact) -> bool:
        answer = QMessageBox.question(
            self,
            "Confirm high-impact scan",
            impact.summary()
            + "\n\nOnly continue if you own this network or have explicit permission.",
            _YES_NO,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _start_scan(self) -> None:
        if self._thread is not None or not self._can_scan():
            return
        target = self._target_edit.text().strip()
        profile_name = self._profile_box.currentData()
        timeout_s = self._timeout_box.value()
        try:
            net = validate_target(target)
        except TargetError as exc:
            self._audit("scan_refused", category=exc.category, target=target,
                        message=str(exc)[:300])
            self._set_status(f"Error: {exc}")
            return
        impact = assess_impact(net, PROFILES[profile_name], self._limits)
        if impact.high and not self._confirm_high_impact(impact):
            self._audit("scan_declined", target=str(net), profile=profile_name,
                        impact=impact.summary())
            self._set_status("Scan not started: high-impact scan was not confirmed.")
            return
        self._job_id = audit.new_job_id()
        recorded = self._audit(
            "scan_requested", target=str(net), profile=profile_name, timeout_s=timeout_s,
            attested=True, high_impact=impact.high, estimated_probes=impact.estimated_probes,
            front_end="gui",
        )
        if not recorded:
            self._job_id = None
            self._set_status("Refusing to scan: the audit log is unavailable. See the log file.")
            return
        thread = ScanThread(
            str(net), profile_name, timeout_s,
            nmap_path=self._nmap_path, guard=self._guard, limits=self._limits,
            confirmed_high_impact=impact.high, parent=self,
        )
        thread.succeeded.connect(self._on_succeeded)
        thread.failed.connect(self._on_failed)
        thread.cancelled.connect(self._on_cancelled)
        thread.finished.connect(self._on_thread_finished)
        self._thread = thread
        self._note.setText("")
        self._set_status(f"Scanning {net} ...")
        self._audit("scan_started", target=str(net))
        thread.start()
        self._update_controls()

    def _cancel_scan(self) -> None:
        if self._thread is not None:
            self._thread.cancel()
            self._cancel_btn.setEnabled(False)
            self._audit("scan_cancel_requested")
            self._set_status("Cancellation requested ... waiting for the scan to stop.")

    def _on_succeeded(self, result: ScanResult) -> None:
        scan_id = None
        saved = True
        try:
            scan_id = save_scan(self._conn, result, attested=self._auth_box.isChecked())
        except sqlite3.Error:
            log.exception("could not save scan")
            saved = False
        self._shown_scan_id = scan_id
        self._show_result(result)
        if not saved:
            self._set_status(
                self._status.text() + " WARNING: it could not be saved to history."
            )
        self._finish_job(
            "scan_completed", scan_id=scan_id, hosts=len(result.hosts),
            complete=result.complete, duration_s=result.duration_s, saved=saved,
        )
        if scan_id is not None:
            self._refresh_history(select_id=scan_id)

    def _on_failed(self, category: str, message: str) -> None:
        event = "scan_timed_out" if category == "timeout" else "scan_failed"
        self._finish_job(event, category=category, message=message[:500])
        self._set_status(f"Error: {message}")

    def _on_cancelled(self) -> None:
        self._finish_job("scan_cancelled", reason="user")
        self._set_status("Scan cancelled. Partial output was discarded.")

    def _on_thread_finished(self) -> None:
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.deleteLater()
        # Safety net: a job must always end with a terminal audit event.
        self._finish_job("scan_failed", category="internal",
                         message="The scan thread ended without reporting a result.")
        self._update_controls()

    # ---- results ------------------------------------------------------

    def _show_result(self, result: ScanResult, historical: bool = False) -> None:
        self._result = result
        self._model.set_hosts(result.hosts)
        self._table.resizeColumnsToContents()
        prefix = (
            f"Saved scan from {result.started_at.astimezone():%Y-%m-%d %H:%M}: "
            if historical
            else ""
        )
        self._set_status(
            f"{prefix}{result.target} ({result.profile}): {len(result.hosts)} host(s) in "
            f"{result.duration_s:.1f}s, nmap {result.nmap_version or '?'}."
        )
        notes = []
        if result.complete is False:
            notes.append("Results may be INCOMPLETE. " + " ".join(result.warnings))
        elif result.complete is None:
            notes.append("Completeness unknown: this record predates completeness tracking.")
        if not result.privileged:
            notes.append(
                "Scanned without Administrator/root privileges: MAC addresses and ARP "
                "discovery may be unavailable, and quiet hosts can be missed."
            )
        if not result.hosts:
            notes.append(
                "No hosts responded. This does not prove the network is empty: devices can "
                "ignore probes, and scans without privileges see less."
            )
        self._note.setText(" ".join(notes))
        self._update_controls()

    def _clear_result(self) -> None:
        self._result = None
        self._shown_scan_id = None
        self._model.set_hosts(())
        self._note.setText("")

    # ---- history ------------------------------------------------------

    def _refresh_history(self, select_id: int | None = None) -> None:
        self._history.blockSignals(True)
        self._history.clear()
        try:
            summaries = list_scans(self._conn)
        except sqlite3.Error:
            log.exception("could not read history")
            summaries = []
        for s in summaries:
            when = s.started_at.astimezone().strftime("%Y-%m-%d %H:%M")
            flag = "  [incomplete]" if s.complete is False else ""
            item = QListWidgetItem(f"{when}  {s.target}  ({s.host_count} hosts){flag}")
            item.setData(Qt.ItemDataRole.UserRole, s.id)
            self._history.addItem(item)
            if s.id == select_id:
                self._history.setCurrentItem(item)
        self._history.blockSignals(False)
        self._update_controls()

    def _on_history_selected(self, current: QListWidgetItem | None, _previous: object) -> None:
        if current is None or self._thread is not None:
            self._update_controls()
            return
        scan_id = current.data(Qt.ItemDataRole.UserRole)
        result = get_scan(self._conn, scan_id)
        if result is not None:
            self._shown_scan_id = scan_id
            self._show_result(result, historical=True)

    def _delete_selected(self) -> None:
        item = self._history.currentItem()
        if item is None or self._thread is not None:
            return
        answer = QMessageBox.question(
            self, "Delete scan",
            "Delete the selected scan and its stored output from history? This cannot be undone.",
            _YES_NO, QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        scan_id = item.data(Qt.ItemDataRole.UserRole)
        delete_scan(self._conn, scan_id)
        self._audit("scan_deleted", scan_id=scan_id)
        self._clear_result()
        self._refresh_history()
        self._set_status("Scan deleted.")

    # ---- export / audit ------------------------------------------------

    def _export(self) -> None:
        if self._result is None:
            return
        answer = QMessageBox.question(
            self, "Export report",
            "Reports contain IP and MAC addresses, hostnames and open services of your "
            "network. Store them securely. Continue?",
            _YES_NO, QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        path, selected = QFileDialog.getSaveFileName(
            self, "Export report", "scan.json", "JSON (*.json);;CSV (*.csv)"
        )
        if not path:
            return
        if not Path(path).suffix:
            path += ".csv" if "csv" in selected.lower() else ".json"
        try:
            info = write_report(self._result, path)
        except (OSError, ValueError) as exc:
            self._audit("report_export_failed", scan_id=self._shown_scan_id, error=str(exc)[:300])
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self._audit("report_exported", scan_id=self._shown_scan_id, path=str(info.path),
                    sha256=info.sha256, size=info.size)
        self._set_status(f"Report written to {info.path} (SHA-256 {info.sha256[:16]}...)")

    def _show_audit(self) -> None:
        AuditDialog(self._conn, self).exec()

    # ---- lifecycle ----------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._thread is not None:
            self._thread.cancel()
            self._thread.wait(10000)  # never destroy a running QThread
            self._finish_job("scan_cancelled", reason="window_closed")
        super().closeEvent(event)
