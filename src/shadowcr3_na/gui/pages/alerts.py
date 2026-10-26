from __future__ import annotations

import sqlite3

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.core.importers.eve import parse_eve
from shadowcr3_na.core.records import ImportResult
from shadowcr3_na.storage import inventory as inv
from shadowcr3_na.storage import investigations as inves

from ..common import (
    NumItem,
    choose_investigation,
    make_table,
    plain_label,
    safe_audit,
    selected_data,
)
from ..tasks import TaskRunner

SEVERITY = {1: "High", 2: "Medium", 3: "Low"}
HEADERS = ("Severity", "Time (UTC)", "Signature", "Source", "Destination", "Proto/Port", "Status",
           "Tool")
INDICATOR_NOTE = ("An alert is an indicator from a detection engine. It is not confirmation of an "
                  "incident and may be a false positive.")


class AlertsPage(QWidget):
    data_changed = Signal()

    def __init__(self, conn: sqlite3.Connection, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._conn = conn
        self._tasks = TaskRunner(self)
        self._import_btn = QPushButton("Import Suricata EVE JSON...")
        self._status_box = QComboBox()
        self._status_box.addItem("All statuses", None)
        for s in inv.ALERT_STATUSES:
            self._status_box.addItem(s.replace("_", " "), s)
        self._buttons = {name: QPushButton(label) for name, label in (
            ("acknowledged", "Acknowledge"), ("resolved", "Resolve"),
            ("false_positive", "False positive"), ("new", "Reopen"))}
        self._note_btn = QPushButton("Edit note...")
        self._add_btn = QPushButton("Add to investigation...")
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        self._table = make_table(HEADERS)
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        self._info = plain_label()
        row1, row2 = QHBoxLayout(), QHBoxLayout()
        row1.addWidget(self._import_btn)
        row1.addWidget(self._status_box)
        row1.addStretch(1)
        for b in (*self._buttons.values(), self._note_btn, self._add_btn):
            row2.addWidget(b)
        layout = QVBoxLayout(self)
        layout.addLayout(row1)
        layout.addWidget(self._progress)
        layout.addWidget(self._table, 2)
        layout.addLayout(row2)
        layout.addWidget(self._details, 1)
        layout.addWidget(self._info)
        self._import_btn.clicked.connect(self._choose)
        self._status_box.currentIndexChanged.connect(lambda *_: self.refresh())
        for status, button in self._buttons.items():
            button.clicked.connect(lambda _=False, s=status: self.set_status(s))
        self._note_btn.clicked.connect(self._edit_note)
        self._add_btn.clicked.connect(self._add_to_investigation)
        self._table.itemSelectionChanged.connect(self._show)
        self._tasks.busy_changed.connect(self._on_busy)
        self.refresh()

    def refresh(self) -> None:
        selected = selected_data(self._table)
        alerts = inv.list_alerts(self._conn, self._status_box.currentData())
        table = self._table
        table.setSortingEnabled(False)
        table.setRowCount(len(alerts))
        for row, a in enumerate(alerts):
            sev = NumItem(4 - a.severity, SEVERITY.get(a.severity, str(a.severity)))
            sev.setData(Qt.ItemDataRole.UserRole, a.id)
            table.setItem(row, 0, sev)
            for col, text in enumerate((f"{a.ts:%Y-%m-%d %H:%M:%S}", a.signature, a.src or "?",
                                        a.dst or "?",
                                        f"{a.proto or '?'}/{a.dst_port if a.dst_port is not None else '?'}",
                                        a.status.replace("_", " "), a.source), 1):
                table.setItem(row, col, QTableWidgetItem(text))
            if a.id == selected:
                table.selectRow(row)
        table.setSortingEnabled(True)
        table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        table.resizeColumnsToContents()
        total = inv.counts(self._conn)["alerts_total"]
        self._info.setText(f"{len(alerts)} shown of {total} imported alert(s). {INDICATOR_NOTE}")
        self._show()

    def _show(self) -> None:
        alert_id = selected_data(self._table)
        alert = inv.get_alert(self._conn, alert_id) if alert_id is not None else None
        for w in (*self._buttons.values(), self._note_btn, self._add_btn):
            w.setEnabled(alert is not None)
        if alert is None:
            self._details.setPlainText(INDICATOR_NOTE)
            return
        imp = inv.get_import(self._conn, alert.import_id) if alert.import_id else None
        lines = [alert.signature,
                 (f"Severity {alert.severity} ({SEVERITY.get(alert.severity, '?')}); category: "
                 f"{alert.category or 'unknown'}; signature id: {alert.signature_id or 'unknown'}"),
                 (f"{alert.src or '?'} -> {alert.dst or '?'} {alert.proto or ''} "
                 f"port {alert.dst_port if alert.dst_port is not None else '?'}"),
                 f"Status: {alert.status}", f"Analyst note: {alert.note or '(none)'}",
                 f"Source file: {imp.path if imp else '(import removed)'}"
                 + (f" sha256 {imp.sha256}" if imp else ""),
                 "", INDICATOR_NOTE, "", "Original event (evidence):", alert.raw]
        self._details.setPlainText("\n".join(lines))

    # ---- triage ---------------------------------------------------------------

    def set_status(self, status: str) -> None:
        alert_id = selected_data(self._table)
        alert = inv.get_alert(self._conn, alert_id) if alert_id is not None else None
        if alert is None or alert.status == status:
            return
        inv.update_alert(self._conn, alert.id, status=status)
        safe_audit(self._conn, "alert_status_changed", alert_id=alert.id,
                   from_status=alert.status, to_status=status)
        self.refresh()
        self.data_changed.emit()

    def _edit_note(self) -> None:
        alert_id = selected_data(self._table)
        alert = inv.get_alert(self._conn, alert_id) if alert_id is not None else None
        if alert is None:
            return
        text, ok = QInputDialog.getMultiLineText(self, "Alert note", "Analyst note:", alert.note or "")
        if ok:
            self.set_note(alert.id, text)

    def set_note(self, alert_id: int, text: str) -> None:
        inv.update_alert(self._conn, alert_id, note=text.strip())
        safe_audit(self._conn, "alert_note_changed", alert_id=alert_id, length=len(text))
        self.refresh()

    def _add_to_investigation(self) -> None:
        alert_id = selected_data(self._table)
        if alert_id is None:
            return
        target = choose_investigation(self, self._conn)
        if target is None:
            return
        inves.add_item(self._conn, target, "alert", alert_id)
        safe_audit(self._conn, "investigation_item_added", investigation_id=target,
                   source="alerts", kind="alert", ref_id=alert_id)
        self.data_changed.emit()

    # ---- import ----------------------------------------------------------------

    def _choose(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Suricata EVE JSON", "",
                                              "EVE JSON (*.json *.jsonl *.log);;All files (*)")
        if path:
            self.import_eve(path)

    def import_eve(self, path: str) -> bool:
        return self._tasks.start(
            lambda cancel: parse_eve(path, cancel=cancel),
            lambda result: self._saved(path, result),
            lambda category, message: self._info.setText(f"Import failed ({category}): {message}"),
            lambda: self._info.setText("Import cancelled."))

    def _saved(self, path: str, result: ImportResult) -> None:
        try:
            import_id = inv.save_alert_import(self._conn, path, result)
        except sqlite3.Error as exc:
            self._info.setText(f"Import could not be saved: {exc}")
            return
        safe_audit(self._conn, "import_completed", import_id=import_id, kind=result.kind, path=path,
                   sha256=result.sha256, records=len(result.records), rejected=result.rejected,
                   ignored=result.ignored, truncated=result.truncated)
        self.refresh()
        extra = " (stopped at the safety limit)" if result.truncated else ""
        self._info.setText(f"Imported {len(result.records)} alert(s){extra}; {result.rejected} "
                           f"malformed record(s) skipped; {result.ignored} non-alert event(s) "
                           f"ignored. {INDICATOR_NOTE}")
        self.data_changed.emit()

    def _on_busy(self, busy: bool) -> None:
        self._progress.setVisible(busy)
        self._import_btn.setEnabled(not busy)

    def shutdown(self) -> None:
        self._tasks.shutdown()
