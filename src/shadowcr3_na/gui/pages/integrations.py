from __future__ import annotations

import sqlite3
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.core.integrations import discover_integrations
from shadowcr3_na.core.policy import DEFAULT_LIMITS
from shadowcr3_na.paths import data_root, default_db_path, log_dir
from shadowcr3_na.storage import audit
from shadowcr3_na.storage import inventory as inv

from ..audit_dialog import AuditDialog
from ..common import confirm, make_table, plain_label, safe_audit, selected_data

HEADERS = ("Integration", "Mode", "Sends traffic", "Privileges", "Available", "Version",
           "Capabilities", "Status")
IMPORT_HEADERS = ("Kind", "File", "SHA-256", "Records", "Rejected", "Limit hit", "Imported")


class IntegrationsPage(QWidget):
    data_changed = Signal()

    def __init__(self, conn: sqlite3.Connection, nmap_path: str | None = None,
                 tshark_path: str | None = None, wireshark_path: str | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._conn = conn
        self._paths = (nmap_path, tshark_path, wireshark_path)
        self._tools = make_table(HEADERS)
        self._imports = make_table(IMPORT_HEADERS)
        self._recheck = QPushButton("Re-check tools")
        self._audit_btn = QPushButton("Audit log...")
        self._remove_btn = QPushButton("Remove selected import")
        self._health = plain_label()
        buttons = QHBoxLayout()
        buttons.addWidget(self._recheck)
        buttons.addWidget(self._audit_btn)
        buttons.addStretch(1)
        buttons.addWidget(self._remove_btn)
        layout = QVBoxLayout(self)
        layout.addWidget(plain_label("Integrations: availability is detected, never assumed. "
                                     "Optional tools can be missing without affecting the rest."))
        layout.addWidget(self._tools, 2)
        layout.addWidget(plain_label("Imported evidence (kept with its file hash)"))
        layout.addWidget(self._imports, 2)
        layout.addLayout(buttons)
        layout.addWidget(self._health)
        self._recheck.clicked.connect(self.refresh)
        self._audit_btn.clicked.connect(lambda: AuditDialog(self._conn, self).exec())
        self._remove_btn.clicked.connect(self._remove_import)
        self._imports.itemSelectionChanged.connect(
            lambda: self._remove_btn.setEnabled(selected_data(self._imports) is not None))
        self.refresh()

    def refresh(self) -> None:
        self._fill_tools()
        self._fill_imports()
        self._health.setText(self._health_text())

    def _fill_tools(self) -> None:
        tools = discover_integrations(*self._paths)
        t = self._tools
        t.setSortingEnabled(False)
        t.setRowCount(len(tools))
        for row, i in enumerate(tools):
            cells = (i.name, i.mode, "yes" if i.generates_traffic else "no", i.privileges,
                     "yes" if i.available else "no", i.version or "", "; ".join(i.capabilities),
                     i.status)
            for col, text in enumerate(cells):
                t.setItem(row, col, QTableWidgetItem(text))
        t.setSortingEnabled(True)
        t.resizeColumnsToContents()

    def _fill_imports(self) -> None:
        rows = inv.list_imports(self._conn)
        t = self._imports
        t.setSortingEnabled(False)
        t.setRowCount(len(rows))
        for row, r in enumerate(rows):
            first = QTableWidgetItem(r.kind)
            first.setData(Qt.ItemDataRole.UserRole, r.id)
            t.setItem(row, 0, first)
            for col, text in enumerate((r.path, r.sha256[:16] + "...", str(r.records),
                                        str(r.rejected), "yes" if r.truncated else "no",
                                        f"{r.imported_at.astimezone():%Y-%m-%d %H:%M}"), 1):
                t.setItem(row, col, QTableWidgetItem(text))
        t.setSortingEnabled(True)
        t.resizeColumnsToContents()
        self._remove_btn.setEnabled(False)

    def _health_text(self) -> str:
        db = default_db_path()
        size = f"{db.stat().st_size // 1024} KB" if db.exists() else "in-memory or not created"
        stale = len(audit.interrupted_jobs(self._conn))
        lim = DEFAULT_LIMITS
        return (f"Policies: active scans run one at a time, max {lim.max_rate_pps} packets/s, "
                f"{lim.max_retries} retries, {lim.cooldown_s:g} s cooldown. Imports are capped "
                "(256 MB, 200,000 records). Charts refresh once per second and only while visible.\n"
                f"Data folder: {data_root()}  |  History database: {Path(db).name} ({size})  |  "
                f"Logs: {log_dir()}  |  Unfinished jobs awaiting review: {stale}\n"
                "All data stays on this computer. Nothing is uploaded.")

    def _remove_import(self) -> None:
        import_id = selected_data(self._imports)
        row = inv.get_import(self._conn, import_id) if import_id is not None else None
        if row is None or not confirm(
                self, "Remove import",
                f"Remove the import of {row.path}? Its alerts and conversations will be deleted "
                "from the database (the original file is not touched). Investigations that link "
                "to them will show the evidence as no longer available."):
            return
        inv.delete_import(self._conn, row.id)
        safe_audit(self._conn, "import_deleted", import_id=row.id, kind=row.kind, path=row.path,
                   sha256=row.sha256)
        self.refresh()
        self.data_changed.emit()
