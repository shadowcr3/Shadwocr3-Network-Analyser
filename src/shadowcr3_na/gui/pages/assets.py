from __future__ import annotations

import sqlite3

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.storage import inventory as inv
from shadowcr3_na.storage import investigations as inves

from ..common import IpItem, choose_investigation, make_table, plain_label, safe_audit, selected_data

HEADERS = ("IP", "MAC", "Vendor", "Hostname", "First seen", "Last seen", "Sources", "Identity")


class AssetsPage(QWidget):
    data_changed = Signal()

    def __init__(self, conn: sqlite3.Connection, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._conn = conn
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by IP, MAC, vendor, hostname or source")
        self._search.setClearButtonEnabled(True)
        self._add_btn = QPushButton("Add to investigation...")
        self._table = make_table(HEADERS)
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        self._details.setMaximumHeight(110)
        self._count = plain_label()
        top = QHBoxLayout()
        top.addWidget(self._search, 1)
        top.addWidget(self._add_btn)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._details)
        layout.addWidget(self._count)
        self._search.textChanged.connect(self._apply_filter)
        self._table.itemSelectionChanged.connect(self._show_details)
        self._add_btn.clicked.connect(self._add_to_investigation)
        self.refresh()

    def refresh(self) -> None:
        assets = inv.list_assets(self._conn)
        table = self._table
        table.setSortingEnabled(False)
        table.setRowCount(len(assets))
        for row, a in enumerate(assets):
            ip_item = IpItem(a.ip)
            ip_item.setData(Qt.ItemDataRole.UserRole, a.id)
            cells = (a.mac or "", a.vendor or "", a.hostname or "",
                     f"{a.first_seen.astimezone():%Y-%m-%d %H:%M}",
                     f"{a.last_seen.astimezone():%Y-%m-%d %H:%M}", ", ".join(a.sources),
                     "UNCERTAIN" if a.uncertain else "consistent")
            table.setItem(row, 0, ip_item)
            for col, text in enumerate(cells, 1):
                table.setItem(row, col, QTableWidgetItem(text))
        table.setSortingEnabled(True)
        table.resizeColumnsToContents()
        self._apply_filter()
        self._show_details()

    def _apply_filter(self) -> None:
        needle = self._search.text().strip().lower()
        shown = 0
        for row in range(self._table.rowCount()):
            cells = (self._table.item(row, c) for c in range(self._table.columnCount()))
            text = " ".join(cell.text() for cell in cells if cell is not None).lower()
            hide = bool(needle) and needle not in text
            self._table.setRowHidden(row, hide)
            shown += 0 if hide else 1
        self._count.setText(
            f"{shown} of {self._table.rowCount()} asset(s). Assets come from scans and imported "
            "logs; this is a partial inventory, not a complete list of devices.")

    def _show_details(self) -> None:
        asset_id = selected_data(self._table)
        asset = inv.get_asset(self._conn, asset_id) if asset_id is not None else None
        self._add_btn.setEnabled(asset is not None)
        if asset is None:
            self._details.setPlainText("Select an asset to see its provenance.")
            return
        lines = [f"{asset.ip}  {asset.hostname or ''}".strip(),
                 (f"Seen between {asset.first_seen:%Y-%m-%d %H:%M} and "
                 f"{asset.last_seen:%Y-%m-%d %H:%M} UTC"),
                 "Sources: " + (", ".join(asset.sources) or "none")]
        if asset.uncertain:
            lines.append(f"UNCERTAIN: {asset.note or 'sources disagree about this device'}")
        self._details.setPlainText("\n".join(lines))

    def _add_to_investigation(self) -> None:
        asset_id = selected_data(self._table)
        if asset_id is None:
            return
        target = choose_investigation(self, self._conn)
        if target is None:
            return
        inves.add_item(self._conn, target, "asset", asset_id)
        safe_audit(self._conn, "investigation_item_added", investigation_id=target,
                   source="assets", kind="asset", ref_id=asset_id)
        self.data_changed.emit()
