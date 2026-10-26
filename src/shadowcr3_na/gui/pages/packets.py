from __future__ import annotations

import logging
import os
import sqlite3
import subprocess
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.core.importers.tshark import (
    CaptureResult,
    connections_from_packets,
    find_wireshark,
    read_capture,
)
from shadowcr3_na.core.records import ImportResult, PacketRecord
from shadowcr3_na.storage import inventory as inv

from ..common import plain_label, safe_audit
from ..tasks import TaskRunner

log = logging.getLogger(__name__)
COLUMNS = ("No.", "Time (UTC)", "Source", "Destination", "Protocol", "Length", "Info")
_Index = QModelIndex | QPersistentModelIndex


class PacketTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self._packets: tuple[PacketRecord, ...] = ()

    def set_packets(self, packets: tuple[PacketRecord, ...]) -> None:
        self.beginResetModel()
        self._packets = packets
        self.endResetModel()

    def rowCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._packets)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        p = self._packets[index.row()]
        if role == Qt.ItemDataRole.UserRole:  # numeric sort key
            return p.number if index.column() == 0 else (p.length or 0) if index.column() == 5 else None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        return (str(p.number), f"{p.ts:%Y-%m-%d %H:%M:%S.%f}" if p.ts else "", p.src or "",
                p.dst or "", p.protocol, "" if p.length is None else str(p.length),
                p.info)[index.column()]


class PacketsPage(QWidget):
    data_changed = Signal()

    def __init__(self, conn: sqlite3.Connection, tshark_path: str | None = None,
                 wireshark_path: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._conn = conn
        self._tshark_path = tshark_path
        self._wireshark = find_wireshark(wireshark_path)
        self._path: str | None = None
        self._capture: CaptureResult | None = None
        self._tasks = TaskRunner(self)
        self._open_btn = QPushButton("Open capture...")
        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Wireshark display filter, e.g. tcp.port == 22")
        self._apply_btn = QPushButton("Apply filter")
        self._ws_btn = QPushButton("Open in Wireshark")
        self._topo_btn = QPushButton("Add conversations to topology")
        self._cancel_btn = QPushButton("Cancel")
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search the displayed packets")
        self._search.setClearButtonEnabled(True)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        self._model = PacketTableModel()
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self._proxy.setFilterKeyColumn(-1)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._status = plain_label(
            "Offline analysis only: this page reads capture files and never captures live "
            "traffic. Packet payloads are not displayed.")
        row1, row2 = QHBoxLayout(), QHBoxLayout()
        for w in (self._open_btn, self._filter, self._apply_btn, self._cancel_btn):
            row1.addWidget(w, 1 if w is self._filter else 0)
        for w in (self._search, self._ws_btn, self._topo_btn):
            row2.addWidget(w, 1 if w is self._search else 0)
        layout = QVBoxLayout(self)
        layout.addLayout(row1)
        layout.addLayout(row2)
        layout.addWidget(self._progress)
        layout.addWidget(self._table, 1)
        layout.addWidget(self._status)
        self._open_btn.clicked.connect(self._choose)
        self._apply_btn.clicked.connect(self._reload)
        self._filter.returnPressed.connect(self._reload)
        self._cancel_btn.clicked.connect(self._tasks.cancel)
        self._search.textChanged.connect(self._proxy.setFilterFixedString)
        self._ws_btn.clicked.connect(self._open_wireshark)
        self._topo_btn.clicked.connect(self._add_to_topology)
        self._tasks.busy_changed.connect(self._update)
        self._update()

    def refresh(self) -> None:
        pass  # nothing is stored here; the capture file is the evidence

    def _update(self, _busy: bool | None = None) -> None:
        busy = self._tasks.busy
        self._progress.setVisible(busy)
        self._cancel_btn.setEnabled(busy)
        self._open_btn.setEnabled(not busy)
        self._apply_btn.setEnabled(not busy and self._path is not None)
        self._ws_btn.setEnabled(not busy and self._path is not None and self._wireshark is not None)
        self._topo_btn.setEnabled(not busy and self._capture is not None
                                  and bool(self._capture.packets))

    def _choose(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open capture", "",
                                              "Captures (*.pcap *.pcapng *.cap);;All files (*)")
        if path:
            self.open_capture(path)

    def open_capture(self, path: str) -> bool:
        self._path = path
        return self._reload()

    def _reload(self) -> bool:
        if self._path is None:
            return False
        path, flt = self._path, self._filter.text().strip() or None
        self._status.setText(f"Reading {os.path.basename(path)} with TShark (no live capture)...")
        return self._tasks.start(
            lambda cancel: read_capture(path, display_filter=flt, cancel=cancel,
                                        tshark_path=self._tshark_path),
            lambda result: self._loaded(path, flt, result), self._failed,
            lambda: self._status.setText("Cancelled."))

    def _loaded(self, path: str, flt: str | None, result: CaptureResult) -> None:
        self._capture = result
        self._model.set_packets(result.packets)
        self._table.resizeColumnsToContents()
        note = f" Stopped after the {len(result.packets)}-packet safety limit." if result.truncated else ""
        self._status.setText(
            f"{os.path.basename(path)}: {len(result.packets)} packet(s) shown"
            f"{f' for filter {flt}' if flt else ''}.{note} TShark {result.tshark_version or '?'}; "
            f"file SHA-256 {result.sha256[:16]}... ({result.size} bytes). Offline analysis; no packets "
            "were captured.")
        safe_audit(self._conn, "capture_opened", path=path, sha256=result.sha256, size=result.size,
                   packets=len(result.packets), truncated=result.truncated, display_filter=flt,
                   tshark=result.tshark_version)
        self._update()

    def _failed(self, category: str, message: str) -> None:
        self._status.setText(f"Could not read the capture ({category}): {message}")
        safe_audit(self._conn, "capture_failed", path=self._path, category=category,
                   message=message[:300])
        self._update()

    def _open_wireshark(self) -> None:
        if self._wireshark is None or self._path is None:
            return
        try:
            subprocess.Popen([self._wireshark, "-r", self._path])  # argument list, no shell
        except OSError as exc:
            self._status.setText(f"Could not start Wireshark: {exc}")
            return
        safe_audit(self._conn, "wireshark_opened", path=self._path)

    def _add_to_topology(self) -> None:
        cap = self._capture
        if cap is None or self._path is None:
            return
        conns, truncated = connections_from_packets(cap.packets)
        without_ip = sum(1 for p in cap.packets if not (p.src and p.dst))
        result = ImportResult("pcap", conns, len(cap.packets), 0, without_ip,
                              cap.truncated or truncated, cap.sha256, cap.size)
        try:
            import_id = inv.save_connection_import(self._conn, "pcap", self._path, result)
        except sqlite3.Error as exc:
            self._status.setText(f"Could not save the conversations: {exc}")
            return
        safe_audit(self._conn, "import_completed", import_id=import_id, kind="pcap",
                   path=self._path, sha256=cap.sha256, records=len(conns), rejected=0,
                   truncated=result.truncated)
        self._status.setText(f"Added {len(conns)} conversation(s) from the displayed packets to "
                             "the topology.")
        self.data_changed.emit()

    def shutdown(self) -> None:
        self._tasks.shutdown()
