from __future__ import annotations

import html
import ipaddress
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt

from core.models import Host

COLUMNS = ("IP", "MAC", "Vendor", "Hostname", "Open ports")
SORT_ROLE = Qt.ItemDataRole.UserRole
_Index = QModelIndex | QPersistentModelIndex


class HostTableModel(QAbstractTableModel):
    def __init__(self, hosts: tuple[Host, ...] = (), parent: Any = None) -> None:
        super().__init__(parent)
        self._hosts = tuple(hosts)

    def set_hosts(self, hosts: tuple[Host, ...]) -> None:
        self.beginResetModel()
        self._hosts = tuple(hosts)
        self.endResetModel()

    def host_at(self, row: int) -> Host:
        return self._hosts[row]

    def rowCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._hosts)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        host, col = self._hosts[index.row()], index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._text(host, col)
        if role == SORT_ROLE:
            return self._sort_key(host, col)
        if role == Qt.ItemDataRole.ToolTipRole and col == 4 and host.open_ports:
            return self._ports_tooltip(host)
        return None

    @staticmethod
    def _text(host: Host, col: int) -> str:
        if col == 0:
            return host.ip
        if col == 1:
            return host.mac or "-"
        if col == 2:
            return host.vendor or "-"
        if col == 3:
            return host.hostname or "-"
        return ", ".join(f"{p.number}/{p.service or '?'}" for p in host.open_ports) or "-"

    @classmethod
    def _sort_key(cls, host: Host, col: int) -> Any:
        if col == 0:
            try:
                return int(ipaddress.IPv4Address(host.ip))
            except ValueError:
                return 0
        if col == 4:
            return len(host.open_ports)
        return cls._text(host, col).lower()

    @staticmethod
    def _ports_tooltip(host: Host) -> str:
        # Banners come from the network: escape them, because Qt renders
        # tooltips as rich text.
        lines = (
            f"{p.number}/{p.protocol} {p.service or '?'} {p.product or ''} {p.version or ''}"
            for p in host.open_ports
        )
        return "<pre>" + "\n".join(html.escape(line.strip()) for line in lines) + "</pre>"
