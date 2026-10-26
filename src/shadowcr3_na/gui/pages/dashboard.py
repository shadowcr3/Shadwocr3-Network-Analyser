from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable

from PySide6.QtCore import QTimer
from PySide6.QtGui import QHideEvent, QShowEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.core.errors import MetricsUnavailable
from shadowcr3_na.core.netmon import InterfaceInfo, InterfaceSampler, format_rate, list_interfaces
from shadowcr3_na.storage.inventory import counts

from ..charts import LineChart
from ..common import plain_label

WINDOWS = ((60, "Last minute"), (300, "Last 5 minutes"), (600, "Last 10 minutes"))
TILES = (("assets", "Assets"), ("connections", "Observed conversations"),
         ("alerts_open", "Open alerts"), ("scans", "Saved scans"), ("last_scan", "Last scan"))


class DashboardPage(QWidget):
    def __init__(
        self,
        conn: sqlite3.Connection,
        sampler: InterfaceSampler | None = None,
        interfaces_fn: Callable[[], list[InterfaceInfo]] = list_interfaces,
        refresh_ms: int = 1000,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._conn = conn
        self._sampler = sampler or InterfaceSampler()
        self._interfaces_fn = interfaces_fn
        self._refresh_ms = refresh_ms
        self._last_ok: float | None = None

        self._iface_box = QComboBox()
        self._iface_box.setAccessibleName("Network interface")
        self._window_box = QComboBox()
        for seconds, label in WINDOWS:
            self._window_box.addItem(label, seconds)
        self._reload_btn = QPushButton("Reload interfaces")
        top = QHBoxLayout()
        top.addWidget(plain_label("Interface", wrap=False))
        top.addWidget(self._iface_box, 1)
        top.addWidget(self._window_box)
        top.addWidget(self._reload_btn)

        self._tiles: dict[str, object] = {}
        tiles = QHBoxLayout()
        for key, title in TILES:
            frame = QFrame()
            frame.setFrameShape(QFrame.Shape.StyledPanel)
            box = QVBoxLayout(frame)
            value = plain_label("-", wrap=False)
            font = value.font()
            font.setPointSize(font.pointSize() + 6)
            font.setBold(True)
            value.setFont(font)
            box.addWidget(value)
            box.addWidget(plain_label(title, wrap=False))
            tiles.addWidget(frame)
            self._tiles[key] = value

        self._throughput = LineChart("Throughput", format_rate, ("Download", "Upload"))
        self._packets = LineChart("Packet rate", lambda v: format_rate(v, "pkt/s"),
                                  ("Received", "Sent"))
        self._status = plain_label("Waiting for the first measurement...")
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addLayout(tiles)
        layout.addWidget(self._throughput, 1)
        layout.addWidget(self._packets, 1)
        layout.addWidget(self._status)

        self._timer = QTimer(self)
        self._timer.setInterval(refresh_ms)
        self._timer.timeout.connect(self.tick)
        self._iface_box.currentIndexChanged.connect(lambda *_: self._redraw())
        self._window_box.currentIndexChanged.connect(lambda *_: self._redraw())
        self._reload_btn.clicked.connect(self.reload_interfaces)
        self.reload_interfaces()
        self.refresh()

    # ---- data ------------------------------------------------------------

    def reload_interfaces(self) -> None:
        self._iface_box.blockSignals(True)
        self._iface_box.clear()
        try:
            interfaces = self._interfaces_fn()
        except MetricsUnavailable as exc:
            self._iface_box.blockSignals(False)
            self._show_unavailable(str(exc))
            return
        for iface in interfaces:
            self._iface_box.addItem(f"{iface.name} ({'up' if iface.is_up else 'down'})", iface.name)
        preferred = next((i for i in interfaces if i.is_up and not _is_loopback(i.name)), None)
        if preferred is not None:
            self._iface_box.setCurrentIndex(self._iface_box.findData(preferred.name))
        self._iface_box.blockSignals(False)
        self._redraw()

    def refresh(self) -> None:
        data = counts(self._conn)
        for key, _title in TILES:
            value = data[key]
            text = "never" if key == "last_scan" and value is None else (
                f"{value.astimezone():%Y-%m-%d %H:%M}" if key == "last_scan" else str(value))
            self._tiles[key].setText(text)  # type: ignore[attr-defined]

    def tick(self) -> None:
        iface = self._iface_box.currentData()
        if not iface:
            return
        try:
            sample = self._sampler.sample(iface)
        except MetricsUnavailable as exc:
            self._show_unavailable(str(exc))
            return
        if sample is not None:
            self._last_ok = time.monotonic()
        self._redraw()

    def _show_unavailable(self, reason: str) -> None:
        for chart in (self._throughput, self._packets):
            chart.set_message(f"Unavailable: {reason}")
        self._status.setText(f"Metrics unavailable: {reason}")

    def _redraw(self) -> None:
        iface = self._iface_box.currentData()
        if not iface:
            return
        seconds = int(self._window_box.currentData())
        points = max(2, int(seconds * 1000 / self._refresh_ms))
        history = self._sampler.history(iface)[-points:]
        self._throughput.set_data([[s.rx_bps for s in history], [s.tx_bps for s in history]])
        self._packets.set_data([[s.rx_pps for s in history], [s.tx_pps for s in history]])
        caption = f"{self._window_box.currentText()}, {self._refresh_ms / 1000:g} s samples"
        self._throughput.set_caption(caption)
        self._packets.set_caption(caption)
        if not history:
            self._status.setText("Waiting for the first measurement...")
            return
        last = history[-1]
        stale = self._last_ok is not None and time.monotonic() - self._last_ok > 5 * (
            self._refresh_ms / 1000)
        text = (f"Source: {last.source}. These are OS interface counters, not a packet capture. "
                f"Updated {last.ts.astimezone():%H:%M:%S}.")
        if last.note:
            text += f" Note: {last.note} (gap shown)."
        if stale:
            text = "STALE: no new data. " + text
        self._status.setText(text)

    # ---- lifecycle: sample only while visible (resource efficiency) -----------

    def showEvent(self, event: QShowEvent) -> None:
        self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event: QHideEvent) -> None:
        self._timer.stop()
        super().hideEvent(event)


def _is_loopback(name: str) -> bool:
    return name == "lo" or name.lower().startswith(("loopback", "lo0"))
