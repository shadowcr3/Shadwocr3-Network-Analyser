from __future__ import annotations

import html
import math
import sqlite3
from datetime import datetime, timedelta, timezone

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPen, QWheelEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from shadowcr3_na.core.importers.zeek import parse_zeek_conn
from shadowcr3_na.core.topology import (
    Topology,
    TopologyEdge,
    TopologyNode,
    build_topology,
    circular_layout,
    filter_topology,
    is_recent,
)
from shadowcr3_na.storage import inventory as inv
from shadowcr3_na.storage import investigations as inves

from ..common import choose_investigation, plain_label, safe_audit
from ..tasks import TaskRunner

ASSET_BRUSH, EXTERNAL_BRUSH = QBrush(QColor("#2f7fd1")), QBrush(QColor("#8a8f98"))
NEW_PEN, UNCERTAIN_PEN = QPen(QColor("#2e9e4f"), 4), QPen(QColor("#e08a1e"), 3)
HIGHLIGHTS = ((None, "No highlight"), (1, "New in last hour"), (24, "New in last 24 h"),
              (168, "New in last 7 days"))


class NodeItem(QGraphicsEllipseItem):
    def __init__(self, node: TopologyNode, highlighted: bool) -> None:
        radius = 9 + min(node.degree, 10) * 1.5
        super().__init__(-radius, -radius, 2 * radius, 2 * radius)
        self.node = node
        self.setBrush(ASSET_BRUSH if node.kind == "asset" else EXTERNAL_BRUSH)
        plain = QPen(Qt.GlobalColor.black, 1)
        self.setPen(NEW_PEN if highlighted else UNCERTAIN_PEN if node.uncertain else plain)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setZValue(2)
        label = QGraphicsSimpleTextItem(node.label[:40], self)  # plain text only
        label.setPos(-label.boundingRect().width() / 2, radius + 2)
        self.setToolTip("<pre>" + html.escape(
            f"{node.kind}: {node.id}\n{node.hostname or ''}\n{node.mac or ''}") + "</pre>")


class EdgeItem(QGraphicsLineItem):
    def __init__(self, edge: TopologyEdge, a: QPointF, b: QPointF) -> None:
        super().__init__(a.x(), a.y(), b.x(), b.y())
        self.edge = edge
        width = 1.5 if edge.bytes is None else min(1 + math.log10(edge.bytes + 1), 6)
        pen = QPen(QColor("#6b7280"), max(width, 2.5))
        if edge.kind == "inferred":
            pen.setStyle(Qt.PenStyle.DashLine)
        self.setPen(pen)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setToolTip("<pre>" + html.escape(
            f"{edge.kind} edge: {edge.src} -> {edge.dst}\n{', '.join(edge.protocols)}") + "</pre>")


class TopologyView(QGraphicsView):
    node_selected = Signal(str)
    edge_selected = Signal(str, str)
    selection_cleared = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setAccessibleName("Network topology graph")
        self._scene.selectionChanged.connect(self._on_selection)

    def show_topology(self, topo: Topology, highlight: set[str]) -> None:
        self._scene.blockSignals(True)
        self._scene.clear()
        positions = circular_layout(topo)
        for edge in topo.edges:
            a, b = positions.get(edge.src), positions.get(edge.dst)
            if a and b:
                self._scene.addItem(EdgeItem(edge, QPointF(*a), QPointF(*b)))
        for node in topo.nodes:
            item = NodeItem(node, node.id in highlight)
            item.setPos(*positions[node.id])
            self._scene.addItem(item)
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-60, -60, 60, 60))
        self._scene.blockSignals(False)
        self.selection_cleared.emit()

    def node_count(self) -> int:
        return sum(isinstance(i, NodeItem) for i in self._scene.items())

    def edge_count(self) -> int:
        return sum(isinstance(i, EdgeItem) for i in self._scene.items())

    def select_node(self, node_id: str) -> bool:
        for item in self._scene.items():
            if isinstance(item, NodeItem) and item.node.id == node_id:
                self._scene.clearSelection()
                item.setSelected(True)
                return True
        return False

    def fit(self) -> None:
        if self._scene.items():
            self.fitInView(self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40),
                           Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event: QWheelEvent) -> None:
        factor = 1.15 ** (event.angleDelta().y() / 120)
        scale = self.transform().m11() * factor
        if 0.15 <= scale <= 6:
            self.scale(factor, factor)

    def _on_selection(self) -> None:
        for item in self._scene.selectedItems():
            if isinstance(item, NodeItem):
                self.node_selected.emit(item.node.id)
                return
            if isinstance(item, EdgeItem):
                self.edge_selected.emit(item.edge.src, item.edge.dst)
                return
        self.selection_cleared.emit()


class TopologyPage(QWidget):
    data_changed = Signal()

    def __init__(self, conn: sqlite3.Connection, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._conn = conn
        self._topo: Topology | None = None
        self._selected: tuple[str, str | None] | None = None
        self._tasks = TaskRunner(self)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search IP, hostname or MAC")
        self._search.setClearButtonEnabled(True)
        self._proto = QComboBox()
        self._highlight = QComboBox()
        for hours, label in HIGHLIGHTS:
            self._highlight.addItem(label, hours)
        self._import_btn = QPushButton("Import Zeek conn.log...")
        self._fit_btn = QPushButton("Fit to window")
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        top = QHBoxLayout()
        for w in (self._search, self._proto, self._highlight, self._import_btn, self._fit_btn):
            top.addWidget(w, 1 if w is self._search else 0)
        self._view = TopologyView()
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        self._add_btn = QPushButton("Add selection to investigation...")
        self._add_btn.setEnabled(False)
        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(0, 0, 0, 0)
        side_layout.addWidget(plain_label("Details"))
        side_layout.addWidget(self._details, 1)
        side_layout.addWidget(self._add_btn)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._view)
        split.addWidget(side)
        split.setStretchFactor(0, 3)
        self._notice = plain_label()
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._progress)
        layout.addWidget(split, 1)
        layout.addWidget(self._notice)

        self._search.textChanged.connect(lambda *_: self._render())
        self._proto.currentIndexChanged.connect(lambda *_: self._render())
        self._highlight.currentIndexChanged.connect(lambda *_: self._render())
        self._fit_btn.clicked.connect(self._view.fit)
        self._import_btn.clicked.connect(self._choose_zeek)
        self._add_btn.clicked.connect(self._add_to_investigation)
        self._view.node_selected.connect(self._on_node)
        self._view.edge_selected.connect(self._on_edge)
        self._view.selection_cleared.connect(self._on_cleared)
        self._tasks.busy_changed.connect(self._on_busy)
        self.refresh()

    def refresh(self) -> None:
        self._topo = build_topology(inv.list_assets(self._conn), inv.list_connections(self._conn))
        current = self._proto.currentData()
        protocols = sorted({p for e in self._topo.edges for p in e.protocols})
        self._proto.blockSignals(True)
        self._proto.clear()
        self._proto.addItem("All protocols", None)
        for p in protocols:
            self._proto.addItem(p, p)
        idx = self._proto.findData(current)
        self._proto.setCurrentIndex(max(idx, 0))
        self._proto.blockSignals(False)
        self._render()

    def _render(self) -> None:
        if self._topo is None:
            return
        shown = filter_topology(self._topo, text=self._search.text(),
                                protocol=self._proto.currentData())
        hours = self._highlight.currentData()
        now = datetime.now(timezone.utc)
        recent = {n.id for n in shown.nodes
                  if hours and is_recent(n, timedelta(hours=hours), now)}
        self._view.show_topology(shown, recent)
        self._view.fit()
        self._notice.setText(
            f"{shown.notice} Showing {len(shown.nodes)} node(s) and {len(shown.edges)} "
            f"relationship(s) in {shown.components} group(s). Edges are observed unless drawn dashed "
            "(inferred); external nodes are addresses outside local ranges.")

    # ---- selection -----------------------------------------------------------

    def _on_node(self, ip: str) -> None:
        node = next((n for n in (self._topo.nodes if self._topo else ()) if n.id == ip), None)
        if node is None:
            return
        alerts = inv.alerts_for_ip(self._conn, ip)
        lines = [f"{'Asset' if node.kind == 'asset' else 'External address'}: {node.id}",
                 f"Hostname: {node.hostname or 'unknown'}", f"MAC: {node.mac or 'unknown'}",
                 f"Relationships in this view: {node.degree}",
                 f"First seen: {node.first_seen:%Y-%m-%d %H:%M} UTC" if node.first_seen else "",
                 f"Sources: {', '.join(node.sources) or 'none (not in the asset inventory)'}"]
        if node.uncertain:
            lines.append("UNCERTAIN identity: sources disagree; see the Assets page.")
        lines.append(f"Related alerts: {len(alerts)}")
        lines += [f"  - [{a.status}] {a.signature}" for a in alerts[:10]]
        self._details.setPlainText("\n".join(line for line in lines if line))
        self._selected = (ip, None)
        self._add_btn.setEnabled(inv.asset_id_for_ip(self._conn, ip) is not None)

    def _on_edge(self, src: str, dst: str) -> None:
        edge = next((e for e in (self._topo.edges if self._topo else ())
                     if (e.src, e.dst) == (src, dst)), None)
        if edge is None:
            return
        lines = [f"{edge.kind.capitalize()} relationship: {src} -> {dst}",
                 f"Protocols: {', '.join(edge.protocols)}",
                 f"Destination ports: {', '.join(map(str, edge.ports)) or 'unknown'}",
                 f"Flows: {edge.flows}; packets: {_n(edge.packets)}; bytes: {_n(edge.bytes)}",
                 (f"First seen {edge.first_seen:%Y-%m-%d %H:%M:%S} UTC, last seen "
                 f"{edge.last_seen:%Y-%m-%d %H:%M:%S} UTC"), "Provenance (imports):"]
        for import_id in edge.import_ids:
            row = inv.get_import(self._conn, import_id)
            lines.append(f"  - #{import_id} {row.kind} {row.path} sha256 {row.sha256[:16]}..."
                         if row else f"  - #{import_id} (source import was removed)")
        self._details.setPlainText("\n".join(lines))
        self._selected = (src, dst)
        self._add_btn.setEnabled(bool(inv.connection_ids_between(self._conn, src, dst)))

    def _on_cleared(self) -> None:
        self._selected = None
        self._add_btn.setEnabled(False)
        self._details.setPlainText("Select a node or a relationship to see its evidence.")

    def _add_to_investigation(self) -> None:
        if self._selected is None:
            return
        target = choose_investigation(self, self._conn)
        if target is None:
            return
        src, dst = self._selected
        if dst is None:
            asset_id = inv.asset_id_for_ip(self._conn, src)
            if asset_id is not None:
                inves.add_item(self._conn, target, "asset", asset_id)
        else:
            for cid in inv.connection_ids_between(self._conn, src, dst):
                inves.add_item(self._conn, target, "connection", cid)
        safe_audit(self._conn, "investigation_item_added", investigation_id=target,
                   source="topology")
        self.data_changed.emit()

    # ---- import ----------------------------------------------------------------

    def _choose_zeek(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Zeek conn.log", "",
                                              "Zeek logs (*.log *.json);;All files (*)")
        if path:
            self.import_zeek(path)

    def import_zeek(self, path: str) -> bool:
        return self._tasks.start(
            lambda cancel: parse_zeek_conn(path, cancel=cancel),
            lambda result: self._saved(path, result),
            lambda category, message: self._notice.setText(f"Import failed ({category}): {message}"),
            lambda: self._notice.setText("Import cancelled."))

    def _saved(self, path: str, result: object) -> None:
        try:
            import_id = inv.save_connection_import(self._conn, "zeek_conn", path, result)  # type: ignore[arg-type]
        except sqlite3.Error as exc:
            self._notice.setText(f"Import could not be saved: {exc}")
            return
        safe_audit(self._conn, "import_completed", import_id=import_id, kind="zeek_conn", path=path,
                   sha256=result.sha256, records=len(result.records),  # type: ignore[attr-defined]
                   rejected=result.rejected, truncated=result.truncated)  # type: ignore[attr-defined]
        self.refresh()
        self.data_changed.emit()

    def _on_busy(self, busy: bool) -> None:
        self._progress.setVisible(busy)
        self._import_btn.setEnabled(not busy)

    def shutdown(self) -> None:
        self._tasks.shutdown()


def _n(value: int | None) -> str:
    return "unknown" if value is None else str(value)
