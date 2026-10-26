"""The unified shell: navigation, workspaces, themes and data refresh."""
from __future__ import annotations

import sqlite3

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStackedWidget,
    QWidget,
)

from shadowcr3_na import __version__
from shadowcr3_na.core.policy import DEFAULT_LIMITS, ScanGuard, ScanLimits
from shadowcr3_na.paths import data_root

from .main_window import MainWindow
from .pages.alerts import AlertsPage
from .pages.assets import AssetsPage
from .pages.dashboard import DashboardPage
from .pages.integrations import IntegrationsPage
from .pages.investigations import InvestigationsPage
from .pages.packets import PacketsPage
from .pages.topology import TopologyPage
from .theme import THEMES, apply_theme

SAFE_USE = (
    "Only scan networks and devices you own or are explicitly authorised to assess. Imported "
    "alerts are indicators, not proof. Public or imported intelligence is not a live observation "
    "of your network. All data stays on this computer."
)


class Workstation(QMainWindow):
    def __init__(
        self,
        conn: sqlite3.Connection,
        nmap_path: str | None = None,
        tshark_path: str | None = None,
        wireshark_path: str | None = None,
        guard: ScanGuard | None = None,
        limits: ScanLimits = DEFAULT_LIMITS,
        sampler: object | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Shadowcr3 Network Analyzer {__version__}")
        self.resize(1280, 800)
        self._conn = conn
        self.dashboard = DashboardPage(conn, sampler=sampler)  # type: ignore[arg-type]
        self.topology = TopologyPage(conn)
        self.assets = AssetsPage(conn)
        self.packets = PacketsPage(conn, tshark_path, wireshark_path)
        self.alerts = AlertsPage(conn)
        self.recon = MainWindow(conn, nmap_path=nmap_path, guard=guard, limits=limits)
        self.investigations = InvestigationsPage(conn)
        self.integrations = IntegrationsPage(conn, nmap_path, tshark_path, wireshark_path)
        self._pages: list[tuple[str, QWidget]] = [
            ("Dashboard", self.dashboard), ("Topology", self.topology), ("Assets", self.assets),
            ("Packets", self.packets), ("Alerts", self.alerts), ("Reconnaissance", self.recon),
            ("Investigations", self.investigations), ("Integrations", self.integrations)]
        self._nav = QListWidget()
        self._nav.setMaximumWidth(190)
        self._nav.setAccessibleName("Workspaces")
        self._stack = QStackedWidget()
        for number, (title, page) in enumerate(self._pages, 1):
            self._nav.addItem(f"{title}\t(Ctrl+{number})".replace("\t", "  "))
            self._stack.addWidget(page)
            action = QAction(title, self)
            action.setShortcut(QKeySequence(f"Ctrl+{number}"))
            action.triggered.connect(lambda _=False, n=number - 1: self.show_page(n))
            self.addAction(action)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._nav)
        split.addWidget(self._stack)
        split.setStretchFactor(1, 1)
        self.setCentralWidget(split)
        self._nav.currentRowChanged.connect(self._on_nav)
        for page in (self.topology, self.assets, self.packets, self.alerts, self.recon,
                     self.investigations, self.integrations):
            page.data_changed.connect(self.refresh_all)  # type: ignore[attr-defined]
        self._build_menus()
        self.statusBar().showMessage(f"Local data: {data_root()}")
        self._nav.setCurrentRow(0)

    # ---- navigation -------------------------------------------------------------

    def show_page(self, index: int) -> None:
        self._nav.setCurrentRow(index)

    def current_page(self) -> QWidget:
        return self._pages[self._stack.currentIndex()][1]

    def _on_nav(self, row: int) -> None:
        if row < 0:
            return
        self._stack.setCurrentIndex(row)
        page = self._pages[row][1]
        refresh = getattr(page, "refresh", None)
        if callable(refresh) and page is not self.recon:
            refresh()

    def refresh_all(self) -> None:
        for _title, page in self._pages:
            refresh = getattr(page, "refresh", None)
            if callable(refresh) and page is not self.recon:
                refresh()

    # ---- menus -------------------------------------------------------------------

    def _build_menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        quit_action = file_menu.addAction("&Quit")
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        view = bar.addMenu("&View")
        refresh = view.addAction("&Refresh all")
        refresh.setShortcut(QKeySequence("F5"))
        refresh.triggered.connect(self.refresh_all)
        theme_menu = view.addMenu("&Theme")
        group = QActionGroup(self)
        group.setExclusive(True)
        for name in THEMES:
            action = theme_menu.addAction(name.capitalize())
            action.setCheckable(True)
            action.setChecked(name == "system")
            group.addAction(action)
            action.triggered.connect(lambda _=False, n=name: self.set_theme(n))
        help_menu = bar.addMenu("&Help")
        about = help_menu.addAction("&Safe use and about")
        about.triggered.connect(self._about)

    def set_theme(self, name: str) -> None:
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, name)

    def _about(self) -> None:
        QMessageBox.information(self, "Shadowcr3 Network Analyzer", SAFE_USE)

    # ---- lifecycle ---------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        self.recon.shutdown()
        for page in (self.topology, self.packets, self.alerts):
            page.shutdown()
        super().closeEvent(event)
