import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402

from shadowcr3_na.core.models import Host, Port  # noqa: E402
from shadowcr3_na.gui.host_table import SORT_ROLE, HostTableModel  # noqa: E402
from shadowcr3_na.gui.worker import ScanThread  # noqa: E402


def run_thread(thread, timeout_ms=20000):
    loop = QEventLoop()
    thread.finished.connect(loop.quit)
    QTimer.singleShot(timeout_ms, loop.quit)
    thread.start()
    loop.exec()
    thread.wait()


def test_thread_success(qapp, fake_nmap, guard):
    got = []
    t = ScanThread("192.168.1.5", "discovery", 30, nmap_path=fake_nmap, guard=guard)
    t.succeeded.connect(got.append)
    run_thread(t)
    assert len(got) == 1 and len(got[0].hosts) == 2


def test_thread_reports_failures_with_a_category(qapp, fake_nmap, guard):
    got = []
    t = ScanThread("8.8.8.8", "discovery", 30, nmap_path=fake_nmap, guard=guard)
    t.failed.connect(lambda category, message: got.append((category, message)))
    run_thread(t)
    assert got and got[0][0] == "out_of_scope" and "outside" in got[0][1]


def test_thread_requires_confirmation_for_large_scans(qapp, fake_nmap, guard):
    got = []
    t = ScanThread("192.168.1.0/24", "discovery", 30, nmap_path=fake_nmap, guard=guard)
    t.failed.connect(lambda category, _m: got.append(category))
    run_thread(t)
    assert got == ["confirmation_required"]


def test_thread_cancel(qapp, fake_nmap, guard, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    flags = []
    t = ScanThread("192.168.1.5", "discovery", 60, nmap_path=fake_nmap, guard=guard)
    t.cancelled.connect(lambda: flags.append("cancelled"))
    QTimer.singleShot(500, t.cancel)
    start = time.monotonic()
    run_thread(t)
    assert flags == ["cancelled"] and time.monotonic() - start < 10


HOSTS = (
    Host("192.168.1.100", "up", "AA:BB", "TP-Link", "router.lan",
         (Port(22, "tcp", "open", "ssh", "<img src=x>", "9.6"), Port(443, "tcp", "closed"))),
    Host("192.168.1.2", "up"),
)


def test_model_display_and_shape(qapp):
    m = HostTableModel(HOSTS)
    assert (m.rowCount(), m.columnCount()) == (2, 5)
    assert m.data(m.index(0, 0)) == "192.168.1.100" and m.data(m.index(0, 4)) == "22/ssh"
    assert m.data(m.index(1, 1)) == "-"
    assert m.headerData(0, Qt.Orientation.Horizontal) == "IP"


def test_ip_sort_key_is_numeric(qapp):
    m = HostTableModel(HOSTS)
    assert m.data(m.index(1, 0), SORT_ROLE) < m.data(m.index(0, 0), SORT_ROLE)


def test_tooltip_neutralises_banner_markup(qapp):
    m = HostTableModel(HOSTS)
    tip = m.data(m.index(0, 4), Qt.ItemDataRole.ToolTipRole)
    assert "<img" not in tip and "&lt;img" in tip


def test_set_hosts_resets(qapp):
    m = HostTableModel()
    m.set_hosts(HOSTS)
    assert m.rowCount() == 2
