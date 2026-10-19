import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication, QEventLoop, Qt, QTimer  # noqa: E402

from core.models import Host, Port  # noqa: E402
from gui.host_table import SORT_ROLE, HostTableModel  # noqa: E402
from gui.worker import ScanThread  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QCoreApplication.instance() or QCoreApplication([])


def run_thread(thread, timeout_ms=20000):
    loop = QEventLoop()
    thread.finished.connect(loop.quit)
    QTimer.singleShot(timeout_ms, loop.quit)
    thread.start()
    loop.exec()
    thread.wait()


def test_thread_success(qapp, fake_nmap):
    got = []
    t = ScanThread("192.168.1.0/24", "discovery", 30, nmap_path=fake_nmap)
    t.succeeded.connect(got.append)
    run_thread(t)
    assert len(got) == 1 and len(got[0].hosts) == 2


def test_thread_reports_expected_failure_as_message(qapp, fake_nmap):
    got = []
    t = ScanThread("8.8.8.8", "discovery", 30, nmap_path=fake_nmap)
    t.failed.connect(got.append)
    run_thread(t)
    assert len(got) == 1 and "outside" in got[0]


def test_thread_cancel(qapp, fake_nmap, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    flags = []
    t = ScanThread("192.168.1.5", "discovery", 60, nmap_path=fake_nmap)
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
    assert m.data(m.index(0, 0)) == "192.168.1.100"
    assert m.data(m.index(0, 4)) == "22/ssh"
    assert m.data(m.index(1, 1)) == "-"
    assert m.headerData(0, Qt.Orientation.Horizontal) == "IP"


def test_ip_sort_key_is_numeric(qapp):
    m = HostTableModel(HOSTS)
    assert m.data(m.index(1, 0), SORT_ROLE) < m.data(m.index(0, 0), SORT_ROLE)  # .2 before .100


def test_tooltip_neutralises_banner_markup(qapp):
    tip = HostTableModel(HOSTS).data(HostTableModel(HOSTS).index(0, 4), Qt.ItemDataRole.ToolTipRole)
    assert "<img" not in tip and "&lt;img" in tip


def test_set_hosts_resets(qapp):
    m = HostTableModel()
    assert m.rowCount() == 0
    m.set_hosts(HOSTS)
    assert m.rowCount() == 2
