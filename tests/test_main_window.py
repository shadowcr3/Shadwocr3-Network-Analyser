import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication, Qt  # noqa: E402
from PySide6.QtWidgets import QMessageBox  # noqa: E402

from gui.main_window import MainWindow  # noqa: E402
from storage.db import connect  # noqa: E402


def wait_for(condition, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def window(qapp, fake_nmap):
    conn = connect(":memory:")
    w = MainWindow(conn, nmap_path=fake_nmap)
    yield w
    w.close()
    conn.close()


def start(w, target="192.168.1.0/24"):
    w._target_edit.setText(target)
    w._auth_box.setChecked(True)
    w._scan_btn.click()


def test_scan_is_disabled_until_target_and_authorisation(window):
    assert not window._scan_btn.isEnabled()
    window._target_edit.setText("192.168.1.0/24")
    assert not window._scan_btn.isEnabled()
    window._auth_box.setChecked(True)
    assert window._scan_btn.isEnabled()


def test_scan_end_to_end_saves_history(window):
    start(window)
    assert wait_for(lambda: window._thread is None and window._model.rowCount() == 2)
    assert window._history.count() == 1
    row = window._conn.execute("SELECT attested FROM scans").fetchone()
    assert row["attested"] == 1
    assert window._export_btn.isEnabled()


def test_out_of_scope_target_fails_instantly_without_a_thread(window):
    start(window, "8.8.8.8")
    assert window._thread is None
    assert "outside" in window._status.text()
    assert window._history.count() == 0


def test_cancel(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    start(window, "192.168.1.5")
    assert window._thread is not None and window._cancel_btn.isEnabled()
    window._cancel_btn.click()
    assert wait_for(lambda: window._thread is None, timeout=10)
    assert "cancelled" in window._status.text()
    assert window._history.count() == 0


def test_selecting_history_reloads_a_scan(window):
    start(window)
    assert wait_for(lambda: window._thread is None and window._history.count() == 1)
    window._clear_result()
    assert window._model.rowCount() == 0
    window._history.setCurrentRow(-1)
    window._history.setCurrentRow(0)
    assert window._model.rowCount() == 2


def test_delete_removes_scan(window, monkeypatch):
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    start(window)
    assert wait_for(lambda: window._thread is None and window._history.count() == 1)
    window._delete_btn.click()
    assert window._history.count() == 0 and window._model.rowCount() == 0
    assert window._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_export_writes_file(window, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    out = tmp_path / "report.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), "JSON (*.json)"))
    start(window)
    assert wait_for(lambda: window._thread is None and window._model.rowCount() == 2)
    window._export_btn.click()
    assert out.exists() and '"192.168.1.1"' in out.read_text(encoding="utf-8")


def test_closing_during_a_scan_does_not_hang(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    start(window, "192.168.1.5")
    started = time.monotonic()
    window.close()
    assert time.monotonic() - started < 10
    assert wait_for(lambda: window._thread is None, timeout=5)


def test_table_sorts_ips_numerically(window):
    start(window)
    assert wait_for(lambda: window._model.rowCount() == 2)
    window._proxy.sort(0, Qt.SortOrder.DescendingOrder)
    assert window._proxy.index(0, 0).data() == "192.168.1.20"
