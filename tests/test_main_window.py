import hashlib
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication, Qt  # noqa: E402
from PySide6.QtWidgets import QFileDialog, QMessageBox  # noqa: E402

from shadowcr3_na.gui import main_window as mw  # noqa: E402
from shadowcr3_na.gui.main_window import MainWindow  # noqa: E402
from shadowcr3_na.storage import audit  # noqa: E402
from shadowcr3_na.storage.db import connect  # noqa: E402

YES = QMessageBox.StandardButton.Yes
NO = QMessageBox.StandardButton.No


def wait_for(condition, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def window(qapp, fake_nmap, guard):
    conn = connect(":memory:")
    w = MainWindow(conn, nmap_path=fake_nmap, guard=guard)
    yield w
    w.close()
    conn.close()


def start(w, target="192.168.1.5", profile="discovery"):
    w._target_edit.setText(target)
    w._auth_box.setChecked(True)
    w._profile_box.setCurrentText(profile)
    w._scan_btn.click()


def finished(w):
    return w._thread is None


def names(w):
    return [e.event for e in reversed(audit.list_events(w._conn))]


def answer(monkeypatch, button):
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: button)


def test_scan_is_disabled_until_target_and_authorisation(window):
    assert not window._scan_btn.isEnabled()
    window._target_edit.setText("192.168.1.5")
    assert not window._scan_btn.isEnabled()
    window._auth_box.setChecked(True)
    assert window._scan_btn.isEnabled()


def test_missing_nmap_disables_scanning_and_explains(qapp, tmp_path, guard):
    conn = connect(":memory:")
    w = MainWindow(conn, nmap_path=str(tmp_path / "nope"), guard=guard)
    w._target_edit.setText("192.168.1.5")
    w._auth_box.setChecked(True)
    assert not w._scan_btn.isEnabled()
    assert "Scanning is disabled" in w._env_label.text() and "not found" in w._env_label.text()
    w.close()
    conn.close()


def test_scan_end_to_end_is_audited_and_saved_with_evidence(window):
    start(window)
    assert wait_for(lambda: finished(window) and window._model.rowCount() == 2)
    assert names(window) == ["scan_requested", "scan_started", "scan_completed"]
    events = list(reversed(audit.list_events(window._conn)))
    assert len({e.job_id for e in events}) == 1 and events[0].details["attested"] is True
    assert window._history.count() == 1 and window._export_btn.isEnabled()
    assert window._conn.execute("SELECT attested FROM scans").fetchone()[0] == 1
    assert window._conn.execute("SELECT COUNT(*) FROM raw_output").fetchone()[0] == 1


def test_out_of_scope_is_refused_and_audited_without_a_thread(window, fake_nmap, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))
    start(window, "8.8.8.8")
    assert window._thread is None and "outside" in window._status.text()
    assert names(window) == ["scan_refused"] and not marker.exists()


def test_high_impact_scan_needs_confirmation(window, monkeypatch):
    answer(monkeypatch, NO)
    start(window, "192.168.1.0/24")
    assert window._thread is None
    assert names(window) == ["scan_declined"]
    answer(monkeypatch, YES)
    window._scan_btn.click()
    assert wait_for(lambda: finished(window) and window._history.count() == 1)
    assert "scan_requested" in names(window) and window._job_id is None


def test_cancel_records_request_and_terminal_event(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    start(window)
    assert window._thread is not None and window._cancel_btn.isEnabled()
    window._cancel_btn.click()
    assert wait_for(lambda: finished(window), timeout=10)
    assert names(window) == ["scan_requested", "scan_started", "scan_cancel_requested", "scan_cancelled"]
    assert "cancelled" in window._status.text() and window._history.count() == 0


def test_tool_failure_is_classified_in_the_audit_log(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_EXIT", "3")
    start(window)
    assert wait_for(lambda: finished(window))
    last = audit.list_events(window._conn)[0]
    assert last.event == "scan_failed" and last.details["category"] == "tool_failure"
    assert window._status.text().startswith("Error:")


def test_timeout_is_its_own_event(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    window._timeout_box.setMinimum(1)
    window._timeout_box.setValue(1)
    start(window)
    assert wait_for(lambda: finished(window), timeout=15)
    assert audit.list_events(window._conn)[0].event == "scan_timed_out"


def test_partial_results_are_labelled(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_STDERR", "Warning: Skipping host 192.168.1.9 due to host timeout")
    start(window)
    assert wait_for(lambda: finished(window) and window._model.rowCount() == 2)
    assert "INCOMPLETE" in window._note.text()
    assert "[incomplete]" in window._history.item(0).text()


def test_zero_hosts_message_does_not_claim_absence(window, monkeypatch, tmp_path):
    empty = tmp_path / "empty.xml"
    empty.write_text("<nmaprun version='7.95'><runstats><finished exit='success' elapsed='1'/>"
                     "</runstats></nmaprun>")
    monkeypatch.setenv("FAKE_NMAP_XML", str(empty))
    start(window)
    assert wait_for(lambda: finished(window))
    assert "does not prove" in window._note.text()


def test_scan_is_refused_when_the_audit_log_is_unavailable(window, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))

    def broken(*_a, **_k):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(mw.audit, "record", broken)
    start(window)
    assert window._thread is None and "audit log is unavailable" in window._status.text()
    assert window._job_id is None and not marker.exists()


def test_rapid_second_scan_hits_the_cooldown(window):
    start(window)
    assert wait_for(lambda: finished(window) and window._history.count() == 1)
    window._scan_btn.click()
    assert wait_for(lambda: finished(window))
    assert "Please wait" in window._status.text()
    assert audit.list_events(window._conn)[0].details["category"] == "rate_limited"


def test_selecting_history_reloads_and_marks_it_as_saved(window):
    start(window)
    assert wait_for(lambda: finished(window) and window._history.count() == 1)
    window._clear_result()
    window._history.setCurrentRow(-1)
    window._history.setCurrentRow(0)
    assert window._model.rowCount() == 2 and window._status.text().startswith("Saved scan from")


def test_delete_requires_confirmation_and_is_audited(window, monkeypatch):
    start(window)
    assert wait_for(lambda: finished(window) and window._history.count() == 1)
    answer(monkeypatch, NO)
    window._delete_btn.click()
    assert window._history.count() == 1
    answer(monkeypatch, YES)
    window._delete_btn.click()
    assert window._history.count() == 0 and window._model.rowCount() == 0
    assert audit.list_events(window._conn)[0].event == "scan_deleted"


def test_export_warns_then_writes_and_audits_the_hash(window, tmp_path, monkeypatch):
    out = tmp_path / "report.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), "JSON (*.json)"))
    start(window)
    assert wait_for(lambda: finished(window) and window._model.rowCount() == 2)
    answer(monkeypatch, NO)
    window._export_btn.click()
    assert not out.exists()
    answer(monkeypatch, YES)
    window._export_btn.click()
    event = audit.list_events(window._conn)[0]
    assert event.event == "report_exported"
    assert event.details["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()


def test_closing_during_a_scan_ends_the_job_cleanly(window, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    start(window)
    started = time.monotonic()
    window.close()
    assert time.monotonic() - started < 10
    last = audit.list_events(window._conn)[0]
    assert last.event == "scan_cancelled" and last.details["reason"] == "window_closed"


def test_interrupted_jobs_are_reported_at_startup(qapp, fake_nmap, guard):
    conn = connect(":memory:")
    old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    with conn:
        conn.execute("INSERT INTO audit_log (ts_utc, event, job_id) VALUES (?, 'scan_started', 'dead')", (old,))
    w = MainWindow(conn, nmap_path=fake_nmap, guard=guard)
    assert "interrupted" in w._note.text()
    assert audit.list_events(conn)[0].event == "scan_interrupted"
    w.close()
    conn.close()


def test_table_sorts_ips_numerically(window):
    start(window)
    assert wait_for(lambda: window._model.rowCount() == 2)
    window._proxy.sort(0, Qt.SortOrder.DescendingOrder)
    assert window._proxy.index(0, 0).data() == "192.168.1.20"


def test_labels_never_interpret_scan_data_as_rich_text(window):
    assert window._status.textFormat() == Qt.TextFormat.PlainText
    assert window._note.textFormat() == Qt.TextFormat.PlainText
