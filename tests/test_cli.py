import json
import sqlite3

import pytest

from shadowcr3_na import cli
from shadowcr3_na.core import errors as E
from shadowcr3_na.storage import audit
from shadowcr3_na.storage.db import connect


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "history.sqlite3")


def run(db, guard, *argv, nmap=None):
    full = ["--db", db, *argv]
    if nmap and argv and argv[0] == "scan":
        full += ["--nmap-path", nmap]
    return cli.main(full, guard=guard)


def events(db):
    conn = connect(db)
    try:
        return [(e.event, e.details) for e in reversed(audit.list_events(conn))]
    finally:
        conn.close()


def test_exit_code_mapping():
    assert cli.exit_code_for(E.InvalidTarget("x")) == 2
    assert cli.exit_code_for(E.ScopeViolation("x")) == 3
    assert cli.exit_code_for(E.NmapNotFound("x")) == 4
    assert cli.exit_code_for(E.ScanTimeout("x")) == 5
    assert cli.exit_code_for(E.ParseError("x")) == 6
    assert cli.exit_code_for(E.ConfirmationRequired("x")) == 7
    assert cli.exit_code_for(E.CooldownActive("x")) == 8
    assert cli.exit_code_for(E.StorageError("x")) == 9


def test_missing_attestation_is_refused_and_audited(db, guard, fake_nmap, tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))
    assert run(db, guard, "scan", "192.168.1.5", nmap=fake_nmap) == 2
    assert not marker.exists()
    assert events(db)[0][0] == "scan_refused" and events(db)[0][1]["category"] == "no_attestation"


def test_out_of_scope_and_invalid_targets(db, guard, fake_nmap, capsys):
    assert run(db, guard, "scan", "8.8.8.8", "--i-am-authorised", nmap=fake_nmap) == 3
    assert run(db, guard, "scan", "example.com", "--i-am-authorised", nmap=fake_nmap) == 2
    assert [e[0] for e in events(db)] == ["scan_refused", "scan_refused"]
    assert "outside the allowed scan scope" in capsys.readouterr().err


def test_both_authorisation_spellings_work(db, guard, fake_nmap):
    assert run(db, guard, "scan", "192.168.1.5", "--i-am-authorized", nmap=fake_nmap) == 0


def test_high_impact_needs_confirmation(db, guard, fake_nmap, capsys):
    assert run(db, guard, "scan", "192.168.1.0/24", "--i-am-authorised", nmap=fake_nmap) == 7
    assert "--confirm-high-impact" in capsys.readouterr().err
    assert run(db, guard, "scan", "192.168.1.0/24", "--i-am-authorised",
               "--confirm-high-impact", nmap=fake_nmap) == 0


def test_successful_scan_is_audited_in_order_and_saved(db, guard, fake_nmap, capsys):
    code = run(db, guard, "scan", "192.168.1.5", "--i-am-authorised", "--save", nmap=fake_nmap)
    assert code == 0
    out = capsys.readouterr().out
    assert "router.lan" in out and "192.168.1.20" in out
    names = [e[0] for e in events(db)]
    assert names == ["scan_requested", "scan_started", "scan_completed"]
    assert events(db)[2][1]["saved"] is True
    assert run(db, guard, "history", "list") == 0
    assert "192.168.1.5" in capsys.readouterr().out


def test_missing_nmap_exit_code_and_terminal_event(db, guard, tmp_path):
    code = run(db, guard, "scan", "192.168.1.5", "--i-am-authorised",
               "--nmap-path", str(tmp_path / "nope"))
    assert code == 4
    assert events(db)[-1][0] == "scan_failed" and events(db)[-1][1]["category"] == "missing_dependency"


def test_timeout_is_a_distinct_audit_event(db, guard, fake_nmap, monkeypatch):
    monkeypatch.setenv("FAKE_NMAP_SLEEP", "30")
    assert run(db, guard, "scan", "192.168.1.5", "--i-am-authorised", "-t", "1", nmap=fake_nmap) == 5
    assert events(db)[-1][0] == "scan_timed_out"


def test_scan_does_not_run_when_the_audit_log_is_unavailable(db, guard, fake_nmap, tmp_path, monkeypatch, capsys):
    marker = tmp_path / "ran"
    monkeypatch.setenv("FAKE_NMAP_MARKER", str(marker))

    def broken(*_a, **_k):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(cli.audit, "record", broken)
    monkeypatch.setattr(cli.audit, "mark_interrupted", lambda *_a, **_k: [])
    assert run(db, guard, "scan", "192.168.1.5", "--i-am-authorised", nmap=fake_nmap) == 9
    assert not marker.exists()
    assert "audit log is unavailable" in capsys.readouterr().err


def test_keyboard_interrupt_is_audited_as_cancelled(db, guard, fake_nmap, monkeypatch, capsys):
    def interrupted(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "scan", interrupted)
    assert run(db, guard, "scan", "192.168.1.5", "--i-am-authorised", nmap=fake_nmap) == 130
    assert events(db)[-1] == ("scan_cancelled", {"reason": "keyboard_interrupt"})


def test_history_show_export_delete_prune(db, guard, fake_nmap, tmp_path, capsys):
    for _ in range(3):
        guard_i = type(guard)()
        run(db, guard_i, "scan", "192.168.1.5", "--i-am-authorised", "--save", nmap=fake_nmap)
    capsys.readouterr()
    assert run(db, guard, "history", "show", "1", "--raw") == 0
    assert "<nmaprun" in capsys.readouterr().out
    out = tmp_path / "scan.json"
    assert run(db, guard, "history", "export", "1", str(out)) == 0
    assert json.loads(out.read_text())["schema_version"] == 2
    assert run(db, guard, "history", "delete", "1") == 2  # needs --yes
    assert run(db, guard, "history", "delete", "1", "--yes") == 0
    assert run(db, guard, "history", "prune", "--keep", "1") == 2
    assert run(db, guard, "history", "prune", "--keep", "1", "--yes") == 0
    assert run(db, guard, "history", "show", "999") == 2
    names = [e[0] for e in events(db)]
    assert {"report_exported", "scan_deleted", "history_pruned"} <= set(names)


def test_audit_command_and_doctor(db, guard, fake_nmap, capsys):
    run(db, guard, "scan", "192.168.1.5", "--i-am-authorised", nmap=fake_nmap)
    capsys.readouterr()
    assert run(db, guard, "audit") == 0
    assert "scan_completed" in capsys.readouterr().out
    assert cli.main(["--db", db, "doctor", "--nmap-path", fake_nmap]) == 0
    assert "7.95" in capsys.readouterr().out
    assert cli.main(["--db", db, "doctor", "--nmap-path", "/definitely/not/here"]) == 4


def test_export_flags_write_reports_and_audit_hashes(db, guard, fake_nmap, tmp_path):
    out = tmp_path / "r.csv"
    assert run(db, guard, "scan", "192.168.1.5", "--i-am-authorised", "--csv", str(out),
               nmap=fake_nmap) == 0
    exported = [e for e in events(db) if e[0] == "report_exported"]
    assert out.exists() and len(exported[0][1]["sha256"]) == 64
