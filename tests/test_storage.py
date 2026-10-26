import os
import sqlite3
import zlib
from datetime import datetime, timedelta, timezone

import pytest

from shadowcr3_na.core.errors import StorageError
from shadowcr3_na.core.models import Host, Port, ScanResult
from shadowcr3_na.storage import audit
from shadowcr3_na.storage import db as dbmod
from shadowcr3_na.storage.db import SCHEMA_VERSION, connect
from shadowcr3_na.storage.repository import (
    delete_scan,
    get_raw_xml,
    get_scan,
    list_scans,
    prune_history,
    save_scan,
)

BASE = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
HOST_A = Host("192.168.1.1", "up", "AA:BB", "TP-Link", "router.lan",
              (Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"), Port(443, "tcp", "closed")))
HOST_B = Host("192.168.1.2", "up")
RAW = "<nmaprun version='7.95'/>"


def make(target="192.168.1.0/24", started=BASE, hosts=None, raw=RAW):
    hosts = (HOST_A, HOST_B) if hosts is None else hosts
    return ScanResult(
        target, "services", "7.99", False, started, 2.5, hosts,
        command=("nmap", "-F", "--", "192.168.1.0/24"), exit_status=0, complete=True,
        warnings=("Warning: x",), raw_sha256="ab" * 32, raw_xml=raw,
    )


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_roundtrip_is_lossless_including_provenance(conn):
    original = make()
    loaded = get_scan(conn, save_scan(conn, original, attested=True))
    assert loaded == original
    assert loaded.command == original.command and loaded.complete is True


def test_missing_scan_is_none(conn):
    assert get_scan(conn, 999) is None and get_raw_xml(conn, 999) is None


def test_list_is_newest_first_with_counts_and_completeness(conn):
    save_scan(conn, make(target="10.0.0.0/24", started=BASE), attested=True)
    save_scan(conn, make(started=BASE + timedelta(hours=1)), attested=True)
    summaries = list_scans(conn)
    assert [s.target for s in summaries] == ["192.168.1.0/24", "10.0.0.0/24"]
    assert all(s.host_count == 2 and s.complete is True for s in summaries)


def test_delete_cascades_to_everything_but_the_audit_log(conn):
    sid = save_scan(conn, make(), attested=True)
    audit.record(conn, "scan_completed", scan_id=sid)
    assert delete_scan(conn, sid) is True and delete_scan(conn, sid) is False
    assert [count(conn, t) for t in ("scans", "hosts", "ports", "raw_output")] == [0, 0, 0, 0]
    assert count(conn, "audit_log") == 1


def test_hostile_strings_are_stored_as_data(conn):
    evil = "x'; DROP TABLE scans;--"
    original = make(hosts=(Host("10.0.0.1", "up", hostname=evil),))
    assert get_scan(conn, save_scan(conn, original, attested=False)) == original


def test_failed_save_leaves_nothing_behind(conn):
    bad = make(hosts=(HOST_B, Host("10.0.0.9", "up", ports=(Port({1}, "tcp", "open"),))))  # type: ignore[arg-type]
    with pytest.raises(sqlite3.Error):
        save_scan(conn, bad, attested=True)
    assert [count(conn, t) for t in ("scans", "hosts", "raw_output")] == [0, 0, 0]


def test_raw_output_roundtrip_and_integrity_check(conn):
    sid = save_scan(conn, make(), attested=True)
    assert get_raw_xml(conn, sid) == RAW
    with conn:
        conn.execute("UPDATE raw_output SET data = ?", (zlib.compress(b"tampered"),))
    with pytest.raises(StorageError, match="integrity"):
        get_raw_xml(conn, sid)
    with conn:
        conn.execute("UPDATE raw_output SET data = ?", (b"not zlib",))
    with pytest.raises(StorageError, match="corrupted"):
        get_raw_xml(conn, sid)


def test_prune_keeps_the_newest(conn):
    ids = [save_scan(conn, make(started=BASE + timedelta(hours=i)), attested=True) for i in range(5)]
    removed = prune_history(conn, keep_last=2)
    assert sorted(removed) == sorted(ids[:3])
    assert [s.id for s in list_scans(conn)] == [ids[4], ids[3]]
    with pytest.raises(ValueError):
        prune_history(conn, -1)


def test_schema_stamp_and_foreign_keys(conn):
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 3
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_data_persists_and_file_is_private(tmp_path):
    db = tmp_path / "sub" / "history.sqlite3"
    c1 = connect(db)
    sid = save_scan(c1, make(), attested=True)
    c1.close()
    c2 = connect(db)
    assert get_scan(c2, sid) == make()
    c2.close()
    if os.name != "nt":
        assert (db.stat().st_mode & 0o777) == 0o600
        assert (db.parent.stat().st_mode & 0o777) == 0o700


def test_newer_database_is_refused(tmp_path):
    db = tmp_path / "future.sqlite3"
    raw = sqlite3.connect(db)
    raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    raw.close()
    with pytest.raises(StorageError, match="Update the app"):
        connect(db)


def test_corrupt_database_is_reported_not_used(tmp_path):
    db = tmp_path / "bad.sqlite3"
    db.write_bytes(b"this is definitely not a sqlite database" * 100)
    with pytest.raises(StorageError):
        connect(db)


def test_migration_v1_to_v2_preserves_data_and_makes_a_backup(tmp_path):
    db = tmp_path / "old.sqlite3"
    old = sqlite3.connect(db)
    old.executescript(dbmod.MIGRATIONS[0] + "PRAGMA user_version = 1;")
    old.execute("INSERT INTO scans (target, profile, nmap_version, privileged, attested,"
                " started_at, duration_s) VALUES ('10.0.0.0/24','discovery','7.94',0,1,"
                "'2026-10-01T00:00:00+00:00',1.5)")
    old.commit()
    old.close()
    conn = connect(db)
    legacy = get_scan(conn, 1)
    assert legacy is not None and legacy.target == "10.0.0.0/24"
    assert legacy.complete is None and legacy.command == () and legacy.raw_sha256 is None
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert (tmp_path / "old.sqlite3.bak-v1").exists()
    conn.close()


def test_failed_migration_rolls_back_completely(tmp_path, monkeypatch):
    db = tmp_path / "m.sqlite3"
    connect(db).close()  # fully migrated
    bad_next = "CREATE TABLE half_done (x INTEGER); SELECT * FROM table_that_does_not_exist;"
    monkeypatch.setattr(dbmod, "MIGRATIONS", (*dbmod.MIGRATIONS, bad_next))
    monkeypatch.setattr(dbmod, "SCHEMA_VERSION", 4)
    with pytest.raises(StorageError, match="migration to version 4 failed"):
        connect(db)
    check = sqlite3.connect(db)
    assert check.execute("PRAGMA user_version").fetchone()[0] == 3
    assert check.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'half_done'").fetchone()[0] == 0
    check.close()


def test_audit_log_is_append_only(conn):
    eid = audit.record(conn, "scan_requested", job_id="j1", target="10.0.0.0/24")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_log SET event = 'x' WHERE id = ?", (eid,))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_log")
    (event,) = audit.list_events(conn)
    assert event.event == "scan_requested" and event.details == {"target": "10.0.0.0/24"}


def test_audit_details_are_bounded(conn):
    audit.record(conn, "scan_failed", message="x" * 50_000)
    (event,) = audit.list_events(conn)
    assert event.details.get("truncated") is True


def test_interrupted_jobs_are_detected_once_and_never_restarted(conn):
    old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    with conn:
        for job, event in (("dead", "scan_started"), ("done", "scan_started"),
                           ("done", "scan_completed")):
            conn.execute("INSERT INTO audit_log (ts_utc, event, job_id) VALUES (?, ?, ?)",
                         (old, event, job))
    audit.record(conn, "scan_started", job_id="running-now")  # recent: must not be flagged
    assert audit.mark_interrupted(conn) == ["dead"]
    assert audit.mark_interrupted(conn) == []
    events = [e.event for e in audit.list_events(conn)]
    assert events.count("scan_interrupted") == 1
