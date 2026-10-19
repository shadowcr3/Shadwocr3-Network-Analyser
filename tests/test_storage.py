import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from core.errors import StorageError
from core.models import Host, Port, ScanResult
from storage.db import SCHEMA_VERSION, connect
from storage.repository import delete_scan, get_scan, list_scans, save_scan

BASE = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
HOST_A = Host("192.168.1.1", "up", "AA:BB", "TP-Link", "router.lan",
              (Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"), Port(443, "tcp", "closed")))
HOST_B = Host("192.168.1.2", "up")


def make(target="192.168.1.0/24", started=BASE, hosts=None):
    hosts = (HOST_A, HOST_B) if hosts is None else hosts
    return ScanResult(target, "services", "7.99", False, started, 2.5, hosts)


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_roundtrip_is_lossless(conn):
    original = make()
    assert get_scan(conn, save_scan(conn, original, attested=True)) == original


def test_missing_scan_is_none(conn):
    assert get_scan(conn, 999) is None


def test_list_is_newest_first_with_host_counts(conn):
    save_scan(conn, make(target="10.0.0.0/24", started=BASE), attested=True)
    save_scan(conn, make(started=BASE + timedelta(hours=1)), attested=True)
    summaries = list_scans(conn)
    assert [s.target for s in summaries] == ["192.168.1.0/24", "10.0.0.0/24"]
    assert all(s.host_count == 2 for s in summaries)


def test_delete_cascades_to_hosts_and_ports(conn):
    sid = save_scan(conn, make(), attested=True)
    assert delete_scan(conn, sid) is True
    assert delete_scan(conn, sid) is False
    assert (count(conn, "scans"), count(conn, "hosts"), count(conn, "ports")) == (0, 0, 0)


def test_hostile_strings_are_stored_as_data(conn):
    evil = "x'; DROP TABLE scans;--"
    original = make(hosts=(Host("10.0.0.1", "up", hostname=evil),))
    assert get_scan(conn, save_scan(conn, original, attested=False)) == original
    assert count(conn, "scans") == 1


def test_failed_save_leaves_nothing_behind(conn):
    bad = make(hosts=(HOST_B, Host("10.0.0.9", "up", ports=(Port({1}, "tcp", "open"),))))  # type: ignore[arg-type]
    with pytest.raises(sqlite3.Error):
        save_scan(conn, bad, attested=True)
    assert (count(conn, "scans"), count(conn, "hosts")) == (0, 0)


def test_foreign_keys_enforced_and_schema_stamped(conn):
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_data_persists_across_connections(tmp_path):
    db = tmp_path / "sub" / "history.sqlite3"
    c1 = connect(db)
    sid = save_scan(c1, make(), attested=True)
    c1.close()
    c2 = connect(db)
    assert get_scan(c2, sid) == make()
    c2.close()


def test_newer_database_is_refused(tmp_path):
    db = tmp_path / "future.sqlite3"
    raw = sqlite3.connect(db)
    raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    raw.close()
    with pytest.raises(StorageError):
        connect(db)
