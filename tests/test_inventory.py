import json
from datetime import datetime, timedelta, timezone

import pytest

from shadowcr3_na.core.importers.eve import parse_eve
from shadowcr3_na.core.importers.zeek import parse_zeek_conn
from shadowcr3_na.core.models import Host, ScanResult
from shadowcr3_na.storage import inventory as inv
from shadowcr3_na.storage.db import connect
from shadowcr3_na.storage.repository import save_scan
from test_importers import ALERT, ZEEK_TSV, write_lines

T0 = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def scan_with(hosts, started=T0):
    return ScanResult("10.0.0.0/24", "discovery", "7.95", False, started, 1.0, tuple(hosts))


def test_local_address_classification():
    assert inv.is_local_address("10.0.0.5") and inv.is_local_address("127.0.0.1")
    assert inv.is_local_address("fe80::1") and inv.is_local_address("fd00::1")
    assert not inv.is_local_address("93.184.216.34") and not inv.is_local_address("garbage")


def test_scan_hosts_become_assets_with_provenance(conn):
    result = scan_with([Host("10.0.0.5", "up", "AA:BB", "TP", "pc.lan"), Host("10.0.0.9", "down")])
    sid = save_scan(conn, result, attested=True)
    assert inv.upsert_assets_from_scan(conn, sid, result) == 1
    (a,) = inv.list_assets(conn)
    assert (a.ip, a.mac, a.hostname, a.uncertain) == ("10.0.0.5", "AA:BB", "pc.lan", False)
    assert a.sources == (f"nmap-scan:{sid}",) and a.first_seen == T0


def test_asset_merge_widens_the_time_range_and_adds_sources(conn):
    with conn:
        inv.upsert_asset(conn, "10.0.0.5", source="a", first_seen=T0, mac="AA:BB")
        inv.upsert_asset(conn, "10.0.0.5", source="b", first_seen=T0 - timedelta(days=1),
                         last_seen=T0 + timedelta(days=1), hostname="pc.lan")
    (a,) = inv.list_assets(conn)
    assert a.first_seen == T0 - timedelta(days=1) and a.last_seen == T0 + timedelta(days=1)
    assert a.sources == ("a", "b") and a.hostname == "pc.lan" and not a.uncertain


def test_conflicting_mac_is_flagged_uncertain_not_overwritten(conn):
    with conn:
        inv.upsert_asset(conn, "10.0.0.5", source="scan1", first_seen=T0, mac="AA:AA")
        inv.upsert_asset(conn, "10.0.0.5", source="scan2", first_seen=T0, mac="BB:BB")
    (a,) = inv.list_assets(conn)
    assert a.mac == "AA:AA" and a.uncertain and "BB:BB" in (a.note or "")


def test_zeek_import_creates_connections_and_only_local_assets(conn, tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(ZEEK_TSV)
    import_id = inv.save_connection_import(conn, "zeek_conn", str(path), parse_zeek_conn(path))
    conns = inv.list_connections(conn)
    assert len(conns) == 2 and all(c.import_id == import_id and c.kind == "observed" for c in conns)
    assert {a.ip for a in inv.list_assets(conn)} == {"10.0.0.5", "10.0.0.7", "10.0.0.1"}
    row = inv.get_import(conn, import_id)
    assert row.kind == "zeek_conn" and len(row.sha256) == 64 and row.rejected == 1


def test_alert_import_and_triage(conn, tmp_path):
    path = write_lines(tmp_path, [json.dumps(ALERT)])
    import_id = inv.save_alert_import(conn, str(path), parse_eve(path))
    (alert,) = inv.list_alerts(conn)
    assert alert.status == "new" and alert.import_id == import_id and alert.severity == 2
    assert inv.update_alert(conn, alert.id, status="acknowledged", note="checking with owner")
    assert inv.get_alert(conn, alert.id).status == "acknowledged"
    assert [a.id for a in inv.list_alerts(conn, status="new")] == []
    with pytest.raises(ValueError):
        inv.update_alert(conn, alert.id, status="bogus")
    assert inv.update_alert(conn, alert.id) is False
    assert inv.update_alert(conn, 999, status="resolved") is False


def test_alerts_sort_by_severity_then_recency(conn, tmp_path):
    lines = [json.dumps({**ALERT, "alert": {**ALERT["alert"], "severity": sev, "signature": f"s{sev}"}})
             for sev in (3, 1, 2)]
    path = write_lines(tmp_path, lines)
    inv.save_alert_import(conn, str(path), parse_eve(path))
    assert [a.severity for a in inv.list_alerts(conn)] == [1, 2, 3]


def test_deleting_an_import_removes_its_records_but_keeps_assets(conn, tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(ZEEK_TSV)
    import_id = inv.save_connection_import(conn, "zeek_conn", str(path), parse_zeek_conn(path))
    assert inv.delete_import(conn, import_id) and not inv.delete_import(conn, import_id)
    assert inv.list_connections(conn) == [] and len(inv.list_assets(conn)) == 3


def test_counts_for_the_dashboard(conn, tmp_path):
    assert inv.counts(conn)["assets"] == 0 and inv.counts(conn)["last_scan"] is None
    path = write_lines(tmp_path, [json.dumps(ALERT)])
    inv.save_alert_import(conn, str(path), parse_eve(path))
    save_scan(conn, scan_with([]), attested=True)
    c = inv.counts(conn)
    assert (c["alerts_total"], c["alerts_open"], c["scans"], c["imports"]) == (1, 1, 1, 1)
    assert c["last_scan"] == T0
