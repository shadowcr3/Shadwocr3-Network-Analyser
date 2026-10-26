import json
from datetime import datetime, timezone

import pytest

from shadowcr3_na.core.importers.eve import parse_eve
from shadowcr3_na.core.models import Host, ScanResult
from shadowcr3_na.storage import inventory as inv
from shadowcr3_na.storage import investigations as inves
from shadowcr3_na.storage.db import connect
from shadowcr3_na.storage.repository import save_scan
from test_importers import ALERT, write_lines


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def seed(conn, tmp_path, signature="ET SCAN Potential SSH Scan"):
    path = write_lines(tmp_path, [json.dumps({**ALERT, "alert": {**ALERT["alert"],
                                                                  "signature": signature}})])
    import_id = inv.save_alert_import(conn, str(path), parse_eve(path))
    alert = inv.list_alerts(conn)[0]
    scan = ScanResult("10.0.0.0/24", "discovery", "7.95", False,
                      datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc), 1.0,
                      (Host("10.0.0.5", "up"),), command=("nmap", "-sn"), complete=False,
                      raw_sha256="ab" * 32)
    scan_id = save_scan(conn, scan, attested=True)
    inv.upsert_assets_from_scan(conn, scan_id, scan)
    return import_id, alert, scan_id, inv.list_assets(conn)[0]


def test_create_validates_and_lists(conn):
    with pytest.raises(ValueError):
        inves.create_investigation(conn, "   ")
    iid = inves.create_investigation(conn, "Suspicious scan from 10.0.0.5")
    assert inves.find_by_title(conn, "Suspicious scan from 10.0.0.5") == iid
    assert [i.id for i in inves.list_investigations(conn)] == [iid]
    assert inves.update_investigation(conn, iid, status="closed", notes="done")
    assert inves.get_investigation(conn, iid).status == "closed"
    with pytest.raises(ValueError):
        inves.update_investigation(conn, iid, status="bogus")


def test_items_are_deduplicated_and_validated(conn, tmp_path):
    _imp, alert, _sid, _asset = seed(conn, tmp_path)
    iid = inves.create_investigation(conn, "case")
    first = inves.add_item(conn, iid, "alert", alert.id, "look here")
    assert inves.add_item(conn, iid, "alert", alert.id) == first
    assert len(inves.list_items(conn, iid)) == 1
    with pytest.raises(ValueError):
        inves.add_item(conn, iid, "packet", 1)
    with pytest.raises(ValueError):
        inves.add_item(conn, 999, "alert", 1)
    assert inves.remove_item(conn, first) and inves.list_items(conn, iid) == []


def test_report_data_carries_provenance_and_flags(conn, tmp_path):
    _imp, alert, sid, asset = seed(conn, tmp_path)
    iid = inves.create_investigation(conn, "Case 1")
    for kind, ref in (("alert", alert.id), ("scan", sid), ("asset", asset.id)):
        inves.add_item(conn, iid, kind, ref, f"{kind} note")
    data = inves.collect_report(conn, iid)
    by_kind = {i.kind: i for i in data.items}
    assert all(i.available and i.note.endswith("note") for i in data.items)
    assert any("INCOMPLETE" in line for line in by_kind["scan"].lines)
    assert "Results may be incomplete." in by_kind["scan"].flags
    assert any("ab" * 32 in line for line in by_kind["scan"].lines)
    assert any("SHA-256" in line for line in by_kind["alert"].lines)
    assert by_kind["scan"].ts < by_kind["alert"].ts  # 09:00 scan precedes the 10:00 alert
    assert "indicators that require interpretation" in inves.DISCLAIMER


def test_report_data_says_when_evidence_is_gone(conn, tmp_path):
    import_id, alert, _sid, _asset = seed(conn, tmp_path)
    iid = inves.create_investigation(conn, "Case")
    inves.add_item(conn, iid, "alert", alert.id, "keep my note")
    inv.delete_import(conn, import_id)
    (item,) = inves.collect_report(conn, iid).items
    assert item.available is False and item.lines == () and item.note == "keep my note"
    assert inves.item_summary(conn, inves.list_items(conn, iid)[0]) == "(evidence no longer available)"


def test_hostile_text_is_flattened_in_report_data(conn, tmp_path):
    evil = "x`\n# FAKE HEADING\n[click](http://evil)\x1b[31m"
    _imp, alert, *_ = seed(conn, tmp_path, signature=evil)
    iid = inves.create_investigation(conn, "Case")
    inves.add_item(conn, iid, "alert", alert.id)
    (item,) = inves.collect_report(conn, iid).items
    joined = " ".join(item.lines)
    assert "\n" not in joined and "\x1b" not in joined


def test_deleting_an_investigation_removes_its_items(conn, tmp_path):
    _imp, alert, *_ = seed(conn, tmp_path)
    iid = inves.create_investigation(conn, "Case")
    inves.add_item(conn, iid, "alert", alert.id)
    assert inves.delete_investigation(conn, iid)
    assert conn.execute("SELECT COUNT(*) FROM investigation_items").fetchone()[0] == 0
    with pytest.raises(ValueError):
        inves.collect_report(conn, iid)
