import csv
import io
import json
from datetime import datetime, timezone

import pytest

from core.export import to_csv, to_json, write_report
from core.models import Host, Port, ScanResult

RESULT = ScanResult(
    "192.168.1.0/24", "services", "7.99", False,
    datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc), 2.5,
    (
        Host("192.168.1.1", "up", "AA:BB:CC:00:11:22", "TP-Link", "router.lan",
             (Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"), Port(443, "tcp", "closed"))),
        Host("192.168.1.2", "up"),
    ),
)


def rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_json_content():
    data = json.loads(to_json(RESULT))
    assert data["schema_version"] == 1
    assert data["target"] == "192.168.1.0/24"
    assert data["started_at"].startswith("2026-10-19T12:00:00")
    assert [h["ip"] for h in data["hosts"]] == ["192.168.1.1", "192.168.1.2"]
    assert data["hosts"][0]["ports"][0]["product"] == "OpenSSH"


def test_csv_one_row_per_port_and_one_for_portless_host():
    r = rows(to_csv(RESULT))
    assert len(r) == 3
    assert r[0]["port"] == "22" and r[1]["port_state"] == "closed"
    assert r[2]["ip"] == "192.168.1.2" and r[2]["port"] == ""


@pytest.mark.parametrize("evil", ['=HYPERLINK("http://x")', "+1+1", "-2", "@SUM(A1)"])
def test_csv_formula_injection_is_neutralised(evil):
    hostile = ScanResult(
        "10.0.0.1", "discovery", None, False, datetime.now(timezone.utc), 1.0,
        (Host("10.0.0.1", "up", hostname=evil),),
    )
    assert rows(to_csv(hostile))[0]["hostname"] == "'" + evil


def test_write_report_by_extension(tmp_path):
    j = write_report(RESULT, tmp_path / "scan.json")
    c = write_report(RESULT, tmp_path / "scan.csv")
    assert json.loads(j.read_text(encoding="utf-8"))["profile"] == "services"
    assert c.read_text(encoding="utf-8-sig").startswith("target,profile")
    assert not list(tmp_path.glob("*.tmp"))


def test_write_report_rejects_unknown_extension(tmp_path):
    with pytest.raises(ValueError):
        write_report(RESULT, tmp_path / "scan.pdf")
    assert not list(tmp_path.iterdir())
