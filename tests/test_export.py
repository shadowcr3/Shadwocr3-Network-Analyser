import csv
import hashlib
import io
from datetime import datetime, timezone

import pytest

from shadowcr3_na.core.export import to_csv, write_report
from shadowcr3_na.core.models import Host, Port, ScanResult

RESULT = ScanResult(
    "192.168.1.0/24", "services", "7.99", False,
    datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc), 2.5,
    (
        Host("192.168.1.1", "up", "AA:BB:CC:00:11:22", "TP-Link", "router.lan",
             (Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"), Port(443, "tcp", "closed"))),
        Host("192.168.1.2", "up"),
    ),
    command=("nmap", "-F"), exit_status=0, complete=False, warnings=("Warning: x",),
    raw_sha256="cd" * 32,
)


def rows(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_rows_and_completeness_column():
    r = rows(to_csv(RESULT))
    assert len(r) == 3 and r[0]["scan_complete"] == "false"
    assert r[0]["port"] == "22" and r[1]["port_state"] == "closed"
    assert r[2]["ip"] == "192.168.1.2" and r[2]["port"] == ""


def test_unknown_completeness_is_reported_as_unknown():
    unknown = ScanResult("10.0.0.1", "discovery", None, False, datetime.now(timezone.utc), 1.0,
                         (Host("10.0.0.1", "up"),))
    assert rows(to_csv(unknown))[0]["scan_complete"] == "unknown"


@pytest.mark.parametrize("evil", ['=HYPERLINK("http://x")', "+1+1", "-2", "@SUM(A1)"])
def test_csv_formula_injection_is_neutralised(evil):
    hostile = ScanResult("10.0.0.1", "discovery", None, False, datetime.now(timezone.utc), 1.0,
                         (Host("10.0.0.1", "up", hostname=evil),))
    assert rows(to_csv(hostile))[0]["hostname"] == "'" + evil


def test_write_report_returns_a_verifiable_hash_and_is_csv_only(tmp_path):
    info = write_report(RESULT, tmp_path / "scan.csv")
    assert hashlib.sha256(info.path.read_bytes()).hexdigest() == info.sha256
    assert info.size == info.path.stat().st_size
    assert info.path.read_text(encoding="utf-8-sig").startswith("target,profile")
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("name", ["scan.json", "scan.pdf", "scan.txt"])
def test_data_export_rejects_other_formats(tmp_path, name):
    with pytest.raises(ValueError):
        write_report(RESULT, tmp_path / name)
    assert not list(tmp_path.iterdir())
