import json

import pytest

from shadowcr3_na.core.errors import InputRejected, ScanCancelled
from shadowcr3_na.core.importers import common
from shadowcr3_na.core.importers.common import parse_iso_ts
from shadowcr3_na.core.importers.eve import parse_eve
from shadowcr3_na.core.importers.zeek import parse_zeek_conn

ALERT = {
    "timestamp": "2026-10-24T10:00:00.123456+0000", "event_type": "alert",
    "src_ip": "10.0.0.5", "dest_ip": "93.184.216.34", "dest_port": 443, "proto": "TCP",
    "alert": {"signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan",
              "category": "Attempted Information Leak", "severity": 2},
}


def write_lines(tmp_path, lines, name="eve.json"):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_timestamp_variants():
    assert parse_iso_ts("2026-10-24T10:00:00.123456+0000").utcoffset().total_seconds() == 0
    assert parse_iso_ts("2026-10-24T10:00:00Z").year == 2026
    assert parse_iso_ts("2026-10-24T10:00:00.5+05:30").utcoffset().total_seconds() == 19800
    assert parse_iso_ts("2026-10-24T10:00:00").tzinfo is not None  # naive taken as UTC
    assert parse_iso_ts("garbage") is None and parse_iso_ts(None) is None


def test_eve_alerts_are_parsed_with_provenance(tmp_path):
    flow = {"timestamp": "2026-10-24T10:00:01.000000+0000", "event_type": "flow"}
    path = write_lines(tmp_path, [json.dumps(ALERT), json.dumps(flow), "", "not json",
                                  json.dumps([1, 2]), json.dumps({**ALERT, "alert": {}})])
    result = parse_eve(path)
    assert result.kind == "suricata_eve" and len(result.records) == 1
    assert (result.read, result.rejected, result.ignored) == (1, 3, 1)
    a = result.records[0]
    assert (a.signature, a.signature_id, a.severity, a.proto) == (
        "ET SCAN Potential SSH Scan", 2001219, 2, "tcp")
    assert (a.src, a.dst, a.dst_port) == ("10.0.0.5", "93.184.216.34", 443)
    assert len(result.sha256) == 64 and result.size == path.stat().st_size


def test_eve_sanitises_fields_and_clamps_severity(tmp_path):
    evil = {**ALERT, "src_ip": "not-an-ip",
            "alert": {"signature": "bad\x1b[31m name\u202e", "severity": 99}}
    (a,) = parse_eve(write_lines(tmp_path, [json.dumps(evil)])).records
    assert a.src is None and a.severity == 3
    assert "\x1b" not in a.signature and "\u202e" not in a.signature


def test_eve_record_limit_sets_truncated(tmp_path):
    path = write_lines(tmp_path, [json.dumps(ALERT)] * 5)
    result = parse_eve(path, max_records=3)
    assert len(result.records) == 3 and result.truncated is True


def test_oversized_lines_are_skipped_with_bounded_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "MAX_LINE_BYTES", 200)
    path = write_lines(tmp_path, [json.dumps(ALERT)[:150], "x" * 5000, json.dumps(ALERT)[:150]])
    result = parse_eve(path)
    assert result.rejected >= 1 and result.truncated is False


@pytest.mark.parametrize("make", [
    lambda tmp: tmp / "missing.json",
    lambda tmp: tmp,  # a directory
])
def test_unreadable_inputs_are_rejected(tmp_path, make):
    with pytest.raises(InputRejected):
        parse_eve(make(tmp_path))


def test_empty_and_oversized_files_are_rejected(tmp_path, monkeypatch):
    empty = tmp_path / "empty.json"
    empty.write_text("")
    with pytest.raises(InputRejected, match="empty"):
        parse_eve(empty)
    big = write_lines(tmp_path, [json.dumps(ALERT)] * 50, "big.json")
    monkeypatch.setattr(common, "MAX_FILE_BYTES", 100)
    with pytest.raises(InputRejected, match="limit"):
        parse_eve(big)


def test_import_can_be_cancelled(tmp_path):
    import threading

    event = threading.Event()
    event.set()
    with pytest.raises(ScanCancelled):
        parse_eve(write_lines(tmp_path, [json.dumps(ALERT)]), cancel=event)


ZEEK_TSV = "\n".join([
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#path\tconn",
    ("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration"
    "\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\torig_ip_bytes\tresp_ip_bytes"),
    ("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tcount"
    "\tcount\tcount\tcount"),
    "1761300000.000000\tC1\t10.0.0.5\t40000\t93.184.216.34\t443\ttcp\tssl\t2.5\t100\t200\t3\t4\t260\t360",
    "1761300010.000000\tC2\t10.0.0.5\t40001\t93.184.216.34\t443\ttcp\t-\t-\t-\t-\t1\t1\t60\t60",
    "1761300020.000000\tC3\t10.0.0.7\t40002\t10.0.0.1\t22\ttcp\t-\t-\t-\t-\t-\t-\t-\t-",
    "short\tline",
    "#close\t2026-10-24-11-00-00",
]) + "\n"


def test_zeek_tsv_is_aggregated_into_conversations(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(ZEEK_TSV)
    result = parse_zeek_conn(path)
    assert result.kind == "zeek_conn" and result.read == 3 and result.rejected == 1
    assert len(result.records) == 2
    web = next(c for c in result.records if c.dst == "93.184.216.34")
    assert (web.flows, web.packets, web.bytes, web.dst_port, web.protocol) == (2, 9, 740, 443, "tcp")
    assert web.first_seen.timestamp() == 1761300000 and web.last_seen.timestamp() == 1761300010
    ssh = next(c for c in result.records if c.dst == "10.0.0.1")
    assert ssh.packets is None and ssh.bytes is None  # unknown stays unknown


def test_zeek_json_format(tmp_path):
    rows = [{"ts": 1761300000.0, "id.orig_h": "10.0.0.7", "id.resp_h": "10.0.0.1", "id.resp_p": 22,
             "proto": "tcp", "orig_ip_bytes": 10, "resp_ip_bytes": 20, "duration": 1.5},
            {"ts": "x", "id.orig_h": "10.0.0.7"}, "garbage"]
    path = tmp_path / "conn.json"
    path.write_text("\n".join(json.dumps(r) if isinstance(r, dict) else r for r in rows) + "\n")
    result = parse_zeek_conn(path)
    assert len(result.records) == 1 and result.records[0].bytes == 30
    assert result.rejected == 1 and result.ignored == 1


def test_zeek_rows_before_a_header_are_rejected(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text("1.0\tC1\t10.0.0.1\n")
    result = parse_zeek_conn(path)
    assert result.records == () and result.rejected == 1
