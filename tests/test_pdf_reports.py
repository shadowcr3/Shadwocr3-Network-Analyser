import hashlib
from datetime import datetime, timezone

import pytest
from pypdf import PdfReader

from shadowcr3_na import __version__
from shadowcr3_na.core.models import Host, Port, ScanResult
from shadowcr3_na.reports import write_scan_report
from shadowcr3_na.reports.investigation_report import build_investigation_pdf
from shadowcr3_na.reports.scan_report import build_scan_pdf
from shadowcr3_na.storage import inventory as inv
from shadowcr3_na.storage import investigations as inves
from shadowcr3_na.storage.db import connect
from shadowcr3_na.storage.repository import save_scan

NOW = datetime(2026, 10, 25, 10, 30, tzinfo=timezone.utc)
SHA = "ab" * 32
CMD = ("nmap", "-F", "-sV", "--max-rate", "250", "--", "192.168.1.0/24")


def pdf_text(path):
    return "\n".join(page.extract_text() for page in PdfReader(str(path)).pages)


def scan(hosts=None, **kw):
    hosts = (
        Host("192.168.1.1", "up", "AA:BB:CC:00:11:22", "TP-Link", "router.lan",
             (Port(22, "tcp", "open", "ssh", "OpenSSH", "9.6"), Port(80, "tcp", "open", "http"),
              Port(443, "tcp", "closed"))),
        Host("192.168.1.20", "up", None, None, None, ()),
    ) if hosts is None else hosts
    base = dict(target="192.168.1.0/24", profile="services", nmap_version="7.99", privileged=True,
                started_at=NOW, duration_s=12.4, hosts=hosts, command=CMD, exit_status=0,
                complete=True, warnings=(), raw_sha256=SHA)
    base.update(kw)
    return ScanResult(**base)


def test_scan_pdf_is_a_branded_real_pdf(tmp_path):
    info = build_scan_pdf(scan(), tmp_path / "r.pdf")
    raw = info.path.read_bytes()
    assert raw.startswith(b"%PDF-") and info.sha256 == hashlib.sha256(raw).hexdigest()
    assert not list(tmp_path.glob("*.tmp"))
    reader = PdfReader(str(info.path))
    meta = reader.metadata
    assert meta.title == "Network Assessment Report 192.168.1.0/24"
    assert meta.author == "Shadowcr3 Network Analyzer" and meta.creator.endswith(__version__)
    text = pdf_text(info.path)
    flat = text.replace(" ", "")
    assert "SHADOWCR3" in flat and "NETWORKANALYZER" in flat  # wordmark and product line
    assert f"Shadowcr3 Network Analyzer v{__version__}" in text
    assert "Confidential: contains network details" in text and "Page 1 of 1" in text
    assert "Network Assessment Report" in text and "192.168.1.0/24" in text


def test_scan_pdf_contents_are_complete_and_accurate(tmp_path):
    path = tmp_path / "r.pdf"
    build_scan_pdf(scan(), path)
    text = pdf_text(path)
    for expected in ("router.lan", "AA:BB:CC:00:11:22", "TP-Link", "22/ssh", "OpenSSH 9.6",
                     "Open services", "Provenance", "--max-rate", SHA, "Nmap 7.99", "12.4 s",
                     "Administrator/root"):
        assert expected in text.replace("\n", " "), expected
    assert "443/tcp" not in text  # closed ports are not listed as open services
    assert "authorised to assess" in text


def test_limitations_are_stated_when_they_apply(tmp_path):
    path = tmp_path / "r.pdf"
    build_scan_pdf(scan(hosts=(), complete=False, privileged=False,
                        warnings=("Warning: Skipping host 192.168.1.9 due to host timeout",)), path)
    text = " ".join(pdf_text(path).split())
    assert "INCOMPLETE" in text and "host timeout" in text
    assert "Standard user" in text and "without Administrator/root privileges" in text
    assert "No hosts responded. This does not prove the network is empty" in text
    legacy = tmp_path / "legacy.pdf"
    build_scan_pdf(scan(complete=None, command=(), raw_sha256=None, exit_status=None), legacy)
    legacy_text = " ".join(pdf_text(legacy).split())
    assert "completeness is unknown" in legacy_text.lower() and "not recorded" in legacy_text


def test_untrusted_text_cannot_inject_markup_or_break_the_document(tmp_path):
    evil = Host("10.0.0.5", "up", "AA:BB", "<b>Vendor</b>", "<script>alert(1)</script>&amp;\x1b[31m\u202e",
                (Port(80, "tcp", "open", "<i>http</i>", "evil\nproduct", "</para><para>"),))
    path = tmp_path / "evil.pdf"
    build_scan_pdf(scan(hosts=(evil,), command=("nmap", "<b>x</b>")), path)
    text = " ".join(pdf_text(path).split())
    assert "<script>alert(1)</script>" in text  # shown literally, not interpreted
    assert "<b>Vendor</b>" in text and "</para><para>" in text
    assert "\x1b" not in text and "\u202e" not in text


def test_large_reports_paginate_with_consistent_page_numbers(tmp_path):
    hosts = tuple(Host(f"10.0.{i // 250}.{i % 250 + 1}", "up", f"AA:BB:CC:00:{i // 256:02X}:{i % 256:02X}",
                       "Vendor", f"host-{i}.lan", (Port(22, "tcp", "open", "ssh"),))
                  for i in range(300))
    path = tmp_path / "big.pdf"
    build_scan_pdf(scan(hosts=hosts), path)
    reader = PdfReader(str(path))
    total = len(reader.pages)
    assert total >= 5
    for n, page in enumerate(reader.pages, 1):
        assert f"Page {n} of {total}" in page.extract_text()
    everything = pdf_text(path)
    assert "host-0.lan" in everything and "host-299.lan" in everything
    assert pdf_text(path).count("IP address") >= 2  # table header repeats across pages


def test_dispatch_by_extension_and_atomic_failure(tmp_path):
    result = scan()
    assert write_scan_report(result, tmp_path / "a.pdf").path.read_bytes().startswith(b"%PDF-")
    assert write_scan_report(result, tmp_path / "a.csv").path.read_text(encoding="utf-8-sig")
    for bad in ("a.json", "a.txt", "a"):
        with pytest.raises(ValueError):
            write_scan_report(result, tmp_path / bad)
    with pytest.raises(OSError):
        write_scan_report(result, tmp_path / "missing-dir" / "a.pdf")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.csv", "a.pdf"]


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def test_investigation_pdf(conn, tmp_path):
    from test_importers import ALERT, write_lines

    from shadowcr3_na.core.importers.eve import parse_eve

    path = write_lines(tmp_path, [('{"timestamp":"2026-10-24T10:00:00.1+0000","event_type":"alert",'
                                  '"src_ip":"10.0.0.5","dest_ip":"93.184.216.34","dest_port":443,'
                                  '"proto":"TCP","alert":{"signature_id":1,"severity":1,'
                                  '"signature":"ET <b>SCAN</b> test"}}')])
    del ALERT
    inv.save_alert_import(conn, str(path), parse_eve(path))
    alert = inv.list_alerts(conn)[0]
    s = scan()
    sid = save_scan(conn, s, attested=True)
    with conn:
        inv.upsert_asset(conn, "10.0.0.5", source="a", first_seen=NOW, mac="AA:AA")
        inv.upsert_asset(conn, "10.0.0.5", source="b", first_seen=NOW, mac="BB:BB")
    asset = inv.list_assets(conn)[0]
    iid = inves.create_investigation(conn, "Case <1> & more")
    inves.update_investigation(conn, iid, notes="Line one.\nOwner confirmed <benign>.")
    for kind, ref in (("alert", alert.id), ("scan", sid), ("asset", asset.id)):
        inves.add_item(conn, iid, kind, ref, "reviewed")
    gone = inves.add_item(conn, iid, "scan", 9999)
    assert gone
    info = build_investigation_pdf(conn, iid, tmp_path / "inv.pdf")
    reader = PdfReader(str(info.path))
    assert reader.metadata.title.startswith("Investigation Report Case")
    text = " ".join(pdf_text(info.path).split())
    flat = text.replace(" ", "")
    assert "SHADOWCR3" in flat and "Investigation Report" in text and "Page 1 of" in text
    assert "Case <1> & more" in text and "Owner confirmed <benign>." in text
    assert "ET <b>SCAN</b> test" in text and "indicators that require interpretation" in text
    assert "Uncertain identity" in text and "Evidence no longer available" in text
    assert "Timeline (UTC)" in text and SHA in text and "reviewed" in text
    assert info.sha256 == hashlib.sha256(info.path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        build_investigation_pdf(conn, 999, tmp_path / "x.pdf")
    with pytest.raises(ValueError):
        build_investigation_pdf(conn, iid, tmp_path / "x.md")
