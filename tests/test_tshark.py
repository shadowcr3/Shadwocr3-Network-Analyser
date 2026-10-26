import os
import shutil
import threading
import time

import pytest

from pcapgen import SAMPLE, make_pcap
from shadowcr3_na.core.errors import InputRejected, ScanCancelled, ScanFailed, ScanTimeout, ToolNotFound
from shadowcr3_na.core.importers import tshark
from shadowcr3_na.core.importers.tshark import (
    build_command,
    connections_from_packets,
    find_tshark,
    read_capture,
    tshark_version,
    validate_capture,
)

REAL = shutil.which("tshark")


@pytest.fixture
def pcap(tmp_path):
    return make_pcap(tmp_path / "sample.pcap", SAMPLE)


def test_command_is_a_passive_argument_list(tmp_path):
    cmd = build_command("tshark", tmp_path / "x.pcap", "tcp.port == 22")
    assert cmd[:3] == ["tshark", "-r", str(tmp_path / "x.pcap")]
    assert "-n" in cmd  # no name resolution: never generates DNS traffic
    assert cmd[cmd.index("-Y") + 1] == "tcp.port == 22"
    assert not any(a in cmd for a in ("-i", "-w", "-a"))  # no live capture, no writing


def test_missing_tshark(tmp_path, monkeypatch):
    with pytest.raises(ToolNotFound):
        find_tshark(str(tmp_path / "nope"))
    monkeypatch.setattr(tshark.shutil, "which", lambda _: None)
    with pytest.raises(ToolNotFound):
        find_tshark()


def test_capture_validation_uses_magic_bytes_not_extension(tmp_path, pcap):
    size, digest = validate_capture(pcap)
    assert size == pcap.stat().st_size and len(digest) == 64
    fake = tmp_path / "evil.pcap"
    fake.write_text("this is not a capture")
    with pytest.raises(InputRejected, match="not a PCAP"):
        validate_capture(fake)
    ng = tmp_path / "x.pcapng"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 20)
    validate_capture(ng)


@pytest.mark.parametrize("bad", ["x\ny", "a" * 600, "x\x00y"])
def test_hostile_display_filters_are_rejected(pcap, fake_tshark, bad):
    with pytest.raises(InputRejected):
        read_capture(pcap, display_filter=bad, tshark_path=fake_tshark)


def test_fake_tshark_output_is_parsed(pcap, fake_tshark, tmp_path, monkeypatch):
    out = tmp_path / "out.tsv"
    out.write_text(
        "1\t1761300000.0\t10.0.0.5\t\t10.0.0.1\t\tDNS\t60\tStandard query\t\t53\n"
        "2\t1761300001.0\t\tfe80::1\t\tff02::1\tICMPv6\t90\tRouter Advertisement\t\t\n"
        "junk line\n"
        "3\t1761300002.0\t\t\t\t\tARP\t42\tWho has 10.0.0.1?\t\t\n")
    monkeypatch.setenv("FAKE_TSHARK_OUTPUT", str(out))
    result = read_capture(pcap, tshark_path=fake_tshark)
    assert [p.number for p in result.packets] == [1, 2, 3]
    assert result.packets[0].dst_port == 53 and result.packets[1].src == "fe80::1"
    assert result.packets[2].src is None and result.tshark_version == "4.2.2"
    assert result.truncated is False and "-n" in result.command


def test_packet_limit_stops_tshark_and_marks_truncated(pcap, fake_tshark, tmp_path, monkeypatch):
    out = tmp_path / "many.tsv"
    out.write_text("".join(f"{i}\t1761300000.0\t10.0.0.5\t\t10.0.0.1\t\tTCP\t60\tx\t\t80\n"
                           for i in range(1, 50)))
    monkeypatch.setenv("FAKE_TSHARK_OUTPUT", str(out))
    result = read_capture(pcap, limit=10, tshark_path=fake_tshark)
    assert len(result.packets) == 10 and result.truncated is True


def test_nonzero_exit_timeout_and_cancel(pcap, fake_tshark, monkeypatch):
    monkeypatch.setenv("FAKE_TSHARK_EXIT", "2")
    with pytest.raises(ScanFailed, match="boom"):
        read_capture(pcap, tshark_path=fake_tshark)
    monkeypatch.delenv("FAKE_TSHARK_EXIT")
    monkeypatch.setenv("FAKE_TSHARK_SLEEP", "30")
    start = time.monotonic()
    with pytest.raises(ScanTimeout):
        read_capture(pcap, tshark_path=fake_tshark, timeout_s=1)
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    with pytest.raises(ScanCancelled):
        read_capture(pcap, tshark_path=fake_tshark, cancel=cancel)
    assert time.monotonic() - start < 15


@pytest.mark.skipif(os.name == "nt", reason="pid probing is POSIX-only")
def test_interrupt_kills_the_tshark_process(pcap, fake_tshark, tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    monkeypatch.setenv("FAKE_TSHARK_SLEEP", "30")
    monkeypatch.setenv("FAKE_TSHARK_PIDFILE", str(pidfile))

    class Interrupt:
        def is_set(self):
            if pidfile.exists() and pidfile.read_text():  # the child has started
                raise KeyboardInterrupt
            return False

    with pytest.raises(KeyboardInterrupt):
        read_capture(pcap, tshark_path=fake_tshark, cancel=Interrupt())  # type: ignore[arg-type]
    pid = int(pidfile.read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.skipif(REAL is None, reason="real tshark not installed")
def test_real_tshark_reads_a_synthetic_capture(pcap):
    result = read_capture(pcap)
    assert len(result.packets) == 4 and result.tshark_version
    first = result.packets[0]
    assert (first.src, first.dst, first.dst_port) == ("10.0.0.5", "10.0.0.1", 53)
    assert result.packets[1].protocol == "TCP" and result.packets[1].dst_port == 443
    assert tshark_version(REAL)


@pytest.mark.skipif(REAL is None, reason="real tshark not installed")
def test_real_tshark_display_filter_and_conversations(pcap):
    only_ssh = read_capture(pcap, display_filter="tcp.dstport == 22")
    assert [p.dst_port for p in only_ssh.packets] == [22]
    packets = read_capture(pcap).packets
    conns, truncated = connections_from_packets(packets)
    web = next(c for c in conns if c.dst == "93.184.216.34")
    assert (web.packets, web.flows, web.dst_port) == (2, 2, 443) and truncated is False


@pytest.mark.skipif(REAL is None, reason="real tshark not installed")
def test_real_tshark_rejects_a_truncated_capture(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)
    with pytest.raises(ScanFailed):
        read_capture(bad)
