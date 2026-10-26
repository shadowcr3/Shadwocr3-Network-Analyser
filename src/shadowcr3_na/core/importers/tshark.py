"""TShark adapter: offline packet inspection of PCAP/PCAPNG files.

Passive by design: reads a file, never captures, and runs with -n so no DNS or other
network requests are generated. Output is structured (-T fields), not scraped text.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from shadowcr3_na.core.errors import (
    InputRejected,
    ScanCancelled,
    ScanFailed,
    ScanTimeout,
    ToolNotFound,
)
from shadowcr3_na.core.records import ConnectionRecord, PacketRecord
from shadowcr3_na.core.runner import _kill_tree, _popen_kwargs
from shadowcr3_na.core.textutil import clean_text

from .common import (
    MAX_FILE_BYTES,
    aggregate_connections,
    check_regular_file,
    epoch_ts,
    sha256_file,
    valid_ip,
)

MAX_PACKETS = 100_000
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
_MAGIC = {
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",  # pcap
    b"\x0a\x0d\x0d\x0a",  # pcapng
}
_FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "_ws.col.Protocol", "frame.len", "_ws.col.Info", "tcp.dstport", "udp.dstport",
)
_FILTER_MAX = 500


@dataclass(frozen=True, slots=True)
class CaptureResult:
    packets: tuple[PacketRecord, ...]
    truncated: bool
    sha256: str
    size: int
    tshark_version: str | None
    command: tuple[str, ...]


def find_tshark(explicit: str | None = None) -> str:
    path = explicit or shutil.which("tshark")
    if not path or not os.path.isfile(path):
        raise ToolNotFound(
            "TShark was not found. Install Wireshark (https://www.wireshark.org/download.html) "
            "and make sure tshark is on PATH."
        )
    return path


def find_wireshark(explicit: str | None = None) -> str | None:
    path = explicit or shutil.which("wireshark")
    return path if path and os.path.isfile(path) else None


def tshark_version(path: str) -> str | None:
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10,
                             **_popen_kwargs()).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"TShark.*?(\d+\.\d+(?:\.\d+)?)", out)
    return m.group(1) if m else None


def validate_capture(path: str | os.PathLike[str]) -> tuple[int, str]:
    """Check type by magic bytes (not extension) and size; return (size, sha256)."""
    size = check_regular_file(path, MAX_CAPTURE_BYTES)
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic not in _MAGIC:
        raise InputRejected(f"{path} is not a PCAP or PCAPNG capture file.")
    return size, sha256_file(path)


def build_command(
    tshark: str, path: str | os.PathLike[str], display_filter: str | None
) -> list[str]:
    cmd = [tshark, "-r", os.fspath(path), "-n", "-T", "fields", "-E", "separator=/t",
           "-E", "occurrence=f"]
    for name in _FIELDS:
        cmd += ["-e", name]
    if display_filter:
        cmd += ["-Y", display_filter]
    return cmd


def read_capture(
    path: str | os.PathLike[str],
    *,
    display_filter: str | None = None,
    limit: int = MAX_PACKETS,
    timeout_s: int = 120,
    cancel: threading.Event | None = None,
    tshark_path: str | None = None,
) -> CaptureResult:
    if display_filter is not None:
        display_filter = display_filter.strip() or None
    if display_filter and (len(display_filter) > _FILTER_MAX or "\n" in display_filter
                           or "\x00" in display_filter):
        raise InputRejected("The display filter is too long or contains control characters.")
    tshark = find_tshark(tshark_path)
    size, digest = validate_capture(path)
    version = tshark_version(tshark)
    cmd = build_command(tshark, path, display_filter)
    lines: list[str] = []
    err_chunks: list[str] = []
    overflow = threading.Event()
    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace", **_popen_kwargs(),
    ) as proc:
        def pump_out() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                if len(lines) >= limit:
                    overflow.set()
                    return
                lines.append(line)

        def pump_err() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                if sum(map(len, err_chunks)) < 4000:
                    err_chunks.append(line)

        threads = [threading.Thread(target=pump_out, daemon=True),
                   threading.Thread(target=pump_err, daemon=True)]
        for t in threads:
            t.start()
        deadline = time.monotonic() + timeout_s
        try:
            while threads[0].is_alive():
                if cancel is not None and cancel.is_set():
                    raise ScanCancelled("Packet import cancelled.")
                if time.monotonic() >= deadline:
                    raise ScanTimeout(f"TShark exceeded {timeout_s}s and was stopped.")
                threads[0].join(0.1)
        except BaseException:
            if proc.poll() is None:
                _kill_tree(proc)
            raise
        if overflow.is_set() and proc.poll() is None:
            _kill_tree(proc)
        proc.wait()
        threads[1].join(2)
    stderr = clean_text("".join(err_chunks).strip())
    if proc.returncode != 0 and not overflow.is_set():
        raise ScanFailed(f"TShark exited with code {proc.returncode}: {stderr}")
    packets = tuple(p for p in (_packet(line) for line in lines) if p is not None)
    return CaptureResult(packets, overflow.is_set(), digest, size, version, tuple(cmd))


def _packet(line: str) -> PacketRecord | None:
    parts = line.rstrip("\n").split("\t")
    parts += [""] * (len(_FIELDS) - len(parts))
    number = _int(parts[0])
    if number is None:
        return None
    ts: datetime | None = epoch_ts(parts[1]) if parts[1] else None
    src = valid_ip(parts[2] or parts[3])
    dst = valid_ip(parts[4] or parts[5])
    return PacketRecord(
        number=number, ts=ts, src=src, dst=dst,
        protocol=clean_text(parts[6], 40) or "?", length=_int(parts[7]),
        info=clean_text(parts[8], 300), dst_port=_int(parts[9] or parts[10]),
    )


def _int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def connections_from_packets(
    packets: tuple[PacketRecord, ...],
) -> tuple[tuple[ConnectionRecord, ...], bool]:
    flows = [
        ConnectionRecord(p.src, p.dst, p.protocol.lower(), p.dst_port, p.ts, p.ts, 1, p.length, 1)
        for p in packets
        if p.src and p.dst and p.ts is not None
    ]
    return aggregate_connections(flows)


__all__ = [
    "MAX_FILE_BYTES", "CaptureResult", "build_command", "connections_from_packets",
    "find_tshark", "find_wireshark", "read_capture", "tshark_version", "validate_capture",
]
