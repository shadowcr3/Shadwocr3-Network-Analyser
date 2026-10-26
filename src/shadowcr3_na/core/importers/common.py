"""Bounded, hash-verified reading of untrusted evidence files."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import threading
from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timezone

from shadowcr3_na.core.errors import InputRejected, ScanCancelled
from shadowcr3_na.core.records import ConnectionRecord

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 200_000
MAX_AGGREGATED = 100_000


def sha256_file(path: str | os.PathLike[str], cancel: threading.Event | None = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            if cancel is not None and cancel.is_set():
                raise ScanCancelled("Import cancelled.")
            h.update(chunk)
    return h.hexdigest()


def check_regular_file(path: str | os.PathLike[str], max_bytes: int | None = None) -> int:
    limit = MAX_FILE_BYTES if max_bytes is None else max_bytes
    try:
        st = os.stat(path)
    except OSError as exc:
        raise InputRejected(f"Cannot read {path}: {exc.strerror or exc}") from None
    if not os.path.isfile(path):
        raise InputRejected(f"{path} is not a regular file.")
    if st.st_size == 0:
        raise InputRejected(f"{path} is empty.")
    if st.st_size > limit:
        raise InputRejected(
            f"{path} is {st.st_size // (1024 * 1024)} MB; the limit is "
            f"{limit // (1024 * 1024)} MB."
        )
    return st.st_size


class BoundedLines:
    """Yields decoded lines; oversized lines are skipped (yielded as None) with bounded memory."""

    def __init__(self, path: str | os.PathLike[str], cancel: threading.Event | None = None) -> None:
        self.path = path
        self.cancel = cancel
        self.size = check_regular_file(path)
        self.sha256 = sha256_file(path, cancel)

    def lines(self) -> Iterator[str | None]:
        with open(self.path, "rb") as f:
            count = 0
            while True:
                raw = f.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    return
                count += 1
                if self.cancel is not None and count % 2000 == 0 and self.cancel.is_set():
                    raise ScanCancelled("Import cancelled.")
                if len(raw) > MAX_LINE_BYTES and not raw.endswith(b"\n"):
                    while True:  # discard the remainder of the oversized line
                        rest = f.readline(MAX_LINE_BYTES)
                        if not rest or rest.endswith(b"\n"):
                            break
                    yield None
                    continue
                yield raw.decode("utf-8", errors="replace")


_TS_TZ = re.compile(r"([+-]\d{2})(\d{2})$")
_TS_FRAC = re.compile(r"\.(\d+)")


def parse_iso_ts(value: object) -> datetime | None:
    """Parse ISO-8601 including Suricata's '+0000' offsets; naive values are taken as UTC."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    text = _TS_TZ.sub(r"\1:\2", text)
    text = _TS_FRAC.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        ts = datetime.fromisoformat(text)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def epoch_ts(value: object) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), timezone.utc)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def valid_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def as_int(value: object) -> int | None:
    try:
        number = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def aggregate_connections(
    records: list[ConnectionRecord], limit: int = MAX_AGGREGATED
) -> tuple[tuple[ConnectionRecord, ...], bool]:
    """Merge flow/packet records into one conversation per (src, dst, protocol, port)."""
    groups: dict[tuple[str, str, str, int | None], ConnectionRecord] = {}
    truncated = False
    for r in records:
        key = (r.src, r.dst, r.protocol, r.dst_port)
        cur = groups.get(key)
        if cur is None:
            if len(groups) >= limit:
                truncated = True
                continue
            groups[key] = r
            continue
        groups[key] = ConnectionRecord(
            r.src, r.dst, r.protocol, r.dst_port,
            min(cur.first_seen, r.first_seen), max(cur.last_seen, r.last_seen),
            _add(cur.packets, r.packets), _add(cur.bytes, r.bytes), cur.flows + r.flows,
        )
    return tuple(groups.values()), truncated


def _add(a: int | None, b: int | None) -> int | None:
    if a is None and b is None:
        return None
    return (a or 0) + (b or 0)


def count_by_key(items: list[str]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        counts[item] += 1
    return dict(counts)
