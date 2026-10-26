"""Zeek conn.log importer (TSV or JSON), aggregated into conversations."""
from __future__ import annotations

import json
import os
import threading
from typing import Any

from shadowcr3_na.core.records import ConnectionRecord, ImportResult

from .common import (
    MAX_RECORDS,
    BoundedLines,
    aggregate_connections,
    as_int,
    epoch_ts,
    valid_ip,
)


def parse_zeek_conn(
    path: str | os.PathLike[str],
    *,
    cancel: threading.Event | None = None,
    max_records: int = MAX_RECORDS,
) -> ImportResult:
    reader = BoundedLines(path, cancel)
    sep, unset = "\t", "-"
    fields: list[str] | None = None
    json_mode: bool | None = None
    flows: list[ConnectionRecord] = []
    rejected = ignored = 0
    truncated = False
    for line in reader.lines():
        if line is None:
            rejected += 1
            continue
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if line.startswith("#"):
            if line.startswith("#separator"):
                sep = _unescape(line.split(" ", 1)[1]) if " " in line else sep
            elif line.startswith("#unset_field"):
                unset = line.split(sep, 1)[1] if sep in line else unset
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            continue
        if json_mode is None:
            json_mode = line.lstrip().startswith("{")
        obj = _row(line, json_mode, fields, sep, unset)
        if obj is None:
            rejected += 1
            continue
        record = _conn_from(obj)
        if record is None:
            ignored += 1
            continue
        if len(flows) >= max_records:
            truncated = True
            break
        flows.append(record)
    merged, merged_truncated = aggregate_connections(flows)
    return ImportResult("zeek_conn", merged, len(flows), rejected, ignored,
                        truncated or merged_truncated, reader.sha256, reader.size)


def _unescape(value: str) -> str:
    try:
        return bytes(value, "ascii").decode("unicode_escape")
    except (UnicodeError, ValueError):
        return "\t"


def _row(
    line: str, json_mode: bool, fields: list[str] | None, sep: str, unset: str
) -> dict[str, Any] | None:
    if json_mode:
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None
    if fields is None:
        return None
    parts = line.split(sep)
    if len(parts) != len(fields):
        return None
    return {k: (None if v == unset else v) for k, v in zip(fields, parts)}


def _conn_from(obj: dict[str, Any]) -> ConnectionRecord | None:
    first = epoch_ts(obj.get("ts"))
    src, dst = valid_ip(obj.get("id.orig_h")), valid_ip(obj.get("id.resp_h"))
    if first is None or src is None or dst is None:
        return None
    duration = obj.get("duration")
    try:
        last_seen = epoch_ts(float(obj["ts"]) + float(duration)) if duration else first
    except (TypeError, ValueError):
        last_seen = first
    proto = obj.get("proto")
    packets = _sum(as_int(obj.get("orig_pkts")), as_int(obj.get("resp_pkts")))
    size = _sum(as_int(obj.get("orig_ip_bytes")), as_int(obj.get("resp_ip_bytes")))
    if size is None:
        size = _sum(as_int(obj.get("orig_bytes")), as_int(obj.get("resp_bytes")))
    return ConnectionRecord(
        src, dst, proto.lower() if isinstance(proto, str) else "unknown",
        as_int(obj.get("id.resp_p")), first, last_seen or first, packets, size, 1,
    )


def _sum(a: int | None, b: int | None) -> int | None:
    return None if a is None and b is None else (a or 0) + (b or 0)
