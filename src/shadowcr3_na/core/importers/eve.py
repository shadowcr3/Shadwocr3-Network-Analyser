"""Suricata EVE JSON importer (alerts only). Alerts are indicators, never proof."""
from __future__ import annotations

import json
import os
import threading
from typing import Any

from shadowcr3_na.core.records import AlertRecord, ImportResult
from shadowcr3_na.core.textutil import clean_text

from .common import MAX_RECORDS, BoundedLines, as_int, parse_iso_ts, valid_ip


def parse_eve(
    path: str | os.PathLike[str],
    *,
    cancel: threading.Event | None = None,
    max_records: int = MAX_RECORDS,
) -> ImportResult:
    reader = BoundedLines(path, cancel)
    alerts: list[AlertRecord] = []
    rejected = ignored = read = 0
    truncated = False
    for line in reader.lines():
        if line is None:
            rejected += 1
            continue
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            rejected += 1
            continue
        if not isinstance(obj, dict):
            rejected += 1
            continue
        if obj.get("event_type") != "alert":
            ignored += 1
            continue
        record = _alert_from(obj, line)
        if record is None:
            rejected += 1
            continue
        read += 1
        if len(alerts) >= max_records:
            truncated = True
            break
        alerts.append(record)
    return ImportResult("suricata_eve", tuple(alerts), read, rejected, ignored, truncated,
                        reader.sha256, reader.size)


def _alert_from(obj: dict[str, Any], line: str) -> AlertRecord | None:
    ts = parse_iso_ts(obj.get("timestamp"))
    alert = obj.get("alert")
    if ts is None or not isinstance(alert, dict):
        return None
    signature = alert.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return None
    severity = as_int(alert.get("severity"))
    category = alert.get("category")
    proto = obj.get("proto")
    return AlertRecord(
        ts=ts,
        source="suricata",
        signature=clean_text(signature, 300),
        signature_id=as_int(alert.get("signature_id")),
        severity=min(max(severity, 1), 3) if severity is not None else 3,
        category=clean_text(category, 120) if isinstance(category, str) else None,
        src=valid_ip(obj.get("src_ip")),
        dst=valid_ip(obj.get("dest_ip")),
        proto=clean_text(proto, 20).lower() if isinstance(proto, str) else None,
        dst_port=as_int(obj.get("dest_port")),
        raw=clean_text(line, 4000),
    )
