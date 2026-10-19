from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import ScanResult

REPORT_SCHEMA_VERSION = 1

CSV_COLUMNS = (
    "target", "profile", "started_at", "ip", "host_state", "mac", "vendor",
    "hostname", "port", "protocol", "port_state", "service", "product", "version",
)

# Spreadsheet apps treat cells starting with these as formulas.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def result_to_dict(r: ScanResult) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": r.target,
        "profile": r.profile,
        "nmap_version": r.nmap_version,
        "privileged": r.privileged,
        "started_at": r.started_at.isoformat(),
        "duration_s": r.duration_s,
        "hosts": [asdict(h) for h in r.hosts],
    }


def to_json(r: ScanResult) -> str:
    return json.dumps(result_to_dict(r), indent=2, ensure_ascii=False) + "\n"


def _cell(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def to_csv(r: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    base = (r.target, r.profile, r.started_at.isoformat())
    for h in r.hosts:
        host_part = (h.ip, h.state, h.mac, h.vendor, h.hostname)
        if not h.ports:
            writer.writerow([_cell(v) for v in (*base, *host_part, *([None] * 6))])
        for p in h.ports:
            port_part = (p.number, p.protocol, p.state, p.service, p.product, p.version)
            writer.writerow([_cell(v) for v in (*base, *host_part, *port_part)])
    return buf.getvalue()


def write_report(result: ScanResult, path: str | Path) -> Path:
    target = Path(path)
    suffix = target.suffix.lower()
    if suffix == ".json":
        text, encoding = to_json(result), "utf-8"
    elif suffix == ".csv":
        text, encoding = to_csv(result), "utf-8-sig"  # BOM so Excel reads UTF-8
    else:
        raise ValueError(f"Unsupported report format '{target.suffix}'. Use .json or .csv.")
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(text, encoding=encoding, newline="")
    tmp.replace(target)  # atomic: readers never see a half-written report
    return target
