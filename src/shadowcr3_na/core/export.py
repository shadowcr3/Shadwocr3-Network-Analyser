from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

from .models import ScanResult

CSV_COLUMNS = (
    "target", "profile", "started_at", "scan_complete", "ip", "host_state", "mac", "vendor",
    "hostname", "port", "protocol", "port_state", "service", "product", "version",
)

# Spreadsheet apps treat cells starting with these as formulas.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True)
class ReportInfo:
    path: Path
    sha256: str
    size: int


def _cell(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _complete_text(value: bool | None) -> str:
    return "unknown" if value is None else str(value).lower()


def to_csv(r: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    base = (r.target, r.profile, r.started_at.isoformat(), _complete_text(r.complete))
    for h in r.hosts:
        host_part = (h.ip, h.state, h.mac, h.vendor, h.hostname)
        if not h.ports:
            writer.writerow([_cell(v) for v in (*base, *host_part, *([None] * 6))])
        for p in h.ports:
            port_part = (p.number, p.protocol, p.state, p.service, p.product, p.version)
            writer.writerow([_cell(v) for v in (*base, *host_part, *port_part)])
    return buf.getvalue()


def write_report(result: ScanResult, path: str | Path) -> ReportInfo:
    """Write a CSV export atomically and return its SHA-256. (PDF: shadowcr3_na.reports.)"""
    target = Path(path)
    if target.suffix.lower() != ".csv":
        raise ValueError(f"Unsupported data format '{target.suffix}'. Use .csv.")
    tmp = target.with_name(target.name + ".tmp")
    try:
        tmp.write_text(to_csv(result), encoding="utf-8-sig", newline="")  # BOM: Excel reads UTF-8
        tmp.replace(target)
    finally:
        if tmp.exists():
            tmp.unlink()
    data = target.read_bytes()
    return ReportInfo(target, hashlib.sha256(data).hexdigest(), len(data))
