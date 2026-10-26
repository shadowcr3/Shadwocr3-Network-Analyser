"""Report generation. PDF is the human-readable format; CSV is for spreadsheets."""
from __future__ import annotations

import os
from pathlib import Path

from shadowcr3_na.core.export import ReportInfo, write_report
from shadowcr3_na.core.models import ScanResult

from .scan_report import build_scan_pdf


def write_scan_report(result: ScanResult, path: str | os.PathLike[str]) -> ReportInfo:
    suffix = Path(path).suffix.lower()
    if suffix == ".pdf":
        return build_scan_pdf(result, path)
    if suffix == ".csv":
        return write_report(result, Path(path))
    raise ValueError(f"Unsupported report format '{Path(path).suffix}'. Use .pdf or .csv.")
