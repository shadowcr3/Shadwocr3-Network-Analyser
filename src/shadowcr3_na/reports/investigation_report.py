"""Branded PDF for an investigation: notes, linked evidence with provenance, timeline."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from reportlab.platypus import Flowable, KeepTogether, Spacer, Table, TableStyle

from shadowcr3_na.core.export import ReportInfo
from shadowcr3_na.storage.investigations import DISCLAIMER, ReportData, collect_report

from . import brand
from .pdf import (
    CONTENT_W,
    Badge,
    build_pdf,
    data_table,
    facts,
    para,
    section,
    title_block,
    utc_now_text,
    write_pdf_atomic,
)


def _card(n: int, item) -> Flowable:
    head = para(f"{n}.  {item.kind.upper()} #{item.ref_id}", "cellb", 80)
    body: list[Flowable] = [head]
    if not item.available:
        body.append(para("Evidence no longer available (it was deleted or its import was "
                         "removed).", "muted"))
    for line in item.lines:
        body.append(para(line, "cell", 600))
    for flag in item.flags:
        body.append(para(flag, "warn", 400))
    if item.note:
        body.append(para("Analyst note: " + item.note, "cell", 2000))
    card = Table([[body]], colWidths=[CONTENT_W])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), brand.LIGHT),
        ("LINEBEFORE", (0, 0), (0, -1), 2.2, brand.ACCENT if item.available else brand.BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return card


def _story(data: ReportData) -> list[Flowable]:
    inv = data.investigation
    status = Badge(inv.status, brand.OK if inv.status == "open" else brand.MUTED)
    story: list[Flowable] = title_block(
        "Investigation Report", inv.title,
        f"Created {inv.created_at:%Y-%m-%d %H:%M} UTC   |   updated "
        f"{inv.updated_at:%Y-%m-%d %H:%M} UTC   |   report generated {utc_now_text()}")
    story.append(facts([("Status", status), ("Linked evidence", str(len(data.items))),
                        ("Unavailable items", str(sum(not i.available for i in data.items)))]))
    story += [Spacer(1, 17), para(DISCLAIMER, "small", 600)]
    story += [Spacer(1, 17), *section("Analyst notes")]
    notes = [n for n in inv.notes.splitlines() if n.strip()]
    story += [para(n, "body", 3000) for n in notes] or [para("No notes.", "muted")]
    story += [Spacer(1, 17), *section("Linked evidence")]
    if not data.items:
        story.append(para("No evidence linked.", "muted"))
    for n, item in enumerate(data.items, 1):
        story += [KeepTogether([_card(n, item)]), Spacer(1, 5)]
    dated = sorted(((i.ts, i) for i in data.items if i.ts is not None),
                   key=lambda pair: (pair[0], pair[1].ref_id))
    story += [Spacer(1, 12), *section("Timeline (UTC)")]
    if dated:
        story.append(data_table(("Time", "Evidence"),
                                [[f"{ts:%Y-%m-%d %H:%M:%S}", f"{i.kind} #{i.ref_id}"]
                                 for ts, i in dated], (40, 134)))
    else:
        story.append(para("No dated evidence.", "muted"))
    return story


def build_investigation_pdf(conn: sqlite3.Connection, inv_id: int,
                            path: str | os.PathLike[str]) -> ReportInfo:
    data = collect_report(conn, inv_id)

    def build(tmp: os.PathLike[str]) -> None:
        build_pdf(Path(tmp), _story(data), kind="Investigation report",
                  short_title=f"Investigation | {data.investigation.title}",
                  title=f"Investigation Report {data.investigation.title}",
                  subject="Evidence-backed investigation report")

    return write_pdf_atomic(path, build)
