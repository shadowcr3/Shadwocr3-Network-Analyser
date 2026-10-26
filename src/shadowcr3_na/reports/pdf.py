"""Branded PDF framework: header band, footer with page x of y, sections, tables, badges.

Everything that reaches the document from a scan, a file or an analyst passes through
`txt()`: it is stripped of control and non-ASCII characters and XML-escaped, because
ReportLab paragraphs interpret markup.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from shadowcr3_na import __version__
from shadowcr3_na.core.export import ReportInfo
from shadowcr3_na.core.textutil import clean_text

from . import brand

PAGE_W, PAGE_H = A4
MARGIN_X, MARGIN_TOP, MARGIN_BOTTOM = 18 * mm, 27 * mm, 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X


def txt(value: object, limit: int = 2000) -> str:
    return escape(clean_text(str(value), limit).replace("\n", " ").strip())


def _style(name: str, **kw: Any) -> ParagraphStyle:
    base: dict[str, Any] = dict(fontName="Helvetica", fontSize=9.5, leading=13,
                                textColor=brand.INK)
    base.update(kw)
    return ParagraphStyle(name, **base)


STYLES = {
    "title": _style("title", fontName="Helvetica-Bold", fontSize=24, leading=28),
    "subtitle": _style("subtitle", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
                       textColor=brand.ACCENT_DARK),
    "meta": _style("meta", fontSize=8.5, leading=12, textColor=brand.SLATE),
    "body": _style("body"),
    "small": _style("small", fontSize=8, leading=11, textColor=brand.SLATE),
    "label": _style("label", fontName="Helvetica-Bold", fontSize=6.8, leading=9,
                    textColor=brand.MUTED),
    "value": _style("value", fontName="Helvetica-Bold", fontSize=10.5, leading=13),
    "cell": _style("cell", fontSize=8.3, leading=10.5, wordWrap="CJK"),
    "cellb": _style("cellb", fontName="Helvetica-Bold", fontSize=8.3, leading=10.5,
                    wordWrap="CJK"),
    "head": _style("head", fontName="Helvetica-Bold", fontSize=8.3, leading=10.5,
                   textColor=brand.WHITE),
    "code": _style("code", fontName="Courier", fontSize=7.4, leading=9.6, wordWrap="CJK"),
    "muted": _style("muted", fontName="Helvetica-Oblique", fontSize=8.5, textColor=brand.MUTED),
    "warn": _style("warn", fontName="Helvetica-Bold", fontSize=9, textColor=brand.WARN),
}


def para(value: object, style: str = "body", limit: int = 2000) -> Paragraph:
    return Paragraph(txt(value, limit), STYLES[style])


# ---- flowables ---------------------------------------------------------------------------


class SectionHeading(Flowable):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = clean_text(text, 120)
        self.height = 9 * mm

    def wrap(self, availWidth: float, availHeight: float) -> tuple[float, float]:
        self.width = availWidth
        return availWidth, self.height

    def draw(self) -> None:
        c = self.canv
        c.setFillColor(brand.ACCENT)
        c.rect(0, 1.2 * mm, 1.5 * mm, 6 * mm, stroke=0, fill=1)
        c.setFillColor(brand.INK)
        c.setFont("Helvetica-Bold", 12.5)
        c.drawString(4 * mm, 2.6 * mm, self.text)
        c.setStrokeColor(brand.BORDER)
        c.setLineWidth(0.5)
        c.line(0, 0, self.width, 0)


def section(text: str) -> list[Flowable]:
    """A section heading that starts a new page only when too little room remains."""
    return [CondPageBreak(30 * mm), SectionHeading(text)]


class Badge(Flowable):
    def __init__(self, text: str, color: Any) -> None:
        super().__init__()
        self.text = clean_text(text, 30).upper()
        self.color = color
        self.height = 5.2 * mm
        self.width = stringWidth(self.text, "Helvetica-Bold", 7.4) + 12

    def wrap(self, availWidth: float, availHeight: float) -> tuple[float, float]:
        return self.width, self.height

    def draw(self) -> None:
        c = self.canv
        width = c.stringWidth(self.text, "Helvetica-Bold", 7.4) + 12
        c.setFillColor(self.color)
        c.roundRect(0, 0, width, self.height, 2.4, stroke=0, fill=1)
        c.setFillColor(brand.WHITE)
        c.setFont("Helvetica-Bold", 7.4)
        c.drawString(6, 1.6 * mm, self.text)


def facts(rows: Sequence[tuple[str, object]], columns: int = 3) -> Table:
    """A grid of labelled values. A value may be text or a flowable such as a Badge."""
    cells: list[list[Any]] = []
    for label, value in rows:
        shown = value if isinstance(value, Flowable) else para(value, "value", 200)
        cells.append([para(label.upper(), "label", 60), shown])
    grid = [cells[i:i + columns] for i in range(0, len(cells), columns)]
    width = CONTENT_W / columns
    table_rows: list[list[Any]] = []
    for row in grid:
        padded: list[Any] = list(row) + [None] * (columns - len(row))
        table_rows.append([[c[0], Spacer(1, 1.2), c[1]] if c else "" for c in padded])
    table = Table(table_rows, colWidths=[width] * columns)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), brand.LIGHT),
        ("LINEBEFORE", (0, 0), (-1, -1), 2, brand.ACCENT),
        ("LINEABOVE", (0, 1), (-1, -1), 3, brand.WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def data_table(headers: Sequence[str], rows: Sequence[Sequence[object]],
               widths_mm: Sequence[float]) -> Table:
    body = [[para(h, "head", 80) for h in headers]]
    body += [[c if isinstance(c, Flowable) else para(c, "cell", 400) for c in row] for row in rows]
    table = Table(body, colWidths=[w * mm for w in widths_mm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), brand.NAVY),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, brand.ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, brand.BORDER),
    ]
    for r in range(2, len(body), 2):
        style.append(("BACKGROUND", (0, r), (-1, r), brand.LIGHT))
    table.setStyle(TableStyle(style))
    return table


def code_box(value: object) -> Table:
    box = Table([[Paragraph(txt(value, 1500), STYLES["code"])]], colWidths=[CONTENT_W])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), brand.LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, brand.BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2, brand.ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return box


def title_block(title: str, subtitle: str, meta: str) -> list[Flowable]:
    return [Spacer(1, 11 * mm), para(title, "title", 120), Spacer(1, 2 * mm),
            para(subtitle, "subtitle", 200), Spacer(1, 1.5 * mm), para(meta, "meta", 300),
            Spacer(1, 6 * mm)]


# ---- page decoration ---------------------------------------------------------------------------


def _wordmark(c: rl_canvas.Canvas, x: float, y: float, size: float) -> None:
    text = c.beginText(x, y)
    text.setFont("Helvetica-Bold", size)
    text.setCharSpace(size * 0.09)
    text.setFillColor(brand.WHITE)
    text.textOut(brand.NAME)
    text.setFillColor(brand.ACCENT)
    text.textOut(brand.NAME_ACCENT)
    text.setCharSpace(0)  # PDF character spacing persists; never let it leak into later text
    c.drawText(text)


def _mark(c: rl_canvas.Canvas, x: float, y: float, size: float) -> None:
    c.setFillColor(brand.ACCENT)
    c.roundRect(x, y, size, size, size * 0.22, stroke=0, fill=1)
    c.setFillColor(brand.NAVY)
    c.setFont("Helvetica-Bold", size * 0.36)
    c.drawCentredString(x + size / 2, y + size * 0.33, "CR3")


def make_canvas(kind: str, short_title: str) -> type[rl_canvas.Canvas]:
    class BrandedCanvas(rl_canvas.Canvas):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._pages: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 (ReportLab API)
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total: int) -> None:
            first = self._pageNumber == 1
            self.saveState()
            band = 30 * mm if first else 12 * mm
            self.setFillColor(brand.NAVY)
            self.rect(0, PAGE_H - band, PAGE_W, band, stroke=0, fill=1)
            self.setFillColor(brand.ACCENT)
            self.rect(0, PAGE_H - band - 1.2 * mm, PAGE_W, 1.2 * mm, stroke=0, fill=1)
            if first:
                _mark(self, MARGIN_X, PAGE_H - 21 * mm, 11 * mm)
                _wordmark(self, MARGIN_X + 14.5 * mm, PAGE_H - 15.6 * mm, 17)
                self.setFillColor(brand.BAND_TEXT)
                self.setFont("Helvetica", 7)
                self.drawString(MARGIN_X + 14.5 * mm, PAGE_H - 19.8 * mm,
                                " ".join(brand.PRODUCT))
                self.setFont("Helvetica-Bold", 8)
                self.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 15.6 * mm, kind.upper())
            else:
                _mark(self, MARGIN_X, PAGE_H - 9.4 * mm, 6.6 * mm)
                _wordmark(self, MARGIN_X + 9 * mm, PAGE_H - 7.7 * mm, 10)
                self.setFillColor(brand.BAND_TEXT)
                self.setFont("Helvetica", 7.5)
                self.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 7.5 * mm, short_title[:80])
            self.setStrokeColor(brand.BORDER)
            self.setLineWidth(0.5)
            self.line(MARGIN_X, 14 * mm, PAGE_W - MARGIN_X, 14 * mm)
            self.setFillColor(brand.SLATE)
            self.setFont("Helvetica", 7.5)
            self.drawString(MARGIN_X, 9.5 * mm, f"{brand.PRODUCT_TITLE} v{__version__}")
            self.drawCentredString(PAGE_W / 2, 9.5 * mm, "Confidential: contains network details")
            self.drawRightString(PAGE_W - MARGIN_X, 9.5 * mm, f"Page {self._pageNumber} of {total}")
            self.restoreState()

    return BrandedCanvas


def build_pdf(path: Path, story: list[Flowable], *, kind: str, short_title: str,
              title: str, subject: str) -> None:
    doc = BaseDocTemplate(
        str(path), pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X, topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM, title=clean_text(title, 150), author=brand.PRODUCT_TITLE,
        subject=clean_text(subject, 200), creator=f"{brand.PRODUCT_TITLE} {__version__}")
    frame = Frame(MARGIN_X, MARGIN_BOTTOM, CONTENT_W, PAGE_H - MARGIN_TOP - MARGIN_BOTTOM,
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0, id="body")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame])])
    doc.build(story, canvasmaker=make_canvas(kind, short_title))


def write_pdf_atomic(path: str | os.PathLike[str],
                     build: Callable[[Path], None]) -> ReportInfo:
    """Build into a temp file, then rename, so a crash never leaves a half-written report."""
    import hashlib

    target = Path(path)
    if target.suffix.lower() != ".pdf":
        raise ValueError(f"Unsupported report format '{target.suffix}'. Use .pdf.")
    tmp = target.with_name(target.name + ".tmp")
    try:
        build(tmp)
        tmp.replace(target)
    finally:
        if tmp.exists():
            tmp.unlink()
    data = target.read_bytes()
    return ReportInfo(target, hashlib.sha256(data).hexdigest(), len(data))


def utc_now_text() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC"
