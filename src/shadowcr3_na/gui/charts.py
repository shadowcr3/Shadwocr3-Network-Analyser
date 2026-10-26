"""A small dependency-free line chart. Colours come from the palette so light and dark both work."""
from __future__ import annotations

import math
from collections.abc import Callable, Sequence

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPaintEvent, QPalette, QPen
from PySide6.QtWidgets import QWidget

SERIES_COLORS = (QColor("#2f7fd1"), QColor("#e08a1e"))


def nice_max(values: Sequence[float | None]) -> float:
    top = max((v for v in values if v is not None), default=0.0)
    if top <= 0:
        return 1.0
    magnitude = 10 ** math.floor(math.log10(top))
    for factor in (1, 2, 5, 10):
        if top <= factor * magnitude:
            return float(factor * magnitude)
    return float(10 * magnitude)


class LineChart(QWidget):
    def __init__(
        self,
        title: str,
        value_text: Callable[[float | None], str],
        series_names: Sequence[str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._title = title
        self._value_text = value_text
        self._names = tuple(series_names)
        self._data: list[list[float | None]] = [[] for _ in self._names]
        self._message: str | None = None
        self._caption = ""
        self.setMinimumHeight(170)
        self.setAccessibleName(title)

    def set_data(self, series: Sequence[Sequence[float | None]]) -> None:
        self._data = [list(s) for s in series]
        self._message = None
        self.update()

    def set_message(self, text: str) -> None:
        self._message = text
        self.update()

    def set_caption(self, text: str) -> None:
        self._caption = text
        self.update()

    @property
    def message(self) -> str | None:
        return self._message

    @property
    def data(self) -> list[list[float | None]]:
        return self._data

    def paintEvent(self, _event: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pal = self.palette()
        text_color = pal.color(QPalette.ColorRole.Text)
        grid_color = pal.color(QPalette.ColorRole.Mid)
        p.fillRect(self.rect(), pal.color(QPalette.ColorRole.Base))
        p.setPen(text_color)
        p.drawText(8, 16, self._title)
        plot = QRectF(78, 26, max(self.width() - 90, 10), max(self.height() - 52, 10))
        p.setPen(QPen(grid_color, 1))
        p.drawRect(plot)
        if self._message:
            p.setPen(text_color)
            p.drawText(plot, int(Qt.AlignmentFlag.AlignCenter) | int(Qt.TextFlag.TextWordWrap),
                       self._message)
            p.end()
            return
        top = nice_max([v for s in self._data for v in s])
        for i in range(1, 4):
            y = plot.bottom() - plot.height() * i / 4
            p.setPen(QPen(grid_color, 1, Qt.PenStyle.DotLine))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(text_color)
            p.drawText(QRectF(0, y - 8, 74, 16),
                       int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                       self._value_text(top * i / 4))
        for idx, series in enumerate(self._data):
            if len(series) < 2:
                continue
            color = SERIES_COLORS[idx % len(SERIES_COLORS)]
            p.setPen(QPen(color, 2))
            step = plot.width() / (len(series) - 1)
            path, pen_down = QPainterPath(), False
            for n, value in enumerate(series):
                if value is None:  # a gap, never an invented zero
                    pen_down = False
                    continue
                pt = QPointF(plot.left() + n * step, plot.bottom() - plot.height() * value / top)
                if pen_down:
                    path.lineTo(pt)
                else:
                    path.moveTo(pt)
                    pen_down = True
            p.drawPath(path)
        x = plot.right()
        for idx, name in reversed(list(enumerate(self._names))):
            last = next((v for v in reversed(self._data[idx]) if v is not None), None) \
                if idx < len(self._data) else None
            label = f"{name}: {self._value_text(last)}"
            width = p.fontMetrics().horizontalAdvance(label) + 20
            x -= width
            p.fillRect(QRectF(x, 6, 10, 10), SERIES_COLORS[idx % len(SERIES_COLORS)])
            p.setPen(text_color)
            p.drawText(QPointF(x + 14, 16), label)
        p.setPen(text_color)
        p.drawText(QPointF(plot.left(), self.height() - 8), self._caption)
        p.end()
