"""A native PySide6 widget for drawing rate graphs."""

from dataclasses import dataclass
from typing import override

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import QWidget

INTEGER_FORMAT_THRESHOLD = 10


@dataclass(frozen=True, slots=True)
class RateGraphTheme:
    """Color theme for the rate graph."""

    line_color: str | QColor
    fill_color: str | QColor
    avg_color: str | QColor
    threshold_color: str | QColor | None = None


class RateGraphWidget(QWidget):
    """A custom widget for drawing live rate graphs."""

    def __init__(
        self,
        left_label: str,
        theme: RateGraphTheme,
        visible_window: int = 60,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the rate graph widget."""
        super().__init__(parent)
        self.left_label = left_label
        self.line_color = QColor(theme.line_color)
        self.fill_color = QColor(theme.fill_color)
        self.avg_color = QColor(theme.avg_color)
        self.threshold_color = QColor(theme.threshold_color) if theme.threshold_color else None
        self.visible_window = visible_window

        self._data: list[float] = []
        self._average: float = 0.0
        self._threshold: float | None = None
        self._y_max: float = 10.0
        self._y_min: float = 0.0

        self.setMinimumSize(200, 100)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, on=True)

    def set_data(self, data: list[float]) -> None:
        """Set the data to be drawn (should be up to visible_window items)."""
        self._data = data[-self.visible_window :]
        self.update()

    def set_average(self, avg: float) -> None:
        """Set the average value for the dotted line."""
        self._average = avg
        self.update()

    def set_threshold(self, threshold: float | None) -> None:
        """Set the threshold value for the dashed line."""
        self._threshold = threshold
        self.update()

    def set_y_range(self, y_min: float, y_max: float) -> None:
        """Set the Y-axis range."""
        self._y_min = y_min
        self._y_max = y_max
        self.update()

    @classmethod
    def create_pps_widget(cls, visible_window: int = 60, parent: QWidget | None = None) -> RateGraphWidget:
        """Create a RateGraphWidget configured for Packets per Second (PPS)."""
        return cls(
            left_label='PPS',
            theme=RateGraphTheme(
                line_color='lime',
                fill_color=QColor(0, 255, 0, 60),
                avg_color='#388e3c',
            ),
            visible_window=visible_window,
            parent=parent,
        )

    @classmethod
    def create_bps_widget(cls, visible_window: int = 60, parent: QWidget | None = None) -> RateGraphWidget:
        """Create a RateGraphWidget configured for Bytes per Second (BPS in KB/s)."""
        return cls(
            left_label='KB/s',
            theme=RateGraphTheme(
                line_color='#00bcd4',
                fill_color=QColor(0, 188, 212, 60),
                avg_color='#0097a7',
            ),
            visible_window=visible_window,
            parent=parent,
        )

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Paint the graph."""
        if not a0:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
        painter.fillRect(a0.rect(), Qt.GlobalColor.black)

        rect = self.rect()
        margin_left = 60
        margin_bottom = 45
        margin_top = 10
        margin_right = 10

        graph_width = rect.width() - margin_left - margin_right
        graph_height = rect.height() - margin_top - margin_bottom

        if graph_width <= 0 or graph_height <= 0:
            return

        # Draw grid
        painter.setPen(QPen(QColor(50, 50, 50), 1, Qt.PenStyle.SolidLine))
        num_x_lines = 6
        for i in range(num_x_lines + 1):
            x = margin_left + i * graph_width / num_x_lines
            painter.drawLine(int(x), margin_top, int(x), margin_top + graph_height)

        num_y_lines = 4
        for i in range(num_y_lines + 1):
            y = margin_top + i * graph_height / num_y_lines
            painter.drawLine(margin_left, int(y), margin_left + graph_width, int(y))

        # Y-axis labels
        painter.setPen(QPen(self.line_color, 1))
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        for i in range(num_y_lines + 1):
            y_val = self._y_min + (self._y_max - self._y_min) * (num_y_lines - i) / num_y_lines
            y = margin_top + i * graph_height / num_y_lines
            text = f'{int(y_val)}' if y_val >= INTEGER_FORMAT_THRESHOLD else f'{y_val:.1f}'
            painter.drawText(0, int(y) - 10, margin_left - 5, 20, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, text)

        # X-axis labels
        painter.setPen(QPen(QColor(200, 200, 200), 1))
        for i in range(num_x_lines + 1):
            x_val = self.visible_window * (num_x_lines - i) / num_x_lines
            x = margin_left + i * graph_width / num_x_lines
            text = f'{int(x_val)}'
            painter.drawText(int(x) - 20, margin_top + graph_height + 5, 40, 20, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, text)

        # Axis titles
        painter.save()
        painter.setPen(QPen(self.line_color, 1))
        painter.translate(15, margin_top + graph_height / 2)
        painter.rotate(-90)
        painter.drawText(-100, -10, 200, 20, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, self.left_label)
        painter.restore()

        painter.setPen(QPen(QColor(200, 200, 200), 1))
        painter.drawText(margin_left, margin_top + graph_height + 20, graph_width, 20, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, 'Time (seconds ago)')

        # Draw data
        if not self._data:
            return

        def value_to_y(val: float) -> float:
            span = self._y_max - self._y_min
            if not span:
                span = 1
            normalized = (val - self._y_min) / span
            return margin_top + graph_height * (1 - normalized)

        path = QPainterPath()
        num_points = len(self._data)
        dx = graph_width / (self.visible_window - 1) if self.visible_window > 1 else 0

        line_path = QPainterPath()
        for i, val in enumerate(self._data):
            x = margin_left + graph_width - (num_points - 1 - i) * dx
            y = value_to_y(val)
            if i:
                line_path.lineTo(x, y)
                path.lineTo(x, y)
            else:
                line_path.moveTo(x, y)
                path.moveTo(x, margin_top + graph_height)
                path.lineTo(x, y)

        if num_points > 0:
            last_x = margin_left + graph_width
            path.lineTo(last_x, margin_top + graph_height)
            path.closeSubpath()

            # Fill
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(self.fill_color))
            painter.drawPath(path)

            # Line
            pen = QPen(self.line_color, 2)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(line_path)

        # Average line
        if self._average > 0:
            y = value_to_y(self._average)
            if margin_top <= y <= margin_top + graph_height:
                pen = QPen(self.avg_color, 1.5, Qt.PenStyle.DotLine)
                painter.setPen(pen)
                painter.drawLine(margin_left, int(y), margin_left + graph_width, int(y))

        # Threshold line
        if self._threshold is not None and self.threshold_color:
            y = value_to_y(self._threshold)
            if margin_top <= y <= margin_top + graph_height:
                pen = QPen(self.threshold_color, 1.5, Qt.PenStyle.DashLine)
                painter.setPen(pen)
                painter.drawLine(margin_left, int(y), margin_left + graph_width, int(y))
