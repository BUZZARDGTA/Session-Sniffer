"""A native PySide6 widget for drawing rate graphs."""

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QEvent, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QLinearGradient, QMouseEvent, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import QWidget

from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.theming import themed_qcolor, themed_text_qcolor
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr

if TYPE_CHECKING:
    from collections.abc import Callable

INTEGER_FORMAT_THRESHOLD = 10
_MARGIN_LEFT = 60
_MARGIN_BOTTOM = 45
_MARGIN_TOP = 10
_MARGIN_RIGHT = 10

_PPS_HEAT_STOPS: tuple[tuple[float, tuple[int, int, int]], ...] = (
    (0.00, (34, 197, 94)),    # #22c55e — calm emerald
    (0.40, (132, 204, 22)),   # #84cc16 — distant sync lime
    (0.70, (234, 179, 8)),    # #eab308 — approaching yellow-amber
    (0.95, (249, 115, 22)),   # #f97316 — close hot orange
    (1.35, (239, 68, 68)),    # #ef4444 — spike crimson red
    (1.85, (236, 72, 153)),   # #ec4899 — point-blank vivid rose-magenta
)

_BPS_HEAT_STOPS: tuple[tuple[float, tuple[int, int, int]], ...] = (
    (0.00, (6, 182, 212)),    # #06b6d4 — calm cyan
    (0.40, (34, 211, 238)),   # #22d3ee — light sky-cyan
    (0.75, (234, 179, 8)),    # #eab308 — approaching yellow-amber
    (1.00, (249, 115, 22)),   # #f97316 — threshold orange
    (1.40, (239, 68, 68)),    # #ef4444 — spike crimson red
    (1.90, (236, 72, 153)),   # #ec4899 — heavy burst vivid rose-magenta
)

_GRADIENT_SAMPLE_STEPS: tuple[float, ...] = (0.0, 0.14, 0.28, 0.42, 0.56, 0.70, 0.85, 1.0)
_PROXIMITY_BADGE_MIN_LEVEL = 0.35
_BADGE_LIGHT_LUMINANCE_THRESHOLD = 158


def interpolate_heat_rgb(level: float, *, is_bps: bool = False) -> tuple[int, int, int]:
    """Interpolate an `(R, G, B)` heat color for *level* (`rate / threshold`)."""
    stops = _BPS_HEAT_STOPS if is_bps else _PPS_HEAT_STOPS
    if level <= stops[0][0]:
        return stops[0][1]
    for i in range(1, len(stops)):
        prev_lvl, prev_rgb = stops[i - 1]
        next_lvl, next_rgb = stops[i]
        if level <= next_lvl:
            t = (level - prev_lvl) / (next_lvl - prev_lvl)
            return (
                round(prev_rgb[0] + (next_rgb[0] - prev_rgb[0]) * t),
                round(prev_rgb[1] + (next_rgb[1] - prev_rgb[1]) * t),
                round(prev_rgb[2] + (next_rgb[2] - prev_rgb[2]) * t),
            )
    return stops[-1][1]


@dataclass(frozen=True, slots=True)
class RateGraphTheme:
    """Color theme for the rate graph."""

    line_color: str | QColor
    fill_color: str | QColor
    avg_color: str | QColor
    threshold_color: str | QColor | None = None


@dataclass(frozen=True, slots=True)
class SpikeOverlayState:
    """Visual spike and proximity radar state rendered on `RateGraphWidget`."""

    active: bool = False
    proximity_level: float = 0.0
    approaching: bool = False
    streak_seconds: int = 0
    peak_text: str = ''
    current_rate_text: str = ''


@dataclass(frozen=True, slots=True)
class ThresholdDragConfig:
    """Interactive vertical drag bounds and callbacks for the threshold marker line."""

    min_value: int
    max_value: int
    unit_label: str
    on_preview: Callable[[int], None] | None = None
    on_commit: Callable[[int], None] | None = None


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
        self._graph_theme = theme
        self.line_color = QColor()
        self.fill_color = QColor()
        self.avg_color = QColor()
        self.threshold_color: QColor | None = None
        self.refresh_theme_colors()
        self.visible_window = visible_window

        self._data: list[float] = []
        self._average: float = 0.0
        self._threshold: float | None = None
        self._y_max: float = 10.0
        self._y_min: float = 0.0
        self._heat_gradient_enabled: bool = False
        self._overlay_state = SpikeOverlayState()
        self._drag_config: ThresholdDragConfig | None = None
        self._hovering_threshold: bool = False
        self._dragging_threshold: bool = False
        self._last_drag_value: int | None = None

        self.setMinimumSize(scale_by_ui(200), scale_by_ui(100))
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, on=True)
        register_language_refresh(self, self.update)

    @property
    def y_max(self) -> float:
        """Return the current upper Y-axis bound."""
        return self._y_max

    @property
    def is_dragging_threshold(self) -> bool:
        """Return whether the user is actively dragging the threshold line."""
        return self._dragging_threshold

    def set_threshold_drag_config(self, config: ThresholdDragConfig | None) -> None:
        """Configure interactive vertical dragging on the dashed threshold line."""
        self._drag_config = config
        self.setMouseTracking(config is not None)

    def refresh_theme_colors(self) -> None:
        """Recompute graph line, fill, average, and threshold colors for the active theme."""
        theme = self._graph_theme
        self.line_color = themed_text_qcolor(theme.line_color, '@table[#000000]')
        self.fill_color = themed_qcolor(theme.fill_color)
        self.avg_color = themed_text_qcolor(theme.avg_color, '@table[#000000]')
        self.threshold_color = themed_text_qcolor(theme.threshold_color, '@table[#000000]') if theme.threshold_color is not None else None
        self.update()

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

    def set_threshold_color(self, color: str | QColor | None) -> None:
        """Persist and apply the threshold marker color across theme refreshes."""
        self._graph_theme = replace(self._graph_theme, threshold_color=color)
        self.refresh_theme_colors()

    def set_heat_gradient(self, *, enabled: bool) -> None:
        """Enable or disable dynamic proximity/rate heat color gradients along the curve and fill."""
        if self._heat_gradient_enabled == enabled:
            return
        self._heat_gradient_enabled = enabled
        self.update()

    def set_spike_state(self, state: SpikeOverlayState) -> None:
        """Update the active visual spike / proximity radar highlight state and badge metrics."""
        if self._overlay_state == state:
            return
        self._overlay_state = state
        self.update()

    def set_y_range(self, y_min: float, y_max: float) -> None:
        """Set the Y-axis range."""
        self._y_min = y_min
        self._y_max = y_max
        self.update()

    @classmethod
    def create_pps_widget(cls, visible_window: int = 60) -> RateGraphWidget:
        """Create a RateGraphWidget configured for Packets per Second (PPS)."""
        return cls(
            left_label='PPS',
            theme=RateGraphTheme(
                line_color='lime',
                fill_color=QColor(0, 255, 0, 60),
                avg_color='#388e3c',
            ),
            visible_window=visible_window,
        )

    @classmethod
    def create_bps_widget(cls, visible_window: int = 60) -> RateGraphWidget:
        """Create a RateGraphWidget configured for Bytes per Second (BPS in KB/s)."""
        return cls(
            left_label='KB/s',
            theme=RateGraphTheme(
                line_color='#00bcd4',
                fill_color=QColor(0, 188, 212, 60),
                avg_color='#0097a7',
            ),
            visible_window=visible_window,
        )

    @classmethod
    def create_latency_widget(cls, visible_window: int = 60) -> RateGraphWidget:
        """Create a RateGraphWidget configured for packet latency (ms/s)."""
        return cls(
            left_label='Latency (ms/s)',
            theme=RateGraphTheme(
                line_color='#ff9800',
                fill_color=QColor(255, 152, 0, 60),
                avg_color='#e65100',
            ),
            visible_window=visible_window,
        )

    def _build_heat_brushes(self, *, margin_top: int, graph_height: int) -> tuple[QBrush, QBrush]:
        """Build vertical line and area-fill brushes mapped dynamically to `rate / threshold`."""
        if not self._heat_gradient_enabled or self._threshold is None or self._threshold <= 0:
            return QBrush(self.line_color), QBrush(self.fill_color)

        is_bps = self.left_label == 'KB/s'
        top_y = float(margin_top)
        bot_y = float(margin_top + graph_height)
        line_grad = QLinearGradient(0.0, top_y, 0.0, bot_y)
        fill_grad = QLinearGradient(0.0, top_y, 0.0, bot_y)
        span = max(1.0, self._y_max - self._y_min)

        for step in _GRADIENT_SAMPLE_STEPS:
            rate_at_step = self._y_min + (1.0 - step) * span
            heat_ratio = max(0.0, rate_at_step / self._threshold)
            r, g, b = interpolate_heat_rgb(heat_ratio, is_bps=is_bps)
            line_grad.setColorAt(step, QColor(r, g, b))
            fill_alpha = min(115, round(30 + min(2.0, heat_ratio) * 42))
            fill_grad.setColorAt(step, QColor(r, g, b, fill_alpha))

        return QBrush(line_grad), QBrush(fill_grad)

    def _paint_danger_zone(self, painter: QPainter, *, margin_left: int, margin_top: int, graph_width: int, threshold_y: float) -> None:
        """Paint a soft vertical heat-tinted danger zone above the threshold line during active spikes."""
        zone_bottom = max(float(margin_top), threshold_y)
        if zone_bottom <= margin_top:
            return
        is_bps = self.left_label == 'KB/s'
        r, g, b = interpolate_heat_rgb(max(1.2, self._overlay_state.proximity_level), is_bps=is_bps)
        zone_grad = QLinearGradient(0.0, float(margin_top), 0.0, zone_bottom)
        zone_grad.setColorAt(0.0, QColor(r, g, b, 58))
        zone_grad.setColorAt(1.0, QColor(r, g, b, 14))
        painter.fillRect(QRectF(margin_left, margin_top, graph_width, zone_bottom - margin_top), zone_grad)

    def _plot_dimensions(self) -> tuple[int, int]:
        rect = self.rect()
        return rect.width() - _MARGIN_LEFT - _MARGIN_RIGHT, rect.height() - _MARGIN_TOP - _MARGIN_BOTTOM

    def _value_to_y(self, value: float, graph_height: int) -> float:
        span = (self._y_max - self._y_min) or 1.0
        return _MARGIN_TOP + graph_height * (1.0 - (value - self._y_min) / span)

    def _is_near_threshold_line(self, x_pos: float, y_pos: float) -> bool:
        if self._drag_config is None or self._threshold is None:
            return False
        graph_width, graph_height = self._plot_dimensions()
        if graph_width <= 0 or graph_height <= 0:
            return False
        if x_pos < _MARGIN_LEFT or x_pos > _MARGIN_LEFT + graph_width:
            return False
        thresh_y = self._value_to_y(self._threshold, graph_height)
        hit_pad = float(scale_by_ui(7))
        if thresh_y < _MARGIN_TOP - hit_pad or thresh_y > _MARGIN_TOP + graph_height + hit_pad:
            return False
        return abs(y_pos - thresh_y) <= hit_pad

    def _y_to_clamped_threshold(self, y_pos: float, cfg: ThresholdDragConfig) -> int:
        _, graph_height = self._plot_dimensions()
        if graph_height <= 0:
            return cfg.min_value
        span = (self._y_max - self._y_min) or 1.0
        raw_val = self._y_min + (1.0 - (y_pos - _MARGIN_TOP) / graph_height) * span
        return min(cfg.max_value, max(cfg.min_value, round(raw_val)))

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Begin interactive threshold dragging when clicking near the dashed threshold line."""
        pos = event.position()
        if event.button() == Qt.MouseButton.LeftButton and self._drag_config is not None and self._is_near_threshold_line(pos.x(), pos.y()):
            self._dragging_threshold = True
            self._last_drag_value = (
                min(self._drag_config.max_value, max(self._drag_config.min_value, round(self._threshold)))
                if self._threshold is not None
                else self._drag_config.min_value
            )
            self.setCursor(Qt.CursorShape.SplitVCursor)
            self.update()
            event.accept()
            return
        super().mousePressEvent(event)

    @override
    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        """Update threshold line drag preview or hover cursor state."""
        pos = event.position()
        if self._dragging_threshold and self._drag_config is not None:
            new_val = self._y_to_clamped_threshold(pos.y(), self._drag_config)
            self._threshold = float(new_val)
            self.update()
            if new_val != self._last_drag_value:
                self._last_drag_value = new_val
                if self._drag_config.on_preview is not None:
                    self._drag_config.on_preview(new_val)
            event.accept()
            return

        near = self._is_near_threshold_line(pos.x(), pos.y())
        if near != self._hovering_threshold:
            self._hovering_threshold = near
            if near:
                self.setCursor(Qt.CursorShape.SplitVCursor)
            else:
                self.unsetCursor()
            self.update()
        super().mouseMoveEvent(event)

    @override
    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        """Commit dragged threshold value on left-button release."""
        if event.button() == Qt.MouseButton.LeftButton and self._dragging_threshold:
            self._dragging_threshold = False
            cfg = self._drag_config
            committed_val = self._last_drag_value
            if cfg is not None and cfg.on_commit is not None and committed_val is not None:
                cfg.on_commit(committed_val)
            pos = event.position()
            self._hovering_threshold = self._is_near_threshold_line(pos.x(), pos.y())
            if self._hovering_threshold:
                self.setCursor(Qt.CursorShape.SplitVCursor)
            else:
                self.unsetCursor()
            self.update()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    @override
    def leaveEvent(self, event: QEvent) -> None:
        """Clear threshold hover state when the cursor leaves the graph."""
        if not self._dragging_threshold and self._hovering_threshold:
            self._hovering_threshold = False
            self.unsetCursor()
            self.update()
        super().leaveEvent(event)

    def _paint_threshold_drag_pill(self, painter: QPainter, *, thresh_line_y: float, graph_height: int, line_color: QColor) -> None:
        """Paint a compact live value tag on the threshold line while hovered or dragged."""
        if self._drag_config is None or self._threshold is None:
            return
        pill_text = f'↕ {round(self._threshold)} {tr(self._drag_config.unit_label)}'
        pill_font = painter.font()
        pill_font.setPointSize(8)
        pill_font.setBold(True)
        painter.setFont(pill_font)
        metrics = painter.fontMetrics()
        pad_x = scale_by_ui(6)
        pad_y = scale_by_ui(2)
        pill_w = metrics.horizontalAdvance(pill_text) + pad_x * 2
        pill_h = metrics.height() + pad_y * 2
        pill_y = min(float(_MARGIN_TOP + graph_height - pill_h), max(float(_MARGIN_TOP), thresh_line_y - pill_h / 2.0))
        pill_rect = QRectF(_MARGIN_LEFT + scale_by_ui(6), pill_y, pill_w, pill_h)
        painter.setPen(QPen(line_color, 1.2))
        painter.setBrush(QBrush(QColor(17, 24, 39, 232)))
        painter.drawRoundedRect(pill_rect, 3.5, 3.5)
        painter.setPen(QPen(line_color, 1))
        painter.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, pill_text)

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Paint the graph."""
        if not a0:
            return
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, on=True)
            painter.fillRect(a0.rect(), themed_qcolor('@table[#000000]'))

            margin_left = _MARGIN_LEFT
            margin_top = _MARGIN_TOP
            graph_width, graph_height = self._plot_dimensions()
            if graph_width <= 0 or graph_height <= 0:
                return

            self._paint_axes_and_grid(painter, margin_left=margin_left, margin_top=margin_top, graph_width=graph_width, graph_height=graph_height)
            if not self._data:
                return

            state = self._overlay_state
            if state.active:
                thresh_y = (
                    min(float(margin_top + graph_height), self._value_to_y(self._threshold, graph_height))
                    if self._threshold is not None
                    else float(margin_top + graph_height)
                )
                self._paint_danger_zone(painter, margin_left=margin_left, margin_top=margin_top, graph_width=graph_width, threshold_y=thresh_y)

            self._paint_data_series(painter, margin_left=margin_left, margin_top=margin_top, graph_width=graph_width, graph_height=graph_height)

            if self._average > 0:
                avg_y = self._value_to_y(self._average, graph_height)
                if margin_top <= avg_y <= margin_top + graph_height:
                    painter.setPen(QPen(self.avg_color, 1.5, Qt.PenStyle.DotLine))
                    painter.drawLine(margin_left, int(avg_y), margin_left + graph_width, int(avg_y))

            if self._threshold is not None and self.threshold_color:
                thresh_line_y = self._value_to_y(self._threshold, graph_height)
                if margin_top <= thresh_line_y <= margin_top + graph_height:
                    is_bps = self.left_label == 'KB/s'
                    interactive_active = self._hovering_threshold or self._dragging_threshold
                    t_color = QColor(*interpolate_heat_rgb(max(1.25, state.proximity_level), is_bps=is_bps)) if state.active else self.threshold_color
                    pen_width = 2.4 if interactive_active else (2.0 if state.active else 1.5)
                    painter.setPen(QPen(t_color, pen_width, Qt.PenStyle.DashLine))
                    painter.drawLine(margin_left, int(thresh_line_y), margin_left + graph_width, int(thresh_line_y))
                    if interactive_active:
                        self._paint_threshold_drag_pill(painter, thresh_line_y=thresh_line_y, graph_height=graph_height, line_color=t_color)

            if state.active or (self._heat_gradient_enabled and state.proximity_level >= _PROXIMITY_BADGE_MIN_LEVEL):
                self._paint_spike_overlay(painter, margin_left=margin_left, margin_top=margin_top, graph_width=graph_width, graph_height=graph_height)
        finally:
            painter.end()

    def _paint_axes_and_grid(self, painter: QPainter, *, margin_left: int, margin_top: int, graph_width: int, graph_height: int) -> None:
        """Paint background grid lines, Y/X tick labels, and axis titles."""
        painter.setPen(QPen(themed_qcolor('@border[#323232]'), 1, Qt.PenStyle.SolidLine))
        num_x_lines = 6
        for i in range(num_x_lines + 1):
            x_pos = margin_left + i * graph_width / num_x_lines
            painter.drawLine(int(x_pos), margin_top, int(x_pos), margin_top + graph_height)

        num_y_lines = 4
        for i in range(num_y_lines + 1):
            y_pos = margin_top + i * graph_height / num_y_lines
            painter.drawLine(margin_left, int(y_pos), margin_left + graph_width, int(y_pos))

        painter.setPen(QPen(self.line_color, 1))
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        for i in range(num_y_lines + 1):
            y_val = self._y_min + (self._y_max - self._y_min) * (num_y_lines - i) / num_y_lines
            y_pos = margin_top + i * graph_height / num_y_lines
            text = f'{int(y_val)}' if y_val >= INTEGER_FORMAT_THRESHOLD else f'{y_val:.1f}'
            painter.drawText(0, int(y_pos) - 10, margin_left - 5, 20, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, text)

        axis_label_color = themed_text_qcolor('@text_muted[#c8c8c8]', '@table[#000000]')
        painter.setPen(QPen(axis_label_color, 1))
        for i in range(num_x_lines + 1):
            x_val = self.visible_window * (num_x_lines - i) / num_x_lines
            x_pos = margin_left + i * graph_width / num_x_lines
            painter.drawText(int(x_pos) - 20, margin_top + graph_height + 5, 40, 20, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, f'{int(x_val)}')

        painter.save()
        painter.setPen(QPen(self.line_color, 1))
        painter.translate(15, margin_top + graph_height / 2)
        painter.rotate(-90)
        painter.drawText(-100, -10, 200, 20, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, tr(self.left_label))
        painter.restore()

        painter.setPen(QPen(axis_label_color, 1))
        painter.drawText(margin_left, margin_top + graph_height + 20, graph_width, 20, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, tr('Time (seconds ago)'))

    def _paint_data_series(self, painter: QPainter, *, margin_left: int, margin_top: int, graph_width: int, graph_height: int) -> None:
        """Paint the filled area and stroke curve for `self._data`."""
        num_points = len(self._data)
        if not num_points:
            return
        span = (self._y_max - self._y_min) or 1.0
        dx = graph_width / (self.visible_window - 1) if self.visible_window > 1 else 0.0

        fill_path = QPainterPath()
        line_path = QPainterPath()
        for i, rate_value in enumerate(self._data):
            x_pos = margin_left + graph_width - (num_points - 1 - i) * dx
            y_pos = margin_top + graph_height * (1.0 - (rate_value - self._y_min) / span)
            if i:
                line_path.lineTo(x_pos, y_pos)
                fill_path.lineTo(x_pos, y_pos)
            else:
                line_path.moveTo(x_pos, y_pos)
                fill_path.moveTo(x_pos, margin_top + graph_height)
                fill_path.lineTo(x_pos, y_pos)

        fill_path.lineTo(margin_left + graph_width, margin_top + graph_height)
        fill_path.closeSubpath()

        line_brush, fill_brush = self._build_heat_brushes(margin_top=margin_top, graph_height=graph_height)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill_brush)
        painter.drawPath(fill_path)

        painter.setPen(QPen(line_brush, 2.2 if self._heat_gradient_enabled else 2.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(line_path)

    def _paint_spike_overlay(
        self,
        painter: QPainter,
        *,
        margin_left: int,
        margin_top: int,
        graph_width: int,
        graph_height: int,
    ) -> None:
        """Draw the heat-interpolated alert frame and live proximity / spike status pill badge."""
        state = self._overlay_state
        is_bps = self.left_label == 'KB/s'
        effective_level = max(1.25, state.proximity_level) if state.active else state.proximity_level
        r, g, b = interpolate_heat_rgb(effective_level, is_bps=is_bps)

        border_alpha = 235 if state.active else min(200, round(95 + state.proximity_level * 105))
        border_width = 1.8 if state.active else 1.2
        painter.setPen(QPen(QColor(r, g, b, border_alpha), border_width, Qt.PenStyle.SolidLine))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(margin_left, margin_top, graph_width, graph_height)

        trend_suffix = ' ▲' if state.approaching else ''
        if state.active:
            core_text = (
                tr('SPIKE · {seconds}s · Peak {peak}', seconds=max(1, state.streak_seconds), peak=state.peak_text)
                if state.peak_text
                else tr('SPIKE')
            )
            badge_text = f'{core_text}{trend_suffix}'
        else:
            pct = min(99, max(1, round(state.proximity_level * 100)))
            rate_label = state.current_rate_text or ''
            badge_text = f"{tr('RADAR · {pct}% · {rate}', pct=pct, rate=rate_label)}{trend_suffix}"

        badge_font = painter.font()
        badge_font.setPointSize(8)
        badge_font.setBold(True)
        painter.setFont(badge_font)
        metrics = painter.fontMetrics()
        pad_x = scale_by_ui(8)
        pad_y = scale_by_ui(3)
        badge_w = min(graph_width - scale_by_ui(12), metrics.horizontalAdvance(badge_text) + pad_x * 2)
        badge_h = metrics.height() + pad_y * 2
        if badge_w <= 0:
            return
        badge_rect = QRectF(margin_left + graph_width - badge_w - scale_by_ui(6), margin_top + scale_by_ui(6), badge_w, badge_h)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(r, g, b, 230 if state.active else 210)))
        painter.drawRoundedRect(badge_rect, 4.0, 4.0)

        luminance = 0.299 * r + 0.587 * g + 0.114 * b
        text_color = QColor('#111827') if luminance > _BADGE_LIGHT_LUMINANCE_THRESHOLD else QColor('#ffffff')
        painter.setPen(QPen(text_color, 1))
        painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, badge_text)
