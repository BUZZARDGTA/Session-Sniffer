"""Live PPS + BPS split graph window for an individual player."""

from typing import TYPE_CHECKING, Any, override

import numpy as np
import pyqtgraph as pg  # pyright: ignore[reportMissingTypeStubs]
from PyQt6.QtCore import Qt
from pyqtgraph.graphicsItems.AxisItem import AxisItem  # pyright: ignore[reportMissingTypeStubs]
from pyqtgraph.graphicsItems.PlotItem import PlotItem  # pyright: ignore[reportMissingTypeStubs]

from session_sniffer.error_messages import format_type_error
from session_sniffer.guis.utils import ToggleAlwaysOnTopMixin, format_player_display

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QVBoxLayout
    from pyqtgraph.GraphicsScene.mouseEvents import MouseDragEvent  # pyright: ignore[reportMissingTypeStubs]

VISIBLE_WINDOW = 60
DEFAULT_MAX_HISTORY = 3600
_LIVE_EDGE_X_MAX = -2


def build_rate_plot_widget(left_label: str, max_history: int) -> tuple[pg.PlotWidget, PlotItem]:
    """Create and configure a standard dark, grid-enabled rate-monitoring `PlotWidget`.

    Returns `(widget, plot_item)`. Raises `RuntimeError` if the plot item is unavailable.
    """
    widget = pg.PlotWidget(
        axisItems={'bottom': PositiveTicksAxis(orientation='bottom')},
        viewBox=DragCursorViewBox(),
    )
    widget.setMouseEnabled(x=True, y=True)
    widget.setMenuEnabled(False)
    widget.setBackground('black')
    widget.showGrid(x=True, y=True)
    widget.setLimits(yMin=0, xMax=0, xMin=-max_history)
    widget.setLabel('left', left_label)
    widget.setLabel('bottom', 'Time (seconds ago)')
    plot = widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
    if not isinstance(plot, PlotItem):
        raise TypeError(format_type_error(plot, PlotItem))  # pyright: ignore[reportUnknownArgumentType]
    return widget, plot


def grow_x_cache(
    n: int,
    x_cache: np.ndarray[Any, np.dtype[np.float64]],
    x_cache_len: int,
) -> tuple[int, np.ndarray[Any, np.dtype[np.float64]], int]:
    """Increment *n* and rebuild the x-axis cache array if the window length changed.

    Returns `(new_n, x_cache, x_cache_len)`.
    """
    n += 1
    if n != x_cache_len:
        x_cache = np.arange(-n + 1, 1, dtype=np.float64)
        x_cache_len = n
    return n, x_cache, x_cache_len


class SingleRateGraphBase(ToggleAlwaysOnTopMixin):
    """Base class for single-series sliding-window rate graph windows."""

    WINDOW_TITLE: str
    LEFT_LABEL: str
    AXIS_PEN: str
    CURVE_PEN: str
    CURVE_BRUSH: tuple[int, int, int, int]
    AVG_PEN: str
    Y_FLOOR: float

    _max_history: int
    _buf: np.ndarray[Any, np.dtype[np.float64]]
    _buf_len: int
    _buf_sum: float
    _graph_idle: bool
    _x_cache_len: int
    _x_cache: np.ndarray[Any, np.dtype[np.float64]]

    def __init__(self, *, max_history: int, always_on_top: bool = True) -> None:
        """Initialize the shared single-series graph window."""
        super().__init__()

        self._max_history = max_history
        self._buf_sum = 0.0

        self.setWindowTitle(self.WINDOW_TITLE)
        self.resize(700, 350)
        layout = self.setup_window_layout(always_on_top=always_on_top, margins=(0, 0, 0, 0), spacing=0)

        self._widget, plot = build_rate_plot_widget(self.LEFT_LABEL, max_history)
        plot.getAxis('left').setTextPen(pg.mkPen(self.AXIS_PEN))
        self._curve = self._widget.plot(pen=pg.mkPen(self.CURVE_PEN, width=2))
        self._curve.setFillLevel(0)
        self._curve.setBrush(pg.mkBrush(*self.CURVE_BRUSH))
        self._avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen(self.AVG_PEN, width=1, style=Qt.PenStyle.DotLine),
        )
        self._widget.addItem(self._avg_line)

        layout.addWidget(self._widget)
        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)
        self._setup_single_history_buffers()

    def _setup_single_history_buffers(self) -> None:
        """Initialise pre-allocated numpy sliding-window buffers."""
        self._buf = np.zeros(self._max_history, dtype=np.float64)
        self._buf_len = VISIBLE_WINDOW
        self._buf_sum = 0.0
        self._x_cache_len = VISIBLE_WINDOW
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)
        self._graph_idle: bool = False

    def _transform_sample(self, sample: float) -> float:
        """Convert an incoming sample into the value stored in the buffer."""
        return float(sample)

    def update_graph(self, sample: float) -> None:
        """Append a new sample and refresh the graph."""
        value = self._transform_sample(sample)
        n = self._buf_len

        if n < self._max_history:
            self._buf[n] = value
            self._buf_sum += value
            n, self._x_cache, self._x_cache_len = grow_x_cache(n, self._x_cache, self._x_cache_len)
            self._buf_len = n
        else:
            self._buf_sum += value - self._buf[0]
            self._buf[:-1] = self._buf[1:]
            self._buf[-1] = value

        # Skip pyqtgraph draw calls when the graph is already showing a stable
        # flat zero baseline and the new sample is also zero.
        if not value and self._graph_idle:
            return

        data = self._buf[:n]
        self._curve.setData(self._x_cache, data)
        if self._is_at_live_edge(self._widget):
            self._widget.setXRange(-VISIBLE_WINDOW, 0)
        visible_max = float(np.max(data[-VISIBLE_WINDOW:]))
        self._widget.setYRange(0, max(visible_max * 1.2, self.Y_FLOOR))
        if n:
            self._avg_line.setPos(self._buf_sum / n)

        # Mark graph as idle once the visible window is fully zeroed out.
        self._graph_idle = not value and not visible_max

    def reset(self) -> None:
        """Clear all history and reset the graph to zero."""
        self._buf[:] = 0.0
        self._buf_len = VISIBLE_WINDOW
        self._buf_sum = 0.0
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)
        self._x_cache_len = VISIBLE_WINDOW

        zeros = np.zeros(VISIBLE_WINDOW, dtype=np.float64)
        self._curve.setData(self._x_cache, zeros)
        self._widget.setXRange(-VISIBLE_WINDOW, 0)
        self._widget.setYRange(0, self.Y_FLOOR)
        self._avg_line.setPos(0)
        self._graph_idle = False

    @staticmethod
    def _is_at_live_edge(widget: pg.PlotWidget) -> bool:
        """Return True if the widget's x-axis view includes the live (rightmost) edge."""
        x_range: list[float] = widget.viewRange()[0]
        return x_range[1] >= _LIVE_EDGE_X_MAX


class DualRateGraphBase(ToggleAlwaysOnTopMixin):
    """Base class for dual PPS+BPS graph windows.

    Subclasses must call `_finish_graph_init(always_on_top=...)` at the end of
    their `__init__` after setting `_max_history` and the window title.
    """

    _BYTES_TO_KBS: int = 1024
    _max_history: int
    _buf_len: int
    _buf_sum: float
    _dual_graph_idle: bool
    _x_cache_len: int
    _x_cache: np.ndarray[Any, np.dtype[np.float64]]
    _pps_widget: pg.PlotWidget
    _pps_curve: Any
    _pps_avg_line: pg.InfiniteLine
    _bps_widget: pg.PlotWidget
    _bps_curve: Any
    _bps_avg_line: pg.InfiniteLine
    _pps_buf: np.ndarray[Any, np.dtype[np.float64]]
    _bps_buf: np.ndarray[Any, np.dtype[np.float64]]
    _pps_sum: float
    _bps_sum: float

    def _setup_dual_graph_widgets(self, layout: QVBoxLayout) -> None:
        """Create PPS and BPS PlotWidgets and add them to *layout*.

        Calls `_configure_pps_widget()` and `_configure_bps_widget()` hooks
        after constructing each widget, allowing subclasses to add threshold lines
        or custom limits.
        """
        # ── PPS graph (top) — lime green tones ──────────────────────────
        self._pps_widget, pps_plot = build_rate_plot_widget('PPS', self._max_history)
        pps_left = pps_plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(pps_left, AxisItem):
            raise TypeError(format_type_error(pps_left, AxisItem))  # pyright: ignore[reportUnknownArgumentType]
        pps_left.setTextPen(pg.mkPen('lime'))

        self._pps_curve = self._pps_widget.plot(pen=pg.mkPen('lime', width=2))
        self._pps_curve.setFillLevel(0)
        self._pps_curve.setBrush(pg.mkBrush(0, 255, 0, 60))

        self._configure_pps_widget()

        self._pps_avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen('#388e3c', width=1, style=Qt.PenStyle.DotLine),
        )
        self._pps_widget.addItem(self._pps_avg_line)

        layout.addWidget(self._pps_widget)

        # ── BPS graph (bottom) — cyan/teal tones ────────────────────────
        self._bps_widget, bps_plot = build_rate_plot_widget('KB/s', self._max_history)
        bps_left = bps_plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(bps_left, AxisItem):
            raise TypeError(format_type_error(bps_left, AxisItem))  # pyright: ignore[reportUnknownArgumentType]
        bps_left.setTextPen(pg.mkPen('#00bcd4'))

        self._bps_curve = self._bps_widget.plot(pen=pg.mkPen('#00bcd4', width=2))
        self._bps_curve.setFillLevel(0)
        self._bps_curve.setBrush(pg.mkBrush(0, 188, 212, 60))

        self._configure_bps_widget()

        self._bps_avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen('#0097a7', width=1, style=Qt.PenStyle.DotLine),
        )
        self._bps_widget.addItem(self._bps_avg_line)

        layout.addWidget(self._bps_widget)

    def _configure_pps_widget(self) -> None:
        """Override to add PPS-specific configuration (threshold lines, custom limits, etc.)."""

    def _configure_bps_widget(self) -> None:
        """Override to add BPS-specific configuration (threshold lines, etc.)."""

    def _finish_graph_init(self, *, always_on_top: bool) -> None:
        """Initialize the common window layout, widgets, and history buffers."""
        self.resize(700, 500)
        layout = self.setup_window_layout(always_on_top=always_on_top, margins=(0, 0, 0, 0), spacing=0)
        self._setup_dual_graph_widgets(layout)
        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)
        self._setup_history_buffers()

    def _setup_history_buffers(self) -> None:
        """Initialise pre-allocated numpy sliding-window buffers."""
        self._pps_buf = np.zeros(self._max_history, dtype=np.float64)
        self._bps_buf = np.zeros(self._max_history, dtype=np.float64)
        self._buf_len = VISIBLE_WINDOW
        self._pps_sum: float = 0.0
        self._bps_sum: float = 0.0
        self._buf_sum = 0.0
        self._x_cache_len = VISIBLE_WINDOW
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)
        self._dual_graph_idle: bool = False

    def _advance_buffers(self, pps: int, bps: int) -> tuple[np.ndarray, np.ndarray, int]:
        """Advance the dual sliding window; return `(pps_data, bps_data, n)`."""
        kbps = bps / self._BYTES_TO_KBS
        n = self._buf_len

        if n < self._max_history:
            # Growth phase: append to end, rebuild x-cache only when length changes
            self._pps_buf[n] = pps
            self._bps_buf[n] = kbps
            self._pps_sum += pps
            self._bps_sum += kbps
            n, self._x_cache, self._x_cache_len = grow_x_cache(n, self._x_cache, self._x_cache_len)
            self._buf_len = n
        else:
            # Steady state: shift left (C-level memcpy), append at end
            self._pps_sum += pps - self._pps_buf[0]
            self._bps_sum += kbps - self._bps_buf[0]
            self._pps_buf[:-1] = self._pps_buf[1:]
            self._pps_buf[-1] = pps
            self._bps_buf[:-1] = self._bps_buf[1:]
            self._bps_buf[-1] = kbps

        return self._pps_buf[:n], self._bps_buf[:n], n

    def update_rates(self, *, pps: int, bps: int) -> None:
        """Append new PPS and BPS samples and refresh both graphs."""
        pps_data, bps_data, n = self._advance_buffers(pps, bps)

        # Skip pyqtgraph draw calls when both graphs are already showing a stable
        # flat zero baseline and both new samples are also zero.
        if not pps and not bps and self._dual_graph_idle:
            return

        self._pps_curve.setData(self._x_cache, pps_data)
        if self._is_at_live_edge(self._pps_widget):
            self._pps_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._on_pps_rendered(pps_data)
        if n:
            self._pps_avg_line.setPos(self._pps_sum / n)

        self._bps_curve.setData(self._x_cache, bps_data)
        if self._is_at_live_edge(self._bps_widget):
            self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._on_bps_rendered(bps_data)
        if n:
            self._bps_avg_line.setPos(self._bps_sum / n)

        # Mark graphs as idle once both visible windows are fully zeroed out.
        if not pps and not bps:
            _pps_visible_max = float(np.max(pps_data[-VISIBLE_WINDOW:]))
            _bps_visible_max = float(np.max(bps_data[-VISIBLE_WINDOW:]))
            self._dual_graph_idle = not _pps_visible_max and not _bps_visible_max
        else:
            self._dual_graph_idle = False

    def _on_pps_rendered(self, pps_data: np.ndarray) -> None:
        """Hook called after PPS graph is updated. Override to add auto-scaling."""

    def _on_bps_rendered(self, bps_data: np.ndarray) -> None:
        """Hook called after BPS graph is updated. Override to add auto-scaling."""

    @staticmethod
    def _is_at_live_edge(widget: pg.PlotWidget) -> bool:
        """Return True if the widget's x-axis view includes the live (rightmost) edge."""
        x_range: list[float] = widget.viewRange()[0]
        return x_range[1] >= _LIVE_EDGE_X_MAX


class PlayerRateGraphWindow(DualRateGraphBase):
    """A standalone window with separate PPS and BPS graphs stacked vertically."""

    _pps_threshold_line: pg.InfiniteLine
    _bps_threshold_line: pg.InfiniteLine

    def __init__(
        self,
        *,
        ip: str,
        initial_pps_threshold: int,
        initial_bps_threshold: int,
        max_history: int = DEFAULT_MAX_HISTORY,
        always_on_top: bool = True,
    ) -> None:
        """Initialize the split rate graph window for the given player IP."""
        super().__init__()

        self.ip = ip
        self._max_history = max_history
        self._initial_pps_threshold = initial_pps_threshold
        self._initial_bps_threshold = initial_bps_threshold

        self.setWindowTitle(f'Rate Graph — {ip}')
        self._finish_graph_init(always_on_top=always_on_top)

    # Configuration hooks — called from _DualRateGraphBase._setup_dual_graph_widgets
    # ——————————————————————————————————————————————————————————————————————————————

    @override
    def _configure_pps_widget(self) -> None:
        self._pps_widget.setYRange(0, 100)
        self._pps_widget.setLimits(yMin=0, yMax=1_000, xMax=0, xMin=-self._max_history)
        self._pps_threshold_line = pg.InfiniteLine(
            angle=0,
            pos=self._initial_pps_threshold,
            pen=pg.mkPen('#66bb6a', width=1.5, style=Qt.PenStyle.DashLine),
        )
        self._pps_widget.addItem(self._pps_threshold_line)

    @override
    def _configure_bps_widget(self) -> None:
        self._bps_widget.setYRange(0, 50)
        self._bps_threshold_line = pg.InfiniteLine(
            angle=0,
            pos=self._initial_bps_threshold / self._BYTES_TO_KBS,
            pen=pg.mkPen('#4dd0e1', width=1.5, style=Qt.PenStyle.DashLine),
        )
        self._bps_widget.addItem(self._bps_threshold_line)

    # Public API —————————————————————————————————————————————————————————————

    def update_usernames(self, usernames: list[str]) -> None:
        """Update the window title to reflect current usernames."""
        self.setWindowTitle(f'Rate Graph — {format_player_display(self.ip, usernames)}')

    def set_pps_threshold(self, threshold: int) -> None:
        """Update the PPS threshold marker line."""
        self._pps_threshold_line.setPos(threshold)

    def set_bps_threshold(self, threshold: int) -> None:
        """Update the BPS threshold marker line (accepts bytes/s, converts to KB/s)."""
        self._bps_threshold_line.setPos(threshold / self._BYTES_TO_KBS)

    def load_history(self, *, pps_history: list[int], bps_history: list[int]) -> None:
        """Backfill both graphs with previously recorded rate samples."""
        # Pad to at least VISIBLE_WINDOW, keep up to max_history
        pps_trimmed = pps_history[-self._max_history :]
        bps_trimmed = bps_history[-self._max_history :]
        pad_len = max(0, VISIBLE_WINDOW - len(pps_trimmed))

        n = pad_len + len(pps_trimmed)
        self._buf_len = n
        self._pps_buf[:pad_len] = 0
        self._pps_buf[pad_len:n] = pps_trimmed
        self._pps_sum = float(np.sum(self._pps_buf[:n]))

        self._bps_buf[:pad_len] = 0
        # Vectorized bytes→KB/s conversion via numpy
        bps_arr = np.array(bps_trimmed, dtype=np.float64)
        bps_arr /= self._BYTES_TO_KBS
        self._bps_buf[pad_len:n] = bps_arr
        self._bps_sum = float(np.sum(self._bps_buf[:n]))

        self._x_cache = np.arange(-n + 1, 1, dtype=np.float64)
        self._x_cache_len = n

        pps_data = self._pps_buf[:n]
        bps_data = self._bps_buf[:n]

        self._pps_curve.setData(self._x_cache, pps_data)
        self._pps_widget.setXRange(-VISIBLE_WINDOW, 0)
        if n:
            self._pps_avg_line.setPos(self._pps_sum / n)

        self._bps_curve.setData(self._x_cache, bps_data)
        self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)
        if n:
            self._bps_avg_line.setPos(self._bps_sum / n)


class PositiveTicksAxis(pg.AxisItem):  # type: ignore[misc]    # pylint: disable=abstract-method
    """Axis that displays tick labels as positive integers."""

    @override
    def tickStrings(self, values: list[float], scale: float, spacing: float) -> list[str]:
        """Override to show absolute tick values."""
        return [str(abs(int(v))) for v in values]


class DragCursorViewBox(pg.ViewBox):  # type: ignore[misc]  # pylint: disable=abstract-method
    """ViewBox that changes cursor shape during vertical drag."""

    @override
    def mouseDragEvent(self, ev: MouseDragEvent, axis: int | None = None) -> None:  # pyright: ignore[reportGeneralTypeIssues]
        """Override to show a vertical resize cursor while dragging."""
        if hasattr(ev, 'isStart') and ev.isStart():
            self.setCursor(Qt.CursorShape.SizeVerCursor)
        elif hasattr(ev, 'isFinish') and ev.isFinish():
            self.setCursor(Qt.CursorShape.ArrowCursor)
        super().mouseDragEvent(ev, axis=axis)
