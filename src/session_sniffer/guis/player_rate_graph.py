"""Live PPS + BPS split graph window for an individual player."""

from typing import Any

import numpy as np
import pyqtgraph as pg  # pyright: ignore[reportMissingTypeStubs]
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QCheckBox, QVBoxLayout, QWidget

VISIBLE_WINDOW = 60
DEFAULT_MAX_HISTORY = 3600


class PlayerRateGraphWindow(QWidget):
    """A standalone window with separate PPS and BPS graphs stacked vertically."""

    _BYTES_TO_KBS = 1024

    def __init__(  # pylint: disable=too-many-arguments
        self, *, ip: str, initial_pps_threshold: int, initial_bps_threshold: int,
        max_history: int = DEFAULT_MAX_HISTORY, always_on_top: bool = True,
    ) -> None:
        """Initialize the split rate graph window for the given player IP."""
        super().__init__()

        self.ip = ip
        self._max_history = max_history

        self.setWindowTitle(f'Rate Graph \u2014 {ip}')
        self.resize(700, 500)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── PPS graph (top) — lime green tones ──────────────────────────
        self._pps_widget = pg.PlotWidget(
            axisItems={'bottom': _PositiveTicksAxis(orientation='bottom')},
            viewBox=_DragCursorViewBox(),
        )
        self._pps_widget.setMouseEnabled(x=True, y=True)
        self._pps_widget.setBackground('black')
        self._pps_widget.showGrid(x=True, y=True)
        self._pps_widget.setYRange(0, 100)
        self._pps_widget.setLimits(yMin=0, yMax=1_000, xMax=0, xMin=-self._max_history)
        self._pps_widget.setLabel('left', 'PPS')
        self._pps_widget.setLabel('bottom', 'Time (seconds ago)')

        pps_plot = self._pps_widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        assert pps_plot is not None  # noqa: S101
        pps_left = pps_plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        pps_left.setTextPen(pg.mkPen('lime'))  # pyright: ignore[reportUnknownMemberType]

        self._pps_curve = self._pps_widget.plot(pen=pg.mkPen('lime', width=2))
        self._pps_curve.setFillLevel(0)
        self._pps_curve.setBrush(pg.mkBrush(0, 255, 0, 60))

        self._pps_threshold_line = pg.InfiniteLine(
            angle=0,
            pos=initial_pps_threshold,
            pen=pg.mkPen('#66bb6a', width=1.5, style=Qt.PenStyle.DashLine),
        )
        self._pps_widget.addItem(self._pps_threshold_line)

        self._pps_avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen('#388e3c', width=1, style=Qt.PenStyle.DotLine),
        )
        self._pps_widget.addItem(self._pps_avg_line)

        layout.addWidget(self._pps_widget)

        # ── BPS graph (bottom) — cyan/teal tones ────────────────────────
        self._bps_widget = pg.PlotWidget(
            axisItems={'bottom': _PositiveTicksAxis(orientation='bottom')},
            viewBox=_DragCursorViewBox(),
        )
        self._bps_widget.setMouseEnabled(x=True, y=True)
        self._bps_widget.setBackground('black')
        self._bps_widget.showGrid(x=True, y=True)
        self._bps_widget.setYRange(0, 50)
        self._bps_widget.setLimits(yMin=0, xMax=0, xMin=-self._max_history)
        self._bps_widget.setLabel('left', 'KB/s')
        self._bps_widget.setLabel('bottom', 'Time (seconds ago)')

        bps_plot = self._bps_widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        assert bps_plot is not None  # noqa: S101
        bps_left = bps_plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        bps_left.setTextPen(pg.mkPen('#00bcd4'))  # pyright: ignore[reportUnknownMemberType]

        self._bps_curve = self._bps_widget.plot(pen=pg.mkPen('#00bcd4', width=2))
        self._bps_curve.setFillLevel(0)
        self._bps_curve.setBrush(pg.mkBrush(0, 188, 212, 60))

        self._bps_threshold_line = pg.InfiniteLine(
            angle=0,
            pos=initial_bps_threshold / self._BYTES_TO_KBS,
            pen=pg.mkPen('#4dd0e1', width=1.5, style=Qt.PenStyle.DashLine),
        )
        self._bps_widget.addItem(self._bps_threshold_line)

        self._bps_avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen('#0097a7', width=1, style=Qt.PenStyle.DotLine),
        )
        self._bps_widget.addItem(self._bps_avg_line)

        layout.addWidget(self._bps_widget)

        # Always-on-top toggle (local to this window)
        always_on_top_checkbox = QCheckBox('Always on Top')
        always_on_top_checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        always_on_top_checkbox.setChecked(always_on_top)
        always_on_top_checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(always_on_top_checkbox)

        # History buffers — pre-allocated numpy arrays avoid per-tick list copies.
        self._pps_buf = np.zeros(self._max_history, dtype=np.float64)
        self._bps_buf = np.zeros(self._max_history, dtype=np.float64)
        self._buf_len = VISIBLE_WINDOW
        self._pps_sum: float = 0.0
        self._bps_sum: float = 0.0
        self._x_cache_len = VISIBLE_WINDOW
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)

    # Public API —————————————————————————————————————————————————————————————

    def update_rates(self, *, pps: int, bps: int) -> None:
        """Append new PPS and BPS samples and refresh both graphs."""
        kbps = bps / self._BYTES_TO_KBS
        n = self._buf_len

        if n < self._max_history:
            # Growth phase: append to end, rebuild x-cache only when length changes
            self._pps_buf[n] = pps
            self._bps_buf[n] = kbps
            self._pps_sum += pps
            self._bps_sum += kbps
            n += 1
            self._buf_len = n
            if n != self._x_cache_len:
                self._x_cache = np.arange(-n + 1, 1, dtype=np.float64)
                self._x_cache_len = n
        else:
            # Steady state: shift left (C-level memcpy), append at end
            self._pps_sum += pps - self._pps_buf[0]
            self._bps_sum += kbps - self._bps_buf[0]
            self._pps_buf[:-1] = self._pps_buf[1:]
            self._pps_buf[-1] = pps
            self._bps_buf[:-1] = self._bps_buf[1:]
            self._bps_buf[-1] = kbps

        pps_data = self._pps_buf[:n]
        bps_data = self._bps_buf[:n]

        self._pps_curve.setData(self._x_cache, pps_data)
        if self._is_at_live_edge(self._pps_widget):
            self._pps_widget.setXRange(-VISIBLE_WINDOW, 0)
        if n:
            self._pps_avg_line.setPos(self._pps_sum / n)

        self._bps_curve.setData(self._x_cache, bps_data)
        if self._is_at_live_edge(self._bps_widget):
            self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)
        if n:
            self._bps_avg_line.setPos(self._bps_sum / n)

    def set_pps_threshold(self, threshold: int) -> None:
        """Update the PPS threshold marker line."""
        self._pps_threshold_line.setPos(threshold)

    def set_bps_threshold(self, threshold: int) -> None:
        """Update the BPS threshold marker line (accepts bytes/s, converts to KB/s)."""
        self._bps_threshold_line.setPos(threshold / self._BYTES_TO_KBS)

    def load_history(self, *, pps_history: list[int], bps_history: list[int]) -> None:
        """Backfill both graphs with previously recorded rate samples."""
        # Pad to at least VISIBLE_WINDOW, keep up to max_history
        pps_trimmed = pps_history[-self._max_history:]
        bps_trimmed = bps_history[-self._max_history:]
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

    # Internal ———————————————————————————————————————————————————————————————

    @staticmethod
    def _is_at_live_edge(widget: pg.PlotWidget) -> bool:  # pyright: ignore[reportMissingTypeStubs]
        """Return True if the widget's x-axis view includes the live (rightmost) edge."""
        x_range: list[float] = widget.viewRange()[0]  # pyright: ignore[reportUnknownMemberType]
        return x_range[1] >= -2  # noqa: PLR2004

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        """Toggle the window-stays-on-top flag without changing the saved setting."""
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()


class _PositiveTicksAxis(pg.AxisItem):  # type: ignore[misc]  # pylint: disable=abstract-method
    """Axis that displays tick labels as positive integers."""

    def tickStrings(self, values: list[float], _scale: float, _spacing: float) -> list[str]:  # ty: ignore[invalid-method-override]  # noqa: N802
        """Override to show absolute tick values."""
        return [str(abs(int(v))) for v in values]


class _DragCursorViewBox(pg.ViewBox):  # type: ignore[misc]  # pylint: disable=abstract-method
    """ViewBox that changes cursor shape during vertical drag."""

    def mouseDragEvent(self, ev: Any, axis: int | None = None) -> None:  # noqa: ANN401, N802
        """Override to show a vertical resize cursor while dragging."""
        if hasattr(ev, 'isStart') and ev.isStart():
            self.setCursor(Qt.CursorShape.SizeVerCursor)
        elif hasattr(ev, 'isFinish') and ev.isFinish():
            self.setCursor(Qt.CursorShape.ArrowCursor)
        super().mouseDragEvent(ev, axis=axis)
