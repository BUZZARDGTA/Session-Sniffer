"""Live PPS + BPS split graph window for the entire session."""

import numpy as np
import pyqtgraph as pg  # pyright: ignore[reportMissingTypeStubs]
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QCheckBox, QVBoxLayout, QWidget

from session_sniffer.guis.player_rate_graph import DragCursorViewBox, PositiveTicksAxis

VISIBLE_WINDOW = 60


class SessionRateGraphWindow(QWidget):
    """A standalone window with separate PPS and BPS graphs for the whole session."""

    _BYTES_TO_KBS = 1024

    def __init__(self, *, max_history: int, always_on_top: bool = True) -> None:
        """Initialize the session-wide split rate graph window."""
        super().__init__()

        self._max_history = max_history

        self.setWindowTitle('Session Rate Graph')
        self.resize(700, 500)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── PPS graph (top) — lime green tones ──────────────────────────
        self._pps_widget = pg.PlotWidget(
            axisItems={'bottom': PositiveTicksAxis(orientation='bottom')},
            viewBox=DragCursorViewBox(),
        )
        self._pps_widget.setMouseEnabled(x=True, y=True)
        self._pps_widget.setBackground('black')
        self._pps_widget.showGrid(x=True, y=True)
        self._pps_widget.setLimits(yMin=0, xMax=0, xMin=-self._max_history)
        self._pps_widget.setLabel('left', 'PPS')
        self._pps_widget.setLabel('bottom', 'Time (seconds ago)')

        pps_plot = self._pps_widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        if pps_plot is None:
            msg = 'Failed to get PPS plot item'
            raise RuntimeError(msg)
        pps_left = pps_plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        pps_left.setTextPen(pg.mkPen('lime'))  # pyright: ignore[reportUnknownMemberType]

        self._pps_curve = self._pps_widget.plot(pen=pg.mkPen('lime', width=2))
        self._pps_curve.setFillLevel(0)
        self._pps_curve.setBrush(pg.mkBrush(0, 255, 0, 60))

        self._pps_avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen('#388e3c', width=1, style=Qt.PenStyle.DotLine),
        )
        self._pps_widget.addItem(self._pps_avg_line)

        layout.addWidget(self._pps_widget)

        # ── BPS graph (bottom) — cyan/teal tones ────────────────────────
        self._bps_widget = pg.PlotWidget(
            axisItems={'bottom': PositiveTicksAxis(orientation='bottom')},
            viewBox=DragCursorViewBox(),
        )
        self._bps_widget.setMouseEnabled(x=True, y=True)
        self._bps_widget.setBackground('black')
        self._bps_widget.showGrid(x=True, y=True)
        self._bps_widget.setLimits(yMin=0, xMax=0, xMin=-self._max_history)
        self._bps_widget.setLabel('left', 'KB/s')
        self._bps_widget.setLabel('bottom', 'Time (seconds ago)')

        bps_plot = self._bps_widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        if bps_plot is None:
            msg = 'Failed to get BPS plot item'
            raise RuntimeError(msg)
        bps_left = bps_plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        bps_left.setTextPen(pg.mkPen('#00bcd4'))  # pyright: ignore[reportUnknownMemberType]

        self._bps_curve = self._bps_widget.plot(pen=pg.mkPen('#00bcd4', width=2))
        self._bps_curve.setFillLevel(0)
        self._bps_curve.setBrush(pg.mkBrush(0, 188, 212, 60))

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
        pps_visible_max = float(np.max(pps_data[-VISIBLE_WINDOW:]))
        self._pps_widget.setYRange(0, max(pps_visible_max * 1.2, 10))
        if n:
            self._pps_avg_line.setPos(self._pps_sum / n)

        self._bps_curve.setData(self._x_cache, bps_data)
        if self._is_at_live_edge(self._bps_widget):
            self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)
        bps_visible_max = float(np.max(bps_data[-VISIBLE_WINDOW:]))
        self._bps_widget.setYRange(0, max(bps_visible_max * 1.2, 1))
        if n:
            self._bps_avg_line.setPos(self._bps_sum / n)

    def reset(self) -> None:
        """Clear all history buffers and reset both graphs to zero."""
        self._pps_buf[:] = 0.0
        self._bps_buf[:] = 0.0
        self._buf_len = VISIBLE_WINDOW
        self._pps_sum = 0.0
        self._bps_sum = 0.0
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)
        self._x_cache_len = VISIBLE_WINDOW

        zeros = np.zeros(VISIBLE_WINDOW, dtype=np.float64)
        self._pps_curve.setData(self._x_cache, zeros)
        self._pps_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._pps_widget.setYRange(0, 10)
        self._pps_avg_line.setPos(0)

        self._bps_curve.setData(self._x_cache, zeros)
        self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._bps_widget.setYRange(0, 1)
        self._bps_avg_line.setPos(0)

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
