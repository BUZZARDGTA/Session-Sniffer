"""Live packet latency graph window for the current capture session."""

import numpy as np
import pyqtgraph as pg  # pyright: ignore[reportMissingTypeStubs]
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QCheckBox, QVBoxLayout, QWidget

from session_sniffer.guis.player_rate_graph import DragCursorViewBox, PositiveTicksAxis

VISIBLE_WINDOW = 60
_FLOOR_MS = 1.0


class PacketsLatencyGraphWindow(QWidget):
    """A standalone window displaying live per-packet latency over time."""

    def __init__(self, *, max_history: int, always_on_top: bool = True) -> None:
        """Initialize the packet latency graph window."""
        super().__init__()

        self._max_history = max_history

        self.setWindowTitle('Packets Latency Graph')
        self.resize(700, 350)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Latency graph — orange tones ─────────────────────────────────
        self._widget = pg.PlotWidget(
            axisItems={'bottom': PositiveTicksAxis(orientation='bottom')},
            viewBox=DragCursorViewBox(),
        )
        self._widget.setMouseEnabled(x=True, y=True)
        self._widget.setBackground('black')
        self._widget.showGrid(x=True, y=True)
        self._widget.setLimits(yMin=0, xMax=0, xMin=-self._max_history)
        self._widget.setLabel('left', 'Latency (ms)')
        self._widget.setLabel('bottom', 'Time (seconds ago)')

        plot = self._widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        if plot is None:
            msg = 'Failed to get plot item'
            raise RuntimeError(msg)
        left = plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]
        left.setTextPen(pg.mkPen('#ff9800'))  # pyright: ignore[reportUnknownMemberType]

        self._curve = self._widget.plot(pen=pg.mkPen('#ff9800', width=2))
        self._curve.setFillLevel(0)
        self._curve.setBrush(pg.mkBrush(255, 152, 0, 60))

        self._avg_line = pg.InfiniteLine(
            angle=0,
            pen=pg.mkPen('#e65100', width=1, style=Qt.PenStyle.DotLine),
        )
        self._widget.addItem(self._avg_line)

        layout.addWidget(self._widget)

        always_on_top_checkbox = QCheckBox('Always on Top')
        always_on_top_checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        always_on_top_checkbox.setChecked(always_on_top)
        always_on_top_checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(always_on_top_checkbox)

        # History buffers
        self._buf = np.zeros(self._max_history, dtype=np.float64)
        self._buf_len = VISIBLE_WINDOW
        self._buf_sum: float = 0.0
        self._x_cache_len = VISIBLE_WINDOW
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)

    # Public API —————————————————————————————————————————————————————————————

    def update_latency(self, latency_ms: float) -> None:
        """Append a new latency sample and refresh the graph."""
        n = self._buf_len

        if n < self._max_history:
            self._buf[n] = latency_ms
            self._buf_sum += latency_ms
            n += 1
            self._buf_len = n
            if n != self._x_cache_len:
                self._x_cache = np.arange(-n + 1, 1, dtype=np.float64)
                self._x_cache_len = n
        else:
            self._buf_sum += latency_ms - self._buf[0]
            self._buf[:-1] = self._buf[1:]
            self._buf[-1] = latency_ms

        data = self._buf[:n]
        self._curve.setData(self._x_cache, data)
        if self._is_at_live_edge():
            self._widget.setXRange(-VISIBLE_WINDOW, 0)
        visible_max = float(np.max(data[-VISIBLE_WINDOW:]))
        self._widget.setYRange(0, max(visible_max * 1.2, _FLOOR_MS))
        if n:
            self._avg_line.setPos(self._buf_sum / n)

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
        self._widget.setYRange(0, _FLOOR_MS)
        self._avg_line.setPos(0)

    # Internal ————————————————————————————————————————————————————————————————

    def _is_at_live_edge(self) -> bool:
        x_range: list[float] = self._widget.viewRange()[0]  # pyright: ignore[reportUnknownMemberType]
        return x_range[1] >= -2  # noqa: PLR2004

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
