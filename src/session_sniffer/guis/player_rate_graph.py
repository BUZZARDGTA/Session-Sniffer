"""Live PPS + BPS split graph window for an individual player."""

from collections import deque
from typing import TYPE_CHECKING, override

from PyQt6.QtGui import QColor

from session_sniffer.guis.rate_graph_widget import RateGraphTheme, RateGraphWidget
from session_sniffer.guis.utils import ToggleAlwaysOnTopMixin, format_player_display

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QVBoxLayout

VISIBLE_WINDOW = 60
DEFAULT_MAX_HISTORY = 3600


class SingleRateGraphBase(ToggleAlwaysOnTopMixin):
    """Base class for single-series sliding-window rate graph windows."""

    WINDOW_TITLE: str
    LEFT_LABEL: str
    AXIS_PEN: str
    CURVE_PEN: str
    CURVE_BRUSH: tuple[int, int, int, int]
    AVG_PEN: str
    Y_FLOOR: float
    _graph_idle: bool
    _buffer: deque[float]

    def __init__(self, *, max_history: int, always_on_top: bool = True) -> None:
        """Initialize the shared single-series graph window."""
        super().__init__()

        self._max_history = max_history
        self._buffer_running_sum = 0.0

        self.setWindowTitle(self.WINDOW_TITLE)
        self.resize(700, 350)
        layout = self.setup_window_layout(always_on_top=always_on_top, margins=(0, 0, 0, 0), spacing=0)

        self._widget = RateGraphWidget(
            left_label=self.LEFT_LABEL,
            theme=RateGraphTheme(
                line_color=self.CURVE_PEN,
                fill_color=QColor(*self.CURVE_BRUSH),
                avg_color=self.AVG_PEN,
            ),
            visible_window=VISIBLE_WINDOW,
        )
        self._widget.set_y_range(0, self.Y_FLOOR)
        layout.addWidget(self._widget)

        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)
        self._setup_single_history_buffers()

    def _setup_single_history_buffers(self) -> None:
        """Initialise pre-allocated sliding-window buffers."""
        self._buffer: deque[float] = deque(maxlen=self._max_history)
        self._buffer_running_sum = 0.0
        self._graph_idle: bool = False
        for _ in range(VISIBLE_WINDOW):
            self._buffer.append(0.0)

    def _transform_sample(self, sample: float) -> float:
        """Convert an incoming sample into the value stored in the buffer."""
        return float(sample)

    def update_graph(self, sample: float) -> None:
        """Append a new sample and refresh the graph."""
        value = self._transform_sample(sample)

        if len(self._buffer) == self._max_history:
            self._buffer_running_sum -= self._buffer[0]

        self._buffer.append(value)
        self._buffer_running_sum += value

        # Skip pyqtgraph draw calls when the graph is already showing a stable
        # flat zero baseline and the new sample is also zero.
        if not value and self._graph_idle:
            return

        visible_data = list(self._buffer)[-VISIBLE_WINDOW:]
        visible_max = max(visible_data) if visible_data else 0.0

        self._widget.set_data(list(self._buffer))
        self._widget.set_y_range(0, max(visible_max * 1.2, self.Y_FLOOR))
        self._widget.set_average(self._buffer_running_sum / len(self._buffer) if self._buffer else 0)

        # Mark graph as idle once the visible window is fully zeroed out.
        self._graph_idle = not value and not visible_max

    def reset(self) -> None:
        """Clear all history and reset the graph to zero."""
        self._setup_single_history_buffers()
        self._widget.set_data(list(self._buffer))
        self._widget.set_y_range(0, self.Y_FLOOR)
        self._widget.set_average(0)


class DualRateGraphBase(ToggleAlwaysOnTopMixin):
    """Base class for dual PPS+BPS graph windows."""

    _max_history: int
    _dual_graph_idle: bool
    _BYTES_TO_KBS: int = 1024
    _pps_widget: RateGraphWidget
    _bps_widget: RateGraphWidget
    _pps_buffer: deque[float]
    _bps_buffer: deque[float]
    _pps_running_sum: float
    _bps_running_sum: float

    def _setup_dual_graph_widgets(self, layout: QVBoxLayout) -> None:
        """Create PPS and BPS PlotWidgets and add them to *layout*."""
        # ── PPS graph (top) — lime green tones ──────────────────────────
        self._pps_widget = RateGraphWidget(
            left_label='PPS',
            theme=RateGraphTheme(
                line_color='lime',
                fill_color=QColor(0, 255, 0, 60),
                avg_color='#388e3c',
            ),
            visible_window=VISIBLE_WINDOW,
        )
        self._configure_pps_widget()
        layout.addWidget(self._pps_widget)

        # ── BPS graph (bottom) — cyan/teal tones ────────────────────────
        self._bps_widget = RateGraphWidget(
            left_label='KB/s',
            theme=RateGraphTheme(
                line_color='#00bcd4',
                fill_color=QColor(0, 188, 212, 60),
                avg_color='#0097a7',
            ),
            visible_window=VISIBLE_WINDOW,
        )
        self._configure_bps_widget()
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
        """Initialise pre-allocated sliding-window buffers."""
        self._pps_buffer: deque[float] = deque(maxlen=self._max_history)
        self._bps_buffer: deque[float] = deque(maxlen=self._max_history)

        for _ in range(VISIBLE_WINDOW):
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        self._pps_running_sum = 0.0
        self._bps_running_sum = 0.0
        self._dual_graph_idle: bool = False

    def update_rates(self, *, pps: int, bps: int) -> None:
        """Append new PPS and BPS samples and refresh both graphs."""
        kbps = bps / self._BYTES_TO_KBS

        if len(self._pps_buffer) == self._max_history:
            self._pps_running_sum -= self._pps_buffer[0]
            self._bps_running_sum -= self._bps_buffer[0]

        self._pps_buffer.append(float(pps))
        self._bps_buffer.append(float(kbps))
        self._pps_running_sum += pps
        self._bps_running_sum += kbps

        if not pps and not bps and self._dual_graph_idle:
            return

        pps_list = list(self._pps_buffer)
        bps_list = list(self._bps_buffer)

        self._pps_widget.set_data(pps_list)
        self._on_pps_rendered(pps_list)
        self._pps_widget.set_average(self._pps_running_sum / len(self._pps_buffer))

        self._bps_widget.set_data(bps_list)
        self._on_bps_rendered(bps_list)
        self._bps_widget.set_average(self._bps_running_sum / len(self._bps_buffer))

        if not pps and not bps:
            _pps_visible_max = max(pps_list[-VISIBLE_WINDOW:]) if pps_list else 0.0
            _bps_visible_max = max(bps_list[-VISIBLE_WINDOW:]) if bps_list else 0.0
            self._dual_graph_idle = not _pps_visible_max and not _bps_visible_max
        else:
            self._dual_graph_idle = False

    def _on_pps_rendered(self, pps_data: list[float]) -> None:
        """Hook called after PPS graph is updated. Override to add auto-scaling."""

    def _on_bps_rendered(self, bps_data: list[float]) -> None:
        """Hook called after BPS graph is updated. Override to add auto-scaling."""


class PlayerRateGraphWindow(DualRateGraphBase):
    """A standalone window with separate PPS and BPS graphs stacked vertically."""

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

    @override
    def _configure_pps_widget(self) -> None:
        self._pps_widget.set_y_range(0, 100)
        self._pps_widget.threshold_color = QColor('#66bb6a')
        self.set_pps_threshold(self._initial_pps_threshold)

    @override
    def _configure_bps_widget(self) -> None:
        self._bps_widget.set_y_range(0, 50)
        self._bps_widget.threshold_color = QColor('#4dd0e1')
        self.set_bps_threshold(self._initial_bps_threshold)

    def update_usernames(self, usernames: list[str]) -> None:
        """Update the window title to reflect current usernames."""
        self.setWindowTitle(f'Rate Graph — {format_player_display(self.ip, usernames)}')

    def set_pps_threshold(self, threshold: int) -> None:
        """Update the PPS threshold marker line."""
        self._pps_widget.set_threshold(float(threshold))

    def set_bps_threshold(self, threshold: int) -> None:
        """Update the BPS threshold marker line (accepts bytes/s, converts to KB/s)."""
        self._bps_widget.set_threshold(threshold / self._BYTES_TO_KBS)

    def load_history(self, *, pps_history: list[int], bps_history: list[int]) -> None:
        """Backfill both graphs with previously recorded rate samples."""
        pps_trimmed = pps_history[-self._max_history :]
        bps_trimmed = bps_history[-self._max_history :]
        pad_len = max(0, VISIBLE_WINDOW - len(pps_trimmed))

        self._pps_buffer.clear()
        self._bps_buffer.clear()

        for _ in range(pad_len):
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        for p in pps_trimmed:
            self._pps_buffer.append(float(p))
        for b in bps_trimmed:
            self._bps_buffer.append(float(b) / self._BYTES_TO_KBS)

        self._pps_running_sum = sum(self._pps_buffer)
        self._bps_running_sum = sum(self._bps_buffer)

        pps_list = list(self._pps_buffer)
        bps_list = list(self._bps_buffer)

        self._pps_widget.set_data(pps_list)
        self._pps_widget.set_average(self._pps_running_sum / len(self._pps_buffer) if self._pps_buffer else 0)

        self._bps_widget.set_data(bps_list)
        self._bps_widget.set_average(self._bps_running_sum / len(self._bps_buffer) if self._bps_buffer else 0)
