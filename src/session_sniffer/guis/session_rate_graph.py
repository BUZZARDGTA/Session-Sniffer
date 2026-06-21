"""Live PPS + BPS split graph window for the entire session."""

from typing import override

import numpy as np

from session_sniffer.guis.player_rate_graph import VISIBLE_WINDOW, DualRateGraphBase


class SessionRateGraphWindow(DualRateGraphBase):
    """A standalone window with separate PPS and BPS graphs for the whole session."""

    def __init__(self, *, max_history: int, always_on_top: bool = True) -> None:
        """Initialize the session-wide split rate graph window."""
        super().__init__()

        self._max_history = max_history

        self.setWindowTitle('Session Rate Graph')
        self._finish_graph_init(always_on_top=always_on_top)

    # Auto-scaling hooks — override to track visible maximum ————————————————

    @override
    def _on_pps_rendered(self, pps_data: np.ndarray) -> None:
        pps_visible_max = float(np.max(pps_data[-VISIBLE_WINDOW:]))
        self._pps_widget.setYRange(0, max(pps_visible_max * 1.2, 10))

    @override
    def _on_bps_rendered(self, bps_data: np.ndarray) -> None:
        bps_visible_max = float(np.max(bps_data[-VISIBLE_WINDOW:]))
        self._bps_widget.setYRange(0, max(bps_visible_max * 1.2, 1))

    # Public API —————————————————————————————————————————————————————————————

    def reset(self) -> None:
        """Clear all history buffers and reset both graphs to zero."""
        self._pps_buffer[:] = 0.0
        self._bps_buffer[:] = 0.0
        self._buffer_len = VISIBLE_WINDOW
        self._pps_running_sum = 0.0
        self._bps_running_sum = 0.0
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
        self._dual_graph_idle = False
