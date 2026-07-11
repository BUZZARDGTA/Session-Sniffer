"""Live PPS + BPS split graph window for the entire session."""

from typing import override

from session_sniffer.guis.player_rate_graph import VISIBLE_WINDOW, DualRateGraphBase


class SessionRateGraphWindow(DualRateGraphBase):
    """A standalone window with separate PPS and BPS graphs for the whole session."""

    def __init__(self) -> None:
        """Initialize the session-wide split rate graph window."""
        super().__init__()

        self.setWindowTitle('Session Rate Graph')
        self._finish_graph_init()

    # Auto-scaling hooks — override to track visible maximum ————————————————

    @override
    def _on_pps_rendered(self, pps_data: list[float]) -> None:
        pps_visible_max = max(pps_data[-VISIBLE_WINDOW:]) if pps_data else 0.0
        self._pps_widget.set_y_range(0, max(pps_visible_max * 1.2, 10.0))

    @override
    def _on_bps_rendered(self, bps_data: list[float]) -> None:
        bps_visible_max = max(bps_data[-VISIBLE_WINDOW:]) if bps_data else 0.0
        self._bps_widget.set_y_range(0, max(bps_visible_max * 1.2, 1.0))

    # Public API —————————————————————————————————————————————————————————————

    def reset(self) -> None:
        """Clear all history buffers and reset both graphs to zero."""
        self._setup_history_buffers()

        zeros = [0.0] * VISIBLE_WINDOW

        self._pps_widget.set_data(zeros)
        self._pps_widget.set_y_range(0, 10.0)
        self._pps_widget.set_average(0.0)

        self._bps_widget.set_data(zeros)
        self._bps_widget.set_y_range(0, 1.0)
        self._bps_widget.set_average(0.0)
