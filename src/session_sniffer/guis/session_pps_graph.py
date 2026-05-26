"""Live PPS graph window for the current capture session."""

from session_sniffer.guis.player_rate_graph import SingleRateGraphBase

_FLOOR_PPS = 10


class SessionPpsGraphWindow(SingleRateGraphBase):
    """A standalone window displaying live PPS over time for the whole session."""

    WINDOW_TITLE = 'Session PPS Graph'
    LEFT_LABEL = 'PPS'
    AXIS_PEN = 'lime'
    CURVE_PEN = 'lime'
    CURVE_BRUSH = (0, 255, 0, 60)
    AVG_PEN = '#388e3c'
    Y_FLOOR = _FLOOR_PPS

    # Public API —————————————————————————————————————————————————————————————

    def update_pps(self, pps: int) -> None:
        """Append a new PPS sample and refresh the graph."""
        self.update_graph(pps)
