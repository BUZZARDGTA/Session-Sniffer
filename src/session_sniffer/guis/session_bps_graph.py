"""Live BPS graph window for the current capture session."""

from session_sniffer.guis.player_rate_graph import SingleRateGraphBase

_FLOOR_KBS = 1.0
_BYTES_TO_KBS = 1024


class SessionBpsGraphWindow(SingleRateGraphBase):
    """A standalone window displaying live bandwidth (KB/s) over time for the whole session."""

    WINDOW_TITLE = 'Session BPS Graph'
    LEFT_LABEL = 'KB/s'
    AXIS_PEN = '#00bcd4'
    CURVE_PEN = '#00bcd4'
    CURVE_BRUSH = (0, 188, 212, 60)
    AVG_PEN = '#0097a7'
    Y_FLOOR = _FLOOR_KBS

    def _transform_sample(self, sample: float) -> float:
        """Convert bytes per second into KB/s for display."""
        return float(sample) / _BYTES_TO_KBS

    # Public API —————————————————————————————————————————————————————————————

    def update_bps(self, bps: int) -> None:
        """Append a new BPS sample (bytes/s) and refresh the graph."""
        self.update_graph(bps)
