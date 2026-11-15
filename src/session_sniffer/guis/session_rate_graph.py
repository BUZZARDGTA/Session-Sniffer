"""Live PPS + BPS split graph window for the entire session."""

from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.player_rate_graph import VISIBLE_WINDOW, DualRateGraphBase
from session_sniffer.i18n import tr


class SessionRateGraphWindow(DualRateGraphBase):
    """A standalone window with separate PPS and BPS graphs for the whole session."""

    def __init__(self) -> None:
        """Initialize the session-wide split rate graph window."""
        super().__init__()

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)
        self._finish_graph_init()

    def _apply_translations(self) -> None:
        """Apply translated text to the window title."""
        self.setWindowTitle(tr('Session Rate Graph'))

    # Public API —————————————————————————————————————————————————————————————

    def reset(self) -> None:
        """Clear all history buffers and reset both graphs to zero."""
        self._setup_history_buffers()

        zeros = [0.0] * VISIBLE_WINDOW

        self._pps_widget.set_data(zeros)
        self._pps_widget.set_y_range(0, self.PPS_Y_FLOOR)
        self._pps_widget.set_average(0.0)

        self._bps_widget.set_data(zeros)
        self._bps_widget.set_y_range(0, self.BPS_Y_FLOOR)
        self._bps_widget.set_average(0.0)
