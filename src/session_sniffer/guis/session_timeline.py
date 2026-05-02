"""Session timeline (Gantt-style) window using pyqtgraph."""

from datetime import datetime

import pyqtgraph as pg  # pyright: ignore[reportMissingTypeStubs]

from session_sniffer.guis.utils import ToggleAlwaysOnTopMixin
from session_sniffer.player.registry import PlayersRegistry

_CONNECTED_COLOR = (80, 200, 80, 200)
_DISCONNECTED_COLOR = (220, 80, 60, 200)
_MIN_BAR_WIDTH = 0.5


class SessionTimelineWindow(ToggleAlwaysOnTopMixin):
    """A standalone Gantt-style chart showing when each player was present in the session."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the session timeline window."""
        super().__init__()

        self.setWindowTitle('Session Timeline')
        self.resize(860, 480)
        layout = self._setup_window_layout(always_on_top=always_on_top, margins=(0, 0, 0, 4), spacing=0)

        self._widget = pg.PlotWidget()
        self._widget.setBackground('black')
        self._widget.showGrid(x=True, y=False)
        self._widget.setLabel('bottom', 'Time (seconds into session)')
        self._widget.setLabel('left', 'Player')
        self._widget.setMouseEnabled(x=True, y=False)

        plot = self._widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        if plot is None:
            msg = 'Failed to get plot item'
            raise RuntimeError(msg)
        self._y_axis = plot.getAxis('left')  # pyright: ignore[reportUnknownVariableType]

        layout.addWidget(self._widget)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the Gantt chart with current player data."""
        all_players = PlayersRegistry.get_default_sorted_players()
        if not all_players:
            self._widget.clear()
            self._y_axis.setTicks([[]])  # pyright: ignore[reportUnknownMemberType]
            return

        session_start = min(p.datetime.first_seen for p in all_players)
        now = datetime.now(tz=session_start.tzinfo)

        connected = sorted(
            (p for p in all_players if not p.left_event.is_set()),
            key=lambda p: p.datetime.first_seen,
        )
        disconnected = sorted(
            (p for p in all_players if p.left_event.is_set()),
            key=lambda p: p.datetime.first_seen,
        )
        ordered = connected + disconnected
        n = len(ordered)

        conn_x: list[float] = []
        conn_y: list[float] = []
        conn_w: list[float] = []
        disc_x: list[float] = []
        disc_y: list[float] = []
        disc_w: list[float] = []
        tick_labels: list[tuple[int, str]] = []
        max_end: float = 60.0

        for i, player in enumerate(ordered):
            start_sec = max((player.datetime.first_seen - session_start).total_seconds(), 0.0)
            end_sec = (player.datetime.last_seen - session_start).total_seconds() if player.left_event.is_set() else (now - session_start).total_seconds()

            end_sec = max(end_sec, start_sec + _MIN_BAR_WIDTH)
            width = end_sec - start_sec
            cx = start_sec + width / 2.0

            if player.left_event.is_set():
                disc_x.append(cx)
                disc_y.append(float(i) - 0.35)
                disc_w.append(width)
            else:
                conn_x.append(cx)
                conn_y.append(float(i) - 0.35)
                conn_w.append(width)

            label = f'{player.ip} ({player.usernames[0]})' if player.usernames else player.ip
            tick_labels.append((i, label))
            max_end = max(max_end, end_sec)

        self._widget.clear()

        if conn_x:
            bars_c = pg.BarGraphItem(  # pyright: ignore[reportUnknownVariableType]
                x=conn_x,
                y=conn_y,
                height=[0.7] * len(conn_x),
                width=conn_w,
                brush=pg.mkBrush(*_CONNECTED_COLOR),
                pen=pg.mkPen(None),
            )
            self._widget.addItem(bars_c)

        if disc_x:
            bars_d = pg.BarGraphItem(  # pyright: ignore[reportUnknownVariableType]
                x=disc_x,
                y=disc_y,
                height=[0.7] * len(disc_x),
                width=disc_w,
                brush=pg.mkBrush(*_DISCONNECTED_COLOR),
                pen=pg.mkPen(None),
            )
            self._widget.addItem(bars_d)

        self._y_axis.setTicks([tick_labels])  # pyright: ignore[reportUnknownMemberType]
        self._widget.setYRange(-0.5, n - 0.5)
        self._widget.setXRange(0, max_end * 1.05)
