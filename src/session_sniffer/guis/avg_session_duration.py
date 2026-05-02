"""Average session duration statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry


def _format_duration(total_seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    secs = int(total_seconds)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f'{h}h {m}m {s}s'
    if m:
        return f'{m}m {s}s'
    return f'{s}s'


class AvgSessionDurationWindow(ToggleAlwaysOnTopMixin):
    """A standalone window listing disconnected players sorted by session duration."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the average session duration window."""
        super().__init__()

        self.setWindowTitle('Session Duration')
        self.resize(520, 420)
        layout = self._setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['IP', 'Duration', 'Usernames'])
        setup_stat_table(self._table, layout)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current session duration data."""
        disconnected = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        entries = [
            (p.ip, p.datetime.session_time.total_seconds(), ', '.join(p.usernames) if p.usernames else '\u2014')
            for p in disconnected
            if p.datetime.session_time is not None
        ]
        entries.sort(key=lambda e: e[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for ip, duration_secs, usernames in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            ip_item = QTableWidgetItem(ip)
            duration_item = NumericTableWidgetItem(_format_duration(duration_secs))
            duration_item.setData(Qt.ItemDataRole.UserRole, duration_secs)
            duration_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, ip_item)
            self._table.setItem(row, 1, duration_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)
