"""Session duration statistics window."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from session_sniffer.constants.tables import SESSION_DURATION_TABLE_MIN_COLUMN_WIDTHS
from session_sniffer.guis.table_context_menu import StatTableWindowMixin, skip_if_menu_open
from session_sniffer.guis.utils import (
    NumericTableWidgetItem,
    format_duration,
    setup_stat_table,
)
from session_sniffer.player.registry import PlayersRegistry


class SessionDurationWindow(StatTableWindowMixin):
    """A standalone window listing disconnected players sorted by session duration."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the session duration window."""
        super().__init__()

        self.setWindowTitle('Session Duration')
        self.resize(520, 420)
        layout = self.setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Duration', 'IP', 'Usernames'])
        setup_stat_table(self._table, layout)
        self.setup_stat_table_controls(layout, always_on_top=always_on_top, min_column_widths=SESSION_DURATION_TABLE_MIN_COLUMN_WIDTHS)
        self._reset_column_sizes()

    @skip_if_menu_open
    def refresh(self) -> None:
        """Rebuild the table with current session duration data."""
        disconnected = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        entries = [
            (player.datetime.session_time.total_seconds(), player.ip, ', '.join(player.usernames) if player.usernames else '—')
            for player in disconnected
            if player.datetime.session_time is not None
        ]
        entries.sort(key=lambda entry: entry[0], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for duration_seconds, ip, usernames in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            duration_item = NumericTableWidgetItem(format_duration(duration_seconds))
            duration_item.setData(Qt.ItemDataRole.UserRole, duration_seconds)
            duration_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ip_item = QTableWidgetItem(ip)
            ip_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, duration_item)
            self._table.setItem(row, 1, ip_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        if self._custom_column_widths is None:
            self._setup_column_resizing()
