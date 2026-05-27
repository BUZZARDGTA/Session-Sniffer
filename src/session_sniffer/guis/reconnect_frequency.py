"""Reconnect frequency statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table_with_header
from session_sniffer.player.registry import PlayersRegistry


class ReconnectFrequencyWindow(ToggleAlwaysOnTopMixin):
    """A standalone window listing players sorted by reconnect (rejoin) count."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the reconnect frequency window."""
        super().__init__()

        self.setWindowTitle('Reconnect Frequency')
        self.resize(520, 420)
        layout = self.setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Rejoins', 'IP', 'Usernames'])
        h_header = setup_stat_table_with_header(self._table, layout)
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 100)
        self._table.setColumnWidth(1, 130)

        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current rejoin data."""
        all_players = PlayersRegistry.get_all_players()
        entries = [
            (p.rejoins, p.ip, ', '.join(p.usernames) if p.usernames else '—')
            for p in all_players
            if p.rejoins > 0
        ]
        entries.sort(key=lambda e: e[0], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for rejoins, ip, usernames in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            rejoins_item = NumericTableWidgetItem(rejoins)
            rejoins_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ip_item = QTableWidgetItem(ip)
            ip_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, rejoins_item)
            self._table.setItem(row, 1, ip_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
