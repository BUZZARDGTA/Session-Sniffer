"""Reconnect frequency statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry


class ReconnectFrequencyWindow(ToggleAlwaysOnTopMixin):
    """A standalone window listing players sorted by reconnect (rejoin) count."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the reconnect frequency window."""
        super().__init__()

        self.setWindowTitle('Reconnect Frequency')
        self.resize(520, 420)
        layout = self._setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['IP', 'Rejoins', 'Usernames'])
        setup_stat_table(self._table, layout)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current rejoin data."""
        all_players = PlayersRegistry.get_default_sorted_players()
        entries = [
            (p.ip, p.rejoins, ', '.join(p.usernames) if p.usernames else '\u2014')
            for p in all_players
            if p.rejoins > 0
        ]
        entries.sort(key=lambda e: e[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for ip, rejoins, usernames in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            ip_item = QTableWidgetItem(ip)
            rejoins_item = NumericTableWidgetItem(str(rejoins))
            rejoins_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, ip_item)
            self._table.setItem(row, 1, rejoins_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)
