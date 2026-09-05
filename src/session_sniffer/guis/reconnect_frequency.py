"""Reconnect frequency statistics window."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

if TYPE_CHECKING:
    from PySide6.QtGui import QResizeEvent, QShowEvent

from session_sniffer.guis.table_context_menu import TableContextMenuManager, skip_if_menu_open
from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table
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
        setup_stat_table(self._table, layout)
        self._reset_column_sizes()

        self._context_menu_manager = TableContextMenuManager(self._table, self, on_reset_column_sizes=self._reset_column_sizes)

        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Adjust column widths when the reconnect frequency window is shown."""
        super().showEvent(event)
        self._reset_column_sizes()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adjust column widths when the reconnect frequency window is resized."""
        super().resizeEvent(event)
        self._reset_column_sizes()

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        self._table.setColumnWidth(0, 100)
        self._table.setColumnWidth(1, 130)
        available_width = self._table.viewport().width() if self._table.viewport() else self._table.width()
        remaining_width = max(150, available_width - 230)
        self._table.setColumnWidth(2, remaining_width)

    @skip_if_menu_open
    def refresh(self) -> None:
        """Rebuild the table with current rejoin data."""
        all_players = PlayersRegistry.get_all_players()
        entries = [(player.rejoins, player.ip, ', '.join(player.usernames) if player.usernames else '—') for player in all_players if player.rejoins > 0]
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
