"""Country breakdown statistics window."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

if TYPE_CHECKING:
    from PySide6.QtGui import QResizeEvent, QShowEvent

from session_sniffer.guis.table_context_menu import TableContextMenuManager, skip_if_menu_open
from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry


class CountryBreakdownWindow(ToggleAlwaysOnTopMixin):
    """A standalone window showing all players grouped and ranked by country."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the country breakdown window."""
        super().__init__()

        self.setWindowTitle('Country Breakdown')
        self.resize(420, 420)
        layout = self.setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(['Country', 'Players'])
        setup_stat_table(self._table, layout, sorting=False)
        self._reset_column_sizes()

        self._context_menu_manager = TableContextMenuManager(self._table, self, on_reset_column_sizes=self._reset_column_sizes)

        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Adjust column widths when the country breakdown window is shown."""
        super().showEvent(event)
        self._reset_column_sizes()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adjust column widths when the country breakdown window is resized."""
        super().resizeEvent(event)
        self._reset_column_sizes()

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        available_width = self._table.viewport().width() if self._table.viewport() else self._table.width()
        players_width = 80
        country_width = max(120, available_width - players_width)
        self._table.setColumnWidth(0, country_width)
        self._table.setColumnWidth(1, players_width)

    @skip_if_menu_open
    def refresh(self) -> None:
        """Rebuild the table with current country data."""
        all_players = PlayersRegistry.get_all_players()
        counts: dict[str, int] = {}
        for player in all_players:
            if (
                country := player.iplookup.ipapi.country
                if (player.iplookup.geolite2.country == '...' and player.iplookup.ipapi.country != '...')
                else player.iplookup.geolite2.country
            ) and country != '...':
                counts[country] = counts.get(country, 0) + 1

        sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for country, count in sorted_counts:
            row = self._table.rowCount()
            self._table.insertRow(row)
            country_item = QTableWidgetItem(country)
            count_item = NumericTableWidgetItem(count)
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, country_item)
            self._table.setItem(row, 1, count_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(1, Qt.SortOrder.DescendingOrder)
