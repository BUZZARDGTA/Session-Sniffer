"""Country breakdown statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry


class CountryBreakdownWindow(ToggleAlwaysOnTopMixin):
    """A standalone window showing all players grouped and ranked by country."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the country breakdown window."""
        super().__init__()

        self.setWindowTitle('Country Breakdown')
        self.resize(420, 420)
        layout = self._setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Rank', 'Country', 'Players'])
        setup_stat_table(self._table, layout, sorting=False)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current country data."""
        all_players = PlayersRegistry.get_default_sorted_players()
        counts: dict[str, int] = {}
        for player in all_players:
            country = player.iplookup.geolite2.country
            if country == '...':
                ipapi_country = player.iplookup.ipapi.country
                if ipapi_country != '...':
                    country = ipapi_country
            if country and country != '...':
                counts[country] = counts.get(country, 0) + 1

        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for rank, (country, count) in enumerate(sorted_counts, start=1):
            row = self._table.rowCount()
            self._table.insertRow(row)
            rank_item = NumericTableWidgetItem(str(rank))
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            country_item = QTableWidgetItem(country)
            count_item = NumericTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, rank_item)
            self._table.setItem(row, 1, country_item)
            self._table.setItem(row, 2, count_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(2, Qt.SortOrder.DescendingOrder)
