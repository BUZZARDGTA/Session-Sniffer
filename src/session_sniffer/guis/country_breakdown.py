"""Country breakdown statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

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

        self._table = QTableWidget(0, 2)
        self._table.setHorizontalHeaderLabels(['Country', 'Players'])
        setup_stat_table(self._table, layout, sorting=False)
        h_header = self._table.horizontalHeader()
        if h_header is None:
            msg = 'Failed to get horizontal header'
            raise RuntimeError(msg)
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        h_header.setStretchLastSection(False)
        self._table.setColumnWidth(1, 80)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current country data."""
        all_players = PlayersRegistry.get_all_players()
        counts: dict[str, int] = {}
        for player in all_players:
            if (
                (
                    country := player.iplookup.ipapi.country
                    if (
                        player.iplookup.geolite2.country == '...'
                        and player.iplookup.ipapi.country != '...'
                    )
                    else player.iplookup.geolite2.country
                )
                and country != '...'
            ):
                counts[country] = counts.get(country, 0) + 1

        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for country, count in sorted_counts:
            row = self._table.rowCount()
            self._table.insertRow(row)
            country_item = QTableWidgetItem(country)
            count_item = NumericTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, country_item)
            self._table.setItem(row, 1, count_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(1, Qt.SortOrder.DescendingOrder)
