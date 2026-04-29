"""Country breakdown statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.player.registry import PlayersRegistry


class _NumericItem(QTableWidgetItem):  # pylint: disable=too-few-public-methods
    """QTableWidgetItem that sorts numerically."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)


class CountryBreakdownWindow(QWidget):
    """A standalone window showing all players grouped and ranked by country."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the country breakdown window."""
        super().__init__()

        self.setWindowTitle('Country Breakdown')
        self.resize(420, 420)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Rank', 'Country', 'Players'])
        h_header = self._table.horizontalHeader()
        if h_header is None:
            msg = 'Failed to get horizontal header'
            raise RuntimeError(msg)
        h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h_header.setStretchLastSection(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        v_header = self._table.verticalHeader()
        if v_header is None:
            msg = 'Failed to get vertical header'
            raise RuntimeError(msg)
        v_header.setVisible(False)
        layout.addWidget(self._table)

        always_on_top_checkbox = QCheckBox('Always on Top')
        always_on_top_checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        always_on_top_checkbox.setChecked(always_on_top)
        always_on_top_checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(always_on_top_checkbox)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current country data."""
        all_players = PlayersRegistry.get_default_sorted_players()
        counts: dict[str, int] = {}
        for player in all_players:
            country = player.iplookup.geolite2.country
            if country == '...':
                ipapi_country = str(player.iplookup.ipapi.country)
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
            rank_item = _NumericItem(str(rank))
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            country_item = QTableWidgetItem(country)
            count_item = _NumericItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, rank_item)
            self._table.setItem(row, 1, country_item)
            self._table.setItem(row, 2, count_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(2, Qt.SortOrder.DescendingOrder)

    # Internal ————————————————————————————————————————————————————————————————

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
