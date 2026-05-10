"""Port heatmap statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry


class PortHeatmapWindow(ToggleAlwaysOnTopMixin):
    """A standalone window ranking observed ports by frequency across all players."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the port heatmap window."""
        super().__init__()

        self.setWindowTitle('Port Heatmap')
        self.resize(400, 420)
        layout = self._setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Port', 'Count', '% of Total'])
        setup_stat_table(self._table, layout)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current port frequency data."""
        all_players = PlayersRegistry.get_all_players()
        counts: dict[int, int] = {}
        for player in all_players:
            for port in player.ports.all:
                counts[port] = counts.get(port, 0) + 1

        total = sum(counts.values())
        sorted_ports = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for port, count in sorted_ports:
            row = self._table.rowCount()
            self._table.insertRow(row)
            port_item = NumericTableWidgetItem(str(port))
            port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            count_item = NumericTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pct = f'{count / total * 100:.1f}%' if total else '0.0%'
            pct_item = QTableWidgetItem(pct)
            pct_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, port_item)
            self._table.setItem(row, 1, count_item)
            self._table.setItem(row, 2, pct_item)
        self._table.setSortingEnabled(True)
