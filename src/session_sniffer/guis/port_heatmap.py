"""Port heatmap statistics window."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidget

from session_sniffer.constants.tables import PORT_HEATMAP_TABLE_MIN_COLUMN_WIDTHS
from session_sniffer.guis.table_context_menu import StatTableWindowMixin, skip_if_menu_open
from session_sniffer.guis.utils import NumericTableWidgetItem, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry


class PortHeatmapWindow(StatTableWindowMixin):
    """A standalone window ranking observed ports by frequency across all players."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the port heatmap window."""
        super().__init__()

        self.setWindowTitle('Port Heatmap')
        self.resize(400, 420)
        layout = self.setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Port', 'Count', '% of Total'])
        setup_stat_table(self._table, layout)
        self.setup_stat_table_controls(layout, always_on_top=always_on_top, min_column_widths=PORT_HEATMAP_TABLE_MIN_COLUMN_WIDTHS)
        self._reset_column_sizes()
        self._table.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    @skip_if_menu_open
    def refresh(self) -> None:
        """Rebuild the table with current port frequency data."""
        counts: dict[int, int] = {}
        for player in PlayersRegistry.get_all_players():
            for port in player.ports.all:
                counts[port] = counts.get(port, 0) + 1

        total = sum(counts.values())
        sorted_ports = sorted(counts.items(), key=lambda item: item[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(sorted_ports))
        center = Qt.AlignmentFlag.AlignCenter
        for row, (port, count) in enumerate(sorted_ports):
            ratio = count / total if total else 0.0
            self._table.setItem(row, 0, NumericTableWidgetItem(port, align=center))
            self._table.setItem(row, 1, NumericTableWidgetItem(count, align=center))
            self._table.setItem(row, 2, NumericTableWidgetItem(f'{ratio * 100:.1f}%', sort_value=ratio, align=center))
        self._table.setSortingEnabled(True)
        self._apply_initial_column_resizing()
