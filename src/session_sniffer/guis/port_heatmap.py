"""Port heatmap statistics window."""

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


class PortHeatmapWindow(QWidget):
    """A standalone window ranking observed ports by frequency across all players."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the port heatmap window."""
        super().__init__()

        self.setWindowTitle('Port Heatmap')
        self.resize(400, 420)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Port', 'Count', '% of Total'])
        h_header = self._table.horizontalHeader()
        if h_header is None:
            msg = 'Failed to get horizontal header'
            raise RuntimeError(msg)
        h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h_header.setStretchLastSection(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
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
        """Rebuild the table with current port frequency data."""
        all_players = PlayersRegistry.get_default_sorted_players()
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
            port_item = _NumericItem(str(port))
            port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            count_item = _NumericItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pct = f'{count / total * 100:.1f}%' if total else '0.0%'
            pct_item = QTableWidgetItem(pct)
            pct_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, port_item)
            self._table.setItem(row, 1, count_item)
            self._table.setItem(row, 2, pct_item)
        self._table.setSortingEnabled(True)

    # Internal ————————————————————————————————————————————————————————————————

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
