"""Reconnect frequency statistics window."""

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


class ReconnectFrequencyWindow(QWidget):
    """A standalone window listing players sorted by reconnect (rejoin) count."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the reconnect frequency window."""
        super().__init__()

        self.setWindowTitle('Reconnect Frequency')
        self.resize(520, 420)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['IP', 'Rejoins', 'Usernames'])
        h_header = self._table.horizontalHeader()
        assert h_header is not None  # noqa: S101
        h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h_header.setStretchLastSection(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
        v_header = self._table.verticalHeader()
        assert v_header is not None  # noqa: S101
        v_header.setVisible(False)
        layout.addWidget(self._table)

        always_on_top_checkbox = QCheckBox('Always on Top')
        always_on_top_checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        always_on_top_checkbox.setChecked(always_on_top)
        always_on_top_checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(always_on_top_checkbox)

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
            rejoins_item = _NumericItem(str(rejoins))
            rejoins_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, ip_item)
            self._table.setItem(row, 1, rejoins_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)

    # Internal ————————————————————————————————————————————————————————————————

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
