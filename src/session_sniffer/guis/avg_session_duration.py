"""Average session duration statistics window."""

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


def _format_duration(total_seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    secs = int(total_seconds)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f'{h}h {m}m {s}s'
    if m:
        return f'{m}m {s}s'
    return f'{s}s'


class AvgSessionDurationWindow(QWidget):
    """A standalone window listing disconnected players sorted by session duration."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the average session duration window."""
        super().__init__()

        self.setWindowTitle('Session Duration')
        self.resize(520, 420)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['IP', 'Duration', 'Usernames'])
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
        """Rebuild the table with current session duration data."""
        disconnected = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        entries = [
            (p.ip, p.datetime.session_time.total_seconds(), ', '.join(p.usernames) if p.usernames else '\u2014')
            for p in disconnected
            if p.datetime.session_time is not None
        ]
        entries.sort(key=lambda e: e[1], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for ip, duration_secs, usernames in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            ip_item = QTableWidgetItem(ip)
            duration_item = _NumericItem(_format_duration(duration_secs))
            duration_item.setData(Qt.ItemDataRole.UserRole, duration_secs)
            duration_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, ip_item)
            self._table.setItem(row, 1, duration_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)

    # Internal ————————————————————————————————————————————————————————————————

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
