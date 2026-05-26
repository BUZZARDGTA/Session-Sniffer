"""Most Seen Players leaderboard window."""

from typing import TYPE_CHECKING, ClassVar

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH
from session_sniffer.guis.utils import setup_table_view_headers
from session_sniffer.player.seen_stats import LeaderboardEntry, build_leaderboard

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime


_SCOPE_TODAY = 'Today'
_SCOPE_THIS_WEEK = 'This Week'
_SCOPE_THIS_MONTH = 'This Month'
_SCOPE_THIS_YEAR = 'This Year'
_SCOPE_ALL_TIME = 'All Time'

_SCOPES = (_SCOPE_TODAY, _SCOPE_THIS_WEEK, _SCOPE_THIS_MONTH, _SCOPE_THIS_YEAR, _SCOPE_ALL_TIME)

_HEADERS = ('Rank', 'IP Address', 'Usernames', 'Sessions', 'First Seen', 'Last Seen', 'Country', 'ISP', 'Mobile', 'VPN', 'Hosting')
_COL_SESSIONS = 3


def _format_bool(value: bool | None) -> str:  # noqa: FBT001
    """Format an optional boolean for display."""
    if value is None:
        return ''
    return 'Yes' if value else 'No'


def _format_datetime(dt: datetime | None) -> str:
    """Format a datetime for display, returning empty string for None."""
    if dt is None:
        return ''
    return dt.strftime('%m/%d/%Y %H:%M')


class _LeaderboardTableModel(QAbstractTableModel):

    _SCOPE_ATTR: ClassVar[dict[str, str]] = {
        _SCOPE_TODAY: 'sessions_today',
        _SCOPE_THIS_WEEK: 'sessions_week',
        _SCOPE_THIS_MONTH: 'sessions_month',
        _SCOPE_THIS_YEAR: 'sessions_year',
        _SCOPE_ALL_TIME: 'sessions_total',
    }

    _CENTER_COLS: ClassVar[frozenset[int]] = frozenset({0, 3, 8, 9, 10})

    def __init__(self) -> None:
        super().__init__()
        self._entries: list[LeaderboardEntry] = []
        self._scope: str = _SCOPE_ALL_TIME
        self._scope_attr: str = 'sessions_total'
        self._username_cache: dict[str, str] = {}
        # Bound method dispatch — avoids per-cell getattr() overhead
        self._display_dispatch: dict[int, Callable[[int, LeaderboardEntry], object]] = {
            0: self._display_rank,
            1: self._display_ip,
            2: self._display_usernames,
            3: self._display_sessions,
            4: self._display_first_seen,
            5: self._display_last_seen,
            6: self._display_country,
            7: self._display_isp,
            8: self._display_mobile,
            9: self._display_vpn,
            10: self._display_hosting,
        }

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        """Return the number of leaderboard entries."""
        if parent is None:
            parent = QModelIndex()
        return len(self._entries)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        """Return the number of columns."""
        if parent is None:
            parent = QModelIndex()
        return len(_HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return cell data for the given index and role."""
        if not index.isValid():
            return None

        entry = self._entries[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            method = self._display_dispatch.get(col)
            return method(index.row(), entry) if method is not None else None

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in self._CENTER_COLS:
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole and col == _COL_SESSIONS:
            return self.get_session_count(entry)

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:  # noqa: N802
        """Return column header labels."""
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        return _HEADERS[section]

    # Display helpers --------------------------------------------------------

    @staticmethod
    def _display_rank(row: int, _entry: LeaderboardEntry) -> int:
        return row + 1

    @staticmethod
    def _display_ip(_row: int, entry: LeaderboardEntry) -> str:
        return entry.ip

    @staticmethod
    def _display_usernames(_row: int, entry: LeaderboardEntry) -> str:
        return ', '.join(entry.usernames) if entry.usernames else ''

    def _display_sessions(self, _row: int, entry: LeaderboardEntry) -> int:
        return self.get_session_count(entry)

    @staticmethod
    def _display_first_seen(_row: int, entry: LeaderboardEntry) -> str:
        return _format_datetime(entry.first_seen)

    @staticmethod
    def _display_last_seen(_row: int, entry: LeaderboardEntry) -> str:
        return _format_datetime(entry.last_seen)

    @staticmethod
    def _display_country(_row: int, entry: LeaderboardEntry) -> str:
        return entry.country

    @staticmethod
    def _display_isp(_row: int, entry: LeaderboardEntry) -> str:
        return entry.isp

    @staticmethod
    def _display_mobile(_row: int, entry: LeaderboardEntry) -> str:
        return _format_bool(entry.mobile)

    @staticmethod
    def _display_vpn(_row: int, entry: LeaderboardEntry) -> str:
        return _format_bool(entry.vpn)

    @staticmethod
    def _display_hosting(_row: int, entry: LeaderboardEntry) -> str:
        return _format_bool(entry.hosting)

    def get_session_count(self, entry: LeaderboardEntry) -> int:
        """Return the session count for the current time scope."""
        return int(getattr(entry, self._scope_attr))

    _get_session_count = get_session_count  # internal alias for backward compat

    @property
    def entries(self) -> list[LeaderboardEntry]:
        """Return the current entries list (read-only access for the sort proxy)."""
        return self._entries

    def load_data(self, entries: list[LeaderboardEntry]) -> None:
        """Replace the model data with new leaderboard entries."""
        self.beginResetModel()
        self._entries = entries
        self.endResetModel()

    def set_scope(self, scope: str) -> None:
        """Change the active time scope and refresh the model."""
        self._scope = scope
        self._scope_attr = self._SCOPE_ATTR.get(scope, 'sessions_total')
        self.beginResetModel()
        self.endResetModel()


class _LeaderboardSortProxy(QSortFilterProxyModel):
    """Proxy that filters out zero-session entries and supports custom sorting."""

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        """Reject rows where the session count for the active scope is zero."""
        _ = source_parent
        model = self.sourceModel()
        if not isinstance(model, _LeaderboardTableModel):
            return True
        # Direct entry access avoids QModelIndex creation + data() indirection
        entry = model.entries[source_row]
        return model.get_session_count(entry) > 0

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802
        """Sort integers numerically instead of lexicographically."""
        model = self.sourceModel()
        if model is None:
            return super().lessThan(left, right)
        left_data = model.data(left, Qt.ItemDataRole.DisplayRole)
        right_data = model.data(right, Qt.ItemDataRole.DisplayRole)

        if isinstance(left_data, int) and isinstance(right_data, int):
            return left_data < right_data
        return super().lessThan(left, right)


class PlayerLeaderboardWindow(QWidget):
    """Standalone window showing the most-seen players leaderboard."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the leaderboard window and load session data."""
        super().__init__(parent)

        self.setWindowTitle('Most Seen Players')
        self.setMinimumSize(1100, 550)
        self.resize(1400, 700)
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint | Qt.WindowType.WindowMinimizeButtonHint | Qt.WindowType.WindowMaximizeButtonHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)

        # Controls bar
        controls_layout = QHBoxLayout()

        scope_label = QLabel('Time Period:')
        controls_layout.addWidget(scope_label)

        self._scope_combo = QComboBox()
        self._scope_combo.addItems(_SCOPES)
        self._scope_combo.setCurrentText(_SCOPE_ALL_TIME)
        self._scope_combo.currentTextChanged.connect(self._on_scope_changed)
        controls_layout.addWidget(self._scope_combo)

        controls_layout.addStretch()

        self._count_label = QLabel()
        controls_layout.addWidget(self._count_label)

        layout.addLayout(controls_layout)

        # Table
        self._model = _LeaderboardTableModel()
        self._proxy = _LeaderboardSortProxy()
        self._proxy.setSourceModel(self._model)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)

        header = setup_table_view_headers(self._table)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Rank
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # IP
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Usernames
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Sessions
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # First Seen
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Last Seen
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Country
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # ISP
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)  # Mobile
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.ResizeToContents)  # VPN
        header.setSectionResizeMode(10, QHeaderView.ResizeMode.ResizeToContents)  # Hosting

        layout.addWidget(self._table)

        # Sort by sessions descending by default
        self._proxy.sort(3, Qt.SortOrder.DescendingOrder)

        # Load data
        self._all_entries: list[LeaderboardEntry] = []
        self.refresh()

    def refresh(self) -> None:
        """Reload leaderboard data from disk and refresh the table."""
        self._all_entries = build_leaderboard(SESSIONS_LOGGING_DIR_PATH)
        self._model.load_data(self._all_entries)
        self._proxy.invalidateFilter()
        self._update_count_label()

    def _on_scope_changed(self, scope: str) -> None:
        self._model.set_scope(scope)
        self._proxy.invalidateFilter()
        self._proxy.sort(self._proxy.sortColumn(), self._proxy.sortOrder())
        self._update_count_label()

    def _update_count_label(self) -> None:
        visible = self._proxy.rowCount()
        total = len(self._all_entries)
        self._count_label.setText(f'{visible} of {total} players')
