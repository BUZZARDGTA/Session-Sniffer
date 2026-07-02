"""Most Seen Players leaderboard window."""

import contextlib
from typing import TYPE_CHECKING, ClassVar, override

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QPoint, QSortFilterProxyModel, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QPixmap, QShortcut, QShowEvent
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH
from session_sniffer.guis._combo_rule_editor import AVAILABLE_FLAG_CODES
from session_sniffer.guis._combo_rule_editor import COUNTRY_FLAGS_DIR as _COUNTRY_FLAGS_DIR
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.utils import (
    apply_search_icon,
    format_player_display,
    get_screen_size,
    popup_menu_at_table,
    resize_window_for_screen,
    set_dialog_window_flags,
    setup_table_view_headers,
)
from session_sniffer.player.seen_stats import LeaderboardBaseline, LeaderboardEntry, build_leaderboard_baseline, overlay_live_session
from session_sniffer.rendering_core.renderer import SESSIONS_LOGGING_PATH

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from pathlib import Path


_SCOPE_TODAY = 'Today'
_SCOPE_THIS_WEEK = 'This Week'
_SCOPE_THIS_MONTH = 'This Month'
_SCOPE_THIS_YEAR = 'This Year'
_SCOPE_ALL_TIME = 'All Time'

_SCOPES = (_SCOPE_TODAY, _SCOPE_THIS_WEEK, _SCOPE_THIS_MONTH, _SCOPE_THIS_YEAR, _SCOPE_ALL_TIME)

_MODE_DAYS = 'Unique Days'
_MODE_SESSIONS = 'Sessions'
_MODES = (_MODE_DAYS, _MODE_SESSIONS)

_HEADERS = ('Rank', 'Usernames', 'IP Address', 'Sessions', 'First Seen', 'Last Seen', 'Country', 'ISP', 'Mobile', 'VPN', 'Hosting')

_SEARCH_COLUMN_ALL = 'All Columns'
_SEARCH_COLUMN_USERNAMES = 'Usernames'
_SEARCH_COLUMN_IP = 'IP Address'
_SEARCH_COLUMN_COUNTRY = 'Country'
_SEARCH_COLUMN_ISP = 'ISP'

_SEARCH_COLUMNS = (
    _SEARCH_COLUMN_ALL,
    _SEARCH_COLUMN_USERNAMES,
    _SEARCH_COLUMN_IP,
    _SEARCH_COLUMN_COUNTRY,
    _SEARCH_COLUMN_ISP,
)
_COLUMN_SESSIONS = 3
_COLUMN_COUNTRY = 6

# How often the displayed leaderboard is re-derived from the live session snapshot while visible.
_LIVE_REFRESH_INTERVAL_MS = 1000

_flag_icon_cache: dict[str, QIcon | None] = {}


def _get_flag_icon(country_code: str) -> QIcon | None:
    """Return a cached QIcon for the given ISO country code, or None if unavailable."""
    if country_code in _flag_icon_cache:
        return _flag_icon_cache[country_code]
    icon: QIcon | None = QIcon(QPixmap(str(_COUNTRY_FLAGS_DIR / f'{country_code}.png'))) if country_code and country_code in AVAILABLE_FLAG_CODES else None
    _flag_icon_cache[country_code] = icon
    return icon


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
    _SCOPE_ATTR_DAYS: ClassVar[dict[str, str]] = {
        _SCOPE_TODAY: 'days_today',
        _SCOPE_THIS_WEEK: 'days_week',
        _SCOPE_THIS_MONTH: 'days_month',
        _SCOPE_THIS_YEAR: 'days_year',
        _SCOPE_ALL_TIME: 'days_total',
    }

    _SCOPE_ATTR_SESSIONS: ClassVar[dict[str, str]] = {
        _SCOPE_TODAY: 'sessions_today',
        _SCOPE_THIS_WEEK: 'sessions_week',
        _SCOPE_THIS_MONTH: 'sessions_month',
        _SCOPE_THIS_YEAR: 'sessions_year',
        _SCOPE_ALL_TIME: 'sessions_total',
    }

    _CENTER_COLUMNS: ClassVar[frozenset[int]] = frozenset({0, 3, 8, 9, 10})

    def __init__(self) -> None:
        super().__init__()
        self._entries: list[LeaderboardEntry] = []
        self._index_by_ip: dict[str, int] = {}
        self._scope: str = _SCOPE_ALL_TIME
        self._mode: str = _MODE_DAYS
        self._scope_attr: str = 'days_total'
        self._username_cache: dict[str, str] = {}
        # Bound method dispatch — avoids per-cell getattr() overhead
        self._display_dispatch: dict[int, Callable[[int, LeaderboardEntry], object]] = {
            0: self._display_rank,
            1: self._display_usernames,
            2: self._display_ip,
            3: self._display_sessions,
            4: self._display_first_seen,
            5: self._display_last_seen,
            6: self._display_country,
            7: self._display_isp,
            8: self._display_mobile,
            9: self._display_vpn,
            10: self._display_hosting,
        }

    @override
    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """Return the number of leaderboard entries."""
        if parent is None:
            parent = QModelIndex()
        return len(self._entries)

    @override
    def columnCount(self, parent: QModelIndex | None = None) -> int:
        """Return the number of columns."""
        if parent is None:
            parent = QModelIndex()
        return len(_HEADERS)

    @override
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return cell data for the given index and role."""
        if not index.isValid():
            return None

        entry = self._entries[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            method = self._display_dispatch.get(column)
            return method(index.row(), entry) if method is not None else None

        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter if column in self._CENTER_COLUMNS else Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        if role == Qt.ItemDataRole.UserRole and column == _COLUMN_SESSIONS:
            return self.get_session_count(entry)

        if role == Qt.ItemDataRole.ToolTipRole and column == _COLUMN_SESSIONS:
            count = self.get_session_count(entry)
            return (
                f'{count} unique calendar day(s) this player was seen within the selected time period'
                if self._mode == _MODE_DAYS
                else f'{count} sniffer session(s) in which this player was seen within the selected time period'
            )

        return _get_flag_icon(entry.country_code) if role == Qt.ItemDataRole.DecorationRole and column == _COLUMN_COUNTRY else None

    @override
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return column header labels."""
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        if section == _COLUMN_SESSIONS:
            return 'Days' if self._mode == _MODE_DAYS else 'Sessions'
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
        """Return the days or session count for the current mode and time scope."""
        return int(getattr(entry, self._scope_attr))

    @property
    def entries(self) -> list[LeaderboardEntry]:
        """Return the current entries list (read-only access for the sort proxy)."""
        return self._entries

    def load_data(self, entries: list[LeaderboardEntry]) -> None:
        """Replace the model data with new leaderboard entries."""
        self.beginResetModel()
        self._entries = entries
        self._index_by_ip = {entry.ip: i for i, entry in enumerate(entries)}
        self.endResetModel()

    def apply_live_update(self, entries: list[LeaderboardEntry]) -> None:
        """Refresh in place from a live overlay: update existing rows and append newly-seen players.

        Row positions are kept stable so the sort proxy re-sorts and the user's selection and scroll
        position survive; only cell values change (plus any appended rows), avoiding a full reset.
        """
        updated_by_ip = {entry.ip: entry for entry in entries}

        for ip, row in self._index_by_ip.items():
            updated = updated_by_ip.get(ip)
            if updated is not None:
                self._entries[row] = updated

        new_entries = [entry for entry in entries if entry.ip not in self._index_by_ip]
        if new_entries:
            first_new_row = len(self._entries)
            self.beginInsertRows(QModelIndex(), first_new_row, first_new_row + len(new_entries) - 1)
            for entry in new_entries:
                self._index_by_ip[entry.ip] = len(self._entries)
                self._entries.append(entry)
            self.endInsertRows()

        if self._entries:
            top_left = self.index(0, 0)
            bottom_right = self.index(len(self._entries) - 1, self.columnCount() - 1)
            self.dataChanged.emit(top_left, bottom_right)

    def set_scope(self, scope: str) -> None:
        """Change the active time scope and refresh the model."""
        self._scope = scope
        self._refresh_scope_attr()
        self.beginResetModel()
        self.endResetModel()

    def set_mode(self, mode: str) -> None:
        """Switch between Unique Days and Sessions counting modes."""
        self._mode = mode
        self._refresh_scope_attr()
        self.beginResetModel()
        self.endResetModel()
        self.headerDataChanged.emit(Qt.Orientation.Horizontal, _COLUMN_SESSIONS, _COLUMN_SESSIONS)

    def _refresh_scope_attr(self) -> None:
        scope_map = self._SCOPE_ATTR_DAYS if self._mode == _MODE_DAYS else self._SCOPE_ATTR_SESSIONS
        default = 'days_total' if self._mode == _MODE_DAYS else 'sessions_total'
        self._scope_attr = scope_map.get(self._scope, default)


class _LeaderboardSortProxy(QSortFilterProxyModel):
    """Proxy that filters out zero-session entries and supports custom sorting."""

    def __init__(self) -> None:
        super().__init__()
        self._search_text: str = ''
        self._search_column: str = _SEARCH_COLUMN_ALL

    def set_search_text(self, text: str) -> None:
        """Update the search filter text and re-evaluate visible rows."""
        self._search_text = text.strip().lower()
        self.invalidateFilter()

    def set_search_column(self, column: str) -> None:
        """Update which column is searched and re-evaluate visible rows."""
        self._search_column = column
        self.invalidateFilter()

    def _entry_matches_search(self, entry: LeaderboardEntry, text: str) -> bool:
        """Return True if *entry* contains *text* within the active search column."""
        if self._search_column == _SEARCH_COLUMN_ALL:
            return text in entry.ip.lower() or any(text in username.lower() for username in entry.usernames) or text in entry.country.lower() or text in entry.isp.lower()
        if self._search_column == _SEARCH_COLUMN_USERNAMES:
            return any(text in username.lower() for username in entry.usernames)
        _targets: dict[str, str] = {
            _SEARCH_COLUMN_IP: entry.ip,
            _SEARCH_COLUMN_COUNTRY: entry.country,
            _SEARCH_COLUMN_ISP: entry.isp,
        }
        return text in _targets.get(self._search_column, '').lower()

    @override
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        """Reject rows where the session count is zero or they don't match the search text."""
        _ = source_parent
        model = self.sourceModel()
        if not isinstance(model, _LeaderboardTableModel):
            return True
        entry = model.entries[source_row]
        if not model.get_session_count(entry):
            return False
        if self._search_text:
            return self._entry_matches_search(entry, self._search_text)
        return True

    @override
    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        """Sort integers numerically instead of lexicographically."""
        model = self.sourceModel()
        if model is None:
            return super().lessThan(left, right)
        left_data = model.data(left, Qt.ItemDataRole.DisplayRole)
        right_data = model.data(right, Qt.ItemDataRole.DisplayRole)

        if isinstance(left_data, int) and isinstance(right_data, int):
            return left_data < right_data
        return super().lessThan(left, right)


_STATS_PERIODS: tuple[tuple[str, str, str], ...] = (
    ('Today', 'sessions_today', 'days_today'),
    ('This Week', 'sessions_week', 'days_week'),
    ('This Month', 'sessions_month', 'days_month'),
    ('This Year', 'sessions_year', 'days_year'),
    ('Total', 'sessions_total', 'days_total'),
)


def _build_seen_stats_dialog(entry: LeaderboardEntry, parent: QWidget | None = None) -> QDialog:
    """Build and return a dialog showing Unique Days and Sessions side-by-side for each time period."""
    dialog = QDialog(parent)
    dialog.setWindowModality(Qt.WindowModality.WindowModal)
    dialog.setWindowTitle(f'Seen Stats — {format_player_display(entry.ip, entry.usernames)}')
    dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

    table = QTableWidget(len(_STATS_PERIODS), 3, dialog)
    table.setHorizontalHeaderLabels(['Period', 'Unique Days', 'Sessions'])
    v_header = table.verticalHeader()
    if v_header is not None:
        v_header.setVisible(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

    for row, (period, sessions_attr, days_attr) in enumerate(_STATS_PERIODS):
        period_item = QTableWidgetItem(period)
        days_item = QTableWidgetItem(str(getattr(entry, days_attr)))
        sessions_item = QTableWidgetItem(str(getattr(entry, sessions_attr)))
        days_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        sessions_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        table.setItem(row, 0, period_item)
        table.setItem(row, 1, days_item)
        table.setItem(row, 2, sessions_item)

    h_header = table.horizontalHeader()
    if h_header is not None:
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

    layout = QVBoxLayout(dialog)
    layout.addWidget(table)
    return dialog


class _LeaderboardBaselineWorker(CrashingQThread):
    """Background thread that scans finished session logs into a reusable leaderboard baseline.

    Emits `finished_ok` with the resulting `LeaderboardBaseline`.
    """

    finished_ok: pyqtSignal = pyqtSignal(object)

    def __init__(self, folder_path: Path, exclude_file: Path) -> None:
        super().__init__()
        self._folder_path = folder_path
        self._exclude_file = exclude_file

    @override
    def _run(self) -> None:
        """Scan the session logs into a baseline and emit it."""
        baseline = build_leaderboard_baseline(self._folder_path, exclude_file=self._exclude_file)
        self.finished_ok.emit(baseline)


def _build_loading_dialog(parent: QWidget) -> QDialog:
    """Build and return a modal dialog shown while the leaderboard is being built in the background."""
    dialog = QDialog(parent)
    set_dialog_window_flags(dialog)
    dialog.setWindowTitle('Most Seen Players')
    dialog.setMinimumSize(340, 140)

    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.setSpacing(10)

    header = QLabel('🏆  Loading leaderboard...')
    header.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(header)

    status_label = QLabel('Scanning session logs, please wait...')
    status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    status_label.setWordWrap(True)
    layout.addWidget(status_label)

    progress_bar = QProgressBar()
    progress_bar.setRange(0, 0)
    progress_bar.setTextVisible(False)
    progress_bar.setFixedHeight(14)
    layout.addWidget(progress_bar)

    return dialog


class PlayerLeaderboardWindow(QWidget):
    """Standalone window showing the most-seen players leaderboard."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the leaderboard window and load session data."""
        super().__init__(parent)

        self.setWindowTitle('Most Seen Players')
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint | Qt.WindowType.WindowMinimizeButtonHint | Qt.WindowType.WindowMaximizeButtonHint)
        self.setMinimumSize(1100, 550)
        screen_size = get_screen_size()
        resize_window_for_screen(self, screen_size)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)

        # Controls bar
        controls_layout = QHBoxLayout()

        scope_label = QLabel('Time Period:')
        controls_layout.addWidget(scope_label)

        self._scope_combo = QComboBox()
        self._scope_combo.addItems(_SCOPES)
        self._scope_combo.setCurrentText(_SCOPE_ALL_TIME)
        self._scope_combo.setToolTip('Restrict the count to encounters within the selected time window')
        self._scope_combo.currentTextChanged.connect(self._on_scope_changed)
        controls_layout.addWidget(self._scope_combo)

        controls_layout.addSpacing(12)

        mode_label = QLabel('Count by:')
        controls_layout.addWidget(mode_label)

        self._mode_combo = QComboBox()
        self._mode_combo.addItems(_MODES)
        self._mode_combo.setCurrentText(_MODE_DAYS)
        self._mode_combo.setToolTip('Choose how encounters are counted — by unique calendar days or by individual sniffer sessions')
        self._mode_combo.setItemData(
            _MODES.index(_MODE_DAYS),
            'Count each calendar day at most once — seeing a player 5 times in one day still counts as 1',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._mode_combo.setItemData(
            _MODES.index(_MODE_SESSIONS),
            'Count every individual sniffer session — seeing a player in 5 sessions counts as 5',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._mode_combo.currentTextChanged.connect(self._on_mode_changed)
        controls_layout.addWidget(self._mode_combo)

        controls_layout.addSpacing(12)

        search_label = QLabel('Search:')
        controls_layout.addWidget(search_label)

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText('Search...')
        self._search_box.setToolTip('Type to filter visible rows')
        self._search_box.setMaximumWidth(280)
        self._search_box.textChanged.connect(self._on_search_changed)
        apply_search_icon(self._search_box)
        controls_layout.addWidget(self._search_box)

        self._search_column_combo = QComboBox()
        self._search_column_combo.addItems(_SEARCH_COLUMNS)
        self._search_column_combo.setCurrentText(_SEARCH_COLUMN_ALL)
        self._search_column_combo.setToolTip('Restrict the search to a specific column')
        self._search_column_combo.currentTextChanged.connect(self._on_search_column_changed)
        controls_layout.addWidget(self._search_column_combo)

        controls_layout.addSpacing(12)

        cap_label = QLabel('Show top:')
        controls_layout.addWidget(cap_label)

        self._cap_spinbox = QSpinBox()
        self._cap_spinbox.setRange(50, 10000)
        self._cap_spinbox.setSingleStep(50)
        self._cap_spinbox.setValue(1000)
        self._cap_spinbox.setToolTip('Maximum number of players to load from session logs')
        self._cap_spinbox.editingFinished.connect(self._on_cap_changed)
        controls_layout.addWidget(self._cap_spinbox)

        search_shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        search_shortcut.activated.connect(self._search_box.setFocus)

        controls_layout.addStretch()

        refresh_button = QPushButton('🔄 Refresh')
        refresh_button.setToolTip('Reload leaderboard data from disk')
        refresh_button.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_button.clicked.connect(self.refresh)
        controls_layout.addWidget(refresh_button)

        controls_layout.addSpacing(12)

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
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

        header = setup_table_view_headers(self._table)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Rank
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Usernames
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # IP
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

        # Data is loaded on a background thread by `load_and_show` before the window is revealed
        self._all_entries: list[LeaderboardEntry] = []
        self._baseline: LeaderboardBaseline | None = None
        self._live_session_file: Path = SESSIONS_LOGGING_PATH.with_suffix('.json')

        # Periodically re-overlays the live session onto the cached baseline while the window is visible
        self._live_timer = QTimer(self)
        self._live_timer.setInterval(_LIVE_REFRESH_INTERVAL_MS)
        self._live_timer.timeout.connect(self._on_live_tick)

    def load_and_show(self) -> None:
        """Load leaderboard data in the background, then reveal the window once it is ready."""
        self._start_load(on_ready=self.show, on_cancel=self.close)

    def refresh(self) -> None:
        """Reload leaderboard data from disk on a background thread, showing a loading dialog."""
        self._start_load(on_ready=None, on_cancel=None)

    def _start_load(self, *, on_ready: Callable[[], object] | None, on_cancel: Callable[[], object] | None) -> None:
        """Run the leaderboard scan on a worker thread behind a modal loading dialog.

        `on_ready` runs once the loaded data has been applied; `on_cancel` runs if the
        user closes the loading dialog before the scan completes.
        """
        worker = _LeaderboardBaselineWorker(SESSIONS_LOGGING_DIR_PATH, self._live_session_file)
        worker.finished.connect(worker.deleteLater)
        loading_dialog = _build_loading_dialog(self)

        def _on_finished_ok(baseline: LeaderboardBaseline) -> None:
            self._apply_baseline(baseline)
            loading_dialog.accept()
            if on_ready is not None:
                on_ready()

        worker.finished_ok.connect(_on_finished_ok)

        def _on_rejected() -> None:
            # If the user closes the loading dialog before the scan completes,
            # stop the finished handler from touching the table afterward.
            with contextlib.suppress(TypeError):
                worker.finished_ok.disconnect(_on_finished_ok)
            if on_cancel is not None:
                on_cancel()

        loading_dialog.rejected.connect(_on_rejected)

        worker.setParent(self)
        worker.start()
        loading_dialog.exec()

    def _apply_baseline(self, baseline: LeaderboardBaseline) -> None:
        """Store a freshly-scanned baseline, render the initial overlaid leaderboard, and begin live refresh."""
        self._baseline = baseline
        entries = overlay_live_session(baseline, self._live_session_file, limit=self._cap_spinbox.value())
        self._all_entries = entries
        self._model.load_data(entries)
        self._proxy.invalidateFilter()
        self._update_count_label()
        if not self._live_timer.isActive():
            self._live_timer.start()

    def _on_live_tick(self) -> None:
        """Merge the latest live session snapshot into the displayed leaderboard without a full reset."""
        if self._baseline is None or not self.isVisible() or self.isMinimized():
            return
        entries = overlay_live_session(self._baseline, self._live_session_file, limit=self._cap_spinbox.value())
        self._all_entries = entries
        self._model.apply_live_update(entries)
        self._update_count_label()

    def _on_cap_changed(self) -> None:
        """Re-apply the display limit, re-scanning from disk only if no baseline is loaded yet."""
        if self._baseline is None:
            self.refresh()
            return
        self._apply_baseline(self._baseline)

    def _on_mode_changed(self, mode: str) -> None:
        self._model.set_mode(mode)
        self._proxy.invalidateFilter()
        self._proxy.sort(self._proxy.sortColumn(), self._proxy.sortOrder())
        self._update_count_label()

    def _on_scope_changed(self, scope: str) -> None:
        self._model.set_scope(scope)
        self._proxy.invalidateFilter()
        self._proxy.sort(self._proxy.sortColumn(), self._proxy.sortOrder())
        self._update_count_label()

    def _on_search_changed(self, text: str) -> None:
        self._proxy.set_search_text(text)
        self._update_count_label()

    def _on_search_column_changed(self, column: str) -> None:
        self._proxy.set_search_column(column)
        self._update_count_label()

    def _show_context_menu(self, pos: QPoint) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return
        entry = self._model.entries[self._proxy.mapToSource(index).row()]

        menu = QMenu(self)

        usernames_text = ', '.join(entry.usernames)
        copy_usernames_action = QAction(f'Copy Usernames:  {usernames_text}' if usernames_text else 'Copy Usernames (none)', self)
        copy_usernames_action.setEnabled(bool(entry.usernames))
        copy_usernames_action.triggered.connect(lambda: self._copy_to_clipboard(usernames_text))
        menu.addAction(copy_usernames_action)

        copy_ip_action = QAction(f'Copy IP:  {entry.ip}', self)
        copy_ip_action.triggered.connect(lambda: self._copy_to_clipboard(entry.ip))
        menu.addAction(copy_ip_action)

        menu.addSeparator()

        seen_stats_action = QAction('View Seen Stats', self)
        seen_stats_action.triggered.connect(lambda: self._show_seen_stats_for_entry(entry))
        menu.addAction(seen_stats_action)

        popup_menu_at_table(menu, self._table, pos)

    def _copy_to_clipboard(self, text: str) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is None:
            message = 'Failed to get clipboard'
            raise RuntimeError(message)
        clipboard.setText(text)

    def _show_seen_stats_for_entry(self, entry: LeaderboardEntry) -> None:
        _build_seen_stats_dialog(entry, self).exec()

    def _update_count_label(self) -> None:
        visible = self._proxy.rowCount()
        total = len(self._all_entries)
        self._count_label.setText(f'{visible} of {total} players')

    @override
    def showEvent(self, a0: QShowEvent | None) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if self.property('_should_maximize_on_show') is True:
            self.setProperty('_should_maximize_on_show', False)  # noqa: FBT003
            self.showMaximized()
