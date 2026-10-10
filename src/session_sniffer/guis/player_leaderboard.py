"""Most Seen Players leaderboard window."""

from pathlib import Path
from typing import TYPE_CHECKING, override

from PySide6.QtCore import (
    QItemSelectionModel,
    QModelIndex,
    QPoint,
    Qt,
    QTimer,
)
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QFocusEvent,
    QIcon,
    QKeyEvent,
    QKeySequence,
    QResizeEvent,
    QShortcut,
    QShowEvent,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QSpinBox,
    QStackedWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH, SESSIONS_LOGGING_DIR_PATH
from session_sniffer.constants.tables import (
    LEADERBOARD_SEEN_STATS_TABLE_MIN_COLUMN_WIDTHS,
    PLAYER_LEADERBOARD_TABLE_MIN_COLUMN_WIDTHS,
)
from session_sniffer.guis._player_leaderboard_loading_widget import LeaderboardLoadingWidget
from session_sniffer.guis._player_leaderboard_model import (
    COLUMN_SESSIONS,
    HEADERS,
    MODE_DAYS,
    MODE_SESSIONS,
    MODES,
    SCOPE_ALL_TIME,
    SCOPES,
    SEARCH_COLUMN_ALL,
    SEARCH_COLUMN_TO_INDEX,
    SEARCH_COLUMNS,
    LeaderboardSortProxy,
    LeaderboardTableModel,
)
from session_sniffer.guis._player_leaderboard_workers import (
    LeaderboardBaselineWorker,
    LeaderboardOverlayWorker,
    OverlayResult,
    SessionFilesScanWorker,
    SessionScanResult,
    server_ips_for,
)
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate, SearchHighlightDelegate
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import setup_static_table_column_resizing, setup_table_header_context_menu
from session_sniffer.guis.table_context_menu import add_copy_usernames_and_ips_actions
from session_sniffer.guis.tables_player_actions import (
    create_ping_menu,
    scan_ports_ip,
    show_detailed_ip_lookup,
)
from session_sniffer.guis.utils import (
    ToggleAlwaysOnTopMixin,
    apply_search_icon,
    consume_maximize_on_show,
    copy_table_all_rows,
    copy_table_cells,
    format_player_display,
    get_screen_size,
    popup_menu_at_table,
    resize_window_for_screen,
    scale_by_ui,
    set_clipboard_text,
    setup_table_view_headers,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.seen_stats import LeaderboardBaseline, LeaderboardEntry, overlay_live_session
from session_sniffer.rendering_core.renderer import SESSIONS_LOGGING_PATH
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable


# How often the displayed leaderboard is re-derived from the live session snapshot while visible.
_LIVE_REFRESH_INTERVAL_MS = 1000

# Minimum spacing between background scans of the sessions directory. Filesystem-change events are
# throttled to this rate so constant live-session writes can't spin the disk walk.
_SESSIONS_SCAN_COOLDOWN_MS = 3000


_STATS_PERIODS: tuple[tuple[str, str, str], ...] = (
    ('Today', 'sessions_today', 'days_today'),
    ('This Week', 'sessions_week', 'days_week'),
    ('This Month', 'sessions_month', 'days_month'),
    ('This Year', 'sessions_year', 'days_year'),
    ('Total', 'sessions_total', 'days_total'),
)


class _SeenStatsDialog(QDialog):
    """Dialog showing Unique Days and Sessions side-by-side for each time period."""

    def __init__(self, entry: LeaderboardEntry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(f'Seen Stats — {format_player_display(entry.ip, entry.usernames)}')
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)

        self._table = QTableWidget(len(_STATS_PERIODS), 3, self)
        self._table.setHorizontalHeaderLabels(['Period', 'Unique Days', 'Sessions'])
        v_header = self._table.verticalHeader()
        if v_header:
            v_header.setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setItemDelegate(ElidedTextTooltipDelegate(self._table))
        self._table.setWordWrap(False)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        for row, (period, sessions_attr, days_attr) in enumerate(_STATS_PERIODS):
            period_item = QTableWidgetItem(period)
            days_item = QTableWidgetItem(str(getattr(entry, days_attr)))
            sessions_item = QTableWidgetItem(str(getattr(entry, sessions_attr)))
            days_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sessions_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, period_item)
            self._table.setItem(row, 1, days_item)
            self._table.setItem(row, 2, sessions_item)

        h_header = self._table.horizontalHeader()
        if h_header:
            for column in range(3):
                h_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            setup_table_header_context_menu(self._table, on_reset=self._reset_column_sizes)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table)
        self._reset_column_sizes()

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout, stretching Period."""
        days_width = scale_by_ui(LEADERBOARD_SEEN_STATS_TABLE_MIN_COLUMN_WIDTHS['Unique Days'])
        sessions_width = scale_by_ui(LEADERBOARD_SEEN_STATS_TABLE_MIN_COLUMN_WIDTHS['Sessions'])
        self._table.setColumnWidth(1, days_width)
        self._table.setColumnWidth(2, sessions_width)
        viewport = self._table.viewport()
        available_width = viewport.width() if viewport and viewport.width() > 0 else self._table.width()
        used_width = self._table.columnWidth(1) + self._table.columnWidth(2)
        min_period_width = scale_by_ui(LEADERBOARD_SEEN_STATS_TABLE_MIN_COLUMN_WIDTHS['Period'])
        remaining_width = max(min_period_width, available_width - used_width)
        self._table.setColumnWidth(0, remaining_width)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Adjust column widths when the dialog is shown."""
        super().showEvent(event)
        self._reset_column_sizes()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adjust column widths when the dialog is resized."""
        super().resizeEvent(event)
        self._reset_column_sizes()


def _build_seen_stats_dialog(entry: LeaderboardEntry, parent: QWidget | None = None) -> QDialog:
    """Build and return a dialog showing Unique Days and Sessions side-by-side for each time period."""
    return _SeenStatsDialog(entry, parent)


class _LeaderboardTableView(QTableView):
    """Custom QTableView for the leaderboard that distributes extra viewport space to flexible columns."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QTableView.ScrollMode.ScrollPerPixel)

    @override
    def focusInEvent(self, event: QFocusEvent) -> None:
        """Handle focus without automatically selecting cell (0, 0)."""
        had_valid_index = self.currentIndex().isValid()
        super().focusInEvent(event)
        if not had_valid_index:
            self.setCurrentIndex(QModelIndex())

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Handle Ctrl+C to copy selected rows and Ctrl+A to select all rows."""
        if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            if event.key() == Qt.Key.Key_C:
                self.copy_selection()
                return
            if event.key() == Qt.Key.Key_A:
                self.selectAll()
                return

        super().keyPressEvent(event)

    def copy_selection(self) -> None:
        """Copy selected rows from the leaderboard table to the clipboard as tab-separated text."""
        copy_table_cells(self)

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Handle leaderboard table viewport resize."""
        super().resizeEvent(event)
        self.setup_static_column_resizing()

    def setup_static_column_resizing(self) -> None:
        """Set up initial column resizing for the table."""
        setup_static_table_column_resizing(self, min_column_widths=PLAYER_LEADERBOARD_TABLE_MIN_COLUMN_WIDTHS)


class PlayerLeaderboardWindow(ToggleAlwaysOnTopMixin):
    """Standalone window showing the most-seen players leaderboard."""

    def __init__(self, parent: QWidget | None = None, *, always_on_top: bool = False) -> None:
        """Initialize the leaderboard window and load session data."""
        super().__init__(parent)

        self.setWindowTitle('Most Seen Players')
        flags = Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint | Qt.WindowType.WindowMinimizeButtonHint | Qt.WindowType.WindowMaximizeButtonHint
        if always_on_top:
            flags |= Qt.WindowType.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        self.setMinimumSize(scale_by_ui(980), scale_by_ui(480))
        screen_size = get_screen_size()
        resize_window_for_screen(self, screen_size)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)

        # Controls bar
        controls_layout = QHBoxLayout()

        scope_label = QLabel('Time Period:')
        controls_layout.addWidget(scope_label)

        self._scope_combo = QComboBox()
        self._scope_combo.addItems(SCOPES)
        self._scope_combo.setCurrentText(SCOPE_ALL_TIME)
        self._scope_combo.setToolTip('Restrict the count to encounters within the selected time window')
        self._scope_combo.currentTextChanged.connect(self._on_scope_changed)
        controls_layout.addWidget(self._scope_combo)

        controls_layout.addSpacing(12)

        mode_label = QLabel('Count by:')
        controls_layout.addWidget(mode_label)

        self._mode_combo = QComboBox()
        self._mode_combo.addItems(MODES)
        self._mode_combo.setCurrentText(MODE_DAYS)
        self._mode_combo.setToolTip('Choose how encounters are counted — by unique calendar days or by individual sniffer sessions')
        self._mode_combo.setItemData(
            MODES.index(MODE_DAYS),
            'Count each calendar day at most once — seeing a player 5 times in one day still counts as 1',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._mode_combo.setItemData(
            MODES.index(MODE_SESSIONS),
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
        self._search_column_combo.addItems(SEARCH_COLUMNS)
        self._search_column_combo.setCurrentText(SEARCH_COLUMN_ALL)
        self._search_column_combo.setToolTip('Restrict the search to a specific column')
        self._search_column_combo.currentTextChanged.connect(self._on_search_column_changed)
        controls_layout.addWidget(self._search_column_combo)

        controls_layout.addStretch()

        self._count_label = QLabel()
        controls_layout.addWidget(self._count_label)

        layout.addLayout(controls_layout)

        search_shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        search_shortcut.activated.connect(self._search_box.setFocus)

        # Second controls row: filters and actions
        filters_layout = QHBoxLayout()

        self._hide_servers_checkbox = QCheckBox('Hide game servers')
        self._hide_servers_checkbox.setToolTip('Exclude known third-party game/relay server IPs from the leaderboard')
        self._hide_servers_checkbox.toggled.connect(self._on_hide_servers_toggled)
        filters_layout.addWidget(self._hide_servers_checkbox)

        self._hide_vpns_checkbox = QCheckBox('Hide VPNs')
        self._hide_vpns_checkbox.setToolTip('Exclude IPs flagged as VPNs or proxies from the leaderboard')
        self._hide_vpns_checkbox.toggled.connect(self._on_hide_vpns_toggled)
        filters_layout.addWidget(self._hide_vpns_checkbox)

        self._hide_hosting_checkbox = QCheckBox('Hide hosting')
        self._hide_hosting_checkbox.setToolTip('Exclude IPs flagged as hosting/datacenter providers from the leaderboard')
        self._hide_hosting_checkbox.toggled.connect(self._on_hide_hosting_toggled)
        filters_layout.addWidget(self._hide_hosting_checkbox)

        self._current_session_checkbox = QCheckBox('Current session only')
        self._current_session_checkbox.setToolTip('Show only players present in your active session (connected or disconnected)')
        self._current_session_checkbox.toggled.connect(self._on_current_session_toggled)
        filters_layout.addWidget(self._current_session_checkbox)

        self._relative_dates_checkbox = QCheckBox('Relative dates')
        self._relative_dates_checkbox.setChecked(True)
        self._relative_dates_checkbox.setToolTip('Display First Seen and Last Seen as natural relative times (e.g., 2 days ago)')
        self._relative_dates_checkbox.toggled.connect(self._on_relative_dates_toggled)
        filters_layout.addWidget(self._relative_dates_checkbox)

        self._always_on_top_checkbox = QCheckBox('Always on Top')
        self._always_on_top_checkbox.setToolTip('Keep this window visible on top of all other applications and games.')
        self._always_on_top_checkbox.setChecked(always_on_top)
        self._always_on_top_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._always_on_top_checkbox.toggled.connect(self.toggle_always_on_top)
        filters_layout.addWidget(self._always_on_top_checkbox)

        filters_layout.addSpacing(12)

        cap_label = QLabel('Show top:')
        filters_layout.addWidget(cap_label)

        self._cap_spinbox = QSpinBox()
        self._cap_spinbox.setRange(50, 10000)
        self._cap_spinbox.setSingleStep(50)
        self._cap_spinbox.setValue(1000)
        self._cap_spinbox.setToolTip('Maximum number of players to load from session logs')
        self._cap_spinbox.editingFinished.connect(self._on_cap_changed)
        filters_layout.addWidget(self._cap_spinbox)

        filters_layout.addStretch()

        layout.addLayout(filters_layout)

        # Table
        self._model = LeaderboardTableModel()
        self._proxy = LeaderboardSortProxy()
        self._proxy.setSourceModel(self._model)

        self._table = _LeaderboardTableView()
        self._table.setModel(self._proxy)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

        header = setup_table_view_headers(self._table)
        self._table.setItemDelegate(
            SearchHighlightDelegate(
                self._table,
                self._search_box.text,
                self._get_active_search_column,
            ),
        )
        header.setStretchLastSection(False)
        for column in range(len(HEADERS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)

        setup_table_header_context_menu(self._table, on_reset=self._table.setup_static_column_resizing)

        self._stacked_widget = QStackedWidget(self)
        self._loading_widget = LeaderboardLoadingWidget(self)
        self._loading_widget.cancelled.connect(self.close)
        self._stacked_widget.addWidget(self._loading_widget)
        self._stacked_widget.addWidget(self._table)

        layout.addWidget(self._stacked_widget)

        # Sort by the Days/Sessions column descending by default. Sorting through the view (not the proxy
        # directly) sets the header's sort indicator, so the order survives model resets on data reload.
        self._table.sortByColumn(COLUMN_SESSIONS, Qt.SortOrder.DescendingOrder)

        # Data is loaded on a background thread by `load_and_show` before the window is revealed
        self._all_entries: list[LeaderboardEntry] = []
        self._baseline: LeaderboardBaseline | None = None
        self._live_session_file: Path = SESSIONS_LOGGING_PATH.with_suffix('.json')
        self._baseline_worker: LeaderboardBaselineWorker | None = None
        self._overlay_worker: LeaderboardOverlayWorker | None = None

        # Periodically re-overlays the live session onto the cached baseline while the window is visible
        self._live_timer = QTimer(self)
        self._live_timer.setInterval(_LIVE_REFRESH_INTERVAL_MS)
        self._live_timer.timeout.connect(self._on_live_tick)

        # Auto-rescan the historical baseline when older session files are added, removed, or edited
        # on disk. Filesystem-change events trigger a throttled directory walk on a background thread;
        # the live session file is excluded (it is already overlaid live), so its constant writes never
        # cause a rescan and the walk itself never runs on the GUI thread.
        self._known_signature: frozenset[tuple[str, float, int]] | None = None
        self._watched_dirs: frozenset[str] = frozenset()
        self._scan_worker: SessionFilesScanWorker | None = None
        self._scan_pending = False
        self._sessions_watcher = DebouncedFileWatcher(
            self,
            self._request_scan,
            interval_ms=_SESSIONS_SCAN_COOLDOWN_MS,
            poll_interval_ms=1000,
        )
        self._scan_cooldown = QTimer(self)
        self._scan_cooldown.setSingleShot(True)
        self._scan_cooldown.setInterval(_SESSIONS_SCAN_COOLDOWN_MS)
        self._scan_cooldown.timeout.connect(self._on_scan_cooldown_elapsed)

    def load_and_show(self) -> None:
        """Reveal the window immediately and load baseline data in the background."""
        self.show()
        self.raise_()
        self.activateWindow()
        self._start_load()

    def _request_scan(self) -> None:
        """Request a background scan now, or defer it until the cooldown elapses."""
        if not self.isVisible() or self.isMinimized():
            return
        if self._scan_cooldown.isActive():
            self._scan_pending = True
            return
        self._scan_cooldown.start()
        self._scan_session_files()

    def _on_scan_cooldown_elapsed(self) -> None:
        """Run a deferred scan if changes arrived during the cooldown window."""
        if self._scan_pending:
            self._scan_pending = False
            self._scan_cooldown.start()
            self._scan_session_files()

    def _scan_session_files(self) -> None:
        """Kick off a background inventory of the sessions directory, unless one is already running."""
        if self._scan_worker is not None:
            return
        worker = SessionFilesScanWorker(SESSIONS_LOGGING_DIR_PATH, self._live_session_file)
        worker.finished_ok.connect(self._on_session_files_scanned)
        worker.finished.connect(self._on_scan_finished)
        self._scan_worker = worker
        worker.start()

    def _on_session_files_scanned(self, result: SessionScanResult) -> None:
        """Re-arm the watcher for new directories and rescan the baseline when older files changed."""
        if result.directories != self._watched_dirs:
            self._rearm_sessions_watcher(result.directories)
        if result.signature == self._known_signature:
            return
        first_scan = self._known_signature is None
        self._known_signature = result.signature
        if first_scan:
            return  # The initial baseline already reflects the current files.
        self._reload_baseline_from_disk()

    def _rearm_sessions_watcher(self, directories: frozenset[str]) -> None:
        """Point the filesystem watcher at the current set of session directories."""
        self._sessions_watcher.watch(directories=[Path(d) for d in directories])
        self._watched_dirs = directories

    def _on_scan_finished(self) -> None:
        """Release the finished scan worker so the next request can start a fresh one."""
        self._scan_worker = None

    def _reload_baseline_from_disk(self) -> None:
        """Silently rescan the historical baseline on a background thread (no loading dialog)."""
        if self._baseline_worker is not None:
            return
        worker = LeaderboardBaselineWorker(SESSIONS_LOGGING_DIR_PATH, self._live_session_file)
        worker.finished.connect(self._clear_baseline_worker)
        worker.finished_ok.connect(self._apply_baseline)
        self._baseline_worker = worker
        worker.start()

    def _set_controls_enabled(self, *, enabled: bool) -> None:
        """Enable or disable header and filter controls while loading baseline data."""
        self._scope_combo.setEnabled(enabled)
        self._mode_combo.setEnabled(enabled)
        self._search_box.setEnabled(enabled)
        self._search_column_combo.setEnabled(enabled)
        self._hide_servers_checkbox.setEnabled(enabled)
        self._hide_vpns_checkbox.setEnabled(enabled)
        self._hide_hosting_checkbox.setEnabled(enabled)
        self._current_session_checkbox.setEnabled(enabled)
        self._relative_dates_checkbox.setEnabled(enabled)
        self._cap_spinbox.setEnabled(enabled)

    def _start_load(self, *, on_ready: Callable[[], object] | None = None) -> None:
        """Run the leaderboard scan on a worker thread behind an in-window loading view."""
        if self._baseline_worker is not None and self._baseline_worker.isRunning():
            return

        self._set_controls_enabled(enabled=False)
        self._stacked_widget.setCurrentWidget(self._loading_widget)
        self._loading_widget.reset_progress()
        self._count_label.setText('Loading...')

        worker = LeaderboardBaselineWorker(SESSIONS_LOGGING_DIR_PATH, self._live_session_file)
        worker.finished.connect(self._clear_baseline_worker)
        self._baseline_worker = worker

        worker.progress.connect(self._loading_widget.update_progress)

        def _on_finished_ok(baseline: LeaderboardBaseline) -> None:
            self._apply_baseline(baseline)
            self._stacked_widget.setCurrentWidget(self._table)
            self._set_controls_enabled(enabled=True)
            self._table.setup_static_column_resizing()
            self._table.clearSelection()
            self._table.setCurrentIndex(QModelIndex())
            if on_ready is not None:
                on_ready()

        worker.finished_ok.connect(_on_finished_ok)
        worker.start()

    def _clear_baseline_worker(self) -> None:
        """Release the finished baseline worker reference."""
        self._baseline_worker = None

    def _apply_baseline(self, baseline: LeaderboardBaseline) -> None:
        """Store a freshly-scanned baseline, render the initial overlaid leaderboard, and begin live refresh."""
        self._baseline = baseline
        connected_players, disconnected_players = PlayersRegistry.get_default_sorted_connected_and_disconnected_players()
        connected_ips = frozenset(player.ip for player in connected_players)
        disconnected_ips = frozenset(player.ip for player in disconnected_players)
        preserve_ips = connected_ips | disconnected_ips
        entries = overlay_live_session(baseline, self._live_session_file, limit=self._cap_spinbox.value(), preserve_ips=preserve_ips)
        self._all_entries = entries
        self._proxy.set_server_ips(server_ips_for(entries))
        self._proxy.set_current_session_ips(connected_ips, disconnected_ips)
        self._model.set_current_session_ips(connected_ips, disconnected_ips)
        self._model.load_data(entries)
        self._proxy.invalidateFilter()
        self._update_count_label()
        if not self._live_timer.isActive():
            self._live_timer.start()

    def _on_live_tick(self) -> None:
        """Kick off a background overlay of the live session, unless one is already running."""
        if self._baseline is None or not self.isVisible() or self.isMinimized():
            return
        if self._overlay_worker is not None:
            return
        connected_players, disconnected_players = PlayersRegistry.get_default_sorted_connected_and_disconnected_players()
        connected_ips = frozenset(player.ip for player in connected_players)
        disconnected_ips = frozenset(player.ip for player in disconnected_players)
        worker = LeaderboardOverlayWorker(
            self._baseline,
            self._live_session_file,
            self._cap_spinbox.value(),
            connected_ips=connected_ips,
            disconnected_ips=disconnected_ips,
        )
        worker.finished_ok.connect(self._on_overlay_ready)
        worker.finished.connect(self._on_overlay_finished)
        self._overlay_worker = worker
        worker.start()

    def _on_overlay_ready(self, result: OverlayResult) -> None:
        """Apply a completed background overlay to the model on the GUI thread."""
        self._all_entries = result.entries
        self._proxy.set_server_ips(result.server_ips)
        self._proxy.set_current_session_ips(result.connected_ips, result.disconnected_ips)
        self._model.set_current_session_ips(result.connected_ips, result.disconnected_ips)
        self._model.apply_live_update(result.entries)
        self._update_count_label()

    def _on_overlay_finished(self) -> None:
        """Release the finished overlay worker so the next tick can start a fresh one."""
        self._overlay_worker = None

    def _on_cap_changed(self) -> None:
        """Re-apply the display limit, re-scanning from disk only if no baseline is loaded yet."""
        if self._baseline is None:
            self._start_load()
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

    def _get_active_search_column(self) -> int:
        return SEARCH_COLUMN_TO_INDEX.get(self._search_column_combo.currentText(), -1)

    def _on_search_changed(self, text: str) -> None:
        self._proxy.set_search_text(text)
        self._update_count_label()
        viewport = self._table.viewport()
        if viewport:
            viewport.update()

    def _on_search_column_changed(self, column: str) -> None:
        self._proxy.set_search_column(column)
        self._update_count_label()
        viewport = self._table.viewport()
        if viewport:
            viewport.update()

    def _on_hide_servers_toggled(self) -> None:
        """Toggle exclusion of known game/relay server IPs and refresh the count label."""
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._proxy.set_hide_servers(hide=self._hide_servers_checkbox.isChecked())
            self._update_count_label()
        finally:
            QApplication.restoreOverrideCursor()

    def _on_hide_vpns_toggled(self) -> None:
        """Toggle exclusion of VPN/proxy IPs and refresh the count label."""
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._proxy.set_hide_vpns(hide=self._hide_vpns_checkbox.isChecked())
            self._update_count_label()
        finally:
            QApplication.restoreOverrideCursor()

    def _on_hide_hosting_toggled(self) -> None:
        """Toggle exclusion of hosting/datacenter IPs and refresh the count label."""
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._proxy.set_hide_hosting(hide=self._hide_hosting_checkbox.isChecked())
            self._update_count_label()
        finally:
            QApplication.restoreOverrideCursor()

    def _on_current_session_toggled(self) -> None:
        """Toggle filtering to players present in the active session and refresh the count label."""
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._proxy.set_current_session_only(enabled=self._current_session_checkbox.isChecked())
            self._update_count_label()
        finally:
            QApplication.restoreOverrideCursor()

    def _on_relative_dates_toggled(self) -> None:
        """Toggle relative date formatting for First Seen and Last Seen columns."""
        self._model.set_relative_dates(relative=self._relative_dates_checkbox.isChecked())

    def _show_context_menu(self, pos: QPoint) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return

        selection_model = self._table.selectionModel()
        if selection_model and not selection_model.isSelected(index):
            selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

        selected_rows = selection_model.selectedRows() if selection_model else []
        if not selected_rows:
            selected_rows = [index]

        selected_entries: list[LeaderboardEntry] = []
        for model_index in selected_rows:
            source_row = self._proxy.mapToSource(model_index).row()
            if 0 <= source_row < len(self._model.entries):
                selected_entries.append(self._model.entries[source_row])

        if not selected_entries:
            return

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        if len(selected_entries) == 1:
            entry = selected_entries[0]
            copy_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Row', self)
            copy_row_action.setShortcut('Ctrl+C')
            copy_row_action.setToolTip('Copy the selected player row to the clipboard as tab-separated text.')
            copy_row_action.triggered.connect(self._table.copy_selection)
            menu.addAction(copy_row_action)

            copy_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy All', self)
            copy_all_action.setToolTip('Copy all visible leaderboard rows to the clipboard as tab-separated text.')
            copy_all_action.setEnabled(self._proxy.rowCount() > 0)
            copy_all_action.triggered.connect(self._copy_all_rows)
            menu.addAction(copy_all_action)

            menu.addSeparator()

            usernames_text = ', '.join(entry.usernames)
            copy_usernames_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Username{pluralize(len(entry.usernames))}', self)
            copy_usernames_action.setToolTip(f'Copy the username{pluralize(len(entry.usernames))} for this player to the clipboard.')
            copy_usernames_action.setEnabled(bool(entry.usernames))
            copy_usernames_action.triggered.connect(lambda: set_clipboard_text(usernames_text))
            menu.addAction(copy_usernames_action)

            copy_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy IP', self)
            copy_ip_action.setToolTip("Copy this player's IP address to the clipboard.")
            copy_ip_action.triggered.connect(lambda: set_clipboard_text(entry.ip))
            menu.addAction(copy_ip_action)
        else:
            all_usernames = [username for entry in selected_entries for username in entry.usernames]
            all_ips = [entry.ip for entry in selected_entries]

            copy_rows_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Rows ({len(selected_entries)})', self)
            copy_rows_action.setShortcut('Ctrl+C')
            copy_rows_action.setToolTip('Copy the selected player rows to the clipboard as tab-separated text.')
            copy_rows_action.triggered.connect(self._table.copy_selection)
            menu.addAction(copy_rows_action)

            copy_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy All', self)
            copy_all_action.setToolTip('Copy all visible leaderboard rows to the clipboard as tab-separated text.')
            copy_all_action.setEnabled(self._proxy.rowCount() > 0)
            copy_all_action.triggered.connect(self._copy_all_rows)
            menu.addAction(copy_all_action)

            add_copy_usernames_and_ips_actions(menu, self, all_usernames, all_ips)

        menu.addSeparator()

        select_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')), 'Select All', self)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip('Select all rows in the leaderboard.')
        select_all_action.setEnabled(self._proxy.rowCount() > 0)
        select_all_action.triggered.connect(self._table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')), 'Clear Selection', self)
        clear_selection_action.setToolTip('Deselect all currently selected rows.')
        clear_selection_action.triggered.connect(self._table.clearSelection)
        menu.addAction(clear_selection_action)

        menu.addSeparator()

        if len(selected_entries) == 1:
            entry = selected_entries[0]

            lookup_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'IP Lookup Details…', self)
            lookup_action.setToolTip('Show detailed IP lookup information for this player.')
            lookup_action.triggered.connect(lambda _checked=False, ip_address=entry.ip: show_detailed_ip_lookup(self, ip_address))
            menu.addAction(lookup_action)

            create_ping_menu(self, menu, [entry.ip])

            menu.addSeparator()

            seen_stats_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'View Seen Stats', self)
            seen_stats_action.setToolTip('Show a breakdown of how many days and sessions this player has appeared in.')
            seen_stats_action.triggered.connect(lambda: self._show_seen_stats_for_entry(entry))
            menu.addAction(seen_stats_action)
        else:
            all_ips = [entry.ip for entry in selected_entries]
            create_ping_menu(self, menu, all_ips)

            scan_ports_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'port_scanner.svg')), 'Scan Ports…', self)
            scan_ports_action.setToolTip('Scan TCP and UDP ports on the selected host(s).')

            def _scan_all_leaderboard() -> None:
                scan_ports_ip(all_ips)

            scan_ports_action.triggered.connect(_scan_all_leaderboard)
            menu.addAction(scan_ports_action)

        popup_menu_at_table(menu, self._table, pos)

    def _copy_all_rows(self) -> None:
        """Copy all visible rows in the leaderboard to clipboard as tab-separated text."""
        copy_table_all_rows(self._table)

    def _show_seen_stats_for_entry(self, entry: LeaderboardEntry) -> None:
        _build_seen_stats_dialog(entry, self).exec()

    def _update_count_label(self) -> None:
        visible = self._proxy.rowCount()
        total = len(self._all_entries)
        if self._current_session_checkbox.isChecked():
            session_total = len(self._proxy.current_session_ips)
            self._count_label.setText(f'{visible} of {session_total} session players ({total} total)')
        else:
            self._count_label.setText(f'{visible} of {total} players')

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if consume_maximize_on_show(self):
            self.showMaximized()
        self._request_scan()

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop live refresh and wait for any in-flight workers before the window is destroyed."""
        self._scan_cooldown.stop()
        self._live_timer.stop()
        self._sessions_watcher.stop()
        if self._scan_worker is not None and self._scan_worker.isRunning():
            self._scan_worker.cancel()
        self._scan_worker = None
        if self._baseline_worker is not None and self._baseline_worker.isRunning():
            self._baseline_worker.cancel()
        self._baseline_worker = None
        if self._overlay_worker is not None and self._overlay_worker.isRunning():
            self._overlay_worker.cancel()
        self._overlay_worker = None
        super().closeEvent(event)
