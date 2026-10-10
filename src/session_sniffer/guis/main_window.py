"""Main window implementation for Session Sniffer."""

import logging
import sys
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QCloseEvent, QIcon, QKeySequence, QShortcut, QShowEvent
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QMenuBar,
    QSplitter,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.background import clear_resolution_queues, wake_all_player_cores
from session_sniffer.background.events import gui_closed__event
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import terminate_script
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis._main_header import SessionHeader
from session_sniffer.guis._main_window_files_mixin import FilesMixin
from session_sniffer.guis._main_window_game_mixin import GameMixin
from session_sniffer.guis._main_window_looky_mixin import LookyMixin
from session_sniffer.guis._main_window_stats_mixin import StatsMixin
from session_sniffer.guis._session_table_section import SessionStatusBar, SessionTableSection
from session_sniffer.guis.discord_intro import DiscordIntro
from session_sniffer.guis.ping_window import PingWindow
from session_sniffer.guis.player_resolver import PlayerResolverWindow
from session_sniffer.guis.port_scanner_window import PortScannerWindow
from session_sniffer.guis.settings_dialog import SettingsDialog
from session_sniffer.guis.stylesheets import MENU_BAR_STYLESHEET
from session_sniffer.guis.tables_player_actions.looky_system._looky_crawler_request_dialog import close_all_crawler_dialogs
from session_sniffer.guis.tables_player_actions.looky_system._looky_lookup_dialog import close_all_lookup_dialogs
from session_sniffer.guis.utils import (
    apply_always_on_top,
    consume_maximize_on_show,
    render_svg_pixmap_from_resource,
    resize_window_for_screen,
    scale_by_ui,
    show_or_focus_window,
)
from session_sniffer.guis.worker_thread import GUIWorkerThread
from session_sniffer.models import GUIState
from session_sniffer.player.registry import PlayersRegistry, SessionHost, SessionTracker
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.status_bar_renderer import build_gui_status_text, reset_status_bar_latency
from session_sniffer.rendering_core.types import (
    CaptureStats,
    GUIRenderingState,
    GUIUpdatePayload,
    PaginationState,
    SearchState,
    SessionFilterState,
    TableMergeState,
)
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _MenuActions:
    """Menu bar QAction references."""

    toggle_capture: QAction
    change_interface: QAction


@dataclass(slots=True)
class _WindowState:
    """Mutable runtime state for the main window."""

    worker_thread: GUIWorkerThread
    window_being_moved: bool
    min_accepted_snapshot_version: int


class _MinimizedTablesPlaceholder(QWidget):
    """Placeholder displayed in the center when all session tables are minimized."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(scale_by_ui(6))

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_size = scale_by_ui(42)
        pixmap = render_svg_pixmap_from_resource('sonar.svg', icon_size, icon_size)
        icon_label.setPixmap(pixmap)
        layout.addWidget(icon_label)

        title_label = QLabel('All Tables Minimized')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet('color: #94a3b8; font-size: 11pt; font-weight: 600;')
        layout.addWidget(title_label)

        subtitle_label = QLabel('Expand connected or disconnected players below to view session data')
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet('color: #475569; font-size: 9pt;')
        layout.addWidget(subtitle_label)


class MainWindow(LookyMixin, GameMixin, StatsMixin, FilesMixin, QMainWindow):
    """Main Qt window that hosts session tables and control UI."""

    _actions: _MenuActions
    _connected: SessionTableSection
    _disconnected: SessionTableSection
    _placeholder: _MinimizedTablesPlaceholder
    _tables_splitter: QSplitter
    _saved_splitter_sizes: list[int]
    _discord_intro_window: DiscordIntro | None
    _detections_manager_window: DetectionsManagerDialog | None
    _userip_manager_window: UserIPDatabasesManager | None

    def _on_splitter_moved(self, _position: int, _index: int) -> None:
        selected_session = SessionFilterState.get_selected_session()
        is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
        if not is_past_session and self._connected.is_expanded and self._disconnected.is_expanded:
            self._saved_splitter_sizes = self._tables_splitter.sizes()

    def _on_session_filter_changed(self, _session_id: int) -> None:
        self._update_splitter_visibility()

    def _update_splitter_visibility(self) -> None:
        self._connected.update_disconnected_players_state()
        self._disconnected.update_disconnected_players_state()
        is_merged = TableMergeState.is_merged()
        self._header.set_search_placeholder_merged(is_merged=is_merged)
        selected_session = SessionFilterState.get_selected_session()
        is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
        if is_past_session:
            self._connected.setVisible(False)
            self._connected.expand_button.setVisible(False)
            self._connected.collapse_button.setVisible(False)
            self._disconnected.collapse_button.setVisible(False)
            self._disconnected.expand_button.setVisible(False)
            self._disconnected.setVisible(True)
            self._tables_splitter.setVisible(True)
            self._placeholder.setVisible(False)
            self._tables_splitter.setSizes([0, 10000])
            return

        if is_merged:
            self._disconnected.setVisible(False)
            self._disconnected.expand_button.setVisible(False)
            self._connected.collapse_button.setVisible(False)
            self._connected.expand_button.setVisible(False)
            self._connected.setVisible(True)
            self._tables_splitter.setVisible(True)
            self._placeholder.setVisible(False)
            return

        self._connected.collapse_button.setVisible(True)
        self._disconnected.collapse_button.setVisible(True)
        connected_expanded = self._connected.is_expanded
        disconnected_expanded = self._disconnected.is_expanded
        self._connected.setVisible(connected_expanded)
        self._connected.expand_button.setVisible(not connected_expanded)
        self._disconnected.setVisible(disconnected_expanded)
        self._disconnected.expand_button.setVisible(not disconnected_expanded)

        both_minimized = not connected_expanded and not disconnected_expanded
        self._tables_splitter.setVisible(not both_minimized)
        self._placeholder.setVisible(both_minimized)

        if connected_expanded and disconnected_expanded and self.isVisible():
            if self._saved_splitter_sizes:
                total_height = sum(self._tables_splitter.sizes())
                saved_total = sum(self._saved_splitter_sizes)
                if saved_total > 0 and total_height > 0:
                    ratio = self._saved_splitter_sizes[0] / saved_total
                    connected_size = int(total_height * ratio)
                    disconnected_size = total_height - connected_size
                    self._tables_splitter.setSizes([connected_size, disconnected_size])
            else:
                total_height = sum(self._tables_splitter.sizes())
                if total_height > 0:
                    half_height = total_height // 2
                    self._tables_splitter.setSizes([half_height, total_height - half_height])

    def _toggle_tables_merged(self) -> None:
        """Toggle merging connected and disconnected tables on the fly."""
        TableMergeState.toggle()
        self._update_splitter_visibility()
        self._connected.table_view.viewport().update()
        self._disconnected.table_view.viewport().update()

    def __init__(
        self,
        screen_size: tuple[int, int],
        capture_holder: CaptureHolder,
        on_change_interface: Callable[[], None],
        on_open_hotspot: Callable[[], None],
    ) -> None:
        """Initialize the main application window.

        Args:
            screen_size: Primary screen dimensions as (width, height) in pixels.
            capture_holder: Mutable reference to the active packet capture instance.
            on_change_interface: Callback invoked when the user requests an interface switch.
            on_open_hotspot: Callback invoked when the user requests the hotspot manager.
        """
        super().__init__()

        self.capture = capture_holder
        self._on_change_interface = on_change_interface
        self._on_open_hotspot = on_open_hotspot
        self._player_resolver_window = PlayerResolverWindow(self._select_connected_ips, self._deselect_connected_ips)
        self._detections_manager_window = None
        self._logs_manager_window = None
        self._settings_dialog_window: SettingsDialog | None = None
        self._userip_manager_window = None
        self._discord_intro_window: DiscordIntro | None = None
        self._leaderboard_window = None
        self._session_rate_graph_window = None
        self._session_pps_graph_window = None
        self._session_bps_graph_window = None
        self._packets_latency_graph_window = None
        self._country_breakdown_window = None
        self._reconnect_frequency_window = None
        self._session_timeline_window = None
        self._port_heatmap_window = None
        self._session_duration_window = None
        self._capture_statistics_window = None

        self.setWindowTitle(TITLE)
        self.setMinimumSize(scale_by_ui(1024), scale_by_ui(600))
        resize_window_for_screen(self, screen_size)
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowMinMaxButtonsHint | Qt.WindowType.WindowCloseButtonHint)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        menu_bar = self.menuBar()
        if not menu_bar:
            message = 'Failed to get menu bar'
            raise RuntimeError(message)
        menu_bar.setStyleSheet(MENU_BAR_STYLESHEET)

        self._actions = self._build_capture_menu(menu_bar)
        self._build_game_menu(menu_bar)
        self._update_game_toolbar_visibility()
        self._build_tools_menu(menu_bar)
        self._build_statistics_menu(menu_bar)
        self._build_data_menu(menu_bar)
        self._build_settings_menu(menu_bar)
        self._build_help_menu(menu_bar)

        self._header = SessionHeader(self)
        self._header.search_changed.connect(self._on_global_search_changed)

        search_shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        search_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        search_shortcut.activated.connect(self._header.focus_search)

        merge_shortcut = QShortcut(QKeySequence('Ctrl+M'), self)
        merge_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        merge_shortcut.activated.connect(self._toggle_tables_merged)

        connected_column_names = [
            column for column in Settings.GUI_ALL_CONNECTED_COLUMNS if column in set(Settings.gui_columns_connected_shown) or column in Settings.GUI_FORCED_COLUMNS
        ]
        self._connected = SessionTableSection(
            is_connected=True,
            column_names=connected_column_names,
            clear_slot=self._clear_connected_players,
            merge_slot=self._toggle_tables_merged,
            parent=self,
        )
        self._connected.table_view.open_rate_graph_callback = self._player_resolver_window.high_rate_monitor.open_graph
        self._connected.table_view.blacklist_high_rate_callback = self._player_resolver_window.high_rate_monitor.blacklist_ips
        self._connected.table_view.unblacklist_high_rate_callback = self._player_resolver_window.high_rate_monitor.unblacklist_ips
        self._connected.table_view.is_high_rate_blacklisted_callback = self._player_resolver_window.high_rate_monitor.is_ip_blacklisted

        self._saved_splitter_sizes = []

        disconnected_column_names = [
            column for column in Settings.GUI_ALL_DISCONNECTED_COLUMNS if column in set(Settings.gui_columns_disconnected_shown) or column in Settings.GUI_FORCED_COLUMNS
        ]
        self._disconnected = SessionTableSection(
            is_connected=False,
            column_names=disconnected_column_names,
            clear_slot=self._clear_disconnected_players,
            merge_slot=self._toggle_tables_merged,
            parent=self,
        )
        self._disconnected.table_view.blacklist_high_rate_callback = self._player_resolver_window.high_rate_monitor.blacklist_ips
        self._disconnected.table_view.unblacklist_high_rate_callback = self._player_resolver_window.high_rate_monitor.unblacklist_ips
        self._disconnected.table_view.is_high_rate_blacklisted_callback = self._player_resolver_window.high_rate_monitor.is_ip_blacklisted

        self._tables_splitter = QSplitter(Qt.Orientation.Vertical, self)
        self._tables_splitter.setChildrenCollapsible(False)
        self._tables_splitter.setHandleWidth(scale_by_ui(6))
        self._tables_splitter.addWidget(self._connected)
        self._tables_splitter.addWidget(self._disconnected)
        self._tables_splitter.setStretchFactor(0, 1)
        self._tables_splitter.setStretchFactor(1, 1)
        self._tables_splitter.splitterMoved.connect(self._on_splitter_moved)

        self._placeholder = _MinimizedTablesPlaceholder(self)
        self._placeholder.setVisible(False)

        self._status_bar = SessionStatusBar(self)
        self.setStatusBar(self._status_bar)

        main_layout.addSpacing(4)
        main_layout.addWidget(self._header)
        main_layout.addSpacing(6)
        main_layout.addWidget(self._tables_splitter, 1)
        main_layout.addWidget(self._placeholder, 1)
        main_layout.addWidget(self._connected.expand_button)
        main_layout.addWidget(self._disconnected.expand_button)

        self._connected.section_toggled.connect(self._update_splitter_visibility)
        self._connected.session_filter_changed.connect(self._on_session_filter_changed)
        self._disconnected.section_toggled.connect(self._update_splitter_visibility)
        self._disconnected.session_filter_changed.connect(self._on_session_filter_changed)

        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            if (
                gui_state.main_window_splitter_sizes is not None
                and gui_state.main_window_splitter_sizes
                and len(gui_state.main_window_splitter_sizes) == self._tables_splitter.count()
                and all(size > 0 for size in gui_state.main_window_splitter_sizes)
            ):
                self._saved_splitter_sizes = list(gui_state.main_window_splitter_sizes)
                self._tables_splitter.setSizes(self._saved_splitter_sizes)

            if gui_state.connected_table_column_widths is not None and gui_state.connected_table_column_widths:
                self._connected.table_view.apply_column_widths(gui_state.connected_table_column_widths)

            if gui_state.disconnected_table_column_widths is not None and gui_state.disconnected_table_column_widths:
                self._disconnected.table_view.apply_column_widths(gui_state.disconnected_table_column_widths)

        self._update_splitter_visibility()

        self.raise_()
        self.activateWindow()

        worker_thread = GUIWorkerThread()
        self._state = _WindowState(
            worker_thread=worker_thread,
            window_being_moved=False,
            min_accepted_snapshot_version=0,
        )
        self._state.worker_thread.update_signal.connect(self._update_gui)
        self._state.worker_thread.start()

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(1_000)
        self._stats_timer.timeout.connect(self._tick_stats)
        self._stats_timer.start()

        self._thread_health_timer = QTimer(self)
        self._thread_health_timer.setInterval(30_000)
        self._thread_health_timer.timeout.connect(self._log_thread_health)
        self._thread_health_timer.start()
        self._last_thread_health_state: tuple[int, int, tuple[tuple[str, str], ...]] | None = None

        self._apply_always_on_top()

        self._update_header_capture_status()
        self._update_status_bar()

    def _build_capture_menu(self, menu_bar: QMenuBar) -> _MenuActions:
        """Build the Capture menu and return key action references."""
        capture_menu = menu_bar.addMenu('Capture')
        if not capture_menu:
            message = 'Failed to create Capture menu'
            raise RuntimeError(message)
        capture_menu.setToolTipsVisible(True)

        toggle_capture_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')), 'Stop Capture', self)
        toggle_capture_action.setToolTip('Stop packet capture')
        toggle_capture_action.triggered.connect(self._toggle_capture)
        capture_menu.addAction(toggle_capture_action)

        capture_menu.addSeparator()

        change_interface_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), 'Change Interface', self)
        change_interface_action.setToolTip('Stop capture, select a different network interface, and restart capture')
        change_interface_action.triggered.connect(self._on_change_interface)
        capture_menu.addAction(change_interface_action)

        hotspot_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'wifi.svg')), 'Hotspot && Sharing', self)
        hotspot_action.setToolTip('Create a Wi-Fi hotspot or configure Internet Connection Sharing (ICS) to capture console traffic')
        hotspot_action.triggered.connect(self._open_hotspot_manager)
        capture_menu.addAction(hotspot_action)

        return _MenuActions(
            toggle_capture=toggle_capture_action,
            change_interface=change_interface_action,
        )

    def _build_tools_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Tools menu and attach tool launcher actions."""
        tools_menu = menu_bar.addMenu('Tools')
        if not tools_menu:
            message = 'Failed to create Tools menu'
            raise RuntimeError(message)
        tools_menu.setToolTipsVisible(True)

        detections_manager_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'shield.svg')), 'Detections Manager', self)
        detections_manager_action.setToolTip('Configure detection, notifications, and protection rules')
        detections_manager_action.triggered.connect(self._open_detections_manager)
        tools_menu.addAction(detections_manager_action)

        userip_manager_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')), 'UserIP Manager', self)
        userip_manager_action.setToolTip('Browse, edit, add, and delete entries in UserIP database files')
        userip_manager_action.triggered.connect(self._open_userip_manager)
        tools_menu.addAction(userip_manager_action)

        logs_manager_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), 'Logs Manager', self)
        logs_manager_action.setToolTip('View, search, filter, and manage application log files')
        logs_manager_action.triggered.connect(self._open_logs_manager)
        tools_menu.addAction(logs_manager_action)

        tools_menu.addSeparator()

        leaderboard_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'trophy.svg')), 'Most Seen Players', self)
        leaderboard_action.setToolTip('View a leaderboard of the most frequently seen players across sessions')
        leaderboard_action.triggered.connect(self._open_player_leaderboard)
        tools_menu.addAction(leaderboard_action)

        port_scanner_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'port_scanner.svg')), 'Port Scanner', self)
        port_scanner_action.setToolTip('Perform multi-threaded TCP and UDP port scanning with service banner detection')
        port_scanner_action.triggered.connect(self._open_port_scanner)
        tools_menu.addAction(port_scanner_action)

        ping_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'Ping Diagnostics', self)
        ping_action.setToolTip('Send ICMP echo, TCP connect, UDP reachability, or Web latency probes')
        ping_action.triggered.connect(self._open_ping_diagnostics)
        tools_menu.addAction(ping_action)

    def _build_settings_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Settings menu."""
        settings_menu = menu_bar.addMenu('Settings')
        if not settings_menu:
            message = 'Failed to create Settings menu'
            raise RuntimeError(message)
        settings_menu.setToolTipsVisible(True)

        open_settings_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'Open Settings', self)
        open_settings_action.setToolTip('View and edit all application settings')
        open_settings_action.triggered.connect(self._open_settings_dialog)
        settings_menu.addAction(open_settings_action)

    def show_discord_intro(self) -> None:
        """Open the Discord intro dialog, retaining a reference to prevent garbage collection."""
        show_or_focus_window(self, '_discord_intro_window', DiscordIntro)

    @override
    def eventFilter(self, a0: QObject, a1: QEvent) -> bool:
        """Filter events to detect window movement."""
        if not isValid(a0):
            return False
        if a0 == self and a1:
            event_type = a1.type()

            if event_type in (QEvent.Type.Move, QEvent.Type.Resize, QEvent.Type.WindowStateChange) and not self._state.window_being_moved:
                self._start_window_move()

            elif (
                event_type
                in (
                    QEvent.Type.WindowActivate,
                    QEvent.Type.WindowDeactivate,
                    QEvent.Type.NonClientAreaMouseButtonRelease,
                    QEvent.Type.Enter,
                    QEvent.Type.HoverEnter,
                )
                and self._state.window_being_moved
            ):
                self._end_window_move()

        return super().eventFilter(a0, a1)

    def _start_window_move(self) -> None:
        """Apply transparency when window movement/dragging starts."""
        self._state.window_being_moved = True
        if sys.platform == 'win32':
            self.setWindowOpacity(0.85)
        self._header.setEnabled(False)
        self._connected.set_all_enabled(enabled=False)
        self._disconnected.set_all_enabled(enabled=False)
        self._tables_splitter.setEnabled(False)
        status_bar = self.statusBar()
        if not status_bar:
            return
        status_bar.setEnabled(False)

    def _end_window_move(self) -> None:
        """Restore opacity and re-enable UI elements after window movement/dragging ends."""
        self._state.window_being_moved = False
        if sys.platform == 'win32':
            self.setWindowOpacity(1.0)
        self._header.setEnabled(True)
        self._connected.set_all_enabled(enabled=True)
        self._disconnected.set_all_enabled(enabled=True)
        self._tables_splitter.setEnabled(True)
        status_bar = self.statusBar()
        if not status_bar:
            return
        status_bar.setEnabled(True)

    def _log_thread_health(self) -> None:
        """Periodically log thread health and active workers when thread state changes."""
        active_qthreads = CrashingQThread.get_active_threads()
        running_qthreads = sorted([(thread.thread_name, thread.cpp_ptr) for thread in active_qthreads if thread.isRunning()])
        active_python_threads = threading.active_count()
        current_state = (active_python_threads, len(active_qthreads), tuple(running_qthreads))
        if current_state == self._last_thread_health_state:
            return

        self._last_thread_health_state = current_state
        logger.debug(
            'Thread health check: %d active Python threads, %d tracked QThreads (%s running)',
            active_python_threads,
            len(active_qthreads),
            running_qthreads,
        )

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Handle the main window close event and terminate background work."""
        self._thread_health_timer.stop()
        self._stats_timer.stop()
        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            selected_session = SessionFilterState.get_selected_session()
            is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
            if not is_past_session and self._connected.is_expanded and self._disconnected.is_expanded:
                current_sizes = self._tables_splitter.sizes()
                if sum(current_sizes) > 0:
                    gui_state.main_window_splitter_sizes = current_sizes
            elif self._saved_splitter_sizes:
                gui_state.main_window_splitter_sizes = self._saved_splitter_sizes

            if self._connected.table_view.has_custom_column_widths:
                gui_state.connected_table_column_widths = self._connected.table_view.get_column_widths()
            else:
                gui_state.connected_table_column_widths = None

            if self._disconnected.table_view.has_custom_column_widths:
                gui_state.disconnected_table_column_widths = self._disconnected.table_view.get_column_widths()
            else:
                gui_state.disconnected_table_column_widths = None

            gui_state.save()

        logger.debug('MainWindow closeEvent received')
        gui_closed__event.set()
        GUIRenderingState.wake()
        wake_all_player_cores()
        logger.debug('MainWindow closeEvent: closing child windows')
        self._player_resolver_window.close()
        if self._settings_dialog_window is not None:
            self._settings_dialog_window.close()
        if self._userip_manager_window is not None:
            self._userip_manager_window.close()
        if self._logs_manager_window is not None:
            self._logs_manager_window.close()
        if self._detections_manager_window is not None:
            self._detections_manager_window.close()
        if self._leaderboard_window is not None:
            self._leaderboard_window.close()

        PingWindow.close_window()
        PortScannerWindow.close_window()

        close_all_crawler_dialogs()
        close_all_lookup_dialogs()
        if self.capture.is_running():
            logger.debug('MainWindow closeEvent: stopping packet capture')
            self.capture.stop()
        GTASuspendManager.shutdown()
        logger.debug('MainWindow closeEvent: stopping all active CrashingQThreads')
        CrashingQThread.stop_all_active_threads()
        logger.debug('MainWindow closeEvent: all active threads stopped, terminating script')
        if a0 is not None:
            a0.accept()
        terminate_script('EXIT')

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event, maximize if required, and restore table splitter layout."""
        super().showEvent(a0)
        if consume_maximize_on_show(self):
            self.showMaximized()
        self._update_splitter_visibility()

    def _open_port_scanner(self) -> None:
        """Open the Port Scanner tool window."""
        PortScannerWindow.open_window()

    def _open_ping_diagnostics(self) -> None:
        """Open the Ping Diagnostics tool window."""
        PingWindow.open_window()

    @Slot(object)
    def _update_gui(self, payload: GUIUpdatePayload) -> None:
        if not isValid(self) or gui_closed__event.is_set():
            return
        if payload.snapshot_version < self._state.min_accepted_snapshot_version:
            return

        self._sync_capture_toggle_action()
        self._header.set_capture_running(is_running=self.capture.is_running())
        self._status_bar.set_texts(
            capture=payload.status_capture_text,
            config=payload.status_config_text,
            issues=payload.status_issues_text,
            performance=payload.status_performance_text,
        )

        if payload.column_config.connected_column_names != self._connected.table_model.column_names:
            self._connected.update_columns(payload.column_config.connected_column_names)
        if payload.column_config.disconnected_column_names != self._disconnected.table_model.column_names:
            self._disconnected.update_columns(payload.column_config.disconnected_column_names)

        connected_count_changed = self._connected.last_count != payload.connected_count
        disconnected_count_changed = self._disconnected.last_count != payload.disconnected_count

        if connected_count_changed:
            self._connected.update_current_count(payload.connected_count)

        if disconnected_count_changed:
            self._disconnected.update_current_count(payload.disconnected_count)

        self._connected.table_view.capture_selection()
        self._disconnected.table_view.capture_selection()

        connected_table_changed = self._connected.table_model.sync_rows(payload.connected_rows_with_colors)
        if self._connected.table_view.isVisible() and (connected_table_changed or connected_count_changed):
            self._connected.table_view.check_initial_data_column_sizing()

        disconnected_table_changed = self._disconnected.table_model.sync_rows(payload.disconnected_rows_with_colors)
        if self._disconnected.table_view.isVisible() and (disconnected_table_changed or disconnected_count_changed):
            self._disconnected.table_view.check_initial_data_column_sizing()

        self._connected.table_view.restore_selection()
        self._disconnected.table_view.restore_selection()

        self._connected.refresh_selection_count()
        self._disconnected.refresh_selection_count()

        self._connected.sync_paging_from_payload(
            total_count=payload.connected_count,
            rows_per_page=payload.connected_rows_per_page,
            page=payload.connected_page,
        )
        self._disconnected.sync_paging_from_payload(
            total_count=payload.disconnected_count,
            rows_per_page=payload.disconnected_rows_per_page,
            page=payload.disconnected_page,
        )

        self._sync_game_status()
        if Settings.is_gta5_feature_set():
            self._update_looky_actions()

        if self._capture_statistics_window is not None and self._capture_statistics_window.isVisible():
            self._capture_statistics_window.refresh()

    def _apply_always_on_top(self) -> None:
        """Apply the always-on-top setting to the main window."""
        apply_always_on_top(self, checked=Settings.gui_always_on_top)

    def _apply_table_settings(self) -> None:
        """Apply configured table sort, pagination, and column settings to connected and disconnected tables."""
        changed = self._settings_dialog_window.changed_settings if self._settings_dialog_window is not None else None
        self._connected.apply_sort_from_settings()
        self._disconnected.apply_sort_from_settings()
        self._connected.apply_pagination_from_settings()
        self._disconnected.apply_pagination_from_settings()
        self._connected.apply_columns_from_settings(changed)
        self._disconnected.apply_columns_from_settings(changed)

    def _sync_player_resolver_settings(self) -> None:
        """Synchronize Player Resolver background monitoring and refresh session table icons."""
        self._player_resolver_window.high_rate_monitor.apply_settings()
        self._player_resolver_window.player_identifier.apply_settings()
        if Settings.high_rate_monitor_run_in_background:
            self._player_resolver_window.high_rate_monitor.start_monitoring()
        elif not self._player_resolver_window.isVisible():
            self._player_resolver_window.high_rate_monitor.stop_monitoring()
        self._connected.table_view.viewport().update()
        self._disconnected.table_view.viewport().update()

    def _apply_userip_settings(self) -> None:
        """Apply UserIP settings changes such as known alts synchronization."""
        changed = self._settings_dialog_window.changed_settings if self._settings_dialog_window is not None else None
        if changed is None or 'USERIP_SYNC_KNOWN_ALTS' in changed:
            UserIPDatabases.build()
            self._connected.table_view.viewport().update()
            self._disconnected.table_view.viewport().update()

    def _open_settings_dialog(self) -> None:
        """Open the Settings window, or focus the existing one."""

        def _factory() -> SettingsDialog:
            window = SettingsDialog(None, self.capture.get(), self._on_change_interface)
            for callback in (
                TableMergeState.reset_override,
                self._update_game_toolbar_visibility,
                self._apply_always_on_top,
                self._update_splitter_visibility,
                self._apply_table_settings,
                self._sync_player_resolver_settings,
                self._apply_userip_settings,
            ):
                window.accepted.connect(callback)
            return window

        show_or_focus_window(self, '_settings_dialog_window', _factory)

    def _on_global_search_changed(self, text: str, column_name: str) -> None:
        """Update global search state across connected and disconnected tables."""
        SearchState.set_search(text, column_name)
        PaginationState.set_connected_page(1)
        PaginationState.set_disconnected_page(1)
        self._connected.table_view.viewport().update()
        self._disconnected.table_view.viewport().update()

    def _update_header_capture_status(self) -> None:
        """Immediately update the header to reflect current capture state."""
        self._header.set_capture_running(is_running=self.capture.is_running())

    def _update_status_bar(self) -> None:
        """Immediately render the status bar with current capture state."""
        capture_section, config_section, issues_section, performance_section = build_gui_status_text(
            capture=self.capture.get(),
            discord_rpc_manager=None,
        )
        self._status_bar.set_texts(
            capture=capture_section,
            config=config_section,
            issues=issues_section,
            performance=performance_section,
        )

    def _sync_capture_toggle_action(self) -> None:
        """Synchronize the toggle capture action icon, text, and tooltip with the current capture state."""
        is_running = self.capture.is_running()
        expected_text = 'Stop Capture' if is_running else 'Start Capture'
        if self._actions.toggle_capture.text() == expected_text:
            return

        if is_running:
            self._actions.toggle_capture.setText('Stop Capture')
            self._actions.toggle_capture.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')))
            self._actions.toggle_capture.setToolTip('Stop packet capture')
        else:
            self._actions.toggle_capture.setText('Start Capture')
            self._actions.toggle_capture.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._actions.toggle_capture.setToolTip('Start packet capture')

    def _toggle_capture(self) -> None:
        """Toggle the packet capture on/off."""
        if self.capture.is_running():
            self.capture.stop()
        else:
            self.capture.start()

        self._sync_capture_toggle_action()
        self._update_header_capture_status()
        self._update_status_bar()

    def set_interface_switching_mode(self, *, switching: bool) -> None:
        """Disable or re-enable the UI while an interface switch is in progress."""
        menu_bar = self.menuBar()
        if menu_bar:
            menu_bar.setEnabled(not switching)
        self._actions.change_interface.setEnabled(not switching)
        self._connected.set_all_enabled(enabled=not switching)
        self._disconnected.set_all_enabled(enabled=not switching)
        self._tables_splitter.setEnabled(not switching)
        status_bar = self.statusBar()
        if status_bar:
            status_bar.setEnabled(not switching)

    def set_change_interface_button_enabled(self, *, enabled: bool) -> None:
        """Enable or disable only the Change Interface toolbar button."""
        self._actions.change_interface.setEnabled(enabled)

    def reset_players_for_interface_switch(self) -> None:
        """Clear all player data in preparation for a new capture interface."""
        self._clear_connected_players()
        self._clear_disconnected_players()
        clear_resolution_queues()
        SessionHost.clear_history()
        SessionHost.players_pending_for_disconnection.clear()

    def set_capture_toggle_enabled(self, *, enabled: bool) -> None:
        """Enable or disable the Stop/Start Capture toolbar button."""
        self._actions.toggle_capture.setEnabled(enabled)

    def on_interface_switched(self) -> None:
        """Synchronize GUI state after the capture interface has been replaced."""
        self._update_game_toolbar_visibility()
        self._sync_capture_toggle_action()
        self._actions.toggle_capture.setEnabled(True)
        self._update_header_capture_status()
        self._update_status_bar()
        wake_all_player_cores()

    def _clear_connected_players(self) -> None:
        """Clear all connected players from the table and registry."""
        self._state.min_accepted_snapshot_version = GUIRenderingState.get_version() + 1
        connected_players = PlayersRegistry.get_default_sorted_players(include_connected=True, include_disconnected=False)
        connected_ips = {player.ip for player in connected_players}

        PlayersRegistry.clear_connected_players()
        SessionHost.players_pending_for_disconnection.clear()
        self._connected.clear_table()

        if connected_ips:
            for ip in connected_ips:
                GTASuspendManager.release_reasons_for_ip(ip)
                RDR2SuspendManager.release_reasons_for_ip(ip)

        if TableMergeState.is_merged():
            self._clear_disconnected_players()
        else:
            self.recalculate_capture_stats()

    def _clear_disconnected_players(self) -> None:
        """Clear all disconnected players from the table and registry."""
        self._state.min_accepted_snapshot_version = GUIRenderingState.get_version() + 1
        disconnected_players = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        disconnected_ips = {player.ip for player in disconnected_players}

        PlayersRegistry.clear_disconnected_players()
        SessionHost.players_pending_for_disconnection = [player for player in SessionHost.players_pending_for_disconnection if player.ip not in disconnected_ips]
        self._disconnected.clear_table()

        if disconnected_ips:
            for ip in disconnected_ips:
                GTASuspendManager.release_reasons_for_ip(ip)
                RDR2SuspendManager.release_reasons_for_ip(ip)

        self.recalculate_capture_stats()

    @override
    def recalculate_capture_stats(self) -> None:
        """Recalculate capture statistics from currently remaining players in registry."""
        total_remaining = PlayersRegistry.get_total_count()
        if not total_remaining:
            self.reset_capture_stats()
            return

        CaptureStats.recalculate_total_packets()
        if not PlayersRegistry.get_connected_count():
            CaptureStats.global_bandwidth = 0
            CaptureStats.global_download = 0
            CaptureStats.global_upload = 0
            CaptureStats.global_bps_rate = 0
            CaptureStats.global_bpm_rate = 0
            CaptureStats.global_pps_rate = 0

        uptime = max(0, int(time.monotonic() - CaptureStats.capture_started_at)) if self.capture.is_running() and CaptureStats.capture_started_at > 0 else 0
        self._header.update_stats(uptime_seconds=uptime, total_packets=CaptureStats.total_packets_captured)
        self._update_status_bar()
        if self._capture_statistics_window is not None and self._capture_statistics_window.isVisible():
            self._capture_statistics_window.refresh()
        if self._session_timeline_window is not None and self._session_timeline_window.isVisible():
            self._session_timeline_window.refresh()
        if self._country_breakdown_window is not None and self._country_breakdown_window.isVisible():
            self._country_breakdown_window.refresh()
        if self._reconnect_frequency_window is not None and self._reconnect_frequency_window.isVisible():
            self._reconnect_frequency_window.refresh()
        if self._port_heatmap_window is not None and self._port_heatmap_window.isVisible():
            self._port_heatmap_window.refresh()
        if self._session_duration_window is not None and self._session_duration_window.isVisible():
            self._session_duration_window.refresh()

    @override
    def reset_capture_stats(self) -> None:
        """Reset capture statistics, graphs, header counters, and open stats windows."""
        CaptureStats.reset_capture_stats()
        reset_status_bar_latency()
        uptime = max(0, int(time.monotonic() - CaptureStats.capture_started_at)) if self.capture.is_running() and CaptureStats.capture_started_at > 0 else 0
        self._header.update_stats(uptime_seconds=uptime, total_packets=0)
        self.reset_session_graph()
        self._update_status_bar()
        if self._session_timeline_window is not None and self._session_timeline_window.isVisible():
            self._session_timeline_window.refresh()
        if self._country_breakdown_window is not None and self._country_breakdown_window.isVisible():
            self._country_breakdown_window.refresh()
        if self._reconnect_frequency_window is not None and self._reconnect_frequency_window.isVisible():
            self._reconnect_frequency_window.refresh()
        if self._port_heatmap_window is not None and self._port_heatmap_window.isVisible():
            self._port_heatmap_window.refresh()
        if self._session_duration_window is not None and self._session_duration_window.isVisible():
            self._session_duration_window.refresh()
