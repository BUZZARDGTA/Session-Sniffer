"""Main window implementation for Session Sniffer."""

import logging
import threading
import time
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Literal, override

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtGui import QAction, QCloseEvent, QIcon, QShowEvent
from PySide6.QtWidgets import QLabel, QMainWindow, QMenuBar, QSplitter, QVBoxLayout, QWidget
from shiboken6 import isValid

from session_sniffer.background.cores import clear_resolution_queues, wake_all_player_cores
from session_sniffer.background.events import gui_closed__event
from session_sniffer.background.tasks import retrigger_detections_scan
from session_sniffer.constants.local import COMBO_RULES_PATH, DETECTIONS_JSON_PATH, SETTINGS_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import terminate_script
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis._main_header import SessionHeader
from session_sniffer.guis._main_window_files_mixin import FilesMixin
from session_sniffer.guis._main_window_game_mixin import GameMixin
from session_sniffer.guis._main_window_looky_mixin import LookyMixin
from session_sniffer.guis._main_window_shortcuts_mixin import ShortcutsMixin, append_shortcut_tooltip
from session_sniffer.guis._main_window_stats_mixin import StatsMixin
from session_sniffer.guis._session_table_section import SessionTableSection
from session_sniffer.guis._settings_runtime import SettingValue, apply_notifications_toggle_changes, apply_runtime_settings_changes
from session_sniffer.guis._settings_widget_builders import build_settings_menu, sync_settings_game_tab_action
from session_sniffer.guis._status_bar import SessionStatusBar
from session_sniffer.guis.discord_intro import DiscordIntro
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.live_language import add_i18n_menu_actions, register_language_refresh
from session_sniffer.guis.live_theme import register_post_theme_refresh
from session_sniffer.guis.loading_overlay import LoadingOverlay, run_blocking_with_loading
from session_sniffer.guis.ping_window import PingWindow
from session_sniffer.guis.player_resolver import PlayerResolverWindow
from session_sniffer.guis.port_scanner_window import PortScannerWindow
from session_sniffer.guis.settings_dialog import SettingsDialog
from session_sniffer.guis.tables_player_actions._detection_dialogs import close_all_detection_notification_dialogs
from session_sniffer.guis.tables_player_actions._userip_dialog import close_all_userip_detected_dialogs
from session_sniffer.guis.tables_player_actions.looky_system._looky_crawler_request_dialog import close_all_crawler_dialogs
from session_sniffer.guis.tables_player_actions.looky_system._looky_lookup_dialog import close_all_lookup_dialogs
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.userip_conflict_resolver import open_userip_conflict_resolver
from session_sniffer.guis.utils import (
    apply_always_on_top,
    consume_maximize_on_show,
    render_svg_pixmap_from_resource,
    resize_window_for_screen,
    scale_by_ui,
    show_or_focus_window,
)
from session_sniffer.guis.worker_thread import GUIWorkerThread
from session_sniffer.i18n import tr
from session_sniffer.models import GUIState
from session_sniffer.notifications_state import notifications_state
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.session_host import SessionHost
from session_sniffer.player.userip import UserIPDatabases, gui_dispatcher
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.status_bar_renderer import build_gui_status_sections, reset_status_bar_latency
from session_sniffer.rendering_core.types import CaptureStats, GUIRenderingState, GUIUpdatePayload, PaginationState, SearchState, SessionFilterState, TableMergeState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QMenu

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MainMenuActions:
    """Menu bar QAction references."""

    toggle_capture: QAction
    change_interface: QAction


@dataclass(slots=True)
class _WindowState:
    """Mutable runtime state for the main window."""

    worker_thread: GUIWorkerThread
    min_accepted_snapshot_version: int
    last_selected_session: int = SessionFilterState.FILTER_ALL


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
        pixmap = render_svg_pixmap_from_resource('app_icon.svg', icon_size, icon_size)
        icon_label.setPixmap(pixmap)
        layout.addWidget(icon_label)

        self._title_label = QLabel()
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title_label.setStyleSheet(themed_qss('color: #94a3b8; font-size: 11pt; font-weight: 600;'))
        layout.addWidget(self._title_label)

        self._subtitle_label = QLabel()
        self._subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._subtitle_label.setStyleSheet(themed_qss('color: #475569; font-size: 9pt;'))
        layout.addWidget(self._subtitle_label)

        self._refresh_language_texts()
        register_language_refresh(self, self._refresh_language_texts)

    def _refresh_language_texts(self) -> None:
        self._title_label.setText(tr('All Tables Minimized'))
        self._subtitle_label.setText(tr('Expand connected or disconnected players below to view session data'))


class MainWindow(LookyMixin, GameMixin, StatsMixin, FilesMixin, ShortcutsMixin, QMainWindow):
    """Main Qt window that hosts session tables and control UI."""

    _actions: MainMenuActions
    _open_settings_action: QAction
    _settings_game_tab_action: QAction
    _detections_relays_tab_action: QAction
    _connected: SessionTableSection
    _disconnected: SessionTableSection
    _placeholder: _MinimizedTablesPlaceholder
    _tables_splitter: QSplitter
    _saved_splitter_sizes: list[int]
    _discord_intro_window: DiscordIntro | None
    _detections_manager_window: DetectionsManagerDialog | None
    _userip_manager_window: UserIPDatabasesManager | None
    _main_i18n_menus: list[tuple[QMenu, str]]
    _main_i18n_actions: list[tuple[QAction, str, str]]

    def _on_splitter_moved(self, _position: int, _index: int) -> None:
        selected_session = SessionFilterState.get_selected_session()
        is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
        if not is_past_session and not TableMergeState.is_merged() and self._connected.is_expanded and self._disconnected.is_expanded:
            self._saved_splitter_sizes = self._tables_splitter.sizes()

    def _on_session_filter_changed(self, _session_id: int) -> None:
        self._update_splitter_visibility()

    def _update_splitter_visibility(self) -> None:
        self._connected.update_disconnected_players_state()
        self._disconnected.update_disconnected_players_state()
        is_merged = TableMergeState.is_merged()
        selected_session = SessionFilterState.get_selected_session()
        is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
        self._header.set_search_placeholder_merged(is_merged=is_merged or is_past_session)
        if self.isVisible():
            current_sizes = self._tables_splitter.sizes()
            if len(current_sizes) == self._tables_splitter.count() and all(size > 0 for size in current_sizes):
                self._saved_splitter_sizes = current_sizes
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
            self._tables_splitter.setSizes([10000, 0])
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
                    self._saved_splitter_sizes = [connected_size, disconnected_size]
            else:
                total_height = sum(self._tables_splitter.sizes())
                if total_height > 0:
                    half_height = total_height // 2
                    restored_sizes = [half_height, total_height - half_height]
                    self._tables_splitter.setSizes(restored_sizes)
                    self._saved_splitter_sizes = restored_sizes

    @override
    def _toggle_tables_merged(self) -> None:
        """Toggle merging connected and disconnected tables on the fly."""
        selected_session = SessionFilterState.get_selected_session()
        if 0 < selected_session < SessionTracker.get_current_session_id():
            return
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
        gui_dispatcher.conflict_resolver_requested.connect(lambda: open_userip_conflict_resolver(None))
        self._discord_intro_window = None
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
        self._interface_switching_overlay: LoadingOverlay | None = None

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

        self._main_i18n_menus = []
        self._main_i18n_actions = []
        self._actions = self._build_capture_menu(menu_bar)
        self._build_game_menu(menu_bar)
        self._apply_always_on_top()
        self._update_game_toolbar_visibility()
        self._build_tools_menu(menu_bar)
        self._build_statistics_menu(menu_bar)
        self._build_data_menu(menu_bar)
        self._build_settings_menu(menu_bar)
        self._build_help_menu(menu_bar)

        self._header = SessionHeader(self)
        self._header.search_changed.connect(self._on_global_search_changed)
        self._header.visual_notifications_toggle_requested.connect(partial(self._toggle_notifications, 'visual'))
        self._header.voice_notifications_toggle_requested.connect(partial(self._toggle_notifications, 'voice'))
        self._header.all_notifications_toggle_requested.connect(partial(self._toggle_notifications, 'all'))

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

        self._init_shortcuts()

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

            if gui_state.connected_table_column_order is not None and gui_state.connected_table_column_order:
                self._connected.table_view.apply_column_order(gui_state.connected_table_column_order)

            if gui_state.connected_table_column_widths is not None and gui_state.connected_table_column_widths:
                self._connected.table_view.apply_column_widths(gui_state.connected_table_column_widths)

            if gui_state.disconnected_table_column_order is not None and gui_state.disconnected_table_column_order:
                self._disconnected.table_view.apply_column_order(gui_state.disconnected_table_column_order)

            if gui_state.disconnected_table_column_widths is not None and gui_state.disconnected_table_column_widths:
                self._disconnected.table_view.apply_column_widths(gui_state.disconnected_table_column_widths)

        self._update_splitter_visibility()
        register_post_theme_refresh(self, self._refresh_after_theme_change)
        register_language_refresh(self, self._refresh_language_texts)

        self.raise_()
        self.activateWindow()

        worker_thread = GUIWorkerThread()
        self._state = _WindowState(
            worker_thread=worker_thread,
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

        self._config_watcher = DebouncedFileWatcher(self, on_change=self._on_config_files_changed, poll_interval_ms=1_000)
        self._config_watcher.watch(files=(SETTINGS_PATH, DETECTIONS_JSON_PATH, COMBO_RULES_PATH))

        self._update_header_capture_status()
        self._update_status_bar()

    def _build_capture_menu(self, menu_bar: QMenuBar) -> MainMenuActions:
        """Build the Capture menu and return key action references."""
        capture_menu = menu_bar.addMenu(tr('Capture'))
        if not capture_menu:
            message = 'Failed to create Capture menu'
            raise RuntimeError(message)
        capture_menu.setToolTipsVisible(True)
        self._main_i18n_menus.append((capture_menu, 'Capture'))

        toggle_hotkey = Settings.get_active_shortcut('toggle_capture_hotkey')
        toggle_capture_action = QAction(QIcon(str(ICONS_DIR_PATH / 'circle-stop.svg')), tr('Stop Capture'), self)
        toggle_capture_action.setToolTip(append_shortcut_tooltip(tr('Stop packet capture'), toggle_hotkey, is_global=True))
        toggle_capture_action.triggered.connect(self._toggle_capture)
        capture_menu.addAction(toggle_capture_action)

        capture_menu.addSeparator()

        actions = add_i18n_menu_actions(
            self,
            capture_menu,
            ICONS_DIR_PATH,
            [
                ('refresh-cw.svg', 'Change Interface', 'Stop capture, select a different network interface, and restart capture', self._on_change_interface),
                (
                    'router.svg', 'Hotspot && Sharing', 'Create a Wi-Fi hotspot or configure Internet Connection Sharing (ICS) to capture console traffic',
                    self._open_hotspot_manager,
                ),
            ],
            self._main_i18n_actions,
        )

        return MainMenuActions(toggle_capture=toggle_capture_action, change_interface=actions[0])

    def _build_tools_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Tools menu and attach tool launcher actions."""
        tools_menu = menu_bar.addMenu(tr('Tools'))
        if not tools_menu:
            message = 'Failed to create Tools menu'
            raise RuntimeError(message)
        tools_menu.setToolTipsVisible(True)
        self._main_i18n_menus.append((tools_menu, 'Tools'))

        self._detections_relays_tab_action = self._build_tools_managers_section(tools_menu)
        add_i18n_menu_actions(
            self,
            tools_menu,
            ICONS_DIR_PATH,
            [
                None,
                ('trophy.svg', 'Most Seen Players', 'View a leaderboard of the most frequently seen players across sessions', self._open_player_leaderboard),
                ('radar.svg', 'Port Scanner', 'Perform multi-threaded TCP and UDP port scanning with service banner detection', self._open_port_scanner),
                ('radio-tower.svg', 'Ping Diagnostics', 'Send ICMP echo, TCP connect, UDP reachability, or Web latency probes', self._open_ping_diagnostics),
            ],
            self._main_i18n_actions,
        )

    def _build_settings_menu(self, menu_bar: QMenuBar) -> None:
        """Build the Settings menu with `Open Settings` and direct-jump tab actions."""
        self._open_settings_action, self._settings_game_tab_action = build_settings_menu(
            self,
            menu_bar,
            self._main_i18n_menus,
            self._main_i18n_actions,
            self._open_settings_dialog_on_tab,
        )

    @override
    def _toggle_notifications(self, mode: Literal['visual', 'voice', 'all']) -> None:
        """Toggle visual, voice, or both session-only notification states (never persisted) and apply runtime effects."""
        visual_was_enabled, voice_was_enabled = notifications_state.visual_enabled, notifications_state.voice_enabled
        enable_both = not (visual_was_enabled or voice_was_enabled)
        notifications_state.visual_enabled = enable_both if mode == 'all' else (not visual_was_enabled if mode == 'visual' else visual_was_enabled)
        notifications_state.voice_enabled = enable_both if mode == 'all' else (not voice_was_enabled if mode == 'voice' else voice_was_enabled)
        apply_notifications_toggle_changes(visual_was_enabled=visual_was_enabled, voice_was_enabled=voice_was_enabled)
        self._header.sync_notification_buttons(visual_enabled=notifications_state.visual_enabled, voice_enabled=notifications_state.voice_enabled)

    def show_discord_intro(self) -> None:
        """Open the Discord intro dialog, retaining a reference to prevent garbage collection."""
        show_or_focus_window(self, '_discord_intro_window', lambda: DiscordIntro(self))

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
        self._unregister_global_hotkeys()
        self._stats_timer.stop()
        self._config_watcher.stop()
        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            selected_session = SessionFilterState.get_selected_session()
            is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
            if not is_past_session and not TableMergeState.is_merged() and self._connected.is_expanded and self._disconnected.is_expanded:
                current_sizes = self._tables_splitter.sizes()
                if len(current_sizes) == self._tables_splitter.count() and all(size > 0 for size in current_sizes):
                    gui_state.main_window_splitter_sizes = current_sizes
            elif self._saved_splitter_sizes:
                gui_state.main_window_splitter_sizes = self._saved_splitter_sizes

            gui_state.connected_table_column_widths = self._connected.table_view.get_persisted_column_widths()
            gui_state.connected_table_column_order = self._connected.table_view.get_persisted_column_order()
            gui_state.disconnected_table_column_widths = self._disconnected.table_view.get_persisted_column_widths()
            gui_state.disconnected_table_column_order = self._disconnected.table_view.get_persisted_column_order()

            gui_state.save()

        logger.debug('MainWindow closeEvent received')
        gui_closed__event.set()
        GUIRenderingState.wake()
        wake_all_player_cores()
        logger.debug('MainWindow closeEvent: closing child windows')
        self._player_resolver_window.close()
        for child_window in (
            self._settings_dialog_window,
            self._userip_manager_window,
            self._logs_manager_window,
            self._detections_manager_window,
            self._leaderboard_window,
        ):
            if child_window is not None:
                child_window.close()

        PingWindow.close_window()
        PortScannerWindow.close_window()

        close_all_crawler_dialogs()
        close_all_lookup_dialogs()
        close_all_userip_detected_dialogs()
        close_all_detection_notification_dialogs()
        if self.capture.is_running():
            logger.debug('MainWindow closeEvent: stopping packet capture')
            self.capture.stop()
        GTASuspendManager.shutdown()
        RDR2SuspendManager.shutdown()
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

        selected_session = SessionFilterState.get_selected_session()
        if selected_session != self._state.last_selected_session:
            self._state.last_selected_session = selected_session
            self._disconnected.reset_page_to_first()
            self._disconnected.sync_session_filter()
            self._update_splitter_visibility()

        self._sync_capture_toggle_action()
        is_capture_running = self.capture.is_running()
        self._header.set_capture_running(is_running=is_capture_running)
        self._status_bar.set_sections(payload.status_sections, capture_running=is_capture_running)

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

    def _apply_table_settings(self, changed: set[str] | None = None) -> None:
        """Apply configured table sort, pagination, and column settings to connected and disconnected tables."""
        if changed is None and self._settings_dialog_window is not None:
            changed = self._settings_dialog_window.changed_settings
        self._connected.apply_sort_from_settings()
        self._disconnected.apply_sort_from_settings()
        self._connected.apply_pagination_from_settings()
        self._disconnected.apply_pagination_from_settings()
        self._connected.apply_columns_from_settings(changed)
        self._disconnected.apply_columns_from_settings(changed)
        wake_rendering_core()

    def _sync_player_resolver_settings(self) -> None:
        """Synchronize Player Resolver background monitoring and refresh session table icons."""
        self._player_resolver_window.high_rate_monitor.apply_settings()
        self._player_resolver_window.player_identifier.apply_settings()
        if Settings.high_rate_monitor_run_in_background:
            self._player_resolver_window.high_rate_monitor.start_monitoring()
        elif not self._player_resolver_window.isVisible() and not self._player_resolver_window.high_rate_monitor.has_open_graphs():
            self._player_resolver_window.high_rate_monitor.stop_monitoring()
        self._connected.table_view.viewport().update()
        self._disconnected.table_view.viewport().update()

    def _apply_userip_settings(self, changed: set[str] | None = None) -> None:
        """Apply UserIP settings changes such as known alts synchronization."""
        if changed is None and self._settings_dialog_window is not None:
            changed = self._settings_dialog_window.changed_settings
        if changed is None or 'userip_sync_known_alts' in changed:
            UserIPDatabases.build()
            self._connected.table_view.viewport().update()
            self._disconnected.table_view.viewport().update()
        if changed is None or 'userip_auto_feed_from_usernames' in changed:
            wake_rendering_core()

    def _on_config_files_changed(self) -> None:
        """Reload externally modified settings.json, detections.json, or combo_rules.json and re-trigger scans."""
        if Settings.has_external_file_change(SETTINGS_PATH):
            old_values: dict[str, SettingValue] = {name.lower(): value for name, value in Settings.iterate_over_settings()}
            Settings.load_from_settings_file(SETTINGS_PATH)
            new_values: dict[str, SettingValue] = {name.lower(): value for name, value in Settings.iterate_over_settings()}
            changed = {key for key, value in new_values.items() if value != old_values.get(key)}
            if changed:
                logger.info('Detected external settings.json modification; applying changed settings: %s', sorted(changed))
                apply_runtime_settings_changes(self.capture.get(), old_values, new_values)
                if 'gui_disconnected_players_enabled' in changed:
                    TableMergeState.reset_override()
                self._apply_always_on_top()
                self._refresh_game_feature_set_ui()
                self._update_splitter_visibility()
                self._apply_table_settings(changed)
                self._sync_player_resolver_settings()
                self._apply_userip_settings(changed)
                self._sync_shortcuts()
                if self._settings_dialog_window is not None:
                    self._settings_dialog_window.refresh_from_external_settings()
                wake_rendering_core()

        detections_changed = False
        if GUIDetectionSettings.has_external_file_change(DETECTIONS_JSON_PATH):
            logger.info('Detected external detections.json modification; reloading detection settings.')
            GUIDetectionSettings.load_from_file_or_defaults(DETECTIONS_JSON_PATH)
            detections_changed = True

        if ComboRulesManager.has_external_file_change(COMBO_RULES_PATH):
            logger.info('Detected external combo_rules.json modification; reloading combo rules.')
            ComboRulesManager.load_from_file(COMBO_RULES_PATH)
            detections_changed = True

        if detections_changed:
            if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
                self._detections_manager_window.load_current_settings()
            retrigger_detections_scan()
            wake_rendering_core()

    def _refresh_game_feature_set_ui(self) -> None:
        """Synchronize the Game menu and dynamic feature-set tab actions across menus."""
        self._update_game_toolbar_visibility()
        sync_settings_game_tab_action(self._settings_game_tab_action)
        self._detections_relays_tab_action.setVisible(Settings.is_gta5_feature_set())

    @override
    def _open_settings_dialog(self) -> None:
        """Open the Settings window, or focus the existing one."""
        self._open_settings_dialog_on_tab(None)

    def _open_settings_dialog_on_tab(self, category: str | None) -> None:
        """Open or focus the Settings window, optionally switching directly to *category*."""
        self._unregister_global_hotkeys()
        created = False

        def _factory() -> SettingsDialog:
            nonlocal created
            created = True
            window = SettingsDialog(None, self.capture.get(), self._on_change_interface)
            window.rejected.connect(self._sync_shortcuts)
            for callback in (
                TableMergeState.reset_override,
                self._apply_always_on_top,
                self._refresh_game_feature_set_ui,
                self._update_splitter_visibility,
                self._apply_table_settings,
                self._sync_player_resolver_settings,
                self._apply_userip_settings,
                self._sync_shortcuts,
            ):
                window.accepted.connect(callback)
            return window

        dialog = show_or_focus_window(self, '_settings_dialog_window', _factory)
        if category is not None:
            dialog.select_category(category)
        if created:
            dialog.destroyed.connect(self._sync_shortcuts)

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
        sections = build_gui_status_sections(
            capture=self.capture.get(),
            discord_rpc_manager=None,
        )
        self._status_bar.set_sections(sections, capture_running=self.capture.is_running())

    def _refresh_after_theme_change(self) -> None:
        """Refresh dynamic header, status bar, and session table views after a runtime theme switch."""
        self._header.set_capture_running(is_running=self.capture.is_running())
        self._header.sync_notification_buttons(visual_enabled=notifications_state.visual_enabled, voice_enabled=notifications_state.voice_enabled)
        self._update_status_bar()
        wake_rendering_core()
        self._connected.table_view.viewport().update()
        self._disconnected.table_view.viewport().update()

    def _refresh_language_texts(self) -> None:
        """Re-translate menus, status texts, capture action, and wake background rendering on language switch."""
        self.setWindowTitle(TITLE)
        for menu, title_key in self._main_i18n_menus:
            menu.setTitle(tr(title_key))
        for action, text_key, tooltip_key in self._main_i18n_actions:
            action.setText(tr(text_key))
            action.setToolTip(tr(tooltip_key))
        self._refresh_game_menu_language_texts()
        sync_settings_game_tab_action(self._settings_game_tab_action)
        self._sync_shortcut_action_labels()
        self._refresh_statistics_menu_language_texts()
        self._refresh_files_menu_language_texts()
        self._update_status_bar()
        wake_rendering_core()

    @override
    def _sync_capture_toggle_action(self) -> None:
        """Synchronize the toggle capture action icon, text, and tooltip with the current capture state."""
        is_running = self.capture.is_running()
        expected_text = tr('Stop Capture') if is_running else tr('Start Capture')
        base_tooltip = tr('Stop packet capture') if is_running else tr('Start packet capture')
        toggle_hotkey = Settings.get_active_shortcut('toggle_capture_hotkey')
        expected_tooltip = append_shortcut_tooltip(base_tooltip, toggle_hotkey, is_global=True)
        if self._actions.toggle_capture.text() == expected_text and self._actions.toggle_capture.toolTip() == expected_tooltip:
            return

        self._actions.toggle_capture.setText(expected_text)
        self._actions.toggle_capture.setToolTip(expected_tooltip)
        if is_running:
            self._actions.toggle_capture.setIcon(QIcon(str(ICONS_DIR_PATH / 'circle-stop.svg')))
        else:
            self._actions.toggle_capture.setIcon(QIcon(str(ICONS_DIR_PATH / 'circle-play.svg')))

    @override
    def _toggle_capture(self) -> None:
        """Toggle the packet capture on/off."""
        stopping = self.capture.is_running()
        title = tr('Stopping Capture\u2026') if stopping else tr('Starting Capture\u2026')
        run_blocking_with_loading(self, title, tr('Updating packet capture engine\u2026'), self.capture.stop if stopping else self.capture.start)

        self._sync_capture_toggle_action()
        self._update_header_capture_status()
        self._update_status_bar()

    def set_interface_switching_mode(self, *, switching: bool) -> None:
        """Disable or re-enable the UI while an interface switch is in progress."""
        if switching:
            if self._interface_switching_overlay is None:
                self._interface_switching_overlay = LoadingOverlay(
                    self,
                    tr('Switching Network Interface\u2026'),
                    tr('Reconfiguring packet capture and filters\u2026'),
                )
            self._interface_switching_overlay.present_immediately()
        elif self._interface_switching_overlay is not None:
            self._interface_switching_overlay.close_overlay()
            self._interface_switching_overlay = None

        menu_bar = self.menuBar()
        if menu_bar:
            menu_bar.setEnabled(not switching)
        self._header.setEnabled(not switching)
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
        self._disconnected.set_selected_session_filter(SessionFilterState.FILTER_ALL)
        self._clear_connected_players()
        self._clear_disconnected_players()
        clear_resolution_queues()
        SessionHost.clear_history()
        SessionHost.players_pending_for_disconnection.clear()

    def on_interface_switched(self, *, capture_toggle_enabled: bool = True) -> None:
        """Synchronize GUI state after the capture interface has been replaced."""
        self._refresh_game_feature_set_ui()
        self._sync_capture_toggle_action()
        self._actions.toggle_capture.setEnabled(capture_toggle_enabled)
        self._update_header_capture_status()
        self._update_status_bar()
        if self._settings_dialog_window is not None and isValid(self._settings_dialog_window):
            self._settings_dialog_window.update_capture(self.capture.get())
        wake_all_player_cores()

    @override
    def _bump_min_accepted_snapshot_version(self) -> None:
        """Advance the minimum accepted rendering snapshot version."""
        self._state.min_accepted_snapshot_version = GUIRenderingState.get_version() + 1

    @override
    def _clear_connected_players(self) -> None:
        """Clear all connected players from the table and registry."""
        current_session_id = SessionTracker.get_current_session_id()
        connected_players = PlayersRegistry.get_default_sorted_players(include_connected=True, include_disconnected=False)
        connected_ips = {player.ip for player in connected_players}
        affected_past_sessions: set[int] = set()
        for player in connected_players:
            if 0 < player.session_id < current_session_id and SessionTracker.remove_session_player(player.session_id, player.ip):
                affected_past_sessions.add(player.session_id)

        PlayersRegistry.clear_connected_players()
        self._prune_empty_past_sessions(affected_past_sessions)
        SessionHost.players_pending_for_disconnection.clear()
        self._connected.clear_table()
        self._cleanup_removed_player_ips(connected_ips)

        if TableMergeState.is_merged():
            self._clear_disconnected_players()
            return
        self._refresh_session_gui_state()
        self.recalculate_capture_stats()

    @override
    def _clear_disconnected_players(self) -> None:
        """Clear all disconnected players from the table and registry (or active session filter)."""
        selected_session = SessionFilterState.get_selected_session()
        current_session_id = SessionTracker.get_current_session_id()
        is_past_session = 0 < selected_session < current_session_id
        if is_past_session or selected_session == SessionFilterState.FILTER_CURRENT:
            if is_past_session:
                for pruned_sid in SessionTracker.clear_session_players(selected_session):
                    SessionHost.prune_history_for_session(pruned_sid)
                self._disconnected.set_selected_session_filter(SessionFilterState.FILTER_ALL)
            target_session_id = selected_session if is_past_session else current_session_id
            removed_ips = {player.ip for player in PlayersRegistry.remove_players_by_session_id(target_session_id)}
            self._disconnected.clear_table()
            self._refresh_session_gui_state()
            self._cleanup_removed_player_ips(removed_ips, remove_from_connected=is_past_session or TableMergeState.is_merged())
            return

        disconnected_players = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        disconnected_ips = {player.ip for player in disconnected_players}

        PlayersRegistry.clear_disconnected_players()
        for pruned_sid in SessionTracker.clear_session_players():
            SessionHost.prune_history_for_session(pruned_sid)
        self._disconnected.clear_table()
        self._refresh_session_gui_state()
        self._cleanup_removed_player_ips(disconnected_ips, remove_from_connected=TableMergeState.is_merged())
        self.recalculate_capture_stats()

    @override
    def recalculate_capture_stats(self) -> None:
        """Recalculate capture statistics from currently remaining players in registry."""
        total_remaining = PlayersRegistry.get_total_count()
        if not total_remaining:
            self.reset_capture_stats()
            return

        CaptureStats.recalculate_total_packets(PlayersRegistry.get_all_players())
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
        self._refresh_stat_breakdown_windows()

    def reset_capture_stats(self) -> None:
        """Reset capture statistics, graphs, header counters, and open stats windows."""
        CaptureStats.reset_capture_stats()
        reset_status_bar_latency()
        uptime = max(0, int(time.monotonic() - CaptureStats.capture_started_at)) if self.capture.is_running() and CaptureStats.capture_started_at > 0 else 0
        self._header.update_stats(uptime_seconds=uptime, total_packets=0)
        self.reset_session_graph()
        self._update_status_bar()
        self._refresh_stat_breakdown_windows()
