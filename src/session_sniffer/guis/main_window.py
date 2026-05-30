"""Main window implementation for Session Sniffer."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QEvent, QObject, Qt, QTimer
from PyQt6.QtGui import QAction, QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QLabel,
    QMainWindow,
    QMenu,
    QVBoxLayout,
    QWidget,
    QWidgetAction,
)

from session_sniffer.background import gui_closed__event
from session_sniffer.background.suspend_manager import ProcessSuspendManager
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import terminate_script
from session_sniffer.guis._main_window_files_mixin import FilesMixin
from session_sniffer.guis._main_window_gta5_mixin import GTA5Mixin
from session_sniffer.guis._main_window_stats_mixin import StatsMixin
from session_sniffer.guis._session_table_section import SessionStatusBar, SessionTableSection
from session_sniffer.guis.detections_manager import DetectionsManagerDialog
from session_sniffer.guis.html_templates import generate_gui_header_html
from session_sniffer.guis.logs_manager import LogsManager
from session_sniffer.guis.player_resolver import PlayerResolverWindow
from session_sniffer.guis.session_host_history_window import populate_host_history_submenu
from session_sniffer.guis.settings_dialog import SettingsDialog
from session_sniffer.guis.stylesheets import GTA5_STATUS_LABEL_STYLESHEET, MENU_BAR_STYLESHEET
from session_sniffer.guis.userip_manager import UserIPDatabasesManager
from session_sniffer.guis.utils import apply_always_on_top, resize_window_for_screen
from session_sniffer.guis.worker_thread import GUIWorkerThread
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.player.warnings import HostingWarnings, MobileWarnings, VPNWarnings
from session_sniffer.rendering_core.types import CaptureState, GUIRenderingState, GUIUpdatePayload
from session_sniffer.settings import Settings
from session_sniffer.utils import find_running_gta5_path

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.guis.table_model import SessionTableModel


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


class MainWindow(GTA5Mixin, StatsMixin, FilesMixin, QMainWindow):
    """Main Qt window that hosts session tables and control UI."""

    _actions: _MenuActions
    _connected: SessionTableSection
    _disconnected: SessionTableSection
    _gta5_status_label: QLabel
    _session_host_submenu: QMenu
    _player_resolver_action: QAction

    def _update_separator_visibility(self) -> None:
        self._tables_separator.setVisible(
            self._connected.is_expanded or self._disconnected.is_expanded,
        )

    def __init__(self, screen_size: tuple[int, int], capture_holder: CaptureHolder, on_change_interface: Callable[[], None]) -> None:
        """Initialize the main application window.

        Args:
            screen_size: Primary screen dimensions as (width, height) in pixels.
            capture_holder: Mutable reference to the active packet capture instance.
            on_change_interface: Callback invoked when the user requests an interface switch.
        """
        super().__init__()

        self.capture = capture_holder
        self._player_resolver_window = PlayerResolverWindow(self._highlight_connected_ips, self)
        self._detections_manager_window: DetectionsManagerDialog | None = None
        self._logs_manager_window: LogsManager | None = None
        self._settings_dialog_window: SettingsDialog | None = None
        self._userip_manager_window: UserIPDatabasesManager | None = None
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

        # Set up the window
        self.setWindowTitle(TITLE)
        self.setMinimumSize(1024, 768)
        resize_window_for_screen(self, screen_size)
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout for the central widget
        main_layout = QVBoxLayout(central_widget)

        # ----- Menu bar -----
        menu_bar = self.menuBar()
        if menu_bar is None:
            msg = 'Failed to get menu bar'
            raise RuntimeError(msg)
        menu_bar.setStyleSheet(MENU_BAR_STYLESHEET)

        # ----- Capture menu -----
        capture_menu = menu_bar.addMenu('Capture')
        if capture_menu is None:
            msg = 'Failed to create Capture menu'
            raise RuntimeError(msg)
        capture_menu.setToolTipsVisible(True)

        toggle_capture_action = QAction('⏹️ Stop Capture', self)
        toggle_capture_action.setToolTip('Stop packet capture')
        toggle_capture_action.triggered.connect(self._toggle_capture)
        capture_menu.addAction(toggle_capture_action)

        change_interface_action = QAction('🔄 Change Interface', self)
        change_interface_action.setToolTip('Stop capture, select a different network interface, and restart capture')
        change_interface_action.triggered.connect(on_change_interface)
        capture_menu.addAction(change_interface_action)

        # ----- GTA5 menu (hidden unless GTA5 preset) -----
        gta5_menu = menu_bar.addMenu('GTA5')
        if gta5_menu is None:
            msg = 'Failed to create GTA5 menu'
            raise RuntimeError(msg)
        gta5_menu.setToolTipsVisible(True)
        gta5_menu_action = gta5_menu.menuAction()
        if gta5_menu_action is None:
            msg = 'Failed to get GTA5 menu action'
            raise RuntimeError(msg)
        gta5_menu_action.setVisible(Settings.capture_game_preset == 'GTA5')
        self._gta5_menu = gta5_menu

        gta5_status_label = QLabel()
        gta5_status_label.setTextFormat(Qt.TextFormat.RichText)
        gta5_status_label.setStyleSheet(GTA5_STATUS_LABEL_STYLESHEET)
        gta5_status_label.setText('<span style="color: #F44336;">●</span> GTA V not running')
        gta5_status_label.setToolTip('GTA V process detection state')
        gta5_status_widget_action = QWidgetAction(self)
        gta5_status_widget_action.setDefaultWidget(gta5_status_label)
        gta5_menu.addAction(gta5_status_widget_action)
        self._gta5_status_label = gta5_status_label

        def _update_gta5_status_display() -> None:
            gta5 = find_running_gta5_path()
            if gta5.is_running:
                version = 'GTA V Enhanced' if gta5.is_enhanced else 'GTA V Legacy'
                self._gta5_status_label.setText(f'<span style="color: #4CAF50;">●</span> {version}')
                self._gta5_status_label.setToolTip(str(gta5.path))
            else:
                self._gta5_status_label.setText('<span style="color: #F44336;">●</span> GTA V not running')
                self._gta5_status_label.setToolTip('GTA V process detection state')

        gta5_menu.aboutToShow.connect(_update_gta5_status_display)
        gta5_menu.addSeparator()

        player_resolver_action = QAction('🔍 Player Resolver', self)
        player_resolver_action.setToolTip('High Rate Monitor and Player Identifier tools')
        player_resolver_action.triggered.connect(self._open_player_resolver)
        gta5_menu.addAction(player_resolver_action)
        self._player_resolver_action = player_resolver_action

        gta5_menu.addSeparator()

        session_host_submenu = gta5_menu.addMenu('👑 Session Host')
        if session_host_submenu is None:
            msg = 'Failed to create Session Host submenu'
            raise RuntimeError(msg)
        session_host_submenu.setToolTipsVisible(True)
        cast('QAction', session_host_submenu.menuAction()).setToolTip('Session host detection controls for the current GTA5 lobby')
        self._session_host_submenu = session_host_submenu

        host_status_action = QAction('ℹ️ No host', self)  # noqa: RUF001
        host_status_action.setEnabled(False)
        host_status_action.setToolTip('Current session host detection state')
        session_host_submenu.addAction(host_status_action)
        self._host_status_action = host_status_action

        def _update_host_status_label() -> None:
            if SessionHost.player is not None:
                self._host_status_action.setText(f'ℹ️ Detected: {SessionHost.player.ip}')  # noqa: RUF001
            elif SessionHost.search_player:
                self._host_status_action.setText('ℹ️ Searching…')  # noqa: RUF001
            else:
                self._host_status_action.setText('ℹ️ No host')  # noqa: RUF001

        session_host_submenu.aboutToShow.connect(_update_host_status_label)

        session_host_submenu.addSeparator()

        clear_host_action = QAction('❌ Clear Session Host', self)
        clear_host_action.setToolTip('Manually clear the currently detected session host')
        clear_host_action.triggered.connect(self._clear_session_host)
        session_host_submenu.addAction(clear_host_action)

        redetect_host_action = QAction('🔄 Re-detect Host', self)
        redetect_host_action.setToolTip('Clear the current host and immediately re-trigger host detection')
        redetect_host_action.triggered.connect(self._redetect_session_host)
        session_host_submenu.addAction(redetect_host_action)

        session_host_submenu.addSeparator()
        host_history_submenu = session_host_submenu.addMenu('📜 Host History')
        if host_history_submenu is None:
            msg = 'Failed to create Host History submenu'
            raise RuntimeError(msg)
        host_history_submenu.setToolTipsVisible(True)
        host_history_submenu.aboutToShow.connect(lambda: populate_host_history_submenu(host_history_submenu, self._highlight_ips))

        gta5_menu.addSeparator()

        gta5_process_submenu = gta5_menu.addMenu('🎮 GTA5 Process')
        if gta5_process_submenu is None:
            msg = 'Failed to create GTA5 Process submenu'
            raise RuntimeError(msg)
        gta5_process_submenu.setToolTipsVisible(True)
        cast('QAction', gta5_process_submenu.menuAction()).setToolTip('GTA5 process controls — suspend/resume for solo and public session manipulation')
        self._gta5_process_submenu = gta5_process_submenu

        gta5_menu_solo_action = QAction('🎯 Solo Public Session (~8s)', self)
        gta5_menu_solo_action.setToolTip(
            'Suspend GTA5 for ~8 seconds then auto-resume.\n'
            'This forces the game to spawn you alone in a public session.',
        )
        gta5_menu_solo_action.triggered.connect(self.gta5_solo_session)
        gta5_process_submenu.addAction(gta5_menu_solo_action)

        gta5_process_submenu.addSeparator()

        gta5_suspend_resume_action = QAction('⏸️ Suspend Process', self)
        gta5_suspend_resume_action.setToolTip('Manually suspend the GTA5 process — stays suspended until you click it again to resume')
        gta5_suspend_resume_action.triggered.connect(self.toggle_manual_gta5_suspend)
        gta5_process_submenu.addAction(gta5_suspend_resume_action)

        self._gta5_solo_menu_action = gta5_menu_solo_action
        self._gta5_suspend_resume_action = gta5_suspend_resume_action
        self._manual_gta5_suspend_active = False
        self._gta5_solo_active = False
        self._gta5_process_suspended = False
        self._gta5_process_detected = False

        gta5_menu.addSeparator()

        looky_submenu = gta5_menu.addMenu('\U0001F441 Looky')
        if looky_submenu is None:
            msg = 'Failed to create Looky submenu'
            raise RuntimeError(msg)
        looky_submenu.setToolTipsVisible(True)
        cast('QAction', looky_submenu.menuAction()).setToolTip('Looky tools for the current GTA5 session')
        self._looky_submenu = looky_submenu

        looky_crawler_session_action = QAction('🤖 Request Crawler in My Session', self)
        looky_crawler_session_action.setToolTip(
            'Request the Looky crawler bot to join your session.\n'
            'The bot will resolve all player usernames in your session to the Looky database.\n'
            'Once completed, all players are automatically re-queried via Looky to pick up resolved or updated usernames.',
        )
        looky_crawler_session_action.triggered.connect(self.request_crawler_in_my_session)
        looky_submenu.addAction(looky_crawler_session_action)
        self._looky_crawler_session_action = looky_crawler_session_action
        self._crawler_worker = None
        self._crawler_progress_dialog = None
        self._player_crawler_worker = None
        self._player_crawler_rockstarids: list[int] | None = None

        if Settings.capture_game_preset == 'GTA5':
            self._sync_gta5_process_button()
            self._sync_looky_submenu()
            if CaptureState.gta5_is_running:
                gta5 = find_running_gta5_path()
                version = 'GTA V Enhanced' if gta5.is_enhanced else 'GTA V Legacy'
                self._gta5_status_label.setText(f'<span style="color: #4CAF50;">●</span> {version}')
                self._gta5_status_label.setToolTip(str(gta5.path) if gta5.is_running else 'GTA5 process detection state')
            self._session_host_submenu.setEnabled(CaptureState.gta5_is_running)
            self._player_resolver_action.setEnabled(CaptureState.gta5_is_running)

        # ----- Tools menu -----
        tools_menu = menu_bar.addMenu('Tools')
        if tools_menu is None:
            msg = 'Failed to create Tools menu'
            raise RuntimeError(msg)
        tools_menu.setToolTipsVisible(True)

        detections_manager_action = QAction('🛡️ Detections Manager', self)
        detections_manager_action.setToolTip('Configure detection, notifications, and protection rules')
        detections_manager_action.triggered.connect(self._open_detections_manager)
        tools_menu.addAction(detections_manager_action)

        userip_manager_action = QAction('🗃️ UserIP Manager', self)
        userip_manager_action.setToolTip('Browse, edit, add, and delete entries in UserIP database files')
        userip_manager_action.triggered.connect(self._open_userip_manager)
        tools_menu.addAction(userip_manager_action)

        logs_manager_action = QAction('📋 Logs Manager', self)
        logs_manager_action.setToolTip('View, search, filter, and manage application log files')
        logs_manager_action.triggered.connect(self._open_logs_manager)
        tools_menu.addAction(logs_manager_action)

        tools_menu.addSeparator()

        leaderboard_action = QAction('🏆 Most Seen Players', self)
        leaderboard_action.setToolTip('View a leaderboard of the most frequently seen players across sessions')
        leaderboard_action.triggered.connect(self._open_player_leaderboard)
        tools_menu.addAction(leaderboard_action)

        # ----- Statistics menu -----
        statistics_menu = menu_bar.addMenu('Statistics')
        if statistics_menu is None:
            msg = 'Failed to create Statistics menu'
            raise RuntimeError(msg)
        statistics_menu.setToolTipsVisible(True)

        capture_health_action = QAction('📊 Capture Statistics', self)
        capture_health_action.setToolTip('Capture restart count and packet latency statistics')
        capture_health_action.triggered.connect(self._open_capture_health)
        statistics_menu.addAction(capture_health_action)

        session_rate_graph_action = QAction('⚡ Session Rate Graph', self)
        session_rate_graph_action.setToolTip('Live PPS and BPS graphs for the whole session')
        session_rate_graph_action.triggered.connect(self._open_session_rate_graph)
        statistics_menu.addAction(session_rate_graph_action)

        statistics_menu.addSeparator()

        session_timeline_action = QAction('🕐 Session Timeline', self)
        session_timeline_action.setToolTip('Gantt chart showing when each player was present')
        session_timeline_action.triggered.connect(self._open_session_timeline)
        statistics_menu.addAction(session_timeline_action)

        statistics_menu.addSeparator()

        country_breakdown_action = QAction('🌍 Country Breakdown', self)
        country_breakdown_action.setToolTip('Rank players by country of origin')
        country_breakdown_action.triggered.connect(self._open_country_breakdown)
        statistics_menu.addAction(country_breakdown_action)

        reconnect_frequency_action = QAction('🔁 Reconnect Frequency', self)
        reconnect_frequency_action.setToolTip('List players sorted by reconnect count')
        reconnect_frequency_action.triggered.connect(self._open_reconnect_frequency)
        statistics_menu.addAction(reconnect_frequency_action)

        avg_session_duration_action = QAction('⏱️ Session Duration', self)
        avg_session_duration_action.setToolTip('Disconnected players ranked by their session duration')
        avg_session_duration_action.triggered.connect(self._open_session_duration)
        statistics_menu.addAction(avg_session_duration_action)

        port_heatmap_action = QAction('📡 Port Heatmap', self)
        port_heatmap_action.setToolTip('Rank observed ports by frequency across all players')
        port_heatmap_action.triggered.connect(self._open_port_heatmap)
        statistics_menu.addAction(port_heatmap_action)

        # ----- Data & Files menu -----
        data_menu = menu_bar.addMenu('Data && Files')
        if data_menu is None:
            msg = 'Failed to create Data & Files menu'
            raise RuntimeError(msg)
        data_menu.setToolTipsVisible(True)

        # --- AppData Roots ---
        open_local_appdata_action = QAction('📂 Open Local AppData Folder', self)
        open_local_appdata_action.setToolTip('Open Local AppData\\Session Sniffer in Windows Explorer')
        open_local_appdata_action.triggered.connect(self._open_local_appdata_folder)
        data_menu.addAction(open_local_appdata_action)

        open_roaming_appdata_action = QAction('📂 Open Roaming AppData Folder', self)
        open_roaming_appdata_action.setToolTip('Open Roaming AppData\\Session Sniffer in Windows Explorer')
        open_roaming_appdata_action.triggered.connect(self._open_roaming_appdata_folder)
        data_menu.addAction(open_roaming_appdata_action)

        data_menu.addSeparator()

        # --- Configuration ---
        open_settings_ini_action = QAction('📄 Open Settings.ini', self)
        open_settings_ini_action.setToolTip('Open Roaming AppData\\Session Sniffer\\Settings.ini')
        open_settings_ini_action.triggered.connect(self._open_settings_file)
        data_menu.addAction(open_settings_ini_action)

        data_menu.addSeparator()

        # --- Folders ---
        open_userip_databases_action = QAction('🗂️ Open UserIP Databases Folder', self)
        open_userip_databases_action.setToolTip('Open Roaming AppData\\Session Sniffer\\UserIP Databases')
        open_userip_databases_action.triggered.connect(self._open_userip_databases_folder)
        data_menu.addAction(open_userip_databases_action)

        open_user_scripts_action = QAction('🗂️ Open User Scripts Folder', self)
        open_user_scripts_action.setToolTip('Open Roaming AppData\\Session Sniffer\\scripts')
        open_user_scripts_action.triggered.connect(self._open_user_scripts_folder)
        data_menu.addAction(open_user_scripts_action)

        data_menu.addSeparator()

        # --- Debug Logs Submenu ---
        debug_logs_submenu = data_menu.addMenu('🐛 Debug Logs')
        if debug_logs_submenu is None:
            msg = 'Failed to create Debug Logs submenu'
            raise RuntimeError(msg)
        debug_logs_submenu.setToolTipsVisible(True)
        cast('QAction', debug_logs_submenu.menuAction()).setToolTip('Open or browse the application debug log files')

        open_debug_logs_folder_action = QAction('📂 Open Debug Logs Folder', self)
        open_debug_logs_folder_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug')
        open_debug_logs_folder_action.triggered.connect(self._open_debug_logs_folder)
        debug_logs_submenu.addAction(open_debug_logs_folder_action)

        debug_logs_submenu.addSeparator()

        open_debug_log_action = QAction('📄 debug.log', self)
        open_debug_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug\\debug.log')
        open_debug_log_action.triggered.connect(self._open_debug_log_file)
        debug_logs_submenu.addAction(open_debug_log_action)

        open_warnings_log_action = QAction('📄 warnings.log', self)
        open_warnings_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug\\warnings.log')
        open_warnings_log_action.triggered.connect(self._open_warnings_log_file)
        debug_logs_submenu.addAction(open_warnings_log_action)

        open_error_log_action = QAction('📄 errors.log', self)
        open_error_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Debug\\errors.log')
        open_error_log_action.triggered.connect(self._open_error_log_file)
        debug_logs_submenu.addAction(open_error_log_action)

        # --- Application Logs Submenu ---
        app_logs_submenu = data_menu.addMenu('📋 Application Logs')
        if app_logs_submenu is None:
            msg = 'Failed to create Application Logs submenu'
            raise RuntimeError(msg)
        app_logs_submenu.setToolTipsVisible(True)
        cast('QAction', app_logs_submenu.menuAction()).setToolTip('Open or browse CSV application log files (detections, protection, UserIP)')

        open_logging_folder_action = QAction('📂 Open Logging Folder', self)
        open_logging_folder_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging')
        open_logging_folder_action.triggered.connect(self._open_logging_folder)
        app_logs_submenu.addAction(open_logging_folder_action)

        open_sessions_logs_action = QAction('🗂️ Open Sessions Folder', self)
        open_sessions_logs_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\Sessions')
        open_sessions_logs_action.triggered.connect(self._open_sessions_logging_folder)
        app_logs_submenu.addAction(open_sessions_logs_action)

        app_logs_submenu.addSeparator()

        open_detection_log_action = QAction('📄 Detection_Logging.csv', self)
        open_detection_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\Detection_Logging.csv')
        open_detection_log_action.triggered.connect(self._open_detection_log_file)
        app_logs_submenu.addAction(open_detection_log_action)

        open_protection_log_action = QAction('📄 Protection_Logging.csv', self)
        open_protection_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\Protection_Logging.csv')
        open_protection_log_action.triggered.connect(self._open_protection_log_file)
        app_logs_submenu.addAction(open_protection_log_action)

        open_userip_log_action = QAction('📄 UserIP_Logging.csv', self)
        open_userip_log_action.setToolTip('Open Local AppData\\Session Sniffer\\Logging\\UserIP_Logging.csv')
        open_userip_log_action.triggered.connect(self._open_userip_log_file)
        app_logs_submenu.addAction(open_userip_log_action)

        # ----- Settings menu -----
        settings_menu = menu_bar.addMenu('Settings')
        if settings_menu is None:
            msg = 'Failed to create Settings menu'
            raise RuntimeError(msg)
        settings_menu.setToolTipsVisible(True)

        open_settings_action = QAction('⚙️ Open Settings', self)
        open_settings_action.setToolTip('View and edit all application settings')
        open_settings_action.triggered.connect(self._open_settings_dialog)
        settings_menu.addAction(open_settings_action)

        settings_menu.addSeparator()

        always_on_top_action = QAction('📌 Always on Top', self)
        always_on_top_action.setToolTip('Keep the main window above all other windows')
        always_on_top_action.setCheckable(True)
        always_on_top_action.setChecked(False)
        always_on_top_action.toggled.connect(self._toggle_main_window_always_on_top)
        settings_menu.addAction(always_on_top_action)

        # ----- Help menu -----
        help_menu = menu_bar.addMenu('Help')
        if help_menu is None:
            msg = 'Failed to create Help menu'
            raise RuntimeError(msg)
        help_menu.setToolTipsVisible(True)

        repo_action = QAction('📦 Project Repository', self)
        repo_action.setToolTip('Open the Session Sniffer GitHub repository in your default web browser')
        repo_action.triggered.connect(self._open_project_repo)
        help_menu.addAction(repo_action)

        docs_action = QAction('📚 Documentation', self)
        docs_action.setToolTip('View the complete documentation and user guide for Session Sniffer')
        docs_action.triggered.connect(self._open_documentation)
        help_menu.addAction(docs_action)

        tips_action = QAction('💡 Tips and Tricks', self)
        tips_action.setToolTip('Learn optimization strategies, hidden features, and best practices')
        tips_action.triggered.connect(self._open_tips_and_tricks)
        help_menu.addAction(tips_action)

        release_notes_action = QAction('📋 Release Notes', self)
        release_notes_action.setToolTip('View the release history and notes on GitHub')
        release_notes_action.triggered.connect(self._open_release_notes)
        help_menu.addAction(release_notes_action)

        license_action = QAction('⚖️ View License', self)
        license_action.setToolTip('View the GNU General Public License (GPLv3) for Session Sniffer')
        license_action.triggered.connect(self._view_license)
        help_menu.addAction(license_action)

        help_menu.addSeparator()

        report_issue_action = QAction('🐛 Report Issue', self)
        report_issue_action.setToolTip('Open a new issue on GitHub to report a bug or request a feature')
        report_issue_action.triggered.connect(self._report_issue)
        help_menu.addAction(report_issue_action)

        discord_action = QAction('💬 Discord Server', self)
        discord_action.setToolTip('Join the official Session Sniffer Discord community for support and updates')
        discord_action.triggered.connect(self._join_discord)
        help_menu.addAction(discord_action)

        help_menu.addSeparator()

        check_updates_action = QAction('🔄 Check for Updates', self)
        check_updates_action.setToolTip('Check GitHub for a newer version of Session Sniffer')
        check_updates_action.triggered.connect(self._check_for_updates)
        help_menu.addAction(check_updates_action)

        help_menu.addSeparator()

        about_action = QAction('💡 About', self)
        about_action.setToolTip(f'About {TITLE}')
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)

        # Main title header
        self._header = QLabel()
        self._header.setTextFormat(Qt.TextFormat.RichText)
        self._header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header.setWordWrap(True)
        self._header.setFont(QFont('Courier', 10, QFont.Weight.Bold))

        # Connected and disconnected table sections
        connected_column_names = [
            col for col in Settings.GUI_ALL_CONNECTED_COLUMNS
            if col in set(Settings.gui_columns_connected_shown) or col in Settings.GUI_FORCED_COLUMNS
        ]
        self._connected = SessionTableSection(
            is_connected=True,
            column_names=connected_column_names,
            clear_slot=self._clear_connected_players,
            parent=self,
        )
        self._connected.table_view.open_rate_graph_callback = self._player_resolver_window.high_rate_monitor.open_graph

        self._tables_separator = QFrame(self)
        self._tables_separator.setFrameShape(QFrame.Shape.HLine)
        self._tables_separator.setFrameShadow(QFrame.Shadow.Sunken)

        disconnected_column_names = [
            col for col in Settings.GUI_ALL_DISCONNECTED_COLUMNS
            if col in set(Settings.gui_columns_disconnected_shown) or col in Settings.GUI_FORCED_COLUMNS
        ]
        self._disconnected = SessionTableSection(
            is_connected=False,
            column_names=disconnected_column_names,
            clear_slot=self._clear_disconnected_players,
            parent=self,
        )

        # Status bar
        self._status_bar = SessionStatusBar(self)
        self.setStatusBar(self._status_bar)

        # Menu action container
        self._actions = _MenuActions(
            toggle_capture=toggle_capture_action,
            change_interface=change_interface_action,
        )

        # Layout
        main_layout.addSpacing(4)
        main_layout.addWidget(self._header)
        main_layout.addSpacing(14)
        main_layout.addWidget(self._connected, 1)
        main_layout.addWidget(self._tables_separator)
        main_layout.addWidget(self._disconnected, 1)
        main_layout.addWidget(self._connected.expand_button)
        main_layout.addWidget(self._disconnected.expand_button)

        # Update separator when either section expands or collapses
        self._connected.section_toggled.connect(self._update_separator_visibility)
        self._disconnected.section_toggled.connect(self._update_separator_visibility)

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Create the worker thread for table updates
        worker_thread = GUIWorkerThread()
        self._state = _WindowState(
            worker_thread=worker_thread,
            window_being_moved=False,
            min_accepted_snapshot_version=0,
        )
        self._state.worker_thread.update_signal.connect(self._update_gui)
        self._state.worker_thread.start()

        # Session rate graph polling timer
        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(1_000)
        self._stats_timer.timeout.connect(self._tick_stats)
        self._stats_timer.start()

        # Install event filter to detect window movement/dragging
        self.installEventFilter(self)

    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:  # noqa: N802
        """Filter events to detect window movement."""
        if a0 == self and a1 is not None:
            event_type = a1.type()

            # Detect start of window movement/dragging
            if (
                event_type in (QEvent.Type.Move, QEvent.Type.Resize, QEvent.Type.WindowStateChange)
                and not self._state.window_being_moved
            ):
                self._start_window_move()

            # Detect end of window movement/dragging
            elif (
                event_type in (
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
        self.setWindowOpacity(0.85)
        self._header.setEnabled(False)
        self._connected.set_all_enabled(enabled=False)
        self._disconnected.set_all_enabled(enabled=False)
        self._tables_separator.setEnabled(False)
        status_bar = self.statusBar()
        if status_bar is None:
            return
        status_bar.setEnabled(False)

    def _end_window_move(self) -> None:
        """Restore opacity and re-enable UI elements after window movement/dragging ends."""
        self._state.window_being_moved = False
        self.setWindowOpacity(1.0)
        self._header.setEnabled(True)
        self._connected.set_all_enabled(enabled=True)
        self._disconnected.set_all_enabled(enabled=True)
        self._tables_separator.setEnabled(True)
        status_bar = self.statusBar()
        if status_bar is None:
            return
        status_bar.setEnabled(True)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802
        """Handle the main window close event and terminate background work."""
        gui_closed__event.set()
        if self.capture.is_running():
            self.capture.stop()
        ProcessSuspendManager.shutdown()
        self._state.worker_thread.quit()
        self._state.worker_thread.wait()
        if a0 is not None:
            a0.accept()
        terminate_script('EXIT')

    def _update_gui(self, payload: GUIUpdatePayload) -> None:
        self._header.setText(payload.header_text)
        self._status_bar.set_texts(
            capture=payload.status_capture_text,
            config=payload.status_config_text,
            issues=payload.status_issues_text,
            performance=payload.status_performance_text,
        )

        # Detect column config changes and rebuild tables when needed
        col_cfg = payload.column_config
        if col_cfg.connected_column_names != self._connected.table_model.column_names:
            self._connected.update_columns(col_cfg.connected_column_names)
        if col_cfg.disconnected_column_names != self._disconnected.table_model.column_names:
            self._disconnected.update_columns(col_cfg.disconnected_column_names)

        connected_count_changed = self._connected.last_count != payload.connected_num
        disconnected_count_changed = self._disconnected.last_count != payload.disconnected_num

        if connected_count_changed:
            self._connected.update_current_count(payload.connected_num)

        self._connected.table_view.capture_selection()
        self._disconnected.table_view.capture_selection()

        connected_payload_ips: set[str] = set()
        for processed_data, compiled_colors in payload.connected_rows_with_colors:
            ip = self._connected.table_model.get_ip_from_data_safely(processed_data)
            connected_payload_ips.add(ip)

            disconnected_row_index = self._disconnected.table_model.get_row_index_by_ip(ip)
            if disconnected_row_index is not None:
                self._disconnected.table_model.delete_row(disconnected_row_index)

            connected_row_index = self._connected.table_model.get_row_index_by_ip(ip)
            if connected_row_index is None:
                self._connected.table_model.add_row_without_refresh(processed_data, compiled_colors)
            else:
                self._connected.table_model.update_row_without_refresh(connected_row_index, processed_data, compiled_colors)

        self._prune_missing_rows(self._connected.table_model, connected_payload_ips)

        if self._connected.table_view.isVisible():
            self._connected.table_view.sort_current_column()
            self._connected.table_view.adjust_username_column_width()

        if disconnected_count_changed:
            self._disconnected.update_current_count(payload.disconnected_num)

        disconnected_payload_ips: set[str] = set()
        for processed_data, compiled_colors in payload.disconnected_rows_with_colors:
            ip = self._disconnected.table_model.get_ip_from_data_safely(processed_data)
            disconnected_payload_ips.add(ip)

            connected_row_index = self._connected.table_model.get_row_index_by_ip(ip)
            if connected_row_index is not None:
                self._connected.table_model.delete_row(connected_row_index)

            disconnected_row_index = self._disconnected.table_model.get_row_index_by_ip(ip)
            if disconnected_row_index is None:
                self._disconnected.table_model.add_row_without_refresh(processed_data, compiled_colors)
            else:
                self._disconnected.table_model.update_row_without_refresh(disconnected_row_index, processed_data, compiled_colors)

        self._prune_missing_rows(self._disconnected.table_model, disconnected_payload_ips)

        if self._disconnected.table_view.isVisible():
            self._disconnected.table_view.sort_current_column()
            self._disconnected.table_view.adjust_username_column_width()

        self._connected.table_view.restore_selection()
        self._disconnected.table_view.restore_selection()

        # Refresh selection counts after potential row removals
        self._connected.refresh_selection_count()
        self._disconnected.refresh_selection_count()

        # Sync pagination controls with payload data
        self._connected.sync_paging_from_payload(
            total_count=payload.connected_num,
            rows_per_page=payload.connected_rows_per_page,
            page=payload.connected_page,
        )
        self._disconnected.sync_paging_from_payload(
            total_count=payload.disconnected_num,
            rows_per_page=payload.disconnected_rows_per_page,
            page=payload.disconnected_page,
        )

        if self._session_host_submenu.isEnabled() != CaptureState.gta5_is_running:
            if CaptureState.gta5_is_running:
                gta5 = find_running_gta5_path()
                version = 'GTA V Enhanced' if gta5.is_enhanced else 'GTA V Legacy'
                self._gta5_status_label.setText(f'<span style="color: #4CAF50;">●</span> {version}')
                self._gta5_status_label.setToolTip(str(gta5.path) if gta5.is_running else 'GTA V process detection state')
            else:
                self._gta5_status_label.setText('<span style="color: #F44336;">●</span> GTA V not running')
                self._gta5_status_label.setToolTip('GTA V process detection state')
            self._session_host_submenu.setEnabled(CaptureState.gta5_is_running)
            self._player_resolver_action.setEnabled(CaptureState.gta5_is_running)
            self._sync_gta5_process_button()

        if self._capture_statistics_window is not None:
            self._capture_statistics_window.refresh()

    @staticmethod
    def _prune_missing_rows(model: SessionTableModel, ips_to_keep: set[str]) -> None:
        """Remove rows from the model whose IPs are not in the current payload."""
        stale_ips = set(model.get_all_ips()) - ips_to_keep
        for ip in stale_ips:
            model.remove_player_by_ip(ip)

    def _clear_session_host(self) -> None:
        """Manually clear the current session host and reset host detection state."""
        SessionHost.clear_session_host_data()

    def _redetect_session_host(self) -> None:
        """Clear the current session host and immediately re-trigger host detection."""
        SessionHost.clear_session_host_data()
        SessionHost.search_player = True
        SessionHost.manual_redetect = True

    def _toggle_main_window_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        """Toggle the always-on-top window flag for this session."""
        apply_always_on_top(self, checked)

    def _open_settings_dialog(self) -> None:
        """Open the Settings window, or focus the existing one."""
        if self._settings_dialog_window is not None and self._settings_dialog_window.isVisible():
            self._settings_dialog_window.raise_()
            self._settings_dialog_window.activateWindow()
            return
        self._settings_dialog_window = SettingsDialog(self, self.capture.get())
        self._settings_dialog_window.accepted.connect(self._update_gta5_toolbar_visibility)
        self._settings_dialog_window.destroyed.connect(lambda: setattr(self, '_settings_dialog_window', None))
        self._settings_dialog_window.show()

    def _open_userip_manager(self) -> None:
        """Open the UserIP Databases Manager window, or focus the existing one."""
        if self._userip_manager_window is not None and self._userip_manager_window.isVisible():
            self._userip_manager_window.raise_()
            self._userip_manager_window.activateWindow()
            return
        self._userip_manager_window = UserIPDatabasesManager(self)
        self._userip_manager_window.destroyed.connect(lambda: setattr(self, '_userip_manager_window', None))
        self._userip_manager_window.show()

    def _open_logs_manager(self) -> None:
        """Open the Logs Manager window, or focus the existing one."""
        if self._logs_manager_window is not None and self._logs_manager_window.isVisible():
            self._logs_manager_window.raise_()
            self._logs_manager_window.activateWindow()
            return
        self._logs_manager_window = LogsManager(self)
        self._logs_manager_window.destroyed.connect(lambda: setattr(self, '_logs_manager_window', None))
        self._logs_manager_window.show()

    def _open_detections_manager(self) -> None:
        """Open the Detections Manager window, or focus the existing one."""
        if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
            self._detections_manager_window.raise_()
            self._detections_manager_window.activateWindow()
            return
        self._detections_manager_window = DetectionsManagerDialog(self)
        self._detections_manager_window.destroyed.connect(lambda: setattr(self, '_detections_manager_window', None))
        self._detections_manager_window.show()

    def _open_player_resolver(self) -> None:
        """Open the Player Resolver window, or focus the existing one."""
        self._player_resolver_window.show_and_focus()

    def _update_header_capture_status(self) -> None:
        """Immediately update the header text to reflect current capture state."""
        self._header.setText(generate_gui_header_html(capture=self.capture.get()))

    def _toggle_capture(self) -> None:
        """Toggle the packet capture on/off."""
        if self.capture.is_running():
            self.capture.stop()
            self._actions.toggle_capture.setText('▶️ Start Capture')
            self._actions.toggle_capture.setToolTip('Start packet capture')
        else:
            self.capture.start()
            self._actions.toggle_capture.setText('⏹️ Stop Capture')
            self._actions.toggle_capture.setToolTip('Stop packet capture')

        self._update_header_capture_status()

    def set_interface_switching_mode(self, *, switching: bool) -> None:
        """Disable or re-enable the UI while an interface switch is in progress."""
        menu_bar = self.menuBar()
        if menu_bar is not None:
            menu_bar.setEnabled(not switching)
        self._actions.change_interface.setEnabled(not switching)
        self._connected.set_all_enabled(enabled=not switching)
        self._disconnected.set_all_enabled(enabled=not switching)
        self._tables_separator.setEnabled(not switching)
        status_bar = self.statusBar()
        if status_bar is not None:
            status_bar.setEnabled(not switching)

    def set_change_interface_button_enabled(self, *, enabled: bool) -> None:
        """Enable or disable only the Change Interface toolbar button."""
        self._actions.change_interface.setEnabled(enabled)

    def reset_players_for_interface_switch(self) -> None:
        """Clear all player data in preparation for a new capture interface."""
        self._clear_connected_players()
        self._clear_disconnected_players()
        SessionHost.clear_history()

    def set_capture_toggle_enabled(self, *, enabled: bool) -> None:
        """Enable or disable the Stop/Start Capture toolbar button."""
        self._actions.toggle_capture.setEnabled(enabled)

    def on_interface_switched(self) -> None:
        """Synchronize GUI state after the capture interface has been replaced."""
        self._update_gta5_toolbar_visibility()
        # Sync the toggle button text to reflect the running state of the new capture
        if self.capture.is_running():
            self._actions.toggle_capture.setText('⏹️ Stop Capture')
            self._actions.toggle_capture.setToolTip('Stop packet capture')
        else:
            self._actions.toggle_capture.setText('▶️ Start Capture')
            self._actions.toggle_capture.setToolTip('Start packet capture')
        self._actions.toggle_capture.setEnabled(True)
        self._update_header_capture_status()

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
                ProcessSuspendManager.release_reasons_for_ip(ip)
            MobileWarnings.remove_notified_ips_batch(connected_ips)
            VPNWarnings.remove_notified_ips_batch(connected_ips)
            HostingWarnings.remove_notified_ips_batch(connected_ips)

    def _clear_disconnected_players(self) -> None:
        """Clear all disconnected players from the table and registry."""
        self._state.min_accepted_snapshot_version = GUIRenderingState.get_version() + 1
        disconnected_players = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        disconnected_ips = {player.ip for player in disconnected_players}

        PlayersRegistry.clear_disconnected_players()
        SessionHost.players_pending_for_disconnection = [
            p for p in SessionHost.players_pending_for_disconnection if p.ip not in disconnected_ips
        ]
        self._disconnected.clear_table()

        if disconnected_ips:
            for ip in disconnected_ips:
                ProcessSuspendManager.release_reasons_for_ip(ip)
            MobileWarnings.remove_notified_ips_batch(disconnected_ips)
            VPNWarnings.remove_notified_ips_batch(disconnected_ips)
            HostingWarnings.remove_notified_ips_batch(disconnected_ips)
