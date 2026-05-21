"""Main window implementation for Session Sniffer."""  # pylint: disable=too-many-lines

import os
import webbrowser
from dataclasses import dataclass
from threading import Event
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QEvent, QItemSelection, QItemSelectionModel, QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from session_sniffer import msgbox
from session_sniffer.background import gui_closed__event
from session_sniffer.background.suspend_manager import ProcessSuspendManager
from session_sniffer.constants.local import (
    APP_DIR_LOCAL,
    APP_DIR_ROAMING,
    DEBUG_DIR_PATH,
    DEBUG_LOG_PATH,
    DETECTION_LOGGING_PATH,
    ERRORS_LOG_PATH,
    LOGGING_DIR_PATH,
    PROTECTION_LOGGING_PATH,
    SESSIONS_LOGGING_DIR_PATH,
    SETTINGS_PATH,
    USER_SCRIPTS_DIR_PATH,
    USERIP_DATABASES_DIR_PATH,
    USERIP_LOGGING_PATH,
    WARNINGS_LOG_PATH,
)
from session_sniffer.constants.standalone import DISCORD_INVITE_URL, TITLE
from session_sniffer.core import terminate_script
from session_sniffer.error_messages import (
    format_gta5_solo_session_no_process_path_message,
    format_gta5_solo_session_process_not_running_message,
    format_gta5_solo_session_suspend_failed_message,
)
from session_sniffer.guis.capture_statistics_window import CaptureStatisticsWindow
from session_sniffer.guis.country_breakdown import CountryBreakdownWindow
from session_sniffer.guis.detections_manager import DetectionsManagerDialog
from session_sniffer.guis.html_templates import generate_gui_header_html
from session_sniffer.guis.logs_manager import LogsManager
from session_sniffer.guis.packets_latency_graph import PacketsLatencyGraphWindow
from session_sniffer.guis.player_leaderboard import PlayerLeaderboardWindow
from session_sniffer.guis.player_resolver import PlayerResolverWindow
from session_sniffer.guis.port_heatmap import PortHeatmapWindow
from session_sniffer.guis.reconnect_frequency import ReconnectFrequencyWindow
from session_sniffer.guis.session_bps_graph import SessionBpsGraphWindow
from session_sniffer.guis.session_duration import SessionDurationWindow
from session_sniffer.guis.session_pps_graph import SessionPpsGraphWindow
from session_sniffer.guis.session_rate_graph import SessionRateGraphWindow
from session_sniffer.guis.session_timeline import SessionTimelineWindow
from session_sniffer.guis.settings_dialog import SettingsDialog
from session_sniffer.guis.stylesheets import (
    COMMON_COLLAPSE_BUTTON_STYLESHEET,
    CONNECTED_CLEAR_BUTTON_STYLESHEET,
    CONNECTED_EXPAND_BUTTON_STYLESHEET,
    CONNECTED_HEADER_CONTAINER_STYLESHEET,
    CONNECTED_HEADER_TEXT_STYLESHEET,
    DISCONNECTED_CLEAR_BUTTON_STYLESHEET,
    DISCONNECTED_EXPAND_BUTTON_STYLESHEET,
    DISCONNECTED_HEADER_CONTAINER_STYLESHEET,
    DISCONNECTED_HEADER_TEXT_STYLESHEET,
    MENU_BAR_STYLESHEET,
    STATUS_BAR_CAPTURE_LABEL_STYLESHEET,
    STATUS_BAR_CONFIG_LABEL_STYLESHEET,
    STATUS_BAR_ISSUES_LABEL_STYLESHEET,
    STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET,
    STATUS_BAR_STYLESHEET,
)
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables import SessionTableView
from session_sniffer.guis.userip_manager import UserIPDatabasesManager
from session_sniffer.guis.utils import resize_window_for_screen
from session_sniffer.guis.worker_thread import GUIWorkerThread
from session_sniffer.logging_setup import get_logger
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.player.warnings import HostingWarnings, MobileWarnings, VPNWarnings
from session_sniffer.rendering_core.types import CaptureState, CaptureStats, GUIRenderingState, GUIUpdatePayload, PaginationState
from session_sniffer.settings import Settings
from session_sniffer.utils import get_pid_by_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.models.player import Player

logger = get_logger(__name__)

GITHUB_REPO_URL = 'https://github.com/BUZZARDGTA/Session-Sniffer'
DOCUMENTATION_URL = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki'


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


class SessionStatusBar(QStatusBar):
    """Status bar with dedicated labels for capture, config, issues, and performance info."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Create the status bar and add the four section labels."""
        super().__init__(parent)
        self.setSizeGripEnabled(False)
        self.setStyleSheet(STATUS_BAR_STYLESHEET)

        self._capture_label = QLabel()
        self._capture_label.setTextFormat(Qt.TextFormat.RichText)
        self._capture_label.setStyleSheet(STATUS_BAR_CAPTURE_LABEL_STYLESHEET)

        self._config_label = QLabel()
        self._config_label.setTextFormat(Qt.TextFormat.RichText)
        self._config_label.setStyleSheet(STATUS_BAR_CONFIG_LABEL_STYLESHEET)

        self._issues_label = QLabel()
        self._issues_label.setTextFormat(Qt.TextFormat.RichText)
        self._issues_label.setStyleSheet(STATUS_BAR_ISSUES_LABEL_STYLESHEET)

        self._performance_label = QLabel()
        self._performance_label.setTextFormat(Qt.TextFormat.RichText)
        self._performance_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._performance_label.setStyleSheet(STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET)

        self.addWidget(self._capture_label)
        self.addWidget(self._config_label)
        self.addWidget(self._issues_label)
        self.addPermanentWidget(self._performance_label)

    def set_texts(self, *, capture: str, config: str, issues: str, performance: str) -> None:
        """Update all four status label texts at once."""
        self._capture_label.setText(capture)
        self._config_label.setText(config)
        self._issues_label.setText(issues)
        self._performance_label.setText(performance)


class SessionTableSection(QWidget):
    """Self-contained collapsible widget containing a session table with header controls."""

    section_toggled = pyqtSignal()
    table_model: SessionTableModel
    table_view: SessionTableView

    def __init__(
        self,
        *,
        is_connected: bool,
        column_names: list[str],
        clear_slot: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        """Build the header, table, and expand button for a collapsible session section."""
        super().__init__(parent)

        self._section_name = 'Connected' if is_connected else 'Disconnected'
        self.last_count: int = -1
        self._selected_count: int = 0

        self._is_connected = is_connected
        self._rows_keyboard_editing = False

        if is_connected:
            header_container_stylesheet = CONNECTED_HEADER_CONTAINER_STYLESHEET
            header_text_stylesheet = CONNECTED_HEADER_TEXT_STYLESHEET
            clear_button_stylesheet = CONNECTED_CLEAR_BUTTON_STYLESHEET
            expand_button_stylesheet = CONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = 'Hide the connected players table'
            clear_tooltip = 'Clear all connected players'
            expand_tooltip = 'Show the connected players table'
            sort_column_name = 'Last Rejoin'
            sort_order = Qt.SortOrder.DescendingOrder
        else:
            header_container_stylesheet = DISCONNECTED_HEADER_CONTAINER_STYLESHEET
            header_text_stylesheet = DISCONNECTED_HEADER_TEXT_STYLESHEET
            clear_button_stylesheet = DISCONNECTED_CLEAR_BUTTON_STYLESHEET
            expand_button_stylesheet = DISCONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = 'Hide the disconnected players table'
            clear_tooltip = 'Clear all disconnected players'
            expand_tooltip = 'Show the disconnected players table'
            sort_column_name = 'Last Seen'
            sort_order = Qt.SortOrder.AscendingOrder

        # Header container
        header_container = QWidget()
        header_container.setStyleSheet(header_container_stylesheet)
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)

        self._header_label = QLabel(self._header_label_text())
        self._header_label.setTextFormat(Qt.TextFormat.RichText)
        self._header_label.setStyleSheet(header_text_stylesheet)
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header_label.setFont(QFont('Courier', 9, QFont.Weight.Bold))

        clear_button = QPushButton('CLEAR')
        clear_button.setToolTip(clear_tooltip)
        clear_button.setStyleSheet(clear_button_stylesheet)
        clear_button.clicked.connect(clear_slot)

        collapse_button = QPushButton('▼')
        collapse_button.setToolTip(collapse_tooltip)
        collapse_button.setStyleSheet(COMMON_COLLAPSE_BUTTON_STYLESHEET)
        collapse_button.clicked.connect(self.minimize)

        header_layout.addWidget(self._header_label, 1)

        # Pagination controls — rows per page
        rows_label = QLabel('Rows:')
        rows_label.setToolTip('Rows per page (0 = show all)')
        header_layout.addWidget(rows_label)

        initial_rpp = (
            Settings.gui_connected_table_rows_per_page
            if is_connected
            else Settings.gui_disconnected_table_rows_per_page
        )

        self._rows_per_page_spinbox = QSpinBox()
        self._rows_per_page_spinbox.setRange(0, 5000)
        self._rows_per_page_spinbox.setSpecialValueText('All')
        self._rows_per_page_spinbox.setSuffix(' rows/page')
        self._rows_per_page_spinbox.setValue(initial_rpp)
        self._rows_per_page_spinbox.setToolTip(
            f'Limit how many {self._section_name.lower()} players are shown per page. Set 0 to show all.',
        )
        self._rows_per_page_spinbox.setKeyboardTracking(False)
        self._rows_per_page_spinbox.valueChanged.connect(self._handle_rows_per_page_changed)
        self._rows_per_page_spinbox.editingFinished.connect(self._finalize_rows_edit)
        header_layout.addWidget(self._rows_per_page_spinbox)
        self._install_spinbox_input_filter(self._rows_per_page_spinbox)

        # Pagination controls — page number
        page_label = QLabel('Page:')
        page_label.setToolTip('Current page when rows are limited.')
        header_layout.addWidget(page_label)

        self._page_spinbox = QSpinBox()
        self._page_spinbox.setRange(1, 1)
        self._page_spinbox.setToolTip('Jump between pages when a row limit is set.')
        self._page_spinbox.setSuffix(' / 1')
        self._page_spinbox.valueChanged.connect(self._handle_page_changed)
        header_layout.addWidget(self._page_spinbox)

        # Internal paging state
        self._rows_per_page: int = initial_rpp
        self._current_page: int = 1
        self._total_pages: int = 1

        # Seed PaginationState so the worker thread knows the initial values
        if is_connected:
            PaginationState.set_connected(rows_per_page=initial_rpp, page=1)
        else:
            PaginationState.set_disconnected(rows_per_page=initial_rpp, page=1)

        header_layout.addWidget(clear_button)
        header_layout.addWidget(collapse_button)

        # Table model and view
        self.table_model = SessionTableModel(column_names)
        self.table_view = SessionTableView(
            self.table_model,
            column_names.index(sort_column_name),
            sort_order,
            is_connected_table=is_connected,
        )
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.table_view.setup_static_column_resizing()
        self.table_model.view = self.table_view

        # Expand button (shown when section is collapsed; laid out by MainWindow, not this section)
        self.expand_button = QPushButton(f'▲  Show {self._section_name} Players (0)')
        self.expand_button.setToolTip(expand_tooltip)
        self.expand_button.setStyleSheet(expand_button_stylesheet)
        self.expand_button.setVisible(False)
        self.expand_button.clicked.connect(self.expand)

        # Section layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header_container)
        layout.addWidget(self.table_view, 1)

        self.table_view.selectionModel().selectionChanged.connect(self._on_selection_changed)

    @property
    def _header_widget(self) -> QWidget:
        """The header container widget, accessed via the header label's parent."""
        return cast('QWidget', self._header_label.parentWidget())

    @property
    def is_expanded(self) -> bool:
        """True when the section content (header + table) is visible."""
        return self.isVisible()

    def expand(self) -> None:
        """Show section content and hide the expand button."""
        self.expand_button.setVisible(False)
        self.setVisible(True)
        self.table_model.refresh_view()
        self.section_toggled.emit()

    def minimize(self) -> None:
        """Collapse section to just an expand button."""
        self.setVisible(False)
        self.expand_button.setText(
            f'▲  Show {self._section_name} Players ({max(self.last_count, 0)})',
        )
        self.expand_button.setVisible(True)
        self.section_toggled.emit()

    def update_current_count(self, count: int) -> None:
        """Update the player count, refresh the header, and sync the expand button text."""
        self.last_count = count
        self._update_header_label()
        if not self.is_expanded:
            self.expand_button.setText(
                f'▲  Show {self._section_name} Players ({count})',
            )

    def clear_table(self) -> None:
        """Clear all table data and reset selection count."""
        self.table_model.reset_columns()
        self._selected_count = 0
        self._update_header_label()

    def update_columns(self, column_names: list[str]) -> None:
        """Replace the column set at runtime and reconfigure the view."""
        sort_col_name = 'Last Rejoin' if self._section_name == 'Connected' else 'Last Seen'
        self.table_model.reset_columns(column_names)
        sort_index = column_names.index(sort_col_name)
        header = self.table_view.horizontalHeader()
        header.setSortIndicator(sort_index, header.sortIndicatorOrder())
        self.table_view.setup_static_column_resizing()

    def set_all_enabled(self, *, enabled: bool) -> None:
        """Enable or disable all interactive child widgets."""
        self._header_widget.setEnabled(enabled)
        self.table_view.setEnabled(enabled)
        self.expand_button.setEnabled(enabled)

    def _header_label_text(self) -> str:
        intro = 'Players connected in your session' if self._section_name == 'Connected' else "Players who've left your session"
        base = f'{intro} ({max(0, self.last_count)}):'
        if self._selected_count > 0:
            noun = 'player' if self._selected_count == 1 else 'players'
            return f'{base} ({self._selected_count} {noun} selected)'
        return base

    def _update_header_label(self) -> None:
        self._header_label.setText(self._header_label_text())

    def refresh_selection_count(self) -> None:
        """Recompute the selected-row count and update the header label."""
        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        self._selected_count = len({idx.row() for idx in self.table_view.selectionModel().selectedIndexes()})
        self._update_header_label()

    # -- Pagination handlers --------------------------------------------------

    def _handle_rows_per_page_changed(self, value: int) -> None:
        self._rows_per_page = max(value, 0)
        self._current_page, self._total_pages = self._sync_paging_controls(
            total_rows=max(self.last_count, 0),
            rows_per_page=self._rows_per_page,
            requested_page=1,
        )
        self._push_pagination_state()
        self._update_header_label()

    def _handle_page_changed(self, value: int) -> None:
        self._current_page = max(value, 1)
        self._push_pagination_state()
        self._update_header_label()

    def _finalize_rows_edit(self) -> None:
        val = self._rows_per_page_spinbox.value()
        self._handle_rows_per_page_changed(val)
        self._rows_per_page_spinbox.clearFocus()

    def _push_pagination_state(self) -> None:
        """Write current pagination state to the shared PaginationState."""
        if self._is_connected:
            PaginationState.set_connected(rows_per_page=self._rows_per_page, page=self._current_page)
        else:
            PaginationState.set_disconnected(rows_per_page=self._rows_per_page, page=self._current_page)

    def _sync_paging_controls(
        self,
        *,
        total_rows: int,
        rows_per_page: int,
        requested_page: int,
    ) -> tuple[int, int]:
        """Update the page spinbox range/value and return (clamped_page, total_pages)."""
        if not rows_per_page:
            total_pages = 1
            page = 1
        else:
            total_pages = max(1, (total_rows + rows_per_page - 1) // rows_per_page)
            page = min(max(1, requested_page), total_pages)

        self._page_spinbox.blockSignals(True)
        self._page_spinbox.setMinimum(1)
        self._page_spinbox.setMaximum(total_pages)
        self._page_spinbox.setEnabled(0 < rows_per_page < total_rows)
        self._page_spinbox.setValue(page)
        self._page_spinbox.blockSignals(False)

        return page, total_pages

    def sync_paging_from_payload(
        self,
        *,
        total_count: int,
        rows_per_page: int,
        page: int,
    ) -> None:
        """Called from _update_gui to keep spinbox decorations in sync."""
        self._rows_per_page = rows_per_page

        if not self._rows_keyboard_editing:
            self._rows_per_page_spinbox.setRange(0, 5000)
            if self._rows_per_page > 0:
                self._rows_per_page_spinbox.setPrefix(f'{total_count} / ')
                self._rows_per_page_spinbox.setSuffix('')
                self._rows_per_page_spinbox.setSpecialValueText('')
            else:
                self._rows_per_page_spinbox.setPrefix('')
                self._rows_per_page_spinbox.setSuffix('')
                self._rows_per_page_spinbox.setSpecialValueText(f'All ({total_count})')

        self._current_page, self._total_pages = self._sync_paging_controls(
            total_rows=max(self.last_count, 0),
            rows_per_page=self._rows_per_page,
            requested_page=page,
        )
        self._push_pagination_state()

        if not self._rows_keyboard_editing:
            self._page_spinbox.setSuffix(f' / {self._total_pages}')

    def _install_spinbox_input_filter(self, spinbox: QSpinBox) -> None:
        """Attach an event filter that tracks keyboard vs. wheel editing."""
        line_edit = spinbox.lineEdit()
        if line_edit is None:
            return

        section = self

        class _SpinboxInputGuard(QObject):
            def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
                """Track input method to distinguish keyboard edits from wheel/spin changes."""
                _ = a0
                if a1 is None:
                    return False
                et = a1.type()
                if et == QEvent.Type.KeyPress:
                    section.set_keyboard_editing(is_editing=True)
                elif et in (QEvent.Type.FocusOut, QEvent.Type.Hide, QEvent.Type.Wheel):
                    section.set_keyboard_editing(is_editing=False)
                return False

        guard = _SpinboxInputGuard(self)
        spinbox.installEventFilter(guard)
        line_edit.installEventFilter(guard)
        # prevent GC
        self._spinbox_guard = guard

    def set_keyboard_editing(self, *, is_editing: bool) -> None:
        """Set the keyboard editing state for the rows-per-page spinbox."""
        self._rows_keyboard_editing = is_editing


class MainWindow(QMainWindow):
    """Main Qt window that hosts session tables and control UI."""

    _actions: _MenuActions
    _connected: SessionTableSection
    _disconnected: SessionTableSection
    _gta5_menu: QMenu
    _gta5_process_submenu: QMenu
    _gta5_suspend_resume_action: QAction
    _gta5_solo_menu_action: QAction
    _manual_gta5_suspend_active: bool
    _gta5_solo_active: bool
    _gta5_process_suspended: bool
    _player_resolver_action: QAction

    def _update_separator_visibility(self) -> None:
        self._tables_separator.setVisible(
            self._connected.is_expanded or self._disconnected.is_expanded,
        )

    def __init__(self, screen_width: int, screen_height: int, capture_holder: CaptureHolder, on_change_interface: Callable[[], None]) -> None:
        """Initialize the main application window.

        Args:
            screen_width: Primary screen width in pixels.
            screen_height: Primary screen height in pixels.
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
        self._leaderboard_window: PlayerLeaderboardWindow | None = None
        self._session_rate_graph_window: SessionRateGraphWindow | None = None
        self._session_pps_graph_window: SessionPpsGraphWindow | None = None
        self._session_bps_graph_window: SessionBpsGraphWindow | None = None
        self._packets_latency_graph_window: PacketsLatencyGraphWindow | None = None
        self._country_breakdown_window: CountryBreakdownWindow | None = None
        self._reconnect_frequency_window: ReconnectFrequencyWindow | None = None
        self._session_timeline_window: SessionTimelineWindow | None = None
        self._port_heatmap_window: PortHeatmapWindow | None = None
        self._session_duration_window: SessionDurationWindow | None = None
        self._capture_statistics_window: CaptureStatisticsWindow | None = None

        # Set up the window
        self.setWindowTitle(TITLE)
        self.setMinimumSize(800, 600)
        resize_window_for_screen(self, screen_width, screen_height)

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
        gta5_menu_action.setVisible(Settings.capture_program_preset == 'GTA5')
        self._gta5_menu = gta5_menu

        player_resolver_action = QAction('🔍 Player Resolver', self)
        player_resolver_action.setToolTip('High Rate Monitor and Player Identifier tools')
        player_resolver_action.triggered.connect(self._open_player_resolver)
        gta5_menu.addAction(player_resolver_action)
        self._player_resolver_action = player_resolver_action

        gta5_menu.addSeparator()

        gta5_process_submenu = gta5_menu.addMenu('🎮 GTA5 Process')
        if gta5_process_submenu is None:
            msg = 'Failed to create GTA5 Process submenu'
            raise RuntimeError(msg)
        gta5_process_submenu.setToolTipsVisible(True)
        self._gta5_process_submenu = gta5_process_submenu

        gta5_menu_solo_action = QAction('🎯 Solo Public Session (~8s)', self)
        gta5_menu_solo_action.setToolTip(
            'Suspend GTA5 for ~8 seconds then auto-resume.\n'
            'This forces the game to spawn you alone in a public session.',
        )
        gta5_menu_solo_action.triggered.connect(self._gta5_solo_session)
        gta5_process_submenu.addAction(gta5_menu_solo_action)

        gta5_process_submenu.addSeparator()

        gta5_suspend_resume_action = QAction('⏸️ Suspend Process', self)
        gta5_suspend_resume_action.setToolTip('Manually suspend the GTA5 process — stays suspended until you click it again to resume')
        gta5_suspend_resume_action.triggered.connect(self._toggle_manual_gta5_suspend)
        gta5_process_submenu.addAction(gta5_suspend_resume_action)

        self._gta5_solo_menu_action = gta5_menu_solo_action
        self._gta5_suspend_resume_action = gta5_suspend_resume_action
        self._manual_gta5_suspend_active = False
        self._gta5_solo_active = False
        self._gta5_process_suspended = False
        self._gta5_process_detected = False
        if Settings.capture_program_preset == 'GTA5':
            self._sync_gta5_process_button()

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

        leaderboard_action = QAction('🏆 Most Seen Players', self)
        leaderboard_action.setToolTip('View a leaderboard of the most frequently seen players across sessions')
        leaderboard_action.triggered.connect(self._open_player_leaderboard)
        tools_menu.addAction(leaderboard_action)

        tools_menu.addSeparator()

        logs_manager_action = QAction('📋 Logs Manager', self)
        logs_manager_action.setToolTip('View, search, filter, and manage application log files')
        logs_manager_action.triggered.connect(self._open_logs_manager)
        tools_menu.addAction(logs_manager_action)

        userip_manager_action = QAction('🗃️ UserIP Manager', self)
        userip_manager_action.setToolTip('Browse, edit, add, and delete entries in UserIP database files')
        userip_manager_action.triggered.connect(self._open_userip_manager)
        tools_menu.addAction(userip_manager_action)

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

        open_settings_action = QAction('⚙️ Open Settings', self)
        open_settings_action.setToolTip('View and edit all application settings')
        open_settings_action.triggered.connect(self._open_settings_dialog)
        settings_menu.addAction(open_settings_action)

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

        discord_action = QAction('💬 Discord Server', self)
        discord_action.setToolTip('Join the official Session Sniffer Discord community for support and updates')
        discord_action.triggered.connect(self._join_discord)
        help_menu.addAction(discord_action)

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

    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
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

    def closeEvent(self, a0: QCloseEvent | None) -> None:
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

    @staticmethod
    def _prune_missing_rows(model: SessionTableModel, ips_to_keep: set[str]) -> None:
        """Remove rows from the model whose IPs are not in the current payload."""
        stale_ips = set(model.get_all_ips()) - ips_to_keep
        for ip in stale_ips:
            model.remove_player_by_ip(ip)

    def _open_project_repo(self) -> None:
        """Open the GitHub repository in the default browser."""
        webbrowser.open(GITHUB_REPO_URL)

    def _open_documentation(self) -> None:
        """Open the documentation URL in the default browser."""
        webbrowser.open(DOCUMENTATION_URL)

    def _join_discord(self) -> None:
        """Open the Discord invite URL in the default browser."""
        webbrowser.open(DISCORD_INVITE_URL)

    def _open_directory(self, directory_path: Path) -> None:
        """Ensure a directory exists and open it in Windows Explorer."""
        directory_path.mkdir(parents=True, exist_ok=True)
        os.startfile(str(directory_path))

    def _open_file(self, file_path: Path) -> None:
        """Ensure a file path exists and open the file using the default Windows association."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch(exist_ok=True)
        os.startfile(str(file_path))

    def _open_local_appdata_folder(self) -> None:
        """Open the Local AppData Session Sniffer directory."""
        self._open_directory(APP_DIR_LOCAL)

    def _open_roaming_appdata_folder(self) -> None:
        """Open the Roaming AppData Session Sniffer directory."""
        self._open_directory(APP_DIR_ROAMING)

    def _open_userip_databases_folder(self) -> None:
        """Open the UserIP databases directory."""
        self._open_directory(USERIP_DATABASES_DIR_PATH)

    def _open_sessions_logging_folder(self) -> None:
        """Open the sessions logging directory."""
        self._open_directory(SESSIONS_LOGGING_DIR_PATH)

    def _open_user_scripts_folder(self) -> None:
        """Open the user scripts directory."""
        self._open_directory(USER_SCRIPTS_DIR_PATH)

    def _open_settings_file(self) -> None:
        """Open the Settings.ini file."""
        self._open_file(SETTINGS_PATH)

    def _open_userip_log_file(self) -> None:
        """Open the UserIP_Logging.csv file."""
        self._open_file(USERIP_LOGGING_PATH)

    def _open_detection_log_file(self) -> None:
        """Open the Detection_Logging.csv file."""
        self._open_file(DETECTION_LOGGING_PATH)

    def _open_protection_log_file(self) -> None:
        """Open the Protection_Logging.csv file."""
        self._open_file(PROTECTION_LOGGING_PATH)

    def _open_error_log_file(self) -> None:
        """Open the errors.log file."""
        self._open_file(ERRORS_LOG_PATH)

    def _open_warnings_log_file(self) -> None:
        """Open the warnings.log file."""
        self._open_file(WARNINGS_LOG_PATH)

    def _open_debug_log_file(self) -> None:
        """Open the debug.log file."""
        self._open_file(DEBUG_LOG_PATH)

    def _open_debug_logs_folder(self) -> None:
        """Open the Debug logs directory."""
        self._open_directory(DEBUG_DIR_PATH)

    def _open_logging_folder(self) -> None:
        """Open the Logging directory."""
        self._open_directory(LOGGING_DIR_PATH)

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
        self._player_resolver_window.show()
        self._player_resolver_window.raise_()
        self._player_resolver_window.activateWindow()

    def _gta5_has_any_process_path(self) -> bool:
        """Return `True` if any protection has a GTA5 process path configured."""
        return any(
            getattr(GUIProtectionSettings, attr) is not None
            for attr in (
                'gta5_relay_process_path',
                'mobile_suspend_process_path',
                'vpn_suspend_process_path',
                'hosting_suspend_process_path',
                'country_block_process_path',
                'isp_block_process_path',
                'asn_block_process_path',
                'player_join_process_path',
                'player_rejoin_process_path',
                'player_leave_process_path',
            )
        )

    def _get_gta5_process_path(self) -> Path | None:
        """Return the first configured process path across all GTA5 protections, or `None`."""
        return next(
            (
                p for attr in (
                    'gta5_relay_process_path',
                    'mobile_suspend_process_path',
                    'vpn_suspend_process_path',
                    'hosting_suspend_process_path',
                    'country_block_process_path',
                    'isp_block_process_path',
                    'asn_block_process_path',
                    'player_join_process_path',
                    'player_rejoin_process_path',
                    'player_leave_process_path',
                )
                if (p := getattr(GUIProtectionSettings, attr)) is not None
            ),
            None,
        )

    def _gta5_process_is_running(self) -> bool:
        """Return `True` if the configured GTA5 process is currently running."""
        process_path = self._get_gta5_process_path()
        if process_path is None:
            return False
        return get_pid_by_path(process_path) is not None

    def _toggle_manual_gta5_suspend(self) -> None:
        """Toggle the manual GTA5 process suspend on or off.

        When not suspended: registers a `'manual:toolbar'` reason in `ProcessSuspendManager`
        with `'Manual'` duration so it never auto-clears.
        When already suspended: releases the `'manual:toolbar'` reason.
        Auto-protection reasons are unaffected and may also independently keep the process suspended.
        """
        self._sync_gta5_process_button()
        if self._manual_gta5_suspend_active:
            ProcessSuspendManager.release_reason_global('manual:toolbar')
        else:
            process_path = self._get_gta5_process_path()
            if process_path is None:
                logger.warning('Manual GTA5 suspend: no process path is configured in any protection')
                return
            if ProcessSuspendManager.is_process_suspended(process_path):
                logger.info('Manual GTA5 suspend: process is already suspended by another protection reason')
                self._sync_gta5_process_button()
                return
            ProcessSuspendManager.request_suspend(
                process_path=process_path,
                reason_key='manual:toolbar',
                left_event=Event(),
                duration='Manual',
            )
        self._sync_gta5_process_button()

    def _gta5_solo_session(self) -> None:
        """Suspend GTA5 for ~8 seconds then auto-resume, forcing a solo public session."""
        self._sync_gta5_process_button()
        process_path = self._get_gta5_process_path()
        if process_path is None:
            logger.warning('GTA5 solo session: no process path is configured in any protection')
            msgbox.show(
                title=TITLE,
                text=format_gta5_solo_session_no_process_path_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        if get_pid_by_path(process_path) is None:
            logger.warning('GTA5 solo session: process not running (%s)', process_path)
            msgbox.show(
                title=TITLE,
                text=format_gta5_solo_session_process_not_running_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        if ProcessSuspendManager.is_process_suspended(process_path):
            logger.info('GTA5 solo session: process is already suspended')
            self._sync_gta5_process_button()
            return
        already_left = Event()
        already_left.set()
        ProcessSuspendManager.request_suspend(
            process_path=process_path,
            reason_key='solo:toolbar',
            left_event=already_left,
            duration=8,
        )
        if not ProcessSuspendManager.has_reason('solo:toolbar'):
            logger.warning('GTA5 solo session: suspend failed for process %s', process_path)
            msgbox.show(
                title=TITLE,
                text=format_gta5_solo_session_suspend_failed_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        self._gta5_solo_active = True
        self._sync_gta5_process_button()

    def _refresh_gta5_process_state(self) -> None:
        """Refresh GTA5 process-control flags from live process and suspend-manager state."""
        self._manual_gta5_suspend_active = ProcessSuspendManager.has_reason('manual:toolbar')
        self._gta5_solo_active = ProcessSuspendManager.has_reason('solo:toolbar')

        can_act = self._gta5_has_any_process_path() and not CaptureState.is_neighbour_interface
        self._gta5_process_detected = can_act and self._gta5_process_is_running()

        process_path = self._get_gta5_process_path()
        self._gta5_process_suspended = (
            can_act
            and process_path is not None
            and ProcessSuspendManager.is_process_suspended(process_path)
        )

    def _sync_gta5_process_button(self) -> None:
        """Update the GTA5 Process submenu title and menu-item enabled states."""
        self._refresh_gta5_process_state()
        is_manual = self._manual_gta5_suspend_active
        is_solo = self._gta5_solo_active
        can_act = self._gta5_has_any_process_path() and not CaptureState.is_neighbour_interface
        self._gta5_process_submenu.setEnabled(can_act)
        if not can_act:
            if is_manual:
                ProcessSuspendManager.release_reason_global('manual:toolbar')
                self._manual_gta5_suspend_active = False
            if is_solo:
                ProcessSuspendManager.release_reason_global('solo:toolbar')
                self._gta5_solo_active = False
            self._gta5_process_suspended = False
            self._gta5_process_submenu.setTitle('🎮 GTA5 Process')
            self._gta5_suspend_resume_action.setText('⏸️ Suspend Process')
            self._gta5_suspend_resume_action.setEnabled(False)
            self._gta5_solo_menu_action.setEnabled(False)
            self._gta5_suspend_resume_action.setToolTip(
                'ARP spoofing mode — process control not available.'
                if CaptureState.is_neighbour_interface
                else 'No process path configured — set one in Detections Manager to enable.',
            )
        elif is_manual:
            self._gta5_process_submenu.setTitle('⏸️ GTA5 Process (Suspended)')
            self._gta5_suspend_resume_action.setText('▶️ Resume Process')
            self._gta5_suspend_resume_action.setToolTip('Remove the manual suspend hold from the GTA5 process')
            self._gta5_suspend_resume_action.setEnabled(True)
            self._gta5_solo_menu_action.setEnabled(False)
        elif is_solo:
            self._gta5_process_submenu.setTitle('🎯 GTA5 Process (Going Solo...)')
            self._gta5_suspend_resume_action.setText('⏸️ Suspend Process')
            self._gta5_suspend_resume_action.setEnabled(False)
            self._gta5_solo_menu_action.setEnabled(False)
        elif self._gta5_process_suspended:
            self._gta5_process_submenu.setTitle('⏸️ GTA5 Process (Suspended)')
            self._gta5_suspend_resume_action.setText('▶️ Resume Process')
            self._gta5_suspend_resume_action.setEnabled(False)
            self._gta5_solo_menu_action.setEnabled(False)
            self._gta5_suspend_resume_action.setToolTip(
                'Process is currently suspended by active protection rules. It will resume automatically when those rules clear.',
            )
            self._gta5_solo_menu_action.setToolTip('Process is already suspended')
        else:
            self._gta5_process_submenu.setTitle('🎮 GTA5 Process')
            self._gta5_suspend_resume_action.setText('⏸️ Suspend Process')
            if self._gta5_process_detected:
                self._gta5_suspend_resume_action.setEnabled(True)
                self._gta5_solo_menu_action.setEnabled(True)
                self._gta5_suspend_resume_action.setToolTip('Manually suspend the GTA5 process — click again to resume')
                self._gta5_solo_menu_action.setToolTip(
                    'Suspend GTA5 for ~8 seconds then auto-resume.\n'
                    'This forces the game to spawn you alone in a public session.',
                )
            else:
                self._gta5_suspend_resume_action.setEnabled(False)
                self._gta5_solo_menu_action.setEnabled(False)
                self._gta5_suspend_resume_action.setToolTip('GTA5 is not currently running')
                self._gta5_solo_menu_action.setToolTip('GTA5 is not currently running')

    def _highlight_connected_ips(self, ips: list[str]) -> None:
        """Select and scroll to player rows by IP in the connected table."""
        model = self._connected.table_model
        view = self._connected.table_view
        selection = QItemSelection()
        first_index = None
        for ip in ips:
            row = model.get_row_index_by_ip(ip)
            if row is None:
                continue
            top_left = model.index(row, 0)
            bottom_right = model.index(row, model.columnCount() - 1)
            selection.select(top_left, bottom_right)
            if first_index is None:
                first_index = top_left
        if first_index is None:
            return
        if not self._connected.is_expanded:
            self._connected.expand()
        view.selectionModel().select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        view.scrollTo(first_index)

    def _open_player_leaderboard(self) -> None:
        """Open the Most Seen Players leaderboard, or focus the existing one."""
        if self._leaderboard_window is not None and self._leaderboard_window.isVisible():
            self._leaderboard_window.raise_()
            self._leaderboard_window.activateWindow()
            return
        self._leaderboard_window = PlayerLeaderboardWindow(self)
        self._leaderboard_window.destroyed.connect(self._on_leaderboard_window_destroyed)
        self._leaderboard_window.show()

    def _on_leaderboard_window_destroyed(self) -> None:
        self._leaderboard_window = None

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

    def reset_session_graph(self) -> None:
        """Reset graph history for all open statistics windows (called on capture restart)."""
        if self._session_rate_graph_window is not None:
            self._session_rate_graph_window.reset()
        if self._session_pps_graph_window is not None:
            self._session_pps_graph_window.reset()
        if self._session_bps_graph_window is not None:
            self._session_bps_graph_window.reset()
        if self._packets_latency_graph_window is not None:
            self._packets_latency_graph_window.reset()
        if self._capture_statistics_window is not None:
            self._capture_statistics_window.reset()

    def _open_session_rate_graph(self) -> None:
        """Open or focus the session-wide rate graph window."""
        if self._session_rate_graph_window is not None:
            self._session_rate_graph_window.show()
            self._session_rate_graph_window.raise_()
            self._session_rate_graph_window.activateWindow()
            return

        window = SessionRateGraphWindow(
            max_history=Settings.gui_rate_graph_max_history,
            always_on_top=Settings.gui_rate_graph_always_on_top,
        )
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_session_rate_graph_window', None))
        self._session_rate_graph_window = window

    def _tick_stats(self) -> None:
        """Tick all open statistics windows with the latest data."""
        CaptureStats.capture_health_samples.append((
            CaptureStats.global_avg_latency_ms,
            CaptureStats.global_pps_rate,
            CaptureStats.global_bps_rate,
        ))
        if self._session_rate_graph_window is not None:
            self._session_rate_graph_window.update_rates(
                pps=CaptureStats.global_pps_rate,
                bps=CaptureStats.global_bps_rate,
            )
        if self._session_pps_graph_window is not None:
            self._session_pps_graph_window.update_pps(CaptureStats.global_pps_rate)
        if self._session_bps_graph_window is not None:
            self._session_bps_graph_window.update_bps(CaptureStats.global_bps_rate)
        if self._packets_latency_graph_window is not None:
            self._packets_latency_graph_window.update_latency(CaptureStats.global_avg_latency_ms)
        if self._country_breakdown_window is not None:
            self._country_breakdown_window.refresh()
        if self._reconnect_frequency_window is not None:
            self._reconnect_frequency_window.refresh()
        if self._session_timeline_window is not None:
            self._session_timeline_window.refresh()
        if self._port_heatmap_window is not None:
            self._port_heatmap_window.refresh()
        if self._session_duration_window is not None:
            self._session_duration_window.refresh()
        if self._capture_statistics_window is not None:
            self._capture_statistics_window.refresh()

        # Sync GTA5 process control state every tick
        if Settings.capture_program_preset == 'GTA5':
            self._sync_gta5_process_button()

    def _open_session_pps_graph(self) -> None:
        """Open or focus the session-wide PPS graph window."""
        if self._session_pps_graph_window is not None:
            self._session_pps_graph_window.show()
            self._session_pps_graph_window.raise_()
            self._session_pps_graph_window.activateWindow()
            return

        window = SessionPpsGraphWindow(
            max_history=Settings.gui_rate_graph_max_history,
            always_on_top=Settings.gui_rate_graph_always_on_top,
        )
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_session_pps_graph_window', None))
        self._session_pps_graph_window = window

    def _open_session_bps_graph(self) -> None:
        """Open or focus the session-wide BPS graph window."""
        if self._session_bps_graph_window is not None:
            self._session_bps_graph_window.show()
            self._session_bps_graph_window.raise_()
            self._session_bps_graph_window.activateWindow()
            return

        window = SessionBpsGraphWindow(
            max_history=Settings.gui_rate_graph_max_history,
            always_on_top=Settings.gui_rate_graph_always_on_top,
        )
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_session_bps_graph_window', None))
        self._session_bps_graph_window = window

    def _open_packets_latency_graph(self) -> None:
        """Open or focus the packets latency graph window."""
        if self._packets_latency_graph_window is not None:
            self._packets_latency_graph_window.show()
            self._packets_latency_graph_window.raise_()
            self._packets_latency_graph_window.activateWindow()
            return

        window = PacketsLatencyGraphWindow(
            max_history=Settings.gui_rate_graph_max_history,
            always_on_top=Settings.gui_rate_graph_always_on_top,
        )
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_packets_latency_graph_window', None))
        self._packets_latency_graph_window = window

    def _open_country_breakdown(self) -> None:
        """Open or focus the country breakdown window."""
        if self._country_breakdown_window is not None:
            self._country_breakdown_window.show()
            self._country_breakdown_window.raise_()
            self._country_breakdown_window.activateWindow()
            return

        window = CountryBreakdownWindow(always_on_top=Settings.gui_rate_graph_always_on_top)
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_country_breakdown_window', None))
        self._country_breakdown_window = window

    def _open_reconnect_frequency(self) -> None:
        """Open or focus the reconnect frequency window."""
        if self._reconnect_frequency_window is not None:
            self._reconnect_frequency_window.show()
            self._reconnect_frequency_window.raise_()
            self._reconnect_frequency_window.activateWindow()
            return

        window = ReconnectFrequencyWindow(always_on_top=Settings.gui_rate_graph_always_on_top)
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_reconnect_frequency_window', None))
        self._reconnect_frequency_window = window

    def _open_session_timeline(self) -> None:
        """Open or focus the session timeline window."""
        if self._session_timeline_window is not None:
            self._session_timeline_window.show()
            self._session_timeline_window.raise_()
            self._session_timeline_window.activateWindow()
            return

        window = SessionTimelineWindow(always_on_top=Settings.gui_rate_graph_always_on_top)
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_session_timeline_window', None))
        self._session_timeline_window = window

    def _open_port_heatmap(self) -> None:
        """Open or focus the port heatmap window."""
        if self._port_heatmap_window is not None:
            self._port_heatmap_window.show()
            self._port_heatmap_window.raise_()
            self._port_heatmap_window.activateWindow()
            return

        window = PortHeatmapWindow(always_on_top=Settings.gui_rate_graph_always_on_top)
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_port_heatmap_window', None))
        self._port_heatmap_window = window

    def _open_session_duration(self) -> None:
        """Open or focus the session duration window."""
        if self._session_duration_window is not None:
            self._session_duration_window.show()
            self._session_duration_window.raise_()
            self._session_duration_window.activateWindow()
            return

        window = SessionDurationWindow(always_on_top=Settings.gui_rate_graph_always_on_top)
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_session_duration_window', None))
        self._session_duration_window = window

    def _open_capture_health(self) -> None:
        """Open or focus the capture statistics window."""
        if self._capture_statistics_window is not None:
            self._capture_statistics_window.show()
            self._capture_statistics_window.raise_()
            self._capture_statistics_window.activateWindow()
            return

        window = CaptureStatisticsWindow(
            max_history=Settings.gui_rate_graph_max_history,
            always_on_top=Settings.gui_rate_graph_always_on_top,
        )
        window.open_session_pps_graph_requested.connect(self._open_session_pps_graph)
        window.open_session_bps_graph_requested.connect(self._open_session_bps_graph)
        window.open_packets_latency_graph_requested.connect(self._open_packets_latency_graph)
        window.show()
        window.destroyed.connect(lambda: setattr(self, '_capture_statistics_window', None))
        self._capture_statistics_window = window

    def set_capture_toggle_enabled(self, *, enabled: bool) -> None:
        """Enable or disable the Stop/Start Capture toolbar button."""
        self._actions.toggle_capture.setEnabled(enabled)

    def _refresh_runtime_capability_windows(self) -> None:
        """Refresh open dialogs that gate controls by preset/interface support."""
        if self._userip_manager_window is not None and self._userip_manager_window.isVisible():
            self._userip_manager_window.refresh_runtime_capabilities()

        if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
            self._detections_manager_window.refresh_protection_availability()

    def _update_gta5_toolbar_visibility(self) -> None:
        """Show or hide the GTA5 menu based on current preset."""
        gta5_preset = Settings.capture_program_preset == 'GTA5'
        SessionHost.clear_session_host_data()
        gta5_menu_action = self._gta5_menu.menuAction()
        if gta5_menu_action is not None:
            gta5_menu_action.setVisible(gta5_preset)

        self._refresh_runtime_capability_windows()

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
            MobileWarnings.remove_notified_ips_batch(disconnected_ips)
            VPNWarnings.remove_notified_ips_batch(disconnected_ips)
            HostingWarnings.remove_notified_ips_batch(disconnected_ips)

    def remove_player_from_connected(self, ip: str) -> None:
        """Remove a single player from connected table and registry by IP address."""
        removed_player: Player | None = PlayersRegistry.remove_connected_player(ip)
        if removed_player is None:
            return

        SessionHost.players_pending_for_disconnection = [
            p for p in SessionHost.players_pending_for_disconnection if p.ip != ip
        ]

        self._connected.table_model.remove_player_by_ip(ip)

        MobileWarnings.remove_notified_ip(ip)
        VPNWarnings.remove_notified_ip(ip)
        HostingWarnings.remove_notified_ip(ip)

    def remove_player_from_disconnected(self, ip: str) -> None:
        """Remove a single player from disconnected table and registry by IP address."""
        removed_player: Player | None = PlayersRegistry.remove_disconnected_player(ip)
        if removed_player is None:
            return

        self._disconnected.table_model.remove_player_by_ip(ip)

        MobileWarnings.remove_notified_ip(ip)
        VPNWarnings.remove_notified_ip(ip)
        HostingWarnings.remove_notified_ip(ip)
