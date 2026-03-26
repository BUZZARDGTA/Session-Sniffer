"""Main window implementation for Session Sniffer."""

import webbrowser
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, QObject, QSize, Qt
from PyQt6.QtGui import QAction, QCloseEvent, QFont, QMouseEvent
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import gui_closed__event
from session_sniffer.constants.local import VERSION
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import terminate_script
from session_sniffer.guis.html_templates import CAPTURE_STOPPED_HTML, GUI_HEADER_HTML_TEMPLATE
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
    STATUS_BAR_CAPTURE_LABEL_STYLESHEET,
    STATUS_BAR_CONFIG_LABEL_STYLESHEET,
    STATUS_BAR_ISSUES_LABEL_STYLESHEET,
    STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET,
    STATUS_BAR_STYLESHEET,
)
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables import SessionTableView
from session_sniffer.guis.utils import resize_window_for_screen
from session_sniffer.guis.worker_thread import GUIWorkerThread
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.player.warnings import GUIDetectionSettings, HostingWarnings, MobileWarnings, VPNWarnings
from session_sniffer.rendering_core.types import GUIRenderingState, GUIUpdatePayload
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.capture.tshark_capture import PacketCapture
    from session_sniffer.models.player import Player

GITHUB_REPO_URL = 'https://github.com/BUZZARDGTA/Session-Sniffer'
DISCORD_INVITE_URL = 'https://discord.gg/hMZ7MsPX7G'
DOCUMENTATION_URL = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki'


class PersistentMenu(QMenu):
    """Custom QMenu that doesn't close when checkable actions are triggered."""

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:
        """Override mouse release event to prevent auto-closing on checkable actions."""
        if event is None:
            super().mouseReleaseEvent(event)
            return

        action = self.actionAt(event.pos())
        if action and action.isCheckable():
            # Trigger the action but don't close the menu
            action.trigger()
            event.accept()
            return
        # For non-checkable actions, use default behavior (close menu)
        super().mouseReleaseEvent(event)


def generate_gui_header_html(*, capture: PacketCapture) -> str:
    """Generate the GUI header HTML based on capture state.

    Args:
        capture: The PacketCapture instance to read state from.

    Returns:
        HTML string for the header.
    """
    stop_status = '' if capture.is_running() else CAPTURE_STOPPED_HTML

    return GUI_HEADER_HTML_TEMPLATE.format(
        title=TITLE,
        version=VERSION,
        stop_status=stop_status,
    )


class MainWindow(QMainWindow):
    """Main Qt window that hosts session tables and control UI."""

    _min_accepted_snapshot_version: int

    def __init__(self, screen_width: int, screen_height: int, capture: PacketCapture) -> None:
        """Initialize the main application window.

        Args:
            screen_width: Primary screen width in pixels.
            screen_height: Primary screen height in pixels.
            capture: Packet capture instance used by the GUI.
        """
        super().__init__()

        self.capture = capture

        # Set up the window
        self.setWindowTitle(TITLE)
        self.setMinimumSize(800, 600)
        resize_window_for_screen(self, screen_width, screen_height)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout for the central widget
        self.main_layout = QVBoxLayout(central_widget)

        # Create the toolbar
        toolbar = QToolBar('Main Toolbar', self)
        toolbar.setAllowedAreas(Qt.ToolBarArea.TopToolBarArea)
        toolbar.setFloatable(False)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

        # ----- Stop/Start Capture Button -----
        self.toggle_capture_action = QAction('⏹️ Stop Capture', self)
        self.toggle_capture_action.setToolTip('Stop packet capture')
        self.toggle_capture_action.triggered.connect(self.toggle_capture)
        toolbar.addAction(self.toggle_capture_action)

        toolbar.addSeparator()

        # ----- Detection Menu -----
        detection_menu_button = QPushButton(' 🔔 Detection ', self)
        detection_menu_button.setToolTip('Configure notification settings for various player detection scenarios')

        detection_menu = PersistentMenu(self)
        detection_menu.setToolTipsVisible(True)

        # Mobile Detection action
        self.mobile_detection_action = QAction('Mobile (cellular) connection', self)
        self.mobile_detection_action.setToolTip('Get notified when a player joins using a mobile/cellular internet connection')
        self.mobile_detection_action.setCheckable(True)
        self.mobile_detection_action.setChecked(GUIDetectionSettings.mobile_detection_enabled)
        self.mobile_detection_action.triggered.connect(self.toggle_mobile_detection)
        detection_menu.addAction(self.mobile_detection_action)

        # VPN Detection action
        self.vpn_detection_action = QAction('Proxy, VPN or Tor exit address', self)
        self.vpn_detection_action.setToolTip('Get notified when a player joins using a VPN, proxy, or Tor exit node')
        self.vpn_detection_action.setCheckable(True)
        self.vpn_detection_action.setChecked(GUIDetectionSettings.vpn_detection_enabled)
        self.vpn_detection_action.triggered.connect(self.toggle_vpn_detection)
        detection_menu.addAction(self.vpn_detection_action)

        # Hosting Detection action
        self.hosting_detection_action = QAction('Hosting, colocated or data center', self)
        self.hosting_detection_action.setToolTip('Get notified when a player joins from a hosting provider or data center')
        self.hosting_detection_action.setCheckable(True)
        self.hosting_detection_action.setChecked(GUIDetectionSettings.hosting_detection_enabled)
        self.hosting_detection_action.triggered.connect(self.toggle_hosting_detection)
        detection_menu.addAction(self.hosting_detection_action)

        detection_menu.addSeparator()

        # Player Join Notification action
        self.player_join_notification_action = QAction('Player join notifications', self)
        self.player_join_notification_action.setToolTip('Get notified whenever any player joins your session')
        self.player_join_notification_action.setCheckable(True)
        self.player_join_notification_action.setChecked(GUIDetectionSettings.player_join_notifications_enabled)
        self.player_join_notification_action.triggered.connect(self.toggle_player_join_notifications)
        detection_menu.addAction(self.player_join_notification_action)

        # Player Rejoin Notification action
        self.player_rejoin_notification_action = QAction('Player rejoin notifications', self)
        self.player_rejoin_notification_action.setToolTip('Get notified whenever any player rejoins your session after disconnecting')
        self.player_rejoin_notification_action.setCheckable(True)
        self.player_rejoin_notification_action.setChecked(GUIDetectionSettings.player_rejoin_notifications_enabled)
        self.player_rejoin_notification_action.triggered.connect(self.toggle_player_rejoin_notifications)
        detection_menu.addAction(self.player_rejoin_notification_action)

        # Player Leave Notification action
        self.player_leave_notification_action = QAction('Player leave notifications', self)
        self.player_leave_notification_action.setToolTip('Get notified whenever any player leaves your session')
        self.player_leave_notification_action.setCheckable(True)
        self.player_leave_notification_action.setChecked(GUIDetectionSettings.player_leave_notifications_enabled)
        self.player_leave_notification_action.triggered.connect(self.toggle_player_leave_notifications)
        detection_menu.addAction(self.player_leave_notification_action)

        detection_menu_button.setMenu(detection_menu)
        toolbar.addWidget(detection_menu_button)

        toolbar.addSeparator()

        # ----- Help Menu -----
        help_menu_button = QPushButton(' ❓ Help ', self)
        help_menu_button.setToolTip('Access help resources, documentation, and community')

        help_menu = PersistentMenu(self)
        help_menu.setToolTipsVisible(True)

        # Project Repository action
        repo_action = QAction('📦 Project Repository', self)
        repo_action.setToolTip('Open the Session Sniffer GitHub repository in your default web browser')
        repo_action.triggered.connect(self.open_project_repo)
        help_menu.addAction(repo_action)

        # Documentation action
        docs_action = QAction('📚 Documentation', self)
        docs_action.setToolTip('View the complete documentation and user guide for Session Sniffer')
        docs_action.triggered.connect(self.open_documentation)
        help_menu.addAction(docs_action)

        # Discord action
        discord_action = QAction('💬 Discord Server', self)
        discord_action.setToolTip('Join the official Session Sniffer Discord community for support and updates')
        discord_action.triggered.connect(self.join_discord)
        help_menu.addAction(discord_action)

        help_menu_button.setMenu(help_menu)
        toolbar.addWidget(help_menu_button)

        # Header text
        self.header_text = QLabel()
        self.header_text.setTextFormat(Qt.TextFormat.RichText)
        self.header_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_text.setWordWrap(True)
        self.header_text.setFont(QFont('Courier', 10, QFont.Weight.Bold))

        # Create container for connected header and controls
        self.connected_header_container = QWidget()
        self.connected_header_container.setStyleSheet(CONNECTED_HEADER_CONTAINER_STYLESHEET)
        self.connected_header_layout = QHBoxLayout(self.connected_header_container)
        self.connected_header_layout.setContentsMargins(0, 0, 0, 0)

        # Custom header for the Session Connected table with matching background as first column
        self.session_connected_header = QLabel('Players connected in your session (0):')
        self.session_connected_header.setTextFormat(Qt.TextFormat.RichText)
        self.session_connected_header.setStyleSheet(CONNECTED_HEADER_TEXT_STYLESHEET)
        self.session_connected_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_connected_header.setFont(QFont('Courier', 9, QFont.Weight.Bold))

        # Add connected header to container with stretch to fill available space
        self.connected_header_layout.addWidget(self.session_connected_header, 1)

        # Add clear button for connected table
        self.connected_clear_button = QPushButton('CLEAR')
        self.connected_clear_button.setToolTip('Clear all connected players')
        self.connected_clear_button.setStyleSheet(CONNECTED_CLEAR_BUTTON_STYLESHEET)
        self.connected_clear_button.clicked.connect(self.clear_connected_players)
        self.connected_header_layout.addWidget(self.connected_clear_button)

        # Add sleek collapse icon button for connected table
        self.connected_collapse_button = QPushButton('▼')
        self.connected_collapse_button.setToolTip('Hide the connected players table')
        self.connected_collapse_button.setStyleSheet(COMMON_COLLAPSE_BUTTON_STYLESHEET)
        self.connected_collapse_button.clicked.connect(self.minimize_connected_section)
        self.connected_header_layout.addWidget(self.connected_collapse_button)

        # Create the table model and view
        connected_hidden_columns = set(Settings.GUI_COLUMNS_CONNECTED_HIDDEN)
        connected_column_names = [
            column_name
            for column_name in Settings.GUI_ALL_CONNECTED_COLUMNS
            if column_name not in connected_hidden_columns
        ]

        self.connected_table_model = SessionTableModel(connected_column_names)
        self.connected_table_view = SessionTableView(
            self.connected_table_model,
            connected_column_names.index('Last Rejoin'),
            Qt.SortOrder.DescendingOrder,
            is_connected_table=True,
        )
        self.connected_table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.connected_table_view.setup_static_column_resizing()
        self.connected_table_model.view = self.connected_table_view

        # Add a horizontal line separator
        self.tables_separator = QFrame(self)
        self.tables_separator.setFrameShape(QFrame.Shape.HLine)
        self.tables_separator.setFrameShadow(QFrame.Shadow.Sunken)

        # Create container for disconnected header and controls
        self.disconnected_header_container = QWidget()
        self.disconnected_header_container.setStyleSheet(DISCONNECTED_HEADER_CONTAINER_STYLESHEET)
        self.disconnected_header_layout = QHBoxLayout(self.disconnected_header_container)
        self.disconnected_header_layout.setContentsMargins(0, 0, 0, 0)

        # Custom header for the Session Disconnected table with matching background as first column
        self.session_disconnected_header = QLabel("Players who've left your session (0):")
        self.session_disconnected_header.setTextFormat(Qt.TextFormat.RichText)
        self.session_disconnected_header.setStyleSheet(DISCONNECTED_HEADER_TEXT_STYLESHEET)
        self.session_disconnected_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.session_disconnected_header.setFont(QFont('Courier', 9, QFont.Weight.Bold))

        # Add disconnected header to container with stretch to fill available space
        self.disconnected_header_layout.addWidget(self.session_disconnected_header, 1)

        # Add clear button for disconnected table
        self.disconnected_clear_button = QPushButton('CLEAR')
        self.disconnected_clear_button.setToolTip('Clear all disconnected players')
        self.disconnected_clear_button.setStyleSheet(DISCONNECTED_CLEAR_BUTTON_STYLESHEET)
        self.disconnected_clear_button.clicked.connect(self.clear_disconnected_players)
        self.disconnected_header_layout.addWidget(self.disconnected_clear_button)

        # Add sleek collapse icon button for disconnected table
        self.disconnected_collapse_button = QPushButton('▼')
        self.disconnected_collapse_button.setToolTip('Hide the disconnected players table')
        self.disconnected_collapse_button.setStyleSheet(COMMON_COLLAPSE_BUTTON_STYLESHEET)
        self.disconnected_collapse_button.clicked.connect(self.minimize_disconnected_section)
        self.disconnected_header_layout.addWidget(self.disconnected_collapse_button)

        # Create expand button for when connected section is hidden
        self.connected_expand_button = QPushButton('▲  Show Connected Players (0)')
        self.connected_expand_button.setToolTip('Show the connected players table')
        self.connected_expand_button.setStyleSheet(CONNECTED_EXPAND_BUTTON_STYLESHEET)
        self.connected_expand_button.clicked.connect(self.expand_connected_section)
        self.connected_expand_button.setVisible(False)

        # Create expand button for when disconnected section is hidden
        self.disconnected_expand_button = QPushButton('▲  Show Disconnected Players (0)')
        self.disconnected_expand_button.setToolTip('Show the disconnected players table')
        self.disconnected_expand_button.setStyleSheet(DISCONNECTED_EXPAND_BUTTON_STYLESHEET)
        self.disconnected_expand_button.clicked.connect(self.expand_disconnected_section)
        self.disconnected_expand_button.setVisible(False)

        # Create the table model and view
        disconnected_hidden_columns = set(Settings.GUI_COLUMNS_DISCONNECTED_HIDDEN)
        disconnected_column_names = [
            column_name
            for column_name in Settings.GUI_ALL_DISCONNECTED_COLUMNS
            if column_name not in disconnected_hidden_columns
        ]

        self.disconnected_table_model = SessionTableModel(disconnected_column_names)
        self.disconnected_table_view = SessionTableView(
            self.disconnected_table_model,
            disconnected_column_names.index('Last Seen'),
            Qt.SortOrder.AscendingOrder,
            is_connected_table=False,
        )
        self.disconnected_table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.disconnected_table_view.setup_static_column_resizing()
        self.disconnected_table_model.view = self.disconnected_table_view

        # Layout to organize the widgets
        self.main_layout.addSpacing(4)
        self.main_layout.addWidget(self.header_text)
        self.main_layout.addSpacing(14)
        self.main_layout.addWidget(self.connected_header_container)
        self.main_layout.addWidget(self.connected_table_view)
        self.main_layout.addWidget(self.tables_separator)
        self.main_layout.addWidget(self.disconnected_header_container)
        self.main_layout.addWidget(self.disconnected_table_view)
        self.main_layout.addWidget(self.connected_expand_button)
        self.main_layout.addWidget(self.disconnected_expand_button)

        # Initialize tracking variables for text updates optimization
        self._last_connected_count = -1
        self._last_disconnected_count = -1

        # Initialize tracking variables for selection counts
        self._connected_selected_count = 0
        self._disconnected_selected_count = 0

        # Ignore any queued GUI updates published before this version.
        # This prevents a stale update from repopulating the tables right after CLEAR.
        self._min_accepted_snapshot_version = 0

        # Connect to selection change signals to track selected cells
        self.connected_table_view.selectionModel().selectionChanged.connect(
            lambda: self._update_selection_count(self.connected_table_view, 'connected'),
        )
        self.disconnected_table_view.selectionModel().selectionChanged.connect(
            lambda: self._update_selection_count(self.disconnected_table_view, 'disconnected'),
        )

        # Create and configure the status bar
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.setSizeGripEnabled(False)
        self.status_bar.setStyleSheet(STATUS_BAR_STYLESHEET)

        # Create individual status labels for better organization
        self.status_capture_label = QLabel()
        self.status_capture_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_capture_label.setStyleSheet(STATUS_BAR_CAPTURE_LABEL_STYLESHEET)

        self.status_config_label = QLabel()
        self.status_config_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_config_label.setStyleSheet(STATUS_BAR_CONFIG_LABEL_STYLESHEET)

        self.status_issues_label = QLabel()
        self.status_issues_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_issues_label.setStyleSheet(STATUS_BAR_ISSUES_LABEL_STYLESHEET)

        self.status_performance_label = QLabel()
        self.status_performance_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_performance_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.status_performance_label.setStyleSheet(STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET)

        # Add labels to status bar with proper spacing
        self.status_bar.addWidget(self.status_capture_label)
        self.status_bar.addWidget(self.status_config_label)
        self.status_bar.addWidget(self.status_issues_label)
        self.status_bar.addPermanentWidget(self.status_performance_label)

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Create the worker thread for table updates
        self.worker_thread = GUIWorkerThread(
            self.connected_table_view,
            self.disconnected_table_view,
        )
        self.worker_thread.update_signal.connect(self.update_gui)
        self.worker_thread.start()

        # Track window movement/dragging for opacity effect
        self._window_being_moved = False

        # Install event filter to detect window movement/dragging
        self.installEventFilter(self)

    def eventFilter(self, obj: QObject | None, event: QEvent | None) -> bool:
        """Filter events to detect window movement."""
        if obj == self and event is not None:
            event_type = event.type()

            # Detect start of window movement/dragging
            if (
                event_type in (QEvent.Type.Move, QEvent.Type.Resize, QEvent.Type.WindowStateChange)
                and not self._window_being_moved
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
                and self._window_being_moved
            ):
                self._end_window_move()

        return super().eventFilter(obj, event)

    def _start_window_move(self) -> None:
        """Apply transparency when window movement/dragging starts."""
        self._window_being_moved = True
        self.setWindowOpacity(0.85)
        # Disable UI elements
        self.header_text.setEnabled(False)
        self.connected_header_container.setEnabled(False)
        self.connected_table_view.setEnabled(False)
        self.disconnected_header_container.setEnabled(False)
        self.disconnected_table_view.setEnabled(False)
        self.tables_separator.setEnabled(False)
        self.status_bar.setEnabled(False)
        self.connected_expand_button.setEnabled(False)
        self.disconnected_expand_button.setEnabled(False)

    def _end_window_move(self) -> None:
        """Restore opacity and re-enable UI elements after window movement/dragging ends."""
        self._window_being_moved = False
        self.setWindowOpacity(1.0)
        # Re-enable UI elements
        self.header_text.setEnabled(True)
        self.connected_header_container.setEnabled(True)
        self.connected_table_view.setEnabled(True)
        self.disconnected_header_container.setEnabled(True)
        self.disconnected_table_view.setEnabled(True)
        self.tables_separator.setEnabled(True)
        self.status_bar.setEnabled(True)
        self.connected_expand_button.setEnabled(True)
        self.disconnected_expand_button.setEnabled(True)

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Handle the main window close event and terminate background work."""
        gui_closed__event.set()
        self.worker_thread.quit()
        self.worker_thread.wait()

        if event is not None:
            event.accept()

        terminate_script('EXIT')

    def _update_connected_header_with_selection(self) -> None:
        """Update the connected table header to include selection information."""
        base_text = f'Players connected in your session ({self._last_connected_count}):'
        if self._connected_selected_count > 0:
            player_text = 'player' if self._connected_selected_count == 1 else 'players'
            combined_text = f'{base_text} ({self._connected_selected_count} {player_text} selected)'
        else:
            combined_text = base_text

        self.session_connected_header.setText(combined_text)

    def _update_disconnected_header_with_selection(self) -> None:
        """Update the disconnected table header to include selection information."""
        base_text = f"Players who've left your session ({self._last_disconnected_count}):"
        if self._disconnected_selected_count > 0:
            player_text = 'player' if self._disconnected_selected_count == 1 else 'players'
            combined_text = f'{base_text} ({self._disconnected_selected_count} {player_text} selected)'
        else:
            combined_text = base_text

        self.session_disconnected_header.setText(combined_text)

    def _update_selection_count(self, table_view: SessionTableView, table_type: str) -> None:
        """Update the selection count for the specified table and refresh table headers."""
        selection_model = table_view.selectionModel()
        selected_indexes = selection_model.selectedIndexes()

        unique_rows = {index.row() for index in selected_indexes}
        selected_count = len(unique_rows)

        if table_type == 'connected':
            self._connected_selected_count = selected_count
            self._update_connected_header_with_selection()
        elif table_type == 'disconnected':
            self._disconnected_selected_count = selected_count
            self._update_disconnected_header_with_selection()

    def _update_separator_visibility(self) -> None:
        """Update the separator visibility based on whether both tables are visible."""
        both_tables_visible = self.connected_table_view.isVisible() and self.disconnected_table_view.isVisible()
        self.tables_separator.setVisible(both_tables_visible)

    def expand_connected_section(self) -> None:
        """Handle the expand button click to show the connected section."""
        self.connected_expand_button.setVisible(False)
        self.connected_header_container.setVisible(True)
        self.connected_table_view.setVisible(True)
        self._update_separator_visibility()
        self.connected_clear_button.setVisible(True)
        self.connected_collapse_button.setVisible(True)
        self.connected_table_model.refresh_view()

    def expand_disconnected_section(self) -> None:
        """Handle the expand button click to show the disconnected section."""
        self.disconnected_expand_button.setVisible(False)
        self.disconnected_header_container.setVisible(True)
        self.disconnected_table_view.setVisible(True)
        self._update_separator_visibility()
        self.disconnected_clear_button.setVisible(True)
        self.disconnected_collapse_button.setVisible(True)
        self.disconnected_table_model.refresh_view()

    def minimize_connected_section(self) -> None:
        """Minimize the connected table completely."""
        self.connected_clear_button.setVisible(False)
        self.connected_collapse_button.setVisible(False)
        self.connected_header_container.setVisible(False)
        self.connected_table_view.setVisible(False)
        self.tables_separator.setVisible(False)
        self.connected_expand_button.setText(f'▲  Show Connected Players ({self.connected_table_model.rowCount()})')
        self.connected_expand_button.setVisible(True)

    def minimize_disconnected_section(self) -> None:
        """Minimize the disconnected table completely."""
        self.disconnected_clear_button.setVisible(False)
        self.disconnected_collapse_button.setVisible(False)
        self.disconnected_header_container.setVisible(False)
        self.disconnected_table_view.setVisible(False)
        self.tables_separator.setVisible(False)
        self.disconnected_expand_button.setText(f'▲  Show Disconnected Players ({self.disconnected_table_model.rowCount()})')
        self.disconnected_expand_button.setVisible(True)

    def update_gui(self, payload: GUIUpdatePayload) -> None:
        """Update header text, status bar, and table data for connected and disconnected players."""
        if payload.snapshot_version < self._min_accepted_snapshot_version:
            return

        self.header_text.setText(payload.header_text)
        self.status_capture_label.setText(payload.status_capture_text)
        self.status_config_label.setText(payload.status_config_text)
        self.status_issues_label.setText(payload.status_issues_text)
        self.status_performance_label.setText(payload.status_performance_text)

        connected_count_changed = self._last_connected_count != payload.connected_num
        disconnected_count_changed = self._last_disconnected_count != payload.disconnected_num

        if connected_count_changed:
            self._last_connected_count = payload.connected_num
            self._update_connected_header_with_selection()

        for processed_data, compiled_colors in payload.connected_rows_with_colors:
            ip = self.connected_table_model.get_ip_from_data_safely(list(processed_data))

            disconnected_row_index = self.disconnected_table_model.get_row_index_by_ip(ip)
            if disconnected_row_index is not None:
                self.disconnected_table_model.delete_row(disconnected_row_index)

            connected_row_index = self.connected_table_model.get_row_index_by_ip(ip)
            if connected_row_index is None:
                self.connected_table_model.add_row_without_refresh(list(processed_data), list(compiled_colors))
            else:
                self.connected_table_model.update_row_without_refresh(connected_row_index, list(processed_data), list(compiled_colors))

        if self.connected_table_view.isVisible():
            self.connected_table_model.sort_current_column()
            self.connected_table_view.adjust_username_column_width()
        elif connected_count_changed:
            self.connected_expand_button.setText(f'▲  Show Connected Players ({payload.connected_num})')

        if disconnected_count_changed:
            self._last_disconnected_count = payload.disconnected_num
            self._update_disconnected_header_with_selection()

        for processed_data, compiled_colors in payload.disconnected_rows_with_colors:
            ip = self.disconnected_table_model.get_ip_from_data_safely(list(processed_data))

            connected_row_index = self.connected_table_model.get_row_index_by_ip(ip)
            if connected_row_index is not None:
                self.connected_table_model.delete_row(connected_row_index)

            disconnected_row_index = self.disconnected_table_model.get_row_index_by_ip(ip)
            if disconnected_row_index is None:
                self.disconnected_table_model.add_row_without_refresh(list(processed_data), list(compiled_colors))
            else:
                self.disconnected_table_model.update_row_without_refresh(disconnected_row_index, list(processed_data), list(compiled_colors))

        if self.disconnected_table_view.isVisible():
            self.disconnected_table_model.sort_current_column()
            self.disconnected_table_view.adjust_username_column_width()
        elif disconnected_count_changed:
            self.disconnected_expand_button.setText(f'▲  Show Disconnected Players ({payload.disconnected_num})')

    def open_project_repo(self) -> None:
        """Open the GitHub repository in the default browser."""
        webbrowser.open(GITHUB_REPO_URL)

    def open_documentation(self) -> None:
        """Open the documentation URL in the default browser."""
        webbrowser.open(DOCUMENTATION_URL)

    def join_discord(self) -> None:
        """Open the Discord invite URL in the default browser."""
        webbrowser.open(DISCORD_INVITE_URL)

    def toggle_mobile_detection(self) -> None:
        """Toggle Mobile detection on/off and save the setting."""
        GUIDetectionSettings.mobile_detection_enabled = self.mobile_detection_action.isChecked()

        if not GUIDetectionSettings.mobile_detection_enabled:
            MobileWarnings.clear_all_notified_ips()

    def toggle_vpn_detection(self) -> None:
        """Toggle VPN detection on/off and save the setting."""
        GUIDetectionSettings.vpn_detection_enabled = self.vpn_detection_action.isChecked()

        if not GUIDetectionSettings.vpn_detection_enabled:
            VPNWarnings.clear_all_notified_ips()

    def toggle_hosting_detection(self) -> None:
        """Toggle Hosting detection on/off and save the setting."""
        GUIDetectionSettings.hosting_detection_enabled = self.hosting_detection_action.isChecked()

        if not GUIDetectionSettings.hosting_detection_enabled:
            HostingWarnings.clear_all_notified_ips()

    def toggle_player_join_notifications(self) -> None:
        """Toggle player join notifications on/off."""
        GUIDetectionSettings.player_join_notifications_enabled = self.player_join_notification_action.isChecked()

    def toggle_player_rejoin_notifications(self) -> None:
        """Toggle player rejoin notifications on/off."""
        GUIDetectionSettings.player_rejoin_notifications_enabled = self.player_rejoin_notification_action.isChecked()

    def toggle_player_leave_notifications(self) -> None:
        """Toggle player leave notifications on/off."""
        GUIDetectionSettings.player_leave_notifications_enabled = self.player_leave_notification_action.isChecked()

    def _update_header_capture_status(self) -> None:
        """Immediately update the header text to reflect current capture state."""
        header_html = generate_gui_header_html(capture=self.capture)
        self.header_text.setText(header_html)

    def toggle_capture(self) -> None:
        """Toggle the packet capture on/off."""
        if self.capture.is_running():
            self.capture.stop()
            self.toggle_capture_action.setText('▶️ Start Capture')
            self.toggle_capture_action.setToolTip('Start packet capture')
        else:
            self.capture.start()
            self.toggle_capture_action.setText('⏹️ Stop Capture')
            self.toggle_capture_action.setToolTip('Stop packet capture')

        self._update_header_capture_status()

    def clear_connected_players(self) -> None:
        """Clear all connected players from the table and registry."""
        self._min_accepted_snapshot_version = GUIRenderingState.get_version() + 1
        connected_players = PlayersRegistry.get_default_sorted_players(include_connected=True, include_disconnected=False)
        connected_ips = {player.ip for player in connected_players}

        PlayersRegistry.clear_connected_players()
        SessionHost.clear_session_host_data()
        self.connected_table_model.clear_all_data()

        self._connected_selected_count = 0
        self._update_connected_header_with_selection()

        if connected_ips:
            MobileWarnings.remove_notified_ips_batch(connected_ips)
            VPNWarnings.remove_notified_ips_batch(connected_ips)
            HostingWarnings.remove_notified_ips_batch(connected_ips)

    def clear_disconnected_players(self) -> None:
        """Clear all disconnected players from the table and registry."""
        self._min_accepted_snapshot_version = GUIRenderingState.get_version() + 1
        disconnected_players = PlayersRegistry.get_default_sorted_players(include_connected=False, include_disconnected=True)
        disconnected_ips = {player.ip for player in disconnected_players}

        PlayersRegistry.clear_disconnected_players()
        self.disconnected_table_model.clear_all_data()

        self._disconnected_selected_count = 0
        self._update_disconnected_header_with_selection()

        if disconnected_ips:
            MobileWarnings.remove_notified_ips_batch(disconnected_ips)
            VPNWarnings.remove_notified_ips_batch(disconnected_ips)
            HostingWarnings.remove_notified_ips_batch(disconnected_ips)

    def remove_player_from_connected(self, ip: str) -> None:
        """Remove a single player from connected table and registry by IP address."""
        removed_player: Player | None = PlayersRegistry.remove_connected_player(ip)
        if removed_player is None:
            return

        if SessionHost.player and SessionHost.player.ip == ip:
            SessionHost.player = None
            SessionHost.search_player = True

        SessionHost.players_pending_for_disconnection = [
            p for p in SessionHost.players_pending_for_disconnection if p.ip != ip
        ]

        self.connected_table_model.remove_player_by_ip(ip)
        self._update_connected_header_with_selection()

        MobileWarnings.remove_notified_ip(ip)
        VPNWarnings.remove_notified_ip(ip)
        HostingWarnings.remove_notified_ip(ip)

    def remove_player_from_disconnected(self, ip: str) -> None:
        """Remove a single player from disconnected table and registry by IP address."""
        removed_player: Player | None = PlayersRegistry.remove_disconnected_player(ip)
        if removed_player is None:
            return

        self.disconnected_table_model.remove_player_by_ip(ip)
        self._update_disconnected_header_with_selection()

        MobileWarnings.remove_notified_ip(ip)
        VPNWarnings.remove_notified_ip(ip)
        HostingWarnings.remove_notified_ip(ip)
