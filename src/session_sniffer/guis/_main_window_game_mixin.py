"""Game process-control, session-host, and player-resolver mixin for `MainWindow`."""

import logging
from datetime import date, datetime
from functools import partial
from threading import Event
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont, QFontMetrics, QIcon
from PySide6.QtWidgets import QLabel, QMainWindow, QMenu, QMenuBar, QMessageBox, QWidgetAction

from session_sniffer import msgbox
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.error_messages import (
    format_game_solo_session_process_not_running_message,
    format_game_solo_session_suspend_failed_message,
)
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.session_host_diagnostics_dialog import show_session_host_diagnostics_dialog
from session_sniffer.guis.session_host_history_window import (
    SessionHostActionCallbacks,
    populate_host_history_submenu,
    setup_session_host_actions,
)
from session_sniffer.guis.stylesheets import GTA5_STATUS_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions import prompt_rename_session
from session_sniffer.guis.utils import format_duration, load_country_flag_icon
from session_sniffer.player.registry import PlayersRegistry, SessionHost, SessionTracker
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.types import CaptureState, SessionFilterState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from session_sniffer.guis._session_table_section import SessionTableSection
    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.player_resolver import PlayerResolverWindow
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager
    from session_sniffer.player.registry import HostDiagnosticsSnapshot, HostHistoryEntry

logger = logging.getLogger(__name__)


def format_game_solo_action_text() -> str:
    """Return the label for the solo public session action."""
    return f'Solo Public Session ({Settings.solo_session_duration}s)'


def format_game_solo_tooltip(game_label: str) -> str:
    """Return the tooltip text for the solo public session action."""
    return f'Suspend {game_label} for {Settings.solo_session_duration} seconds then auto-resume.\nThis forces the game to spawn you alone in a public session.'


def _format_session_time_component(target_dt: datetime, current_date: date) -> str:
    """Format a session timestamp with date prefix if not today."""
    prefix = f'{target_dt.strftime("%m/%d")} ' if target_dt.date() != current_date else ''
    return f'{prefix}{target_dt.strftime("%H:%M:%S")}'


class GameMixin(QMainWindow):
    """Game process-control, session-host, and player-resolver mixin for `MainWindow`."""

    _game_menu: QMenu
    _game_status_label: QLabel
    _game_status_widget_action: QAction
    _game_menu_status_separator: QAction
    _player_resolver_action: QAction
    _looky_submenu: QMenu
    _game_menu_gta5_separator: QAction
    _sessions_submenu: QMenu
    _game_menu_process_separator: QAction
    _game_process_submenu: QMenu
    _game_suspend_resume_action: QAction
    _game_solo_menu_action: QAction

    _manual_game_suspend_active: bool
    _game_solo_active: bool
    _game_process_suspended: bool
    _game_externally_suspended: bool
    _game_process_detected: bool
    _last_game_status_key: tuple[object, ...]
    _player_resolver_window: PlayerResolverWindow

    if TYPE_CHECKING:
        _update_looky_actions: Callable[[], None]
        _build_looky_submenu: Callable[[QMenu], None]
        _select_ips: Callable[[list[str]], None]
        _detections_manager_window: DetectionsManagerDialog | None
        _userip_manager_window: UserIPDatabasesManager | None
        _disconnected: SessionTableSection

    def _active_game_label(self) -> str:
        """Return the user-facing game label for the active preset."""
        if Settings.is_rdr2_feature_set():
            return 'RDR2'
        return 'GTA V'

    def _active_game_process_name(self) -> str:
        """Return the short process label for the active game."""
        if Settings.is_rdr2_feature_set():
            return 'RDR2'
        return 'GTA5'

    def _active_suspend_manager(self) -> type[GTASuspendManager | RDR2SuspendManager]:
        """Return the suspend manager class for the active feature set."""
        if Settings.is_rdr2_feature_set():
            return RDR2SuspendManager
        return GTASuspendManager

    def _game_has_any_process_path(self) -> bool:
        """Return `True` if the active game is currently running."""
        if Settings.is_rdr2_feature_set():
            return CaptureState.rdr2_is_running
        return CaptureState.gta5_is_running

    def _get_game_process_path(self) -> Path | None:
        """Return the path to the running game executable, or `None` if not running."""
        if Settings.is_rdr2_feature_set():
            return CaptureState.rdr2_path
        return CaptureState.gta5_path

    def _game_process_is_running(self) -> bool:
        """Return `True` if the active game process is currently running."""
        return self._get_game_process_path() is not None

    def _game_is_os_suspended(self) -> bool:
        """Return `True` if the game process is externally suspended outside the manager."""
        if Settings.is_rdr2_feature_set():
            return CaptureState.rdr2_is_suspended
        return CaptureState.gta5_is_suspended

    def _build_game_menu(self, menu_bar: QMenuBar) -> None:
        """Construct the dynamic Game menu and its submenus."""
        game_menu = menu_bar.addMenu('GTA V')
        if not game_menu:
            message = 'Failed to create Game menu'
            raise RuntimeError(message)
        game_menu.setToolTipsVisible(True)
        game_menu_action = game_menu.menuAction()
        if not game_menu_action:
            message = 'Failed to get Game menu action'
            raise RuntimeError(message)
        game_menu_action.setVisible(Settings.is_gta5_feature_set() or Settings.is_rdr2_feature_set())
        self._game_menu = game_menu

        # Process status indicator widget
        game_status_label = QLabel()
        game_status_label.setTextFormat(Qt.TextFormat.RichText)
        game_status_label.setStyleSheet(GTA5_STATUS_LABEL_STYLESHEET)
        game_status_label.setText('<span style="color: #f44336;">●</span> GTA V not running')
        game_status_label.setToolTip('GTA V process detection state')
        game_status_widget_action = QWidgetAction(self)
        game_status_widget_action.setDefaultWidget(game_status_label)
        game_menu.addAction(game_status_widget_action)
        self._game_status_label = game_status_label
        self._game_status_widget_action = game_status_widget_action
        self._resize_game_status_label('● GTA V not running')

        game_menu.aboutToShow.connect(self._update_game_status_label)
        self._game_menu_status_separator = game_menu.addSeparator()

        # Shared: Player Resolver action
        player_resolver_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')), 'Player Resolver', self)
        player_resolver_action.setToolTip('Find the exact IP of a player in your current session.')
        player_resolver_action.triggered.connect(self._open_player_resolver)
        game_menu.addAction(player_resolver_action)
        self._player_resolver_action = player_resolver_action

        # GTA V only: Looky submenu
        self._build_looky_submenu(game_menu)
        self._game_menu_gta5_separator = game_menu.addSeparator()

        # Shared: Sessions submenu
        sessions_submenu = game_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'network.svg')), 'Sessions')
        if not sessions_submenu:
            message = 'Failed to create Sessions submenu'
            raise RuntimeError(message)
        sessions_submenu.setToolTipsVisible(True)
        sessions_submenu.menuAction().setToolTip('Sessions tree, host controls, and history')
        sessions_submenu.aboutToShow.connect(self._update_sessions_menu)
        self._sessions_submenu = sessions_submenu

        self._game_menu_process_separator = game_menu.addSeparator()

        # Shared: Game Process submenu
        self._icon_controller = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg'))
        self._icon_user = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user.svg'))
        self._icon_pause = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg'))
        self._icon_play = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg'))

        game_process_submenu = game_menu.addMenu(self._icon_controller, 'GTA5 Process')
        if not game_process_submenu:
            message = 'Failed to create Game Process submenu'
            raise RuntimeError(message)
        game_process_submenu.setToolTipsVisible(True)
        game_process_submenu.menuAction().setToolTip('Game process controls — suspend/resume for solo and public session manipulation')
        self._game_process_submenu = game_process_submenu

        game_solo_menu_action = QAction(self._icon_user, format_game_solo_action_text(), self)
        game_solo_menu_action.setToolTip(format_game_solo_tooltip(self._active_game_process_name()))
        game_solo_menu_action.triggered.connect(self.game_solo_session)
        game_process_submenu.addAction(game_solo_menu_action)

        game_process_submenu.addSeparator()

        game_suspend_resume_action = QAction(self._icon_pause, 'Suspend Process', self)
        game_suspend_resume_action.setToolTip('Manually suspend the game process — stays suspended until you click it again to resume')
        game_suspend_resume_action.triggered.connect(self.toggle_manual_game_suspend)
        game_process_submenu.addAction(game_suspend_resume_action)

        game_process_submenu.aboutToShow.connect(self._sync_game_process_button)

        self._game_solo_menu_action = game_solo_menu_action
        self._game_suspend_resume_action = game_suspend_resume_action
        self._manual_game_suspend_active = False
        self._game_solo_active = False
        self._game_process_suspended = False
        self._game_externally_suspended = False
        self._game_process_detected = False
        self._last_game_status_key = ()

    def toggle_manual_game_suspend(self) -> None:
        """Toggle manual process suspend on or off for the active game."""
        manager = self._active_suspend_manager()
        game_label = self._active_game_process_name()
        self._sync_game_process_button()
        if self._game_externally_suspended:
            logger.info('Resuming %s process that was left suspended outside this app', game_label)
            manager.resume_os_suspended()
            self._sync_game_process_button()
            return
        if self._manual_game_suspend_active:
            manager.release_reason_global('manual:toolbar')
        else:
            if not self._game_process_is_running():
                logger.warning('Manual %s suspend: process is not running', game_label)
                return
            if manager.is_suspended():
                logger.info('Manual %s suspend: process is already suspended by another protection reason', game_label)
                self._sync_game_process_button()
                return
            manager.request_suspend(
                reason_key='manual:toolbar',
                left_event=Event(),
                duration='Manual',
            )
        self._sync_game_process_button()

    def game_solo_session(self) -> None:
        """Suspend the active game for the configured duration then auto-resume, forcing a solo public session."""
        manager = self._active_suspend_manager()
        game_label = self._active_game_process_name()
        self._sync_game_process_button()
        if not self._game_process_is_running():
            logger.warning('%s solo session: process is not running', game_label)
            msgbox.show(
                title=TITLE,
                text=format_game_solo_session_process_not_running_message(game_label),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        if self._game_externally_suspended:
            logger.info('%s solo session: process is already suspended outside this app', game_label)
            self._sync_game_process_button()
            return
        if manager.is_suspended():
            logger.info('%s solo session: process is already suspended', game_label)
            self._sync_game_process_button()
            return
        already_left = Event()
        already_left.set()
        manager.request_suspend(
            reason_key='solo:toolbar',
            left_event=already_left,
            duration=Settings.solo_session_duration,
        )
        if not manager.has_reason('solo:toolbar'):
            logger.warning('%s solo session: suspend failed', game_label)
            msgbox.show(
                title=TITLE,
                text=format_game_solo_session_suspend_failed_message(game_label),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        self._game_solo_active = True
        self._sync_game_process_button()

    def _refresh_game_process_state(self) -> None:
        """Refresh game process-control flags from the lock-free suspend snapshot and cached state."""
        manager = self._active_suspend_manager()
        suspend_snapshot = manager.snapshot()
        self._manual_game_suspend_active = suspend_snapshot.manual_active
        self._game_solo_active = suspend_snapshot.solo_active

        can_act = self._game_has_any_process_path() and CaptureState.is_local_capture()
        self._game_process_detected = can_act and self._game_process_is_running()

        self._game_process_suspended = can_act and suspend_snapshot.is_suspended
        self._game_externally_suspended = can_act and not suspend_snapshot.is_suspended and self._game_is_os_suspended()

    def _sync_game_process_button(self) -> None:
        """Update the Game Process submenu title and menu-item enabled states."""
        self._refresh_game_process_state()
        manager = self._active_suspend_manager()
        game_label = self._active_game_process_name()
        process_menu_title = f'{game_label} Process'

        can_act = self._game_has_any_process_path() and CaptureState.is_local_capture()
        status_key = (
            can_act,
            self._manual_game_suspend_active,
            self._game_solo_active,
            self._game_process_suspended,
            self._game_externally_suspended,
            self._game_process_detected,
            game_label,
        )
        if status_key == self._last_game_status_key:
            return
        self._last_game_status_key = status_key

        self._game_process_submenu.setEnabled(can_act)
        if not can_act:
            if self._manual_game_suspend_active:
                manager.release_reason_global('manual:toolbar')
                self._manual_game_suspend_active = False
            if self._game_solo_active:
                manager.release_reason_global('solo:toolbar')
                self._game_solo_active = False
            self._game_process_suspended = False
            self._game_externally_suspended = False
            self._game_process_submenu.setTitle(process_menu_title)
            self._game_process_submenu.setIcon(self._icon_controller)
            self._game_suspend_resume_action.setText('Suspend Process')
            self._game_suspend_resume_action.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(
                'External capture mode — process control not available.'
                if not CaptureState.is_local_capture()
                else f'{game_label} is not currently running — launch {game_label} to enable process control.',
            )
        elif self._manual_game_suspend_active:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Suspended)')
            self._game_process_submenu.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setText('Resume Process')
            self._game_suspend_resume_action.setIcon(self._icon_play)
            self._game_suspend_resume_action.setToolTip(f'Remove the manual suspend hold from the {game_label} process')
            self._game_suspend_resume_action.setEnabled(True)
            self._game_solo_menu_action.setEnabled(False)
        elif self._game_solo_active:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Going Solo...)')
            self._game_process_submenu.setIcon(self._icon_user)
            self._game_suspend_resume_action.setText('Suspend Process')
            self._game_suspend_resume_action.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
        elif self._game_process_suspended:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Suspended)')
            self._game_process_submenu.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setText('Resume Process')
            self._game_suspend_resume_action.setIcon(self._icon_play)
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(
                'Process is currently suspended by active protection rules. It will resume automatically when those rules clear.',
            )
            self._game_solo_menu_action.setToolTip('Process is already suspended')
        elif self._game_externally_suspended:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Suspended)')
            self._game_process_submenu.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setText('Resume Process')
            self._game_suspend_resume_action.setIcon(self._icon_play)
            self._game_suspend_resume_action.setEnabled(True)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(f'{game_label} was left suspended outside this app — click to resume it')
            self._game_solo_menu_action.setToolTip('Process is currently suspended — resume it first')
        else:
            self._game_process_submenu.setTitle(process_menu_title)
            self._game_process_submenu.setIcon(self._icon_controller)
            self._game_suspend_resume_action.setText('Suspend Process')
            self._game_suspend_resume_action.setIcon(self._icon_pause)
            if self._game_process_detected:
                self._game_suspend_resume_action.setEnabled(True)
                self._game_solo_menu_action.setEnabled(True)
                self._game_suspend_resume_action.setToolTip(f'Manually suspend the {game_label} process — click again to resume')
                self._game_solo_menu_action.setText(format_game_solo_action_text())
                self._game_solo_menu_action.setToolTip(format_game_solo_tooltip(game_label))
            else:
                self._game_suspend_resume_action.setEnabled(False)
                self._game_solo_menu_action.setEnabled(False)
                self._game_suspend_resume_action.setToolTip(f'{game_label} is not currently running')
                self._game_solo_menu_action.setText(format_game_solo_action_text())
                self._game_solo_menu_action.setToolTip(f'{game_label} is not currently running')

    def _resize_game_status_label(self, visible_text: str) -> None:
        """Resize the game status label to fit `visible_text`."""
        status_font = QFont(self._game_status_label.font())
        status_font.setPointSize(10)
        self._game_status_label.setMinimumWidth(QFontMetrics(status_font).horizontalAdvance(visible_text) + 44 + 12)

    def _update_game_status_label(self) -> None:
        """Refresh the game status label and tooltip from cached `CaptureState` values."""
        game_label = self._active_game_label()
        if Settings.is_rdr2_feature_set():
            running = CaptureState.rdr2_is_running
            suspended = CaptureState.rdr2_is_suspended
            path = CaptureState.rdr2_path
            version_text = 'RDR2'
        else:
            running = CaptureState.gta5_is_running
            suspended = CaptureState.gta5_is_suspended
            path = CaptureState.gta5_path
            version_text = 'GTA V Enhanced' if CaptureState.gta5_is_enhanced else 'GTA V Legacy'

        path_tooltip = str(path) if path is not None else f'{game_label} process detection state'
        if running:
            if suspended:
                visible_text = f'{version_text} (Suspended)'
                self._game_status_label.setText(f'<span style="color: #ff9800;">●</span> {visible_text}')
                self._game_status_label.setToolTip(
                    f'{path_tooltip}\
Process is currently suspended'
                )
            else:
                visible_text = version_text
                self._game_status_label.setText(f'<span style="color: #4caf50;">●</span> {visible_text}')
                self._game_status_label.setToolTip(path_tooltip)
        else:
            visible_text = f'{game_label} not running'
            self._game_status_label.setText(f'<span style="color: #f44336;">●</span> {visible_text}')
            self._game_status_label.setToolTip(f'{game_label} process detection state')
        self._resize_game_status_label(f'● {visible_text}')
        self._last_game_status_key = self._get_current_game_status_key()

    def _get_current_game_status_key(self) -> tuple[object, ...]:
        """Return a comparable snapshot of the active game process detection state."""
        if Settings.is_rdr2_feature_set():
            return (
                'RDR2',
                CaptureState.rdr2_is_running,
                CaptureState.rdr2_is_suspended,
                CaptureState.is_local_capture(),
            )
        return (
            'GTA5',
            CaptureState.gta5_is_running,
            CaptureState.gta5_is_enhanced,
            CaptureState.gta5_is_legacy,
            CaptureState.gta5_is_suspended,
            CaptureState.is_local_capture(),
        )

    def _sync_game_status(self) -> None:
        """Update game status label and actions if process status changed."""
        status_key = self._get_current_game_status_key()
        if status_key != self._last_game_status_key:
            self._update_game_status_label()
            can_interact = self._game_has_any_process_path() or not CaptureState.is_local_capture()
            self._sessions_submenu.setEnabled(can_interact)
            self._player_resolver_action.setEnabled(can_interact)
            self._sync_game_process_button()

    def _refresh_runtime_capability_windows(self) -> None:
        """Refresh open dialogs that gate controls by feature set / interface support."""
        if self._userip_manager_window is not None and self._userip_manager_window.isVisible():
            self._userip_manager_window.refresh_runtime_capabilities()

        if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
            self._detections_manager_window.refresh_detection_availability()

    def _update_game_toolbar_visibility(self) -> None:
        """Show, hide, or rename the Game menu and its actions based on the active feature set."""
        has_feature_set = Settings.is_gta5_feature_set() or Settings.is_rdr2_feature_set()
        is_gta5 = Settings.is_gta5_feature_set()
        SessionHost.clear_session_host_data()

        game_menu_action = self._game_menu.menuAction()
        if game_menu_action:
            game_menu_action.setVisible(has_feature_set)

        if not has_feature_set:
            return

        game_label = self._active_game_label()
        self._game_menu.setTitle(game_label)
        self._game_process_submenu.menuAction().setToolTip(f'{self._active_game_process_name()} process controls — suspend/resume for solo and public session manipulation')
        self._player_resolver_action.setToolTip(f'Find the exact IP of a player in your current {game_label} session.')

        local_only = CaptureState.is_local_capture()
        self._game_status_widget_action.setVisible(local_only)
        self._game_menu_status_separator.setVisible(local_only)
        self._game_menu_process_separator.setVisible(local_only)
        process_action = self._game_process_submenu.menuAction()
        if process_action:
            process_action.setVisible(local_only)

        # GTA V exclusive items
        looky_action = self._looky_submenu.menuAction()
        if looky_action:
            looky_action.setVisible(is_gta5 and local_only)
        self._game_menu_gta5_separator.setVisible(is_gta5 and local_only)

        can_interact = self._game_has_any_process_path() or not CaptureState.is_local_capture()
        self._sessions_submenu.setEnabled(can_interact)
        self._player_resolver_action.setEnabled(can_interact)

        if is_gta5:
            self._update_looky_actions()
            self._refresh_runtime_capability_windows()

        self._update_game_status_label()
        self._sync_game_process_button()

    def _open_player_resolver(self) -> None:
        """Open the Player Resolver window, or focus the existing one."""
        self._player_resolver_window.show_and_focus()

    def _update_sessions_menu(self) -> None:
        """Rebuild the dynamic Sessions tree with all recorded sessions, host controls, and history."""
        self._sessions_submenu.clear()

        current_session_id = SessionTracker.get_current_session_id()
        all_session_ids = SessionTracker.get_all_session_ids()
        has_past_disconnected = len(all_session_ids) > 1 and any(player.session_id < current_session_id for player in PlayersRegistry.get_disconnected_players())
        current_filter = SessionFilterState.get_selected_session()

        host_callbacks = SessionHostActionCallbacks(
            clear_host=self._clear_session_host,
            redetect_host=self._redetect_session_host,
            show_diagnostics=self._show_session_host_diagnostics,
        )

        for session_id in reversed(all_session_ids):
            is_current = session_id == current_session_id
            display_name = SessionTracker.get_session_display_name(session_id)
            player_count = SessionTracker.get_session_player_count(session_id)
            player_noun = f'player{pluralize(player_count)}'
            time_label = SessionTracker.get_session_time_label(session_id)
            session_title = f'{display_name} (Current)' if is_current else display_name
            label_parts = [session_title, f'{player_count} {player_noun}']
            if time_label is not None:
                label_parts.append(time_label)
            session_label = '  |  '.join(label_parts)
            session_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / ('radio.svg' if is_current else 'history.svg')))
            session_menu = self._sessions_submenu.addMenu(session_icon, session_label)
            if not session_menu:
                continue
            session_menu.setToolTipsVisible(True)
            menu_tooltip = f'{player_count} {player_noun} recorded in {display_name}'
            if time_label is not None:
                menu_tooltip = f'{menu_tooltip}  |  {time_label}'
            session_menu.setToolTip(menu_tooltip)
            session_menu.menuAction().setToolTip(menu_tooltip)

            target_filter = SessionFilterState.FILTER_CURRENT if is_current else session_id
            players_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'player.svg')), f'Players: {player_count}', session_menu)
            if is_current:
                connected_count = len([player for player in PlayersRegistry.get_connected_players() if not player.is_third_party_server])
                disconnected_count = len(
                    [player for player in PlayersRegistry.get_disconnected_players() if player.session_id == session_id and not player.is_third_party_server]
                )
                connected_noun = f'connected player{pluralize(connected_count)}'
                disconnected_noun = f'disconnected player{pluralize(disconnected_count)}'
                players_action.setToolTip(f'{connected_count} {connected_noun}, {disconnected_count} {disconnected_noun}')
            else:
                players_action.setToolTip(f'{player_count} {player_noun} recorded in this session')

            players_action.triggered.connect(partial(self._apply_session_filter, target_filter))

            start_dt = SessionTracker.get_session_start_time(session_id)
            end_dt = SessionTracker.get_session_end_time(session_id)
            now_dt = datetime.now(tz=LOCAL_TZ)
            now_date = now_dt.date()

            if is_current:
                if start_dt is not None:
                    elapsed_seconds = max(0.0, (now_dt - start_dt).total_seconds())
                    formatted_start = _format_session_time_component(start_dt, now_date)
                    time_action_text = f'Time: Started at {formatted_start} ({format_duration(elapsed_seconds)} ago)'
                    time_action_tooltip = f'Session started at {start_dt.strftime("%Y-%m-%d %H:%M:%S")} (running for {format_duration(elapsed_seconds)})'
                else:
                    time_action_text = 'Time: Current session'
                    time_action_tooltip = 'Current active session'
            elif start_dt is not None and end_dt is not None:
                duration_seconds = max(0.0, (end_dt - start_dt).total_seconds())
                formatted_start = _format_session_time_component(start_dt, now_date)
                formatted_end = _format_session_time_component(end_dt, now_date)
                if formatted_start == formatted_end:
                    time_action_text = f'Time: {formatted_start} ({format_duration(duration_seconds)})'
                else:
                    time_action_text = f'Time: {formatted_start} - {formatted_end} ({format_duration(duration_seconds)})'
                time_action_tooltip = (
                    f'Session duration: {format_duration(duration_seconds)} ({start_dt.strftime("%Y-%m-%d %H:%M:%S")} - {end_dt.strftime("%Y-%m-%d %H:%M:%S")})'
                )
            elif start_dt is not None:
                formatted_start = _format_session_time_component(start_dt, now_date)
                time_action_text = f'Time: Started at {formatted_start}'
                time_action_tooltip = f'Session started at {start_dt.strftime("%Y-%m-%d %H:%M:%S")}'
            elif end_dt is not None:
                formatted_end = _format_session_time_component(end_dt, now_date)
                time_action_text = f'Time: Ended at {formatted_end}'
                time_action_tooltip = f'Session ended at {end_dt.strftime("%Y-%m-%d %H:%M:%S")}'
            else:
                time_action_text = 'Time: No time recorded'
                time_action_tooltip = 'No timestamps recorded for this session'

            time_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'timer.svg')), time_action_text, session_menu)
            time_action.setToolTip(time_action_tooltip)
            time_action.triggered.connect(partial(self._apply_session_filter, target_filter))

            if is_current:
                current_session_host = SessionHost.get_player()
                session_history = SessionHost.get_history(session_id=session_id)
                last_host = session_history[-1] if session_history else None

                if current_session_host is not None and not current_session_host.left_event.is_set():
                    matched_player = PlayersRegistry.get_player_by_ip(current_session_host.ip)
                    usernames = ', '.join(matched_player.usernames) if matched_player is not None and matched_player.usernames else ''
                    host_text = f'Host: Detected: {current_session_host.ip}' + (f'  |  {usernames}' if usernames else '')
                    country_code = (
                        current_session_host.iplookup.geolite2.country_code
                        if current_session_host.iplookup.geolite2.country_code not in {'...', 'N/A'}
                        else current_session_host.iplookup.ipapi.country_code
                    )
                    flag_icon = load_country_flag_icon(country_code) or QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg'))
                    host_action = QAction(flag_icon, host_text, session_menu)
                    host_action.setToolTip('Select this host player in the table and open host diagnostics')
                    host_action.triggered.connect(partial(self._select_and_show_current_host_diagnostics, current_session_host.ip))
                    session_menu.addAction(host_action)
                elif last_host is not None:
                    matched_player = PlayersRegistry.get_player_by_ip(last_host.ip)
                    usernames = ', '.join(matched_player.usernames) if matched_player is not None and matched_player.usernames else ''
                    host_text = f'Host: Detected: {last_host.ip}' + (f'  |  {usernames}' if usernames else '') + ' (Left)'
                    flag_icon = load_country_flag_icon(last_host.country_code) or QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg'))
                    host_action = QAction(flag_icon, host_text, session_menu)
                    host_action.setToolTip('Select this host player in the table and open host diagnostics (Host has left the session)')
                    host_action.triggered.connect(self._create_past_host_action_handler(last_host))
                    session_menu.addAction(host_action)
                    if SessionHost.search_player:
                        searching_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')), 'Host: Searching…', session_menu)
                        searching_action.setEnabled(False)
                        session_menu.addAction(searching_action)
                elif SessionHost.search_player:
                    searching_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')), 'Host: Searching…', session_menu)
                    searching_action.setEnabled(False)
                    session_menu.addAction(searching_action)
                else:
                    no_host_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')), 'Host: No host', session_menu)
                    no_host_action.setEnabled(False)
                    session_menu.addAction(no_host_action)

                session_menu.addAction(players_action)
                session_menu.addAction(time_action)
                setup_session_host_actions(session_menu, host_callbacks)
            else:
                session_history = SessionHost.get_history(session_id=session_id)
                if session_history:
                    last_host = session_history[-1]
                    matched_player = PlayersRegistry.get_player_by_ip(last_host.ip)
                    usernames = ', '.join(matched_player.usernames) if matched_player is not None and matched_player.usernames else ''
                    host_label = f'Host: {last_host.ip}' + (f'  |  {usernames}' if usernames else '')
                    flag_icon = load_country_flag_icon(last_host.country_code) or QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg'))
                    host_action = QAction(flag_icon, host_label, session_menu)
                    host_action.setToolTip('Select this host player in the table and open host diagnostics')
                    host_action.triggered.connect(self._create_past_host_action_handler(last_host))
                    session_menu.addAction(host_action)

                    session_menu.addAction(players_action)
                    session_menu.addAction(time_action)

                    diagnostics_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')), 'Host Diagnostics…', session_menu)
                    diagnostics_action.setToolTip('Show diagnostics recorded for this host detection')
                    diagnostics_action.triggered.connect(partial(self._open_host_history_diagnostics, last_host))
                    session_menu.addSeparator()
                    session_menu.addAction(diagnostics_action)
                else:
                    no_host_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')), 'Host: None recorded', session_menu)
                    no_host_action.setEnabled(False)
                    session_menu.addAction(no_host_action)

                    session_menu.addAction(players_action)
                    session_menu.addAction(time_action)

            session_menu.addSeparator()

            rename_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')), f"Rename Session '{display_name}'…", session_menu)
            rename_action.setToolTip(f"Rename Session '{display_name}'")
            rename_action.triggered.connect(partial(self._prompt_rename_session, session_id))
            session_menu.addAction(rename_action)

            filter_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')), 'Filter to this Session', session_menu)
            filter_action.setCheckable(True)
            is_filter_active = current_filter in (SessionFilterState.FILTER_CURRENT, session_id) if is_current else current_filter == session_id
            filter_action.setChecked(is_filter_active)

            if is_filter_active:
                filter_action.setEnabled(True)
                filter_action.setToolTip('Show all sessions (currently filtered to this session)')
                filter_target = SessionFilterState.FILTER_ALL
            elif len(all_session_ids) <= 1:
                filter_action.setEnabled(False)
                filter_action.setToolTip('Filter to only show players from this session (only one session recorded)')
                filter_target = target_filter
            elif is_current and not has_past_disconnected and current_filter == SessionFilterState.FILTER_ALL:
                filter_action.setEnabled(False)
                filter_action.setToolTip('Filter to only show players from this session (no disconnected players from other sessions)')
                filter_target = target_filter
            else:
                filter_action.setEnabled(True)
                filter_action.setToolTip('Filter to only show players from this session')
                filter_target = target_filter

            filter_action.triggered.connect(partial(self._apply_session_filter, filter_target))
            session_menu.addAction(filter_action)

        self._sessions_submenu.addSeparator()
        history_menu = self._sessions_submenu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'host_history.svg')), 'Host History')
        if history_menu:
            history_menu.setToolTipsVisible(True)
            history_menu.aboutToShow.connect(
                partial(
                    populate_host_history_submenu,
                    history_menu,
                    self._select_ips,
                    self._open_host_history_diagnostics,
                )
            )

    def _create_past_host_action_handler(self, target_entry: HostHistoryEntry) -> Callable[[], None]:
        def _handler() -> None:
            self._select_ips([target_entry.ip])
            self._open_host_history_diagnostics(target_entry)

        return _handler

    def _select_and_show_current_host_diagnostics(self, target_ip: str) -> None:
        self._select_ips([target_ip])
        self._show_session_host_diagnostics()

    def _prompt_rename_session(self, session_id: int) -> None:
        """Prompt user to rename the specified session and synchronize the session filter."""
        if prompt_rename_session(self, session_id):
            self._disconnected.sync_session_filter()

    def _apply_session_filter(self, session_id: int) -> None:
        """Apply a session filter and synchronize table controls."""
        self._disconnected.set_selected_session_filter(session_id)

    def _clear_session_host(self) -> None:
        """Manually clear the current session host and reset host detection state."""
        SessionHost.clear_session_host_data()

    def _open_host_history_diagnostics(self, history_entry: HostHistoryEntry) -> None:
        """Display diagnostic information for a specific host history entry."""
        diagnostics = history_entry.diagnostics
        if diagnostics is None and SessionHost.last_diagnostics is not None and SessionHost.last_diagnostics.detected_host_ip == history_entry.ip:
            diagnostics = SessionHost.last_diagnostics

        if diagnostics is None:
            QMessageBox.information(
                self,
                TITLE,
                f'No session host detection diagnostics were recorded for host {history_entry.ip}.',
            )
            return

        show_session_host_diagnostics_dialog(
            self,
            diagnostics,
            dialog_key=history_entry.dialog_key,
        )

    def _show_session_host_diagnostics(self) -> None:
        """Display detailed diagnostic information from the last session host detection attempt."""
        diagnostics = SessionHost.last_diagnostics
        if diagnostics is None:
            current_history = SessionHost.get_history(session_id=SessionTracker.get_current_session_id())
            if current_history and current_history[-1].diagnostics is not None:
                diagnostics = current_history[-1].diagnostics

        if diagnostics is None:
            QMessageBox.information(self, TITLE, 'No session host detection diagnostics are available yet.')
            return

        show_session_host_diagnostics_dialog(
            self,
            diagnostics,
            redetect_callback=self._redetect_host_from_diagnostics,
        )

    def _redetect_host_from_diagnostics(self) -> HostDiagnosticsSnapshot | None:
        """Re-evaluate session host detection in-place for the diagnostics window."""
        if not Settings.is_session_host_feature_set():
            QMessageBox.warning(self, TITLE, 'Session Host Detection is not supported for the current game feature set.')
            return None

        if not Settings.gui_session_host_detection:
            QMessageBox.warning(self, TITLE, 'Session Host Detection is disabled in Settings.\n\nPlease enable it in Settings to detect the session host.')
            return None

        if CaptureState.is_local_capture():
            if Settings.is_gta5_feature_set() and not CaptureState.gta5_is_running:
                QMessageBox.warning(self, TITLE, 'Grand Theft Auto V is not currently running.')
                return None
            if Settings.is_rdr2_feature_set() and not CaptureState.rdr2_is_running:
                QMessageBox.warning(self, TITLE, 'Red Dead Redemption 2 is not currently running.')
                return None

        connected_players = PlayersRegistry.get_connected_players()
        if not connected_players:
            QMessageBox.information(self, TITLE, 'No connected players were found in the current session.')
            return None

        SessionHost.clear_session_host_data()
        SessionHost.manual_redetect = True

        SessionHost.get_host_player(connected_players)
        SessionHost.manual_redetect = False
        SessionHost.search_player = False
        SessionHost.search_start_time = None

        return SessionHost.last_diagnostics

    def _redetect_session_host(self) -> None:
        """Clear the current session host and immediately re-evaluate host detection with notification on failure."""
        snapshot = self._redetect_host_from_diagnostics()
        if snapshot is not None:
            self._show_session_host_diagnostics()
