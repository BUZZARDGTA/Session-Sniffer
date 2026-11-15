"""Game process-control, session-host, and player-resolver mixin for `MainWindow`."""

import html
import logging
from datetime import datetime
from functools import partial
from threading import Event
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont, QFontMetrics, QIcon
from PySide6.QtWidgets import QLabel, QMainWindow, QMenu, QMenuBar, QMessageBox, QWidgetAction

from session_sniffer import msgbox
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.error_messages import format_game_solo_session_process_not_running_message, format_game_solo_session_suspend_failed_message
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis._main_window_looky_mixin import (
    format_game_solo_action_text,
    format_game_solo_tooltip,
    format_session_time_component,
)
from session_sniffer.guis._main_window_shortcuts_mixin import append_shortcut_tooltip
from session_sniffer.guis.session_host_diagnostics_dialog import show_session_host_diagnostics_dialog
from session_sniffer.guis.session_host_history_window import SessionHostActionCallbacks, populate_host_history_submenu, setup_session_host_actions
from session_sniffer.guis.stylesheets import GTA5_STATUS_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions import prompt_rename_session
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.utils import format_duration, format_menu_usernames, format_player_action_tooltip, load_country_flag_icon
from session_sniffer.i18n import get_active_language, tr, tr_plural
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.session_host import SessionHost
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.modmenu_logs_parser import ModMenuLogsParser
from session_sniffer.rendering_core.types import CaptureState, SessionFilterState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from session_sniffer.guis._session_table_section import SessionTableSection
    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.player_resolver import PlayerResolverWindow
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager
    from session_sniffer.player.session_host import HostDiagnosticsSnapshot, HostHistoryEntry

logger = logging.getLogger(__name__)


class GameMixin(QMainWindow):
    """Game process-control, session-host, and player-resolver mixin for `MainWindow`."""

    _game_menu: QMenu
    _game_status_label: QLabel
    _game_status_widget_action: QAction
    _game_menu_status_separator: QAction
    _player_resolver_action: QAction
    _looky_submenu: QMenu
    _current_session_submenu: QMenu
    _session_history_submenu: QMenu
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
    _last_game_process_button_key: tuple[object, ...]
    _last_feature_set: str | None
    _player_resolver_window: PlayerResolverWindow

    if TYPE_CHECKING:

        def _update_looky_actions(self) -> None: ...
        def _refresh_looky_language_texts(self) -> None: ...
        def _sync_shortcuts(self) -> None: ...

        def _build_looky_submenu(self, gta5_menu: QMenu) -> None:
            del gta5_menu

        def _select_ips(self, ip_addresses: list[str]) -> None:
            del ip_addresses

        def _cleanup_removed_player_ips(self, removed_ips: set[str], *, remove_from_connected: bool = False, remove_from_disconnected: bool = False) -> None:
            del removed_ips, remove_from_connected, remove_from_disconnected

        def _refresh_session_gui_state(self) -> None: ...

        _detections_manager_window: DetectionsManagerDialog | None
        _userip_manager_window: UserIPDatabasesManager | None
        _disconnected: SessionTableSection

    def _active_game_label(self) -> str:
        """Return the user-facing game label for the active preset."""
        return 'RDR2' if Settings.is_rdr2_feature_set() else 'GTA V'

    def _active_game_process_name(self) -> str:
        """Return the short process label for the active game."""
        return 'RDR2' if Settings.is_rdr2_feature_set() else 'GTA5'

    def _active_suspend_manager(self) -> type[GTASuspendManager | RDR2SuspendManager]:
        """Return the suspend manager class for the active feature set."""
        return RDR2SuspendManager if Settings.is_rdr2_feature_set() else GTASuspendManager

    def _game_has_any_process_path(self) -> bool:
        """Return `True` if the active game is currently running."""
        return CaptureState.rdr2_is_running if Settings.is_rdr2_feature_set() else CaptureState.gta5_is_running

    def _get_game_process_path(self) -> Path | None:
        """Return the path to the running game executable, or `None` if not running."""
        return CaptureState.rdr2_path if Settings.is_rdr2_feature_set() else CaptureState.gta5_path

    def _game_process_is_running(self) -> bool:
        """Return `True` if the active game process is currently running."""
        return self._get_game_process_path() is not None

    def _game_is_os_suspended(self) -> bool:
        """Return `True` if the game process is externally suspended outside the manager."""
        return CaptureState.rdr2_is_suspended if Settings.is_rdr2_feature_set() else CaptureState.gta5_is_suspended

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
        game_menu_action.setVisible(Settings.is_rockstar_feature_set())
        self._game_menu = game_menu

        game_status_label = QLabel()
        game_status_label.setTextFormat(Qt.TextFormat.RichText)
        game_status_label.setStyleSheet(GTA5_STATUS_LABEL_STYLESHEET)
        initial_status_text = tr('{game} not running', game='GTA V')
        game_status_label.setText(themed_qss(f'<span style="color: #f44336;">●</span> {html.escape(initial_status_text)}'))
        game_status_label.setToolTip(tr('{game} process detection state', game='GTA V'))
        game_status_widget_action = QWidgetAction(self)
        game_status_widget_action.setDefaultWidget(game_status_label)
        game_menu.addAction(game_status_widget_action)
        self._game_status_label = game_status_label
        self._game_status_widget_action = game_status_widget_action
        self._resize_game_status_label(f'● {initial_status_text}')

        game_menu.aboutToShow.connect(self._update_game_status_label)
        self._game_menu_status_separator = game_menu.addSeparator()

        player_resolver_action = QAction(QIcon(str(ICONS_DIR_PATH / 'search.svg')), '', self)
        player_resolver_action.triggered.connect(self._open_player_resolver)
        game_menu.addAction(player_resolver_action)
        self._player_resolver_action = player_resolver_action
        self._refresh_player_resolver_action_texts()

        self._build_looky_submenu(game_menu)
        self._game_menu_gta5_separator = game_menu.addSeparator()

        current_session_submenu = game_menu.addMenu(QIcon(str(ICONS_DIR_PATH / 'radio.svg')), tr('Current Session'))
        if not current_session_submenu:
            message = 'Failed to create Current Session submenu'
            raise RuntimeError(message)
        current_session_submenu.setToolTipsVisible(True)
        current_session_submenu.menuAction().setToolTip(tr('Current active session controls, host detection, and player stats'))
        current_session_submenu.aboutToShow.connect(self._update_current_session_menu)
        self._current_session_submenu = current_session_submenu

        session_history_submenu = game_menu.addMenu(QIcon(str(ICONS_DIR_PATH / 'rotate-ccw-clock.svg')), tr('Session History'))
        if not session_history_submenu:
            message = 'Failed to create Session History submenu'
            raise RuntimeError(message)
        session_history_submenu.setToolTipsVisible(True)
        session_history_submenu.menuAction().setToolTip(tr('Past sessions, recorded session hosts, and history archive'))
        session_history_submenu.aboutToShow.connect(self._update_session_history_menu)
        self._session_history_submenu = session_history_submenu

        self._game_menu_process_separator = game_menu.addSeparator()

        self._icon_controller = QIcon(str(ICONS_DIR_PATH / 'gamepad-2.svg'))
        self._icon_user = QIcon(str(ICONS_DIR_PATH / 'user.svg'))
        self._icon_pause = QIcon(str(ICONS_DIR_PATH / 'circle-pause.svg'))
        self._icon_play = QIcon(str(ICONS_DIR_PATH / 'circle-play.svg'))

        game_process_submenu = game_menu.addMenu(self._icon_controller, tr('{game} Process', game='GTA5'))
        if not game_process_submenu:
            message = 'Failed to create Game Process submenu'
            raise RuntimeError(message)
        game_process_submenu.setToolTipsVisible(True)
        game_process_submenu.menuAction().setToolTip(tr('Game process controls — suspend/resume for solo and public session manipulation'))
        self._game_process_submenu = game_process_submenu

        game_solo_menu_action = QAction(self._icon_user, format_game_solo_action_text(), self)
        game_solo_menu_action.setToolTip(format_game_solo_tooltip(self._active_game_process_name()))
        game_solo_menu_action.triggered.connect(self.game_solo_session)
        game_process_submenu.addAction(game_solo_menu_action)
        game_process_submenu.addSeparator()

        initial_suspend_hotkey = Settings.get_active_shortcut('suspend_process_hotkey')
        game_suspend_resume_action = QAction(self._icon_pause, tr('Suspend Process'), self)
        game_suspend_resume_action.setToolTip(
            append_shortcut_tooltip(
                tr('Manually suspend the game process — stays suspended until you click it again to resume'),
                initial_suspend_hotkey,
                is_global=True,
            ),
        )
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
        self._last_game_process_button_key = ()
        self._last_feature_set = Settings.capture_feature_set

    def _refresh_player_resolver_action_texts(self) -> None:
        """Refresh the Player Resolver menu action text and tooltip with its configured global hotkey."""
        resolver_hotkey = Settings.get_active_shortcut('player_resolver_hotkey')
        self._player_resolver_action.setText(tr('Player Resolver'))
        base_tooltip = (
            tr('Find the exact IP of a player in your current {game} session.', game=self._active_game_label())
            if Settings.is_rockstar_feature_set()
            else tr('Find the exact IP of a player in your current session.')
        )
        self._player_resolver_action.setToolTip(append_shortcut_tooltip(base_tooltip, resolver_hotkey, is_global=True))

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
            manager.request_suspend(reason_key='manual:toolbar', left_event=Event(), duration='Manual')
        self._sync_game_process_button()

    def game_solo_session(self) -> None:
        """Suspend the active game for the configured duration then auto-resume, forcing a solo public session."""
        manager = self._active_suspend_manager()
        game_label = self._active_game_process_name()
        self._sync_game_process_button()
        if not self._game_process_is_running():
            logger.warning('%s solo session: process is not running', game_label)
            msgbox.show(
                title=TITLE, text=format_game_solo_session_process_not_running_message(game_label),
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
        manager.request_suspend(reason_key='solo:toolbar', left_event=already_left, duration=Settings.solo_session_duration)
        if not manager.has_reason('solo:toolbar'):
            logger.warning('%s solo session: suspend failed', game_label)
            msgbox.show(
                title=TITLE, text=format_game_solo_session_suspend_failed_message(game_label),
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

    def _can_trigger_solo_session(self) -> bool:
        """Return `True` when the active game process is running and eligible for a solo session."""
        self._refresh_game_process_state()
        return self._game_process_detected and not self._game_process_suspended and not self._game_externally_suspended

    def _can_toggle_manual_game_suspend(self) -> bool:
        """Return `True` when the active game process can be manually suspended or resumed."""
        self._refresh_game_process_state()
        can_resume = self._manual_game_suspend_active or self._game_externally_suspended
        can_suspend = self._game_process_detected and not self._game_solo_active and not self._game_process_suspended
        return can_resume or can_suspend

    def _sync_game_process_button(self) -> None:
        """Update the Game Process submenu title and menu-item enabled states."""
        self._refresh_game_process_state()
        manager = self._active_suspend_manager()
        game_label = self._active_game_process_name()
        process_menu_title = tr('{game} Process', game=game_label)
        can_act = self._game_has_any_process_path() and CaptureState.is_local_capture()
        solo_hotkey = Settings.get_active_shortcut('solo_session_hotkey')
        suspend_hotkey = Settings.get_active_shortcut('suspend_process_hotkey')
        status_key = (
            can_act, self._manual_game_suspend_active, self._game_solo_active, self._game_process_suspended, self._game_externally_suspended,
            self._game_process_detected, game_label, Settings.solo_session_duration, solo_hotkey, suspend_hotkey, get_active_language(),
        )
        if status_key == self._last_game_process_button_key:
            return
        self._last_game_process_button_key = status_key
        self._game_solo_menu_action.setText(format_game_solo_action_text())
        self._game_solo_menu_action.setToolTip(format_game_solo_tooltip(game_label))
        suspend_text = tr('Suspend Process')
        resume_text = tr('Resume Process')

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
            self._game_suspend_resume_action.setText(suspend_text)
            self._game_suspend_resume_action.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(
                tr('External capture mode — process control not available.')
                if not CaptureState.is_local_capture()
                else tr('{game} is not currently running — launch {game} to enable process control.', game=game_label),
            )
        elif self._manual_game_suspend_active:
            self._game_process_submenu.setTitle(tr('{title} (Suspended)', title=process_menu_title))
            self._game_process_submenu.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setText(resume_text)
            self._game_suspend_resume_action.setIcon(self._icon_play)
            self._game_suspend_resume_action.setToolTip(
                append_shortcut_tooltip(tr('Remove the manual suspend hold from the {game} process', game=game_label), suspend_hotkey, is_global=True),
            )
            self._game_suspend_resume_action.setEnabled(True)
            self._game_solo_menu_action.setEnabled(False)
        elif self._game_solo_active:
            self._game_process_submenu.setTitle(tr('{title} (Going Solo...)', title=process_menu_title))
            self._game_process_submenu.setIcon(self._icon_user)
            self._game_suspend_resume_action.setText(suspend_text)
            self._game_suspend_resume_action.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
        elif self._game_process_suspended:
            self._game_process_submenu.setTitle(tr('{title} (Suspended)', title=process_menu_title))
            self._game_process_submenu.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setText(resume_text)
            self._game_suspend_resume_action.setIcon(self._icon_play)
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(tr('Process is currently suspended by active protection rules. It will resume automatically when those rules clear.'))
            self._game_solo_menu_action.setToolTip(tr('Process is already suspended'))
        elif self._game_externally_suspended:
            self._game_process_submenu.setTitle(tr('{title} (Suspended)', title=process_menu_title))
            self._game_process_submenu.setIcon(self._icon_pause)
            self._game_suspend_resume_action.setText(resume_text)
            self._game_suspend_resume_action.setIcon(self._icon_play)
            self._game_suspend_resume_action.setEnabled(True)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(
                append_shortcut_tooltip(tr('{game} was left suspended outside this app — click to resume it', game=game_label), suspend_hotkey, is_global=True),
            )
            self._game_solo_menu_action.setToolTip(tr('Process is currently suspended — resume it first'))
        else:
            self._game_process_submenu.setTitle(process_menu_title)
            self._game_process_submenu.setIcon(self._icon_controller)
            self._game_suspend_resume_action.setText(suspend_text)
            self._game_suspend_resume_action.setIcon(self._icon_pause)
            if self._game_process_detected:
                self._game_suspend_resume_action.setEnabled(True)
                self._game_solo_menu_action.setEnabled(True)
                self._game_suspend_resume_action.setToolTip(
                    append_shortcut_tooltip(tr('Manually suspend the {game} process — click again to resume', game=game_label), suspend_hotkey, is_global=True),
                )
                self._game_solo_menu_action.setText(format_game_solo_action_text())
                self._game_solo_menu_action.setToolTip(format_game_solo_tooltip(game_label))
            else:
                self._game_suspend_resume_action.setEnabled(False)
                self._game_solo_menu_action.setEnabled(False)
                self._game_suspend_resume_action.setToolTip(tr('{game} is not currently running', game=game_label))
                self._game_solo_menu_action.setText(format_game_solo_action_text())
                self._game_solo_menu_action.setToolTip(tr('{game} is not currently running', game=game_label))

    def _resize_game_status_label(self, visible_text: str) -> None:
        """Resize the game status label to fit `visible_text`."""
        status_font = QFont(self._game_status_label.font())
        status_font.setPointSize(10)
        self._game_status_label.setMinimumWidth(QFontMetrics(status_font).horizontalAdvance(visible_text) + 44 + 12)

    def _update_game_status_label(self) -> None:
        """Refresh the game status label and tooltip from cached `CaptureState` values."""
        game_label = self._active_game_label()
        if Settings.is_rdr2_feature_set():
            running, suspended, path, version_text = CaptureState.rdr2_is_running, CaptureState.rdr2_is_suspended, CaptureState.rdr2_path, 'RDR2'
        else:
            running, suspended, path = CaptureState.gta5_is_running, CaptureState.gta5_is_suspended, CaptureState.gta5_path
            version_text = 'GTA V Enhanced' if CaptureState.gta5_is_enhanced else 'GTA V Legacy'

        default_tooltip = tr('{game} process detection state', game=game_label)
        path_tooltip = str(path) if path is not None else default_tooltip
        if running:
            if suspended:
                visible_text = tr('{version} (Suspended)', version=version_text)
                self._game_status_label.setText(themed_qss(f'<span style="color: #ff9800;">●</span> {html.escape(visible_text)}'))
                self._game_status_label.setToolTip(f'{path_tooltip}\n{tr("Process is currently suspended")}')
            else:
                visible_text = version_text
                self._game_status_label.setText(themed_qss(f'<span style="color: #4caf50;">●</span> {html.escape(visible_text)}'))
                self._game_status_label.setToolTip(path_tooltip)
        else:
            visible_text = tr('{game} not running', game=game_label)
            self._game_status_label.setText(themed_qss(f'<span style="color: #f44336;">●</span> {html.escape(visible_text)}'))
            self._game_status_label.setToolTip(default_tooltip)
        self._resize_game_status_label(f'● {visible_text}')
        self._last_game_status_key = self._get_current_game_status_key()

    def _get_current_game_status_key(self) -> tuple[object, ...]:
        """Return a comparable snapshot of the active game process detection state."""
        active_language = get_active_language()
        if Settings.is_rdr2_feature_set():
            return ('RDR2', CaptureState.rdr2_is_running, CaptureState.rdr2_is_suspended, CaptureState.is_local_capture(), active_language)
        return (
            'GTA5', CaptureState.gta5_is_running, CaptureState.gta5_is_enhanced, CaptureState.gta5_is_legacy,
            CaptureState.gta5_is_suspended, CaptureState.is_local_capture(), active_language,
        )

    def _sync_game_status(self) -> None:
        """Update game status label and actions if process status changed."""
        status_key = self._get_current_game_status_key()
        if status_key != self._last_game_status_key:
            self._update_game_status_label()
            self._sync_game_process_button()

    def _refresh_runtime_capability_windows(self) -> None:
        """Refresh open dialogs that gate controls by feature set / interface support."""
        if self._userip_manager_window is not None and self._userip_manager_window.isVisible():
            self._userip_manager_window.refresh_runtime_capabilities()

        if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
            self._detections_manager_window.refresh_detection_availability()

    def _update_game_toolbar_visibility(self) -> None:
        """Show, hide, or rename the Game menu and its actions based on the active feature set."""
        has_feature_set = Settings.is_rockstar_feature_set()
        is_gta5 = Settings.is_gta5_feature_set()
        current_feature_set = Settings.capture_feature_set
        if current_feature_set != self._last_feature_set or not has_feature_set:
            SessionHost.clear_session_host_data()
        self._last_feature_set = current_feature_set

        game_menu_action = self._game_menu.menuAction()
        if game_menu_action:
            game_menu_action.setVisible(has_feature_set)

        self._update_looky_actions()
        self._sync_shortcuts()
        self._refresh_runtime_capability_windows()

        if not has_feature_set:
            if SessionFilterState.get_selected_session() != SessionFilterState.FILTER_ALL:
                self._disconnected.set_selected_session_filter(SessionFilterState.FILTER_ALL)
            return

        game_label = self._active_game_label()
        self._game_menu.setTitle(game_label)
        self._game_process_submenu.menuAction().setToolTip(
            tr('{game} process controls — suspend/resume for solo and public session manipulation', game=self._active_game_process_name()),
        )
        self._refresh_player_resolver_action_texts()

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

        self._update_game_status_label()
        self._sync_game_process_button()

    def _refresh_game_menu_language_texts(self) -> None:
        """Re-translate Game menu actions, submenus, and status widgets on language change."""
        self._refresh_player_resolver_action_texts()
        self._current_session_submenu.setTitle(tr('Current Session'))
        self._current_session_submenu.menuAction().setToolTip(tr('Current active session controls, host detection, and player stats'))
        self._session_history_submenu.setTitle(tr('Session History'))
        self._session_history_submenu.menuAction().setToolTip(tr('Past sessions, recorded session hosts, and history archive'))
        self._game_process_submenu.menuAction().setToolTip(
            tr('{game} process controls — suspend/resume for solo and public session manipulation', game=self._active_game_process_name()),
        )
        self._refresh_looky_language_texts()
        self._last_game_status_key = ()
        self._last_game_process_button_key = ()
        self._update_game_status_label()
        self._sync_game_process_button()

    def _open_player_resolver(self) -> None:
        """Open the Player Resolver window, or focus the existing one."""
        self._player_resolver_window.show_and_focus()

    def _update_current_session_menu(self) -> None:
        """Rebuild the Current Session submenu with live host detection controls and active session stats."""
        self._current_session_submenu.clear()
        current_session_id = SessionTracker.get_current_session_id()
        display_name = SessionTracker.get_session_display_name(current_session_id)
        current_filter = SessionFilterState.get_selected_session()
        is_filter_active = current_filter in (SessionFilterState.FILTER_CURRENT, current_session_id)

        current_session_host = SessionHost.get_player()
        session_history = SessionHost.get_history(session_id=current_session_id)
        last_host = session_history[-1] if session_history else None
        last_host_live = PlayersRegistry.get_player_by_ip(last_host.ip) if last_host is not None else None
        last_host_left = last_host_live is None or last_host_live.left_event.is_set() or not PlayersRegistry.is_player_connected(last_host_live)

        if current_session_host is not None and not current_session_host.left_event.is_set():
            matched_player = PlayersRegistry.get_player_by_ip(current_session_host.ip)
            fallback_names = SessionHost.last_diagnostics.detected_host_usernames if SessionHost.last_diagnostics is not None else ()
            usernames = matched_player.usernames if matched_player is not None and matched_player.usernames else fallback_names
            formatted_usernames = format_menu_usernames(usernames)
            host_text = (
                tr('Host: Detected: {ip}  |  {usernames}', ip=current_session_host.ip, usernames=formatted_usernames)
                if formatted_usernames
                else tr('Host: Detected: {ip}', ip=current_session_host.ip)
            )
            flag_icon = load_country_flag_icon(current_session_host.iplookup.resolve_country_code()) or QIcon(str(ICONS_DIR_PATH / 'crown.svg'))
            host_action = QAction(flag_icon, host_text, self._current_session_submenu)
            host_action.setToolTip(format_player_action_tooltip(tr('Select this host player in the table and open host diagnostics'), usernames))
            host_action.triggered.connect(partial(self._select_and_show_current_host_diagnostics, current_session_host.ip))
            self._current_session_submenu.addAction(host_action)
        elif last_host is not None and last_host_left and not SessionHost.is_manually_cleared(current_session_id):
            matched_player = last_host_live or (SessionTracker.get_session_snapshot_player(last_host.session_id, last_host.ip) if last_host.session_id is not None else None)
            fallback_names = last_host.diagnostics.detected_host_usernames if last_host.diagnostics is not None else ()
            usernames = matched_player.usernames if matched_player is not None and matched_player.usernames else fallback_names
            formatted_usernames = format_menu_usernames(usernames)
            host_text = (
                tr('Host: Detected: {ip}  |  {usernames} (Left)', ip=last_host.ip, usernames=formatted_usernames)
                if formatted_usernames
                else tr('Host: Detected: {ip} (Left)', ip=last_host.ip)
            )
            flag_icon = load_country_flag_icon(last_host.country_code) or QIcon(str(ICONS_DIR_PATH / 'crown.svg'))
            host_action = QAction(flag_icon, host_text, self._current_session_submenu)
            host_action.setToolTip(format_player_action_tooltip(tr('Select this host player in the table and open host diagnostics (Host has left the session)'), usernames))
            host_action.triggered.connect(self._create_past_host_action_handler(last_host))
            self._current_session_submenu.addAction(host_action)
            if SessionHost.search_player:
                searching_action = QAction(QIcon(str(ICONS_DIR_PATH / 'crown.svg')), tr('Host: Searching…'), self._current_session_submenu)
                searching_action.setEnabled(False)
                self._current_session_submenu.addAction(searching_action)
        elif SessionHost.search_player:
            searching_action = QAction(QIcon(str(ICONS_DIR_PATH / 'crown.svg')), tr('Host: Searching…'), self._current_session_submenu)
            searching_action.setEnabled(False)
            self._current_session_submenu.addAction(searching_action)
        else:
            no_host_action = QAction(QIcon(str(ICONS_DIR_PATH / 'crown.svg')), tr('Host: No host'), self._current_session_submenu)
            no_host_action.setEnabled(False)
            self._current_session_submenu.addAction(no_host_action)

        host_callbacks = SessionHostActionCallbacks(
            clear_host=self._clear_session_host, redetect_host=self._redetect_session_host, show_diagnostics=self._show_session_host_diagnostics,
        )
        setup_session_host_actions(self._current_session_submenu, host_callbacks)
        self._current_session_submenu.addSeparator()

        connected_count = len([p for p in PlayersRegistry.get_connected_players() if p.session_id in (0, current_session_id) and not p.is_third_party_server])
        disconnected_count = len([p for p in PlayersRegistry.get_disconnected_players() if p.session_id == current_session_id and not p.is_third_party_server])
        player_count = connected_count + disconnected_count

        players_action = QAction(
            QIcon(str(ICONS_DIR_PATH / 'user-round.svg')),
            tr_plural('Players: {count} player', 'Players: {count} players', player_count),
            self._current_session_submenu,
        )
        connected_summary = tr_plural('{count} connected player', '{count} connected players', connected_count)
        disconnected_summary = tr_plural('{count} disconnected player', '{count} disconnected players', disconnected_count)
        players_action.setToolTip(tr('{connected}, {disconnected}', connected=connected_summary, disconnected=disconnected_summary))
        players_action.triggered.connect(partial(self._apply_session_filter, SessionFilterState.FILTER_CURRENT))
        self._current_session_submenu.addAction(players_action)

        now_dt = datetime.now(tz=LOCAL_TZ)
        now_date = now_dt.date()
        start_dt = SessionTracker.get_session_start_time(current_session_id)
        if start_dt is not None:
            elapsed_seconds = max(0.0, (now_dt - start_dt).total_seconds())
            duration_label = format_duration(elapsed_seconds)
            formatted_start = format_session_time_component(start_dt, now_date)
            time_action_text = tr('Time: Started at {time} ({duration})', time=formatted_start, duration=duration_label)
            time_action_tooltip = tr('Session started at {time} (running for {duration})', time=start_dt.strftime('%Y-%m-%d %H:%M:%S'), duration=duration_label)
        else:
            time_action_text = tr('Time: Current session')
            time_action_tooltip = tr('Current active session')

        time_action = QAction(QIcon(str(ICONS_DIR_PATH / 'timer.svg')), time_action_text, self._current_session_submenu)
        time_action.setToolTip(time_action_tooltip)
        time_action.triggered.connect(partial(self._apply_session_filter, SessionFilterState.FILTER_CURRENT))
        self._current_session_submenu.addAction(time_action)
        self._current_session_submenu.addSeparator()

        rename_action = QAction(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), tr("Rename Session '{name}'…", name=display_name), self._current_session_submenu)
        rename_action.setToolTip(tr("Rename Session '{name}'", name=display_name))
        rename_action.triggered.connect(partial(self._prompt_rename_session, current_session_id))
        self._current_session_submenu.addAction(rename_action)

        all_session_ids = SessionTracker.get_all_session_ids()
        has_past_disconnected = len(all_session_ids) > 1 and (
            any(p.session_id < current_session_id and not p.is_third_party_server for p in PlayersRegistry.get_disconnected_players())
            or any(not p.is_third_party_server for p in SessionTracker.get_all_snapshot_players())
        )

        filter_action = QAction(QIcon(str(ICONS_DIR_PATH / 'search.svg')), tr('Filter to this Session'), self._current_session_submenu)
        filter_action.setCheckable(True)
        filter_action.setChecked(is_filter_active)

        if is_filter_active:
            filter_action.setEnabled(True)
            filter_action.setToolTip(tr('Show all sessions (currently filtered to this session)'))
            filter_target = SessionFilterState.FILTER_ALL
        elif len(all_session_ids) <= 1:
            filter_action.setEnabled(False)
            filter_action.setToolTip(tr('Filter to only show players from this session (only one session recorded)'))
            filter_target = SessionFilterState.FILTER_CURRENT
        elif not has_past_disconnected and current_filter == SessionFilterState.FILTER_ALL:
            filter_action.setEnabled(False)
            filter_action.setToolTip(tr('Filter to only show players from this session (no disconnected players from other sessions)'))
            filter_target = SessionFilterState.FILTER_CURRENT
        else:
            filter_action.setEnabled(True)
            filter_action.setToolTip(tr('Filter to only show players from this session'))
            filter_target = SessionFilterState.FILTER_CURRENT

        filter_action.triggered.connect(partial(self._apply_session_filter, filter_target))
        self._current_session_submenu.addAction(filter_action)

    def _update_session_history_menu(self) -> None:
        """Rebuild the Session History submenu with past sessions, host history, and management controls."""
        self._session_history_submenu.clear()
        current_session_id = SessionTracker.get_current_session_id()
        all_session_ids = SessionTracker.get_all_session_ids()
        past_session_ids = [session_id for session_id in all_session_ids if session_id < current_session_id]
        current_filter = SessionFilterState.get_selected_session()
        now_date = datetime.now(tz=LOCAL_TZ).date()

        if not past_session_ids:
            no_past_sessions_action = QAction(tr('(no previous sessions recorded)'), self._session_history_submenu)
            no_past_sessions_action.setEnabled(False)
            self._session_history_submenu.addAction(no_past_sessions_action)
        else:
            for session_id in reversed(past_session_ids):
                display_name = SessionTracker.get_session_display_name(session_id)
                player_count = SessionTracker.get_session_player_count(session_id)
                start_dt = SessionTracker.get_session_start_time(session_id)
                end_dt = SessionTracker.get_session_end_time(session_id)

                duration_label: str | None = None
                if start_dt is not None and end_dt is not None:
                    duration_seconds = max(0.0, (end_dt - start_dt).total_seconds())
                    duration_label = format_duration(duration_seconds)
                    formatted_start = format_session_time_component(start_dt, now_date)
                    formatted_end = format_session_time_component(end_dt, now_date)
                    time_action_text = (
                        tr('Time: {time}', time=formatted_start)
                        if formatted_start == formatted_end
                        else tr('Time: {start} - {end}', start=formatted_start, end=formatted_end)
                    )
                    time_action_tooltip = tr(
                        'Session duration: {duration} ({start} - {end})',
                        duration=duration_label,
                        start=start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                        end=end_dt.strftime('%Y-%m-%d %H:%M:%S'),
                    )
                elif start_dt is not None:
                    formatted_start = format_session_time_component(start_dt, now_date)
                    time_action_text = tr('Time: Started at {time}', time=formatted_start)
                    time_action_tooltip = tr('Session started at {time}', time=start_dt.strftime('%Y-%m-%d %H:%M:%S'))
                elif end_dt is not None:
                    formatted_end = format_session_time_component(end_dt, now_date)
                    time_action_text = tr('Time: Ended at {time}', time=formatted_end)
                    time_action_tooltip = tr('Session ended at {time}', time=end_dt.strftime('%Y-%m-%d %H:%M:%S'))
                else:
                    time_action_text = tr('Time: No time recorded')
                    time_action_tooltip = tr('No timestamps recorded for this session')

                label_parts = [display_name, tr_plural('{count} player', '{count} players', player_count)]
                if duration_label is not None:
                    label_parts.append(duration_label)
                session_label = '  |  '.join(label_parts)
                session_icon = QIcon(str(ICONS_DIR_PATH / 'rotate-ccw-clock.svg'))
                session_menu = self._session_history_submenu.addMenu(session_icon, session_label)
                if not session_menu:
                    continue
                session_menu.setToolTipsVisible(True)
                menu_tooltip = tr_plural('{count} player recorded in {name}', '{count} players recorded in {name}', player_count, name=display_name)
                exact_time_label = SessionTracker.get_session_time_label(session_id)
                if exact_time_label is not None:
                    menu_tooltip = f'{menu_tooltip}  |  {exact_time_label} ({duration_label})' if duration_label is not None else f'{menu_tooltip}  |  {exact_time_label}'
                session_menu.setToolTip(menu_tooltip)
                session_menu.menuAction().setToolTip(menu_tooltip)

                players_action = QAction(QIcon(str(ICONS_DIR_PATH / 'user-round.svg')), tr('Players: {count}', count=player_count), session_menu)
                players_action.setToolTip(tr_plural('{count} player recorded in this session', '{count} players recorded in this session', player_count))
                players_action.triggered.connect(partial(self._apply_session_filter, session_id))

                time_action = QAction(QIcon(str(ICONS_DIR_PATH / 'timer.svg')), time_action_text, session_menu)
                time_action.setToolTip(time_action_tooltip)
                time_action.triggered.connect(partial(self._apply_session_filter, session_id))

                session_history = SessionHost.get_history(session_id=session_id)
                if session_history:
                    last_host = session_history[-1]
                    matched_player = SessionTracker.get_session_snapshot_player(session_id, last_host.ip) or PlayersRegistry.get_player_by_ip(last_host.ip)
                    fallback_names = last_host.diagnostics.detected_host_usernames if last_host.diagnostics is not None else ()
                    usernames = matched_player.usernames if matched_player is not None and matched_player.usernames else fallback_names
                    formatted_usernames = format_menu_usernames(usernames)
                    host_label = (
                        tr('Host: {ip}  |  {usernames}', ip=last_host.ip, usernames=formatted_usernames)
                        if formatted_usernames
                        else tr('Host: {ip}', ip=last_host.ip)
                    )
                    flag_icon = load_country_flag_icon(last_host.country_code) or QIcon(str(ICONS_DIR_PATH / 'crown.svg'))
                    host_action = QAction(flag_icon, host_label, session_menu)
                    host_action.setToolTip(format_player_action_tooltip(tr('Select this host player in the table and open host diagnostics'), usernames))
                    host_action.triggered.connect(self._create_past_host_action_handler(last_host))
                    session_menu.addAction(host_action)
                    session_menu.addAction(players_action)
                    session_menu.addAction(time_action)

                    diagnostics_action = QAction(QIcon(str(ICONS_DIR_PATH / 'bug.svg')), tr('Host Diagnostics…'), session_menu)
                    diagnostics_action.setToolTip(tr('Show diagnostics recorded for this host detection'))
                    diagnostics_action.triggered.connect(partial(self._open_host_history_diagnostics, last_host))
                    session_menu.addSeparator()
                    session_menu.addAction(diagnostics_action)
                else:
                    no_host_action = QAction(QIcon(str(ICONS_DIR_PATH / 'crown.svg')), tr('Host: None recorded'), session_menu)
                    no_host_action.setEnabled(False)
                    session_menu.addAction(no_host_action)
                    session_menu.addAction(players_action)
                    session_menu.addAction(time_action)

                session_menu.addSeparator()
                rename_action = QAction(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), tr("Rename Session '{name}'…", name=display_name), session_menu)
                rename_action.setToolTip(tr("Rename Session '{name}'", name=display_name))
                rename_action.triggered.connect(partial(self._prompt_rename_session, session_id))
                session_menu.addAction(rename_action)

                delete_action = QAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), tr("Delete Session '{name}'…", name=display_name), session_menu)
                delete_action.setToolTip(tr("Delete Session '{name}' and remove its player history", name=display_name))
                delete_action.triggered.connect(partial(self._prompt_delete_session, session_id, display_name))
                session_menu.addAction(delete_action)

                filter_action = QAction(QIcon(str(ICONS_DIR_PATH / 'search.svg')), tr('Filter to this Session'), session_menu)
                filter_action.setCheckable(True)
                is_filter_active_past = current_filter == session_id
                filter_action.setChecked(is_filter_active_past)
                filter_action.setEnabled(True)
                filter_action.setToolTip(
                    tr('Show all sessions (currently filtered to this session)') if is_filter_active_past else tr('Filter to only show players from this session'),
                )
                filter_target = SessionFilterState.FILTER_ALL if is_filter_active_past else session_id
                filter_action.triggered.connect(partial(self._apply_session_filter, filter_target))
                session_menu.addAction(filter_action)

        self._session_history_submenu.addSeparator()
        history_menu = self._session_history_submenu.addMenu(QIcon(str(ICONS_DIR_PATH / 'host_history.svg')), tr('Host History'))
        if history_menu:
            history_menu.setToolTipsVisible(True)
            history_menu.aboutToShow.connect(partial(populate_host_history_submenu, history_menu, self._select_ips, self._open_host_history_diagnostics))

        self._session_history_submenu.addSeparator()
        clear_history_action = QAction(QIcon(str(ICONS_DIR_PATH / 'rotate-ccw.svg')), tr('Clear Past Sessions && History…'), self._session_history_submenu)
        clear_history_action.setToolTip(tr('Clear all past sessions, their player logs, and session host history'))
        clear_history_action.setEnabled(bool(past_session_ids) or bool(SessionHost.get_history()))
        clear_history_action.triggered.connect(self._prompt_clear_past_sessions_and_history)
        self._session_history_submenu.addAction(clear_history_action)

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

    def _prompt_delete_session(self, session_id: int, display_name: str) -> None:
        """Prompt user to delete the specified session and synchronize the session filter."""
        prompt_message = tr("Are you sure you want to delete session '{name}'?\n\nThis will remove the session and its player history permanently.", name=display_name)
        buttons = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        if QMessageBox.question(self, TITLE, prompt_message, buttons, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        removed_ips = {player.ip for player in SessionTracker.delete_session(session_id)}
        SessionHost.prune_history_for_session(session_id)
        if SessionFilterState.get_selected_session() == session_id:
            self._disconnected.set_selected_session_filter(SessionFilterState.FILTER_ALL)
            self._disconnected.clear_table()
        self._refresh_session_gui_state()
        self._cleanup_removed_player_ips(removed_ips, remove_from_connected=True, remove_from_disconnected=True)

    def _prompt_clear_past_sessions_and_history(self) -> None:
        """Prompt user to clear past sessions and host history while preserving the active session."""
        prompt_message = tr(
            'Are you sure you want to clear past sessions and history?\n\n'
            'This will delete all past sessions and clear session host history permanently. Your current active session will not be affected.',
        )
        buttons = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        if QMessageBox.question(self, TITLE, prompt_message, buttons, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        current_session_id = SessionTracker.get_current_session_id()
        past_session_ids = [session_id for session_id in SessionTracker.get_all_session_ids() if session_id < current_session_id]
        removed_ips = {player.ip for session_id in past_session_ids for player in SessionTracker.delete_session(session_id)}
        SessionHost.clear_past_sessions_history(current_session_id)
        if SessionFilterState.get_selected_session() in past_session_ids:
            self._disconnected.set_selected_session_filter(SessionFilterState.FILTER_ALL)
            self._disconnected.clear_table()
        self._refresh_session_gui_state()
        self._cleanup_removed_player_ips(removed_ips, remove_from_connected=True, remove_from_disconnected=True)

    def _apply_session_filter(self, session_id: int) -> None:
        """Apply a session filter and synchronize table controls."""
        self._disconnected.set_selected_session_filter(session_id)

    def _clear_session_host(self) -> None:
        """Manually clear the current session host and reset host detection state."""
        SessionHost.clear_session_host_data(clear_pending_disconnections=False, mark_manually_cleared=True)

    def _open_host_history_diagnostics(self, history_entry: HostHistoryEntry) -> None:
        """Display diagnostic information for a specific host history entry."""
        diagnostics = history_entry.diagnostics
        if diagnostics is None and SessionHost.last_diagnostics is not None and SessionHost.last_diagnostics.detected_host_ip == history_entry.ip:
            diagnostics = SessionHost.last_diagnostics
        if diagnostics is None:
            QMessageBox.information(self, TITLE, tr('No session host detection diagnostics were recorded for host {ip}.', ip=history_entry.ip))
            return
        show_session_host_diagnostics_dialog(self, diagnostics, dialog_key=history_entry.dialog_key)

    def _show_session_host_diagnostics(self) -> None:
        """Display detailed diagnostic information from the last session host detection attempt."""
        diagnostics = SessionHost.last_diagnostics
        if diagnostics is None:
            current_history = SessionHost.get_history(session_id=SessionTracker.get_current_session_id())
            if current_history and current_history[-1].diagnostics is not None:
                diagnostics = current_history[-1].diagnostics
        if diagnostics is None and SessionHost.is_modmenu_lua_source_of_truth() and Settings.gui_session_host_detection and not SessionHost.is_manually_cleared():
            diagnostics = self.redetect_host_from_diagnostics(clear_history=False)
        if diagnostics is None:
            QMessageBox.information(self, TITLE, tr('No session host detection diagnostics are available yet.'))
            return
        show_session_host_diagnostics_dialog(self, diagnostics, redetect_callback=self.redetect_host_from_diagnostics)

    def redetect_host_from_diagnostics(self, *, clear_history: bool = True, show_dialogs: bool = True) -> HostDiagnosticsSnapshot | None:
        """Re-evaluate session host detection in-place for the diagnostics window."""
        if not Settings.is_session_host_feature_set():
            if show_dialogs:
                QMessageBox.warning(self, TITLE, tr('Session Host Detection is not supported for the current game feature set.'))
            return None
        if not Settings.gui_session_host_detection:
            if show_dialogs:
                QMessageBox.warning(self, TITLE, tr('Session Host Detection is disabled in Settings.\n\nPlease enable it in Settings to detect the session host.'))
            return None
        if Settings.is_gta5_feature_set():
            ModMenuLogsParser.refresh()
        current_session_id = SessionTracker.get_current_session_id()
        connected_players = [
            p for p in PlayersRegistry.get_connected_players() if p.session_id in (0, current_session_id) and p not in SessionHost.players_pending_for_disconnection
        ]
        if not connected_players and not SessionHost.is_modmenu_lua_source_of_truth():
            if show_dialogs:
                QMessageBox.information(self, TITLE, tr('No connected players were found in the current session.'))
            return None
        if clear_history:
            SessionHost.clear_session_host_data(clear_pending_disconnections=False, clear_current_session_history=True)
            SessionHost.manual_redetect = True
        SessionHost.get_host_player(connected_players)
        SessionHost.manual_redetect = False
        SessionHost.search_player = False
        SessionHost.search_start_time = None
        return SessionHost.last_diagnostics

    def _redetect_session_host(self) -> None:
        """Clear the current session host and immediately re-evaluate host detection with notification on failure."""
        snapshot = self.redetect_host_from_diagnostics()
        if snapshot is not None:
            self._show_session_host_diagnostics()

    def _redetect_session_host_from_hotkey(self) -> bool:
        """Re-evaluate session host detection from a hotkey, showing dialogs only when the window is active."""
        if self.isActiveWindow():
            self._redetect_session_host()
            return False
        return self.redetect_host_from_diagnostics(show_dialogs=False) is not None
