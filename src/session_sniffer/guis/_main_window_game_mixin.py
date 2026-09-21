"""Game process-control, session-host, and player-resolver mixin for `MainWindow`."""

import logging
from threading import Event
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont, QFontMetrics, QIcon
from PySide6.QtWidgets import QLabel, QMainWindow, QMenu, QMenuBar, QWidgetAction

from session_sniffer import msgbox
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import (
    format_game_solo_session_process_not_running_message,
    format_game_solo_session_suspend_failed_message,
)
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.session_host_history_window import setup_session_host_actions
from session_sniffer.guis.stylesheets import GTA5_STATUS_LABEL_STYLESHEET
from session_sniffer.player.registry import SessionHost
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager

logger = logging.getLogger(__name__)


def format_game_solo_action_text() -> str:
    """Return the label for the solo public session action."""
    return f'Solo Public Session ({Settings.solo_session_duration}s)'


def format_game_solo_tooltip(game_label: str) -> str:
    """Return the tooltip text for the solo public session action."""
    return (
        f'Suspend {game_label} for {Settings.solo_session_duration} seconds then auto-resume.\n'
        'This forces the game to spawn you alone in a public session.'
    )


class GameMixin(QMainWindow):
    """Game process-control, session-host, and player-resolver mixin for `MainWindow`."""

    _game_menu: QMenu
    _game_status_label: QLabel
    _game_status_widget_action: QAction
    _game_menu_status_separator: QAction
    _player_resolver_action: QAction
    _looky_submenu: QMenu
    _game_menu_gta5_separator: QAction
    _session_host_submenu: QMenu
    _host_status_action: QAction
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

    if TYPE_CHECKING:
        _update_looky_actions: Callable[[], None]
        _build_looky_submenu: Callable[[QMenu], None]
        _select_connected_ips: Callable[[list[str]], None]
        _clear_session_host: Callable[[], None]
        _redetect_session_host: Callable[[], None]
        _open_player_resolver: Callable[[], None]
        _detections_manager_window: DetectionsManagerDialog | None
        _userip_manager_window: UserIPDatabasesManager | None

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

        # Shared: Session Host submenu
        session_host_submenu = game_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')), 'Session Host')
        if not session_host_submenu:
            message = 'Failed to create Session Host submenu'
            raise RuntimeError(message)
        session_host_submenu.setToolTipsVisible(True)
        session_host_submenu.menuAction().setToolTip('Session host detection controls for the current lobby')
        self._session_host_submenu = session_host_submenu

        host_status_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'No host', self)
        host_status_action.setEnabled(False)
        host_status_action.setToolTip('Current session host detection state')
        session_host_submenu.addAction(host_status_action)
        self._host_status_action = host_status_action

        def _update_host_status_label() -> None:
            current_session_host = SessionHost.get_player()
            if current_session_host is not None:
                self._host_status_action.setText(f'Detected: {current_session_host.ip}')
            elif SessionHost.search_player:
                self._host_status_action.setText('Searching…')
            else:
                self._host_status_action.setText('No host')

        session_host_submenu.aboutToShow.connect(_update_host_status_label)
        setup_session_host_actions(session_host_submenu, self._clear_session_host, self._redetect_session_host, self._select_connected_ips)

        self._game_menu_process_separator = game_menu.addSeparator()

        # Shared: Game Process submenu
        game_process_submenu = game_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')), 'GTA5 Process')
        if not game_process_submenu:
            message = 'Failed to create Game Process submenu'
            raise RuntimeError(message)
        game_process_submenu.setToolTipsVisible(True)
        game_process_submenu.menuAction().setToolTip('Game process controls — suspend/resume for solo and public session manipulation')
        self._game_process_submenu = game_process_submenu

        game_solo_menu_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user.svg')), format_game_solo_action_text(), self)
        game_solo_menu_action.setToolTip(format_game_solo_tooltip(self._active_game_process_name()))
        game_solo_menu_action.triggered.connect(self.game_solo_session)
        game_process_submenu.addAction(game_solo_menu_action)

        game_process_submenu.addSeparator()

        game_suspend_resume_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')), 'Suspend Process', self)
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
            self._game_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')))
            self._game_suspend_resume_action.setText('Suspend Process')
            self._game_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(
                'External capture mode — process control not available.'
                if not CaptureState.is_local_capture()
                else f'{game_label} is not currently running — launch {game_label} to enable process control.',
            )
        elif self._manual_game_suspend_active:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Suspended)')
            self._game_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._game_suspend_resume_action.setText('Resume Process')
            self._game_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._game_suspend_resume_action.setToolTip(f'Remove the manual suspend hold from the {game_label} process')
            self._game_suspend_resume_action.setEnabled(True)
            self._game_solo_menu_action.setEnabled(False)
        elif self._game_solo_active:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Going Solo...)')
            self._game_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user.svg')))
            self._game_suspend_resume_action.setText('Suspend Process')
            self._game_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
        elif self._game_process_suspended:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Suspended)')
            self._game_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._game_suspend_resume_action.setText('Resume Process')
            self._game_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._game_suspend_resume_action.setEnabled(False)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(
                'Process is currently suspended by active protection rules. It will resume automatically when those rules clear.',
            )
            self._game_solo_menu_action.setToolTip('Process is already suspended')
        elif self._game_externally_suspended:
            self._game_process_submenu.setTitle(f'{process_menu_title} (Suspended)')
            self._game_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._game_suspend_resume_action.setText('Resume Process')
            self._game_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._game_suspend_resume_action.setEnabled(True)
            self._game_solo_menu_action.setEnabled(False)
            self._game_suspend_resume_action.setToolTip(f'{game_label} was left suspended outside this app — click to resume it')
            self._game_solo_menu_action.setToolTip('Process is currently suspended — resume it first')
        else:
            self._game_process_submenu.setTitle(process_menu_title)
            self._game_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')))
            self._game_suspend_resume_action.setText('Suspend Process')
            self._game_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
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
                self._game_status_label.setToolTip(f'{path_tooltip}\
Process is currently suspended')
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
            self._session_host_submenu.setEnabled(can_interact)
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
        self._game_process_submenu.menuAction().setToolTip(
            f'{self._active_game_process_name()} process controls — suspend/resume for solo and public session manipulation'
        )
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
        self._session_host_submenu.setEnabled(can_interact)
        self._player_resolver_action.setEnabled(can_interact)

        if is_gta5:
            self._update_looky_actions()
            self._refresh_runtime_capability_windows()

        self._update_game_status_label()
        self._sync_game_process_button()
