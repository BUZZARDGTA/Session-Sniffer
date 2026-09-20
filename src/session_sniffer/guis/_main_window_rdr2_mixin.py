"""RDR2 process-control, session-host, and player-resolver mixin for `MainWindow`."""

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
    format_rdr2_solo_session_process_not_running_message,
    format_rdr2_solo_session_suspend_failed_message,
)
from session_sniffer.guis.session_host_history_window import setup_session_host_actions
from session_sniffer.guis.stylesheets import GTA5_STATUS_LABEL_STYLESHEET
from session_sniffer.player.registry import SessionHost
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = logging.getLogger(__name__)

RDR2_SOLO_TOOLTIP = 'Suspend RDR2 for ~8 seconds then auto-resume.\nThis forces the game to spawn you alone in a public session.'


class RDR2Mixin(QMainWindow):
    """RDR2 process-control, session-host, and player-resolver mixin for `MainWindow`."""

    _rdr2_menu: QMenu
    _rdr2_status_label: QLabel
    _rdr2_status_widget_action: QAction
    _rdr2_menu_status_separator: QAction
    _rdr2_player_resolver_action: QAction
    _rdr2_session_host_submenu: QMenu
    _rdr2_host_status_action: QAction
    _rdr2_menu_process_separator: QAction
    _rdr2_process_submenu: QMenu
    _rdr2_suspend_resume_action: QAction
    _rdr2_solo_menu_action: QAction
    _manual_rdr2_suspend_active: bool
    _rdr2_solo_active: bool
    _rdr2_process_suspended: bool
    _rdr2_externally_suspended: bool
    _rdr2_process_detected: bool
    _last_rdr2_status_key: tuple[bool, bool, bool]

    if TYPE_CHECKING:
        _highlight_ips: Callable[[list[str]], None]
        _clear_session_host: Callable[[], None]
        _redetect_session_host: Callable[[], None]
        _open_player_resolver: Callable[[], None]

    def _build_rdr2_menu(self, menu_bar: QMenuBar) -> None:
        """Construct the RDR2 menu and its submenus."""
        rdr2_menu = menu_bar.addMenu('RDR2')
        if not rdr2_menu:
            message = 'Failed to create RDR2 menu'
            raise RuntimeError(message)
        rdr2_menu.setToolTipsVisible(True)
        rdr2_menu_action = rdr2_menu.menuAction()
        if not rdr2_menu_action:
            message = 'Failed to get RDR2 menu action'
            raise RuntimeError(message)
        rdr2_menu_action.setVisible(Settings.is_rdr2_feature_set())
        self._rdr2_menu = rdr2_menu

        rdr2_status_label = QLabel()
        rdr2_status_label.setTextFormat(Qt.TextFormat.RichText)
        rdr2_status_label.setStyleSheet(GTA5_STATUS_LABEL_STYLESHEET)
        rdr2_status_label.setText('<span style="color: #f44336;">●</span> RDR2 not running')
        rdr2_status_label.setToolTip('RDR2 process detection state')
        rdr2_status_widget_action = QWidgetAction(self)
        rdr2_status_widget_action.setDefaultWidget(rdr2_status_label)
        rdr2_menu.addAction(rdr2_status_widget_action)
        self._rdr2_status_label = rdr2_status_label
        self._rdr2_status_widget_action = rdr2_status_widget_action
        self._resize_rdr2_status_label('● RDR2 not running')

        rdr2_menu.aboutToShow.connect(self._update_rdr2_status_label)
        self._rdr2_menu_status_separator = rdr2_menu.addSeparator()

        player_resolver_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')), 'Player Resolver', self)
        player_resolver_action.setToolTip('Find the exact IP of a player in your current RDR2 session.')
        player_resolver_action.triggered.connect(self._open_player_resolver)
        rdr2_menu.addAction(player_resolver_action)
        self._rdr2_player_resolver_action = player_resolver_action

        rdr2_menu.addSeparator()

        session_host_submenu = rdr2_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'crown.svg')), 'Session Host')
        if not session_host_submenu:
            message = 'Failed to create RDR2 Session Host submenu'
            raise RuntimeError(message)
        session_host_submenu.setToolTipsVisible(True)
        session_host_submenu.menuAction().setToolTip('Session host detection controls for the current RDR2 lobby')
        self._rdr2_session_host_submenu = session_host_submenu

        host_status_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'No host', self)
        host_status_action.setEnabled(False)
        host_status_action.setToolTip('Current session host detection state')
        session_host_submenu.addAction(host_status_action)
        self._rdr2_host_status_action = host_status_action

        def _update_rdr2_host_status_label() -> None:
            current_session_host = SessionHost.get_player()
            if current_session_host is not None:
                self._rdr2_host_status_action.setText(f'Detected: {current_session_host.ip}')
            elif SessionHost.search_player:
                self._rdr2_host_status_action.setText('Searching…')
            else:
                self._rdr2_host_status_action.setText('No host')

        session_host_submenu.aboutToShow.connect(_update_rdr2_host_status_label)
        setup_session_host_actions(session_host_submenu, self._clear_session_host, self._redetect_session_host, self._highlight_ips, error_label='RDR2 Host History')

        self._rdr2_menu_process_separator = rdr2_menu.addSeparator()

        rdr2_process_submenu = rdr2_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')), 'RDR2 Process')
        if not rdr2_process_submenu:
            message = 'Failed to create RDR2 Process submenu'
            raise RuntimeError(message)
        rdr2_process_submenu.setToolTipsVisible(True)
        rdr2_process_submenu.menuAction().setToolTip('RDR2 process controls — suspend/resume for solo and public session manipulation')
        self._rdr2_process_submenu = rdr2_process_submenu

        rdr2_solo_menu_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user.svg')), 'Solo Public Session (~8s)', self)
        rdr2_solo_menu_action.setToolTip(RDR2_SOLO_TOOLTIP)
        rdr2_solo_menu_action.triggered.connect(self.rdr2_solo_session)
        rdr2_process_submenu.addAction(rdr2_solo_menu_action)

        rdr2_process_submenu.addSeparator()

        rdr2_suspend_resume_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')), 'Suspend Process', self)
        rdr2_suspend_resume_action.setToolTip('Manually suspend the RDR2 process — stays suspended until you click it again to resume')
        rdr2_suspend_resume_action.triggered.connect(self.toggle_manual_rdr2_suspend)
        rdr2_process_submenu.addAction(rdr2_suspend_resume_action)

        rdr2_process_submenu.aboutToShow.connect(self._sync_rdr2_process_button)

        self._rdr2_solo_menu_action = rdr2_solo_menu_action
        self._rdr2_suspend_resume_action = rdr2_suspend_resume_action
        self._manual_rdr2_suspend_active = False
        self._rdr2_solo_active = False
        self._rdr2_process_suspended = False
        self._rdr2_externally_suspended = False
        self._rdr2_process_detected = False
        self._last_rdr2_status_key = (False, False, False)

    def _rdr2_has_any_process_path(self) -> bool:
        """Return `True` if RDR2 is currently running."""
        return CaptureState.rdr2_is_running

    def _get_rdr2_process_path(self) -> Path | None:
        """Return the path to the running RDR2 executable, or `None` if not running."""
        return CaptureState.rdr2_path

    def _rdr2_process_is_running(self) -> bool:
        """Return `True` if RDR2 is currently running."""
        return self._get_rdr2_process_path() is not None

    def toggle_manual_rdr2_suspend(self) -> None:
        """Toggle the manual RDR2 process suspend on or off."""
        self._sync_rdr2_process_button()
        if self._rdr2_externally_suspended:
            logger.info('Resuming RDR2 process that was left suspended outside this app')
            RDR2SuspendManager.resume_os_suspended()
            self._sync_rdr2_process_button()
            return
        if self._manual_rdr2_suspend_active:
            RDR2SuspendManager.release_reason_global('manual:toolbar')
        else:
            if not self._rdr2_process_is_running():
                logger.warning('Manual RDR2 suspend: RDR2 process is not running')
                return
            if RDR2SuspendManager.is_suspended():
                logger.info('Manual RDR2 suspend: process is already suspended by another protection reason')
                self._sync_rdr2_process_button()
                return
            RDR2SuspendManager.request_suspend(
                reason_key='manual:toolbar',
                left_event=Event(),
                duration='Manual',
            )
        self._sync_rdr2_process_button()

    def rdr2_solo_session(self) -> None:
        """Suspend RDR2 for ~8 seconds then auto-resume, forcing a solo public session."""
        self._sync_rdr2_process_button()
        if not self._rdr2_process_is_running():
            logger.warning('RDR2 solo session: RDR2 process is not running')
            msgbox.show(
                title=TITLE,
                text=format_rdr2_solo_session_process_not_running_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        if self._rdr2_externally_suspended:
            logger.info('RDR2 solo session: process is already suspended outside this app')
            self._sync_rdr2_process_button()
            return
        if RDR2SuspendManager.is_suspended():
            logger.info('RDR2 solo session: process is already suspended')
            self._sync_rdr2_process_button()
            return
        already_left = Event()
        already_left.set()
        RDR2SuspendManager.request_suspend(
            reason_key='solo:toolbar',
            left_event=already_left,
            duration=8,
        )
        if not RDR2SuspendManager.has_reason('solo:toolbar'):
            logger.warning('RDR2 solo session: suspend failed')
            msgbox.show(
                title=TITLE,
                text=format_rdr2_solo_session_suspend_failed_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        self._rdr2_solo_active = True
        self._sync_rdr2_process_button()

    def _refresh_rdr2_process_state(self) -> None:
        """Refresh RDR2 process-control flags from the lock-free suspend snapshot and cached state."""
        suspend_snapshot = RDR2SuspendManager.snapshot()
        self._manual_rdr2_suspend_active = suspend_snapshot.manual_active
        self._rdr2_solo_active = suspend_snapshot.solo_active

        can_act = self._rdr2_has_any_process_path() and CaptureState.is_local_capture()
        self._rdr2_process_detected = can_act and self._rdr2_process_is_running()

        self._rdr2_process_suspended = can_act and suspend_snapshot.is_suspended
        self._rdr2_externally_suspended = can_act and not suspend_snapshot.is_suspended and CaptureState.rdr2_is_suspended

    def _sync_rdr2_process_button(self) -> None:
        """Update the RDR2 Process submenu title and menu-item enabled states."""
        self._refresh_rdr2_process_state()
        can_act = self._rdr2_has_any_process_path() and CaptureState.is_local_capture()
        self._rdr2_process_submenu.setEnabled(can_act)
        if not can_act:
            if self._manual_rdr2_suspend_active:
                RDR2SuspendManager.release_reason_global('manual:toolbar')
                self._manual_rdr2_suspend_active = False
            if self._rdr2_solo_active:
                RDR2SuspendManager.release_reason_global('solo:toolbar')
                self._rdr2_solo_active = False
            self._rdr2_process_suspended = False
            self._rdr2_externally_suspended = False
            self._rdr2_process_submenu.setTitle('RDR2 Process')
            self._rdr2_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')))
            self._rdr2_suspend_resume_action.setText('Suspend Process')
            self._rdr2_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._rdr2_suspend_resume_action.setEnabled(False)
            self._rdr2_solo_menu_action.setEnabled(False)
            self._rdr2_suspend_resume_action.setToolTip(
                'External capture mode — process control not available.'
                if not CaptureState.is_local_capture()
                else 'RDR2 is not currently running — launch RDR2 to enable process control.',
            )
        elif self._manual_rdr2_suspend_active:
            self._rdr2_process_submenu.setTitle('RDR2 Process (Suspended)')
            self._rdr2_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._rdr2_suspend_resume_action.setText('Resume Process')
            self._rdr2_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._rdr2_suspend_resume_action.setToolTip('Remove the manual suspend hold from the RDR2 process')
            self._rdr2_suspend_resume_action.setEnabled(True)
            self._rdr2_solo_menu_action.setEnabled(False)
        elif self._rdr2_solo_active:
            self._rdr2_process_submenu.setTitle('RDR2 Process (Going Solo...)')
            self._rdr2_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user.svg')))
            self._rdr2_suspend_resume_action.setText('Suspend Process')
            self._rdr2_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._rdr2_suspend_resume_action.setEnabled(False)
            self._rdr2_solo_menu_action.setEnabled(False)
        elif self._rdr2_process_suspended:
            self._rdr2_process_submenu.setTitle('RDR2 Process (Suspended)')
            self._rdr2_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._rdr2_suspend_resume_action.setText('Resume Process')
            self._rdr2_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._rdr2_suspend_resume_action.setEnabled(False)
            self._rdr2_solo_menu_action.setEnabled(False)
            self._rdr2_suspend_resume_action.setToolTip(
                'Process is currently suspended by active protection rules. It will resume automatically when those rules clear.',
            )
            self._rdr2_solo_menu_action.setToolTip('Process is already suspended')
        elif self._rdr2_externally_suspended:
            self._rdr2_process_submenu.setTitle('RDR2 Process (Suspended)')
            self._rdr2_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            self._rdr2_suspend_resume_action.setText('Resume Process')
            self._rdr2_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._rdr2_suspend_resume_action.setEnabled(True)
            self._rdr2_solo_menu_action.setEnabled(False)
            self._rdr2_suspend_resume_action.setToolTip('RDR2 was left suspended outside this app — click to resume it')
            self._rdr2_solo_menu_action.setToolTip('Process is currently suspended — resume it first')
        else:
            self._rdr2_process_submenu.setTitle('RDR2 Process')
            self._rdr2_process_submenu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')))
            self._rdr2_suspend_resume_action.setText('Suspend Process')
            self._rdr2_suspend_resume_action.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'pause.svg')))
            if self._rdr2_process_detected:
                self._rdr2_suspend_resume_action.setEnabled(True)
                self._rdr2_solo_menu_action.setEnabled(True)
                self._rdr2_suspend_resume_action.setToolTip('Manually suspend the RDR2 process — click again to resume')
                self._rdr2_solo_menu_action.setToolTip(RDR2_SOLO_TOOLTIP)
            else:
                self._rdr2_suspend_resume_action.setEnabled(False)
                self._rdr2_solo_menu_action.setEnabled(False)
                self._rdr2_suspend_resume_action.setToolTip('RDR2 is not currently running')
                self._rdr2_solo_menu_action.setToolTip('RDR2 is not currently running')

    def _resize_rdr2_status_label(self, visible_text: str) -> None:
        """Resize the RDR2 status label to fit `visible_text`."""
        status_font = QFont(self._rdr2_status_label.font())
        status_font.setPointSize(10)
        self._rdr2_status_label.setMinimumWidth(QFontMetrics(status_font).horizontalAdvance(visible_text) + 44 + 12)

    def _update_rdr2_status_label(self) -> None:
        """Refresh the RDR2 status label and tooltip from cached `CaptureState` values."""
        if CaptureState.rdr2_is_running:
            path_tooltip = str(CaptureState.rdr2_path) if CaptureState.rdr2_path is not None else 'RDR2 process detection state'
            if CaptureState.rdr2_is_suspended:
                visible_text = 'RDR2 (Suspended)'
                self._rdr2_status_label.setText(f'<span style="color: #ff9800;">●</span> {visible_text}')
                self._rdr2_status_label.setToolTip(f'{path_tooltip}\nProcess is currently suspended')
            else:
                visible_text = 'RDR2'
                self._rdr2_status_label.setText(f'<span style="color: #4caf50;">●</span> {visible_text}')
                self._rdr2_status_label.setToolTip(path_tooltip)
        else:
            visible_text = 'RDR2 not running'
            self._rdr2_status_label.setText('<span style="color: #f44336;">●</span> RDR2 not running')
            self._rdr2_status_label.setToolTip('RDR2 process detection state')
        self._resize_rdr2_status_label(f'● {visible_text}')
        self._last_rdr2_status_key = (
            CaptureState.rdr2_is_running,
            CaptureState.rdr2_is_suspended,
            CaptureState.is_local_capture(),
        )

    def _sync_rdr2_status(self) -> None:
        """Update RDR2 status label and actions if process status changed."""
        rdr2_status_key = (
            CaptureState.rdr2_is_running,
            CaptureState.rdr2_is_suspended,
            CaptureState.is_local_capture(),
        )
        if rdr2_status_key != self._last_rdr2_status_key:
            self._update_rdr2_status_label()
            self._rdr2_session_host_submenu.setEnabled(CaptureState.rdr2_is_running or not CaptureState.is_local_capture())
            self._rdr2_player_resolver_action.setEnabled(CaptureState.rdr2_is_running or not CaptureState.is_local_capture())
            self._sync_rdr2_process_button()
