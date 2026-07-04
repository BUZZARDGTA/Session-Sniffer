"""GTA5 process-control and toolbar-visibility mixin for `MainWindow`."""

from threading import Event
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QMainWindow, QMenu

from session_sniffer import msgbox
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import (
    format_gta5_solo_session_process_not_running_message,
    format_gta5_solo_session_suspend_failed_message,
)
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.logging_setup import get_logger
from session_sniffer.player.registry import SessionHost
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtGui import QAction

    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager

logger = get_logger(__name__)

GTA5_SOLO_TOOLTIP = 'Suspend GTA5 for ~8 seconds then auto-resume.\nThis forces the game to spawn you alone in a public session.'


class GTA5Mixin(QMainWindow):
    """GTA5 process-control and toolbar-visibility mixin for `MainWindow`.

    Expects these attributes on the concrete class (set in `__init__`):
        `_gta5_menu`, `_gta5_process_submenu`, `_gta5_suspend_resume_action`,
        `_gta5_solo_menu_action`, `_manual_gta5_suspend_active`, `_gta5_solo_active`,
        `_gta5_process_suspended`, `_gta5_externally_suspended`, `_gta5_process_detected`,
        `_detections_manager_window`, `_userip_manager_window`
    """

    # -- Attribute stubs for type checkers --
    _gta5_menu: QMenu
    _gta5_process_submenu: QMenu
    _gta5_status_widget_action: QAction
    _gta5_menu_status_separator: QAction
    _gta5_menu_process_separator: QAction
    _looky_submenu: QMenu
    _gta5_suspend_resume_action: QAction
    _gta5_solo_menu_action: QAction
    _manual_gta5_suspend_active: bool
    _gta5_solo_active: bool
    _gta5_process_suspended: bool
    _gta5_externally_suspended: bool
    _gta5_process_detected: bool
    _detections_manager_window: DetectionsManagerDialog | None
    _userip_manager_window: UserIPDatabasesManager | None

    def _gta5_has_any_process_path(self) -> bool:
        """Return `True` if GTA5 is currently running."""
        return CaptureState.gta5_is_running

    def _get_gta5_process_path(self) -> Path | None:
        """Return the path to the running GTA5 executable, or `None` if not running."""
        return CaptureState.gta5_path

    def _gta5_process_is_running(self) -> bool:
        """Return `True` if GTA5 is currently running."""
        return self._get_gta5_process_path() is not None

    def toggle_manual_gta5_suspend(self) -> None:
        """Toggle the manual GTA5 process suspend on or off.

        When the process was left suspended outside this manager (e.g. by a prior
        crashed session): resumes it so the toolbar can recover the orphaned process.
        When not suspended: registers a `'manual:toolbar'` reason in `GTASuspendManager`
        with `'Manual'` duration so it never auto-clears.
        When already suspended: releases the `'manual:toolbar'` reason.
        Auto-protection reasons are unaffected and may also independently keep the process suspended.
        """
        self._sync_gta5_process_button()
        if self._gta5_externally_suspended:
            logger.info('Resuming GTA5 process that was left suspended outside this app')
            GTASuspendManager.resume_os_suspended()
            self._sync_gta5_process_button()
            return
        if self._manual_gta5_suspend_active:
            GTASuspendManager.release_reason_global('manual:toolbar')
        else:
            if not self._gta5_process_is_running():
                logger.warning('Manual GTA5 suspend: GTA5 process is not running')
                return
            if GTASuspendManager.is_suspended():
                logger.info('Manual GTA5 suspend: process is already suspended by another protection reason')
                self._sync_gta5_process_button()
                return
            GTASuspendManager.request_suspend(
                reason_key='manual:toolbar',
                left_event=Event(),
                duration='Manual',
            )
        self._sync_gta5_process_button()

    def gta5_solo_session(self) -> None:
        """Suspend GTA5 for ~8 seconds then auto-resume, forcing a solo public session."""
        self._sync_gta5_process_button()
        if not self._gta5_process_is_running():
            logger.warning('GTA5 solo session: GTA5 process is not running')
            msgbox.show(
                title=TITLE,
                text=format_gta5_solo_session_process_not_running_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        if self._gta5_externally_suspended:
            logger.info('GTA5 solo session: process is already suspended outside this app')
            self._sync_gta5_process_button()
            return
        if GTASuspendManager.is_suspended():
            logger.info('GTA5 solo session: process is already suspended')
            self._sync_gta5_process_button()
            return
        already_left = Event()
        already_left.set()
        GTASuspendManager.request_suspend(
            reason_key='solo:toolbar',
            left_event=already_left,
            duration=8,
        )
        if not GTASuspendManager.has_reason('solo:toolbar'):
            logger.warning('GTA5 solo session: suspend failed')
            msgbox.show(
                title=TITLE,
                text=format_gta5_solo_session_suspend_failed_message(),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
            )
            return
        self._gta5_solo_active = True
        self._sync_gta5_process_button()

    def _refresh_gta5_process_state(self) -> None:
        """Refresh GTA5 process-control flags from the lock-free suspend snapshot and cached state.

        Every value read here comes from an atomic snapshot the background suspend threads
        publish (the suspend/manual/solo flags) or from `CaptureState` ClassVars the GTA5
        process monitor refreshes (running/suspended). The GUI thread therefore never
        acquires the suspend-manager lock nor scans any process, adding zero latency.
        """
        suspend_snapshot = GTASuspendManager.snapshot()
        self._manual_gta5_suspend_active = suspend_snapshot.manual_active
        self._gta5_solo_active = suspend_snapshot.solo_active

        can_act = self._gta5_has_any_process_path() and CaptureState.is_local_capture()
        self._gta5_process_detected = can_act and self._gta5_process_is_running()

        self._gta5_process_suspended = can_act and suspend_snapshot.is_suspended
        self._gta5_externally_suspended = can_act and not suspend_snapshot.is_suspended and CaptureState.gta5_is_suspended

    def _sync_gta5_process_button(self) -> None:
        """Update the GTA5 Process submenu title and menu-item enabled states."""
        self._refresh_gta5_process_state()
        can_act = self._gta5_has_any_process_path() and CaptureState.is_local_capture()
        self._gta5_process_submenu.setEnabled(can_act)
        if not can_act:
            if self._manual_gta5_suspend_active:
                GTASuspendManager.release_reason_global('manual:toolbar')
                self._manual_gta5_suspend_active = False
            if self._gta5_solo_active:
                GTASuspendManager.release_reason_global('solo:toolbar')
                self._gta5_solo_active = False
            self._gta5_process_suspended = False
            self._gta5_externally_suspended = False
            self._gta5_process_submenu.setTitle('🎮 GTA5 Process')
            self._gta5_suspend_resume_action.setText('⏸️ Suspend Process')
            self._gta5_suspend_resume_action.setEnabled(False)
            self._gta5_solo_menu_action.setEnabled(False)
            self._gta5_suspend_resume_action.setToolTip(
                'External capture mode — process control not available.'
                if not CaptureState.is_local_capture()
                else 'GTA5 is not currently running — launch GTA5 to enable process control.',
            )
        elif self._manual_gta5_suspend_active:
            self._gta5_process_submenu.setTitle('⏸️ GTA5 Process (Suspended)')
            self._gta5_suspend_resume_action.setText('▶️ Resume Process')
            self._gta5_suspend_resume_action.setToolTip('Remove the manual suspend hold from the GTA5 process')
            self._gta5_suspend_resume_action.setEnabled(True)
            self._gta5_solo_menu_action.setEnabled(False)
        elif self._gta5_solo_active:
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
        elif self._gta5_externally_suspended:
            self._gta5_process_submenu.setTitle('⏸️ GTA5 Process (Suspended)')
            self._gta5_suspend_resume_action.setText('▶️ Resume Process')
            self._gta5_suspend_resume_action.setEnabled(True)
            self._gta5_solo_menu_action.setEnabled(False)
            self._gta5_suspend_resume_action.setToolTip('GTA5 was left suspended outside this app — click to resume it')
            self._gta5_solo_menu_action.setToolTip('Process is currently suspended — resume it first')
        else:
            self._gta5_process_submenu.setTitle('🎮 GTA5 Process')
            self._gta5_suspend_resume_action.setText('⏸️ Suspend Process')
            if self._gta5_process_detected:
                self._gta5_suspend_resume_action.setEnabled(True)
                self._gta5_solo_menu_action.setEnabled(True)
                self._gta5_suspend_resume_action.setToolTip('Manually suspend the GTA5 process — click again to resume')
                self._gta5_solo_menu_action.setToolTip(GTA5_SOLO_TOOLTIP)
            else:
                self._gta5_suspend_resume_action.setEnabled(False)
                self._gta5_solo_menu_action.setEnabled(False)
                self._gta5_suspend_resume_action.setToolTip('GTA5 is not currently running')
                self._gta5_solo_menu_action.setToolTip('GTA5 is not currently running')

    def _refresh_runtime_capability_windows(self) -> None:
        """Refresh open dialogs that gate controls by feature set / interface support."""
        if self._userip_manager_window is not None and self._userip_manager_window.isVisible():
            self._userip_manager_window.refresh_runtime_capabilities()

        if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
            self._detections_manager_window.refresh_detection_availability()

    def _update_gta5_toolbar_visibility(self) -> None:
        """Show or hide the GTA5 menu (and process-bound items inside it) based on feature set and capture mode."""
        gta5_feature_set = Settings.is_gta5_feature_set()
        SessionHost.clear_session_host_data()
        gta5_menu_action = self._gta5_menu.menuAction()
        if gta5_menu_action is not None:
            gta5_menu_action.setVisible(gta5_feature_set)

        # Hide local-process-bound items when capturing traffic from another machine.
        local_only_visible = gta5_feature_set and CaptureState.is_local_capture()
        self._gta5_status_widget_action.setVisible(local_only_visible)
        self._gta5_menu_status_separator.setVisible(local_only_visible)
        looky_action = self._looky_submenu.menuAction()
        if looky_action is not None:
            looky_action.setVisible(local_only_visible)
        self._gta5_menu_process_separator.setVisible(local_only_visible)
        process_action = self._gta5_process_submenu.menuAction()
        if process_action is not None:
            process_action.setVisible(local_only_visible)

        self._refresh_runtime_capability_windows()
