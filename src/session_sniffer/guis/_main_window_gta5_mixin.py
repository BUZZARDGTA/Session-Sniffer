"""GTA5 process-control and toolbar-visibility mixin for `MainWindow`."""

import time
from datetime import datetime
from http import HTTPStatus
from threading import Event
from typing import TYPE_CHECKING, cast

import requests
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout

from session_sniffer import msgbox
from session_sniffer.background.suspend_manager import ProcessSuspendManager
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import (
    format_gta5_solo_session_process_not_running_message,
    format_gta5_solo_session_suspend_failed_message,
)
from session_sniffer.guis.stylesheets import CRAWLER_TARGET_INFO_LABEL_STYLESHEET
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.looky import (
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    send_crawler_instruction,
    send_crawlme_instruction,
    watch_instruction_status,
)
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import find_running_gta5_path

if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtGui import QAction, QCloseEvent

    from session_sniffer.guis.detections_manager import DetectionsManagerDialog
    from session_sniffer.guis.userip_manager import UserIPDatabasesManager
    from session_sniffer.models.player import Player

logger = get_logger(__name__)


class _CrawlerProgressDialog(QDialog):
    """Non-modal dialog that shows live Looky crawler progress."""

    def __init__(self, parent: QMainWindow, target_info: str) -> None:
        """Initialize the crawler progress dialog."""
        super().__init__(parent)
        self._running = True

        self.setWindowTitle('Looky Crawler Progress')
        self.setMinimumWidth(440)
        self.setMinimumHeight(300)
        self.setModal(False)

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        info_label = QLabel(target_info)
        info_label.setWordWrap(True)
        info_label.setTextFormat(Qt.TextFormat.RichText)
        info_label.setStyleSheet(CRAWLER_TARGET_INFO_LABEL_STYLESHEET)
        layout.addWidget(info_label)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        layout.addWidget(self._log)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # indeterminate/busy
        self._progress_bar.setTextVisible(False)
        layout.addWidget(self._progress_bar)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.try_again_btn = QPushButton('🔄 Try Again')
        self.try_again_btn.hide()
        btn_layout.addWidget(self.try_again_btn)
        self._close_btn = QPushButton('Close')
        self._close_btn.setEnabled(False)
        self._close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self._close_btn)
        layout.addLayout(btn_layout)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802
        """Block the window close while the crawler is still running."""
        if self._running:
            if a0 is not None:
                a0.ignore()
        else:
            super().closeEvent(a0)

    def append_step(self, status_text: str) -> None:
        """Append a timestamped status line to the log."""
        ts = datetime.now().strftime('%H:%M:%S')  # noqa: DTZ005
        self._log.appendPlainText(f'[{ts}]  {status_text}')

    def append_separator(self, text: str) -> None:
        """Append an untimstamped separator line surrounded by blank lines."""
        self._log.appendPlainText('')
        self._log.appendPlainText(text)
        self._log.appendPlainText('')

    def finish(self, message: str, is_warning: bool) -> None:  # noqa: FBT001
        """Mark the crawler as done, display the final message, and enable the Close button."""
        self._running = False
        self._progress_bar.hide()
        ts = datetime.now().strftime('%H:%M:%S')  # noqa: DTZ005
        prefix = '\u26a0' if is_warning else '\u2713'
        self._log.appendPlainText(f'[{ts}]  {prefix}  {message}')
        if is_warning:
            self.try_again_btn.show()
        self._close_btn.setEnabled(True)

    def reset(self) -> None:
        """Reset the dialog to its initial busy state for a retry attempt."""
        self._running = True
        self._log.clear()
        self._progress_bar.show()
        self.try_again_btn.hide()
        self._close_btn.setEnabled(False)


class _CrawlerWorker(QThread):
    """Background thread that fetches a Looky RID, sends a crawler instruction, and tracks it to completion."""

    result_ready: pyqtSignal = pyqtSignal(str, bool)  # message, is_warning
    status_update: pyqtSignal = pyqtSignal(str)        # status text for the menu action label

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self._api_key = api_key

    def run(self) -> None:
        """Send a crawlme instruction and track it to completion via SSE."""
        try:
            tracking_id = send_crawlme_instruction(self._api_key)
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                self.result_ready.emit(f'Rate limited (429) — {extract_rate_limit_message(exc)}', True)  # noqa: FBT003
            else:
                self.result_ready.emit(f'Crawler request failed:\n\n{exc}', True)  # noqa: FBT003
            return
        except (requests.RequestException, KeyError) as exc:
            self.result_ready.emit(f'Crawler request failed:\n\n{exc}', True)  # noqa: FBT003
            return

        seen_status_texts: set[str] = set()
        try:
            for status, result in watch_instruction_status(tracking_id, self._api_key):
                status_text = result or status
                if status_text not in seen_status_texts:
                    self.status_update.emit(status_text)
                    seen_status_texts.add(status_text)
        except requests.RequestException as exc:
            self.result_ready.emit(f'Lost connection while tracking crawler:\n\n{exc}', True)  # noqa: FBT003
            return

        for player in PlayersRegistry.get_default_sorted_players():
            if player.looky.is_initialized:
                player.looky.needs_refresh = True

        self.result_ready.emit('Crawler completed successfully.', False)  # noqa: FBT003


class _PlayerCrawlerWorker(QThread):
    """Background thread that sends per-RID crawler instructions and tracks them to completion via SSE."""

    result_ready: pyqtSignal = pyqtSignal(str, bool)  # message, is_warning
    status_update: pyqtSignal = pyqtSignal(str)        # timestamped step for the progress dialog
    separator_update: pyqtSignal = pyqtSignal(str)     # untimstamped separator line for the progress dialog

    def __init__(self, rockstarids: list[int], names: list[str], api_key: str) -> None:
        super().__init__()
        self._rockstarids = rockstarids
        self._names = names
        self._api_key = api_key

    def run(self) -> None:
        """Send and track a crawler instruction per RID serially, retrying after rate-limit waits."""
        errors: list[str] = []
        any_succeeded = False
        for i, (rid, name) in enumerate(zip(self._rockstarids, self._names, strict=True)):
            if i > 0:
                self.separator_update.emit('')
            self.status_update.emit(f'RID {i + 1}/{len(self._rockstarids)} - {rid} ({name}):' if name else f'RID {i + 1}/{len(self._rockstarids)} - {rid}:')

            tracking_id: str | None = None
            while True:
                try:
                    tracking_id = send_crawler_instruction(rid, self._api_key)
                    break
                except requests.HTTPError as exc:
                    if exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                        wait_seconds = extract_rate_limit_wait_seconds(exc)
                        self.separator_update.emit(f'----------  Rate limited — waiting {wait_seconds}s...  ----------')
                        time.sleep(wait_seconds)
                    else:
                        errors.append(f'RID {rid}: HTTP error — {exc}')
                        break
                except (requests.RequestException, KeyError) as exc:
                    errors.append(f'RID {rid}: request failed — {exc}')
                    break

            if tracking_id is None:
                continue

            seen_status_texts: set[str] = set()
            try:
                for status, result in watch_instruction_status(tracking_id, self._api_key):
                    status_text = result or status
                    if status_text not in seen_status_texts:
                        self.status_update.emit(status_text)
                        seen_status_texts.add(status_text)
                any_succeeded = True
            except requests.RequestException as exc:
                self.result_ready.emit(f'Lost connection while tracking crawler:\n\n{exc}', True)  # noqa: FBT003
                return

        if not any_succeeded:
            self.result_ready.emit('Crawler request failed:\n\n' + '\n'.join(errors), True)  # noqa: FBT003
            return

        for player in PlayersRegistry.get_default_sorted_players():
            if player.looky.is_initialized:
                player.looky.needs_refresh = True

        if errors:
            self.result_ready.emit('Crawler completed with partial errors:\n\n' + '\n'.join(errors), True)  # noqa: FBT003
        else:
            self.result_ready.emit('Crawler completed successfully.', False)  # noqa: FBT003


class GTA5Mixin(QMainWindow):
    """GTA5 process-control and toolbar-visibility mixin for `MainWindow`.

    Expects these attributes on the concrete class (set in `__init__`):
        `_gta5_menu`, `_gta5_process_submenu`, `_gta5_suspend_resume_action`,
        `_gta5_solo_menu_action`, `_manual_gta5_suspend_active`, `_gta5_solo_active`,
        `_gta5_process_suspended`, `_gta5_process_detected`,
        `_detections_manager_window`, `_userip_manager_window`
    """

    # -- Attribute stubs for type checkers --
    _gta5_menu: QMenu
    _gta5_process_submenu: QMenu
    _looky_submenu: QMenu
    _gta5_suspend_resume_action: QAction
    _gta5_solo_menu_action: QAction
    _looky_crawler_session_action: QAction
    _crawler_worker: _CrawlerWorker | None
    _crawler_progress_dialog: _CrawlerProgressDialog | None
    _player_crawler_worker: _PlayerCrawlerWorker | None
    _player_crawler_rockstarids: list[int] | None
    _player_crawler_names: list[str] | None
    _manual_gta5_suspend_active: bool
    _gta5_solo_active: bool
    _gta5_process_suspended: bool
    _gta5_process_detected: bool
    _detections_manager_window: DetectionsManagerDialog | None
    _userip_manager_window: UserIPDatabasesManager | None

    def _gta5_has_any_process_path(self) -> bool:
        """Return `True` if GTA5 is currently running."""
        return find_running_gta5_path().is_running

    def _get_gta5_process_path(self) -> Path | None:
        """Return the path to the running GTA5 executable, or `None` if not running."""
        return find_running_gta5_path().path

    def _gta5_process_is_running(self) -> bool:
        """Return `True` if GTA5 is currently running."""
        return self._get_gta5_process_path() is not None

    def toggle_manual_gta5_suspend(self) -> None:
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
                logger.warning('Manual GTA5 suspend: GTA5 process is not running')
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

    def gta5_solo_session(self) -> None:
        """Suspend GTA5 for ~8 seconds then auto-resume, forcing a solo public session."""
        self._sync_gta5_process_button()
        process_path = self._get_gta5_process_path()
        if process_path is None:
            logger.warning('GTA5 solo session: GTA5 process is not running')
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
        can_act = self._gta5_has_any_process_path() and not CaptureState.is_neighbour_interface
        self._gta5_process_submenu.setEnabled(can_act)
        if not can_act:
            if self._manual_gta5_suspend_active:
                ProcessSuspendManager.release_reason_global('manual:toolbar')
                self._manual_gta5_suspend_active = False
            if self._gta5_solo_active:
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

    def _refresh_runtime_capability_windows(self) -> None:
        """Refresh open dialogs that gate controls by preset/interface support."""
        if self._userip_manager_window is not None and self._userip_manager_window.isVisible():
            self._userip_manager_window.refresh_runtime_capabilities()

        if self._detections_manager_window is not None and self._detections_manager_window.isVisible():
            self._detections_manager_window.refresh_protection_availability()

    def _update_gta5_toolbar_visibility(self) -> None:
        """Show or hide the GTA5 menu based on current preset."""
        gta5_preset = Settings.capture_game_preset == 'GTA5'
        SessionHost.clear_session_host_data()
        gta5_menu_action = self._gta5_menu.menuAction()
        if gta5_menu_action is not None:
            gta5_menu_action.setVisible(gta5_preset)

        self._sync_looky_submenu()
        self._refresh_runtime_capability_windows()

    def _sync_looky_submenu(self) -> None:
        """Enable or disable the Looky submenu based on whether an API key is configured."""
        has_key = bool(Settings.looky_api_key)
        self._looky_submenu.setEnabled(has_key)
        cast('QAction', self._looky_submenu.menuAction()).setToolTip(
            'Looky API key is not configured — set one in Settings → Looky → Authentication.'
            if not has_key
            else 'Looky tools for the current GTA5 session',
        )

    def request_crawler_in_my_session(self) -> None:
        """Request the Looky crawler to join the current session."""
        api_key = Settings.looky_api_key
        if not api_key:
            QMessageBox.warning(self, TITLE, 'No Looky API key is configured.\n\nSet one in Settings → Looky → Authentication.')
            return

        if self._crawler_progress_dialog is not None:
            QMessageBox.information(self, TITLE, 'A crawler request is already in progress.')
            return

        self._looky_crawler_session_action.setEnabled(False)
        self._looky_crawler_session_action.setToolTip('A crawler request is already in progress — wait for it to complete.')
        _session_info = (
            '<b>Target:</b> Your own session<br><br>'
            'The Looky bot will join <b>your</b> current GTA session and resolve all visible player usernames.'
        )
        self._crawler_progress_dialog = _CrawlerProgressDialog(self, _session_info)
        self._crawler_progress_dialog.try_again_btn.clicked.connect(self._retry_crawler_in_session)
        self._crawler_progress_dialog.finished.connect(self._on_crawler_dialog_closed)
        self._crawler_progress_dialog.show()
        self._crawler_worker = _CrawlerWorker(api_key)
        self._crawler_worker.result_ready.connect(self._on_crawler_result)
        self._crawler_worker.status_update.connect(self._on_crawler_status_update)
        self._crawler_worker.finished.connect(self._crawler_worker.deleteLater)
        self._crawler_worker.start()

    def _on_crawler_status_update(self, status_text: str) -> None:
        """Update the crawler action label and progress dialog with the latest bot status."""
        self._looky_crawler_session_action.setText(f'\U0001f916 Crawler: {status_text}')
        if self._crawler_progress_dialog is not None:
            self._crawler_progress_dialog.append_step(status_text)

    def _on_crawler_result(self, message: str, is_warning: bool) -> None:  # noqa: FBT001
        """Show the result of a crawler request in the progress dialog and re-enable the action button."""
        self._looky_crawler_session_action.setText('\U0001f916 Request Crawler in My Session')
        if not is_warning:
            self._looky_crawler_session_action.setEnabled(True)
            self._looky_crawler_session_action.setToolTip(
                'Request the Looky crawler bot to join your session.\n'
                'The bot will resolve all player usernames in your session to the Looky database.\n'
                'Once completed, all players are automatically re-queried via Looky to pick up resolved or updated usernames.',
            )
            self._sync_looky_submenu()
        if self._crawler_progress_dialog is not None:
            self._crawler_progress_dialog.finish(message, is_warning)

    def _on_crawler_finished(self) -> None:
        """Release the crawler worker reference once its thread has fully stopped."""
        self._crawler_worker = None

    def _on_crawler_dialog_closed(self, _result: int) -> None:
        """Re-enable the crawler action once the progress dialog is closed."""
        self._crawler_progress_dialog = None
        self._player_crawler_rockstarids = None
        self._player_crawler_names = None
        if not self._looky_crawler_session_action.isEnabled():
            self._looky_crawler_session_action.setEnabled(True)
            self._looky_crawler_session_action.setToolTip(
                'Request the Looky crawler bot to join your session.\n'
                'The bot will resolve all player usernames in your session to the Looky database.\n'
                'Once completed, all players are automatically re-queried via Looky to pick up resolved or updated usernames.',
            )
            self._sync_looky_submenu()

    def _retry_crawler_in_session(self) -> None:
        """Retry the Looky crawler session request from within the progress dialog."""
        api_key = Settings.looky_api_key
        if not api_key or self._crawler_progress_dialog is None or self._crawler_worker is not None:
            return
        self._crawler_progress_dialog.reset()
        self._crawler_worker = _CrawlerWorker(api_key)
        self._crawler_worker.result_ready.connect(self._on_crawler_result)
        self._crawler_worker.status_update.connect(self._on_crawler_status_update)
        self._crawler_worker.finished.connect(self._crawler_worker.deleteLater)
        self._crawler_worker.finished.connect(self._on_crawler_finished)
        self._crawler_worker.start()

    def request_crawler_for_player(self, player: Player) -> None:
        """Request the Looky crawler for a specific player's Rockstar IDs."""
        api_key = Settings.looky_api_key
        if not api_key:
            QMessageBox.warning(self, TITLE, 'No Looky API key is configured.\n\nSet one in Settings \u2192 Looky \u2192 Authentication.')
            return

        if self._crawler_progress_dialog is not None:
            QMessageBox.information(self, TITLE, 'A crawler request is already in progress.')
            return

        if not player.looky.is_initialized or not player.looky.rockstarids:
            reason = (
                'This player has not been queried via the Looky API yet.'
                if not player.looky.is_initialized
                else 'Looky was queried but returned no results for this IP address.'
            )
            QMessageBox.warning(self, TITLE, f'No Rockstar ID found for {player.ip}.\n\n{reason}')
            return

        self._player_crawler_rockstarids = list(player.looky.rockstarids)
        self._player_crawler_names = list(player.looky.names)
        _rid_suffix = pluralize(len(self._player_crawler_rockstarids))
        _players_str = (
            ', '.join(f'{name} ({rid})' for name, rid in zip(player.looky.names, self._player_crawler_rockstarids, strict=True))
            if player.looky.names
            else '<i>none resolved yet</i>'
        )
        _player_info = (
            f'<b>Target IP:</b> {player.ip}<br>'
            f'<b>Looky name{_rid_suffix}:</b> {_players_str}<br><br>'
            f"The Looky bot will join this player's session via their Rockstar ID{_rid_suffix} and resolve their username{_rid_suffix} in the Looky database."
        )
        self._crawler_progress_dialog = _CrawlerProgressDialog(self, _player_info)
        self._crawler_progress_dialog.try_again_btn.clicked.connect(self._retry_player_crawler)
        self._crawler_progress_dialog.finished.connect(self._on_crawler_dialog_closed)
        self._crawler_progress_dialog.show()
        self._player_crawler_worker = _PlayerCrawlerWorker(self._player_crawler_rockstarids, self._player_crawler_names, api_key)
        self._player_crawler_worker.result_ready.connect(self._on_player_crawler_result)
        self._player_crawler_worker.status_update.connect(self._crawler_progress_dialog.append_step)
        self._player_crawler_worker.separator_update.connect(self._crawler_progress_dialog.append_separator)
        self._player_crawler_worker.finished.connect(self._player_crawler_worker.deleteLater)
        self._player_crawler_worker.finished.connect(self._on_player_crawler_finished)
        self._player_crawler_worker.start()

    def _on_player_crawler_result(self, message: str, is_warning: bool) -> None:  # noqa: FBT001
        """Show the result of a per-player crawler request and clean up."""
        if self._crawler_progress_dialog is not None:
            self._crawler_progress_dialog.finish(message, is_warning)

    def _on_player_crawler_finished(self) -> None:
        """Release the player crawler worker reference once its thread has fully stopped."""
        self._player_crawler_worker = None

    def _retry_player_crawler(self) -> None:
        """Retry the per-player Looky crawler request from within the progress dialog."""
        api_key = Settings.looky_api_key
        if (not api_key or self._crawler_progress_dialog is None
                or not self._player_crawler_rockstarids or not self._player_crawler_names
                or self._player_crawler_worker is not None):
            return
        self._crawler_progress_dialog.reset()
        self._player_crawler_worker = _PlayerCrawlerWorker(self._player_crawler_rockstarids, self._player_crawler_names, api_key)
        self._player_crawler_worker.result_ready.connect(self._on_player_crawler_result)
        self._player_crawler_worker.status_update.connect(self._crawler_progress_dialog.append_step)
        self._player_crawler_worker.separator_update.connect(self._crawler_progress_dialog.append_separator)
        self._player_crawler_worker.finished.connect(self._player_crawler_worker.deleteLater)
        self._player_crawler_worker.finished.connect(self._on_player_crawler_finished)
        self._player_crawler_worker.start()
