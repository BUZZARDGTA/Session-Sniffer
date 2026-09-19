"""Crawler request progress dialog, worker thread, and RID picker for the Looky System."""

from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from threading import Thread
from typing import TYPE_CHECKING, ClassVar, override

import requests
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.looky_text import (
    LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING,
    LOOKY_TITLE,
)
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_BODY_LABEL_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_CRAWLER_LOG_STYLESHEET,
    LOOKY_LIST_WIDGET_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
)
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import (
    build_looky_progress_widgets,
    check_looky_prerequisites,
)
from session_sniffer.guis.utils import ElidedTextTooltipDelegate, set_dialog_window_flags
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.looky_system import (
    LookyInstructionContext,
    LookyState,
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    is_terminal_failure_instruction_status,
    send_crawler_instruction,
    send_crawlme_instruction,
    watch_instruction_status,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player

logger = get_logger(__name__)


class _CrawlerSendWorker(CrashingQThread):
    """Pre-flight thread: sends the crawler instruction and emits the tracking ID, a rate-limit wait, or an error."""

    send_succeeded: Signal = Signal(str)  # tracking_id
    send_rate_limited: Signal = Signal(object, str)  # (wait_seconds: int | None, message)
    send_failed: Signal = Signal(str)  # error message

    def __init__(self, send_fn: Callable[[], str]) -> None:
        super().__init__()
        self._send_fn = send_fn

    @override
    def _run(self) -> None:
        """Invoke the send function and emit the result."""
        try:
            tracking_id = self._send_fn()
        except requests.HTTPError as e:
            if not self.isInterruptionRequested():
                if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    wait_seconds = extract_rate_limit_wait_seconds(e)
                    self.send_rate_limited.emit(wait_seconds, extract_rate_limit_message(e))
                else:
                    status_code = e.response.status_code if e.response is not None else '?'
                    self.send_failed.emit(f'API error: HTTP {status_code}')
                    if e.response is not None:
                        logger.debug('HTTP %s Response: %s', status_code, e.response.text)
                        logger.debug('Response Headers: %s', dict(e.response.headers))
                        logger.debug('Request Headers: %s', dict(e.request.headers))
        except requests.RequestException as e:
            if not self.isInterruptionRequested():
                self.send_failed.emit(f'Connection error: {e}')
                if hasattr(e, 'request') and e.request is not None:
                    logger.debug('Request Headers: %s', dict(e.request.headers))
        except KeyError:
            if not self.isInterruptionRequested():
                self.send_failed.emit('Unexpected API response: missing trackingId.')
        else:
            if not self.isInterruptionRequested():
                self.send_succeeded.emit(tracking_id)


class _CrawlerWatchWorker(CrashingQThread):
    """Background thread that streams SSE status updates for a known tracking ID."""

    status_updated: Signal = Signal(str, object)  # (status, result: str | None)
    reconnect_triggered: Signal = Signal(int)  # attempt number (1-based)
    request_completed: Signal = Signal()
    request_failed: Signal = Signal(str)  # error message
    instruction_failed: Signal = Signal(str)  # bot failure message

    def __init__(self, tracking_id: str, api_key: str, version: str, rid: int | None) -> None:
        super().__init__()
        self._tracking_id = tracking_id
        self._api_key = api_key
        self._version = version
        self._rid = rid
        self._active_response: requests.Response | None = None

    def cancel(self) -> None:
        """Signal interruption and close the active socket from a daemon thread.

        `requestInterruption()` sets a flag instantly (no I/O). The socket close
        is offloaded to a daemon thread because urllib3's streaming response teardown
        can briefly block — calling it on the GUI thread would freeze the window.
        """
        self.requestInterruption()
        active_response = self._active_response
        if active_response is not None:
            def _close_socket() -> None:
                try:
                    active_response.close()
                except OSError as e:
                    logger.debug('Failed to close crawler active response socket: %s', e)
            Thread(target=_close_socket, name='CrawlerCancel-closeSSE', daemon=True).start()

    def _on_response(self, response: requests.Response) -> None:
        self._active_response = response

    @override
    def _run(self) -> None:
        """Stream SSE status events until the instruction completes, fails, or is cancelled."""
        last_status = ''
        last_result: str | None = None
        failure_message: str | None = None
        try:
            context = LookyInstructionContext(
                tracking_id=self._tracking_id,
                api_key=self._api_key,
                version=self._version,
                rid=self._rid,
            )
            for status, result in watch_instruction_status(
                context,
                should_cancel=self.isInterruptionRequested,
                on_reconnect=self.reconnect_triggered.emit,
                on_response=self._on_response,
            ):
                last_status = status
                last_result = result
                self.status_updated.emit(status, result)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                message = extract_rate_limit_message(e)
                wait_seconds = extract_rate_limit_wait_seconds(e)
                if wait_seconds is not None:
                    failure_message = f'Rate limited during status stream: {message}. Try again in {wait_seconds} second{pluralize(wait_seconds)}.'
                else:
                    failure_message = f'Rate limited during status stream: {message}.'
            else:
                status_code = e.response.status_code if e.response is not None else '?'
                failure_message = f'API error while watching status: HTTP {status_code}'
                if e.response is not None:
                    logger.debug('HTTP %s Response: %s', status_code, e.response.text)
                    logger.debug('Response Headers: %s', dict(e.response.headers))
                    logger.debug('Request Headers: %s', dict(e.request.headers))
        except requests.RequestException as e:
            failure_message = f'Connection error while watching status: {e}'
            if hasattr(e, 'request') and e.request is not None:
                logger.debug('Request Headers: %s', dict(e.request.headers))
        except AttributeError:
            # Closing the active SSE response socket (via cancel()) while urllib3's iter_lines() is
            # running on this thread causes an AttributeError: 'NoneType' object has no attribute 'read'
            # from within http.client internals. This is a known consequence of the forced close, not
            # an unexpected bug, so treat it as a clean cancellation. If cancellation is not in
            # progress, re-raise as an unexpected error.
            if not self.isInterruptionRequested():
                raise

        if self.isInterruptionRequested():
            return
        if failure_message is not None:
            self.request_failed.emit(failure_message)
            return
        if is_terminal_failure_instruction_status(last_status):
            logger.debug('Looky instruction %s ended with failure status=%r result=%r', self._tracking_id, last_status, last_result)
            error_message = f'Instruction ended: {last_result}' if last_result else f'Instruction ended with status: {last_status}'
            if self._rid is None and last_result == 'Unable to join target':
                error_message += (
                    '<br><br><b>Tip:</b> Since you used "Crawl Current Session", ensure you are actively '
                    'playing on the exact Rockstar account that is linked to your Looky account, and '
                    'that your session is joinable.'
                )
            self.instruction_failed.emit(error_message)
            return
        self.request_completed.emit()


class _CrawlerRequestDialog(QDialog):
    """Non-modal crawler dialog: sends the instruction (auto-retrying on rate limit) then streams SSE status."""

    _open_dialogs: ClassVar[dict[str, _CrawlerRequestDialog]] = {}
    # Keeps Python references to workers that were cancelled but are still running,
    # preventing 'QThread: Destroyed while thread is still running' crashes.
    _detaching_workers: ClassVar[set[_CrawlerSendWorker | _CrawlerWatchWorker]] = set()

    def __init__(self, parent: QWidget | None, request: _CrawlerRequest) -> None:
        super().__init__(parent)
        self._request = request
        self._registry_key = request.registry_key
        self._watch_worker: _CrawlerWatchWorker | None = None
        self._send_worker: _CrawlerSendWorker | None = None
        self._retry_remaining = 0
        self._rate_limit_message = ''
        self._last_status = ''
        self._cancel_button: QPushButton | None = None
        self._is_completed = False
        _CrawlerRequestDialog._open_dialogs[request.registry_key] = self

        set_dialog_window_flags(self)
        self.setWindowTitle(LOOKY_TITLE)
        self.setMinimumSize(600, 250)
        self.resize(750, 350)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QLabel(f'Crawler Request — {request.display_name}')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(header)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setStyleSheet(LOOKY_CRAWLER_LOG_STYLESHEET)
        layout.addWidget(self._log)

        self._widgets = build_looky_progress_widgets(layout, self)

        # Repurpose the shared "Close" button as "Minimize" (crawler keeps running in the background)
        # and add a real "Cancel" button that stops the crawler and closes the window.
        self._widgets.button_box.rejected.disconnect(self.reject)
        minimize_button = self._widgets.button_box.button(QDialogButtonBox.StandardButton.Close)
        if minimize_button:
            minimize_button.setText('Minimize')
            minimize_button.setToolTip('Hide this window; the crawler keeps running in the background.')
            minimize_button.clicked.connect(self.showMinimized)
        cancel_button = self._widgets.button_box.addButton('Cancel', QDialogButtonBox.ButtonRole.RejectRole)
        if cancel_button:
            cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
            cancel_button.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
            cancel_button.setToolTip('Close this window.\nNote: if a bot was already sent, it may still join your session.')
            cancel_button.clicked.connect(self.close)
            self._cancel_button = cancel_button

        self._widgets.try_again_button.clicked.connect(self._send_now)

        self._retry_timer = QTimer(self)
        self._retry_timer.setInterval(1000)
        self._retry_timer.timeout.connect(self._tick_retry_countdown)

        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setInterval(1000)
        self._auto_close_timer.timeout.connect(self._tick_auto_close_countdown)
        self._auto_close_remaining = 0

        self._maybe_send()

    @property
    def is_completed(self) -> bool:
        """Return whether the crawler request completed successfully."""
        return self._is_completed

    @classmethod
    def restore_existing(cls, registry_key: str) -> bool:
        """Restore and raise an already-open dialog for *registry_key*; return True if one existed."""
        existing = cls._open_dialogs.get(registry_key)
        if existing is None:
            return False
        if existing.is_completed:
            existing.close()
            return False
        existing.showNormal()
        existing.raise_()
        existing.activateWindow()
        return True

    @classmethod
    def close_all_open_dialogs(cls) -> None:
        """Close and cleanly cancel all open crawler dialogs."""
        for dialog in list(cls._open_dialogs.values()):
            dialog.close()

    # ------------------------------------------------------------------
    # Send (with rate-limit auto-retry)
    # ------------------------------------------------------------------

    def _maybe_send(self) -> None:
        """Send immediately, unless a local rate-limit cooldown is still active — then show its countdown."""
        remaining = LookyState.crawler_cooldown_remaining()
        if remaining > 0:
            self._start_retry_countdown(remaining, 'Rate limit cooldown active.')
        else:
            self._send_now()

    def _send_now(self) -> None:
        """Send (or re-send) the crawler instruction now, resetting the UI to the in-progress state.

        Used for the initial send, the auto-retry when the countdown elapses, and the manual "Retry now"
        button — which lets the user force a request through even while the local cooldown is active.
        """
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        self._append_log_line('Sending request...')
        self._widgets.progress_bar.show()
        self._widgets.status_label.hide()
        self._widgets.try_again_button.hide()
        self._widgets.try_again_button.setText('Try Again')
        if self._cancel_button is not None:
            self._cancel_button.setText('Cancel')
            self._cancel_button.setToolTip('Close this window.\nNote: if a bot was already sent, it may still join your session.')
        worker = _CrawlerSendWorker(self._request.send_fn)
        worker.send_succeeded.connect(self._on_send_succeeded)
        worker.send_rate_limited.connect(self._on_send_rate_limited)
        worker.send_failed.connect(self._show_failed)
        self._send_worker = worker
        worker.start()

    def _on_send_succeeded(self, tracking_id: str) -> None:
        """Send accepted — clear any cooldown and begin streaming SSE status for the returned tracking ID."""
        LookyState.clear_crawler_cooldown()
        self._append_log_line(f'Request accepted — tracking ID: {tracking_id}')
        self._append_log_line('Connecting to status stream…')
        worker = _CrawlerWatchWorker(tracking_id, self._request.api_key, self._request.version, self._request.rid)
        worker.status_updated.connect(self._on_status_updated)
        worker.reconnect_triggered.connect(self._on_reconnect_triggered)
        worker.request_completed.connect(self._on_completed)
        worker.request_failed.connect(self._show_watch_stream_lost)
        worker.instruction_failed.connect(self._show_failed)
        self._watch_worker = worker
        worker.start()

    def _on_send_rate_limited(self, wait_seconds: int | None, message: str) -> None:
        """Rate limited by the server — if the server provided a wait time, cache it and show an auto-retry countdown.

        If no wait time was provided by the server, fall back to a manual-retry error state.
        """
        if wait_seconds is None:
            self._show_failed(f'Rate limited: {message}')
            return
        LookyState.record_crawler_cooldown(wait_seconds)
        self._start_retry_countdown(wait_seconds, f'Rate limited: {message}')

    def _start_retry_countdown(self, wait_seconds: int, message: str) -> None:
        """Show the amber countdown UI and start the 1-second auto-retry timer."""
        self._rate_limit_message = message
        self._retry_remaining = max(1, wait_seconds)
        self._widgets.progress_bar.hide()
        self._widgets.try_again_button.hide()
        self._update_retry_label()
        self._widgets.status_label.show()
        self._retry_timer.start()

    def _tick_retry_countdown(self) -> None:
        """Advance the rate-limit countdown; auto-retry the send when it reaches zero."""
        self._retry_remaining -= 1
        if self._retry_remaining <= 0:
            self._send_now()
        else:
            self._update_retry_label()

    def _update_retry_label(self) -> None:
        """Refresh the amber rate-limit countdown text."""
        seconds_word = 'second' if self._retry_remaining == 1 else 'seconds'
        self._widgets.status_label.setText(
            f'<span style="color: #fbbf24; font-weight: 600;">Server rate limit active<br>Automatically retrying in {self._retry_remaining} {seconds_word}…</span>',
        )

    # ------------------------------------------------------------------
    # Watch (SSE status stream)
    # ------------------------------------------------------------------

    def _append_log_line(self, text: str) -> None:
        """Append a timestamped log line with `text`."""
        timestamp = datetime.now(tz=UTC).astimezone().strftime('%H:%M:%S')
        self._log.appendPlainText(f'[{timestamp}]  {text}')

    def _on_status_updated(self, status: str, result: object) -> None:
        """Append a friendly timestamped SSE status line to the log and update the live status label."""
        status_labels = {
            'queued': 'Queued — waiting for a bot to pick up the request',
            'running': 'Running — crawler is actively working',
            'completed': 'Completed — instruction finished successfully',
            'failed': 'Failed — the bot encountered an error',
            'canceled': 'Canceled — the request was canceled',
        }
        label = status_labels.get(status.lower(), status)
        text = label if result is None else f'{label} — {result}'
        self._append_log_line(text)
        self._last_status = status.lower()

    def _on_reconnect_triggered(self, attempt: int) -> None:
        """Show an amber log line indicating that the stream dropped and we are waiting to reconnect."""
        self._append_log_line(f'Stream dropped — reconnecting (attempt {attempt})…')

    def _on_completed(self) -> None:
        """The crawler instruction completed successfully."""
        self._is_completed = True
        self._retry_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText('<span style="color: #4ade80; font-weight: 600;">Completed</span>')
        self._widgets.status_label.show()
        self._log.setPlaceholderText('')
        if self._request.on_completed is not None:
            self._request.on_completed()

        self._auto_close_remaining = 3
        self._update_close_button_countdown()
        self._auto_close_timer.start()

    def _tick_auto_close_countdown(self) -> None:
        """Advance the auto-close countdown; close the dialog when it reaches zero."""
        self._auto_close_remaining -= 1
        if self._auto_close_remaining <= 0:
            self._auto_close_timer.stop()
            self.close()
        else:
            self._update_close_button_countdown()

    def _update_close_button_countdown(self) -> None:
        """Refresh the Close button text with the remaining countdown seconds."""
        if self._cancel_button is not None:
            self._cancel_button.setText(f'Close ({self._auto_close_remaining}s)')
            self._cancel_button.setToolTip(f'Close this window (auto-closing in {self._auto_close_remaining}s).')

    def _show_failed(self, message: str) -> None:
        """Show a failure with a manual Try Again button (used for both send and instruction failures)."""
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">Failed: {message}</span>')
        self._widgets.status_label.show()
        self._widgets.try_again_button.setText('Try Again')
        self._widgets.try_again_button.show()
        if self._cancel_button is not None:
            self._cancel_button.setText('Close')
            self._cancel_button.setToolTip('Close this window.')
        self._log.setPlaceholderText('')

    def _show_watch_stream_lost(self, message: str) -> None:
        """Show a connection loss error with a Try Again button."""
        self._append_log_line(f'Status stream lost: {message}')
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(
            '<span style="color: #fbbf24; font-weight: 600;">Status stream lost</span>',
        )
        self._widgets.status_label.show()
        self._widgets.try_again_button.setText('Try Again')
        self._widgets.try_again_button.show()
        if self._cancel_button is not None:
            self._cancel_button.setText('Close')
            self._cancel_button.setToolTip('Close this window.')
        self._log.setPlaceholderText('')

    # ------------------------------------------------------------------
    # Lifetime / cleanup
    # ------------------------------------------------------------------

    def _cancel_workers_async(self) -> None:
        """Signal workers to stop without blocking the GUI thread.

        Workers that are still running are moved into `_detaching_workers` so the Python
        object (and its QThread) is not garbage-collected before the thread finishes.
        Each worker removes itself from the set via its `finished` signal.
        """
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        if self._watch_worker is not None:
            watch_worker = self._watch_worker
            self._watch_worker = None
            if watch_worker.isRunning():
                watch_worker.cancel()
                _CrawlerRequestDialog._detaching_workers.add(watch_worker)

                def _remove_watch_worker(detached_worker: _CrawlerWatchWorker = watch_worker) -> None:
                    _CrawlerRequestDialog._detaching_workers.discard(detached_worker)
                watch_worker.finished.connect(_remove_watch_worker)
        if self._send_worker is not None:
            send_worker = self._send_worker
            self._send_worker = None
            if send_worker.isRunning():
                send_worker.requestInterruption()
                _CrawlerRequestDialog._detaching_workers.add(send_worker)

                def _remove_send_worker(detached_worker: _CrawlerSendWorker = send_worker) -> None:
                    _CrawlerRequestDialog._detaching_workers.discard(detached_worker)
                send_worker.finished.connect(_remove_send_worker)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Hide the window instantly, then cancel background workers asynchronously."""
        self.hide()
        _CrawlerRequestDialog._open_dialogs.pop(self._registry_key, None)
        self._cancel_workers_async()
        super().closeEvent(event)

    @override
    def reject(self) -> None:
        """Hide the window instantly, then cancel workers asynchronously (Escape / Cancel button).

        Calls `super().reject()` (which hides via `done()`), never `self.close()` — closing would
        re-enter `QDialog.closeEvent`, which itself calls `reject()`, causing infinite recursion.
        """
        self.hide()
        _CrawlerRequestDialog._open_dialogs.pop(self._registry_key, None)
        self._cancel_workers_async()
        super().reject()


class _RIDPickerDialog(QDialog):
    """Modal dialog for selecting one Rockstar ID when a player has multiple."""

    def __init__(self, parent: QWidget, entries: list[tuple[str, int]]) -> None:
        super().__init__(parent)
        set_dialog_window_flags(self)
        self.setWindowTitle(LOOKY_TITLE)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QLabel('Crawler Request — Select Rockstar ID')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(header)

        label = QLabel('Multiple RIDs found for this player.\n\nSelect one to request the crawler:')
        label.setWordWrap(True)
        label.setStyleSheet(LOOKY_BODY_LABEL_STYLESHEET)
        layout.addWidget(label)

        self._list = QListWidget()
        self._list.setStyleSheet(LOOKY_LIST_WIDGET_STYLESHEET)
        self._list.setItemDelegate(ElidedTextTooltipDelegate(self._list))
        self._list.setWordWrap(False)
        for name, rid in entries:
            item = QListWidgetItem(f'{name} (RID: {rid})')
            item.setData(Qt.ItemDataRole.UserRole, rid)
            self._list.addItem(item)
        self._list.setCurrentRow(0)
        self._list.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self._list)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        if ok_button:
            ok_button.setCursor(Qt.CursorShape.PointingHandCursor)
            ok_button.setStyleSheet(LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET)
        cancel_button = button_box.button(QDialogButtonBox.StandardButton.Cancel)
        if cancel_button:
            cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
            cancel_button.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
        layout.addWidget(button_box)

    def selected_rid(self) -> int | None:
        """Return the currently selected RID, or `None` if nothing is selected."""
        item = self._list.currentItem()
        if not item:
            return None
        return int(item.data(Qt.ItemDataRole.UserRole))

    @staticmethod
    def pick_rid(parent: QWidget, entries: list[tuple[str, int]]) -> int | None:
        """Show the picker dialog and return the chosen RID, or `None` if canceled."""
        dialog = _RIDPickerDialog(parent, entries)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.selected_rid()


@dataclass(frozen=True, slots=True)
class _CrawlerRequest:
    """All parameters needed to send a crawler instruction and show its progress dialog."""

    display_name: str
    api_key: str
    registry_key: str
    version: str
    rid: int | None
    send_fn: Callable[[], str]
    on_completed: Callable[[], None] | None = None


def _start_crawler_send(request: _CrawlerRequest) -> None:
    """Open the crawler request dialog for *request* (or restore it if already open).

    The dialog itself sends the instruction and shows progress, so a rate-limited or failed send still
    opens the window (with a countdown auto-retry and a manual retry button) instead of a dead-end
    warning box.
    """
    if _CrawlerRequestDialog.restore_existing(request.registry_key):
        return
    _CrawlerRequestDialog(None, request).show()


def get_crawler_game_version() -> str:
    """Return 'enhanced' or 'legacy' depending on the currently running GTA5 game edition, falling back to settings."""
    if CaptureState.gta5_is_enhanced:
        return 'enhanced'
    if CaptureState.gta5_is_legacy:
        return 'legacy'
    if Settings.looky_game_version.lower() in ('enhanced', 'legacy'):
        return Settings.looky_game_version.lower()
    return 'legacy'


def show_crawler_request(parent: QWidget, player: Player) -> None:
    """Validate and start a Looky System crawler instruction for `player`; open a crawler request dialog on success."""
    api_key = check_looky_prerequisites(parent, player=player)
    if api_key is None:
        return

    if not player.looky_system.rockstarids:
        QMessageBox.warning(
            parent,
            LOOKY_TITLE,
            'No Rockstar ID found for this IP address.\nThe Looky System has not resolved any players for this IP yet.',
        )
        return

    entries = list(zip(player.looky_system.usernames, player.looky_system.rockstarids, strict=False))
    rid = player.looky_system.rockstarids[0] if len(player.looky_system.rockstarids) == 1 else _RIDPickerDialog.pick_rid(parent, entries)
    if rid is None:
        return

    display_name = next((name for name, rockstar_id in entries if rockstar_id == rid), player.ip)

    def _on_crawl_completed() -> None:
        with player.looky_system.lock:
            player.looky_system.needs_refresh = True

    version = get_crawler_game_version()
    _start_crawler_send(
        _CrawlerRequest(
            display_name=display_name,
            api_key=api_key,
            registry_key=f'crawler:{rid}',
            version=version,
            rid=rid,
            send_fn=lambda: send_crawler_instruction(rid, api_key, version),
            on_completed=_on_crawl_completed,
        ),
    )


def show_crawlme_request(parent: QWidget) -> None:
    """Validate and start a Looky System crawlme instruction; open a crawler request dialog on success."""
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    if not CaptureState.gta5_is_running:
        QMessageBox.warning(parent, LOOKY_TITLE, LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING)
        return

    def _on_crawl_completed() -> None:
        for player in PlayersRegistry.get_default_sorted_players():
            if player.looky_system.is_initialized:
                with player.looky_system.lock:
                    player.looky_system.needs_refresh = True

    version = get_crawler_game_version()
    _start_crawler_send(
        _CrawlerRequest(
            display_name='Current Session',
            api_key=api_key,
            registry_key='crawlme',
            version=version,
            rid=None,
            send_fn=lambda: send_crawlme_instruction(api_key, version),
            on_completed=_on_crawl_completed,
        ),
    )


def close_all_crawler_dialogs() -> None:
    """Close and cleanly cancel all open crawler dialogs."""
    _CrawlerRequestDialog.close_all_open_dialogs()
