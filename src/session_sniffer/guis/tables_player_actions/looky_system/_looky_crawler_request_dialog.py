"""Crawler request progress dialog, worker thread, and RID picker for the Looky System."""

import html
import logging
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

from session_sniffer.background.cores import trigger_looky_rescan_all_players
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.looky_text import (
    LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING,
    get_looky_restriction,
    get_looky_title,
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
from session_sniffer.guis.theming import themed_qss
from session_sniffer.guis.utils import scale_by_ui, set_dialog_window_flags
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.networking.looky_system import (
    LookyInstructionContext,
    LookyState,
    extract_api_error_message,
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    is_terminal_failure_instruction_status,
    send_crawler_instruction,
    send_crawlme_instruction,
    send_proxy_join_instruction,
    watch_instruction_status,
)
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player

logger = logging.getLogger(__name__)


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
                    api_message = extract_api_error_message(e)
                    self.send_failed.emit(api_message or tr('API error: HTTP {status_code}', status_code=status_code))
                    if e.response is not None:
                        logger.debug('HTTP %s Response: %s', status_code, e.response.text)
                        logger.debug('Response Headers: %s', dict(e.response.headers))
                        logger.debug('Request Headers: %s', dict(e.request.headers))
        except requests.RequestException as e:
            if not self.isInterruptionRequested():
                self.send_failed.emit(tr('Connection error: {error}', error=e))
                if e.request is not None:
                    logger.debug('Request Headers: %s', dict(e.request.headers))
        except KeyError:
            if not self.isInterruptionRequested():
                self.send_failed.emit(tr('Unexpected API response: missing trackingId.'))
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

    @override
    def cancel(self, timeout_ms: int = 2000) -> bool:
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
        return super().cancel(timeout_ms=timeout_ms)

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
                rate_message = extract_rate_limit_message(e)
                wait_seconds = extract_rate_limit_wait_seconds(e)
                if wait_seconds is not None:
                    failure_message = tr_plural(
                        'Rate limited during status stream: {message}. Try again in {count} second.',
                        'Rate limited during status stream: {message}. Try again in {count} seconds.',
                        wait_seconds,
                        message=rate_message,
                    )
                else:
                    failure_message = tr('Rate limited during status stream: {message}.', message=rate_message)
            else:
                status_code = e.response.status_code if e.response is not None else '?'
                api_message = extract_api_error_message(e)
                failure_message = tr('API error while watching status: {detail}', detail=api_message or f'HTTP {status_code}')
                if e.response is not None:
                    logger.debug('HTTP %s Response: %s', status_code, e.response.text)
                    logger.debug('Response Headers: %s', dict(e.response.headers))
                    logger.debug('Request Headers: %s', dict(e.request.headers))
        except requests.RequestException as e:
            failure_message = tr('Connection error while watching status: {error}', error=e)
            if e.request is not None:
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
            error_message = (
                tr('Instruction ended: {result}', result=html.escape(last_result))
                if last_result is not None and last_result
                else tr('Instruction ended with status: {status}', status=html.escape(last_status))
            )
            if self._rid is None and last_result == 'Unable to join target':
                tip_heading = html.escape(tr('Tip:'))
                tip_body = html.escape(
                    tr(
                        'Since you used "Crawl Current Session", ensure you are actively playing on the exact Rockstar account '
                        'that is linked to your Looky account, and that your session is joinable.',
                    ),
                )
                error_message += f'<br><br><b>{tip_heading}</b> {tip_body}'
            self.instruction_failed.emit(error_message)
            return
        self.request_completed.emit()


class _CrawlerRequestDialog(QDialog):
    """Non-modal crawler dialog: sends the instruction (auto-retrying on rate limit) then streams SSE status."""

    _open_dialogs: ClassVar[dict[str, _CrawlerRequestDialog]] = {}
    # Keeps Python references to workers that were cancelled but are still running,
    # preventing 'QThread: Destroyed while thread is still running' crashes.
    _detaching_workers: ClassVar[set[_CrawlerSendWorker | _CrawlerWatchWorker]] = set()

    def __init__(self, request: _CrawlerRequest) -> None:
        super().__init__(None)
        self._request = request
        self._registry_key = request.registry_key
        self._watch_worker: _CrawlerWatchWorker | None = None
        self._send_worker: _CrawlerSendWorker | None = None
        self._retry_remaining = 0
        self._rate_limit_message = ''
        self._cancel_button: QPushButton | None = None
        self._minimize_button: QPushButton | None = None
        self._is_completed = False
        self._is_retryable_stopped = False
        _CrawlerRequestDialog._open_dialogs[request.registry_key] = self

        set_dialog_window_flags(self)
        self.setWindowTitle(get_looky_title())
        self.setMinimumSize(scale_by_ui(500), scale_by_ui(360))
        self.resize(scale_by_ui(640), scale_by_ui(400))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self._header = QLabel(self._format_header_text())
        self._header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(self._header)

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
            minimize_button.setText(tr('Minimize'))
            minimize_button.setToolTip(tr('Hide this window; the operation keeps running in the background.'))
            minimize_button.clicked.connect(self.showMinimized)
            self._minimize_button = minimize_button
        cancel_button = self._widgets.button_box.addButton(tr('Cancel'), QDialogButtonBox.ButtonRole.RejectRole)
        if cancel_button:
            cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
            cancel_button.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
            cancel_button.setToolTip(tr('Close this window.\nNote: if a bot was already sent, it may still join your session.'))
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

        register_language_refresh(self, self._refresh_language_texts)
        self._maybe_send()

    def _format_header_text(self) -> str:
        """Build the localized dialog header banner text."""
        display = tr('Current Session') if self._request.translate_display_name else self._request.display_name
        return f'{tr(self._request.title_prefix)} \u2014 {display}'

    def _refresh_language_texts(self) -> None:
        """Refresh dialog chrome when the runtime language changes."""
        self.setWindowTitle(get_looky_title())
        self._header.setText(self._format_header_text())
        if self._minimize_button is not None:
            self._minimize_button.setText(tr('Minimize'))
            self._minimize_button.setToolTip(tr('Hide this window; the operation keeps running in the background.'))
        self._widgets.try_again_button.setText(tr('Try Again'))
        if self._is_completed:
            self._widgets.status_label.setText(themed_qss(f'<span style="color: #4ade80; font-weight: 600;">{html.escape(tr("Completed"))}</span>'))
            self._update_close_button_countdown()
        elif self._is_retryable_stopped and self._cancel_button is not None:
            self._cancel_button.setText(tr('Close'))
            self._cancel_button.setToolTip(tr('Close this window.'))
        elif self._cancel_button is not None:
            self._cancel_button.setText(tr('Cancel'))
            self._cancel_button.setToolTip(tr('Close this window.\nNote: if a bot was already sent, it may still join your session.'))
        if self._retry_timer.isActive():
            self._update_retry_label()

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
            self._start_retry_countdown(remaining, tr('Rate limit cooldown active'))
        else:
            self._send_now()

    def _send_now(self) -> None:
        """Send (or re-send) the crawler instruction now, resetting the UI to the in-progress state.

        Used for the initial send, the auto-retry when the countdown elapses, and the manual "Retry now"
        button — which lets the user force a request through even while the local cooldown is active.
        """
        self._is_retryable_stopped = False
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        self._append_log_line(tr('Sending request...'))
        self._widgets.progress_bar.show()
        self._widgets.status_label.hide()
        self._widgets.try_again_button.hide()
        self._widgets.try_again_button.setText(tr('Try Again'))
        if self._cancel_button is not None:
            self._cancel_button.setText(tr('Cancel'))
            self._cancel_button.setToolTip(tr('Close this window.\nNote: if a bot was already sent, it may still join your session.'))
        worker = _CrawlerSendWorker(self._request.send_fn)
        worker.send_succeeded.connect(self._on_send_succeeded)
        worker.send_rate_limited.connect(self._on_send_rate_limited)
        worker.send_failed.connect(self._show_failed)
        self._send_worker = worker
        worker.start()

    def _on_send_succeeded(self, tracking_id: str) -> None:
        """Send accepted — clear any cooldown and begin streaming SSE status for the returned tracking ID."""
        LookyState.clear_crawler_cooldown()
        self._append_log_line(tr('Request accepted — tracking ID: {tracking_id}', tracking_id=tracking_id))
        self._append_log_line(tr('Connecting to status stream…'))
        worker = _CrawlerWatchWorker(tracking_id, self._request.api_key, self._request.version, self._request.rid)
        worker.status_updated.connect(self._on_status_updated)
        worker.reconnect_triggered.connect(self._on_reconnect_triggered)
        worker.request_completed.connect(self._on_completed)
        worker.request_failed.connect(self._show_watch_stream_lost)
        worker.instruction_failed.connect(self._show_instruction_failed)
        self._watch_worker = worker
        worker.start()

    def _on_send_rate_limited(self, wait_seconds: int | None, message: str) -> None:
        """Rate limited by the server — if the server provided a wait time, cache it and show an auto-retry countdown.

        If no wait time was provided by the server, fall back to a manual-retry error state.
        """
        if wait_seconds is None:
            self._show_failed(tr('Rate limited: {message}', message=message))
            return
        self._append_log_line(
            tr_plural(
                'Rate limited: {message} (retrying in {count} second)',
                'Rate limited: {message} (retrying in {count} seconds)',
                wait_seconds,
                message=message,
            ),
        )
        LookyState.record_crawler_cooldown(wait_seconds)
        self._start_retry_countdown(wait_seconds, tr('Rate limited: {message}', message=message))

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
        header_text = html.escape(self._rate_limit_message or tr('Server rate limit active'))
        retry_line = html.escape(
            tr_plural(
                'Automatically retrying in {count} second…',
                'Automatically retrying in {count} seconds…',
                self._retry_remaining,
            ),
        )
        self._widgets.status_label.setText(
            themed_qss(
                f'<span style="color: #fbbf24; font-weight: 600;">{header_text}<br>'
                f'{retry_line}</span>',
            ),
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
        status_lower = status.lower()
        status_labels = {
            'queued': tr('Queued — waiting for a bot to pick up the request'),
            'running': tr('Running — bot is actively working'),
            'completed': tr('Completed — instruction finished successfully'),
            'failed': tr('Failed — the bot encountered an error'),
            'canceled': tr('Canceled — the request was canceled'),
        }
        label = status_labels.get(status_lower, status)
        text = label if result is None else f'{label} — {result}'
        self._append_log_line(text)
        if status_lower not in {'completed', 'failed', 'canceled'} and not is_terminal_failure_instruction_status(status_lower):
            color = '@warning[#fbbf24]' if status_lower == 'queued' else '@lock[#d8b4fe]'
            self._widgets.status_label.setText(themed_qss(f'<span style="color: {color}; font-weight: 600;">{html.escape(text)}</span>'))
            self._widgets.status_label.show()

    def _on_reconnect_triggered(self, attempt: int) -> None:
        """Show an amber log line indicating that the stream dropped and we are waiting to reconnect."""
        self._append_log_line(tr('Stream dropped — reconnecting (attempt {attempt})…', attempt=attempt))

    def _on_completed(self) -> None:
        """The crawler instruction completed successfully."""
        self._is_completed = True
        self._retry_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(themed_qss(f'<span style="color: #4ade80; font-weight: 600;">{html.escape(tr("Completed"))}</span>'))
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
            self._cancel_button.setText(tr('Close ({seconds}s)', seconds=self._auto_close_remaining))
            self._cancel_button.setToolTip(tr('Close this window (auto-closing in {seconds}s).', seconds=self._auto_close_remaining))

    def _enter_retryable_stop_state(self, status_html: str) -> None:
        """Stop timers, hide progress bar, display *status_html*, and show the Try Again / Close controls."""
        self._is_retryable_stopped = True
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(themed_qss(status_html))
        self._widgets.status_label.show()
        self._widgets.try_again_button.setText(tr('Try Again'))
        self._widgets.try_again_button.show()
        if self._cancel_button is not None:
            self._cancel_button.setText(tr('Close'))
            self._cancel_button.setToolTip(tr('Close this window.'))
        self._log.setPlaceholderText('')

    def _show_failed(self, message: str, *, is_html: bool = False) -> None:
        """Show a failure with a manual Try Again button (used for both send and instruction failures)."""
        formatted_message = message if is_html else html.escape(message)
        failed_text = tr('Failed: {message}', message=formatted_message)
        self._enter_retryable_stop_state(f'<span style="color: #f87171; font-weight: 600;">{failed_text}</span>')

    def _show_instruction_failed(self, message: str) -> None:
        """Show an HTML-formatted instruction failure message."""
        self._show_failed(message, is_html=True)

    def _show_watch_stream_lost(self, message: str) -> None:
        """Show a connection loss error with a Try Again button."""
        self._append_log_line(tr('Status stream lost: {message}', message=message))
        stream_lost_text = html.escape(tr('Status stream lost'))
        self._enter_retryable_stop_state(f'<span style="color: #fbbf24; font-weight: 600;">{stream_lost_text}</span>')

    # ------------------------------------------------------------------
    # Lifetime / cleanup
    # ------------------------------------------------------------------

    @staticmethod
    def _detach_and_cancel_worker(worker: _CrawlerWatchWorker | _CrawlerSendWorker | None) -> None:
        """Cancel *worker* non-blockingly and retain a reference in `_detaching_workers` until finished."""
        if worker is None or not worker.isRunning():
            return
        worker.cancel(timeout_ms=0)
        _CrawlerRequestDialog._detaching_workers.add(worker)

        def _remove_detached_worker(detached_worker: _CrawlerWatchWorker | _CrawlerSendWorker = worker) -> None:
            _CrawlerRequestDialog._detaching_workers.discard(detached_worker)

        worker.finished.connect(_remove_detached_worker)

    def _cancel_workers_async(self) -> None:
        """Signal workers to stop without blocking the GUI thread.

        Workers that are still running are moved into `_detaching_workers` so the Python
        object (and its QThread) is not garbage-collected before the thread finishes.
        Each worker removes itself from the set via its `finished` signal.
        """
        self._retry_timer.stop()
        self._auto_close_timer.stop()
        watch_worker, self._watch_worker = self._watch_worker, None
        send_worker, self._send_worker = self._send_worker, None
        self._detach_and_cancel_worker(watch_worker)
        self._detach_and_cancel_worker(send_worker)

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

    def __init__(
        self,
        parent: QWidget,
        entries: list[tuple[str, int]],
        *,
        title_prefix: str = 'Crawler Request',
        select_prompt: str = 'Multiple RIDs found for this player.\n\nSelect one to request the crawler:',
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(get_looky_title())
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)
        self.setMinimumWidth(scale_by_ui(420))
        self._selected_rid: int | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header = QLabel(tr('{prefix} — Select Rockstar ID', prefix=tr(title_prefix)))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(header)

        label = QLabel(tr(select_prompt))
        label.setWordWrap(True)
        label.setStyleSheet(LOOKY_BODY_LABEL_STYLESHEET)
        layout.addWidget(label)

        self._list = QListWidget()
        self._list.setStyleSheet(LOOKY_LIST_WIDGET_STYLESHEET)
        self._list.setItemDelegate(ElidedTextTooltipDelegate(self._list))
        self._list.setWordWrap(False)
        for name, rid in entries:
            item_label = tr('{name} (RID: {rid})', name=name, rid=rid) if name else tr('RID: {rid}', rid=rid)
            item = QListWidgetItem(item_label)
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

    @override
    def accept(self) -> None:
        """Capture selected RID before closing."""
        item = self._list.currentItem()
        self._selected_rid = int(item.data(Qt.ItemDataRole.UserRole)) if item else None
        super().accept()

    def selected_rid(self) -> int | None:
        """Return the currently selected RID, or `None` if nothing is selected."""
        if self._selected_rid is not None:
            return self._selected_rid
        item = self._list.currentItem()
        if not item:
            return None
        return int(item.data(Qt.ItemDataRole.UserRole))

    @staticmethod
    def pick_rid(
        parent: QWidget,
        entries: list[tuple[str, int]],
        *,
        title_prefix: str = 'Crawler Request',
        select_prompt: str = 'Multiple RIDs found for this player.\n\nSelect one to request the crawler:',
    ) -> int | None:
        """Show the picker dialog and return the chosen RID, or `None` if canceled."""
        dialog = _RIDPickerDialog(parent, entries, title_prefix=title_prefix, select_prompt=select_prompt)
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
    title_prefix: str = 'Crawler Request'
    translate_display_name: bool = False
    on_completed: Callable[[], object] | None = None


def _start_crawler_send(request: _CrawlerRequest) -> None:
    """Open the crawler request dialog for *request* (or restore it if already open).

    The dialog itself sends the instruction and shows progress, so a rate-limited or failed send still
    opens the window (with a countdown auto-retry and a manual retry button) instead of a dead-end
    warning box.
    """
    if _CrawlerRequestDialog.restore_existing(request.registry_key):
        return
    _CrawlerRequestDialog(request).show()


def get_crawler_game_version() -> str:
    """Return 'enhanced' or 'legacy' depending on the currently running GTA5 game edition, falling back to settings."""
    if CaptureState.gta5_is_enhanced:
        return 'enhanced'
    if CaptureState.gta5_is_legacy:
        return 'legacy'
    if Settings.looky_game_version.lower() in ('enhanced', 'legacy'):
        return Settings.looky_game_version.lower()
    return 'legacy'


@dataclass(frozen=True, slots=True)
class _InstructionSpec:
    """Static metadata for a Looky RID-based instruction (crawler or proxy join)."""

    registry_prefix: str
    instruction_fn: Callable[[int, str, str], str]
    title_prefix: str
    select_prompt: str


_CRAWLER_SPEC = _InstructionSpec(
    registry_prefix='crawler',
    instruction_fn=send_crawler_instruction,
    title_prefix='Crawler Request',
    select_prompt='Multiple RIDs found for this player.\n\nSelect one to request the crawler:',
)

_PROXY_JOIN_SPEC = _InstructionSpec(
    registry_prefix='proxy_join',
    instruction_fn=send_proxy_join_instruction,
    title_prefix='Proxy Join',
    select_prompt='Multiple RIDs found for this player.\n\nSelect one to proxy join:',
)


def _show_rid_instruction_request(
    parent: QWidget,
    rid: int,
    display_name: str,
    spec: _InstructionSpec,
    *,
    restriction: str | None = None,
) -> None:
    """Validate prerequisites and start a Looky instruction request for *rid*."""
    api_key = check_looky_prerequisites(parent, restriction=restriction)
    if api_key is None:
        return

    version = get_crawler_game_version()
    _start_crawler_send(
        _CrawlerRequest(
            display_name=display_name,
            api_key=api_key,
            registry_key=f'{spec.registry_prefix}:{rid}',
            version=version,
            rid=rid,
            send_fn=lambda: spec.instruction_fn(rid, api_key, version),
            title_prefix=spec.title_prefix,
            on_completed=trigger_looky_rescan_all_players,
        ),
    )


def _show_player_instruction_request(
    parent: QWidget,
    player: Player,
    spec: _InstructionSpec,
) -> None:
    """Resolve or prompt for a Rockstar ID on *player* and start a Looky instruction request."""
    restriction = get_looky_restriction([player])
    api_key = check_looky_prerequisites(parent, restriction=restriction)
    if api_key is None:
        return

    with player.looky_system.lock:
        rockstarids = list(player.looky_system.rockstarids)
        entry_names = list(player.looky_system.entry_names)
    if not rockstarids:
        QMessageBox.warning(
            parent,
            get_looky_title(),
            tr('No Rockstar ID found for this IP address.\nThe Looky System has not resolved any players for this IP yet.'),
        )
        return

    entries = [(entry_names[i] if i < len(entry_names) else '', rid) for i, rid in enumerate(rockstarids)]
    rid = (
        rockstarids[0]
        if len(rockstarids) == 1
        else _RIDPickerDialog.pick_rid(parent, entries, title_prefix=spec.title_prefix, select_prompt=spec.select_prompt)
    )
    if rid is None:
        return

    display_name = next((name for name, rockstar_id in entries if rockstar_id == rid and name), player.ip)
    _show_rid_instruction_request(
        parent,
        rid,
        display_name,
        spec,
        restriction=restriction,
    )


def show_crawler_by_rid(
    parent: QWidget,
    rid: int,
    display_name: str,
    *,
    restriction: str | None = None,
) -> None:
    """Validate and start a Looky System crawler instruction for `rid`; open a request dialog on success."""
    _show_rid_instruction_request(
        parent,
        rid,
        display_name,
        _CRAWLER_SPEC,
        restriction=restriction,
    )


def show_crawler_request(parent: QWidget, player: Player) -> None:
    """Validate and start a Looky System crawler instruction for `player`; open a crawler request dialog on success."""
    _show_player_instruction_request(parent, player, _CRAWLER_SPEC)


def show_proxy_join_by_rid(
    parent: QWidget,
    rid: int,
    display_name: str,
    *,
    restriction: str | None = None,
) -> None:
    """Validate and start a Looky System proxy join instruction for `rid`; open a request dialog on success."""
    _show_rid_instruction_request(
        parent,
        rid,
        display_name,
        _PROXY_JOIN_SPEC,
        restriction=restriction,
    )


def show_proxy_join_request(parent: QWidget, player: Player) -> None:
    """Validate and start a Looky System proxy join instruction for `player`; open a proxy join request dialog on success."""
    _show_player_instruction_request(parent, player, _PROXY_JOIN_SPEC)


def show_crawlme_request(parent: QWidget) -> None:
    """Validate and start a Looky System crawlme instruction; open a crawler request dialog on success."""
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    if not CaptureState.gta5_is_running:
        QMessageBox.warning(parent, get_looky_title(), tr(LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING))
        return

    version = get_crawler_game_version()
    _start_crawler_send(
        _CrawlerRequest(
            display_name='Current Session',
            api_key=api_key,
            registry_key='crawlme',
            version=version,
            rid=None,
            send_fn=lambda: send_crawlme_instruction(api_key, version),
            translate_display_name=True,
            on_completed=trigger_looky_rescan_all_players,
        ),
    )


def close_all_crawler_dialogs() -> None:
    """Close and cleanly cancel all open crawler dialogs."""
    _CrawlerRequestDialog.close_all_open_dialogs()
