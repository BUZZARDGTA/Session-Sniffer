"""Crawler request progress dialog, worker thread, and RID picker for the Looky System."""

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import TYPE_CHECKING, ClassVar, cast, override

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
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.looky_text import LOOKY_TITLE
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_BODY_LABEL_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_CRAWLER_LOG_STYLESHEET,
    LOOKY_LIST_WIDGET_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
)
from session_sniffer.guis.tables_player_actions._looky_helpers import (
    build_looky_progress_widgets,
    check_looky_prerequisites,
)
from session_sniffer.guis.utils import ElidedTextTooltipDelegate, set_dialog_window_flags
from session_sniffer.networking.looky_system import (
    LookyState,
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    is_terminal_failure_instruction_status,
    send_crawler_instruction,
    send_crawlme_instruction,
    watch_instruction_status,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player


class _CrawlerSendWorker(CrashingQThread):
    """Pre-flight thread: sends the crawler instruction and emits the tracking ID, a rate-limit wait, or an error."""

    send_succeeded: Signal = Signal(str)  # tracking_id
    send_rate_limited: Signal = Signal(int, str)  # (wait_seconds, message)
    send_failed: Signal = Signal(str)  # error message

    def __init__(self, send_fn: Callable[[], str], parent: QWidget) -> None:
        super().__init__(parent)
        self._send_fn = send_fn

    @override
    def _run(self) -> None:
        """Invoke the send function and emit the result."""
        try:
            tracking_id = self._send_fn()
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                self.send_rate_limited.emit(extract_rate_limit_wait_seconds(e), extract_rate_limit_message(e))
            else:
                status_code = e.response.status_code if e.response is not None else '?'
                self.send_failed.emit(f'API error: HTTP {status_code}')
            return
        except requests.RequestException as e:
            self.send_failed.emit(f'Connection error: {e}')
            return
        except KeyError:
            self.send_failed.emit('Unexpected API response: missing trackingId.')
            return
        self.send_succeeded.emit(tracking_id)


class _CrawlerWatchWorker(CrashingQThread):
    """Background thread that streams SSE status updates for a known tracking ID."""

    status_updated: Signal = Signal(str, object)  # (status, result: str | None)
    request_completed: Signal = Signal()
    request_failed: Signal = Signal(str)  # error message

    def __init__(self, tracking_id: str, api_key: str) -> None:
        super().__init__()
        self._tracking_id = tracking_id
        self._api_key = api_key

    @override
    def _run(self) -> None:
        """Stream SSE status events until the instruction completes, fails, or is cancelled."""
        last_status = ''
        failure_message: str | None = None
        try:
            for status, result in watch_instruction_status(
                self._tracking_id,
                self._api_key,
                should_cancel=self.isInterruptionRequested,
            ):
                if self.isInterruptionRequested():
                    return
                last_status = status
                self.status_updated.emit(status, result)
        except requests.HTTPError as e:
            if self.isInterruptionRequested():
                return
            if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                message = extract_rate_limit_message(e)
                wait_seconds = extract_rate_limit_wait_seconds(e)
                failure_message = f'Rate limited during status stream: {message}. Try again in {wait_seconds} second{pluralize(wait_seconds)}.'
            else:
                status_code = e.response.status_code if e.response is not None else '?'
                failure_message = f'API error while watching status: HTTP {status_code}'
        except requests.RequestException as e:
            if self.isInterruptionRequested():
                return
            failure_message = f'Connection error while watching status: {e}'

        if self.isInterruptionRequested():
            return
        if failure_message is not None:
            self.request_failed.emit(failure_message)
            return
        if is_terminal_failure_instruction_status(last_status):
            self.request_failed.emit(f'Instruction ended with status: {last_status}')
            return
        self.request_completed.emit()


class _CrawlerRequestDialog(QDialog):
    """Non-modal crawler dialog: sends the instruction (auto-retrying on rate limit) then streams SSE status."""

    # Tracks the currently-open crawler dialogs, keyed by request, so re-invoking the action restores
    # the existing (possibly minimized) window instead of opening a duplicate and sending a new crawl.
    _open_dialogs: ClassVar[dict[str, _CrawlerRequestDialog]] = {}

    # Workers whose dialog closed while they were still running. Kept referenced here (parent-less) so
    # they are not garbage-collected mid-run, and removed once they finish on their own and self-delete.
    _detached_workers: ClassVar[set[CrashingQThread]] = set()

    def __init__(self, parent: QWidget, request: _CrawlerRequest) -> None:
        super().__init__(parent)
        self._request = request
        self._registry_key = request.registry_key
        self._watch_worker: _CrawlerWatchWorker | None = None
        self._send_worker: _CrawlerSendWorker | None = None
        self._retry_remaining = 0
        self._rate_limit_message = ''
        _CrawlerRequestDialog._open_dialogs[request.registry_key] = self

        set_dialog_window_flags(self)
        self.setWindowTitle(LOOKY_TITLE)
        self.setMinimumSize(500, 360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QLabel(f'🤖  Crawler Request — {request.display_name}')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(header)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setPlaceholderText('Sending request...')
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
            cancel_button.setToolTip('Stop the crawler request and close this window.')
            cancel_button.clicked.connect(self.close)

        self._widgets.try_again_button.clicked.connect(self._send_now)

        self._retry_timer = QTimer(self)
        self._retry_timer.setInterval(1000)
        self._retry_timer.timeout.connect(self._tick_retry_countdown)

        self._maybe_send()

    @classmethod
    def restore_existing(cls, registry_key: str) -> bool:
        """Restore and raise an already-open dialog for *registry_key*; return True if one existed."""
        existing = cls._open_dialogs.get(registry_key)
        if existing is None:
            return False
        existing.showNormal()
        existing.raise_()
        existing.activateWindow()
        return True

    @classmethod
    def _detach_and_release(cls, worker: CrashingQThread) -> None:
        """Detach a still-running *worker* so its dialog can close without freezing the GUI.

        Closing a streaming socket does not reliably unblock a thread already blocked in `recv()` on
        Windows, so waiting on the worker here could hang the GUI for minutes. Instead the worker's
        signals are dropped (so no queued slot fires against the closing dialog) and it is kept
        referenced, parent-less, until it finishes on its own, at which point it is scheduled for deletion.
        """
        with contextlib.suppress(TypeError, RuntimeError):
            cast('Any', worker).disconnect()
        worker.setParent(None)
        cls._detached_workers.add(worker)

        def _release() -> None:
            cls._detached_workers.discard(worker)
            worker.deleteLater()

        worker.finished.connect(_release)

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
        self._log.clear()
        self._log.setPlaceholderText('Sending request...')
        self._widgets.progress_bar.show()
        self._widgets.status_label.hide()
        self._widgets.try_again_button.hide()
        self._widgets.try_again_button.setText('Try Again')
        worker = _CrawlerSendWorker(self._request.send_fn, self)
        worker.send_succeeded.connect(self._on_send_succeeded)
        worker.send_rate_limited.connect(self._on_send_rate_limited)
        worker.send_failed.connect(self._show_failed)
        self._send_worker = worker
        worker.start()

    def _on_send_succeeded(self, tracking_id: str) -> None:
        """Send accepted — clear any cooldown and begin streaming SSE status for the returned tracking ID."""
        LookyState.clear_crawler_cooldown()
        self._log.setPlaceholderText('Waiting for response...')
        worker = _CrawlerWatchWorker(tracking_id, self._request.api_key)
        worker.status_updated.connect(self._on_status_updated)
        worker.request_completed.connect(self._on_completed)
        worker.request_failed.connect(self._show_failed)
        worker.setParent(self)
        self._watch_worker = worker
        worker.start()

    def _on_send_rate_limited(self, wait_seconds: int, message: str) -> None:
        """Rate limited by the server — record the cooldown locally and show a countdown that auto-retries."""
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
            f'<span style="color: #fbbf24; font-weight: 600;">⏳ {self._rate_limit_message} Automatically retrying in {self._retry_remaining} {seconds_word}…</span>',
        )

    # ------------------------------------------------------------------
    # Watch (SSE status stream)
    # ------------------------------------------------------------------

    def _on_status_updated(self, status: str, result: object) -> None:
        """Append a timestamped SSE status line to the log."""
        ts = datetime.now(tz=UTC).astimezone().strftime('%H:%M:%S')
        line = f'[{ts}]  ● {status}' if result is None else f'[{ts}]  ● {status}: {result}'
        self._log.appendPlainText(line)

    def _on_completed(self) -> None:
        """The crawler instruction completed successfully."""
        self._retry_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText('<span style="color: #4ade80; font-weight: 600;">✓ Completed</span>')
        self._widgets.status_label.show()
        self._log.setPlaceholderText('')
        if self._request.on_completed is not None:
            self._request.on_completed()

    def _show_failed(self, message: str) -> None:
        """Show a failure with a manual Try Again button (used for both send and watch failures)."""
        self._retry_timer.stop()
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">✗ Failed: {message}</span>')
        self._widgets.status_label.show()
        self._widgets.try_again_button.setText('Try Again')
        self._widgets.try_again_button.show()
        self._log.setPlaceholderText('')

    # ------------------------------------------------------------------
    # Lifetime / cleanup
    # ------------------------------------------------------------------

    def _cancel_and_detach_workers(self) -> None:
        """Stop the retry timer and interrupt/detach any still-running workers. Idempotent."""
        self._retry_timer.stop()
        if self._watch_worker is not None:
            if self._watch_worker.isRunning():
                self._watch_worker.requestInterruption()
                _CrawlerRequestDialog._detach_and_release(self._watch_worker)
            self._watch_worker = None
        if self._send_worker is not None:
            if self._send_worker.isRunning():
                _CrawlerRequestDialog._detach_and_release(self._send_worker)
            self._send_worker = None

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Cancel and detach the background workers so the dialog closes instantly without freezing."""
        _CrawlerRequestDialog._open_dialogs.pop(self._registry_key, None)
        self._cancel_and_detach_workers()
        super().closeEvent(event)

    @override
    def reject(self) -> None:
        """Cancel the crawler and close (Escape / Cancel button), cleaning up workers first.

        Calls `super().reject()` (which hides via `done()`), never `self.close()` — closing would
        re-enter `QDialog.closeEvent`, which itself calls `reject()`, causing infinite recursion.
        """
        _CrawlerRequestDialog._open_dialogs.pop(self._registry_key, None)
        self._cancel_and_detach_workers()
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

        header = QLabel('🤖  Crawler Request — Select Rockstar ID')
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
    send_fn: Callable[[], str]
    on_completed: Callable[[], None] | None = None


def _start_crawler_send(parent: QWidget, request: _CrawlerRequest) -> None:
    """Open the crawler request dialog for *request* (or restore it if already open).

    The dialog itself sends the instruction and shows progress, so a rate-limited or failed send still
    opens the window (with a countdown auto-retry and a manual retry button) instead of a dead-end
    warning box.
    """
    if _CrawlerRequestDialog.restore_existing(request.registry_key):
        return
    _CrawlerRequestDialog(parent, request).show()


def show_crawler_request(parent: QWidget, player: Player) -> None:
    """Validate and start a Looky System crawler instruction for `player`; open a crawler request dialog on success."""
    api_key = check_looky_prerequisites(parent)
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

    display_name = next((name for name, r in entries if r == rid), player.ip)

    def _on_crawl_completed() -> None:
        with player.looky_system.lock:
            player.looky_system.needs_refresh = True

    _start_crawler_send(
        parent,
        _CrawlerRequest(
            display_name=display_name,
            api_key=api_key,
            registry_key=f'crawler:{rid}',
            send_fn=lambda: send_crawler_instruction(rid, api_key),
            on_completed=_on_crawl_completed,
        ),
    )


def show_crawlme_request(parent: QWidget) -> None:
    """Validate and start a Looky System crawlme instruction; open a crawler request dialog on success."""
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    def _on_crawl_completed() -> None:
        for player in PlayersRegistry.get_default_sorted_players():
            if player.looky_system.is_initialized:
                with player.looky_system.lock:
                    player.looky_system.needs_refresh = True

    _start_crawler_send(
        parent,
        _CrawlerRequest(
            display_name='My Session',
            api_key=api_key,
            registry_key='crawlme',
            send_fn=lambda: send_crawlme_instruction(api_key),
            on_completed=_on_crawl_completed,
        ),
    )
