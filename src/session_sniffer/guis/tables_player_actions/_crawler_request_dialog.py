"""Crawler request progress dialog, worker thread, and RID picker for the Looky System."""

from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import TYPE_CHECKING, override

import requests
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
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
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_CRAWLER_LOG_STYLESHEET,
)
from session_sniffer.guis.tables_player_actions._looky_helpers import (
    build_looky_progress_widgets,
    check_looky_prerequisites,
)
from session_sniffer.guis.utils import set_dialog_window_flags
from session_sniffer.networking.looky_system import (
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    is_terminal_failure_instruction_status,
    send_crawler_instruction,
    send_crawlme_instruction,
    watch_instruction_status,
)
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player


class _CrawlerSendWorker(CrashingQThread):
    """Pre-flight thread: sends the crawler instruction and emits the tracking ID or an error."""

    send_succeeded: pyqtSignal = pyqtSignal(str)  # tracking_id
    send_failed: pyqtSignal = pyqtSignal(str)  # error message

    def __init__(self, send_fn: Callable[[], str], parent: QWidget) -> None:
        super().__init__(parent)
        self._send_fn = send_fn

    @override
    def _run(self) -> None:
        """Invoke the send function and emit the result."""
        try:
            tracking_id = self._send_fn()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                msg = extract_rate_limit_message(exc)
                wait = extract_rate_limit_wait_seconds(exc)
                self.send_failed.emit(f'Rate limited: {msg}. Try again in {wait}s.')
            else:
                code = exc.response.status_code if exc.response is not None else '?'
                self.send_failed.emit(f'API error: HTTP {code}')
            return
        except requests.RequestException as exc:
            self.send_failed.emit(f'Connection error: {exc}')
            return
        except KeyError:
            self.send_failed.emit('Unexpected API response: missing trackingId.')
            return
        self.send_succeeded.emit(tracking_id)


class _CrawlerWatchWorker(CrashingQThread):
    """Background thread that streams SSE status updates for a known tracking ID."""

    status_updated: pyqtSignal = pyqtSignal(str, object)  # (status, result: str | None)
    request_completed: pyqtSignal = pyqtSignal()
    request_failed: pyqtSignal = pyqtSignal(str)  # error message

    def __init__(self, tracking_id: str, api_key: str) -> None:
        super().__init__()
        self._tracking_id = tracking_id
        self._api_key = api_key

    @override
    def _run(self) -> None:
        """Stream SSE status events until the instruction completes or fails."""
        last_status = ''
        try:
            for status, result in watch_instruction_status(self._tracking_id, self._api_key):
                last_status = status
                self.status_updated.emit(status, result)
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                msg = extract_rate_limit_message(exc)
                wait = extract_rate_limit_wait_seconds(exc)
                self.request_failed.emit(f'Rate limited during status stream: {msg}. Try again in {wait}s.')
            else:
                code = exc.response.status_code if exc.response is not None else '?'
                self.request_failed.emit(f'API error while watching status: HTTP {code}')
            return
        except requests.RequestException as exc:
            self.request_failed.emit(f'Connection error while watching status: {exc}')
            return

        if is_terminal_failure_instruction_status(last_status):
            self.request_failed.emit(f'Instruction canceled (status: {last_status})')
            return

        self.request_completed.emit()


class _RIDPickerDialog(QDialog):
    """Modal dialog for selecting one Rockstar ID when a player has multiple."""

    def __init__(self, parent: QWidget, entries: list[tuple[str, int]]) -> None:
        super().__init__(parent)
        self.setWindowTitle(LOOKY_TITLE)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setMinimumWidth(320)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        label = QLabel('Multiple Rockstar IDs found for this player.\n\nSelect one to request the crawler:')
        label.setWordWrap(True)
        layout.addWidget(label)

        self._list = QListWidget()
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
        layout.addWidget(button_box)

    def selected_rid(self) -> int | None:
        """Return the currently selected RID, or `None` if nothing is selected."""
        item = self._list.currentItem()
        if item is None:
            return None
        return int(item.data(Qt.ItemDataRole.UserRole))

    @staticmethod
    def pick_rid(parent: QWidget, entries: list[tuple[str, int]]) -> int | None:
        """Show the picker dialog and return the chosen RID, or `None` if canceled."""
        dialog = _RIDPickerDialog(parent, entries)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.selected_rid()


@dataclass
class _WatchConfig:
    """Groups the tracking ID and API key needed to start a `_CrawlerWatchWorker`."""

    tracking_id: str
    api_key: str


def _build_crawler_request_dialog(
    parent: QWidget,
    display_name: str,
    watch_config: _WatchConfig,
    send_fn: Callable[[], str],
    on_completed: Callable[[], None] | None = None,
) -> QDialog:
    """Build and wire a non-modal dialog that shows live SSE status updates for a Looky System crawler request."""
    dialog = QDialog(parent)
    set_dialog_window_flags(dialog)
    dialog.setWindowTitle(LOOKY_TITLE)
    dialog.setMinimumSize(500, 360)

    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(8)

    header = QLabel(f'🤖  Crawler Request — {display_name}')
    header.setAlignment(Qt.AlignmentFlag.AlignCenter)
    header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
    layout.addWidget(header)

    log = QPlainTextEdit()
    log.setReadOnly(True)
    log.setPlaceholderText('Waiting for response...')
    log.setStyleSheet(LOOKY_CRAWLER_LOG_STYLESHEET)
    layout.addWidget(log)

    widgets = build_looky_progress_widgets(layout, dialog)

    def _on_status_updated(status: str, result: object) -> None:
        ts = datetime.now(tz=UTC).astimezone().strftime('%H:%M:%S')
        line = f'[{ts}]  \u25cf {status}' if result is None else f'[{ts}]  \u25cf {status}: {result}'
        log.appendPlainText(line)

    def _on_completed() -> None:
        widgets.progress_bar.hide()
        widgets.status_label.setText('<span style="color: #4ade80; font-weight: 600;">✓ Completed</span>')
        widgets.status_label.show()
        if on_completed is not None:
            on_completed()

    def _on_failed(msg: str) -> None:
        widgets.progress_bar.hide()
        widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">\u2717 Failed: {msg}</span>')
        widgets.status_label.show()
        widgets.try_again_btn.show()

    def _on_try_again() -> None:
        log.clear()
        widgets.progress_bar.show()
        widgets.status_label.hide()
        widgets.try_again_btn.hide()
        retry_send_worker = _CrawlerSendWorker(send_fn, dialog)

        def _on_retry_send_failed(msg: str) -> None:
            widgets.progress_bar.hide()
            widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">\u2717 Failed: {msg}</span>')
            widgets.status_label.show()
            widgets.try_again_btn.show()

        def _on_retry_send_succeeded(new_tracking_id: str) -> None:
            watch_worker = _CrawlerWatchWorker(new_tracking_id, watch_config.api_key)
            watch_worker.status_updated.connect(_on_status_updated)
            watch_worker.request_completed.connect(_on_completed)
            watch_worker.request_failed.connect(_on_failed)
            watch_worker.setParent(dialog)
            watch_worker.start()

        retry_send_worker.send_failed.connect(_on_retry_send_failed)
        retry_send_worker.send_succeeded.connect(_on_retry_send_succeeded)
        retry_send_worker.setParent(dialog)
        retry_send_worker.start()

    widgets.try_again_btn.clicked.connect(_on_try_again)

    worker = _CrawlerWatchWorker(watch_config.tracking_id, watch_config.api_key)
    worker.status_updated.connect(_on_status_updated)
    worker.request_completed.connect(_on_completed)
    worker.request_failed.connect(_on_failed)
    worker.setParent(dialog)
    worker.start()

    return dialog


def _start_crawler_send(parent: QWidget, display_name: str, send_fn: Callable[[], str], api_key: str, on_completed: Callable[[], None] | None = None) -> None:
    """Start a pre-flight send worker; open a crawler request dialog only on success."""
    worker = _CrawlerSendWorker(send_fn, parent)

    def _on_send_failed(msg: str) -> None:
        QMessageBox.warning(parent, LOOKY_TITLE, msg)

    worker.send_failed.connect(_on_send_failed)

    def _open_dialog(tracking_id: str) -> None:
        _build_crawler_request_dialog(parent, display_name, _WatchConfig(tracking_id, api_key), send_fn, on_completed).show()

    worker.send_succeeded.connect(_open_dialog)
    worker.start()


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
    rid = (
        player.looky_system.rockstarids[0]
        if len(player.looky_system.rockstarids) == 1
        else _RIDPickerDialog.pick_rid(parent, entries)
    )
    if rid is None:
        return

    display_name = next((name for name, r in entries if r == rid), player.ip)

    def _on_crawl_completed() -> None:
        with player.looky_system.lock:
            player.looky_system.needs_refresh = True

    _start_crawler_send(
        parent,
        display_name,
        lambda: send_crawler_instruction(rid, api_key),
        api_key,
        on_completed=_on_crawl_completed,
    )


def show_crawlme_request(parent: QWidget) -> None:
    """Validate and start a Looky System crawlme instruction; open a crawler request dialog on success."""
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    def _on_crawl_completed() -> None:
        for p in PlayersRegistry.get_default_sorted_players():
            if p.looky_system.is_initialized:
                with p.looky_system.lock:
                    p.looky_system.needs_refresh = True

    _start_crawler_send(parent, 'My Session', lambda: send_crawlme_instruction(api_key), api_key, on_completed=_on_crawl_completed)
