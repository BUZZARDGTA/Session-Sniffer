"""Shared Looky System pre-flight validation for player action dialogs."""

import html
import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, override

import requests
from pydantic import ValidationError
from PySide6.QtCore import QRectF, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.looky_text import (
    LOOKY_WARNING_API_ACCESS_MISSING,
    LOOKY_WARNING_API_KEY_MISSING,
    LOOKY_WARNING_DISABLED,
    LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING,
    LOOKY_WARNING_RESTRICTED_NOT_LOCAL,
    get_looky_restriction,
    get_looky_title,
)
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
    LOOKY_STATUS_LABEL_STYLESHEET,
)
from session_sniffer.guis.theming import themed_qss
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.player import Player
from session_sniffer.networking.looky_system import (
    LOOKY_PHASE_IP_BATCHES,
    LOOKY_PHASE_PLAYER_PROFILES,
    LOOKY_PHASE_RESOLVE_USERNAMES,
    LookyState,
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    get_cached_rid_for_username,
    get_looky_user_url,
    get_rid_by_username,
)
from session_sniffer.player.registry import SessionTracker
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import record_looky_db_correlation
from session_sniffer.player.userip_loader import update_userip_databases
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Sequence

    from PySide6.QtGui import QHideEvent, QPaintEvent, QShowEvent

    from session_sniffer.guis.tables_player_actions._ip_lookup_dialog import StandaloneIPLookup

_PROGRESS_BAR_HEIGHT = 14
_INDETERMINATE_FRAME_INTERVAL_MS = 16
_INDETERMINATE_CYCLE_SECONDS = 1.4
_INDETERMINATE_CHUNK_RATIO = 0.42
_LOOKY_TRACK_BACKGROUND = QColor('#1a1325')
_LOOKY_TRACK_BORDER = QColor('#3b2060')
_LOOKY_CHUNK_GRADIENT_STOPS: tuple[tuple[float, QColor], ...] = (
    (0.0, QColor('#6d28d9')),
    (0.5, QColor('#a855f7')),
    (1.0, QColor('#ec4899')),
)

_PHASE_DETAILS: dict[str, str] = {
    LOOKY_PHASE_IP_BATCHES: 'Checking which usernames Looky has recorded on your database IP addresses.',
    LOOKY_PHASE_RESOLVE_USERNAMES: 'Finding the Rockstar ID for each username in your database.',
    LOOKY_PHASE_PLAYER_PROFILES: 'Finding all IP addresses and usernames linked to those Rockstar IDs.',
}


class LookyProgressBar(QProgressBar):
    """Custom-painted Looky progress bar with width-independent indeterminate animation.

    Qt's `QStyleSheetStyle` animates indeterminate `QProgressBar` widgets using an
    unbounded step counter modulo the widget width, which causes the chunk to jump
    rapidly back and forth whenever a dialog is resized after staying open. Driving
    the marquee from a normalized `[0.0, 1.0)` wall-clock phase avoids any speedup
    or jitter during window resizes.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Looky progress bar in indeterminate mode."""
        super().__init__(parent)
        self._phase: float = 0.0
        self._last_tick: float | None = None
        self._animation_timer = QTimer(self)
        self._animation_timer.setInterval(_INDETERMINATE_FRAME_INTERVAL_MS)
        self._animation_timer.timeout.connect(self._advance_animation)
        self.setTextVisible(False)
        self.setFixedHeight(_PROGRESS_BAR_HEIGHT)
        self.setRange(0, 0)

    def _is_indeterminate(self) -> bool:
        return not self.minimum() and not self.maximum()

    def _sync_animation_state(self) -> None:
        if self.isVisible() and self._is_indeterminate():
            if not self._animation_timer.isActive():
                self._last_tick = time.monotonic()
                self._animation_timer.start()
        else:
            if self._animation_timer.isActive():
                self._animation_timer.stop()
            self._last_tick = None

    def _advance_animation(self) -> None:
        now = time.monotonic()
        if self._last_tick is not None:
            elapsed = max(0.0, now - self._last_tick)
            self._phase = (self._phase + elapsed / _INDETERMINATE_CYCLE_SECONDS) % 1.0
        self._last_tick = now
        self.update()

    @override
    def setRange(self, minimum: int, maximum: int) -> None:
        super().setRange(minimum, maximum)
        self._sync_animation_state()
        self.update()

    @override
    def setMinimum(self, minimum: int) -> None:
        super().setMinimum(minimum)
        self._sync_animation_state()
        self.update()

    @override
    def setMaximum(self, maximum: int) -> None:
        super().setMaximum(maximum)
        self._sync_animation_state()
        self.update()

    @override
    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self._sync_animation_state()

    @override
    def hideEvent(self, event: QHideEvent) -> None:
        super().hideEvent(event)
        self._sync_animation_state()

    @override
    def paintEvent(self, arg__1: QPaintEvent) -> None:
        del arg__1
        track_rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        track_radius = track_rect.height() / 2.0
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setBrush(_LOOKY_TRACK_BACKGROUND)
            painter.setPen(QPen(_LOOKY_TRACK_BORDER, 1.0))
            painter.drawRoundedRect(track_rect, track_radius, track_radius)

            inner_rect = track_rect.adjusted(1.0, 1.0, -1.0, -1.0)
            if inner_rect.width() <= 0.0 or inner_rect.height() <= 0.0:
                return
            inner_radius = max(0.0, inner_rect.height() / 2.0)
            is_rtl = self.layoutDirection() == Qt.LayoutDirection.RightToLeft

            if self._is_indeterminate():
                chunk_width = inner_rect.width() * _INDETERMINATE_CHUNK_RATIO
                travel = inner_rect.width() + chunk_width
                chunk_left = (inner_rect.right() - self._phase * travel) if is_rtl else (inner_rect.left() - chunk_width + self._phase * travel)
            else:
                value_range = self.maximum() - self.minimum()
                progress_ratio = max(0.0, min(1.0, (self.value() - self.minimum()) / value_range)) if value_range > 0 else 0.0
                chunk_width = inner_rect.width() * progress_ratio
                if chunk_width <= 0.0:
                    return
                chunk_left = (inner_rect.right() - chunk_width) if is_rtl else inner_rect.left()

            chunk_rect = QRectF(chunk_left, inner_rect.top(), chunk_width, inner_rect.height())
            clip_path = QPainterPath()
            clip_path.addRoundedRect(inner_rect, inner_radius, inner_radius)
            chunk_path = QPainterPath()
            chunk_path.addRoundedRect(chunk_rect, inner_radius, inner_radius)

            gradient_start = chunk_rect.right() if is_rtl else chunk_rect.left()
            gradient_end = chunk_rect.left() if is_rtl else chunk_rect.right()
            linear_gradient = QLinearGradient(gradient_start, 0.0, gradient_end, 0.0)
            for stop_point, stop_color in _LOOKY_CHUNK_GRADIENT_STOPS:
                linear_gradient.setColorAt(stop_point, stop_color)

            painter.save()
            painter.setClipPath(clip_path)
            painter.fillPath(chunk_path, linear_gradient)
            painter.restore()
        finally:
            painter.end()


@dataclass(frozen=True, slots=True)
class LookyProgressWidgets:
    """The three mutable widgets built by `build_looky_progress_widgets`."""

    progress_bar: LookyProgressBar
    status_label: QLabel
    try_again_button: QPushButton
    button_box: QDialogButtonBox


def build_looky_progress_widgets(layout: QVBoxLayout, dialog: QDialog) -> LookyProgressWidgets:
    """Add a shared progress / status / try-again / close block to `layout`.

    Appends an indeterminate `LookyProgressBar`, a hidden `QLabel` for status text,
    a hidden `QPushButton` for retries, and a Close `QDialogButtonBox` wired to
    `dialog.reject`. Returns the mutable widgets so callers can hide,
    show, and update them from signal handlers.
    """
    progress_bar = LookyProgressBar()
    layout.addWidget(progress_bar)

    status_label = QLabel()
    status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    status_label.setTextFormat(Qt.TextFormat.RichText)
    status_label.setWordWrap(True)
    status_label.setStyleSheet(LOOKY_STATUS_LABEL_STYLESHEET)
    status_label.hide()
    layout.addWidget(status_label)

    try_again_button = QPushButton(tr('Try Again'))
    try_again_button.setStyleSheet(LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET)
    try_again_button.setCursor(Qt.CursorShape.PointingHandCursor)
    try_again_button.hide()
    layout.addWidget(try_again_button)

    button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    button_box.rejected.connect(dialog.reject)
    close_button = button_box.button(QDialogButtonBox.StandardButton.Close)
    if close_button:
        close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        close_button.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
    layout.addWidget(button_box)

    return LookyProgressWidgets(progress_bar, status_label, try_again_button, button_box)


class LookyRefreshLoadingDialog(QDialog):
    """Modal dialog shown while batch-lookup is running in the background."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle(get_looky_title())
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)
        self.setMinimumSize(scale_by_ui(420), scale_by_ui(175))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        self._header = QLabel()
        self._header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(self._header)
        self._widgets = build_looky_progress_widgets(layout, self)
        self._last_progress: tuple[str, int, int] | None = None
        self._last_error: str | None = None
        self._refresh_language_texts()
        self._widgets.status_label.show()
        register_language_refresh(self, self._refresh_language_texts)

    def _refresh_language_texts(self) -> None:
        self.setWindowTitle(get_looky_title())
        self._header.setText(f'\U0001f441  {tr("Looky — Fetching...")}')
        if self._last_error is not None:
            self.show_error(self._last_error)
        elif self._last_progress is not None:
            self.update_progress(*self._last_progress)
        else:
            preparing = html.escape(tr('Preparing Looky System lookup...'))
            collecting = html.escape(tr('Collecting database IP addresses and usernames to query.'))
            self._widgets.status_label.setText(
                themed_qss(
                    f'<span style="color: @lock[#d8b4fe]; font-weight: 600;">{preparing}</span>'
                    f'<br><span style="color: @text_muted[#9ca3af]; font-size: 8.5pt;">{collecting}</span>',
                ),
            )

    def update_progress(self, status_text: str, current: int, total: int) -> None:
        """Update the progress bar and status label with the active lookup phase and completion count."""
        self._last_progress = (status_text, current, total)
        self._widgets.progress_bar.setRange(0, max(1, total))
        self._widgets.progress_bar.setValue(current)
        pct = round(current * 100 / total) if total > 0 else 0
        translated_status = status_text
        detail_text = ''
        for phase_label, phase_detail in _PHASE_DETAILS.items():
            if status_text == phase_label:
                translated_status = tr(phase_label)
                detail_text = tr(phase_detail)
                break
            cooldown_prefix = f'{phase_label} (rate limited \u2014 resuming in '
            if status_text.startswith(cooldown_prefix) and status_text.endswith('s)'):
                seconds_part = status_text[len(cooldown_prefix):-2]
                translated_status = tr('{phase} (rate limited — resuming in {seconds}s)', phase=tr(phase_label), seconds=seconds_part)
                detail_text = tr(phase_detail)
                break
        detail_html = f'<br><span style="color: @text_muted[#9ca3af]; font-size: 8.5pt;">{html.escape(detail_text)}</span>' if detail_text else ''
        self._widgets.status_label.setText(
            themed_qss(f'<span style="color: @lock[#d8b4fe]; font-weight: 600;">{html.escape(translated_status)}: <b>{current} / {total}</b> ({pct}%)</span>{detail_html}'),
        )
        self._widgets.status_label.show()

    def show_error(self, message: str) -> None:
        """Hide the progress bar and show the error message."""
        self._last_error = message
        self._widgets.progress_bar.hide()
        failed_text = html.escape(tr('Failed: {message}', message=message))
        self._widgets.status_label.setText(themed_qss(f'<span style="color: #f87171; font-weight: 600;">\u2717 {failed_text}</span>'))
        self._widgets.status_label.show()


def check_looky_prerequisites(parent: QWidget, *, restriction: str | None = None) -> str | None:
    """Validate Looky System prerequisites and return the API key on success.

    Checks (in order):
    - GTA V feature set is active
    - API key is set
    - Looky System is enabled
    - API access is granted
    - Local capture is active
    - Target restriction (`restriction`, as returned by `get_looky_restriction`)

    Returns the API key string when all prerequisites are met, or None after
    displaying a warning for the first unmet prerequisite.
    """
    warning_message: str | None = None
    if not Settings.is_gta5_feature_set():
        warning_message = tr(LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING)
    elif not bool(Settings.looky_api_key):
        warning_message = tr(LOOKY_WARNING_API_KEY_MISSING)
    elif not Settings.looky_enabled:
        warning_message = tr(LOOKY_WARNING_DISABLED)
    elif not LookyState.api_access:
        warning_message = tr(LOOKY_WARNING_API_ACCESS_MISSING)
    elif not CaptureState.is_local_capture():
        warning_message = tr(LOOKY_WARNING_RESTRICTED_NOT_LOCAL)
    elif restriction is not None:
        warning_message = restriction

    if warning_message is not None:
        QMessageBox.warning(parent, get_looky_title(), warning_message)
        return None

    return Settings.looky_api_key


def format_looky_request_error(exc: Exception) -> str:
    """Format a user-facing error message for a Looky System HTTP, network, or validation failure."""
    if isinstance(exc, requests.HTTPError):
        if exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            rate_message = extract_rate_limit_message(exc)
            wait_seconds = extract_rate_limit_wait_seconds(exc)
            if wait_seconds is None:
                return tr('Rate limited: {message}.', message=rate_message)
            return tr_plural(
                'Rate limited: {message}. Try again in {count} second.',
                'Rate limited: {message}. Try again in {count} seconds.',
                wait_seconds,
                message=rate_message,
            )
        status_code = exc.response.status_code if exc.response is not None else '?'
        return tr('Looky System API error: HTTP {status_code}', status_code=status_code)
    if isinstance(exc, requests.RequestException):
        return tr('Looky System request failed: {error}', error=exc)
    return tr('Looky System response format unexpected: {error}', error=exc)


class _LookyUsernameRidWorker(CrashingQThread):
    """Background worker resolving a single username to its Rockstar ID via Looky System."""

    rid_resolved: Signal = Signal(int)
    rid_not_found: Signal = Signal()
    rid_failed: Signal = Signal(str)

    def __init__(self, username: str, api_key: str) -> None:
        super().__init__()
        self.username = username
        self._api_key = api_key

    @override
    def _run(self) -> None:
        try:
            rid = get_rid_by_username(self.username, self._api_key)
        except (requests.RequestException, ValidationError) as e:
            if not self.isInterruptionRequested():
                self.rid_failed.emit(format_looky_request_error(e))
            return
        if self.isInterruptionRequested():
            return
        if rid is not None and rid > 0:
            self.rid_resolved.emit(rid)
        else:
            self.rid_not_found.emit()


_active_rid_workers: set[_LookyUsernameRidWorker] = set()


def close_all_rid_lookup_workers() -> None:
    """Cancel any in-flight username-to-RID Looky lookup workers on application shutdown."""
    for worker in list(_active_rid_workers):
        worker.cancel()
    _active_rid_workers.clear()


def open_looky_profile_by_username(parent: QWidget, player: Player, username: str) -> None:
    """Resolve *username* to its Rockstar ID via Looky System and open the profile URL."""
    cleaned_username = username.strip()
    if not cleaned_username:
        return
    cached_rid = get_cached_rid_for_username(cleaned_username)
    if cached_rid is not None and cached_rid > 0:
        QDesktopServices.openUrl(QUrl(get_looky_user_url(cached_rid)))
        return

    api_key = check_looky_prerequisites(parent, restriction=get_looky_restriction([player]))
    if api_key is None:
        return

    username_cf = cleaned_username.casefold()
    if any(active.username.casefold() == username_cf for active in _active_rid_workers):
        return

    worker = _LookyUsernameRidWorker(cleaned_username, api_key)

    def _on_resolved(rid: int) -> None:
        QDesktopServices.openUrl(QUrl(get_looky_user_url(rid)))

    def _on_not_found() -> None:
        if isValid(parent):
            QMessageBox.information(parent, get_looky_title(), tr('No Looky System profile found for "{username}".', username=cleaned_username))

    def _on_failed(message: str) -> None:
        if isValid(parent):
            QMessageBox.warning(parent, get_looky_title(), tr('Failed: {message}', message=message))

    worker.rid_resolved.connect(_on_resolved)
    worker.rid_not_found.connect(_on_not_found)
    worker.rid_failed.connect(_on_failed)
    _active_rid_workers.add(worker)
    worker.finished.connect(lambda: _active_rid_workers.discard(worker))
    worker.start()


def sync_player_looky_usernames_and_userip(
    player: Player | StandaloneIPLookup,
    player_looky_names: Sequence[str],
    live_update: tuple[Player, Sequence[str]] | None,
    snapshot_updates: Sequence[tuple[Player, Sequence[str]]],
) -> None:
    """Correlate Looky usernames with UserIP databases, re-resolve `userip`, rebuild usernames, and wake the renderer."""
    record_looky_db_correlation(player_looky_names, UserIPDatabases.get_known_username_dbs_cf())
    update_userip_databases()
    player.userip = UserIPDatabases.resolve_userip_for_player(player) if isinstance(player, Player) else UserIPDatabases.resolve_userip(player.ip)
    if live_update is not None:
        live_update[0].userip = UserIPDatabases.resolve_userip_for_player(live_update[0])
    for snapshot_player, _ in snapshot_updates:
        snapshot_player.userip = UserIPDatabases.resolve_userip_for_player(snapshot_player)
    include_looky = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
    player.rebuild_usernames(looky_usernames=player_looky_names if include_looky and player.looky_system.is_initialized else ())
    if live_update is not None:
        live_player, live_names = live_update
        live_player.rebuild_usernames(looky_usernames=live_names if include_looky and live_player.looky_system.is_initialized else ())
        SessionTracker.update_session_player_snapshot(live_player, metadata_only=True)
    for snapshot_player, snap_names in snapshot_updates:
        snapshot_player.rebuild_usernames(looky_usernames=snap_names if include_looky and snapshot_player.looky_system.is_initialized else ())
    if isinstance(player, Player) and live_update is None:
        SessionTracker.update_session_player_snapshot(player, metadata_only=True)
    wake_rendering_core()
