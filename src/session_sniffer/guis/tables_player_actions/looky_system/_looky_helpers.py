"""Shared Looky System pre-flight validation for player action dialogs."""

import html
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING

import requests
from PySide6.QtCore import Qt
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

from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.looky_text import (
    LOOKY_WARNING_API_ACCESS_MISSING,
    LOOKY_WARNING_API_KEY_MISSING,
    LOOKY_WARNING_DISABLED,
    LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING,
    LOOKY_WARNING_RESTRICTED_NOT_LOCAL,
    get_looky_title,
)
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
    LOOKY_PROGRESS_BAR_STYLESHEET,
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

    from session_sniffer.guis.tables_player_actions._ip_lookup_dialog import StandaloneIPLookup

_PHASE_DETAILS: dict[str, str] = {
    LOOKY_PHASE_IP_BATCHES: 'Checking which usernames Looky has recorded on your database IP addresses.',
    LOOKY_PHASE_RESOLVE_USERNAMES: 'Finding the Rockstar ID for each username in your database.',
    LOOKY_PHASE_PLAYER_PROFILES: 'Finding all IP addresses and usernames linked to those Rockstar IDs.',
}


@dataclass(frozen=True, slots=True)
class LookyProgressWidgets:
    """The three mutable widgets built by `build_looky_progress_widgets`."""

    progress_bar: QProgressBar
    status_label: QLabel
    try_again_button: QPushButton
    button_box: QDialogButtonBox


def build_looky_progress_widgets(layout: QVBoxLayout, dialog: QDialog) -> LookyProgressWidgets:
    """Add a shared progress / status / try-again / close block to `layout`.

    Appends an indeterminate `QProgressBar`, a hidden `QLabel` for status text,
    a hidden `QPushButton` for retries, and a Close `QDialogButtonBox` wired to
    `dialog.reject`. Returns the three mutable widgets so callers can hide,
    show, and update them from signal handlers.
    """
    progress_bar = QProgressBar()
    progress_bar.setRange(0, 0)
    progress_bar.setTextVisible(False)
    progress_bar.setFixedHeight(14)
    progress_bar.setStyleSheet(LOOKY_PROGRESS_BAR_STYLESHEET)
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
