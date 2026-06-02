"""LookyLookupDialog and show_looky_lookup helper."""

import time
from http import HTTPStatus
from typing import TYPE_CHECKING, override

import requests
from pydantic import ValidationError
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.looky_text import LOOKY_TITLE
from session_sniffer.guis.tables_player_actions._looky_helpers import (
    build_looky_progress_widgets,
    check_looky_prerequisites,
)
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import set_dialog_window_flags
from session_sniffer.networking.looky import (
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    lookup_ip,
)
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.models.looky import LookyPlayer
    from session_sniffer.models.player import Player


class _LookyFetchWorker(CrashingQThread):
    """Background thread that fetches Looky IP lookup results for a given IP address."""

    fetch_succeeded: pyqtSignal = pyqtSignal()
    fetch_not_found: pyqtSignal = pyqtSignal()
    fetch_failed: pyqtSignal = pyqtSignal(str)  # error message

    def __init__(self, ip: str, api_key: str) -> None:
        super().__init__()
        self._ip = ip
        self._api_key = api_key
        self.results: list[LookyPlayer] = []

    @override
    def _run(self) -> None:
        """Fetch Looky lookup results and emit the appropriate outcome signal."""
        try:
            results = lookup_ip(self._ip, self._api_key, Settings.looky_game_version.lower())
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == HTTPStatus.NOT_FOUND:
                self.fetch_not_found.emit()
            elif exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                msg = extract_rate_limit_message(exc)
                wait = extract_rate_limit_wait_seconds(exc)
                self.fetch_failed.emit(f'Rate limited: {msg}. Try again in {wait}s.')
            else:
                code = exc.response.status_code if exc.response is not None else '?'
                self.fetch_failed.emit(f'Looky API error: HTTP {code}')
            return
        except requests.RequestException as exc:
            self.fetch_failed.emit(f'Looky System request failed: {exc}')
            return
        except ValidationError as exc:
            self.fetch_failed.emit(f'Looky System response format unexpected: {exc}')
            return
        self.results = results
        self.fetch_succeeded.emit()


class LookyLookupDialog(PlayerInfoDialogMixin):
    """Non-modal dialog that renders pre-fetched Looky System player results."""

    def __init__(self, parent: QWidget, player: Player, results: list[LookyPlayer]) -> None:
        """Render *results* for *player*."""
        super().__init__(parent)
        set_dialog_window_flags(self)

        self.setWindowTitle(LOOKY_TITLE)
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._add_header_label(
            outer_layout,
            f'🔎  Looky Lookup \u2014 {player.ip}',
            '#6b21a8',
            '#7c3aed',
        )

        scroll_layout = self._init_scroll_area(outer_layout)

        for entry in results:
            group, form = self._make_group(f'\U0001f3ae  {entry.name}', accent='#6b21a8')
            self._add_row(form, 'Rockstar ID', str(entry.rockstarid))
            self._add_row(form, 'Username', entry.name)
            self._add_row(form, 'Last Seen', entry.lastSeen.strftime('%Y-%m-%d %H:%M:%S UTC'))
            self._add_row(form, 'Last Country', entry.lastCountry)
            self._add_row(form, 'Modder', 'Yes' if entry.isModder else 'No')
            self._add_row(form, 'Enhanced', 'Yes' if entry.isEnhanced else 'No')
            self._add_row(form, 'Legacy', 'Yes' if entry.isLegacy else 'No')
            self._add_row(form, 'VPN', 'Yes' if entry.isVpn else 'No')
            scroll_layout.addWidget(group)

        scroll_layout.addStretch(1)
        self._add_close_button_box(outer_layout)


def show_looky_lookup(parent: QWidget, player: Player) -> None:
    """Validate and fetch Looky IP lookup results for *player*; show a progress dialog, then open the results."""
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    dialog = QDialog(parent)
    set_dialog_window_flags(dialog)
    dialog.setWindowTitle(LOOKY_TITLE)
    dialog.setMinimumSize(400, 160)

    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(8)

    header = QLabel(f'🔎  Looky Lookup \u2014 {player.ip}')
    header.setAlignment(Qt.AlignmentFlag.AlignCenter)
    header.setStyleSheet('font-size: 14px; font-weight: 600; padding: 4px;')
    layout.addWidget(header)

    widgets = build_looky_progress_widgets(layout, dialog)

    def _on_fetch_not_found() -> None:
        widgets.progress_bar.hide()
        widgets.status_label.setText(
            f'<span style="color: #60a5fa; font-weight: 600;">\u2139 No results found</span>'
            f"<br><span>We couldn't find any players matching &quot;{player.ip}&quot;</span>",
        )
        widgets.status_label.show()

    def _on_fetch_failed(msg: str) -> None:
        widgets.progress_bar.hide()
        widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">\u2717 Failed: {msg}</span>')
        widgets.status_label.show()
        widgets.try_again_btn.show()

    def _do_fetch() -> None:
        worker = _LookyFetchWorker(player.ip, api_key)

        def _on_fetch_succeeded() -> None:
            with player.looky.lock:
                player.looky.usernames = [p.name for p in worker.results]
                player.looky.rockstarids = [p.rockstarid for p in worker.results]
                player.looky.needs_refresh = False
                player.looky.last_fetched_at = time.monotonic()
                player.looky.is_initialized = True

            if not worker.results:
                widgets.progress_bar.hide()
                widgets.status_label.setText('<span style="color: #60a5fa; font-weight: 600;">\u2139 No players found for this IP on Looky System.</span>')
                widgets.status_label.show()
                return

            dialog.accept()
            LookyLookupDialog(parent, player, worker.results).show()

        worker.fetch_succeeded.connect(_on_fetch_succeeded)
        worker.fetch_not_found.connect(_on_fetch_not_found)
        worker.fetch_failed.connect(_on_fetch_failed)
        worker.setParent(dialog)
        worker.start()

    def _on_try_again() -> None:
        widgets.status_label.hide()
        widgets.try_again_btn.hide()
        widgets.progress_bar.show()
        _do_fetch()

    widgets.try_again_btn.clicked.connect(_on_try_again)
    _do_fetch()
    dialog.show()
