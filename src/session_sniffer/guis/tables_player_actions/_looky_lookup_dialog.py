"""LookyLookupDialog and show_looky_lookup helper."""

import time
from http import HTTPStatus
from typing import TYPE_CHECKING, override

import requests
from pydantic import ValidationError
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialogButtonBox,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.looky_text import LOOKY_TITLE
from session_sniffer.guis.stylesheets import LOOKY_ACTION_BUTTON_STYLESHEET, LOOKY_CRAWLER_HEADER_STYLESHEET
from session_sniffer.guis.tables_player_actions._looky_helpers import check_looky_prerequisites
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import set_dialog_window_flags
from session_sniffer.networking.looky_system import (
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    lookup_ip,
)
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.looky_system import LookyPlayer
    from session_sniffer.models.player import Player


class _LookyFetchWorker(CrashingQThread):
    """Background thread that fetches Looky System IP lookup results for a given IP address."""

    fetch_succeeded: Signal = Signal()
    fetch_not_found: Signal = Signal()
    fetch_failed: Signal = Signal(str)  # error message

    def __init__(self, ip: str, api_key: str) -> None:
        super().__init__()
        self._ip = ip
        self._api_key = api_key
        self.results: list[LookyPlayer] = []

    @override
    def _run(self) -> None:
        """Fetch Looky System lookup results and emit the appropriate outcome signal."""
        try:
            results = lookup_ip(self._ip, self._api_key, Settings.looky_game_version.lower())
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTPStatus.NOT_FOUND:
                self.fetch_not_found.emit()
            elif e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                message = extract_rate_limit_message(e)
                wait_seconds = extract_rate_limit_wait_seconds(e)
                self.fetch_failed.emit(f'Rate limited: {message}. Try again in {wait_seconds} second{pluralize(wait_seconds)}.')
            else:
                status_code = e.response.status_code if e.response is not None else '?'
                self.fetch_failed.emit(f'Looky System API error: HTTP {status_code}')
            return
        except requests.RequestException as e:
            self.fetch_failed.emit(f'Looky System request failed: {e}')
            return
        except ValidationError as e:
            self.fetch_failed.emit(f'Looky System response format unexpected: {e}')
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
            f'🔎  Lookup — {player.ip}',
            '#1c0a38',
            '#2e1065',
        ).setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)

        scroll_layout = self._init_scroll_area(outer_layout)

        for entry in results:
            group, form = self._make_group(f'🎮  {entry.name}', accent='#4c1d95')
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
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        close_button = button_box.button(QDialogButtonBox.StandardButton.Close)
        if close_button:
            close_button.setCursor(Qt.CursorShape.PointingHandCursor)
            close_button.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
        outer_layout.addWidget(button_box)


def show_looky_lookup(parent: QWidget, player: Player) -> None:
    """Validate and fetch Looky System IP lookup results for *player*; open a results dialog or show an error."""
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    worker = _LookyFetchWorker(player.ip, api_key)

    def _on_fetch_succeeded() -> None:
        with player.looky_system.lock:
            player.looky_system.usernames = [player.name for player in worker.results]
            player.looky_system.rockstarids = [player.rockstarid for player in worker.results]
            player.looky_system.needs_refresh = False
            player.looky_system.last_fetched_at = time.monotonic()
            player.looky_system.is_initialized = True

        if not worker.results:
            QMessageBox.information(parent, LOOKY_TITLE, 'No players found for this IP on Looky System.')
            return

        LookyLookupDialog(parent, player, worker.results).show()

    def _on_fetch_not_found() -> None:
        QMessageBox.information(parent, LOOKY_TITLE, f'No results found\n\nWe couldn\'t find any players matching "{player.ip}"')

    def _on_fetch_failed(message: str) -> None:
        QMessageBox.warning(parent, LOOKY_TITLE, f'Failed: {message}')

    worker.fetch_succeeded.connect(_on_fetch_succeeded)
    worker.fetch_not_found.connect(_on_fetch_not_found)
    worker.fetch_failed.connect(_on_fetch_failed)
    worker.finished.connect(worker.deleteLater)
    worker.setParent(parent)
    worker.start()
