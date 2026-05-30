"""LookyLookupDialog and show_looky_lookup helper."""

from typing import TYPE_CHECKING

import requests
from pydantic import ValidationError
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import format_player_display, set_dialog_window_flags
from session_sniffer.networking.looky import lookup_ip
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.models.player import Player


class LookyLookupDialog(PlayerInfoDialogMixin):
    """Non-modal dialog that shows Looky GTA player results for a given IP."""

    def __init__(self, parent: QWidget, player: Player) -> None:
        """Fetch Looky data and display it."""
        super().__init__(parent)
        set_dialog_window_flags(self)

        self.setWindowTitle(f'{TITLE} - Looky Lookup ({format_player_display(player.ip, player.usernames)})')
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._add_header_label(
            outer_layout,
            f'🔎  Looky Lookup \u2014 {format_player_display(player.ip, player.usernames)}',
            '#6b21a8',
            '#7c3aed',
        )

        scroll_layout = self._init_scroll_area(outer_layout)

        if not Settings.looky_api_key or not Settings.looky_enabled:
            no_key_label = QLabel('No Looky API key configured.\nSet one in Settings → Looky System → Authentication.')
            no_key_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            no_key_label.setWordWrap(True)
            scroll_layout.addWidget(no_key_label)
            scroll_layout.addStretch(1)
            self._add_close_button_box(outer_layout)
            return

        if not Settings.looky_api_access:
            no_access_label = QLabel('Your Looky account does not have API access.')
            no_access_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            no_access_label.setWordWrap(True)
            scroll_layout.addWidget(no_access_label)
            scroll_layout.addStretch(1)
            self._add_close_button_box(outer_layout)
            return

        try:
            results = lookup_ip(player.ip, Settings.looky_api_key, Settings.looky_game_version.lower())
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else '?'
            error_label = QLabel(f'Looky API error: HTTP {status}\n{exc}')
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_label.setWordWrap(True)
            scroll_layout.addWidget(error_label)
            scroll_layout.addStretch(1)
            self._add_close_button_box(outer_layout)
            return
        except requests.RequestException as exc:
            error_label = QLabel(f'Looky request failed:\n{exc}')
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_label.setWordWrap(True)
            scroll_layout.addWidget(error_label)
            scroll_layout.addStretch(1)
            self._add_close_button_box(outer_layout)
            return
        except ValidationError as exc:
            error_label = QLabel(f'Looky response format unexpected:\n{exc}')
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_label.setWordWrap(True)
            scroll_layout.addWidget(error_label)
            scroll_layout.addStretch(1)
            self._add_close_button_box(outer_layout)
            return

        if not results:
            empty_label = QLabel('No players found for this IP on Looky.')
            empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            scroll_layout.addWidget(empty_label)
            scroll_layout.addStretch(1)
            self._add_close_button_box(outer_layout)
            return

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
    """Open a `LookyLookupDialog` for *player* (non-modal)."""
    dialog = LookyLookupDialog(parent, player)
    dialog.show()
