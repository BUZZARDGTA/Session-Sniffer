"""Looky System menu-building and action handlers mixin for `MainWindow`."""

from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import QMainWindow, QMenu, QMessageBox

from session_sniffer.background import trigger_looky_rescan_all_players
from session_sniffer.guis.looky_text import (
    configure_looky_action,
    get_looky_restriction,
    get_looky_title,
)
from session_sniffer.guis.tables_player_actions import show_crawlme_request
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import check_looky_prerequisites
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import date, datetime

_MOD_ALT = 0x0001
_MOD_CONTROL = 0x0002
_MOD_SHIFT = 0x0004
_MOD_WIN = 0x0008
_MAX_F_KEY_NUMBER = 24

_PORTABLE_KEY_TO_WIN32_VKS: dict[str, tuple[int, ...]] = {
    'backspace': (0x08,), 'tab': (0x09,), 'clear': (0x0C,), 'return': (0x0D,), 'enter': (0x0D,), 'pause': (0x13,), 'capslock': (0x14,),
    'space': (0x20,), 'pgup': (0x21,), 'pgdown': (0x22,), 'end': (0x23,), 'home': (0x24,), 'left': (0x25,),
    'up': (0x26,), 'right': (0x27,), 'down': (0x28,), 'print': (0x2C,), 'ins': (0x2D,), 'del': (0x2E,),
    '!': (0x31,), '@': (0x32,), '#': (0x33,), '$': (0x34,), '%': (0x35,), '^': (0x36,), '&': (0x37,), '(': (0x39,), ')': (0x30,),
    '-': (0x6D, 0xBD), '_': (0xBD,), '.': (0x6E, 0xBE), '/': (0x6F, 0xBF), '?': (0xBF,),
    'numlock': (0x90,), 'scrolllock': (0x91,), ';': (0xBA,), ':': (0xBA,), '=': (0xBB,), ',': (0xBC,), '<': (0xBC,), '>': (0xBE,),
    '`': (0xC0,), '~': (0xC0,), '[': (0xDB,), '{': (0xDB,), '\\': (0xDC,), '|': (0xDC,), ']': (0xDD,), '}': (0xDD,), "'": (0xDE,), '"': (0xDE,),
}


def _resolve_portable_key_vks(portable_key: str, *, mod_flags: int = 0, is_numpad: bool = False) -> tuple[int, ...] | None:
    """Resolve a lowercase portable key string to one or more Win32 virtual-key codes."""
    if portable_key == '*':
        return (0x38, 0x6A) if (mod_flags & _MOD_SHIFT) and not is_numpad else (0x6A,)
    if portable_key == '+':
        return (0x6B, 0xBB) if (mod_flags & _MOD_SHIFT) and not is_numpad else (0x6B,)
    if (mapped := _PORTABLE_KEY_TO_WIN32_VKS.get(portable_key)) is not None:
        return mapped
    if len(portable_key) == 1 and ('a' <= portable_key <= 'z' or '0' <= portable_key <= '9'):
        return (ord(portable_key.upper()),) if 'a' <= portable_key <= 'z' else (ord(portable_key), 0x60 + ord(portable_key) - ord('0'))
    if portable_key.startswith('f') and portable_key[1:].isdigit() and 1 <= (fn_num := int(portable_key[1:])) <= _MAX_F_KEY_NUMBER:
        return (0x70 + fn_num - 1,)
    return None


def parse_win32_hotkey_spec(hotkey: str | None) -> tuple[int, tuple[int, ...]] | None:
    """Translate a portable `QKeySequence` string into `(win32_modifier_flags, primary_vks)`."""
    if hotkey is None or not hotkey:
        return None
    seq = QKeySequence.fromString(hotkey, QKeySequence.SequenceFormat.PortableText)
    portable = seq.toString(QKeySequence.SequenceFormat.PortableText).split(', ', 1)[0].strip().lower()
    if not portable:
        return None

    mod_flags, is_numpad = 0, False
    for _ in range(5):
        if portable.startswith('num+'):
            is_numpad, portable = True, portable[4:]
            continue
        for mod_prefix, flag in (('ctrl+', _MOD_CONTROL), ('shift+', _MOD_SHIFT), ('alt+', _MOD_ALT), ('meta+', _MOD_WIN)):
            if portable.startswith(mod_prefix):
                mod_flags |= flag
                portable = portable[len(mod_prefix) :]
                break

    primary_vks = _resolve_portable_key_vks(portable, mod_flags=mod_flags, is_numpad=is_numpad)
    return (mod_flags, primary_vks) if primary_vks is not None else None


def format_game_solo_action_text() -> str:
    """Return the label for the solo public session action."""
    hotkey = Settings.solo_session_hotkey
    if bool(hotkey):
        return tr('Solo Public Session ({duration}s) [{hotkey}]', duration=Settings.solo_session_duration, hotkey=hotkey)
    return tr('Solo Public Session ({duration}s)', duration=Settings.solo_session_duration)


def format_game_solo_tooltip(game_label: str) -> str:
    """Return the tooltip text for the solo public session action."""
    if bool(Settings.solo_session_hotkey):
        return tr(
            'Suspend {game_label} for {duration} seconds then auto-resume.\n'
            'This forces the game to spawn you alone in a public session.\n\n'
            'Global Hotkey: {hotkey}',
            game_label=game_label,
            duration=Settings.solo_session_duration,
            hotkey=Settings.solo_session_hotkey,
        )
    return tr(
        'Suspend {game_label} for {duration} seconds then auto-resume.\n'
        'This forces the game to spawn you alone in a public session.',
        game_label=game_label,
        duration=Settings.solo_session_duration,
    )


def format_session_time_component(target_dt: datetime, current_date: date) -> str:
    """Format a session timestamp with date prefix if not today."""
    prefix = f'{target_dt.strftime("%m/%d")} ' if target_dt.date() != current_date else ''
    return f'{prefix}{target_dt.strftime("%H:%M:%S")}'


class LookyMixin(QMainWindow):
    """Looky System menu-building and action handlers mixin for `MainWindow`.

    Expects these attributes on the concrete class (set in `__init__`):
        `_looky_crawler_join_own_session_action`, `_looky_rescan_all_action`
    """

    # -- Attribute stubs for type checkers --
    _looky_open_website_action: QAction
    _looky_crawler_join_own_session_action: QAction
    _looky_rescan_all_action: QAction
    _looky_submenu: QMenu

    if TYPE_CHECKING:
        _open_looky_website: Callable[[], None]

    def _build_looky_submenu(self, gta5_menu: QMenu) -> None:
        """Build the Looky System submenu and attach it to `gta5_menu`."""
        looky_submenu = gta5_menu.addMenu(QIcon(str(ICONS_DIR_PATH / 'scan-eye.svg')), tr('Looky System'))
        if not looky_submenu:
            message = 'Failed to create Looky System submenu'
            raise RuntimeError(message)
        looky_submenu.setToolTipsVisible(True)
        looky_submenu.menuAction().setToolTip(tr('Looky System tools and shortcuts for GTA5 sessions'))
        self._looky_submenu = looky_submenu

        looky_open_website_action = QAction(QIcon(str(ICONS_DIR_PATH / 'globe.svg')), tr('Open Website'), self)
        looky_open_website_action.setToolTip(tr('Open the Looky System website in your default browser'))
        looky_open_website_action.triggered.connect(self._open_looky_website)
        looky_submenu.addAction(looky_open_website_action)
        self._looky_open_website_action = looky_open_website_action

        looky_submenu.addSeparator()

        looky_crawler_join_own_session_action = QAction(QIcon(str(ICONS_DIR_PATH / 'bot.svg')), tr('Request Crawler in My Session'), self)
        looky_crawler_join_own_session_action.setToolTip(tr('Call the crawler bot to resolve usernames for players in your current session.'))
        looky_crawler_join_own_session_action.triggered.connect(self._request_crawler_own_session)
        looky_submenu.addAction(looky_crawler_join_own_session_action)
        self._looky_crawler_join_own_session_action = looky_crawler_join_own_session_action

        looky_rescan_all_action = QAction(QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')), tr('Rescan All Players'), self)
        looky_rescan_all_action.setToolTip(tr('Immediately refresh Looky System data for all players without waiting for the next automatic update.'))
        looky_rescan_all_action.triggered.connect(self._rescan_all_looky_players)
        looky_submenu.addAction(looky_rescan_all_action)
        self._looky_rescan_all_action = looky_rescan_all_action

        looky_submenu.aboutToShow.connect(self._update_looky_actions)

    def _refresh_looky_language_texts(self) -> None:
        """Re-translate the Looky System submenu labels and tooltips on language change."""
        self._looky_submenu.setTitle(tr('Looky System'))
        self._looky_submenu.menuAction().setToolTip(tr('Looky System tools and shortcuts for GTA5 sessions'))
        self._looky_open_website_action.setText(tr('Open Website'))
        self._looky_open_website_action.setToolTip(tr('Open the Looky System website in your default browser'))
        self._looky_crawler_join_own_session_action.setText(tr('Request Crawler in My Session'))
        self._looky_rescan_all_action.setText(tr('Rescan All Players'))
        self._update_looky_actions()

    def _update_looky_actions(self) -> None:
        """Update enabled state and tooltips for Looky System submenu actions based on current settings."""
        configure_looky_action(
            self._looky_crawler_join_own_session_action,
            tr('Call the crawler bot to resolve usernames for players in your current session.'),
            is_gta5_running=CaptureState.gta5_is_running,
        )
        configure_looky_action(
            self._looky_rescan_all_action,
            tr('Immediately refresh Looky System data for all players without waiting for the next automatic update.'),
            restriction=self._get_rescan_all_restriction(),
        )

    @staticmethod
    def _get_rescan_all_restriction() -> str | None:
        """Return why no player may be rescanned with Looky System, or `None` when at least one is allowed."""
        players = [player for player in PlayersRegistry.get_default_sorted_players() if not player.is_third_party_server]
        if any(get_looky_restriction([player]) is None for player in players):
            return None
        return get_looky_restriction(players)

    def _request_crawler_own_session(self) -> None:
        """Request the Looky System crawler bot to join the current session."""
        show_crawlme_request(self)

    def _rescan_all_looky_players(self) -> None:
        """Reset the Looky System fetch timestamp for every player so `looky_core` re-fetches them immediately."""
        if check_looky_prerequisites(self, restriction=self._get_rescan_all_restriction()) is None:
            return

        count = trigger_looky_rescan_all_players()
        if not count:
            QMessageBox.information(self, get_looky_title(), tr('No Looky System players to rescan.\nNo players have been fetched yet.'))
        else:
            QMessageBox.information(
                self,
                get_looky_title(),
                tr_plural(
                    '{count} player queued for Looky System rescan.\nResults will update automatically.',
                    '{count} players queued for Looky System rescan.\nResults will update automatically.',
                    count,
                ),
            )
