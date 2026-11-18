"""Looky System menu-building and action handlers mixin for `MainWindow`."""

from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QMainWindow, QMenu, QMessageBox

from session_sniffer.background.cores import trigger_looky_rescan_all_players
from session_sniffer.guis._main_window_shortcuts_mixin import append_shortcut_tooltip
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


def format_game_solo_action_text() -> str:
    """Return the label for the solo public session action."""
    return tr('Solo Public Session ({duration}s)', duration=Settings.solo_session_duration)


def format_game_solo_tooltip(game_label: str) -> str:
    """Return the tooltip text for the solo public session action."""
    hotkey = Settings.get_active_shortcut('solo_session_hotkey')
    if hotkey is not None:
        return tr(
            'Suspend {game_label} for {duration} seconds then auto-resume.\n'
            'This forces the game to spawn you alone in a public session.\n\n'
            'Global Hotkey: {hotkey}',
            game_label=game_label,
            duration=Settings.solo_session_duration,
            hotkey=hotkey,
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

        crawler_hotkey = Settings.get_active_shortcut('looky_crawler_hotkey')
        looky_crawler_join_own_session_action = QAction(
            QIcon(str(ICONS_DIR_PATH / 'bot.svg')),
            tr('Request Crawler in My Session'),
            self,
        )
        looky_crawler_join_own_session_action.setToolTip(
            append_shortcut_tooltip(
                tr('Call the crawler bot to resolve usernames for players in your current session.'),
                crawler_hotkey,
                is_global=True,
            ),
        )
        looky_crawler_join_own_session_action.triggered.connect(self._request_crawler_own_session)
        looky_submenu.addAction(looky_crawler_join_own_session_action)
        self._looky_crawler_join_own_session_action = looky_crawler_join_own_session_action

        rescan_hotkey = Settings.get_active_shortcut('looky_rescan_hotkey')
        looky_rescan_all_action = QAction(
            QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')),
            tr('Rescan All Players'),
            self,
        )
        looky_rescan_all_action.setToolTip(
            append_shortcut_tooltip(
                tr('Immediately refresh Looky System data for all players without waiting for the next automatic update.'),
                rescan_hotkey,
                is_global=True,
            ),
        )
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
            append_shortcut_tooltip(
                tr('Call the crawler bot to resolve usernames for players in your current session.'),
                Settings.get_active_shortcut('looky_crawler_hotkey'),
                is_global=True,
            ),
            is_gta5_running=CaptureState.gta5_is_running,
        )
        configure_looky_action(
            self._looky_rescan_all_action,
            append_shortcut_tooltip(
                tr('Immediately refresh Looky System data for all players without waiting for the next automatic update.'),
                Settings.get_active_shortcut('looky_rescan_hotkey'),
                is_global=True,
            ),
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
