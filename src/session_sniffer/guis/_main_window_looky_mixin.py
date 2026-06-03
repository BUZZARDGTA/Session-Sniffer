"""Looky System menu-building and action handlers mixin for `MainWindow`."""

from typing import TYPE_CHECKING, cast

from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QMainWindow, QMenu, QMessageBox

from session_sniffer.guis.looky_text import (
    LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS,
    LOOKY_MENU_TOOLTIP_API_KEY_MISSING,
    LOOKY_MENU_TOOLTIP_DISABLED,
    LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING,
    LOOKY_TITLE,
)
from session_sniffer.guis.tables_player_actions import show_crawlme_request
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


class LookyMixin(QMainWindow):  # pylint: disable=too-few-public-methods
    """Looky System menu-building and action handlers mixin for `MainWindow`.

    Expects these attributes on the concrete class (set in `__init__`):
        `_looky_crawler_join_own_session_action`, `_looky_rescan_all_action`
    """

    # -- Attribute stubs for type checkers --
    _looky_crawler_join_own_session_action: QAction
    _looky_rescan_all_action: QAction

    if TYPE_CHECKING:
        _open_looky_website: Callable[[], None]

    def _build_looky_submenu(self, gta5_menu: QMenu) -> None:
        """Build the Looky System submenu and attach it to `gta5_menu`."""
        looky_submenu = gta5_menu.addMenu('👁 Looky System')
        if looky_submenu is None:
            msg = 'Failed to create Looky System submenu'
            raise RuntimeError(msg)
        looky_submenu.setToolTipsVisible(True)
        cast('QAction', looky_submenu.menuAction()).setToolTip('Looky System tools and shortcuts for GTA5 sessions')

        looky_open_website_action = QAction('🌐 Open Website', self)
        looky_open_website_action.setToolTip('Open the Looky System website in your default browser')
        looky_open_website_action.triggered.connect(self._open_looky_website)
        looky_submenu.addAction(looky_open_website_action)

        looky_submenu.addSeparator()

        looky_crawler_join_own_session_action = QAction('🤖 Request Crawler in My Session', self)
        looky_crawler_join_own_session_action.setToolTip('Call the crawler bot to resolve usernames for players in your current session.')
        looky_crawler_join_own_session_action.triggered.connect(self._request_crawler_own_session)
        looky_submenu.addAction(looky_crawler_join_own_session_action)
        self._looky_crawler_join_own_session_action = looky_crawler_join_own_session_action

        looky_rescan_all_action = QAction('🔄 Rescan All Players', self)
        looky_rescan_all_action.setToolTip('Immediately refresh Looky System data for all players without waiting for the next automatic update.')
        looky_rescan_all_action.triggered.connect(self._rescan_all_looky_players)
        looky_submenu.addAction(looky_rescan_all_action)
        self._looky_rescan_all_action = looky_rescan_all_action

        looky_submenu.aboutToShow.connect(self._update_looky_actions)

    def _update_looky_actions(self) -> None:
        """Update enabled state and tooltips for Looky System submenu actions based on current settings."""
        # The crawler is only available for GTA V Legacy, so hide it entirely when enhanced is running.
        self._looky_crawler_join_own_session_action.setVisible(not CaptureState.gta5_is_enhanced)

        if not Settings.looky_enabled:
            self._looky_crawler_join_own_session_action.setEnabled(False)
            self._looky_crawler_join_own_session_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
        elif not Settings.looky_api_key:
            self._looky_crawler_join_own_session_action.setEnabled(False)
            self._looky_crawler_join_own_session_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
        elif not LookyState.api_access:
            self._looky_crawler_join_own_session_action.setEnabled(False)
            self._looky_crawler_join_own_session_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
        elif not CaptureState.gta5_is_running:
            self._looky_crawler_join_own_session_action.setEnabled(False)
            self._looky_crawler_join_own_session_action.setToolTip(LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING)
        else:
            self._looky_crawler_join_own_session_action.setEnabled(True)
            self._looky_crawler_join_own_session_action.setToolTip('Call the crawler bot to resolve usernames for players in your current session.')

        if not Settings.looky_enabled:
            self._looky_rescan_all_action.setEnabled(False)
            self._looky_rescan_all_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
        elif not Settings.looky_api_key:
            self._looky_rescan_all_action.setEnabled(False)
            self._looky_rescan_all_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
        elif not LookyState.api_access:
            self._looky_rescan_all_action.setEnabled(False)
            self._looky_rescan_all_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
        else:
            self._looky_rescan_all_action.setEnabled(True)
            self._looky_rescan_all_action.setToolTip('Immediately refresh Looky System data for all players without waiting for the next automatic update.')

    def _request_crawler_own_session(self) -> None:
        """Request the Looky System crawler bot to join the current session."""
        show_crawlme_request(self)

    def _rescan_all_looky_players(self) -> None:
        """Reset the Looky System fetch timestamp for every player so `looky_core` re-fetches them immediately."""
        players = PlayersRegistry.get_default_sorted_players()
        count = 0
        for player in players:
            if player.looky_system.is_initialized:
                with player.looky_system.lock:
                    player.looky_system.last_fetched_at = 0.0
                count += 1

        if not count:
            QMessageBox.information(self, LOOKY_TITLE, 'No Looky System players to rescan.\nNo players have been fetched yet.')
        else:
            noun = 'player' if count == 1 else 'players'
            QMessageBox.information(self, LOOKY_TITLE, f'{count} {noun} queued for Looky System rescan.\nResults will update automatically.')
