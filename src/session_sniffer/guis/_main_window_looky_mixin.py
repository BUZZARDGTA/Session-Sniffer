"""Looky System menu-building and action handlers mixin for `MainWindow`."""

from typing import TYPE_CHECKING

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMainWindow, QMenu, QMessageBox

from session_sniffer.guis.looky_text import (
    LOOKY_TITLE,
    configure_looky_action,
)
from session_sniffer.guis.tables_player_actions import show_crawlme_request
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


class LookyMixin(QMainWindow):
    """Looky System menu-building and action handlers mixin for `MainWindow`.

    Expects these attributes on the concrete class (set in `__init__`):
        `_looky_crawler_join_own_session_action`, `_looky_rescan_all_action`
    """

    # -- Attribute stubs for type checkers --
    _looky_crawler_join_own_session_action: QAction
    _looky_rescan_all_action: QAction
    _looky_submenu: QMenu

    if TYPE_CHECKING:
        _open_looky_website: Callable[[], None]

    def _build_looky_submenu(self, gta5_menu: QMenu) -> None:
        """Build the Looky System submenu and attach it to `gta5_menu`."""
        looky_submenu = gta5_menu.addMenu('👁️ Looky System')
        if not looky_submenu:
            message = 'Failed to create Looky System submenu'
            raise RuntimeError(message)
        looky_submenu.setToolTipsVisible(True)
        looky_submenu.menuAction().setToolTip('Looky System tools and shortcuts for GTA5 sessions')
        self._looky_submenu = looky_submenu

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
        configure_looky_action(
            self._looky_crawler_join_own_session_action,
            'Call the crawler bot to resolve usernames for players in your current session.',
            is_gta5_running=CaptureState.gta5_is_running,
        )
        configure_looky_action(
            self._looky_rescan_all_action,
            'Immediately refresh Looky System data for all players without waiting for the next automatic update.',
            check_gta5_restriction=True,
        )

    def _request_crawler_own_session(self) -> None:
        """Request the Looky System crawler bot to join the current session."""
        show_crawlme_request(self)

    def _rescan_all_looky_players(self) -> None:
        """Reset the Looky System fetch timestamp for every player so `looky_core` re-fetches them immediately."""
        if (
            Settings.looky_exclusive_gta5_process
            and CaptureState.is_local_capture()
            and not CaptureState.gta5_is_running
        ):
            QMessageBox.warning(self, LOOKY_TITLE, 'Looky System is restricted to GTA V, which is not currently running.')
            return

        players = PlayersRegistry.get_default_sorted_players()
        count = 0
        for player in players:
            if Settings.looky_exclusive_gta5_process and CaptureState.is_local_capture() and not player.is_gta5_process:
                continue
            if player.looky_system.is_initialized:
                with player.looky_system.lock:
                    player.looky_system.last_fetched_at = 0.0
                count += 1

        if not count:
            QMessageBox.information(self, LOOKY_TITLE, 'No Looky System players to rescan.\nNo players have been fetched yet.')
        else:
            noun = 'player' if count == 1 else 'players'
            QMessageBox.information(self, LOOKY_TITLE, f'{count} {noun} queued for Looky System rescan.\nResults will update automatically.')
