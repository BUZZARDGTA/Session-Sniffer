"""Preload and warm up application caches during the launcher startup phase."""

import logging
from typing import TYPE_CHECKING

from session_sniffer.player.userip_loader import update_userip_databases
from session_sniffer.rendering_core.country_flags import preload_country_flags
from session_sniffer.rendering_core.modmenu_logs_parser import ModMenuLogsParser
from session_sniffer.rendering_core.session_table_renderer import get_server_background_color
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


def preload_application_caches(
    progress_callback: Callable[[str], None] | None = None,
) -> None:
    """Preload and warm up application caches in the background.

    Warms UserIP databases, country flag image decoding, mod menu log parsing,
    and session table styles so that the sniffer window and rendering engine
    experience zero latency upon opening.
    """
    if progress_callback is not None:
        progress_callback('UserIP databases')
    logger.debug('Preloading UserIP databases cache...')
    update_userip_databases()

    if progress_callback is not None:
        progress_callback('Country flags')
    logger.debug('Preloading country flag images cache...')
    preload_country_flags()

    if progress_callback is not None:
        progress_callback('Mod menu logs')
    logger.debug('Preloading mod menu logs cache...')
    ModMenuLogsParser.refresh()

    if progress_callback is not None:
        progress_callback('Table styles')
    logger.debug('Preloading table styles and colors cache...')
    get_server_background_color(Settings.gui_servers_color, enabled=Settings.gui_servers_color_enabled)

    logger.debug('Application cache preloading completed.')
