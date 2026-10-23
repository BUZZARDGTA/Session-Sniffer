"""Shared Looky System UI text and small helpers."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import QWidget

    from session_sniffer.guis.tables_player_actions._ip_lookup_dialog import StandaloneIPLookup

from session_sniffer.constants.standalone import TITLE
from session_sniffer.models.player import Player
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

LOOKY_TITLE = f'{TITLE} - Looky System'
LOOKY_SETTINGS_AUTH_PATH = 'Settings → Looky System → Authentication'
LOOKY_SETTINGS_GENERAL_PATH = 'Settings → Looky System → General'

# Menu tooltips
LOOKY_MENU_TOOLTIP_API_KEY_MISSING = f'Looky System requires an API key. Add one in {LOOKY_SETTINGS_AUTH_PATH}.'
LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS = f'Your Looky System API key is invalid or your account has no API access. Update your key in {LOOKY_SETTINGS_AUTH_PATH}.'
LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING = 'Looky System is available only while GTA V is running.'
LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING = 'Looky System is restricted to GTA V, which is not currently running or being scanned.'
LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_GTA5_PLAYER = 'Looky System is restricted to players confirmed as GTA V traffic.'
LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL = 'Looky System is a PC-only feature and is not supported for console captures.'
LOOKY_MENU_TOOLTIP_DISABLED = f'Looky System is disabled. Enable it in {LOOKY_SETTINGS_GENERAL_PATH}.'

# Dialog / message-box warnings
LOOKY_WARNING_API_ACCESS_MISSING = 'Your Looky System account does not have API access.'
LOOKY_WARNING_API_KEY_MISSING = f'Looky System requires an API key.\n\nAdd your API key in {LOOKY_SETTINGS_AUTH_PATH}.'
LOOKY_WARNING_DISABLED = f'Looky System is disabled.\n\nEnable it in {LOOKY_SETTINGS_GENERAL_PATH}.'
LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING = 'Looky System is restricted to GTA V, which is not currently running or being scanned.'
LOOKY_WARNING_RESTRICTED_NOT_LOCAL = 'Looky System is a PC-only feature and is not supported for console captures.'

# Log messages
LOOKY_LOG_API_KEY_INVALID = '[Looky System] Unable to connect: the API key appears to be invalid. Please update it in Settings.'
LOOKY_LOG_VERIFICATION_HTTP_FAILED_TEMPLATE = '[Looky System] Token verification failed: HTTP %s %s'


def get_looky_restriction(targets: Iterable[Player | StandaloneIPLookup]) -> str | None:
    """Return why Looky System may not be used for `targets`, or `None` when all of them are allowed.

    With `Settings.looky_exclusive_gta5_process` enabled, captured players must be confirmed GTA V traffic
    (`Player.is_gta5_process`, set when a packet uses one of the GTA V process's own UDP socket ports), and
    standalone IPs (not part of the session tables) require capture to be filtering on the GTA V process.
    """
    if not Settings.looky_exclusive_gta5_process:
        return None
    for target in targets:
        if isinstance(target, Player):
            if not target.is_gta5_process:
                return LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_GTA5_PLAYER
        elif not CaptureState.is_scanning_gta5_process():
            return LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING
    return None


def configure_looky_action(
    action: QAction | QWidget,
    default_tooltip: str | None = None,
    *,
    is_gta5_running: bool | None = None,
    restriction: str | None = None,
) -> None:
    """Configure the enabled status and tooltip of a Looky-related QAction or QWidget.

    Avoids duplicating the gating logic and tooltip settings across multiple widgets and menus.
    """
    if not Settings.looky_enabled:
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
    elif not Settings.is_gta5_feature_set():
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING)
    elif not bool(Settings.looky_api_key):
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
    elif not LookyState.api_access:
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
    elif not CaptureState.is_local_capture():
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_RESTRICTED_NOT_LOCAL)
    elif is_gta5_running is False:
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING)
    elif restriction is not None:
        action.setEnabled(False)
        action.setToolTip(restriction)
    else:
        action.setEnabled(True)
        if default_tooltip is not None:
            action.setToolTip(default_tooltip)
