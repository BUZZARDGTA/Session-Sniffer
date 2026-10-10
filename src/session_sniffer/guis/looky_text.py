"""Shared Looky System UI text and small helpers."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import QWidget

from session_sniffer.constants.standalone import TITLE
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


def is_looky_gta5_restricted() -> bool:
    """Return whether Looky System is restricted due to non-local capture or unmonitored GTA V process."""
    if not CaptureState.is_local_capture():
        return True
    return Settings.looky_exclusive_gta5_process and not CaptureState.is_scanning_gta5_process()


def configure_looky_action(
    action: QAction | QWidget,
    default_tooltip: str | None = None,
    *,
    is_gta5_running: bool | None = None,
    check_gta5_restriction: bool = False,
) -> None:
    """Configure the enabled status and tooltip of a Looky-related QAction or QWidget.

    Avoids duplicating the gating logic and tooltip settings across multiple widgets and menus.
    """
    if not Settings.looky_enabled:
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
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
    elif check_gta5_restriction and is_looky_gta5_restricted():
        action.setEnabled(False)
        action.setToolTip(LOOKY_MENU_TOOLTIP_RESTRICTED_GTA5_NOT_RUNNING)
    else:
        action.setEnabled(True)
        if default_tooltip is not None:
            action.setToolTip(default_tooltip)
