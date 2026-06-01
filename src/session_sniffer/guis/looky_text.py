"""Shared Looky System UI text and small helpers."""

LOOKY_SETTINGS_AUTH_PATH = 'Settings → Looky System → Authentication'
LOOKY_MENU_TOOLTIP_READY = 'Looky tools for the current GTA5 session'
LOOKY_MENU_TOOLTIP_NO_KEY = f'Looky API key is not configured — set one in {LOOKY_SETTINGS_AUTH_PATH}.'
LOOKY_MENU_TOOLTIP_INVALID_OR_NO_ACCESS = (
    'Looky API key is invalid or your account has no API access. '
    f'Update your key in {LOOKY_SETTINGS_AUTH_PATH}.'
)
LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING = 'Looky is available only while GTA V is running.'
LOOKY_NO_KEY_OR_DISABLED_WARNING = (
    'No Looky API key is configured or Looky is disabled.\n\n'
    f'Set one in {LOOKY_SETTINGS_AUTH_PATH}.'
)
LOOKY_NO_API_ACCESS_WARNING = 'Your Looky account does not have API access.'
LOOKY_NO_KEY_CONFIGURED_LABEL = f'No Looky API key configured.\nSet one in {LOOKY_SETTINGS_AUTH_PATH}.'
LOOKY_INVALID_KEY_LOG_WARNING = '[Looky System] Unable to connect to Looky: your API key appears to be invalid. Please update it in Settings.'
LOOKY_VERIFICATION_HTTP_WARNING_TEMPLATE = '[Looky System] Token verification failed: HTTP %s %s'


def is_looky_usable(*, has_key: bool, has_api_access: bool) -> bool:
    """Return whether Looky actions should be enabled."""
    return has_key and has_api_access


def resolve_looky_menu_state(*, looky_enabled: bool, gta5_is_running: bool, has_key: bool, has_api_access: bool) -> tuple[bool, bool, str]:
    """Return the visible, enabled, and tooltip state for Looky menus."""
    is_visible = looky_enabled
    is_enabled = is_visible and gta5_is_running and is_looky_usable(has_key=has_key, has_api_access=has_api_access)
    if not is_visible:
        return is_visible, is_enabled, resolve_looky_menu_tooltip(has_key=has_key, has_api_access=has_api_access)

    if not has_key:
        return is_visible, is_enabled, LOOKY_MENU_TOOLTIP_NO_KEY

    if not has_api_access:
        return is_visible, is_enabled, LOOKY_MENU_TOOLTIP_INVALID_OR_NO_ACCESS

    if not gta5_is_running:
        return is_visible, is_enabled, LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING

    return is_visible, is_enabled, resolve_looky_menu_tooltip(has_key=has_key, has_api_access=has_api_access)


def resolve_looky_menu_tooltip(*, has_key: bool, has_api_access: bool) -> str:
    """Return the most helpful tooltip for the current Looky menu state."""
    if not has_key:
        return LOOKY_MENU_TOOLTIP_NO_KEY

    if not has_api_access:
        return LOOKY_MENU_TOOLTIP_INVALID_OR_NO_ACCESS

    return LOOKY_MENU_TOOLTIP_READY
