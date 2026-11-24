"""Runtime side effects for saved settings changes."""

import sys
from contextlib import nullcontext
from dataclasses import replace
from typing import TYPE_CHECKING

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QMessageBox

from session_sniffer.background.cores import ensure_looky_core_running, wake_looky_core
from session_sniffer.background.tasks import retrigger_detections_scan
from session_sniffer.background.voice_notifications import clear_voice_notification_queue
from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.capture.pcap import validate_bpf_filter
from session_sniffer.capture.process_monitor import ensure_process_monitor_running
from session_sniffer.constants.standalone import TITLE
from session_sniffer.ctypes_windows import is_admin
from session_sniffer.discord.webhook import is_valid_webhook_url
from session_sniffer.guis.live_language import apply_runtime_language
from session_sniffer.guis.live_theme import apply_runtime_theme, resolve_effective_theme
from session_sniffer.guis.loading_overlay import loading_overlay_scope, run_with_active_loading
from session_sniffer.guis.relay_conflict import prompt_to_disable_gta5_relay_if_filtered
from session_sniffer.guis.tables_player_actions._detection_dialogs import close_all_detection_notification_dialogs
from session_sniffer.guis.tables_player_actions._userip_dialog import close_all_userip_detected_dialogs
from session_sniffer.guis.theming import get_active_theme
from session_sniffer.i18n import get_active_language, resolve_effective_language, tr
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.notifications_state import notifications_state
from session_sniffer.player import prune_old_backups, run_userip_backup_async
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import SETTING_METADATA, Settings, SettingType
from session_sniffer.utils import validate_and_strip_balanced_outer_parens
from session_sniffer.utils_exceptions import ParenthesisMismatchError
from session_sniffer.webserver import (
    WEBSERVER_LAN_HOST,
    WebServer,
    allow_webserver_firewall_port,
    check_windows_firewall_status,
    format_webserver_error,
    format_webserver_firewall_failure,
    format_webserver_firewall_warning,
    has_managed_webserver_firewall_rule,
    is_loopback_ipv4,
    remove_webserver_firewall_rule,
    start_webserver_from_settings,
)

if TYPE_CHECKING:
    from PySide6.QtWidgets import QWidget

    from session_sniffer.capture.packet_capture import PacketCapture

SettingValue = bool | str | int | float | tuple[str, ...] | None
_DISCORD_PRESENCE_TITLE_MIN_LEN = 2


def validate_settings_values(values: dict[str, SettingValue]) -> list[str]:
    """Validate collected dialog setting *values* and return a list of localized error messages."""
    errors: list[str] = []

    for key, value in values.items():
        meta = SETTING_METADATA[key]
        if key == 'webserver_host':
            if not isinstance(value, str) or not value:
                errors.append(tr('{label}: Please enter a valid IPv4 address or choose a preset under Network Access.', label=tr(meta.display_label)))
            elif not is_ipv4_address(value):
                errors.append(tr('{label}: "{value}" is not a valid IPv4 address.', label=tr(meta.display_label), value=value))

        elif meta.setting_type == SettingType.IPV4 and isinstance(value, str) and not is_ipv4_address(value):
            errors.append(tr('{label}: "{value}" is not a valid IPv4 address.', label=tr(meta.display_label), value=value))

        elif meta.setting_type == SettingType.COLOR and (not isinstance(value, str) or not QColor(value).isValid()):
            errors.append(tr('{label}: "{value}" is not a valid color.', label=tr(meta.display_label), value=value))

        elif meta.setting_type == SettingType.MAC_ADDRESS and isinstance(value, str):
            formatted = format_mac_address(value)
            if not is_mac_address(formatted):
                errors.append(
                    tr(
                        '{label}: "{value}" is not a valid MAC address (expected format: AA:BB:CC:DD:EE:FF).',
                        label=tr(meta.display_label),
                        value=value,
                    ),
                )

        elif meta.setting_type == SettingType.STRING and key == 'capture_prepend_custom_capture_filter' and isinstance(value, str):
            try:
                stripped_filter = validate_and_strip_balanced_outer_parens(value)
            except ParenthesisMismatchError:
                errors.append(tr('{label}: filter expression has unbalanced parentheses.', label=tr(meta.display_label)))
            else:
                if stripped_filter and (bpf_error := validate_bpf_filter(stripped_filter)) is not None:
                    errors.append(tr('{label}: invalid BPF filter expression ({error}).', label=tr(meta.display_label), error=bpf_error))

        elif key == 'discord_presence_title' and isinstance(value, str) and 0 < len(value) < _DISCORD_PRESENCE_TITLE_MIN_LEN:
            errors.append(tr('Presence Title must be either empty (to disable) or at least 2 characters long.'))

    if bool(values.get('discord_webhook_enabled')):
        url_value = values.get('discord_webhook_url')
        if not isinstance(url_value, str) or not is_valid_webhook_url(url_value):
            errors.append(
                tr(
                    'Discord Webhook is enabled but the Webhook URL is missing or invalid. '
                    'Expected format: https://discord.com/api/webhooks/<id>/<token>',
                ),
            )

    datetime_option_keys = (
        'gui_columns_datetime_show_date',
        'gui_columns_datetime_show_time',
        'gui_columns_datetime_show_elapsed_time',
    )
    if not any(values.get(opt_key) for opt_key in datetime_option_keys):
        options_list = '\n'.join(f'  - {tr(SETTING_METADATA[opt_key].display_label)}' for opt_key in datetime_option_keys)
        errors.append(
            tr(
                'At least one of the DateTime column display options must be enabled:\n{options}',
                options=options_list,
            ),
        )

    hotkey_bindings: dict[str, list[tuple[str, str]]] = {}
    for key, meta in SETTING_METADATA.items():
        if meta.setting_type != SettingType.HOTKEY:
            continue
        chord_val = values.get(key)
        if isinstance(chord_val, str) and chord_val:
            label_text = f'{tr(meta.group)} \u2014 {tr(meta.display_label)}' if meta.group is not None and meta.group else tr(meta.display_label)
            hotkey_bindings.setdefault(chord_val.casefold(), []).append((chord_val, label_text))
    for bound_items in hotkey_bindings.values():
        if len(bound_items) > 1:
            display_chord = bound_items[0][0]
            actions_list = '\n'.join(f'  - {item_label}' for _, item_label in bound_items)
            errors.append(
                tr(
                    'Shortcut "{shortcut}" is assigned to multiple actions:\n{actions}',
                    shortcut=display_chord,
                    actions=actions_list,
                ),
            )

    return errors


def apply_runtime_settings_changes(
    capture: PacketCapture,
    old_values: dict[str, SettingValue],
    new_values: dict[str, SettingValue],
    *,
    dialog_parent: QWidget | None = None,
) -> None:
    """Apply runtime side effects after `Settings` attributes have been updated from `old_values` to `new_values`."""
    selected_theme = resolve_effective_theme()
    theme_needs_apply = selected_theme != get_active_theme()
    selected_language = resolve_effective_language(
        language=Settings.gui_language,
        follow_system=Settings.gui_language_follow_system,
    )
    language_needs_apply = selected_language != get_active_language()

    capture_settings_changed = any(
        value != old_values.get(key) for key, value in new_values.items() if key in SETTING_METADATA and SETTING_METADATA[key].requires_capture_restart
    )
    capture_will_restart = capture_settings_changed and capture.is_running()

    webserver_enabled_changed = new_values.get('webserver_enabled') != old_values.get('webserver_enabled')
    webserver_host_changed = new_values.get('webserver_host') != old_values.get('webserver_host')
    webserver_port_changed = new_values.get('webserver_port') != old_values.get('webserver_port')
    webserver_credentials_changed = new_values.get('webserver_username') != old_values.get('webserver_username') or new_values.get('webserver_password') != old_values.get(
        'webserver_password',
    )
    webserver_will_rebind = webserver_enabled_changed or (Settings.webserver_enabled and (webserver_host_changed or webserver_port_changed))

    busy_ctx = (
        loading_overlay_scope(dialog_parent, tr('Applying Settings\u2026'), tr('Updating runtime services and capture configuration\u2026'))
        if dialog_parent is not None and dialog_parent.isVisible() and (theme_needs_apply or language_needs_apply or capture_will_restart or webserver_will_rebind)
        else nullcontext()
    )
    with busy_ctx:
        if theme_needs_apply:
            apply_runtime_theme(selected_theme)
        if language_needs_apply:
            apply_runtime_language(wake_renderer=True)

        run_with_active_loading(Settings.rebuild_blocked_ip_ranges)
        ensure_process_monitor_running()
        ensure_looky_core_running()
        if Settings.looky_enabled and Settings.is_gta5_feature_set():
            wake_looky_core()

        if capture_will_restart:
            capture_filter_str, display_filter_fn = build_capture_filters(
                capture_ip_address=capture.config.interface.ip_address,
                broadcast_support=capture.config.broadcast_support,
                multicast_support=capture.config.multicast_support,
            )
            capture.config = replace(capture.config, capture_filter=capture_filter_str, display_filter_fn=display_filter_fn)
            capture.request_restart()

        if webserver_enabled_changed:
            if Settings.webserver_enabled:
                run_with_active_loading(start_webserver_from_settings)
            else:
                run_with_active_loading(WebServer.stop_server)
                if sys.platform == 'win32' and is_admin() and has_managed_webserver_firewall_rule():
                    run_with_active_loading(remove_webserver_firewall_rule)
        elif Settings.webserver_enabled and (webserver_host_changed or webserver_port_changed):
            run_with_active_loading(start_webserver_from_settings)
        elif Settings.webserver_enabled and webserver_credentials_changed:
            WebServer.update_auth_credentials(auth_username=Settings.webserver_username, auth_password=Settings.webserver_password)

    if dialog_parent is not None:
        if webserver_will_rebind and Settings.webserver_enabled:
            webserver_status = WebServer.get_status()
            if not webserver_status.running and webserver_status.error_code is not None:
                QMessageBox.warning(dialog_parent, TITLE, format_webserver_error(webserver_status))
            elif webserver_status.running and not is_loopback_ipv4(Settings.webserver_host):
                _prompt_webserver_firewall_if_blocked(dialog_parent)
        prompt_to_disable_gta5_relay_if_filtered(dialog_parent, context='settings')

    if new_values.get('userip_backup_frequency') != old_values.get('userip_backup_frequency') or new_values.get('userip_backup_retention_limit') != old_values.get(
        'userip_backup_retention_limit',
    ):
        if Settings.userip_backup_frequency != 'Disabled':
            run_userip_backup_async()
        else:
            prune_old_backups()

    _retrigger_connected_userip_detections(
        voice_newly_enabled=False,
        visual_newly_enabled=False,
        gta5_local_newly_enabled=new_values.get('capture_feature_set') == 'GTA V' and old_values.get('capture_feature_set') != 'GTA V' and CaptureState.is_local_capture(),
    )
    retrigger_detections_scan()


def _prompt_webserver_firewall_if_blocked(dialog_parent: QWidget) -> None:
    """Offer to add a scoped Windows Firewall rule when the newly saved LAN Web Server port is blocked."""
    port = Settings.webserver_port
    target_ip = Settings.webserver_host if Settings.webserver_host != WEBSERVER_LAN_HOST else None
    fw_status = check_windows_firewall_status(port, local_ip=target_ip)
    if fw_status == 'blocked':
        reply = QMessageBox.question(
            dialog_parent,
            TITLE,
            tr(
                'Windows Firewall is blocking phones and other devices from connecting to the Web Server on port {port}.\n\n'
                'Allow Session Sniffer through Windows Firewall for your local network?',
                port=port,
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply == QMessageBox.StandardButton.Yes and not allow_webserver_firewall_port(port, local_ip=target_ip):
            QMessageBox.warning(dialog_parent, TITLE, format_webserver_firewall_failure(port))
    elif fw_status in ('explicitly_blocked', 'block_all_inbound'):
        QMessageBox.warning(dialog_parent, TITLE, format_webserver_firewall_warning(fw_status, port))


def apply_notifications_toggle_changes(*, visual_was_enabled: bool, voice_was_enabled: bool) -> None:
    """Apply runtime side effects after the session-only `notifications_state` toggles changed."""
    if not notifications_state.voice_enabled:
        clear_voice_notification_queue()
    if not notifications_state.visual_enabled:
        close_all_userip_detected_dialogs()
        close_all_detection_notification_dialogs()
    _retrigger_connected_userip_detections(
        voice_newly_enabled=notifications_state.voice_enabled and not voice_was_enabled,
        visual_newly_enabled=notifications_state.visual_enabled and not visual_was_enabled,
        gta5_local_newly_enabled=False,
    )
    retrigger_detections_scan()


def _retrigger_connected_userip_detections(*, voice_newly_enabled: bool, visual_newly_enabled: bool, gta5_local_newly_enabled: bool) -> None:
    """Re-queue processed UserIP detections of connected players whose notification or protection actions just became enabled."""
    if not (voice_newly_enabled or visual_newly_enabled or gta5_local_newly_enabled):
        return
    retrigger_userip = False
    for player in PlayersRegistry.get_connected_players():
        if player.left_event.is_set() or player.userip is None or player.userip_detection is None or not player.userip_detection.as_processed_task:
            continue
        db_settings = player.userip.settings
        notif_retrigger = (voice_newly_enabled and bool(db_settings.voice_notifications)) or (visual_newly_enabled and db_settings.notifications)
        if notif_retrigger or (gta5_local_newly_enabled and db_settings.protection.enabled):
            player.userip_detection.as_processed_task = False
            retrigger_userip = True
    if retrigger_userip:
        wake_rendering_core()
