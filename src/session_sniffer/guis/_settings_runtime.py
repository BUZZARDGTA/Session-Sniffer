"""Runtime side effects for saved settings changes."""

from dataclasses import replace
from typing import TYPE_CHECKING

from session_sniffer.background import clear_voice_notification_queue, ensure_looky_core_running, retrigger_detections_scan, wake_looky_core
from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.capture.process_monitor import ensure_process_monitor_running
from session_sniffer.guis.relay_conflict import prompt_to_disable_gta5_relay_if_filtered
from session_sniffer.player import prune_old_backups, run_userip_backup_async
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import SETTING_METADATA, Settings
from session_sniffer.webserver import WebServer, start_webserver_from_settings

if TYPE_CHECKING:
    from PySide6.QtWidgets import QWidget

    from session_sniffer.capture.packet_capture import PacketCapture

SettingValue = bool | str | int | float | tuple[str, ...] | None


def apply_runtime_settings_changes(
    capture: PacketCapture,
    old_values: dict[str, SettingValue],
    new_values: dict[str, SettingValue],
    *,
    dialog_parent: QWidget | None = None,
) -> None:
    """Apply runtime side effects after `Settings` attributes have been updated from `old_values` to `new_values`."""
    Settings.rebuild_blocked_ip_ranges()
    ensure_process_monitor_running()
    ensure_looky_core_running()
    if Settings.looky_enabled and Settings.is_gta5_feature_set():
        wake_looky_core()

    capture_settings_changed = any(
        value != old_values.get(key) for key, value in new_values.items() if key in SETTING_METADATA and SETTING_METADATA[key].requires_capture_restart
    )
    if capture_settings_changed and capture.is_running():
        capture_filter_str, display_filter_fn = build_capture_filters(
            capture_ip_address=capture.config.interface.ip_address,
            broadcast_support=capture.config.broadcast_support,
            multicast_support=capture.config.multicast_support,
        )
        capture.config = replace(capture.config, capture_filter=capture_filter_str, display_filter_fn=display_filter_fn)
        capture.request_restart()

    webserver_enabled_changed = new_values.get('webserver_enabled') != old_values.get('webserver_enabled')
    webserver_host_changed = new_values.get('webserver_host') != old_values.get('webserver_host')
    webserver_port_changed = new_values.get('webserver_port') != old_values.get('webserver_port')
    webserver_credentials_changed = new_values.get('webserver_username') != old_values.get('webserver_username') or new_values.get('webserver_password') != old_values.get(
        'webserver_password',
    )
    if webserver_enabled_changed:
        if Settings.webserver_enabled:
            start_webserver_from_settings()
        else:
            WebServer.stop_server()
    elif Settings.webserver_enabled and (webserver_host_changed or webserver_port_changed):
        start_webserver_from_settings()
    elif Settings.webserver_enabled and webserver_credentials_changed:
        WebServer.update_auth_credentials(auth_username=Settings.webserver_username, auth_password=Settings.webserver_password)

    if not Settings.voice_notifications_enabled:
        clear_voice_notification_queue()
    if dialog_parent is not None:
        prompt_to_disable_gta5_relay_if_filtered(dialog_parent, context='settings')

    if new_values.get('userip_backup_frequency') != old_values.get('userip_backup_frequency') or new_values.get('userip_backup_retention_limit') != old_values.get(
        'userip_backup_retention_limit',
    ):
        if Settings.userip_backup_frequency != 'Disabled':
            run_userip_backup_async()
        else:
            prune_old_backups()

    voice_newly_enabled = bool(new_values.get('voice_notifications_enabled')) and not bool(old_values.get('voice_notifications_enabled'))
    gta5_newly_enabled = new_values.get('capture_feature_set') == 'GTA V' and old_values.get('capture_feature_set') != 'GTA V'
    if voice_newly_enabled or gta5_newly_enabled:
        retrigger_userip = False
        for player in PlayersRegistry.get_connected_players():
            if player.left_event.is_set() or player.userip is None or player.userip_detection is None or not player.userip_detection.as_processed_task:
                continue
            if (voice_newly_enabled and bool(player.userip.settings.voice_notifications)) or (
                gta5_newly_enabled and player.userip.settings.protection.enabled and CaptureState.is_local_capture()
            ):
                player.userip_detection.as_processed_task = False
                retrigger_userip = True
        if retrigger_userip:
            wake_rendering_core()

    retrigger_detections_scan()
