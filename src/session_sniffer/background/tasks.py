"""Background tasks for UserIP processing and detection notifications."""

import csv
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from threading import Lock, Thread
from typing import TYPE_CHECKING, Literal, NamedTuple, TypedDict, cast

from session_sniffer import msgbox
from session_sniffer.background.cores import enqueue_player_for_resolution
from session_sniffer.background.events import gui_closed__event
from session_sniffer.background.voice_notifications import queue_voice_notification, tts_voice_name
from session_sniffer.constants.local import DETECTION_LOGGING_PATH, PROTECTION_LOGGING_PATH, TTS_DIR_PATH, USERIP_DATABASES_DIR_PATH, USERIP_LOGGING_PATH
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.core import ScriptControl, terminate_on_uncaught_exception
from session_sniffer.error_messages import format_type_error
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.country_data import matches_country
from session_sniffer.guis.tables_player_actions._detection_dialogs import (
    DetectionNotificationInfo,
    NotificationType,
    PlayerDetectionInfo,
    show_detection_notification_dialog,
    show_player_detection_dialog,
)
from session_sniffer.guis.tables_player_actions._userip_dialog import show_userip_detected_dialog
from session_sniffer.guis.utils import find_main_window
from session_sniffer.models.player import Player, PlayerUserIPDetection
from session_sniffer.networking.geolite2 import query_geolite2_asn, query_geolite2_city, query_geolite2_country
from session_sniffer.networking.third_party_servers import ThirdPartyServers, is_ip_in_ranges
from session_sniffer.player.combo_rules import ComboRulesManager, matches_asn_entry, matches_player_isp
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIP, UserIPDatabases, gui_dispatcher
from session_sniffer.player.userip_loader import append_userip_entry_if_missing, record_userip_detection, record_userip_last_seen, update_userip_databases
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.rendering_core.types import CaptureState, CaptureStats
from session_sniffer.settings import Settings
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

_GTA5_RELAY_RANGES = ThirdPartyServers.get_ip_obj_ranges_for(['TAKETWO_INTERACTIVE', 'MICROSOFT'])
_DETECTION_CSV_HEADERS = ('Detection', 'Usernames', 'IP', 'Date', 'Time', 'Country')
_USERIP_CSV_HEADERS = ('Database', 'Usernames', 'IP', 'Date', 'Time', 'Country')


class _DetectionSettings(NamedTuple):
    voice: Literal['Male', 'Female'] | bool
    log: bool
    msgbox: bool
    tts_filename: str
    suspend_enabled: bool = False
    suspend_duration: int | Literal['Auto'] = 'Auto'
    suspension_name: str = ''


def _on_pool_task_done(future: Future[None]) -> None:
    """Crash the app when a pool task raised an unexpected exception."""
    exc = future.exception()
    if exc is None:
        return
    terminate_on_uncaught_exception(exc)


_detection_logging_file_write_lock = Lock()
_protection_logging_file_write_lock = Lock()
_userip_logging_file_write_lock = Lock()


def _append_csv_log_row(lock: Lock, csv_path: Path, headers: Sequence[str], row: Sequence[str]) -> None:
    """Thread-safely append a row to a CSV log file, writing headers if the file is new or empty."""
    with lock:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        write_csv_header = not csv_path.exists() or not csv_path.stat().st_size
        with csv_path.open('a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            if write_csv_header:
                writer.writerow(headers)
            writer.writerow(row)


def _log_to_protection_csv(detection: str, usernames: str, ip: str, country: str) -> None:
    """Append a protection event entry to Protection_Logging.csv."""
    now = datetime.now(tz=LOCAL_TZ)
    _append_csv_log_row(
        _protection_logging_file_write_lock,
        PROTECTION_LOGGING_PATH,
        _DETECTION_CSV_HEADERS,
        [detection, usernames, ip, now.strftime('%Y-%m-%d'), now.strftime('%H:%M:%S'), country],
    )


_active_userip_tasks: set[tuple[str, Literal['connected', 'disconnected']]] = set()
_active_userip_tasks_lock = Lock()
_active_detection_check_ips: set[str] = set()
_pending_detection_rescan_ips: set[str] = set()
_detection_check_lock = Lock()
_fired_detections: dict[tuple[str, int], dict[str, tuple[object, ...]]] = {}
_active_global_suspend_reasons: dict[str, set[str]] = {}
_fired_detections_lock = Lock()
_MINUTE_INTERVAL_SECONDS = 60.0
_ONE_SECOND_TD = timedelta(seconds=1)
_notification_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix='Notification')
_detection_check_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='DetectionCheck')


def _check_userip_usernames(player: Player) -> bool:
    """Check if player has usernames in userip data."""
    return isinstance(player.userip, UserIP) and len(player.userip.usernames) > 0


def _check_reverse_dns_hostname(player: Player) -> bool:
    """Check if player reverse DNS is initialized."""
    return player.reverse_dns.is_initialized


def _check_iplookup_geolite2(player: Player) -> bool:
    """Check if player GeoLite2 data is initialized."""
    if not player.iplookup.geolite2.is_initialized:
        player.iplookup.geolite2.country, player.iplookup.geolite2.country_code = query_geolite2_country(player.ip)
        player.iplookup.geolite2.city = query_geolite2_city(player.ip)
        player.iplookup.geolite2.asn = query_geolite2_asn(player.ip)
        player.iplookup.geolite2.is_initialized = True
    return True


def _check_iplookup_ipapi(player: Player) -> bool:
    """Check if player IP API data is initialized."""
    return player.iplookup.ipapi.is_initialized


_FIELD_CHECKERS: dict[str, Callable[[Player], bool]] = {
    'userip.usernames': _check_userip_usernames,
    'reverse_dns.hostname': _check_reverse_dns_hostname,
    'iplookup.geolite2': _check_iplookup_geolite2,
    'iplookup.ipapi': _check_iplookup_ipapi,
}


def wait_for_player_data_ready(
    player: Player,
    *,
    data_fields: tuple[Literal['userip.usernames', 'reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'], ...],
    timeout: float,
) -> bool:
    """Wait for specific player data fields to be ready for display.

    Args:
        player: The player object to wait for
        data_fields: Tuple of data field paths to wait for
        timeout: Maximum time to wait for data to be ready

    Returns:
        Whether all specified data is ready before the timeout expires.
    """
    deadline = time.monotonic() + timeout

    checker_items = [_FIELD_CHECKERS[field] for field in data_fields if field in _FIELD_CHECKERS]

    while True:
        if player.left_event.is_set() or gui_closed__event.is_set():
            break

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        if all(checker(player) for checker in checker_items):
            return True

        gui_closed__event.wait(min(0.02, remaining))

    return False


class NotificationConfig(TypedDict):
    """Type definition for notification configuration."""

    title: str
    description: str
    icon: msgbox.Style
    thread_name: str


_NOTIFICATION_TYPE_SETTING_PREFIX: dict[NotificationType, str] = {
    'player_joined_session': 'player_join',
    'player_rejoined_session': 'player_rejoin',
    'player_left_session': 'player_leave',
}

_NOTIFICATION_CONFIGS: dict[NotificationType, NotificationConfig] = {
    'player_joined_session': {
        'title': 'PLAYER JOINED SESSION!',
        'description': 'A new player has joined your session!',
        'icon': msgbox.Style.MB_ICONINFORMATION,
        'thread_name': 'PlayerJoined',
    },
    'player_rejoined_session': {
        'title': 'PLAYER REJOINED SESSION!',
        'description': 'A player has rejoined your session after disconnecting!',
        'icon': msgbox.Style.MB_ICONINFORMATION,
        'thread_name': 'PlayerRejoined',
    },
    'player_left_session': {
        'title': 'PLAYER LEFT SESSION!',
        'description': 'A player has left your session!',
        'icon': msgbox.Style.MB_ICONINFORMATION,
        'thread_name': 'PlayerLeft',
    },
}

_NOTIFICATION_TO_EVENT: dict[NotificationType, str] = {
    'player_joined_session': 'join',
    'player_rejoined_session': 'rejoin',
    'player_left_session': 'leave',
}


def handle_detection_notification(
    player: Player,
    notification_type: NotificationType,
) -> None:
    """Handle voice notifications, logging, message box popups, and suspension actions for player connection events.

    This function now reads all settings from GUIDetectionSettings and is used only for
    player_joined_session, player_rejoined_session, and player_left_session events.
    VPN/hosting/mobile notifications are handled by check_global_detections.

    Args:
        player: The player object with detection data
        notification_type: Type of notification - `player_joined_session`,
            `player_rejoined_session`, or `player_left_session`
    """
    prefix = _NOTIFICATION_TYPE_SETTING_PREFIX[notification_type]

    enabled = cast('bool', getattr(GUIDetectionSettings, f'{prefix}_enabled'))
    voice_setting = cast('Literal["Male", "Female"] | bool', getattr(GUIDetectionSettings, f'{prefix}_voice_notifications'))
    logging_setting = cast('bool', getattr(GUIDetectionSettings, f'{prefix}_logging'))
    msgbox_setting = cast('bool', getattr(GUIDetectionSettings, f'{prefix}_message_box'))

    # Check if there are combo rules with event conditions that might need evaluation
    has_event_combo_rules = any(rule.has_event_condition for rule in ComboRulesManager.rules if rule.enabled)

    standalone_active = enabled or voice_setting or logging_setting or msgbox_setting
    if not standalone_active and not has_event_combo_rules:
        return

    def notification_thread() -> None:
        """Thread function to handle voice, logging, message box, and suspension actions."""
        config = _NOTIFICATION_CONFIGS[notification_type]

        data_ready = False

        if standalone_active:
            duration = cast('int | Literal["Auto"]', getattr(GUIDetectionSettings, f'{prefix}_duration'))

            # Execute suspension action (only when enabled and suspension is supported)
            if enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
                GTASuspendManager.request_suspend(
                    reason_key=f'event:{notification_type}:{player.ip}',
                    left_event=player.left_event,
                    duration=duration,
                )

            # Voice notification (queued, plays sequentially through VoiceNotificationWorker)
            if Settings.voice_notifications_enabled and voice_setting:
                tts_candidate_path = TTS_DIR_PATH / tts_voice_name(voice_setting=voice_setting) / 'event' / f'{notification_type}.wav'
                queue_voice_notification(tts_candidate_path)

            data_ready = wait_for_player_data_ready(player, data_fields=('iplookup.geolite2', 'reverse_dns.hostname', 'iplookup.ipapi'), timeout=3.0)

            # Detection logging
            if logging_setting:
                now = datetime.now(tz=LOCAL_TZ)
                _append_csv_log_row(
                    _detection_logging_file_write_lock,
                    DETECTION_LOGGING_PATH,
                    _DETECTION_CSV_HEADERS,
                    [config['title'], ', '.join(player.usernames), player.ip, now.strftime('%Y-%m-%d'), now.strftime('%H:%M:%S'), player.iplookup.geolite2.country],
                )

            # Message box popup
            if msgbox_setting:
                _info = PlayerDetectionInfo(
                    event_type=notification_type,
                    title=config['title'],
                    description=config['description'],
                    event_time=datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S'),
                    data_ready=data_ready,
                )

                def _show_detection_dialog() -> None:
                    show_player_detection_dialog(find_main_window(), player, _info)

                gui_dispatcher.invoke(_show_detection_dialog)

        # Combo Rules evaluation (rules WITH event condition fire here)
        combo_event = _NOTIFICATION_TO_EVENT.get(notification_type)
        if combo_event is not None:
            _check_iplookup_geolite2(player)
            if not data_ready and ComboRulesManager.needs_ipapi(event_rules=True, geo_country_missing=player.iplookup.geolite2.country_code in ('...', 'N/A')):
                wait_for_player_data_ready(player, data_fields=('iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

            matched_combo_rules = ComboRulesManager.evaluate(player, event_type=combo_event)
            for rule in matched_combo_rules:
                # Suspension action
                if rule.protection_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture():
                    GTASuspendManager.request_suspend(
                        reason_key=f'combo:{rule.name}:{player.ip}',
                        left_event=player.left_event,
                        duration=rule.duration,
                    )

                # Voice notification
                if Settings.voice_notifications_enabled and rule.voice_notifications:
                    tts_candidate_path = TTS_DIR_PATH / tts_voice_name(voice_setting=rule.voice_notifications) / 'detection' / 'combo_rule_detected.wav'
                    queue_voice_notification(tts_candidate_path)

                # Logging
                if rule.logging:
                    _log_to_protection_csv(
                        f'COMBO RULE MATCHED: {rule.name}',
                        ', '.join(player.usernames),
                        player.ip,
                        player.iplookup.geolite2.country,
                    )

                # Message box
                if rule.message_box and player.userip is None:
                    conditions_summary = ', '.join(f'{key}={value}' for key, value in rule.conditions.items() if key != 'event')
                    _display_title = f'Combo Rule Matched: {rule.name}'
                    _extra: list[tuple[str, str]] = [('Event', combo_event), ('Conditions', conditions_summary)]
                    _et = datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')

                    def _make_event_combo_notif(title: str, extra_fields: list[tuple[str, str]], event_time_str: str) -> None:
                        def _callback() -> None:
                            show_detection_notification_dialog(
                                find_main_window(),
                                player,
                                DetectionNotificationInfo(display_title=title, extra_detection_fields=extra_fields, event_time=event_time_str),
                            )

                        gui_dispatcher.invoke(_callback)

                    _make_event_combo_notif(_display_title, _extra, _et)

    _notification_pool.submit(notification_thread).add_done_callback(_on_pool_task_done)


def process_userip_task(
    player: Player,
    userip: UserIP,
    connection_type: Literal['connected', 'disconnected'],
) -> None:
    """Process a queued UserIP task for a player on a background thread.

    Args:
        player: The player object to process.
        userip: The resolved UserIP snapshot captured at task-spawn time.
            Passed directly so this task never depends on `player.userip`,
            which may be temporarily `None` during a database re-parse.
        connection_type: Either `'connected'` or `'disconnected'`.
    """
    userip_detection = player.userip_detection
    if userip_detection is None:
        raise TypeError(format_type_error(userip_detection, PlayerUserIPDetection))

    task_key: tuple[str, Literal['connected', 'disconnected']] = (player.ip, connection_type)
    with _active_userip_tasks_lock:
        if task_key in _active_userip_tasks:
            return
        _active_userip_tasks.add(task_key)

    try:
        # We want to run this as fast as possible so it's on top of the function.
        # Protection actions are skipped when protection is not supported.
        protection_triggered = (
            connection_type == 'connected'
            and userip.settings.protection.enabled
            and Settings.is_gta5_feature_set()
            and CaptureState.is_local_capture()
        )
        if protection_triggered:
            GTASuspendManager.request_suspend(
                reason_key=f'userip:{player.ip}',
                left_event=player.left_event,
                duration=userip.settings.protection.suspend_process_mode,
            )

        if Settings.voice_notifications_enabled and userip.settings.voice_notifications:
            tts_candidate_path = TTS_DIR_PATH / tts_voice_name(voice_setting=userip.settings.voice_notifications) / 'userip' / f'{connection_type}.wav'
            queue_voice_notification(tts_candidate_path)

        if connection_type == 'connected':
            updated_userip = record_userip_detection(userip.db_path, player.ip, player.datetime.last_rejoin)
        else:
            updated_userip = record_userip_last_seen(userip.db_path, player.ip, player.datetime.last_seen)
        if updated_userip is not None:
            userip = updated_userip
            player.userip = updated_userip
            wake_rendering_core()

        if player.userip is None:
            player.userip = userip
        if userip.usernames:
            player.usernames = dedup_preserve_order(player.usernames, userip.usernames)

        if connection_type == 'connected':
            if userip.settings.notifications:

                def _show_userip_dialog() -> None:
                    show_userip_detected_dialog(find_main_window(), player, userip)

                gui_dispatcher.invoke(_show_userip_dialog)

            if protection_triggered or userip.settings.log:
                wait_for_player_data_ready(player, data_fields=('userip.usernames', 'iplookup.geolite2'), timeout=10.0)

                relative_database_path = userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
                date_part, time_part = userip_detection.date_time.split('_', maxsplit=1)
                usernames_display = ', '.join(player.usernames) or ', '.join(userip.usernames)

                if protection_triggered:
                    _log_to_protection_csv(
                        f'USERIP PROTECTION: {relative_database_path}',
                        usernames_display,
                        player.ip,
                        player.iplookup.geolite2.country,
                    )

                if userip.settings.log:
                    _append_csv_log_row(
                        _userip_logging_file_write_lock,
                        USERIP_LOGGING_PATH,
                        _USERIP_CSV_HEADERS,
                        [
                            str(relative_database_path),
                            ', '.join(userip.usernames),
                            player.ip,
                            date_part,
                            time_part,
                            player.iplookup.geolite2.country,
                        ],
                    )
    finally:
        with _active_userip_tasks_lock:
            _active_userip_tasks.discard(task_key)


def spawn_connected_userip_detection(
    player: Player,
    userip: UserIP,
    *,
    detection_type: Literal['Static IP', 'Username'] | None = None,
) -> None:
    """Assign `userip` and `userip_detection` on `player` and start `process_userip_task`."""
    now = datetime.now(tz=LOCAL_TZ)
    effective_type: Literal['Static IP', 'Username'] = (
        detection_type
        if detection_type is not None
        else (player.userip_detection.type if player.userip_detection is not None else 'Static IP')
    )
    player.userip = userip
    if userip.usernames:
        player.usernames = dedup_preserve_order(player.usernames, userip.usernames)
    player.userip_detection = PlayerUserIPDetection(
        time=now.strftime('%H:%M:%S'),
        date_time=now.strftime('%Y-%m-%d_%H:%M:%S'),
        type=effective_type,
    )
    Thread(
        target=process_userip_task,
        name=f'ProcessUserIPTask-{player.ip}-connected',
        args=(player, userip, 'connected'),
        daemon=True,
    ).start()


def trigger_auto_username_userip(player: Player, detected_usernames: Sequence[str]) -> None:
    """Auto-detect player UserIP from username and auto-feed matching database.

    Exclusively active on PC (GTA V feature set and local capture).
    """
    if not (Settings.userip_auto_feed_from_usernames and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()):
        return

    if not detected_usernames:
        return

    if player.userip is not None or UserIPDatabases.is_known_ip(player.ip) or UserIPDatabases.is_conflicting_ip(player.ip):
        return

    candidate_usernames = dedup_preserve_order(detected_usernames, player.usernames)
    matched = UserIPDatabases.resolve_userip_by_usernames(candidate_usernames, player.ip)
    if matched is None:
        return

    resolved_userip, matched_username = matched

    # Auto-feed the database if entry is not present
    appended = append_userip_entry_if_missing(resolved_userip.db_path, matched_username, player.ip)
    if appended:
        update_userip_databases()
        resolved_userip = UserIPDatabases.resolve_userip(player.ip) or resolved_userip

    if UserIPDatabases.is_conflicting_ip(player.ip):
        return

    # Immediate detection if not already processed
    should_trigger_detection = player.userip_detection is None or not player.userip_detection.as_processed_task
    if should_trigger_detection:
        spawn_connected_userip_detection(player, resolved_userip, detection_type='Username')
    elif resolved_userip.usernames:
        player.usernames = dedup_preserve_order(player.usernames, resolved_userip.usernames)

    wake_rendering_core()


def is_gta5_relay_ip(ip: str) -> bool:
    """Return True if *ip* belongs to the GTAV Take-Two Interactive or Microsoft relay IP ranges."""
    return is_ip_in_ranges(IPv4Address(ip), _GTA5_RELAY_RANGES)


def is_gta5_relay_monitoring_active() -> bool:
    """Return True if GTA5 relay monitoring is active and has any actionable notification or response enabled."""
    if not Settings.is_gta5_feature_set() or not GUIDetectionSettings.has_any_gta5_relay_action_enabled():
        return False
    if CaptureState.is_local_capture() and not CaptureState.gta5_is_running:
        return False
    return (
        GUIDetectionSettings.gta5_relay_enabled
        or (Settings.voice_notifications_enabled and bool(GUIDetectionSettings.gta5_relay_voice_notifications))
        or GUIDetectionSettings.gta5_relay_logging
        or GUIDetectionSettings.gta5_relay_message_box
    )


def monitor_gta5_relay_task(player: Player) -> None:
    """Monitor a GTA5 relay IP, flag it in the table, and trigger relay actions when relay traffic is sustained."""
    if not Settings.is_gta5_feature_set() or not is_gta5_relay_ip(player.ip):
        return

    prev_exchanged = player.packets.exchanged
    wave_start_exchanged, wave_start_download, wave_start_upload = 0, 0, 0
    last_pps_update_time = player.packets.pps.last_update_time
    streak_seconds = 0.0
    max_streak_seconds = 0.0

    while not player.left_event.is_set() and not gui_closed__event.is_set() and PlayersRegistry.is_player_connected(player):
        if not Settings.is_gta5_feature_set() or (CaptureState.is_local_capture() and not CaptureState.gta5_is_running):
            player.relay_monitor_started = False
            return

        curr_exchanged = player.packets.exchanged
        if curr_exchanged < prev_exchanged:
            wave_start_exchanged, wave_start_download, wave_start_upload = 0, 0, 0
            streak_seconds, max_streak_seconds = 0.0, 0.0
        prev_exchanged = curr_exchanged

        curr_pps_update_time = player.packets.pps.last_update_time
        if curr_pps_update_time > last_pps_update_time:
            curr_pps = player.packets.pps.calculated_rate if (not CaptureState.is_local_capture() or player.is_gta5_process) else 0
            if not curr_pps:
                wave_start_exchanged = curr_exchanged - player.packets.pps.accumulated_packets
                wave_start_download = player.bandwidth.download
                wave_start_upload = player.bandwidth.upload
                streak_seconds, max_streak_seconds = 0.0, 0.0
            elif curr_pps >= Settings.gta5_relay_min_pps:
                streak_seconds += curr_pps_update_time - last_pps_update_time
                max_streak_seconds = max(max_streak_seconds, streak_seconds)
            else:
                streak_seconds = 0.0
            last_pps_update_time = curr_pps_update_time

            if (
                max_streak_seconds >= Settings.gta5_relay_streak_duration
                and (curr_exchanged - wave_start_exchanged) >= Settings.gta5_relay_packet_threshold
                and max(player.bandwidth.download - wave_start_download, player.bandwidth.upload - wave_start_upload)
                >= Settings.gta5_relay_min_bandwidth_kb * 1024
            ):
                break

        gui_closed__event.wait(0.25)

    if player.left_event.is_set() or gui_closed__event.is_set() or not PlayersRegistry.is_player_connected(player):
        return

    if not player.is_gta5_relay:
        player.is_gta5_relay = True
        wake_rendering_core()

    if not is_gta5_relay_monitoring_active():
        player.relay_monitor_started = False
        return

    if GUIDetectionSettings.gta5_relay_enabled and CaptureState.is_local_capture():
        GTASuspendManager.request_suspend(
            reason_key=f'gta5_relay:{player.ip}', left_event=player.left_event, duration=GUIDetectionSettings.gta5_relay_duration,
        )

    if Settings.voice_notifications_enabled and GUIDetectionSettings.gta5_relay_voice_notifications:
        tts_candidate_path = TTS_DIR_PATH / tts_voice_name(voice_setting=GUIDetectionSettings.gta5_relay_voice_notifications) / 'detection' / 'gta5_relay_detected.wav'
        queue_voice_notification(tts_candidate_path)

    if GUIDetectionSettings.gta5_relay_logging or GUIDetectionSettings.gta5_relay_message_box:
        required_fields: tuple[Literal['iplookup.geolite2', 'reverse_dns.hostname', 'iplookup.ipapi'], ...] = (
            ('iplookup.geolite2', 'reverse_dns.hostname', 'iplookup.ipapi') if GUIDetectionSettings.gta5_relay_message_box else ('iplookup.geolite2',)
        )
        wait_for_player_data_ready(player, data_fields=required_fields, timeout=3.0)

    if GUIDetectionSettings.gta5_relay_logging:
        _log_to_protection_csv('GTA5 RELAY DETECTED!', ', '.join(player.usernames), player.ip, player.iplookup.geolite2.country)

    if GUIDetectionSettings.gta5_relay_message_box:
        _et = datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')

        def _show_relay_notif() -> None:
            notification_info = DetectionNotificationInfo(
                display_title='GTA5 Relay Detected', extra_detection_fields=[('Packets', str(player.packets.exchanged))], event_time=_et,
            )
            show_detection_notification_dialog(find_main_window(), player, notification_info)

        gui_dispatcher.invoke(_show_relay_notif)


def check_global_detections(player: Player) -> None:
    """Check and apply global detection settings from Detections Manager.

    This function evaluates various detection rules configured in the Detections Manager
    and triggers appropriate actions when conditions are met.

    Args:
        player: The player object to check detections against.
    """
    _check_iplookup_geolite2(player)
    geo_missing = player.iplookup.geolite2.country_code in ('...', 'N/A')
    if GUIDetectionSettings.has_any_ipapi_detection_enabled(geo_country_missing=geo_missing) or ComboRulesManager.needs_ipapi(
        event_rules=False, geo_country_missing=geo_missing,
    ):
        wait_for_player_data_ready(player, data_fields=('iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)
    if player.left_event.is_set() or not PlayersRegistry.is_player_connected(player):
        return

    join_key = (player.ip, player.rejoins)
    with _fired_detections_lock:
        for stale_key in [key for key in _fired_detections if key[0] == player.ip and key[1] != player.rejoins]:
            del _fired_detections[stale_key]
        fired_map = _fired_detections.setdefault(join_key, {})
    current_active_titles: set[str] = set()
    current_suspend_reasons: set[str] = set()

    def execute_suspension_action(duration: int | Literal['Auto'], suspension_name: str) -> None:
        """Execute a suspension action."""
        if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
            return
        GTASuspendManager.request_suspend(reason_key=f'global:{suspension_name}:{player.ip}', left_event=player.left_event, duration=duration)

    def handle_detection_notifications(
        detection_title: str,
        display_title: str,
        extra_detection_fields: list[tuple[str, str]],
        settings: _DetectionSettings,
    ) -> None:
        """Handle per-join deduplication, suspension, voice, logging, and message box for a detection."""
        effective_suspend = settings.suspend_enabled and bool(settings.suspension_name) and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
        effective_voice: Literal['Male', 'Female'] | bool = settings.voice if Settings.voice_notifications_enabled and settings.voice else False
        effective_log = settings.log
        effective_msgbox = settings.msgbox and player.userip is None
        if not (effective_suspend or bool(effective_voice) or effective_log or effective_msgbox):
            return
        current_active_titles.add(detection_title)
        if effective_suspend:
            current_suspend_reasons.add(f'global:{settings.suspension_name}:{player.ip}')
        signature = (detection_title, effective_suspend, settings.suspend_duration if effective_suspend else None, effective_voice, effective_log, effective_msgbox)
        with _fired_detections_lock:
            if fired_map.get(detection_title) == signature:
                return
            fired_map[detection_title] = signature

        if effective_suspend:
            execute_suspension_action(settings.suspend_duration, settings.suspension_name)

        if effective_voice:
            tts_candidate_path = TTS_DIR_PATH / tts_voice_name(voice_setting=effective_voice) / 'detection' / f'{settings.tts_filename}.wav'
            queue_voice_notification(tts_candidate_path)

        if effective_log:
            _log_to_protection_csv(detection_title, ', '.join(player.usernames), player.ip, player.iplookup.geolite2.country)

        if effective_msgbox:
            _event_time = datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')

            def _show_detection_notif() -> None:
                info = DetectionNotificationInfo(display_title=display_title, extra_detection_fields=extra_detection_fields, event_time=_event_time)
                show_detection_notification_dialog(find_main_window(), player, info)

            gui_dispatcher.invoke(_show_detection_notif)

    is_server_ip = player.is_third_party_server

    # Mobile Connection Detection
    if player.iplookup.ipapi.is_initialized and player.iplookup.ipapi.mobile is True:
        handle_detection_notifications(
            detection_title='MOBILE CONNECTION DETECTED!',
            display_title='Mobile Connection Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=False if is_server_ip else GUIDetectionSettings.mobile_voice_notifications,
                log=GUIDetectionSettings.mobile_logging,
                msgbox=GUIDetectionSettings.mobile_message_box,
                tts_filename='mobile_connection_detected',
                suspend_enabled=GUIDetectionSettings.mobile_suspend_enabled,
                suspend_duration=GUIDetectionSettings.mobile_suspend_duration,
                suspension_name='MobileDetection',
            ),
        )

    # VPN/Proxy/Tor Detection
    if player.iplookup.ipapi.is_initialized and player.iplookup.ipapi.proxy is True:
        handle_detection_notifications(
            detection_title='VPN/PROXY/TOR CONNECTION DETECTED!',
            display_title='VPN/Proxy/Tor Connection Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=False if is_server_ip else GUIDetectionSettings.vpn_voice_notifications,
                log=GUIDetectionSettings.vpn_logging,
                msgbox=GUIDetectionSettings.vpn_message_box,
                tts_filename='vpn_connection_detected',
                suspend_enabled=GUIDetectionSettings.vpn_suspend_enabled,
                suspend_duration=GUIDetectionSettings.vpn_suspend_duration,
                suspension_name='VPNDetection',
            ),
        )

    # Hosting/Data Center Detection
    if player.iplookup.ipapi.is_initialized and player.iplookup.ipapi.hosting is True:
        handle_detection_notifications(
            detection_title='HOSTING/DATA CENTER CONNECTION DETECTED!',
            display_title='Hosting/Data Center Connection Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=False if is_server_ip else GUIDetectionSettings.hosting_voice_notifications,
                log=GUIDetectionSettings.hosting_logging,
                msgbox=GUIDetectionSettings.hosting_message_box,
                tts_filename='hosting_connection_detected',
                suspend_enabled=GUIDetectionSettings.hosting_suspend_enabled,
                suspend_duration=GUIDetectionSettings.hosting_suspend_duration,
                suspension_name='HostingDetection',
            ),
        )

    # Country Detection
    if GUIDetectionSettings.country_detection_list and any(
        matches_country(country, player.iplookup.geolite2.country, player.iplookup.geolite2.country_code, player.iplookup.ipapi.country, player.iplookup.ipapi.country_code)
        for country in GUIDetectionSettings.country_detection_list
    ):
        handle_detection_notifications(
            detection_title='BLOCKED COUNTRY DETECTED!',
            display_title='Blocked Country Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=GUIDetectionSettings.country_voice_notifications,
                log=GUIDetectionSettings.country_logging,
                msgbox=GUIDetectionSettings.country_message_box,
                tts_filename='country_detected',
                suspend_enabled=GUIDetectionSettings.country_suspend_enabled,
                suspend_duration=GUIDetectionSettings.country_suspend_duration,
                suspension_name='CountryDetection',
            ),
        )

    # ISP Detection
    if GUIDetectionSettings.isp_detection_list and (player.iplookup.ipapi.is_initialized or player.iplookup.geolite2.is_initialized):
        matched_isp = next((block_entry for block_entry in GUIDetectionSettings.isp_detection_list if matches_player_isp(block_entry, player)), None)

        if matched_isp is not None:
            handle_detection_notifications(
                detection_title='BLOCKED ISP DETECTED!',
                display_title='Blocked ISP Detected',
                extra_detection_fields=[('Matched Entry', matched_isp)],
                settings=_DetectionSettings(
                    voice=GUIDetectionSettings.isp_voice_notifications,
                    log=GUIDetectionSettings.isp_logging,
                    msgbox=GUIDetectionSettings.isp_message_box,
                    tts_filename='isp_detected',
                    suspend_enabled=GUIDetectionSettings.isp_suspend_enabled,
                    suspend_duration=GUIDetectionSettings.isp_suspend_duration,
                    suspension_name='ISPDetection',
                ),
            )

    # ASN Detection
    if GUIDetectionSettings.asn_detection_list:
        asns_to_check: list[str] = []
        if player.iplookup.ipapi.is_initialized and player.iplookup.ipapi.asn and player.iplookup.ipapi.asn not in ('...', 'N/A'):
            asns_to_check.append(player.iplookup.ipapi.asn)
        if player.iplookup.geolite2.is_initialized and player.iplookup.geolite2.asn and player.iplookup.geolite2.asn not in ('...', 'N/A'):
            asns_to_check.append(player.iplookup.geolite2.asn)

        if asns_to_check:
            matched_asn = None
            for block_entry in GUIDetectionSettings.asn_detection_list:
                for asn in asns_to_check:
                    if matches_asn_entry(block_entry, asn):
                        matched_asn = asn
                        break
                if matched_asn is not None:
                    break

            if matched_asn is not None:
                if player.iplookup.ipapi.is_initialized and player.iplookup.geolite2.is_initialized:
                    asn_display = (
                        f'IP-API: {player.iplookup.ipapi.asn}, GeoLite2: {player.iplookup.geolite2.asn}'
                        if player.iplookup.ipapi.asn != player.iplookup.geolite2.asn
                        else matched_asn
                    )
                else:
                    asn_display = matched_asn
                handle_detection_notifications(
                    detection_title='BLOCKED ASN DETECTED!',
                    display_title='Blocked ASN Detected',
                    extra_detection_fields=[('ASN', asn_display)],
                    settings=_DetectionSettings(
                        voice=GUIDetectionSettings.asn_voice_notifications,
                        log=GUIDetectionSettings.asn_logging,
                        msgbox=GUIDetectionSettings.asn_message_box,
                        tts_filename='asn_detected',
                        suspend_enabled=GUIDetectionSettings.asn_suspend_enabled,
                        suspend_duration=GUIDetectionSettings.asn_suspend_duration,
                        suspension_name='ASNDetection',
                    ),
                )

    # Combo Rules evaluation (rules without event condition fire here at join-time)
    matched_combo_rules = ComboRulesManager.evaluate(player, event_type=None)
    for rule in matched_combo_rules:
        conditions_summary = ', '.join(f'{key}={value}' for key, value in rule.conditions.items() if key != 'event')
        handle_detection_notifications(
            detection_title=f'COMBO RULE MATCHED: {rule.name}',
            display_title=f'Combo Rule Matched: {rule.name}',
            extra_detection_fields=[('Conditions', conditions_summary)],
            settings=_DetectionSettings(
                voice=rule.voice_notifications,
                log=rule.logging,
                msgbox=rule.message_box,
                tts_filename='combo_rule_detected',
                suspend_enabled=rule.protection_enabled,
                suspend_duration=rule.duration,
                suspension_name=f'ComboRule:{rule.name}',
            ),
        )

    with _fired_detections_lock:
        for stale_title in [title for title in fired_map if title not in current_active_titles]:
            del fired_map[stale_title]
        prev_suspend_reasons = _active_global_suspend_reasons.get(player.ip, set())
        stale_suspend_reasons = prev_suspend_reasons - current_suspend_reasons
        if current_suspend_reasons:
            _active_global_suspend_reasons[player.ip] = current_suspend_reasons
        else:
            _active_global_suspend_reasons.pop(player.ip, None)
    for stale_reason in stale_suspend_reasons:
        GTASuspendManager.release_reason_global(stale_reason)


def _run_global_detections_check(player: Player) -> None:
    """Run `check_global_detections(player)`, re-running once if a rescan was requested while active."""
    try:
        while True:
            check_global_detections(player)
            with _detection_check_lock:
                if player.ip in _pending_detection_rescan_ips and not player.left_event.is_set() and PlayersRegistry.is_player_connected(player):
                    _pending_detection_rescan_ips.discard(player.ip)
                    continue
                _pending_detection_rescan_ips.discard(player.ip)
                _active_detection_check_ips.discard(player.ip)
                return
    except BaseException:
        with _detection_check_lock:
            _pending_detection_rescan_ips.discard(player.ip)
            _active_detection_check_ips.discard(player.ip)
        raise


def submit_global_detections_check(player: Player) -> None:
    """Submit global detection checks to the background detection worker pool."""
    enqueue_player_for_resolution(player)
    has_non_event_combo_rules = any(not rule.has_event_condition for rule in ComboRulesManager.rules if rule.enabled)
    if not GUIDetectionSettings.has_any_global_detection_enabled() and not has_non_event_combo_rules:
        with _fired_detections_lock:
            _fired_detections.pop((player.ip, player.rejoins), None)
            stale_reasons = _active_global_suspend_reasons.pop(player.ip, set())
        for stale_reason in stale_reasons:
            GTASuspendManager.release_reason_global(stale_reason)
        return
    with _detection_check_lock:
        if player.ip in _active_detection_check_ips:
            _pending_detection_rescan_ips.add(player.ip)
            return
        _active_detection_check_ips.add(player.ip)
    _detection_check_pool.submit(_run_global_detections_check, player).add_done_callback(_on_pool_task_done)


def retrigger_detections_scan() -> None:
    """Re-evaluate global detections, combo rules, and GTA5 relay monitoring for all connected players."""
    relay_active = Settings.is_gta5_feature_set() and (CaptureState.gta5_is_running or not CaptureState.is_local_capture())
    for player in PlayersRegistry.get_connected_players():
        if player.left_event.is_set():
            continue
        player.detection_checked = True
        submit_global_detections_check(player)
        if relay_active and not player.relay_monitor_started and (player.is_gta5_process or not CaptureState.is_local_capture()) and is_gta5_relay_ip(player.ip):
            player.relay_monitor_started = True
            Thread(target=monitor_gta5_relay_task, name=f'GTA5RelayMonitor-{player.ip}', args=(player,), daemon=True).start()


def player_rates_core() -> None:
    """Compute per-player rate metrics and aggregate global capture stats at 1-second intervals.

    Runs in a dedicated background thread so that PPS/PPM/BPS/BPM calculations stay on a
    precise 1-second timer, independent of the rendering loop cadence.
    """
    while not gui_closed__event.is_set():
        _start = time.monotonic()

        if ScriptControl.has_crashed():
            return

        global_bandwidth = global_download = global_upload = 0
        global_bps_rate = global_bpm_rate = global_pps_rate = 0

        current_time = time.monotonic()
        for index, player in enumerate(PlayersRegistry.get_connected_players()):
            if player.left_event.is_set():
                continue

            if index > 0 and not index % 500:
                time.sleep(0)

            if (current_time - player.packets.pps.last_update_time) >= 1.0:
                player.packets.pps.calculate_and_update_rate(current_time)
            if (current_time - player.packets.ppm.last_update_time) >= _MINUTE_INTERVAL_SECONDS:
                player.packets.ppm.calculate_and_update_rate(current_time)
            if (current_time - player.bandwidth.bps.last_update_time) >= 1.0:
                player.bandwidth.bps.calculate_and_update_rate(current_time)
            if (current_time - player.bandwidth.bpm.last_update_time) >= _MINUTE_INTERVAL_SECONDS:
                player.bandwidth.bpm.calculate_and_update_rate(current_time)

            global_bandwidth += player.bandwidth.exchanged
            global_download += player.bandwidth.download
            global_upload += player.bandwidth.upload
            global_bps_rate += player.bandwidth.bps.calculated_rate
            global_bpm_rate += player.bandwidth.bpm.calculated_rate
            global_pps_rate += player.packets.pps.calculated_rate

        CaptureStats.global_bandwidth = global_bandwidth
        CaptureStats.global_download = global_download
        CaptureStats.global_upload = global_upload
        CaptureStats.global_bps_rate = global_bps_rate
        CaptureStats.global_bpm_rate = global_bpm_rate
        CaptureStats.global_pps_rate = global_pps_rate
        CaptureStats.peak_bps_rate = max(CaptureStats.peak_bps_rate, global_bps_rate)
        CaptureStats.peak_bpm_rate = max(CaptureStats.peak_bpm_rate, global_bpm_rate)
        CaptureStats.peak_pps_rate = max(CaptureStats.peak_pps_rate, global_pps_rate)

        one_second_ago = datetime.now(tz=LOCAL_TZ) - _ONE_SECOND_TD
        recent_latencies_total_ms = 0.0
        recent_latencies_count = 0
        for timestamp, latency in reversed(tuple(CaptureStats.packets_latencies)):
            if timestamp < one_second_ago:
                break
            recent_latencies_total_ms += latency.total_seconds() * 1000
            recent_latencies_count += 1
        CaptureStats.global_avg_latency_ms = recent_latencies_total_ms / recent_latencies_count if recent_latencies_count else 0.0

        gui_closed__event.wait(max(0.05, 1.0 - (time.monotonic() - _start)))
