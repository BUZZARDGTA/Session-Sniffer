"""Background tasks for UserIP processing and detection notifications."""

import contextlib
import csv
import time
import winsound
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Literal, NamedTuple, TypedDict

from session_sniffer import msgbox
from session_sniffer.background.events import gui_closed__event
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import DETECTION_LOGGING_PATH, PROTECTION_LOGGING_PATH, TTS_DIR_PATH, USERIP_DATABASES_DIR_PATH, USERIP_LOGGING_PATH
from session_sniffer.core import ScriptControl, terminate_on_uncaught_exception
from session_sniffer.error_messages import format_type_error
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.tables_player_actions import (
    DetectionNotificationInfo,
    PlayerDetectionInfo,
    show_detection_notification_dialog,
    show_player_detection_dialog,
    show_userip_detected_dialog,
)
from session_sniffer.guis.utils import find_main_window
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.player import Player, PlayerUserIPDetection
from session_sniffer.networking.third_party_servers import ThirdPartyServers
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIP, gui_dispatcher
from session_sniffer.rendering_core.types import CaptureState, CaptureStats
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


class _DetectionSettings(NamedTuple):
    voice: Literal['Male', 'Female'] | bool
    log: bool
    msgbox: bool
    tts_filename: str


def _on_pool_task_done(future: Future[None]) -> None:
    """Crash the app when a pool task raised an unexpected exception."""
    exc = future.exception()
    if exc is None:
        return
    terminate_on_uncaught_exception(exc)


_detection_logging_file_write_lock = Lock()
_protection_logging_file_write_lock = Lock()
_userip_logging_file_write_lock = Lock()
_VOICE_QUEUE_MAXSIZE = 10
_INTER_SOUND_PAUSE_SECONDS = 0.5
_MINUTE_INTERVAL_SECONDS = 60.0
_notification_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix='Notification')
_detection_check_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='DetectionCheck')


class _DeduplicatedQueue:
    """Bounded FIFO queue that silently rejects duplicate entries."""

    def __init__(self, maxsize: int) -> None:
        self._deque: deque[str] = deque()
        self._set: set[str] = set()
        self._lock = Lock()
        self._not_empty = Event()
        self._maxsize = maxsize

    def put(self, item: str) -> None:
        """Enqueue *item* unless it is already present or the queue is full."""
        with self._lock:
            if item in self._set:
                return
            if len(self._deque) >= self._maxsize:
                logger.debug('Voice queue full (%d items); dropping %s', self._maxsize, item)
                return
            self._deque.append(item)
            self._set.add(item)
            self._not_empty.set()

    def get(self, timeout: float) -> str | None:
        """Dequeue the oldest item, waiting up to *timeout* seconds. Returns `None` on timeout.

        The item stays in the duplicate-rejection set until :meth:`acknowledge` is called,
        so concurrent enqueues of the same value are still rejected during playback.
        """
        if not self._not_empty.wait(timeout):
            return None
        with self._lock:
            if not self._deque:
                self._not_empty.clear()
                return None
            item = self._deque.popleft()
            if not self._deque:
                self._not_empty.clear()
            return item

    def acknowledge(self, item: str) -> None:
        """Remove *item* from the duplicate-rejection set after it has been fully processed."""
        with self._lock:
            self._set.discard(item)

    def clear(self) -> None:
        """Remove all pending items."""
        with self._lock:
            self._deque.clear()
            self._set.clear()
            self._not_empty.clear()

    def remove_matching(self, predicate: Callable[[str], bool]) -> None:
        """Remove all items for which *predicate(item)* is truthy."""
        with self._lock:
            kept: deque[str] = deque()
            kept_set: set[str] = set()
            for item in self._deque:
                if not predicate(item):
                    kept.append(item)
                    kept_set.add(item)
            self._deque = kept
            self._set = kept_set
            if not self._deque:
                self._not_empty.clear()


_voice_notification_queue = _DeduplicatedQueue(maxsize=_VOICE_QUEUE_MAXSIZE)


def _voice_notification_worker() -> None:
    """Singleton worker that plays queued voice notification WAV files sequentially.

    Dequeues one WAV path at a time, plays it synchronously (blocking until done),
    then waits a short pause before playing the next one. Exits when the GUI closes.
    """
    while not gui_closed__event.is_set():
        wav_path = _voice_notification_queue.get(timeout=0.1)
        if wav_path is None:
            continue
        with contextlib.suppress(RuntimeError):
            winsound.PlaySound(wav_path, winsound.SND_FILENAME | winsound.SND_NODEFAULT)
        gui_closed__event.wait(_INTER_SOUND_PAUSE_SECONDS)
        _voice_notification_queue.acknowledge(wav_path)


Thread(target=_voice_notification_worker, name='VoiceNotificationWorker', daemon=True).start()


def clear_voice_notification_queue() -> None:
    """Drain all pending voice notifications from the queue."""
    _voice_notification_queue.clear()


def clear_detection_voice_notifications() -> None:
    """Remove only detection voice notifications from the queue, keeping userip ones."""
    _voice_notification_queue.remove_matching(lambda p: 'detection' in Path(p).parts)


def _tts_voice_name(voice_setting: Literal['Male', 'Female'] | bool) -> Literal['Liam', 'Jane']:  # noqa: FBT001
    """Map a voice-notification setting to its TTS folder name (`Liam` for Male, `Jane` otherwise)."""
    return 'Liam' if voice_setting == 'Male' else 'Jane'


def _check_userip_usernames(player: Player) -> bool:
    """Check if player has usernames in userip data."""
    return isinstance(player.userip, UserIP) and len(player.userip.usernames) > 0


def _is_player_packet_flow_active(player: Player) -> bool:
    """Return `True` when a player is actively exchanging packets."""
    return player.packets.pps.accumulated_packets > 0 or player.packets.pps.calculated_rate > 0


def _check_reverse_dns_hostname(player: Player) -> bool:
    """Check if player reverse DNS is initialized."""
    return player.reverse_dns.is_initialized


def _check_iplookup_geolite2(player: Player) -> bool:
    """Check if player GeoLite2 data is initialized."""
    return player.iplookup.geolite2.is_initialized


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

        gui_closed__event.wait(min(0.1, remaining))

    return False


class NotificationConfig(TypedDict):
    """Type definition for notification configuration."""

    emoji: str
    title: str
    description: str
    icon: msgbox.Style
    thread_name: str


NotificationType = Literal[
    'player_joined_session',
    'player_rejoined_session',
    'player_left_session',
]

_NOTIFICATION_TYPE_SETTING_PREFIX: dict[NotificationType, str] = {
    'player_joined_session': 'player_join',
    'player_rejoined_session': 'player_rejoin',
    'player_left_session': 'player_leave',
}

_NOTIFICATION_CONFIGS: dict[NotificationType, NotificationConfig] = {
    'player_joined_session': {
        'emoji': '🟢',
        'title': 'PLAYER JOINED SESSION!',
        'description': 'A new player has joined your session!',
        'icon': msgbox.Style.MB_ICONINFORMATION,
        'thread_name': 'PlayerJoined',
    },
    'player_rejoined_session': {
        'emoji': '🔄',
        'title': 'PLAYER REJOINED SESSION!',
        'description': 'A player has rejoined your session after disconnecting!',
        'icon': msgbox.Style.MB_ICONINFORMATION,
        'thread_name': 'PlayerRejoined',
    },
    'player_left_session': {
        'emoji': '🔴',
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

    def notification_thread() -> None:
        """Thread function to handle voice, logging, message box, and suspension actions."""
        config = _NOTIFICATION_CONFIGS[notification_type]
        prefix = _NOTIFICATION_TYPE_SETTING_PREFIX[notification_type]

        enabled: bool = getattr(GUIDetectionSettings, f'{prefix}_enabled')
        voice_setting: Literal['Male', 'Female'] | bool = getattr(GUIDetectionSettings, f'{prefix}_voice_notifications')
        logging_setting: bool = getattr(GUIDetectionSettings, f'{prefix}_logging')
        msgbox_setting: bool = getattr(GUIDetectionSettings, f'{prefix}_message_box')

        # Check if there are combo rules with event conditions that might need evaluation
        has_event_combo_rules = any(rule.has_event_condition for rule in ComboRulesManager.rules if rule.enabled)

        standalone_active = enabled or voice_setting or logging_setting or msgbox_setting
        if not standalone_active and not has_event_combo_rules:
            return

        data_ready = False

        if standalone_active:
            duration: int | Literal['Auto'] = getattr(GUIDetectionSettings, f'{prefix}_duration')

            # Execute suspension action (only when enabled and suspension is supported)
            if enabled and Settings.is_gta5_preset() and CaptureState.is_local_capture():
                GTASuspendManager.request_suspend(
                    reason_key=f'event:{notification_type}:{player.ip}',
                    left_event=player.left_event,
                    duration=duration,
                )

            # Voice notification (queued, plays sequentially through VoiceNotificationWorker)
            if voice_setting:
                tts_candidate_path = TTS_DIR_PATH / _tts_voice_name(voice_setting) / 'event' / f'{notification_type}.wav'
                _voice_notification_queue.put(str(tts_candidate_path))

            data_ready = wait_for_player_data_ready(player, data_fields=('reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=3.0)

            # Detection logging
            if logging_setting:
                with _detection_logging_file_write_lock:
                    now = datetime.now(tz=LOCAL_TZ)
                    DETECTION_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
                    write_csv_header = not DETECTION_LOGGING_PATH.exists() or not DETECTION_LOGGING_PATH.stat().st_size
                    with DETECTION_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if write_csv_header:
                            writer.writerow(['Detection', 'Username', 'IP', 'Date', 'Time', 'Country'])
                        writer.writerow(
                            [
                                config['title'],
                                ', '.join(player.usernames),
                                player.ip,
                                now.strftime('%Y-%m-%d'),
                                now.strftime('%H:%M:%S'),
                                player.iplookup.geolite2.country,
                            ],
                        )

            # Message box popup
            if msgbox_setting:
                _info = PlayerDetectionInfo(
                    emoji=config['emoji'],
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
            # Ensure IP lookup data is ready (may already be loaded above)
            if not data_ready:
                wait_for_player_data_ready(player, data_fields=('iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

            matched_combo_rules = ComboRulesManager.evaluate(player, event_type=combo_event)
            for rule in matched_combo_rules:
                # Suspension action
                if rule.protection_enabled and Settings.is_gta5_preset() and CaptureState.is_local_capture():
                    GTASuspendManager.request_suspend(
                        reason_key=f'combo:{rule.name}:{player.ip}',
                        left_event=player.left_event,
                        duration=rule.duration,
                    )

                # Voice notification
                if rule.voice_notifications:
                    tts_candidate_path = TTS_DIR_PATH / _tts_voice_name(rule.voice_notifications) / 'detection' / 'combo_rule_detected.wav'
                    _voice_notification_queue.put(str(tts_candidate_path))

                # Logging
                if rule.logging:
                    with _protection_logging_file_write_lock:
                        now = datetime.now(tz=LOCAL_TZ)
                        PROTECTION_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
                        write_header = not PROTECTION_LOGGING_PATH.exists() or not PROTECTION_LOGGING_PATH.stat().st_size
                        with PROTECTION_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                            writer = csv.writer(f)
                            if write_header:
                                writer.writerow(['Detection', 'Username', 'IP', 'Date', 'Time', 'Country'])
                            writer.writerow(
                                [
                                    f'COMBO RULE MATCHED: {rule.name}',
                                    ', '.join(player.usernames),
                                    player.ip,
                                    now.strftime('%Y-%m-%d'),
                                    now.strftime('%H:%M:%S'),
                                    player.iplookup.geolite2.country,
                                ],
                            )

                # Message box
                if rule.message_box and player.userip is None:
                    conditions_summary = ', '.join(f'{k}={v}' for k, v in rule.conditions.items() if k != 'event')
                    _display_title = f'Combo Rule Matched: {rule.name}'
                    _extra: list[tuple[str, str]] = [('Event', combo_event), ('Conditions', conditions_summary)]
                    _et = datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')

                    def _make_event_combo_notif(t: str, e: list[tuple[str, str]], et: str) -> None:
                        def _callback() -> None:
                            show_detection_notification_dialog(
                                find_main_window(),
                                player,
                                DetectionNotificationInfo(emoji='\U0001f517', display_title=t, extra_detection_fields=e, event_time=et),
                            )

                        gui_dispatcher.invoke(_callback)

                    _make_event_combo_notif(_display_title, _extra, _et)

    _notification_pool.submit(notification_thread).add_done_callback(_on_pool_task_done)


def process_userip_task(
    player: Player,
    connection_type: Literal['connected', 'disconnected'],
) -> None:
    """Process a queued UserIP task for a player on a background thread."""
    if player.userip_detection is None:
        raise TypeError(format_type_error(player.userip_detection, PlayerUserIPDetection))

    timeout = 10
    start_time = time.monotonic()

    while not isinstance(player.userip, UserIP):
        if PlayersRegistry.get_player_by_ip(player.ip) is None:
            return

        if time.monotonic() - start_time > timeout:
            raise TypeError(format_type_error(player.userip, UserIP))

        gui_closed__event.wait(0.01)  # Wait to prevent high CPU usage

    # We want to run this as fast as possible so it's on top of the function.
    # Protection actions are skipped when protection is not supported.
    if connection_type == 'connected' and player.userip.settings.protection.enabled and Settings.is_gta5_preset() and CaptureState.is_local_capture():
        suspend_mode = player.userip.settings.protection.suspend_process_mode
        GTASuspendManager.request_suspend(
            reason_key=f'userip:{player.ip}',
            left_event=player.left_event,
            duration=suspend_mode,
        )

    if player.userip.settings.voice_notifications:
        tts_candidate_path = TTS_DIR_PATH / _tts_voice_name(player.userip.settings.voice_notifications) / 'userip' / f'{connection_type}.wav'
        _voice_notification_queue.put(str(tts_candidate_path))

    if connection_type == 'connected':
        wait_for_player_data_ready(player, data_fields=('userip.usernames', 'iplookup.geolite2'), timeout=10.0)

        relative_database_path = player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

        if player.userip.settings.log:
            with _userip_logging_file_write_lock:
                USERIP_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
                write_csv_header = not USERIP_LOGGING_PATH.exists() or not USERIP_LOGGING_PATH.stat().st_size
                with USERIP_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    if write_csv_header:
                        writer.writerow(['Database', 'Username', 'IP', 'Date', 'Time', 'Country'])
                    date_part, time_part = player.userip_detection.date_time.split('_', maxsplit=1)
                    writer.writerow(
                        [
                            str(relative_database_path),
                            ', '.join(player.userip.usernames),
                            player.ip,
                            date_part,
                            time_part,
                            player.iplookup.geolite2.country,
                        ],
                    )

        if player.userip.settings.notifications:
            wait_for_player_data_ready(player, data_fields=('userip.usernames', 'reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

            def _show_userip_dialog() -> None:
                show_userip_detected_dialog(find_main_window(), player)

            gui_dispatcher.invoke(_show_userip_dialog)


_GTA5_RELAY_PPS_NONZERO_STREAK_SECS = 5.0


def is_gta5_relay_ip(ip: str) -> bool:
    """Return True if *ip* belongs to the GTAV Take-Two Interactive relay IP ranges."""
    addr = IPv4Address(ip)
    return any(addr in network for network in ThirdPartyServers.TAKETWO_INTERACTIVE.ip_networks)


def monitor_gta5_relay_task(player: Player) -> None:
    """Monitor a GTA5 relay IP and suspend the game process when the packet threshold is reached.

    Only active when:
    - The GTA5 game preset is selected.
    - The player IP belongs to the Take-Two Interactive / GTA5 relay CIDR ranges.
    - GTA5 relay detection is enabled and a process path is configured.

    The monitor polls the player's packet count until it reaches the
    configurable `GUIDetectionSettings.gta5_relay_packet_threshold` while
    the player is still connected.

    Args:
        player: The player object to monitor.
    """
    if not Settings.is_gta5_preset():
        return

    if not is_gta5_relay_ip(player.ip):
        return

    # Poll until the packet threshold is exceeded AND PPS has been continuously
    # above 0 for at least `_GTA5_RELAY_PPS_NONZERO_STREAK_SECS` (any 0-PPS sample resets the streak).
    # A 0-PPS relay is not actively sending packets and must be a false positive.
    _pps_nonzero_since: float | None = None
    while not player.left_event.is_set() and not gui_closed__event.is_set():
        pps_active = _is_player_packet_flow_active(player)
        if pps_active:
            if _pps_nonzero_since is None:
                _pps_nonzero_since = time.monotonic()
        else:
            _pps_nonzero_since = None  # reset streak on any 0-PPS sample

        if (
            player.packets.exchanged >= GUIDetectionSettings.gta5_relay_packet_threshold
            and _pps_nonzero_since is not None
            and (time.monotonic() - _pps_nonzero_since) >= _GTA5_RELAY_PPS_NONZERO_STREAK_SECS
        ):
            break

        gui_closed__event.wait(0.25)

    if player.left_event.is_set() or gui_closed__event.is_set():
        return

    if GUIDetectionSettings.gta5_relay_enabled and CaptureState.is_local_capture():
        GTASuspendManager.request_suspend(
            reason_key=f'gta5_relay:{player.ip}',
            left_event=player.left_event,
            duration=GUIDetectionSettings.gta5_relay_duration,
        )

    wait_for_player_data_ready(player, data_fields=('reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

    if GUIDetectionSettings.gta5_relay_voice_notifications:
        tts_candidate_path = TTS_DIR_PATH / _tts_voice_name(GUIDetectionSettings.gta5_relay_voice_notifications) / 'detection' / 'gta5_relay_detected.wav'
        _voice_notification_queue.put(str(tts_candidate_path))

    if GUIDetectionSettings.gta5_relay_logging:
        with _protection_logging_file_write_lock:
            now = datetime.now(tz=LOCAL_TZ)
            PROTECTION_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
            write_csv_header = not PROTECTION_LOGGING_PATH.exists() or not PROTECTION_LOGGING_PATH.stat().st_size
            with PROTECTION_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if write_csv_header:
                    writer.writerow(['Detection', 'Username', 'IP', 'Date', 'Time', 'Country'])
                writer.writerow(
                    [
                        'GTA5 RELAY DETECTED!',
                        ', '.join(player.usernames),
                        player.ip,
                        now.strftime('%Y-%m-%d'),
                        now.strftime('%H:%M:%S'),
                        player.iplookup.geolite2.country,
                    ],
                )

    if GUIDetectionSettings.gta5_relay_message_box:
        _et = datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')

        def _show_relay_notif() -> None:
            show_detection_notification_dialog(
                find_main_window(),
                player,
                DetectionNotificationInfo(
                    emoji='\U0001f6e1',
                    display_title='GTA5 Relay Detected',
                    extra_detection_fields=[('Packets', str(player.packets.exchanged))],
                    event_time=_et,
                ),
            )

        gui_dispatcher.invoke(_show_relay_notif)


def check_global_detections(player: Player) -> None:
    """Check and apply global detection settings from Detections Manager.

    This function evaluates various detection rules configured in the Detections Manager
    and triggers appropriate actions when conditions are met.

    Args:
        player: The player object to check detections against.
    """

    def execute_suspension_action(
        duration: int | Literal['Auto'],
        suspension_name: str,
    ) -> None:
        """Execute a suspension action."""
        if not Settings.is_gta5_preset() or not CaptureState.is_local_capture():
            return
        GTASuspendManager.request_suspend(
            reason_key=f'global:{suspension_name}:{player.ip}',
            left_event=player.left_event,
            duration=duration,
        )

    def handle_detection_notifications(
        detection_title: str,
        emoji: str,
        display_title: str,
        extra_detection_fields: list[tuple[str, str]],
        settings: _DetectionSettings,
    ) -> None:
        """Handle voice, logging, and message box for a detection."""
        if settings.voice:
            tts_candidate_path = TTS_DIR_PATH / _tts_voice_name(settings.voice) / 'detection' / f'{settings.tts_filename}.wav'
            _voice_notification_queue.put(str(tts_candidate_path))

        if settings.log:
            with _protection_logging_file_write_lock:
                now = datetime.now(tz=LOCAL_TZ)
                PROTECTION_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
                write_csv_header = not PROTECTION_LOGGING_PATH.exists() or not PROTECTION_LOGGING_PATH.stat().st_size
                with PROTECTION_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    if write_csv_header:
                        writer.writerow(['Detection', 'Username', 'IP', 'Date', 'Time', 'Country'])
                    writer.writerow(
                        [
                            detection_title,
                            ', '.join(player.usernames),
                            player.ip,
                            now.strftime('%Y-%m-%d'),
                            now.strftime('%H:%M:%S'),
                            player.iplookup.geolite2.country,
                        ],
                    )

        if settings.msgbox and player.userip is None:
            _event_time = datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')

            def _show_detection_notif() -> None:
                show_detection_notification_dialog(
                    find_main_window(),
                    player,
                    DetectionNotificationInfo(emoji=emoji, display_title=display_title, extra_detection_fields=extra_detection_fields, event_time=_event_time),
                )

            gui_dispatcher.invoke(_show_detection_notif)

    # Wait for IP lookup data to be ready
    wait_for_player_data_ready(player, data_fields=('reverse_dns.hostname', 'iplookup.ipapi', 'iplookup.geolite2'), timeout=15.0)

    # Mobile Connection Detection
    if player.iplookup.ipapi.mobile:
        if GUIDetectionSettings.mobile_suspend_enabled:
            execute_suspension_action(
                GUIDetectionSettings.mobile_suspend_duration,
                'MobileDetection',
            )
        handle_detection_notifications(
            detection_title='MOBILE CONNECTION DETECTED!',
            emoji='\U0001f4f1',
            display_title='Mobile Connection Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=GUIDetectionSettings.mobile_voice_notifications,
                log=GUIDetectionSettings.mobile_logging,
                msgbox=GUIDetectionSettings.mobile_message_box,
                tts_filename='mobile_connection_detected',
            ),
        )
    # VPN/Proxy/Tor Detection
    if player.iplookup.ipapi.proxy:
        if GUIDetectionSettings.vpn_suspend_enabled:
            execute_suspension_action(
                GUIDetectionSettings.vpn_suspend_duration,
                'VPNDetection',
            )
        handle_detection_notifications(
            detection_title='VPN/PROXY/TOR CONNECTION DETECTED!',
            emoji='\U0001f512',
            display_title='VPN/Proxy/Tor Connection Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=GUIDetectionSettings.vpn_voice_notifications,
                log=GUIDetectionSettings.vpn_logging,
                msgbox=GUIDetectionSettings.vpn_message_box,
                tts_filename='vpn_connection_detected',
            ),
        )

    # Hosting/Data Center Detection
    if player.iplookup.ipapi.hosting:
        if GUIDetectionSettings.hosting_suspend_enabled:
            execute_suspension_action(
                GUIDetectionSettings.hosting_suspend_duration,
                'HostingDetection',
            )
        handle_detection_notifications(
            detection_title='HOSTING/DATA CENTER CONNECTION DETECTED!',
            emoji='\U0001f3e2',
            display_title='Hosting/Data Center Connection Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=GUIDetectionSettings.hosting_voice_notifications,
                log=GUIDetectionSettings.hosting_logging,
                msgbox=GUIDetectionSettings.hosting_message_box,
                tts_filename='hosting_connection_detected',
            ),
        )

    # Country Detection
    if GUIDetectionSettings.country_detection_list and player.iplookup.geolite2.country and player.iplookup.geolite2.country in GUIDetectionSettings.country_detection_list:
        if GUIDetectionSettings.country_suspend_enabled:
            execute_suspension_action(
                'Auto',
                'CountryDetection',
            )
        handle_detection_notifications(
            detection_title='BLOCKED COUNTRY DETECTED!',
            emoji='\U0001f30d',
            display_title='Blocked Country Detected',
            extra_detection_fields=[],
            settings=_DetectionSettings(
                voice=GUIDetectionSettings.country_voice_notifications,
                log=GUIDetectionSettings.country_logging,
                msgbox=GUIDetectionSettings.country_message_box,
                tts_filename='country_detected',
            ),
        )

    # ISP Detection
    if GUIDetectionSettings.isp_detection_list:
        matched_isp = None
        for block_entry in GUIDetectionSettings.isp_detection_list:
            block_entry_upper = block_entry.upper().strip()

            as_name_clean = (
                player.iplookup.ipapi.as_name.upper().replace('AS', '', 1).strip()
                if player.iplookup.ipapi.as_name and player.iplookup.ipapi.as_name not in ('...', 'N/A')
                else ''
            )

            if as_name_clean and block_entry_upper in as_name_clean:
                matched_isp = block_entry
                break
            if player.iplookup.ipapi.isp and player.iplookup.ipapi.isp not in ('...', 'N/A') and block_entry_upper in player.iplookup.ipapi.isp.upper():
                matched_isp = block_entry
                break

        if matched_isp:
            if GUIDetectionSettings.isp_suspend_enabled:
                execute_suspension_action(
                    'Auto',
                    'ISPDetection',
                )
            handle_detection_notifications(
                detection_title='BLOCKED ISP DETECTED!',
                emoji='\U0001f310',
                display_title='Blocked ISP Detected',
                extra_detection_fields=[('Matched Entry', matched_isp)],
                settings=_DetectionSettings(
                    voice=GUIDetectionSettings.isp_voice_notifications,
                    log=GUIDetectionSettings.isp_logging,
                    msgbox=GUIDetectionSettings.isp_message_box,
                    tts_filename='isp_detected',
                ),
            )

    # ASN Detection
    if GUIDetectionSettings.asn_detection_list:
        asns_to_check: list[str] = []
        if player.iplookup.ipapi.asn and player.iplookup.ipapi.asn not in ('...', 'N/A'):
            asns_to_check.append(player.iplookup.ipapi.asn)
        if player.iplookup.geolite2.asn and player.iplookup.geolite2.asn not in ('...', 'N/A'):
            asns_to_check.append(player.iplookup.geolite2.asn)

        if asns_to_check:
            matched_asn = None
            for block_entry in GUIDetectionSettings.asn_detection_list:
                block_entry_upper = block_entry.upper().strip()
                normalized_asn = block_entry_upper if block_entry_upper.startswith('AS') else f'AS{block_entry_upper}'
                for asn in asns_to_check:
                    if asn.upper() == normalized_asn:
                        matched_asn = asn
                        break
                if matched_asn:
                    break

            if matched_asn:
                if GUIDetectionSettings.asn_suspend_enabled:
                    execute_suspension_action(
                        'Auto',
                        'ASNDetection',
                    )
                asn_display = (
                    f'IP-API: {player.iplookup.ipapi.asn}, GeoLite2: {player.iplookup.geolite2.asn}'
                    if player.iplookup.ipapi.asn != player.iplookup.geolite2.asn
                    else matched_asn
                )
                handle_detection_notifications(
                    detection_title='BLOCKED ASN DETECTED!',
                    emoji='\U0001f522',
                    display_title='Blocked ASN Detected',
                    extra_detection_fields=[('ASN', asn_display)],
                    settings=_DetectionSettings(
                        voice=GUIDetectionSettings.asn_voice_notifications,
                        log=GUIDetectionSettings.asn_logging,
                        msgbox=GUIDetectionSettings.asn_message_box,
                        tts_filename='asn_detected',
                    ),
                )

    # Combo Rules evaluation (rules without event condition fire here at join-time)
    matched_combo_rules = ComboRulesManager.evaluate(player, event_type=None)
    for rule in matched_combo_rules:
        if rule.protection_enabled:
            execute_suspension_action(
                rule.duration,
                f'ComboRule:{rule.name}',
            )
        conditions_summary = ', '.join(f'{k}={v}' for k, v in rule.conditions.items() if k != 'event')
        handle_detection_notifications(
            detection_title=f'COMBO RULE MATCHED: {rule.name}',
            emoji='\U0001f517',
            display_title=f'Combo Rule Matched: {rule.name}',
            extra_detection_fields=[('Conditions', conditions_summary)],
            settings=_DetectionSettings(
                voice=rule.voice_notifications,
                log=rule.logging,
                msgbox=rule.message_box,
                tts_filename='combo_rule_detected',
            ),
        )


def submit_global_detections_check(player: Player) -> None:
    """Submit global detection checks to the background detection worker pool."""
    _detection_check_pool.submit(check_global_detections, player).add_done_callback(_on_pool_task_done)


def player_rates_core() -> None:
    """Compute per-player rate metrics and aggregate global capture stats at 1-second intervals.

    Runs in a dedicated background thread so that PPS/PPM/BPS/BPM calculations stay on a
    precise 1-second timer, independent of the rendering loop cadence.
    """
    while not gui_closed__event.is_set():
        _start = time.monotonic()

        if ScriptControl.has_crashed():
            return

        global_bandwidth = 0
        global_download = 0
        global_upload = 0
        global_bps_rate = 0
        global_bpm_rate = 0
        global_pps_rate = 0
        connected_count = 0

        for player in PlayersRegistry.get_connected_players():
            if player.left_event.is_set():
                continue
            connected_count += 1

            if (time.monotonic() - player.packets.pps.last_update_time) >= 1.0:
                player.packets.pps.calculate_and_update_rate()

            if (time.monotonic() - player.packets.ppm.last_update_time) >= _MINUTE_INTERVAL_SECONDS:
                player.packets.ppm.calculate_and_update_rate()

            if (time.monotonic() - player.bandwidth.bps.last_update_time) >= 1.0:
                player.bandwidth.bps.calculate_and_update_rate()

            if (time.monotonic() - player.bandwidth.bpm.last_update_time) >= _MINUTE_INTERVAL_SECONDS:
                player.bandwidth.bpm.calculate_and_update_rate()

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

        one_second_ago = datetime.now(tz=LOCAL_TZ) - timedelta(seconds=1)
        recent_latencies = [(t, lat) for t, lat in list(CaptureStats.packets_latencies) if t >= one_second_ago]
        CaptureStats.global_avg_latency_ms = sum(lat.total_seconds() * 1000 for _, lat in recent_latencies) / len(recent_latencies) if recent_latencies else 0.0

        gui_closed__event.wait(max(0.0, 1.0 - (time.monotonic() - _start)))
