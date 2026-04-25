"""Background tasks for UserIP processing and detection notifications."""

import contextlib
import csv
import time
import winsound
from collections import deque
from datetime import datetime
from pathlib import Path
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, Literal, TypedDict, cast

from session_sniffer import msgbox
from session_sniffer.background.suspend_manager import ProcessSuspendManager
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import DETECTION_LOGGING_PATH, PROTECTION_LOGGING_PATH, TTS_DIR_PATH, USERIP_DATABASES_DIR_PATH, USERIP_LOGGING_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import ThreadsExceptionHandler
from session_sniffer.error_messages import format_type_error
from session_sniffer.models.player import Player, PlayerUserIPDetection
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIP
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_triple_quoted_text, pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

gui_closed__event = Event()
_detection_logging_file_write_lock = Lock()
_protection_logging_file_write_lock = Lock()
_userip_logging_file_write_lock = Lock()
_VOICE_QUEUE_MAXSIZE = 10
_INTER_SOUND_PAUSE_SECONDS = 0.5


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
            if item in self._set or len(self._deque) >= self._maxsize:
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
    def check_userip_usernames(player: Player) -> bool:
        """Check if player has usernames in userip data."""
        return isinstance(player.userip, UserIP) and len(player.userip.usernames) > 0

    def check_reverse_dns_hostname(player: Player) -> bool:
        """Check if player reverse DNS is initialized."""
        return player.reverse_dns.is_initialized

    def check_iplookup_geolite2(player: Player) -> bool:
        """Check if player GeoLite2 data is initialized."""
        return player.iplookup.geolite2.is_initialized

    def check_iplookup_ipapi(player: Player) -> bool:
        """Check if player IP API data is initialized."""
        return player.iplookup.ipapi.is_initialized

    field_checkers = {
        'userip.usernames': check_userip_usernames,
        'reverse_dns.hostname': check_reverse_dns_hostname,
        'iplookup.geolite2': check_iplookup_geolite2,
        'iplookup.ipapi': check_iplookup_ipapi,
    }

    deadline = time.monotonic() + timeout

    checker_items = [
        field_checkers[field]
        for field in data_fields
        if field in field_checkers
    ]

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


def handle_detection_notification(
    player: Player,
    notification_type: NotificationType,
) -> None:
    """Handle voice notifications, logging, message box popups, and protection actions for player connection events.

    This function now reads all settings from GUIProtectionSettings and is used only for
    player_joined_session, player_rejoined_session, and player_left_session events.
    VPN/hosting/mobile notifications are handled by check_global_protections.

    Args:
        player: The player object with detection data
        notification_type: Type of notification - `player_joined_session`,
            `player_rejoined_session`, or `player_left_session`
    """
    notification_configs: dict[NotificationType, NotificationConfig] = {
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

    def notification_thread() -> None:
        """Thread function to handle voice, logging, message box, and protection actions."""
        config = notification_configs[notification_type]
        prefix = _NOTIFICATION_TYPE_SETTING_PREFIX[notification_type]

        enabled: bool = getattr(GUIProtectionSettings, f'{prefix}_enabled')
        voice_setting: Literal['Male', 'Female'] | bool = getattr(GUIProtectionSettings, f'{prefix}_voice_notifications')
        logging_setting: bool = getattr(GUIProtectionSettings, f'{prefix}_logging')
        msgbox_setting: bool = getattr(GUIProtectionSettings, f'{prefix}_message_box')

        # Check if there are combo rules with event conditions that might need evaluation
        has_event_combo_rules = any(rule.has_event_condition for rule in ComboRulesManager.rules if rule.enabled)

        standalone_active = enabled or voice_setting or logging_setting or msgbox_setting
        if not standalone_active and not has_event_combo_rules:
            return

        data_ready = False

        if standalone_active:
            process_path: Path | None = getattr(GUIProtectionSettings, f'{prefix}_process_path')
            duration: int | Literal['Auto', 'Manual', 'Adaptive'] = getattr(GUIProtectionSettings, f'{prefix}_duration')

            # Execute protection action (only when enabled and protection is supported)
            if enabled and Settings.is_protection_supported and process_path:
                ProcessSuspendManager.request_suspend(
                    process_path=process_path,
                    reason_key=f'event:{notification_type}:{player.ip}',
                    left_event=player.left_event,
                    duration=duration,
                    is_active=(lambda: player.packets.pps.is_first_calculation or player.packets.pps.calculated_rate > 0) if duration == 'Adaptive' else None,
                )

            # Voice notification (queued, plays sequentially through VoiceNotificationWorker)
            if voice_setting:
                tts_voice_name = 'Liam' if voice_setting == 'Male' else 'Jane'
                tts_candidate_path = TTS_DIR_PATH / tts_voice_name / 'event' / f'{notification_type}.wav'
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
                        writer.writerow([
                            config['title'],
                            ', '.join(player.usernames),
                            player.ip,
                            now.strftime('%Y-%m-%d'),
                            now.strftime('%H:%M:%S'),
                            player.iplookup.geolite2.country,
                        ])

            # Message box popup
            if msgbox_setting:
                data_status_line = '' if data_ready else '⚠️ Some data may still be loading and missing from this notification\n\n'

                msgbox.show(
                    title=f"{TITLE} - {config['title']}",
                    text=format_triple_quoted_text(f"""
                        {config['emoji']} {config['title']} {config['emoji']}

                        {config['description']}

                        {data_status_line}############ PLAYER DETAILS ############
                        Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or ""}
                        Event Time: {datetime.now(tz=LOCAL_TZ).strftime("%H:%M.%S")}

                        ############ CONNECTION DETAILS ############
                        IP Address: {player.ip}
                        Hostname: {player.reverse_dns.hostname}
                        Last Port: {player.ports.last}
                        Middle Ports: {", ".join(map(str, reversed(player.ports.middle)))}
                        First Port: {player.ports.first}
                        Total Packets Exchanged: {player.packets.total_exchanged}
                        Current Session Packets: {player.packets.exchanged}
                        Rejoins: {player.rejoins}

                        ############ LOCATION DETAILS ############
                        Continent: {player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})
                        Country: {player.iplookup.ipapi.country} ({player.iplookup.ipapi.country_code})
                        Region: {player.iplookup.ipapi.region} ({player.iplookup.ipapi.region_code})

                        ############ NETWORK DETAILS ############
                        ISP: {player.iplookup.ipapi.isp}
                        Organization: {player.iplookup.ipapi.org}
                        ASN: {player.iplookup.ipapi.asn} ({player.iplookup.ipapi.as_name})

                        ############ DETECTION FLAGS ############
                        Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
                        Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
                        Hosting, colocated or data center: {player.iplookup.ipapi.hosting}
                    """),
                    style=msgbox.Style.MB_OK | config['icon'] | msgbox.Style.MB_SYSTEMMODAL,
                )

        # Combo Rules evaluation (rules WITH event condition fire here)
        notification_to_event: dict[NotificationType, str] = {
            'player_joined_session': 'join',
            'player_rejoined_session': 'rejoin',
            'player_left_session': 'leave',
        }
        combo_event = notification_to_event.get(notification_type)
        if combo_event is not None:
            # Ensure IP lookup data is ready (may already be loaded above)
            if not data_ready:
                wait_for_player_data_ready(player, data_fields=('iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

            matched_combo_rules = ComboRulesManager.evaluate(player, event_type=combo_event)
            for rule in matched_combo_rules:
                # Protection action
                if rule.protection_enabled and Settings.is_protection_supported and rule.process_path:
                    ProcessSuspendManager.request_suspend(
                        process_path=rule.process_path,
                        reason_key=f'combo:{rule.name}:{player.ip}',
                        left_event=player.left_event,
                        duration=rule.duration,
                        is_active=(lambda: player.packets.pps.is_first_calculation or player.packets.pps.calculated_rate > 0) if rule.duration == 'Adaptive' else None,
                    )

                # Voice notification
                if rule.voice_notifications:
                    tts_voice_name = 'Liam' if rule.voice_notifications == 'Male' else 'Jane'
                    tts_candidate_path = TTS_DIR_PATH / tts_voice_name / 'detection' / 'combo_rule_detected.wav'
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
                            writer.writerow([
                                f'COMBO RULE MATCHED: {rule.name}',
                                ', '.join(player.usernames),
                                player.ip,
                                now.strftime('%Y-%m-%d'),
                                now.strftime('%H:%M:%S'),
                                player.iplookup.geolite2.country,
                            ])

                # Message box
                if rule.message_box and player.userip is None:
                    conditions_summary = ', '.join(
                        f'{k}={v}' for k, v in rule.conditions.items() if k != 'event'
                    )
                    msgbox.show(
                        title=f'{TITLE} - COMBO RULE: {rule.name}',
                        text=format_triple_quoted_text(f"""
                            \U0001f517 Combo Rule Matched: {rule.name}
                            Event: {combo_event}
                            IP Address: {player.ip}
                            Country: {player.iplookup.geolite2.country}
                            ISP: {player.iplookup.ipapi.isp}
                            ASN: {player.iplookup.ipapi.as_name}
                            Conditions: {conditions_summary}
                            Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                        """),
                        style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
                    )

    config = notification_configs[notification_type]

    Thread(
        target=notification_thread,
        name=f"{config['thread_name']}-{player.ip}",
        daemon=True,
    ).start()


def process_userip_task(
    player: Player,
    connection_type: Literal['connected', 'disconnected'],
) -> None:
    """Process a queued UserIP task for a player on a background thread."""
    with ThreadsExceptionHandler():
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

        # We wants to run this as fast as possible so it's on top of the function.
        # Protection actions are skipped when protection is not supported.
        if (
            connection_type == 'connected'
            and player.userip.settings.protection.enabled
            and Settings.is_protection_supported
            and isinstance(player.userip.settings.protection.process_path, Path)
        ):
            suspend_mode = player.userip.settings.protection.suspend_process_mode
            ProcessSuspendManager.request_suspend(
                process_path=player.userip.settings.protection.process_path,
                reason_key=f'userip:{player.ip}',
                left_event=player.left_event,
                duration=suspend_mode,
                is_active=(lambda: player.packets.pps.is_first_calculation or player.packets.pps.calculated_rate > 0) if suspend_mode == 'Adaptive' else None,
            )

        if player.userip.settings.voice_notifications:
            tts_voice_name = 'Liam' if player.userip.settings.voice_notifications == 'Male' else 'Jane'
            tts_candidate_path = TTS_DIR_PATH / tts_voice_name / 'userip' / f'{connection_type}.wav'
            _voice_notification_queue.put(str(tts_candidate_path))

        if connection_type == 'connected':
            wait_for_player_data_ready(player, data_fields=('userip.usernames', 'iplookup.geolite2'), timeout=10.0)

            relative_database_path = player.userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

            if player.userip.settings.log:
                with _userip_logging_file_write_lock:
                    USERIP_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
                    write_csv_header = not USERIP_LOGGING_PATH.exists() or not USERIP_LOGGING_PATH.stat().st_size
                    with USERIP_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if write_csv_header:
                            writer.writerow(['Database', 'Username', 'IP', 'Date', 'Time', 'Country'])
                        date_part, time_part = player.userip_detection.date_time.split('_', maxsplit=1)
                        writer.writerow([
                            str(relative_database_path),
                            ', '.join(player.userip.usernames),
                            player.ip,
                            date_part,
                            time_part,
                            player.iplookup.geolite2.country,
                        ])

            if player.userip.settings.notifications:
                wait_for_player_data_ready(player, data_fields=('userip.usernames', 'reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=10.0)

                Thread(
                    target=msgbox.show,
                    name=f'UserIPMsgBox-{player.ip}',
                    kwargs={
                        'title': TITLE,
                        'text': format_triple_quoted_text(f"""
                            #### UserIP detected at {player.userip_detection.time} ####
                            User{pluralize(len(player.userip.usernames))}: {', '.join(player.userip.usernames)}
                            IP Address: {player.ip}
                            Hostname: {player.reverse_dns.hostname}
                            Port{pluralize(len(player.ports.all))}: {', '.join(map(str, reversed(player.ports.all)))}
                            Country Code: {player.iplookup.geolite2.country_code}
                            Detection Type: {player.userip_detection.type}
                            Database: {relative_database_path}
                            ############# IP Lookup ##############
                            Continent: {player.iplookup.ipapi.continent}
                            Country: {player.iplookup.geolite2.country}
                            Region: {player.iplookup.ipapi.region}
                            City: {player.iplookup.geolite2.city}
                            Organization: {player.iplookup.ipapi.org}
                            ISP: {player.iplookup.ipapi.isp}
                            ASN / ISP: {player.iplookup.geolite2.asn}
                            ASN: {player.iplookup.ipapi.as_name}
                            Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
                            Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
                            Hosting, colocated or data center: {player.iplookup.ipapi.hosting}
                        """),
                        'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SYSTEMMODAL,
                    },
                    daemon=True,
                ).start()


def check_global_protections(player: Player) -> None:
    """Check and apply global protection settings from Protections Manager.

    This function evaluates various protection rules configured in the Protections Manager
    and triggers appropriate actions when conditions are met.

    Args:
        player: The player object to check protections against.
    """
    with ThreadsExceptionHandler():
        def execute_protection_action(
            process_path: Path | None,
            duration: int | Literal['Auto', 'Manual', 'Adaptive'],
            protection_name: str,
        ) -> None:
            """Execute a protection action (Suspend)."""
            if not Settings.is_protection_supported or not process_path:
                return
            ProcessSuspendManager.request_suspend(
                process_path=process_path,
                reason_key=f'global:{protection_name}:{player.ip}',
                left_event=player.left_event,
                duration=duration,
                is_active=(lambda: player.packets.pps.is_first_calculation or player.packets.pps.calculated_rate > 0) if duration == 'Adaptive' else None,
            )

        def handle_detection_notifications(  # noqa: PLR0913  # pylint: disable=too-many-arguments,too-many-positional-arguments
            detection_title: str,
            msgbox_text: str,
            voice_setting: Literal['Male', 'Female'] | bool,  # noqa: FBT001
            logging_setting: bool,  # noqa: FBT001
            msgbox_setting: bool,  # noqa: FBT001
            notification_name: str,
            tts_filename: str,
        ) -> None:
            """Handle voice, logging, and message box for a detection."""
            if voice_setting:
                tts_voice_name = 'Liam' if voice_setting == 'Male' else 'Jane'
                tts_candidate_path = TTS_DIR_PATH / tts_voice_name / 'detection' / f'{tts_filename}.wav'
                _voice_notification_queue.put(str(tts_candidate_path))

            if logging_setting:
                with _protection_logging_file_write_lock:
                    now = datetime.now(tz=LOCAL_TZ)
                    PROTECTION_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)
                    write_csv_header = not PROTECTION_LOGGING_PATH.exists() or not PROTECTION_LOGGING_PATH.stat().st_size
                    with PROTECTION_LOGGING_PATH.open('a', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if write_csv_header:
                            writer.writerow(['Detection', 'Username', 'IP', 'Date', 'Time', 'Country'])
                        writer.writerow([
                            detection_title,
                            ', '.join(player.usernames),
                            player.ip,
                            now.strftime('%Y-%m-%d'),
                            now.strftime('%H:%M:%S'),
                            player.iplookup.geolite2.country,
                        ])

            if msgbox_setting and player.userip is None:
                Thread(
                    target=msgbox.show,
                    name=f'{notification_name}-{player.ip}',
                    kwargs={
                        'title': TITLE,
                        'text': format_triple_quoted_text(msgbox_text),
                        'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND,
                    },
                    daemon=True,
                ).start()

        # Wait for IP lookup data to be ready
        wait_for_player_data_ready(player, data_fields=('iplookup.ipapi', 'iplookup.geolite2'), timeout=15.0)

        # Mobile Connection Detection
        if player.iplookup.ipapi.mobile:
            if GUIProtectionSettings.mobile_suspend_enabled:
                execute_protection_action(
                    GUIProtectionSettings.mobile_suspend_process_path,
                    GUIProtectionSettings.mobile_suspend_duration,
                    'MobileProtection',
                )
            handle_detection_notifications(
                detection_title='MOBILE CONNECTION DETECTED!',
                msgbox_text=f"""
                    \U0001f4f1 Mobile Connection Detected
                    IP Address: {player.ip}
                    Country: {player.iplookup.geolite2.country}
                    ISP: {player.iplookup.ipapi.isp}
                    Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                """,
                voice_setting=GUIProtectionSettings.mobile_voice_notifications,
                logging_setting=GUIProtectionSettings.mobile_logging,
                msgbox_setting=GUIProtectionSettings.mobile_message_box,
                notification_name='MobileDetectionNotif',
                tts_filename='mobile_connection_detected',
            )

        # VPN/Proxy/Tor Detection
        if player.iplookup.ipapi.proxy:
            if GUIProtectionSettings.vpn_suspend_enabled:
                execute_protection_action(
                    GUIProtectionSettings.vpn_suspend_process_path,
                    GUIProtectionSettings.vpn_suspend_duration,
                    'VPNProtection',
                )
            handle_detection_notifications(
                detection_title='VPN/PROXY/TOR CONNECTION DETECTED!',
                msgbox_text=f"""
                    \U0001f512 VPN/Proxy/Tor Connection Detected
                    IP Address: {player.ip}
                    Country: {player.iplookup.geolite2.country}
                    ISP: {player.iplookup.ipapi.isp}
                    Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                """,
                voice_setting=GUIProtectionSettings.vpn_voice_notifications,
                logging_setting=GUIProtectionSettings.vpn_logging,
                msgbox_setting=GUIProtectionSettings.vpn_message_box,
                notification_name='VPNDetectionNotif',
                tts_filename='vpn_connection_detected',
            )

        # Hosting/Data Center Detection
        if player.iplookup.ipapi.hosting:
            if GUIProtectionSettings.hosting_suspend_enabled:
                execute_protection_action(
                    GUIProtectionSettings.hosting_suspend_process_path,
                    GUIProtectionSettings.hosting_suspend_duration,
                    'HostingProtection',
                )
            handle_detection_notifications(
                detection_title='HOSTING/DATA CENTER CONNECTION DETECTED!',
                msgbox_text=f"""
                    \U0001f3e2 Hosting/Data Center Connection Detected
                    IP Address: {player.ip}
                    Country: {player.iplookup.geolite2.country}
                    Organization: {player.iplookup.ipapi.org}
                    Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                """,
                voice_setting=GUIProtectionSettings.hosting_voice_notifications,
                logging_setting=GUIProtectionSettings.hosting_logging,
                msgbox_setting=GUIProtectionSettings.hosting_message_box,
                notification_name='HostingDetectionNotif',
                tts_filename='hosting_connection_detected',
            )

        # Country Blocklist Detection
        if GUIProtectionSettings.country_block_list:
            country_name = player.iplookup.geolite2.country
            if country_name and country_name in GUIProtectionSettings.country_block_list:
                if GUIProtectionSettings.country_block_enabled:
                    execute_protection_action(
                        GUIProtectionSettings.country_block_process_path,
                        'Auto',
                        'CountryBlockProtection',
                    )
                handle_detection_notifications(
                    detection_title='BLOCKED COUNTRY DETECTED!',
                    msgbox_text=f"""
                        \U0001f30d Blocked Country Detected
                        IP Address: {player.ip}
                        Country: {country_name}
                        Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                    """,
                    voice_setting=GUIProtectionSettings.country_voice_notifications,
                    logging_setting=GUIProtectionSettings.country_logging,
                    msgbox_setting=GUIProtectionSettings.country_message_box,
                    notification_name='CountryDetectionNotif',
                    tts_filename='country_detected',
                )

        # ISP Blocklist Protection
        if GUIProtectionSettings.isp_block_list:
            as_name = cast('str', player.iplookup.ipapi.as_name)
            isp = cast('str', player.iplookup.ipapi.isp)

            matched_isp = None
            for block_entry in GUIProtectionSettings.isp_block_list:
                block_entry_upper = block_entry.upper().strip()

                as_name_clean = as_name.upper().replace('AS', '', 1).strip() if as_name and as_name not in ('...', 'N/A') else ''

                if as_name_clean and block_entry_upper in as_name_clean:
                    matched_isp = block_entry
                    break
                if isp and isp not in ('...', 'N/A') and block_entry_upper in isp.upper():
                    matched_isp = block_entry
                    break

            if matched_isp:
                if GUIProtectionSettings.isp_block_enabled:
                    execute_protection_action(
                        GUIProtectionSettings.isp_block_process_path,
                        'Auto',
                        'ISPBlockProtection',
                    )
                handle_detection_notifications(
                    detection_title='BLOCKED ISP DETECTED!',
                    msgbox_text=f"""
                        \U0001f310 Blocked ISP Detected
                        IP Address: {player.ip}
                        Matched Entry: {matched_isp}
                        AS Name: {as_name}
                        ISP: {isp}
                        Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                    """,
                    voice_setting=GUIProtectionSettings.isp_voice_notifications,
                    logging_setting=GUIProtectionSettings.isp_logging,
                    msgbox_setting=GUIProtectionSettings.isp_message_box,
                    notification_name='ISPDetectionNotif',
                    tts_filename='isp_detected',
                )

        # ASN Blocklist Protection
        if GUIProtectionSettings.asn_block_list:
            asn_ipapi = cast('str', player.iplookup.ipapi.asn)
            asn_geolite2 = player.iplookup.geolite2.asn

            asns_to_check: list[str] = []
            if asn_ipapi and asn_ipapi not in ('...', 'N/A'):
                asns_to_check.append(asn_ipapi)
            if asn_geolite2 and asn_geolite2 not in ('...', 'N/A'):
                asns_to_check.append(asn_geolite2)

            if asns_to_check:
                matched_asn = None
                for block_entry in GUIProtectionSettings.asn_block_list:
                    block_entry_upper = block_entry.upper().strip()
                    normalized_asn = block_entry_upper if block_entry_upper.startswith('AS') else f'AS{block_entry_upper}'
                    for asn in asns_to_check:
                        if asn.upper() == normalized_asn:
                            matched_asn = asn
                            break
                    if matched_asn:
                        break

                if matched_asn:
                    if GUIProtectionSettings.asn_block_enabled:
                        execute_protection_action(
                            GUIProtectionSettings.asn_block_process_path,
                            'Auto',
                            'ASNBlockProtection',
                        )
                    asn_display = f'IP-API: {asn_ipapi}, GeoLite2: {asn_geolite2}' if asn_ipapi != asn_geolite2 else matched_asn
                    handle_detection_notifications(
                        detection_title='BLOCKED ASN DETECTED!',
                        msgbox_text=f"""
                            \U0001f522 Blocked ASN Detected
                            IP Address: {player.ip}
                            ASN: {asn_display}
                            AS Name: {player.iplookup.ipapi.as_name}
                            ISP: {player.iplookup.ipapi.isp}
                            Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                        """,
                        voice_setting=GUIProtectionSettings.asn_voice_notifications,
                        logging_setting=GUIProtectionSettings.asn_logging,
                        msgbox_setting=GUIProtectionSettings.asn_message_box,
                        notification_name='ASNDetectionNotif',
                        tts_filename='asn_detected',
                    )

        # Combo Rules evaluation (rules without event condition fire here at join-time)
        matched_combo_rules = ComboRulesManager.evaluate(player, event_type=None)
        for rule in matched_combo_rules:
            if rule.protection_enabled:
                execute_protection_action(
                    rule.process_path,
                    rule.duration,
                    f'ComboRule:{rule.name}',
                )
            conditions_summary = ', '.join(
                f'{k}={v}' for k, v in rule.conditions.items() if k != 'event'
            )
            handle_detection_notifications(
                detection_title=f'COMBO RULE MATCHED: {rule.name}',
                msgbox_text=f"""
                    \U0001f517 Combo Rule Matched: {rule.name}
                    IP Address: {player.ip}
                    Country: {player.iplookup.geolite2.country}
                    ISP: {player.iplookup.ipapi.isp}
                    ASN: {player.iplookup.ipapi.as_name}
                    Conditions: {conditions_summary}
                    Time: {datetime.now(tz=LOCAL_TZ).strftime('%H:%M:%S')}
                """,
                voice_setting=rule.voice_notifications,
                logging_setting=rule.logging,
                msgbox_setting=rule.message_box,
                notification_name=f'ComboRuleNotif-{rule.name}',
                tts_filename='combo_rule_detected',
            )
