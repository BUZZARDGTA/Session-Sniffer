"""Background tasks for UserIP processing and detection notifications."""

import subprocess
import time
import winsound
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Literal, TypedDict

import psutil

from session_sniffer import msgbox
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import TTS_DIR_PATH, USERIP_DATABASES_DIR_PATH, USERIP_LOGGING_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import SYSTEM32_PATH
from session_sniffer.core import ThreadsExceptionHandler
from session_sniffer.error_messages import format_type_error
from session_sniffer.models.player import Player, PlayerUserIPDetection
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIP
from session_sniffer.text_utils import format_triple_quoted_text, pluralize
from session_sniffer.utils import get_pid_by_path, terminate_process_tree, validate_file, write_lines_to_file

gui_closed__event = Event()
_userip_logging_file_write_lock = Lock()

SHUTDOWN_EXE = SYSTEM32_PATH / 'shutdown.exe'


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

    while not player.left_event.is_set() and (datetime.now(tz=LOCAL_TZ) - player.datetime.last_seen) < timedelta(seconds=timeout):
        if all(field_checkers[field](player) for field in data_fields if field in field_checkers):
            return True

        gui_closed__event.wait(0.1)

    return False


class NotificationConfig(TypedDict):
    """Type definition for notification configuration."""
    emoji: str
    title: str
    description: str
    icon: msgbox.Style
    thread_name: str


def show_detection_warning_popup(
    player: Player,
    notification_type: Literal['mobile', 'vpn', 'hosting', 'player_joined', 'player_rejoined', 'player_left'],
) -> None:
    """Show a notification popup for detections or player connection events.

    Args:
        player: The player object with detection data
        notification_type: Type of notification - `mobile`, `vpn`, `hosting`, `player_joined`, `player_rejoined`, or `player_left`
    """
    def show_popup_thread() -> None:
        """Thread function to show popup after ensuring data is ready."""
        notification_configs: dict[Literal['mobile', 'vpn', 'hosting', 'player_joined', 'player_rejoined', 'player_left'], NotificationConfig] = {
            'mobile': {
                'emoji': '📱',
                'title': 'MOBILE CONNECTION DETECTED!',
                'description': 'A player using a mobile (cellular) connection has been detected in your session!',
                'icon': msgbox.Style.MB_ICONINFORMATION,
                'thread_name': 'MobileWarning',
            },
            'vpn': {
                'emoji': '🚨',
                'title': 'VPN CONNECTION DETECTED!',
                'description': 'A player using a VPN/Proxy/Tor connection has been detected in your session!',
                'icon': msgbox.Style.MB_ICONEXCLAMATION,
                'thread_name': 'VPNWarning',
            },
            'hosting': {
                'emoji': '🏢',
                'title': 'HOSTING CONNECTION DETECTED!',
                'description': 'A player connecting from a hosting provider or data center has been detected in your session!',
                'icon': msgbox.Style.MB_ICONWARNING,
                'thread_name': 'HostingWarning',
            },
            'player_joined': {
                'emoji': '🟢',
                'title': 'PLAYER JOINED SESSION!',
                'description': 'A new player has joined your session!',
                'icon': msgbox.Style.MB_ICONINFORMATION,
                'thread_name': 'PlayerJoined',
            },
            'player_rejoined': {
                'emoji': '🔄',
                'title': 'PLAYER REJOINED SESSION!',
                'description': 'A player has rejoined your session after disconnecting!',
                'icon': msgbox.Style.MB_ICONINFORMATION,
                'thread_name': 'PlayerRejoined',
            },
            'player_left': {
                'emoji': '🔴',
                'title': 'PLAYER LEFT SESSION!',
                'description': 'A player has left your session!',
                'icon': msgbox.Style.MB_ICONINFORMATION,
                'thread_name': 'PlayerLeft',
            },
        }

        config = notification_configs[notification_type]
        data_ready = wait_for_player_data_ready(player, data_fields=('reverse_dns.hostname', 'iplookup.geolite2', 'iplookup.ipapi'), timeout=3.0)
        time_label = 'Detection Time' if notification_type in {'mobile', 'vpn', 'hosting'} else 'Event Time'
        data_status_line = '' if data_ready else '⚠️ Some data may still be loading and missing from this notification\n\n'

        msgbox.show(
            title=f"{TITLE} - {config['title']}",
            text=format_triple_quoted_text(f"""
                {config['emoji']} {config['title']} {config['emoji']}

                {config['description']}

                {data_status_line}############ PLAYER DETAILS ############
                Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or ""}
                {time_label}: {datetime.now(tz=LOCAL_TZ).strftime("%H:%M.%S")}

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

    # Get thread name for the notification type
    notification_configs_for_thread_name = {
        'mobile': 'MobileWarning',
        'vpn': 'VPNWarning',
        'hosting': 'HostingWarning',
        'player_joined': 'PlayerJoined',
        'player_rejoined': 'PlayerRejoined',
        'player_left': 'PlayerLeft',
    }

    Thread(
        target=show_popup_thread,
        name=f'{notification_configs_for_thread_name[notification_type]}-{player.ip}',
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

            time.sleep(0.01)  # Sleep to prevent high CPU usage

        def suspend_process_for_duration_or_mode(process_pid: int, duration_or_mode: float | Literal['Auto', 'Manual']) -> None:
            """Suspends the specified process for a given duration or until a specified condition is met.

            Args:
                process_pid: The process ID of the process to be suspended.
                duration_or_mode: Specifies how long the process should be suspended.
                    - If a float, it defines the duration (in seconds) to suspend the process.
                    - If "Manual", the process remains suspended until manually resumed.
                    - If "Auto", the process resumes when the player is flagged as "disconnected".
            """
            process = psutil.Process(process_pid)
            process.suspend()

            if isinstance(duration_or_mode, (int, float)):
                gui_closed__event.wait(duration_or_mode)
                process.resume()
                return

            if duration_or_mode == 'Manual':
                return
            if duration_or_mode == 'Auto':
                while not player.left_event.is_set():
                    gui_closed__event.wait(0.1)
                process.resume()
                return

        # We wants to run this as fast as possible so it's on top of the function.
        if connection_type == 'connected' and player.userip.settings.PROTECTION:
            if player.userip.settings.PROTECTION == 'Suspend_Process' and isinstance(player.userip.settings.PROTECTION_PROCESS_PATH, Path):
                if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                    Thread(
                        target=suspend_process_for_duration_or_mode,
                        name=f'UserIPSuspendProcess-{player.ip}',
                        args=(process_pid, player.userip.settings.PROTECTION_SUSPEND_PROCESS_MODE),
                        daemon=True,
                    ).start()

            elif player.userip.settings.PROTECTION in {'Exit_Process', 'Restart_Process'} and isinstance(player.userip.settings.PROTECTION_PROCESS_PATH, Path):
                if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                    terminate_process_tree(process_pid)

                    if player.userip.settings.PROTECTION == 'Restart_Process' and isinstance(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH, Path):
                        subprocess.Popen([str(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH.absolute())])

            elif player.userip.settings.PROTECTION in {'Shutdown_PC', 'Restart_PC'}:
                validate_file(SHUTDOWN_EXE)
                subprocess.run(
                    [str(SHUTDOWN_EXE), '/s' if player.userip.settings.PROTECTION == 'Shutdown_PC' else '/r'],
                    check=False,
                )

        if player.userip.settings.VOICE_NOTIFICATIONS:
            tts_voice_name = 'Liam' if player.userip.settings.VOICE_NOTIFICATIONS == 'Male' else 'Jane'
            tts_candidate_path = TTS_DIR_PATH / f'{tts_voice_name} ({connection_type}).wav'
            winsound.PlaySound(str(tts_candidate_path), winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)

        if connection_type == 'connected':
            wait_for_player_data_ready(player, data_fields=('userip.usernames', 'iplookup.geolite2'), timeout=10.0)

            relative_database_path = player.userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

            if player.userip.settings.LOG:
                with _userip_logging_file_write_lock:
                    write_lines_to_file(USERIP_LOGGING_PATH, 'a', [(
                        f'User{pluralize(len(player.userip.usernames))}: {", ".join(player.userip.usernames)} | '
                        f'IP:{player.ip} | Ports:{", ".join(map(str, reversed(player.ports.all)))} | '
                        f'Time:{player.userip_detection.date_time} | Country:{player.iplookup.geolite2.country} | '
                        f'Detection Type: {player.userip_detection.type} | '
                        f'Database:{relative_database_path}'
                    )])

            if player.userip.settings.NOTIFICATIONS:
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
