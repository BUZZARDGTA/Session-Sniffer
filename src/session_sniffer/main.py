"""Session Sniffer application entry point and main GUI/capture orchestration."""

import atexit
import logging
import os
import sys
from datetime import datetime, timedelta
from threading import Thread

import colorama
from PyQt6.QtCore import QTimer

from session_sniffer import msgbox
from session_sniffer.background import (
    hostname_core,
    iplookup_core,
    pinger_core,
    process_userip_task,
    show_detection_warning_popup,
)
from session_sniffer.capture.arp_spoofing import arp_spoofing_task
from session_sniffer.capture.interface_setup import get_filtered_tshark_interfaces, populate_network_interfaces_info, select_interface
from session_sniffer.capture.tshark_capture import CaptureConfig, Packet, PacketCapture
from session_sniffer.capture.utils.check_tshark_filters import check_broadcast_multicast_support
from session_sniffer.capture.utils.npcap_checker import ensure_npcap_installed
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import BIN_DIR_PATH, SCRIPT_DIR, SETTINGS_PATH, USER_SCRIPTS_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.third_party_servers import ThirdPartyServers
from session_sniffer.core import ThreadsExceptionHandler
from session_sniffer.exceptions import UnsupportedPlatformError
from session_sniffer.guis.app import app
from session_sniffer.guis.discord_intro import DiscordIntro
from session_sniffer.guis.exceptions import UnsupportedScreenResolutionError
from session_sniffer.guis.main_window import MainWindow
from session_sniffer.guis.utils import get_screen_size
from session_sniffer.launcher.package_checker import check_packages_version, get_dependencies_from_pyproject
from session_sniffer.logging_setup import console, get_logger, setup_logging
from session_sniffer.models.player import Player, PlayerUserIPDetection
from session_sniffer.networking.geolite2.service import update_and_initialize_geolite2_readers
from session_sniffer.networking.interface import AllInterfaces, Interface
from session_sniffer.networking.manuf_lookup import MacLookup
from session_sniffer.networking.utils import is_private_device_ipv4
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.warnings import GUIDetectionSettings
from session_sniffer.rendering_core.renderer import rendering_core
from session_sniffer.rendering_core.types import GeoIP2Readers, TsharkStats
from session_sniffer.settings import Settings
from session_sniffer.updater import UpdateCheckOutcome, check_for_updates
from session_sniffer.utils import clear_screen, is_pyinstaller_compiled, set_window_title

# Production-friendly logging: INFO to console, quiet third-party debug noise
setup_logging(console_level=logging.INFO)
logger = get_logger(__name__)

# TODO(BUZZARDGTA): NPCAP_RECOMMENDED_VERSION_NUMBER = "1.78"
RESERVED_NETWORK_RANGES = [  # https://en.wikipedia.org/wiki/Reserved_IP_addresses
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.88.99.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '233.252.0.0/24',
    '240.0.0.0/4',
    '255.255.255.255/32',
]
RESERVED_NETWORKS_FILTER = ' or '.join(RESERVED_NETWORK_RANGES)
TSHARK_PATH = BIN_DIR_PATH / 'WiresharkPortable64' / 'App' / 'Wireshark' / 'tshark.exe'

USER_SCRIPTS_DIR_PATH.mkdir(parents=True, exist_ok=True)


def main() -> None:
    """Run environment checks, initialize dependencies, and start the GUI."""
    colorama.init(autoreset=True)
    os.chdir(SCRIPT_DIR)

    if sys.platform != 'win32':
        raise UnsupportedPlatformError(sys.platform)

    # Check minimum screen resolution requirement early to avoid wasting user's time
    try:
        screen_width, screen_height = get_screen_size()
    except UnsupportedScreenResolutionError as e:
        msgbox.show(
            title='Unsupported Screen Resolution',
            text=e.msgbox_text,
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_TOPMOST,
        )
        sys.exit(1)

    if not is_pyinstaller_compiled():
        clear_screen()
        set_window_title(f'Checking that your Python packages versions match project dependencies - {TITLE}')
        console.print('\nChecking that your Python packages versions match project dependencies ...', highlight=False)

        if outdated_packages := check_packages_version(get_dependencies_from_pyproject()):
            msgbox_message = 'The following packages have version mismatches:\n\n'

            # Iterate over outdated packages and add each package's information to the message box text
            for package_name, required_version, installed_version in outdated_packages:
                msgbox_message += f'{package_name} (required {required_version}, installed {installed_version})\n'

            # Add additional message box text
            msgbox_message += f'\nKeeping your packages synced with "{TITLE}" ensures smooth script execution and prevents compatibility issues.'
            msgbox_message += '\n\nDo you want to ignore this warning and continue with script execution?'

            # Show message box
            msgbox_style = msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND
            msgbox_title = TITLE
            errorlevel = msgbox.show(msgbox_title, msgbox_message, msgbox_style)
            if errorlevel != msgbox.ReturnValues.IDYES:
                sys.exit(0)

    clear_screen()
    set_window_title(f'Applying your custom settings from "Settings.ini" - {TITLE}')
    console.print('\nApplying your custom settings from "Settings.ini" ...\n', highlight=False)
    Settings.load_from_settings_file(SETTINGS_PATH)

    clear_screen()
    set_window_title(f'Searching for a new update - {TITLE}')
    console.print('\nSearching for a new update ...\n', highlight=False)
    outcome = check_for_updates(updater_channel=Settings.UPDATER_CHANNEL)
    if outcome is UpdateCheckOutcome.ABORT:
        sys.exit(0)

    clear_screen()
    set_window_title(f'Checking that "Npcap" driver is installed on your system - {TITLE}')
    console.print('\nChecking that "Npcap" driver is installed on your system ...\n', highlight=False)
    ensure_npcap_installed()

    clear_screen()
    set_window_title(f"Initializing and updating MaxMind's GeoLite2 Country, City and ASN databases - {TITLE}")
    console.print("\nInitializing and updating MaxMind's GeoLite2 Country, City and ASN databases ...\n", highlight=False)
    geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = update_and_initialize_geolite2_readers()

    clear_screen()
    set_window_title(f'Initializing MacLookup module - {TITLE}')
    console.print('\nInitializing MacLookup module ...\n', highlight=False)
    mac_lookup = MacLookup(load_on_init=True)

    clear_screen()
    set_window_title(f'Capture network interface selection - {TITLE}')
    console.print('\nCapture network interface selection ...\n', highlight=False)
    populate_network_interfaces_info(mac_lookup)

    # Get list of Interface objects that are available in tshark
    available_interfaces: list[Interface] = []
    tshark_interfaces = [
        (i, device_name) for _, device_name, name in get_filtered_tshark_interfaces(str(TSHARK_PATH))
        if (i := AllInterfaces.get_interface_by_name(name))
    ]

    for interface, device_name in tshark_interfaces:
        # Populate the device_name from tshark
        interface.device_name = device_name

        if (
            Settings.CAPTURE_INTERFACE_NAME is not None
            and interface.name.casefold() == Settings.CAPTURE_INTERFACE_NAME.casefold()
            and interface.name != Settings.CAPTURE_INTERFACE_NAME
        ):
            Settings.CAPTURE_INTERFACE_NAME = interface.name
            Settings.rewrite_settings_file()

        available_interfaces.append(interface)

    selected_interface = select_interface(available_interfaces, screen_width, screen_height)
    if selected_interface is None:
        sys.exit(0)

    clear_screen()
    set_window_title(f'Initializing addresses and establishing connection to your PC / Console - {TITLE}')
    console.print('\nInitializing addresses and establishing connection to your PC / Console ...\n', highlight=False)
    need_rewrite_settings = False

    if (
        Settings.CAPTURE_INTERFACE_NAME is None
        or selected_interface.name != Settings.CAPTURE_INTERFACE_NAME
    ):
        Settings.CAPTURE_INTERFACE_NAME = selected_interface.name
        need_rewrite_settings = True

    if selected_interface.mac_address != Settings.CAPTURE_MAC_ADDRESS:
        Settings.CAPTURE_MAC_ADDRESS = selected_interface.mac_address
        need_rewrite_settings = True

    if selected_interface.ip_address != Settings.CAPTURE_IP_ADDRESS:
        Settings.CAPTURE_IP_ADDRESS = selected_interface.ip_address
        need_rewrite_settings = True

    if need_rewrite_settings:
        Settings.rewrite_settings_file()

    capture_filter: list[str] = ['ip', 'udp']

    if Settings.CAPTURE_IP_ADDRESS:
        capture_filter.append(
            f'((src host {Settings.CAPTURE_IP_ADDRESS} and (not (dst net {RESERVED_NETWORKS_FILTER}))) or '
            f'(dst host {Settings.CAPTURE_IP_ADDRESS} and (not (src net {RESERVED_NETWORKS_FILTER}))))',
        )

    broadcast_support, multicast_support = check_broadcast_multicast_support(TSHARK_PATH, Settings.CAPTURE_INTERFACE_NAME)
    if broadcast_support and multicast_support:
        capture_filter.append('not (broadcast or multicast)')
        vpn_mode_enabled = False
    elif broadcast_support:
        capture_filter.append('not broadcast')
        vpn_mode_enabled = True
    elif multicast_support:
        capture_filter.append('not multicast')
        vpn_mode_enabled = True
    else:
        vpn_mode_enabled = True

    capture_filter.append('not (portrange 0-1023 or port 5353)')

    excluded_protocols: list[str] = []

    if Settings.CAPTURE_PROGRAM_PRESET:
        if Settings.CAPTURE_PROGRAM_PRESET == 'GTA5':
            capture_filter.append('(len >= 71 and len <= 1032)')
        elif Settings.CAPTURE_PROGRAM_PRESET == 'Minecraft':
            capture_filter.append('(len >= 49 and len <= 1498)')

        # If the <CAPTURE_PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
        # In case RTCP can be useful to get someone IP, I decided not to block them without using a <CAPTURE_PROGRAM_PRESET>.
        # RTCP is known to be for example the Discord's server IP while you are in a call there.
        # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
        # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
        # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
        # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
        excluded_protocols.append('rtcp')

    if Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS:
        capture_filter.append(f"not (net {' or '.join(ThirdPartyServers.get_all_ip_ranges())})")

        # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
        # But there can be a lot more, those are just a couples I could find on my own usage.
        excluded_protocols.extend(['ssdp', 'raknet', 'dtls', 'nbns', 'pcp', 'bt-dht', 'uaudp', 'classicstun', 'dhcp', 'mdns', 'llmnr'])

    display_filter: list[str] = []

    if excluded_protocols:
        display_filter.append(
            f"not ({' or '.join(excluded_protocols)})",
        )

    if Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER:
        capture_filter.insert(0, f'({Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER})')

    if Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER:
        display_filter.insert(0, f'({Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER})')

    capture_filter_str = ' and '.join(capture_filter) if capture_filter else None
    display_filter_str = ' and '.join(display_filter) if display_filter else None

    clear_screen()
    set_window_title(f'DEBUG CONSOLE - {TITLE}')

    def packet_callback(packet: Packet) -> None:
        """Callback function to process each captured packet."""
        with ThreadsExceptionHandler():
            packet_latency = datetime.now(tz=LOCAL_TZ) - packet.datetime
            TsharkStats.packets_latencies.append((packet.datetime, packet_latency))
            if packet_latency >= timedelta(seconds=Settings.CAPTURE_OVERFLOW_TIMER):
                TsharkStats.restarted_times += 1
                TsharkStats.packets_latencies.clear()
                logger.warning(
                    'Packet capture overflow detected: latency %.2fs exceeds threshold of %.2fs. '
                    'Restarting capture now (restart #%d). Skipping this packet.',
                    packet_latency.total_seconds(),
                    Settings.CAPTURE_OVERFLOW_TIMER,
                    TsharkStats.restarted_times,
                )
                capture.request_restart()
                return  # Skip processing this packet

            if Settings.CAPTURE_IP_ADDRESS:
                if packet.ip.src == Settings.CAPTURE_IP_ADDRESS:
                    target_ip = packet.ip.dst
                    target_port = packet.port.dst
                    sent_by_local_host = True
                elif packet.ip.dst == Settings.CAPTURE_IP_ADDRESS:
                    target_ip = packet.ip.src
                    target_port = packet.port.src
                    sent_by_local_host = False
                else:
                    return  # Neither source nor destination matches the specified `Settings.CAPTURE_IP_ADDRESS`.
            else:
                is_src_private_ip = is_private_device_ipv4(packet.ip.src)
                is_dst_private_ip = is_private_device_ipv4(packet.ip.dst)

                if is_src_private_ip and is_dst_private_ip:
                    return  # Both source and destination are private IPs, no action needed.

                if is_src_private_ip:
                    target_ip = packet.ip.dst
                    target_port = packet.port.dst
                    sent_by_local_host = True
                elif is_dst_private_ip:
                    target_ip = packet.ip.src
                    target_port = packet.port.src
                    sent_by_local_host = False
                else:
                    return  # Neither source nor destination is a private IP address.

            matched_player = PlayersRegistry.get_player_by_ip(target_ip)
            if matched_player is None:
                matched_player = PlayersRegistry.add_connected_player(
                    Player(
                        ip=target_ip,
                        port=target_port,
                        packet_datetime=packet.datetime,
                        packet_length=packet.length,
                        sent_by_local_host=sent_by_local_host,
                    ),
                )

                if GUIDetectionSettings.player_join_notifications_enabled:
                    show_detection_warning_popup(matched_player, 'player_joined')

            elif matched_player.left_event.is_set():
                matched_player.mark_as_rejoined(
                    port=target_port,
                    packet_datetime=packet.datetime,
                    packet_length=packet.length,
                    sent_by_local_host=sent_by_local_host,
                )
                PlayersRegistry.move_player_to_connected(matched_player)

                if GUIDetectionSettings.player_join_notifications_enabled:
                    show_detection_warning_popup(matched_player, 'player_joined')

                if GUIDetectionSettings.player_rejoin_notifications_enabled:
                    show_detection_warning_popup(matched_player, 'player_rejoined')
            else:
                matched_player.mark_as_seen(
                    port=target_port,
                    packet_datetime=packet.datetime,
                    packet_length=packet.length,
                    sent_by_local_host=sent_by_local_host,
                )

            if matched_player.ip in UserIPDatabases.ips_set and (
                not matched_player.userip_detection
                or not matched_player.userip_detection.as_processed_task
            ):
                matched_player.userip_detection = PlayerUserIPDetection(
                    time=packet.datetime.strftime('%H:%M:%S'),
                    date_time=packet.datetime.strftime('%Y-%m-%d_%H:%M:%S'),
                )
                Thread(
                    target=process_userip_task,
                    name=f'ProcessUserIPTask-{matched_player.ip}-connected',
                    args=(matched_player, 'connected'),
                    daemon=True,
                ).start()

    capture = PacketCapture(
        CaptureConfig(
            interface=selected_interface,
            tshark_path=TSHARK_PATH,
            capture_filter=capture_filter_str,
            display_filter=display_filter_str,
            callback=packet_callback,
        ),
    )
    capture.start()

    if Settings.CAPTURE_ARP_SPOOFING:
        Thread(
            target=arp_spoofing_task,
            name=f'ARPSpoofingTask-{selected_interface.ip_address}',
            args=(
                selected_interface,
                capture,
            ),
            daemon=True,
        ).start()

    # Initialize GUI first - now it has all the data it needs
    window = MainWindow(screen_width, screen_height, capture)
    window.show()

    # Start background processing threads FIRST
    rendering_core__thread = Thread(
        target=rendering_core,
        name='rendering_core',
        args=(
            capture,
            GeoIP2Readers(
                enabled=geoip2_enabled,
                asn_reader=geolite2_asn_reader,
                city_reader=geolite2_city_reader,
                country_reader=geolite2_country_reader,
            ),
        ),
        kwargs={'vpn_mode_enabled': vpn_mode_enabled},
        daemon=True,
    )
    rendering_core__thread.start()

    hostname_core__thread = Thread(target=hostname_core, name='hostname_core', daemon=True)
    hostname_core__thread.start()

    iplookup_core__thread = Thread(target=iplookup_core, name='iplookup_core', daemon=True)
    iplookup_core__thread.start()

    pinger_core__thread = Thread(target=pinger_core, name='pinger_core', daemon=True)
    pinger_core__thread.start()

    if Settings.SHOW_DISCORD_POPUP:
        # Delay the popup opening by 3 seconds
        QTimer.singleShot(3000, lambda: DiscordIntro().exec())

    # Start the application's event loop
    sys.exit(app.exec())


if __name__ == '__main__':
    atexit.register(logging.shutdown)
    main()
