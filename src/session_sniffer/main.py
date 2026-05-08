"""Session Sniffer application entry point and main GUI/capture orchestration."""

import atexit
import ctypes
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Event, Thread

import colorama
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

from session_sniffer import msgbox
from session_sniffer.background import (
    check_global_protections,
    gui_closed__event,
    handle_detection_notification,
    hostname_core,
    iplookup_core,
    monitor_gta5_relay_task,
    pinger_core,
    process_userip_task,
)
from session_sniffer.capture.arp_spoofing import arp_spoofing_task
from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.capture.interface_setup import get_filtered_tshark_interfaces, populate_network_interfaces_info, refresh_available_interfaces
from session_sniffer.capture.tshark_capture import CaptureConfig, CaptureHolder, Packet, PacketCapture
from session_sniffer.capture.utils.check_tshark_filters import check_broadcast_multicast_support
from session_sniffer.capture.utils.npcap_checker import ensure_npcap_installed
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import BIN_DIR_PATH, COMBO_RULES_PATH, PROTECTIONS_JSON_PATH, SCRIPT_DIR, SETTINGS_PATH, USER_SCRIPTS_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import ThreadsExceptionHandler
from session_sniffer.diagnostics import SlowdownDetector
from session_sniffer.error_messages import format_capture_interrupted_message, format_outdated_packages_message
from session_sniffer.exceptions import UnsupportedPlatformError
from session_sniffer.guis.app import app
from session_sniffer.guis.discord_intro import DiscordIntro
from session_sniffer.guis.exceptions import UnsupportedScreenResolutionError
from session_sniffer.guis.interface_selection_dialog import select_interface
from session_sniffer.guis.main_window import MainWindow
from session_sniffer.guis.splash_screen import SplashScreen
from session_sniffer.guis.utils import get_screen_size
from session_sniffer.launcher.package_checker import check_packages_version, get_dependencies_from_pyproject
from session_sniffer.logging_setup import get_logger, setup_logging
from session_sniffer.models.player import PacketInfo, Player, PlayerUserIPDetection
from session_sniffer.networking.geolite2.service import update_and_initialize_geolite2_readers
from session_sniffer.networking.interface import AllInterfaces, Interface
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.networking.manuf_lookup import MacLookup
from session_sniffer.networking.utils import is_private_device_ipv4
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.renderer import rendering_core
from session_sniffer.rendering_core.types import CaptureState, GeoIP2Readers, TsharkStats
from session_sniffer.settings import Settings
from session_sniffer.updater import UpdateCheckOutcome, check_for_updates
from session_sniffer.utils import clear_screen, is_pyinstaller_compiled, set_window_title

# Production-friendly logging: file handlers only (no console output)
setup_logging(console_level=logging.INFO)
logger = get_logger(__name__)

# TODO(BUZZARDGTA): NPCAP_RECOMMENDED_VERSION_NUMBER = "1.78"
TSHARK_PATH = BIN_DIR_PATH / 'WiresharkPortable64' / 'App' / 'Wireshark' / 'tshark.exe'

USER_SCRIPTS_DIR_PATH.mkdir(parents=True, exist_ok=True)


def _hide_console_window() -> None:
    """Hide the console window on Windows (best-effort)."""
    if sys.platform == 'win32':
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE


def main() -> None:
    """Run environment checks, initialize dependencies, and start the GUI."""
    _hide_console_window()

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

    # Show splash screen for startup progress
    splash = SplashScreen()
    splash.show()
    # Own all msgboxes shown during splash so they appear above it without being globally topmost
    msgbox.set_owner_hwnd(int(splash.winId()))

    if not is_pyinstaller_compiled():
        splash.update_status('Checking Python package versions')
        deps = splash.run_with_spinner(get_dependencies_from_pyproject)
        outdated_packages = splash.run_with_spinner(check_packages_version, deps)
        if outdated_packages:
            msgbox_message = format_outdated_packages_message(
                app_title=TITLE,
                outdated_packages=outdated_packages,
            )

            # Show message box
            msgbox_style = msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND
            msgbox_title = TITLE
            errorlevel = msgbox.show(msgbox_title, msgbox_message, msgbox_style)
            if errorlevel != msgbox.ReturnValues.IDYES:
                sys.exit(0)

    splash.update_status('Applying custom settings from Settings.ini')
    splash.run_with_spinner(Settings.load_from_settings_file, SETTINGS_PATH)
    Settings.rebuild_blocked_ip_ranges()

    splash.run_with_spinner(GUIProtectionSettings.load_from_file_or_defaults, PROTECTIONS_JSON_PATH)
    splash.run_with_spinner(ComboRulesManager.load_from_file, COMBO_RULES_PATH)

    splash.update_status('Checking for updates')
    outcome = splash.run_with_spinner(check_for_updates, updater_channel=Settings.updater_channel)
    if outcome is UpdateCheckOutcome.ABORT:
        sys.exit(0)

    splash.update_status('Verifying Npcap driver')
    splash.run_with_spinner(ensure_npcap_installed)

    splash.update_status('Initializing GeoLite2 databases')
    geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = splash.run_with_spinner(update_and_initialize_geolite2_readers)

    splash.update_status('Initializing MAC lookup')
    mac_lookup = splash.run_with_spinner(MacLookup, load_on_init=True)

    splash.update_status('Network interface selection')
    splash.run_with_spinner(populate_network_interfaces_info, mac_lookup)

    # Get list of Interface objects that are available in tshark
    available_interfaces: list[Interface] = []
    tshark_interfaces = splash.run_with_spinner(
        lambda: [
            (i, device_name) for _, device_name, name in get_filtered_tshark_interfaces(str(TSHARK_PATH))
            if (i := AllInterfaces.get_interface_by_name(name))
        ],
    )

    for interface, device_name in tshark_interfaces:
        # Populate the device_name from tshark
        interface.identity.device_name = device_name

        if (
            Settings.capture_interface_name is not None
            and interface.identity.name.casefold() == Settings.capture_interface_name.casefold()
            and interface.identity.name != Settings.capture_interface_name
        ):
            Settings.capture_interface_name = interface.identity.name
            Settings.rewrite_settings_file()

        available_interfaces.append(interface)

    selected_interface = select_interface(
        available_interfaces, screen_width, screen_height,
        before_dialog=splash.lower_to_back,
        mac_lookup=mac_lookup,
        tshark_path=str(TSHARK_PATH),
    )
    if selected_interface is None:
        sys.exit(0)

    CaptureState.is_arp_interface = selected_interface.is_arp

    splash.update_status('Establishing connection')
    need_rewrite_settings = False

    if (
        Settings.capture_interface_name is None
        or selected_interface.name != Settings.capture_interface_name
    ):
        Settings.capture_interface_name = selected_interface.name
        need_rewrite_settings = True

    if selected_interface.mac_address != Settings.capture_mac_address:
        Settings.capture_mac_address = selected_interface.mac_address
        need_rewrite_settings = True

    if selected_interface.ip_address != Settings.capture_ip_address:
        Settings.capture_ip_address = selected_interface.ip_address
        need_rewrite_settings = True

    if need_rewrite_settings:
        Settings.rewrite_settings_file()

    broadcast_support, multicast_support = splash.run_with_spinner(check_broadcast_multicast_support, TSHARK_PATH, Settings.capture_interface_name)
    vpn_mode_enabled = not (broadcast_support and multicast_support)

    capture_filter_str, display_filter_str = splash.run_with_spinner(
        build_capture_filters,
        broadcast_support=broadcast_support,
        multicast_support=multicast_support,
    )

    clear_screen()
    set_window_title(f'DEBUG CONSOLE - {TITLE}')

    splash.update_status('Starting packet capture')

    _packet_slowdown = SlowdownDetector.get('packet_callback')

    def packet_callback(packet: Packet) -> None:
        """Callback function to process each captured packet."""
        with ThreadsExceptionHandler():
            _pkt_start = time.monotonic()
            packet_latency = datetime.now(tz=LOCAL_TZ) - packet.datetime
            TsharkStats.packets_latencies.append((packet.datetime, packet_latency))
            if packet_latency >= timedelta(seconds=Settings.capture_overflow_timer):
                TsharkStats.restarted_times += 1
                TsharkStats.packets_latencies.clear()
                logger.warning(
                    'Packet capture overflow detected: latency %.2fs exceeds threshold of %.2fs. '
                    'Restarting capture now (restart #%d). Skipping this packet.',
                    packet_latency.total_seconds(),
                    Settings.capture_overflow_timer,
                    TsharkStats.restarted_times,
                )
                capture_holder.request_restart()
                return  # Skip processing this packet

            if Settings.capture_ip_address:
                if packet.ip.src == Settings.capture_ip_address:
                    target_ip = packet.ip.dst
                    target_port = packet.port.dst
                    sent_by_local_host = True
                elif packet.ip.dst == Settings.capture_ip_address:
                    target_ip = packet.ip.src
                    target_port = packet.port.src
                    sent_by_local_host = False
                else:
                    return  # Neither source nor destination matches the specified `Settings.capture_ip_address`.
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

            if Settings.blocked_ip_ranges and check_ip_against_ranges(target_ip, Settings.blocked_ip_ranges):
                return  # IP is blocked; discard packet silently

            matched_player = PlayersRegistry.get_player_by_ip(target_ip)
            if matched_player is None:
                matched_player = PlayersRegistry.add_connected_player(
                    Player(
                        ip=target_ip,
                        packet=PacketInfo(
                            datetime=packet.datetime,
                            length=packet.length,
                            port=target_port,
                            sent_by_local_host=sent_by_local_host,
                        ),
                    ),
                )

                handle_detection_notification(matched_player, 'player_joined_session')

            elif matched_player.left_event.is_set():
                matched_player.mark_as_rejoined(
                    port=target_port,
                    packet_datetime=packet.datetime,
                    packet_length=packet.length,
                    sent_by_local_host=sent_by_local_host,
                )
                PlayersRegistry.move_player_to_connected(matched_player)

                handle_detection_notification(matched_player, 'player_rejoined_session')
            else:
                matched_player.mark_as_seen(
                    port=target_port,
                    packet_datetime=packet.datetime,
                    packet_length=packet.length,
                    sent_by_local_host=sent_by_local_host,
                )

            if not matched_player.protection_checked:
                matched_player.protection_checked = True
                Thread(
                    target=check_global_protections,
                    name=f'CheckProtections-{matched_player.ip}',
                    args=(matched_player,),
                    daemon=True,
                ).start()

            if not matched_player.relay_monitor_started:
                matched_player.relay_monitor_started = True
                Thread(
                    target=monitor_gta5_relay_task,
                    name=f'GTA5RelayMonitor-{matched_player.ip}',
                    args=(matched_player,),
                    daemon=True,
                ).start()

            if UserIPDatabases.is_known_ip(matched_player.ip) and (
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

            _packet_slowdown.check(time.monotonic() - _pkt_start, 'packet_callback')

    _adapter_lost_event = Event()

    capture = PacketCapture(
        CaptureConfig(
            interface=selected_interface,
            tshark_path=TSHARK_PATH,
            broadcast_support=broadcast_support,
            multicast_support=multicast_support,
            capture_filter=capture_filter_str,
            display_filter=display_filter_str,
            callback=packet_callback,
            on_capture_lost=_adapter_lost_event.set,
        ),
    )
    # Wrap in a mutable holder so background threads pick up a new capture on interface switch
    capture_holder = CaptureHolder(capture)

    splash.run_with_spinner(capture.start)
    CaptureState.vpn_mode_enabled = vpn_mode_enabled

    _arp_failed_event = Event()
    arp_stop_event = Event()
    if Settings.capture_arp_spoofing:
        Thread(
            target=arp_spoofing_task,
            name=f'ARPSpoofingTask-{selected_interface.ip_address}',
            args=(
                selected_interface,
                capture_holder,
                arp_stop_event,
                _arp_failed_event.set,
            ),
            daemon=True,
        ).start()

    # Initialize GUI first - now it has all the data it needs
    def _switch_interface() -> None:
        nonlocal arp_stop_event

        # Lock the button immediately to prevent double-clicks
        window.set_change_interface_button_enabled(enabled=False)

        # Refresh interface list then show the selection dialog.
        # Capture keeps running at this point — no flash of "CAPTURE STOPPED".
        new_available_interfaces = refresh_available_interfaces(mac_lookup, str(TSHARK_PATH))
        new_interface = select_interface(
            new_available_interfaces,
            screen_width,
            screen_height,
            force_dialog=True,
            mac_lookup=mac_lookup,
            tshark_path=str(TSHARK_PATH),
        )

        if new_interface is None:
            # User cancelled — just re-enable the button, everything else is untouched
            window.set_change_interface_button_enabled(enabled=True)
            return

        # User confirmed a new interface — now stop capture and lock the full UI
        was_running = capture_holder.is_running()
        if was_running:
            capture_holder.stop()
        window.set_interface_switching_mode(switching=True)

        # Run the ~200 ms tshark probe off the Qt thread so the UI stays responsive.
        with ThreadPoolExecutor(max_workers=1) as _pool:
            _future = _pool.submit(check_broadcast_multicast_support, TSHARK_PATH, new_interface.name)
            while not _future.done():
                app.processEvents()
                time.sleep(0.016)
            new_broadcast, new_multicast = _future.result()
        new_vpn_mode = not (new_broadcast and new_multicast)

        # Settings must be updated before build_capture_filters() — it reads Settings.capture_ip_address.
        CaptureState.is_arp_interface = new_interface.is_arp
        Settings.capture_interface_name = new_interface.name
        Settings.capture_mac_address = new_interface.mac_address
        Settings.capture_ip_address = new_interface.ip_address
        Settings.rewrite_settings_file()

        new_capture_filter, new_display_filter = build_capture_filters(
            broadcast_support=new_broadcast,
            multicast_support=new_multicast,
        )

        CaptureState.vpn_mode_enabled = new_vpn_mode
        TsharkStats.restarted_times = 0
        TsharkStats.packets_latencies.clear()
        TsharkStats.global_bandwidth = 0
        TsharkStats.global_download = 0
        TsharkStats.global_upload = 0
        TsharkStats.global_bps_rate = 0
        TsharkStats.global_pps_rate = 0

        window.reset_players_for_interface_switch()
        window.reset_session_graph()

        new_capture = PacketCapture(
            CaptureConfig(
                interface=new_interface,
                tshark_path=TSHARK_PATH,
                broadcast_support=new_broadcast,
                multicast_support=new_multicast,
                capture_filter=new_capture_filter,
                display_filter=new_display_filter,
                callback=packet_callback,
                on_capture_lost=_adapter_lost_event.set,
            ),
        )
        new_capture.start()
        capture_holder.set(new_capture)

        # Stop old ARP spoofing thread and start a new one if needed
        arp_stop_event.set()
        arp_stop_event = Event()
        if Settings.capture_arp_spoofing:
            Thread(
                target=arp_spoofing_task,
                name=f'ARPSpoofingTask-{new_interface.ip_address}',
                args=(new_interface, capture_holder, arp_stop_event, _arp_failed_event.set),
                daemon=True,
            ).start()

        window.on_interface_switched()
        window.set_interface_switching_mode(switching=False)

    window = MainWindow(screen_width, screen_height, capture_holder, on_change_interface=_switch_interface)

    def _handle_capture_lost(*, stop_capture: bool, warning_message: str | None) -> None:
        """Shared handler for any event that requires stopping capture and re-selecting an interface."""
        if stop_capture:
            capture_holder.stop()
        window.on_interface_switched()
        window.set_capture_toggle_enabled(enabled=False)
        if warning_message is not None:
            QMessageBox.warning(window, 'Capture Interrupted', warning_message)
        _switch_interface()

    def _on_adapter_lost_poll() -> None:
        """Poll for unexpected TShark crashes and re-show the interface selection dialog."""
        if gui_closed__event.is_set() or not _adapter_lost_event.is_set():
            return
        _adapter_lost_event.clear()
        _handle_capture_lost(stop_capture=False, warning_message=format_capture_interrupted_message())

    _adapter_lost_timer = QTimer()
    _adapter_lost_timer.setInterval(500)
    _adapter_lost_timer.timeout.connect(_on_adapter_lost_poll)
    _adapter_lost_timer.start()

    def _on_arp_failed_poll() -> None:
        """Poll for ARP spoofing failures and re-show the interface selection dialog."""
        if gui_closed__event.is_set() or not _arp_failed_event.is_set():
            return
        _arp_failed_event.clear()
        _handle_capture_lost(stop_capture=True, warning_message=None)

    _arp_failed_timer = QTimer()
    _arp_failed_timer.setInterval(500)
    _arp_failed_timer.timeout.connect(_on_arp_failed_poll)
    _arp_failed_timer.start()

    splash.finish_loading()
    QTimer.singleShot(1500, splash.close_splash)
    QTimer.singleShot(1500, window.show)

    # Start background processing threads FIRST
    rendering_core__thread = Thread(
        target=rendering_core,
        name='rendering_core',
        args=(
            capture_holder,
            GeoIP2Readers(
                enabled=geoip2_enabled,
                asn_reader=geolite2_asn_reader,
                city_reader=geolite2_city_reader,
                country_reader=geolite2_country_reader,
            ),
        ),
        daemon=True,
    )
    rendering_core__thread.start()

    hostname_core__thread = Thread(target=hostname_core, name='hostname_core', daemon=True)
    hostname_core__thread.start()

    iplookup_core__thread = Thread(target=iplookup_core, name='iplookup_core', daemon=True)
    iplookup_core__thread.start()

    pinger_core__thread = Thread(target=pinger_core, name='pinger_core', daemon=True)
    pinger_core__thread.start()

    if Settings.show_discord_popup:
        # Delay the popup opening by 3 seconds
        QTimer.singleShot(3000, lambda: DiscordIntro().exec())

    # Start the application's event loop
    sys.exit(app.exec())


if __name__ == '__main__':
    atexit.register(logging.shutdown)
    main()
