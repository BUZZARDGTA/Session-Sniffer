"""Session Sniffer application entry point and main GUI/capture orchestration."""

import atexit
import contextlib
import logging
import os
import queue
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Event, Lock, Thread

import colorama
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

from session_sniffer import msgbox
from session_sniffer.background import (
    ensure_gta5_process_monitor_running,
    ensure_looky_core_running,
    gui_closed__event,
    handle_detection_notification,
    hostname_core,
    iplookup_core,
    is_gta5_relay_ip,
    monitor_gta5_relay_task,
    pinger_core,
    player_rates_core,
    process_userip_task,
    submit_global_protections_check,
)
from session_sniffer.capture.arp_spoofing import ArpSpoofingController
from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.capture.interface_setup import get_filtered_scapy_interfaces, populate_network_interfaces_info
from session_sniffer.capture.packet_capture import CaptureConfig, CaptureHolder, Packet, PacketCapture
from session_sniffer.capture.utils.check_capture_filters import check_broadcast_multicast_support
from session_sniffer.capture.utils.npcap_checker import ensure_npcap_installed
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import COMBO_RULES_PATH, PROTECTIONS_JSON_PATH, SCRIPT_DIR, SETTINGS_PATH, USER_SCRIPTS_DIR_PATH
from session_sniffer.constants.standalone import (
    GTA5_PACKET_SIZE_MAX,
    GTA5_PACKET_SIZE_MIN,
    MINECRAFT_PACKET_SIZE_MAX,
    MINECRAFT_PACKET_SIZE_MIN,
    TITLE,
)
from session_sniffer.ctypes_console import hide_console_window
from session_sniffer.error_messages import format_capture_interrupted_message, format_outdated_packages_message
from session_sniffer.exceptions import UnsupportedPlatformError
from session_sniffer.guis.app import app
from session_sniffer.guis.discord_intro import DiscordIntro
from session_sniffer.guis.exceptions import UnsupportedScreenResolutionError
from session_sniffer.guis.interface_selection import select_interface
from session_sniffer.guis.main_window import MainWindow
from session_sniffer.guis.relay_conflict import prompt_to_disable_gta5_relay_if_filtered
from session_sniffer.guis.splash_screen import SplashScreen
from session_sniffer.guis.utils import get_screen_size
from session_sniffer.launcher.package_checker import check_packages_version, get_dependencies_from_pyproject
from session_sniffer.logging_setup import get_logger, register_secret_provider, setup_logging
from session_sniffer.models.player import PacketInfo, Player, PlayerUserIPDetection
from session_sniffer.networking.ctypes_adapters_info import get_adapters_info
from session_sniffer.networking.geolite2.service import update_and_initialize_geolite2_readers
from session_sniffer.networking.interface import AllInterfaces, Interface, SelectedInterfaceRow
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.networking.manuf_lookup import MacLookup
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.renderer import rendering_core
from session_sniffer.rendering_core.types import CaptureState, CaptureStats, GeoIP2Readers
from session_sniffer.settings import Settings
from session_sniffer.updater import UpdateCheckOutcome, check_for_updates
from session_sniffer.utils import is_pyinstaller_compiled
from session_sniffer.webserver import start_webserver_from_settings

# Production-friendly logging: file handlers only (no console output)
setup_logging(console_level=logging.INFO)
logger = get_logger(__name__)

USER_SCRIPTS_DIR_PATH.mkdir(parents=True, exist_ok=True)


_PACKET_DROUGHT_THRESHOLD_SECS = 8.0


def main() -> None:
    """Run environment checks, initialize dependencies, and start the GUI."""
    if is_pyinstaller_compiled():
        old_exe = Path(sys.executable).with_name(f'{Path(sys.executable).name}.old')
        with contextlib.suppress(OSError):
            old_exe.unlink()

    hide_console_window()

    colorama.init(autoreset=True)
    os.chdir(SCRIPT_DIR)

    if sys.platform != 'win32':
        raise UnsupportedPlatformError(sys.platform)

    # Check minimum screen resolution requirement early to avoid wasting user's time
    try:
        screen_size = get_screen_size()
    except UnsupportedScreenResolutionError as e:
        msgbox.show(
            title='Unsupported Screen Resolution',
            text=e.msgbox_text,
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_TOPMOST,
        )
        sys.exit(1)

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

            msgbox_style = msgbox.Style.MB_YESNO | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND
            msgbox_title = TITLE
            errorlevel = msgbox.show(msgbox_title, msgbox_message, msgbox_style)
            if errorlevel != msgbox.ReturnValues.IDYES:
                sys.exit(0)

    splash.update_status('Applying custom settings from Settings.ini')
    splash.run_with_spinner(Settings.load_from_settings_file, SETTINGS_PATH)
    register_secret_provider(lambda: Settings.looky_api_key)
    register_secret_provider(lambda: Settings.webserver_password)
    Settings.rebuild_blocked_ip_ranges()
    CaptureStats.resize_history_deques(Settings.gui_rate_graph_max_history)

    splash.run_with_spinner(GUIProtectionSettings.load_from_file_or_defaults, PROTECTIONS_JSON_PATH)
    splash.run_with_spinner(ComboRulesManager.load_from_file, COMBO_RULES_PATH)

    splash.update_status('Checking for updates')
    outcome, pending_download = splash.run_with_spinner(check_for_updates, updater_channel=Settings.updater_channel)
    if outcome is UpdateCheckOutcome.ABORT:
        sys.exit(0)
    if pending_download is not None:
        splash.lower_to_back()
        pending_download()

    splash.update_status('Verifying Npcap driver')
    splash.run_with_spinner(ensure_npcap_installed)

    splash.update_status('Initializing GeoLite2 databases')
    geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = splash.run_with_spinner(update_and_initialize_geolite2_readers)

    splash.update_status('Initializing MAC lookup')
    splash.run_with_spinner(MacLookup.load)

    splash.update_status('Network interface selection')
    splash.run_with_spinner(populate_network_interfaces_info)

    available_interfaces: list[Interface] = []
    capture_interfaces = splash.run_with_spinner(get_filtered_scapy_interfaces)

    for device_name, friendly_name in capture_interfaces:
        interface = AllInterfaces.get_interface_by_name(friendly_name)
        if interface is None:
            continue

        # Populate device_name from scapy (the NPF path used by pcap)
        interface.identity.device_name = device_name

        if (
            Settings.capture_interface_name is not None
            and interface.identity.name.casefold() == Settings.capture_interface_name.casefold()
            and interface.identity.name != Settings.capture_interface_name
        ):
            Settings.capture_interface_name = interface.identity.name
            Settings.rewrite_settings_file()

        available_interfaces.append(interface)

    msgbox.set_owner_hwnd(0)  # Clear owner before handing off z-order to the interface dialog
    selected_interface = select_interface(
        available_interfaces, screen_size,
        before_dialog=splash.lower_to_back,
    )
    if selected_interface is None:
        sys.exit(0)

    CaptureState.apply_interface_names(
        is_neighbour=selected_interface.is_neighbour,
        name=selected_interface.name,
        ip=selected_interface.ip_address,
        interface_type=selected_interface.interface.interface_type,
    )

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

    broadcast_support, multicast_support = splash.run_with_spinner(check_broadcast_multicast_support, selected_interface.device_name or selected_interface.name)
    vpn_mode_enabled = not (broadcast_support and multicast_support)

    capture_filter_str, display_filter_fn = splash.run_with_spinner(
        build_capture_filters,
        capture_ip_address=selected_interface.ip_address,
        broadcast_support=broadcast_support,
        multicast_support=multicast_support,
    )

    splash.update_status('Starting packet capture')

    def packet_callback(packet: Packet) -> None:
        """Callback function to process each captured packet."""
        packet_latency = datetime.now(tz=LOCAL_TZ) - packet.datetime
        CaptureStats.packets_latencies.append((packet.datetime, packet_latency))
        CaptureStats.total_packets_captured += 1
        if Settings.capture_overflow_timer > 0 and packet_latency.total_seconds() >= Settings.capture_overflow_timer:
            CaptureStats.restarted_times += 1
            CaptureStats.packets_latencies.clear()
            logger.warning(
                'Packet capture overflow detected: latency %.2fs exceeds threshold of %.2fs. '
                'Restarting capture now (restart no.%d). Skipping this packet.',
                packet_latency.total_seconds(),
                Settings.capture_overflow_timer,
                CaptureStats.restarted_times,
            )
            capture_holder.request_restart()
            return  # Skip processing this packet

        if Settings.capture_game_preset and Settings.capture_filter_preset_packet_size:
            if Settings.is_gta5_preset():
                _preset_min, _preset_max = GTA5_PACKET_SIZE_MIN, GTA5_PACKET_SIZE_MAX
            else:  # Minecraft
                _preset_min, _preset_max = MINECRAFT_PACKET_SIZE_MIN, MINECRAFT_PACKET_SIZE_MAX
            if packet.length < _preset_min or packet.length > _preset_max:
                logger.debug(
                    '[%s preset] Filtered packet - size %d outside expected range [%d-%d]: %s:%d -> %s:%d',
                    Settings.capture_game_preset,
                    packet.length,
                    _preset_min,
                    _preset_max,
                    packet.ip.src,
                    packet.port.src,
                    packet.ip.dst,
                    packet.port.dst,
                )
                return

        if packet.ip.src == Settings.capture_ip_address:
            target_ip = packet.ip.dst
            target_port = packet.port.dst
            sent_by_local_host = True
        elif packet.ip.dst == Settings.capture_ip_address:
            target_ip = packet.ip.src
            target_port = packet.port.src
            sent_by_local_host = False
        else:
            return  # Neither source nor destination matches the capture IP address.

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
            submit_global_protections_check(matched_player)

        if not matched_player.relay_monitor_started:
            matched_player.relay_monitor_started = True
            if Settings.is_gta5_preset() and CaptureState.gta5_is_running and is_gta5_relay_ip(matched_player.ip):
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

    _adapter_lost_event = Event()

    capture = PacketCapture(
        CaptureConfig(
            interface=selected_interface,
            broadcast_support=broadcast_support,
            multicast_support=multicast_support,
            capture_filter=capture_filter_str,
            display_filter_fn=display_filter_fn,
            callback=packet_callback,
            on_capture_lost=_adapter_lost_event.set,
        ),
    )
    # Wrap in a mutable holder so background threads pick up a new capture on interface switch
    capture_holder = CaptureHolder(capture)

    splash.run_with_spinner(capture.start)
    CaptureStats.capture_started_at = time.monotonic()
    CaptureState.vpn_mode_enabled = vpn_mode_enabled

    _arp_failed_event = Event()
    ArpSpoofingController.configure(capture_holder, on_failed=_arp_failed_event.set)
    if Settings.capture_arp_spoofing:
        ArpSpoofingController.start(selected_interface)

    # Initialize GUI first - now it has all the data it needs
    def _switch_interface() -> None:
        # Lock the button immediately to prevent double-clicks
        window.set_change_interface_button_enabled(enabled=False)

        # Build the initial interface list from the current AllInterfaces registry
        # without calling refresh_available_interfaces(), which blocks the GUI thread
        # via COM/ICS Windows APIs (win32com.client.Dispatch('HNetCfg.HNetShare')).
        # The dialog's live-refresh timer will call refresh_available_interfaces()
        # from within its own event loop a few seconds after the dialog opens.
        new_available_interfaces: list[Interface] = []
        for _device_name, _friendly_name in get_filtered_scapy_interfaces():
            _interface = AllInterfaces.get_interface_by_name(_friendly_name)
            if _interface is None:
                continue
            _interface.identity.device_name = _device_name
            new_available_interfaces.append(_interface)

        new_interface = select_interface(
            new_available_interfaces,
            screen_size,
            force_dialog=True,
        )

        if new_interface is None:
            window.set_change_interface_button_enabled(enabled=True)
            return

        # Stop ARP spoofing before touching capture state: otherwise the old ARP thread
        # observes the new capture starting and spawns arpspoof.exe on the OLD interface.
        ArpSpoofingController.stop()

        was_running = capture_holder.is_running()
        if was_running:
            capture_holder.stop()
        window.set_interface_switching_mode(switching=True)

        # Run the broadcast/multicast filter probe off the Qt thread so the UI stays responsive.
        with ThreadPoolExecutor(max_workers=1) as _pool:
            _future = _pool.submit(check_broadcast_multicast_support, new_interface.device_name or new_interface.name)
            while not _future.done():
                app.processEvents()
                time.sleep(0.016)
            new_broadcast, new_multicast = _future.result()
        new_vpn_mode = not (new_broadcast and new_multicast)

        CaptureState.apply_interface_names(
            is_neighbour=new_interface.is_neighbour,
            name=new_interface.name,
            ip=new_interface.ip_address,
            interface_type=new_interface.interface.interface_type,
        )
        Settings.capture_interface_name = new_interface.name
        Settings.capture_mac_address = new_interface.mac_address
        Settings.capture_ip_address = new_interface.ip_address
        Settings.rewrite_settings_file()

        new_capture_filter, new_display_filter_fn = build_capture_filters(
            capture_ip_address=new_interface.ip_address,
            broadcast_support=new_broadcast,
            multicast_support=new_multicast,
        )

        CaptureState.vpn_mode_enabled = new_vpn_mode
        CaptureStats.reset_on_interface_switch()

        window.reset_players_for_interface_switch()
        window.reset_session_graph()

        new_capture = PacketCapture(
            CaptureConfig(
                interface=new_interface,
                broadcast_support=new_broadcast,
                multicast_support=new_multicast,
                capture_filter=new_capture_filter,
                display_filter_fn=new_display_filter_fn,
                callback=packet_callback,
                on_capture_lost=_adapter_lost_event.set,
            ),
        )
        new_capture.start()
        CaptureStats.capture_started_at = time.monotonic()
        capture_holder.set(new_capture)

        if Settings.capture_arp_spoofing:
            ArpSpoofingController.start(new_interface)

        window.on_interface_switched()
        window.set_interface_switching_mode(switching=False)

    window = MainWindow(screen_size, capture_holder, on_change_interface=_switch_interface)

    # Re-entry guard: adapter-lost and ARP-failed pollers can both fire while the interface
    # dialog is already open; non-blocking acquire skips the second caller cleanly.
    _capture_lost_lock = Lock()

    def _handle_capture_lost(*, stop_capture: bool, warning_message: str | None) -> None:
        """Shared handler for any event that requires stopping capture and re-selecting an interface."""
        if not _capture_lost_lock.acquire(blocking=False):
            return
        try:
            if stop_capture and capture_holder.is_running():
                capture_holder.stop()
            window.on_interface_switched()
            window.set_capture_toggle_enabled(enabled=False)
            if warning_message is not None:
                QMessageBox.warning(window, 'Capture Interrupted', warning_message)
            _switch_interface()
        finally:
            _capture_lost_lock.release()

    def _on_adapter_lost_poll() -> None:
        """Poll for unexpected capture exits and re-show the interface selection dialog."""
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

    _ip_changed_queue: queue.Queue[str] = queue.Queue()

    def _on_ip_changed_poll() -> None:
        """Poll for capture interface IP changes and silently restart the capture."""
        if gui_closed__event.is_set():
            return

        try:
            new_ip = _ip_changed_queue.get_nowait()
        except queue.Empty:
            return

        current_config = capture_holder.config
        if current_config.interface.ip_address == new_ip:
            return  # Race: IP was already updated (e.g. manual interface switch ran concurrently)

        was_running = capture_holder.is_running()
        if was_running:
            capture_holder.stop()

        new_capture_filter, new_display_filter_fn = build_capture_filters(
            capture_ip_address=new_ip,
            broadcast_support=current_config.broadcast_support,
            multicast_support=current_config.multicast_support,
        )

        Settings.capture_ip_address = new_ip
        Settings.rewrite_settings_file()

        new_selected_interface = SelectedInterfaceRow(
            interface=current_config.interface.interface,
            ip_address=new_ip,
            is_neighbour=current_config.interface.is_neighbour,
        )

        new_capture = PacketCapture(
            CaptureConfig(
                interface=new_selected_interface,
                broadcast_support=current_config.broadcast_support,
                multicast_support=current_config.multicast_support,
                capture_filter=new_capture_filter,
                display_filter_fn=new_display_filter_fn,
                callback=packet_callback,
                on_capture_lost=_adapter_lost_event.set,
            ),
        )

        new_capture.start()
        CaptureStats.capture_started_at = time.monotonic()
        capture_holder.set(new_capture)
        window.on_interface_switched()

    _ip_changed_timer = QTimer()
    _ip_changed_timer.setInterval(500)
    _ip_changed_timer.timeout.connect(_on_ip_changed_poll)
    _ip_changed_timer.start()

    def _monitor_capture_ip_change_loop() -> None:
        """Background thread: detect when the capture interface IP changes and queue a silent restart.

        Some VPN clients assign a new IP address to their adapter when switching servers.
        The BPF capture filter is compiled once at capture start with the old IP, so after
        the IP changes the sniffer keeps running but captures zero matching packets.

        Strategy: poll `total_packets_captured` every 2 seconds.  When the counter stops advancing
        for ≥8 seconds (packet drought), call `get_adapters_info()` once to check whether the
        interface IP actually changed.  If it did → queue a restart.  If the IP is unchanged the
        drought is just normal idle time (no game running) and nothing is done.  This avoids calling
        the Windows adapter API on every iteration while also preventing false restarts when the
        user simply isn't in a session.
        """
        last_packet_count = CaptureStats.total_packets_captured
        last_count_change = time.monotonic()
        drought_active = False

        while not gui_closed__event.wait(2.0):
            if not capture_holder.is_running() or not _ip_changed_queue.empty():
                # Capture stopped or a restart is already queued — reset baseline and wait.
                last_packet_count = CaptureStats.total_packets_captured
                last_count_change = time.monotonic()
                drought_active = False
                continue

            if CaptureStats.total_packets_captured != last_packet_count:
                last_packet_count = CaptureStats.total_packets_captured
                last_count_change = time.monotonic()
                drought_active = False
                continue

            if time.monotonic() - last_count_change < _PACKET_DROUGHT_THRESHOLD_SECS:
                continue  # Drought not long enough yet

            # Packet drought confirmed — check whether the interface IP changed.
            current_interface = capture_holder.config.interface
            if not drought_active:
                drought_active = True
            if current_interface.is_neighbour:
                last_count_change = time.monotonic()  # reset so we don't spin
                drought_active = False
                continue  # ARP-spoof mode: filter IP is the neighbour's IP, not the adapter's

            adapter_guid = current_interface.interface.identity.adapter_guid
            if adapter_guid is None:
                last_count_change = time.monotonic()
                drought_active = False
                continue

            adapter_has_ip = False
            for adapter in get_adapters_info():
                if adapter.identity.adapter_guid != adapter_guid:
                    continue
                if not adapter.ipv4_addresses:
                    break  # Adapter found but no IP yet (VPN reconnecting)
                adapter_has_ip = True
                new_ip = adapter.ipv4_addresses[0]
                if new_ip != current_interface.ip_address:
                    logger.warning(
                        'Capture interface IP changed from %s to %s — restarting capture.',
                        current_interface.ip_address,
                        new_ip,
                    )
                    _ip_changed_queue.put(new_ip)
                break

            # Reset the drought clock only if the adapter had a valid IP.
            # If the adapter had no IP (VPN reconnecting) or was not found at all,
            # keep the drought active so we re-check on the very next poll cycle
            # (~2 s) rather than waiting another full 8 s.
            if adapter_has_ip:
                last_count_change = time.monotonic()
                drought_active = False

    Thread(
        target=_monitor_capture_ip_change_loop,
        name='CaptureIPChangeMonitor',
        daemon=True,
    ).start()

    ensure_gta5_process_monitor_running()

    splash.finish_loading()

    def _reveal_main_window() -> None:
        # Remove always-on-top from the splash so the main window can rise above it.
        # With auto-connect the dialog is skipped, so lower_to_back() is never called
        # via before_dialog; calling it here is idempotent for the manual-connect path.
        splash.lower_to_back()
        # Show and activate the main window while the splash still owns the foreground.
        # Closing the splash first surrenders foreground ownership to whatever Windows
        # picks next, causing activateWindow() to be silently ignored on the new window.
        window.show()
        window.raise_()
        window.activateWindow()
        QTimer.singleShot(100, splash.close_splash)

    QTimer.singleShot(1500, _reveal_main_window)

    def _check_startup_relay_conflict() -> None:
        """Warn at startup when relay protection is enabled but relay IPs are being filtered out."""
        prompt_to_disable_gta5_relay_if_filtered(window, context='startup')

    QTimer.singleShot(2000, _check_startup_relay_conflict)

    # Start background processing threads FIRST
    player_rates_core__thread = Thread(target=player_rates_core, name='player_rates_core', daemon=True)
    player_rates_core__thread.start()

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

    # Start web server if enabled
    if Settings.webserver_enabled:
        start_webserver_from_settings()

    hostname_core__thread = Thread(target=hostname_core, name='hostname_core', daemon=True)
    hostname_core__thread.start()

    iplookup_core__thread = Thread(target=iplookup_core, name='iplookup_core', daemon=True)
    iplookup_core__thread.start()

    pinger_core__thread = Thread(target=pinger_core, name='pinger_core', daemon=True)
    pinger_core__thread.start()

    ensure_looky_core_running()

    if Settings.show_discord_popup:
        # Delay the popup opening by 3 seconds
        QTimer.singleShot(3000, lambda: DiscordIntro().exec())

    # Start the application's event loop
    sys.exit(app.exec())


if __name__ == '__main__':
    atexit.register(logging.shutdown)
    main()
