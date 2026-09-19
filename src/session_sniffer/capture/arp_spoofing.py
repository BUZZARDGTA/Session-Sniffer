"""ARP spoofing background task utilities."""

import logging
import socket
import time
from dataclasses import dataclass
from threading import Event, Thread
from typing import TYPE_CHECKING, ClassVar

from session_sniffer import msgbox
from session_sniffer.background.events import gui_closed__event
from session_sniffer.capture.arp import (
    ArpSpoofTargets,
    build_arp_spoof_bpf_filter,
    forward_intercepted_frame,
    mac_string_to_bytes,
    resolve_mac_address,
    send_arp_restore_packets,
    send_arp_spoof_packets,
)
from session_sniffer.capture.exceptions import ArpResolutionError, PcapFilterError, PcapOpenError, PcapReadError, PcapSendError
from session_sniffer.capture.pcap import PcapHandle
from session_sniffer.error_messages import format_arp_spoofing_failed_message

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.networking.interface import SelectedInterfaceRow

logger = logging.getLogger(__name__)

_ARP_SPOOF_INTERVAL_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class _ArpControllerConfig:
    """App-wide wiring for `ArpSpoofingController`."""

    capture_holder: CaptureHolder
    on_failed: Callable[[], None]


class ArpSpoofingController:
    """App-wide owner of the single ARP spoofing thread.

    Class-level service: there is at most one ARP thread alive at any time.
    Call `configure()` once at startup, then `start()` / `stop()` as needed.
    Safe to call `stop()` when nothing is running.
    """

    _config: ClassVar[_ArpControllerConfig | None] = None
    _stop_event: ClassVar[Event] = Event()
    _thread: ClassVar[Thread | None] = None

    @classmethod
    def configure(cls, capture_holder: CaptureHolder, on_failed: Callable[[], None]) -> None:
        """Wire the controller to the app-wide capture holder and failure callback."""
        cls._config = _ArpControllerConfig(capture_holder=capture_holder, on_failed=on_failed)

    @classmethod
    def is_running(cls) -> bool:
        """Return True if the ARP spoofing thread is active."""
        return cls._thread is not None and cls._thread.is_alive()

    @classmethod
    def start(cls, interface: SelectedInterfaceRow) -> None:
        """Start ARP spoofing on `interface`. Caller must ensure no thread is currently active."""
        if cls._config is None:
            message = 'ArpSpoofingController.start() called before configure()'
            raise RuntimeError(message)
        if cls.is_running():
            message = 'ArpSpoofingController.start() called while a previous thread is still alive'
            raise RuntimeError(message)
        if cls._thread is not None and not cls._thread.is_alive():
            cls._thread = None
        cls._stop_event.clear()
        cls._thread = Thread(
            target=arp_spoofing_task,
            name='ARPSpoofingTask',
            args=(interface, cls._config.capture_holder, cls._stop_event, cls._config.on_failed),
            daemon=True,
        )
        cls._thread.start()

    @classmethod
    def stop(cls) -> None:
        """Signal the running thread to exit and wait for it to die."""
        if cls._thread is None:
            return
        cls._stop_event.set()
        cls._thread.join()
        cls._thread = None


def arp_spoofing_task(
    selected_interface: SelectedInterfaceRow,
    capture_holder: CaptureHolder,
    stop_event: Event,
    on_failed: Callable[[], None],
) -> None:
    """Manage ARP spoofing lifecycle synchronized with packet capture state.

    Opens a dedicated pcap handle on the interface, resolves the gateway MAC,
    and continuously sends spoofed ARP replies while the capture is running.

    Exits when `stop_event` is set (interface switch) or `gui_closed__event` is set (app close).
    """
    # Validate required interface fields
    if selected_interface.device_name is None:
        logger.error('ARP spoofing cannot start: device_name is None')
        return

    if selected_interface.mac_address is None:
        logger.error('ARP spoofing cannot start: interface MAC address is None')
        return

    host_mac = selected_interface.interface.identity.mac_address or selected_interface.mac_address
    target_ip = selected_interface.ip_address
    target_mac = selected_interface.mac_address
    source_ip = selected_interface.interface.ip_addresses[0] if selected_interface.interface.ip_addresses else None
    gateway_ip = selected_interface.gateway_ip
    gateway_mac: str | None = None
    targets: ArpSpoofTargets | None = None

    def report_failure(
        stage: str,
        *,
        error_details: str | None,
        msgbox_style: msgbox.Style,
        spawn_msgbox_thread: bool,
    ) -> None:
        """Log, notify, and terminate the ARP spoofing task on failure."""
        logger.error('%s.', stage.capitalize())
        if error_details:
            logger.error('Error: %s', error_details)

        message = format_arp_spoofing_failed_message(
            selected_interface=selected_interface,
            error_details=error_details,
        )

        def show_msgbox() -> None:
            msgbox.show(
                title='ARP Spoofing Failed',
                text=message,
                style=msgbox_style,
            )

        if spawn_msgbox_thread:
            Thread(
                target=show_msgbox,
                name=f'ARPSpoof-{stage}-msgbox',
                daemon=True,
            ).start()
        else:
            show_msgbox()
        logger.info('Task terminated due to %s.', stage)

    def _should_exit() -> bool:
        return gui_closed__event.is_set() or stop_event.is_set()

    pcap_handle: PcapHandle | None = None

    try:
        while not _should_exit():
            # Wait for capture to be running
            while not capture_holder.is_running() and not _should_exit():
                time.sleep(0.5)

            if _should_exit():
                break

            # Open a dedicated pcap handle for sending ARP packets and forwarding intercepted traffic
            try:
                pcap_handle = PcapHandle.open_live(
                    selected_interface.device_name,
                    snaplen=65535,
                    promiscuous=True,
                    timeout_milliseconds=20,
                    buffer_size=33_554_432,
                )
            except (PcapOpenError, OSError) as exception:
                report_failure(
                    'startup failure',
                    error_details=str(exception),
                    msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_TOPMOST,
                    spawn_msgbox_thread=False,
                )
                on_failed()
                return

            # Resolve gateway MAC address
            if gateway_ip is None:
                logger.info('No gateway IP available, skipping gateway ARP spoofing')
            elif gateway_mac is None:
                try:
                    gateway_mac = resolve_mac_address(gateway_ip, source_ip=source_ip)
                    logger.info('Resolved gateway MAC: %s -> %s', gateway_ip, gateway_mac)
                except ArpResolutionError as exception:
                    report_failure(
                        'gateway MAC resolution failure',
                        error_details=str(exception),
                        msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_TOPMOST,
                        spawn_msgbox_thread=False,
                    )
                    on_failed()
                    return

            if gateway_ip is not None and gateway_mac is not None:
                targets = ArpSpoofTargets(
                    target_ip=target_ip,
                    target_mac=target_mac,
                    gateway_ip=gateway_ip,
                    gateway_mac=gateway_mac,
                )

            logger.info(
                'Started spoofing on interface %s%s',
                selected_interface.ip_address,
                f' (gateway: {gateway_ip})' if gateway_ip else '',
            )

            host_mac_bytes: bytes | None = None
            target_mac_bytes: bytes | None = None
            gateway_mac_bytes: bytes | None = None
            target_ip_bytes: bytes | None = None

            if targets is not None:
                host_mac_bytes = mac_string_to_bytes(host_mac)
                target_mac_bytes = mac_string_to_bytes(targets.target_mac)
                gateway_mac_bytes = mac_string_to_bytes(targets.gateway_mac)
                target_ip_bytes = socket.inet_aton(targets.target_ip)

                bpf_filter = build_arp_spoof_bpf_filter(host_mac, targets)
                try:
                    pcap_handle.set_filter(bpf_filter)
                    logger.debug('Applied ARP spoof BPF filter: %s', bpf_filter)
                except PcapFilterError as exception:
                    logger.warning('Failed to compile/set ARP spoof BPF filter, falling back to software filtering: %s', exception)

            next_spoof_timestamp = 0.0

            # Forward packets and periodically refresh spoofed ARP replies while capture is running
            while capture_holder.is_running() and not _should_exit():
                if targets is None or host_mac_bytes is None or target_mac_bytes is None or gateway_mac_bytes is None or target_ip_bytes is None:
                    time.sleep(0.5)
                    continue

                current_time = time.monotonic()
                if current_time >= next_spoof_timestamp:
                    try:
                        send_arp_spoof_packets(
                            pcap_handle,
                            host_mac=host_mac,
                            targets=targets,
                        )
                        next_spoof_timestamp = current_time + _ARP_SPOOF_INTERVAL_SECONDS
                    except PcapSendError as exception:
                        report_failure(
                            'unexpected packet injection error',
                            error_details=str(exception),
                            msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_TOPMOST,
                            spawn_msgbox_thread=False,
                        )
                        on_failed()
                        return

                try:
                    raw_frame = pcap_handle.next_raw_frame()
                except PcapReadError as exception:
                    if not capture_holder.is_running() or _should_exit():
                        break
                    report_failure(
                        'capture read error',
                        error_details=str(exception),
                        msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_TOPMOST,
                        spawn_msgbox_thread=False,
                    )
                    on_failed()
                    return

                if raw_frame is None:
                    continue

                rewritten_frame = forward_intercepted_frame(
                    raw_frame,
                    host_mac_bytes=host_mac_bytes,
                    target_mac_bytes=target_mac_bytes,
                    target_ip_bytes=target_ip_bytes,
                    gateway_mac_bytes=gateway_mac_bytes,
                )
                if rewritten_frame is not None:
                    try:
                        pcap_handle.send_packet(rewritten_frame)
                    except PcapSendError as exception:
                        logger.debug('Failed to forward frame: %s', exception)

            # Capture stopped; restore ARP tables and close handle
            if targets is not None:
                try:
                    send_arp_restore_packets(
                        pcap_handle,
                        targets=targets,
                    )
                except PcapSendError as exception:
                    logger.warning('Failed sending ARP restore packets: %s', exception)
            pcap_handle.close()
            pcap_handle = None
            logger.info('Stopped spoofing.')
    finally:
        if pcap_handle is not None:
            if targets is not None:
                try:
                    send_arp_restore_packets(
                        pcap_handle,
                        targets=targets,
                    )
                except PcapSendError as exception:
                    logger.warning('Failed sending ARP restore packets: %s', exception)
            pcap_handle.close()
        logger.info('Task terminated.')
