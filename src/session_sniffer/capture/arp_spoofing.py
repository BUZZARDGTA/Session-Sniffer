"""ARP spoofing background task utilities."""

import time
from dataclasses import dataclass
from threading import Event, Thread
from typing import TYPE_CHECKING, ClassVar

from session_sniffer import msgbox
from session_sniffer.background.events import gui_closed__event
from session_sniffer.capture.arp import resolve_mac_address, send_arp_spoof_packets
from session_sniffer.capture.exceptions import ArpResolutionError, PcapOpenError, PcapSendError
from session_sniffer.capture.pcap import PcapHandle
from session_sniffer.error_messages import format_arp_spoofing_failed_message
from session_sniffer.logging_setup import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import CaptureHolder
    from session_sniffer.networking.interface import SelectedInterfaceRow

logger = get_logger(__name__)

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

            # Open a dedicated pcap handle for sending ARP packets
            if pcap_handle is None:
                try:
                    pcap_handle = PcapHandle.open_live(
                        selected_interface.device_name,
                        snaplen=64,
                        promiscuous=False,
                        timeout_milliseconds=100,
                        buffer_size=0,
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
            gateway_ip = selected_interface.gateway_ip
            if gateway_ip is None:
                logger.info('No gateway IP available, sending broadcast ARP spoofing only')

            gateway_mac: str | None = None
            if gateway_ip is not None:
                try:
                    gateway_mac = resolve_mac_address(gateway_ip)
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

            logger.info(
                'Started spoofing on interface %s%s',
                selected_interface.ip_address,
                f' (gateway: {gateway_ip})' if gateway_ip else '',
            )

            # Send spoofed ARP replies while capture is running
            while capture_holder.is_running() and not _should_exit():
                try:
                    if gateway_ip is not None and gateway_mac is not None:
                        send_arp_spoof_packets(
                            pcap_handle,
                            interface_mac=selected_interface.mac_address,
                            interface_ip=selected_interface.ip_address,
                            gateway_ip=gateway_ip,
                            gateway_mac=gateway_mac,
                        )
                except PcapSendError as exception:
                    report_failure(
                        'unexpected packet injection error',
                        error_details=str(exception),
                        msgbox_style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_TOPMOST,
                        spawn_msgbox_thread=False,
                    )
                    on_failed()
                    return

                # Wait before sending the next round of spoofed packets
                elapsed = 0.0
                while elapsed < _ARP_SPOOF_INTERVAL_SECONDS and not _should_exit() and capture_holder.is_running():
                    time.sleep(0.1)
                    elapsed += 0.1

            # Capture stopped; close handle and wait for next capture start
            pcap_handle.close()
            pcap_handle = None
            logger.info('Stopped spoofing.')
    finally:
        if pcap_handle is not None:
            pcap_handle.close()
        logger.info('Task terminated.')
