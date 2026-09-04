"""Module for packet capture using Npcap/WinPcap, including packet parsing and lifecycle management."""

import struct
import threading
from dataclasses import dataclass, field
from datetime import datetime as datetime_type
from typing import TYPE_CHECKING, NamedTuple, Self, final

from session_sniffer.capture.exceptions import (
    CaptureAlreadyRunningError,
    CaptureError,
    CaptureExitError,
    CaptureNotRunningError,
    CaptureThreadAlreadyRunningError,
    InvalidIPv4AddressFormatError,
    InvalidIPv4AddressMultipleError,
    InvalidLengthNumericError,
    InvalidPortNumberError,
    MalformedEthernetFrameTooShortError,
    MalformedEtherTypeError,
    MalformedIPVersionError,
    MalformedLoopbackFrameTooShortError,
    MalformedPacketError,
    MalformedProtocolError,
    MalformedVlanFrameTooShortError,
    MissingPortError,
    MissingRequiredPacketFieldError,
)
from session_sniffer.capture.pcap import DLT_EN10MB, DLT_NULL, DLT_RAW, PcapHandle
from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.utils import is_ipv4_address

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.networking.interface import SelectedInterfaceRow

logger = get_logger(__name__)

# Protocol numbers and header sizes
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_VLAN = 0x8100
_IP_PROTOCOL_UDP = 17
_IPV4_VERSION = 4

_ETHERNET_HEADER_LENGTH = 14
_VLAN_HEADER_LENGTH = 18
_NULL_HEADER_LENGTH = 4
_IPV4_MIN_HEADER_LENGTH = 20
_UDP_HEADER_LENGTH = 8


def _log_malformed_packet_skip(
    reason: str,
    /,
    *,
    raw_length: int,
) -> None:
    """Log a malformed packet including reason and length."""
    logger.warning(
        '%s (Packet skipped). length=%d',
        reason,
        raw_length,
    )


def _parse_and_validate_port(port: int, /) -> int:
    if not MIN_PORT <= port <= MAX_PORT:
        raise InvalidPortNumberError(port)
    return port


def _parse_and_validate_ip(ip: str, /) -> str:
    if ',' in ip:
        raise InvalidIPv4AddressMultipleError(ip)
    if not is_ipv4_address(ip):
        raise InvalidIPv4AddressFormatError(ip)
    return ip


def _parse_and_validate_length(length: int, /) -> int:
    if length < 0:
        raise InvalidLengthNumericError(length)
    return length


class PacketIP(NamedTuple):
    """Hold source and destination IP addresses for a packet."""

    src: str
    dst: str


class Port(NamedTuple):
    """Hold source and destination ports for a packet."""

    src: int
    dst: int


class Packet(NamedTuple):
    """Represent a parsed packet emitted by the capture pipeline."""

    datetime: datetime_type
    ip: PacketIP
    port: Port
    length: int
    payload: bytes | None = None

    @classmethod
    def from_raw_frame(
        cls,
        raw_bytes: bytes,
        packet_time: datetime_type,
        datalink_type: int = DLT_EN10MB,
        *,
        include_payload: bool = False,
    ) -> Self:
        """Parse raw link-layer frame bytes into a `Packet` structure.

        Args:
            raw_bytes: The raw packet bytes captured from the adapter.
            packet_time: Timestamp when packet was captured.
            datalink_type: Datalink header type (e.g. DLT_EN10MB, DLT_NULL, DLT_RAW).
            include_payload: Whether to extract UDP payload bytes.

        Returns:
            A `Packet` instance.

        Raises:
            MissingRequiredPacketFieldError: If required fields or headers are truncated.
            MissingPortError: If port values are invalid.
            MalformedPacketError: If packet is not a valid IPv4/UDP packet.
        """
        frame_length = len(raw_bytes)

        if datalink_type == DLT_EN10MB:
            if frame_length < _ETHERNET_HEADER_LENGTH:
                raise MalformedEthernetFrameTooShortError

            ethertype = struct.unpack_from('!H', raw_bytes, 12)[0]
            ip_offset = _ETHERNET_HEADER_LENGTH

            if ethertype == _ETHERTYPE_VLAN:
                if frame_length < _VLAN_HEADER_LENGTH:
                    raise MalformedVlanFrameTooShortError
                ethertype = struct.unpack_from('!H', raw_bytes, 16)[0]
                ip_offset = _VLAN_HEADER_LENGTH

            if ethertype != _ETHERTYPE_IPV4:
                raise MalformedEtherTypeError(ethertype)

        elif datalink_type == DLT_NULL:
            if frame_length < _NULL_HEADER_LENGTH:
                raise MalformedLoopbackFrameTooShortError
            ip_offset = _NULL_HEADER_LENGTH

        elif datalink_type == DLT_RAW:
            ip_offset = 0

        elif frame_length >= _ETHERNET_HEADER_LENGTH:
            ethertype = struct.unpack_from('!H', raw_bytes, 12)[0]
            ip_offset = _ETHERNET_HEADER_LENGTH if ethertype == _ETHERTYPE_IPV4 else 0
        else:
            ip_offset = 0

        if frame_length < ip_offset + _IPV4_MIN_HEADER_LENGTH:
            raise MissingRequiredPacketFieldError

        version_and_ihl = raw_bytes[ip_offset]
        version = version_and_ihl >> 4
        if version != _IPV4_VERSION:
            raise MalformedIPVersionError(version)

        ip_header_length = (version_and_ihl & 0x0F) * 4
        if ip_header_length < _IPV4_MIN_HEADER_LENGTH or frame_length < ip_offset + ip_header_length + _UDP_HEADER_LENGTH:
            raise MissingRequiredPacketFieldError

        protocol = raw_bytes[ip_offset + 9]
        if protocol != _IP_PROTOCOL_UDP:
            raise MalformedProtocolError(protocol)

        src_ip_bytes = raw_bytes[ip_offset + 12 : ip_offset + 16]
        dst_ip_bytes = raw_bytes[ip_offset + 16 : ip_offset + 20]
        src_ip = f'{src_ip_bytes[0]}.{src_ip_bytes[1]}.{src_ip_bytes[2]}.{src_ip_bytes[3]}'
        dst_ip = f'{dst_ip_bytes[0]}.{dst_ip_bytes[1]}.{dst_ip_bytes[2]}.{dst_ip_bytes[3]}'

        udp_offset = ip_offset + ip_header_length
        src_port, dst_port, udp_length = struct.unpack_from('!HHH', raw_bytes, udp_offset)

        if not src_port or not dst_port:
            raise MissingPortError

        payload: bytes | None = None
        if include_payload:
            payload_offset = udp_offset + _UDP_HEADER_LENGTH
            payload_end = udp_offset + max(_UDP_HEADER_LENGTH, udp_length)
            payload = raw_bytes[payload_offset:payload_end]

        return cls(
            datetime=packet_time,
            ip=PacketIP(
                src=_parse_and_validate_ip(src_ip),
                dst=_parse_and_validate_ip(dst_ip),
            ),
            port=Port(
                src=_parse_and_validate_port(src_port),
                dst=_parse_and_validate_port(dst_port),
            ),
            length=_parse_and_validate_length(frame_length),
            payload=payload,
        )


type PacketCallback = Callable[[Packet], None]


@dataclass(frozen=True, kw_only=True, slots=True)
class CaptureConfig:
    """Configuration for packet capture.

    Attributes:
        interface: The selected network interface to capture packets from.
        callback: A callback function to process captured packets.
        broadcast_support: Whether the interface supports the `broadcast` capture filter.
        multicast_support: Whether the interface supports the `multicast` capture filter.
        capture_filter: An optional BPF capture filter string.
        display_filter_fn: An optional Python callable applied to each packet before
            invoking `callback`. Return `True` to forward the packet, `False` to drop it.
        include_payload: Whether to extract UDP payload bytes in captured packets.
        on_capture_lost: An optional callback invoked when capture exits unexpectedly.
    """

    interface: SelectedInterfaceRow
    callback: PacketCallback
    broadcast_support: bool
    multicast_support: bool
    capture_filter: str | None = None
    display_filter_fn: Callable[[Packet], bool] | None = None
    include_payload: bool = False
    on_capture_lost: Callable[[], None] | None = None


@dataclass(kw_only=True, slots=True)
class _CaptureState:
    """Internal state for managing the packet capture."""

    control_lock: threading.Lock = field(default_factory=threading.Lock)
    running_event: threading.Event = field(default_factory=threading.Event)
    restart_requested: threading.Event = field(default_factory=threading.Event)
    capture_thread: threading.Thread | None = None
    pcap_handle: PcapHandle | None = None


class PacketCapture:
    """Manage background packet capture and emit parsed packets via callback."""

    def __init__(self, config: CaptureConfig, /) -> None:
        """Initialize the `PacketCapture` class.

        Args:
            config: Configuration for the packet capture.
        """
        self.config = config
        self._state = _CaptureState()

    def start(self) -> None:
        """Start packet capture by launching the background capture thread."""
        with self._state.control_lock:
            if self._state.running_event.is_set():
                raise CaptureAlreadyRunningError

            self._state.running_event.set()
            self._start_thread()

    def stop(self) -> None:
        """Stop packet capture and join the capture thread."""
        with self._state.control_lock:
            if not self._state.running_event.is_set():
                raise CaptureNotRunningError

            self._state.running_event.clear()

        self._terminate_handle()

        if self._state.capture_thread is not None and self._state.capture_thread.is_alive() and self._state.capture_thread is not threading.current_thread():
            self._state.capture_thread.join()

    def request_restart(self) -> None:
        """Request an async restart of the packet capture.

        Safe to call from within the packet callback.
        """
        self._state.restart_requested.set()

    def is_running(self) -> bool:
        """Return whether packet capture is currently active."""
        return self._state.running_event.is_set()

    def is_restart_requested(self) -> bool:
        """Return whether a restart of the packet capture has been requested."""
        return self._state.restart_requested.is_set()

    def get_pcap_drop_count(self) -> int | None:
        """Return cumulative npcap drop count (`ps_drop` + `ps_ifdrop`) for the current capture session.

        Returns `None` when no active capture handle is available (e.g. between restarts).
        The counters reset each time a new pcap handle is opened (i.e. on every capture restart).
        """
        with self._state.control_lock:
            if self._state.pcap_handle is None:
                return None
            return self._state.pcap_handle.get_drop_count()

    def _terminate_handle(self) -> None:
        """Break the pcap read loop and close the handle."""
        with self._state.control_lock:
            handle = self._state.pcap_handle
            if handle is not None:
                handle.break_loop()

    def _start_thread(self) -> None:
        """Create and start a new capture thread."""
        if self._state.capture_thread and self._state.capture_thread.is_alive():
            raise CaptureThreadAlreadyRunningError

        self._state.capture_thread = threading.Thread(
            target=self._run_capture_loop,
            name='PacketCapture',
            daemon=True,
        )
        self._state.capture_thread.start()

    def _run_capture_loop(self) -> None:
        """Main capture loop — restarts the capture handle after each restart request."""
        while self._state.running_event.is_set():
            self._state.restart_requested.clear()

            try:
                self._capture_and_process()
            except CaptureExitError as e:
                logger.warning('Packet capture stopped unexpectedly: %s', e)
                with self._state.control_lock:
                    self._state.running_event.clear()
                if self.config.on_capture_lost is not None:
                    self.config.on_capture_lost()
                    break
                raise

    def _capture_and_process(self) -> None:
        """Run one packet capture session until stopped, restarted, or crashed."""
        if not self.config.interface.device_name:
            message = f'Interface "{self.config.interface.name}" has no device name; cannot open pcap handle'
            raise CaptureError(message)

        try:
            pcap_handle = PcapHandle.open_live(
                self.config.interface.device_name,
                snaplen=65535,
                promiscuous=True,
                timeout_milliseconds=100,
            )
            if self.config.capture_filter:
                pcap_handle.set_filter(self.config.capture_filter)
        except Exception as e:
            raise CaptureExitError(e) from e

        with self._state.control_lock:
            self._state.pcap_handle = pcap_handle

        need_payload = self.config.include_payload or (self.config.display_filter_fn is not None)

        try:
            while self._state.running_event.is_set() and not self._state.restart_requested.is_set():
                captured_packet = pcap_handle.next_packet()
                if captured_packet is None:
                    continue

                try:
                    packet = Packet.from_raw_frame(
                        captured_packet.data,
                        captured_packet.timestamp,
                        captured_packet.datalink_type,
                        include_payload=need_payload,
                    )
                except MissingRequiredPacketFieldError:
                    continue
                except MalformedPacketError as e:
                    _log_malformed_packet_skip(str(e), raw_length=len(captured_packet.data))
                    continue

                if self.config.display_filter_fn is not None and not self.config.display_filter_fn(packet):
                    continue

                self.config.callback(packet)
        finally:
            with self._state.control_lock:
                if self._state.pcap_handle is pcap_handle:
                    self._state.pcap_handle = None
            pcap_handle.close()


@final
class CaptureHolder:
    """Thread-safe mutable reference to the active `PacketCapture` instance.

    Allows background threads to transparently reference whichever capture is
    currently active without needing to be restarted when the user switches
    to a different network interface.
    """

    def __init__(self, capture: PacketCapture) -> None:
        """Initialise the holder with an initial capture instance."""
        self._capture = capture
        self._lock = threading.Lock()

    def get(self) -> PacketCapture:
        """Return the currently active capture instance."""
        with self._lock:
            return self._capture

    def set(self, capture: PacketCapture) -> None:
        """Atomically swap the active capture instance."""
        with self._lock:
            self._capture = capture

    # --- Delegating helpers so callers can use CaptureHolder in place of PacketCapture ---

    @property
    def config(self) -> CaptureConfig:
        """Return the config of the currently active capture."""
        return self.get().config

    def is_running(self) -> bool:
        """Return whether the active capture is running."""
        return self.get().is_running()

    def is_restart_requested(self) -> bool:
        """Return whether the active capture has a pending restart request."""
        return self.get().is_restart_requested()

    def start(self) -> None:
        """Start the active capture."""
        self.get().start()

    def stop(self) -> None:
        """Stop the active capture."""
        self.get().stop()

    def request_restart(self) -> None:
        """Request a restart of the active capture."""
        self.get().request_restart()
