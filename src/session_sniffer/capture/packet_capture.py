"""Module for packet capture using scapy, including packet processing and capture lifecycle management."""
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NamedTuple, Self, final

from session_sniffer.capture.exceptions import (
    CaptureAlreadyRunningError,
    CaptureError,
    CaptureExitError,
    CaptureNoSnifferError,
    CaptureNotRunningError,
    CaptureThreadAlreadyRunningError,
    InvalidIPv4AddressFormatError,
    InvalidIPv4AddressMultipleError,
    InvalidLengthNumericError,
    InvalidPortNumberError,
    MalformedPacketError,
    MissingPortError,
    MissingRequiredPacketFieldError,
)
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.utils import is_ipv4_address

if TYPE_CHECKING:
    from collections.abc import Callable

    from scapy.packet import Packet as ScapyPacket

    from session_sniffer.networking.interface import SelectedInterfaceRow

logger = get_logger(__name__)


def _log_malformed_packet_skip(
    reason: str,
    /,
    *,
    raw_pkt: ScapyPacket,
) -> None:
    """Log a malformed packet including reason and full debug info."""
    logger.warning(
        '%s (Packet skipped). raw_pkt=%r',
        reason,
        raw_pkt.summary(),
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


def _convert_epoch_time_to_datetime(time_epoch: float, /) -> datetime:
    dt_utc = datetime.fromtimestamp(time_epoch, tz=UTC)
    return dt_utc.astimezone(LOCAL_TZ)


class IP(NamedTuple):
    """Hold source and destination IP addresses for a packet."""

    src: str
    dst: str


class Port(NamedTuple):
    """Hold source and destination ports for a packet."""

    src: int
    dst: int


class Packet(NamedTuple):
    """Represent a parsed packet emitted by the capture pipeline."""

    datetime: datetime
    ip: IP
    port: Port
    length: int

    @classmethod
    def from_scapy(cls, raw_pkt: ScapyPacket) -> Self:
        """Create a `Packet` from a scapy packet object.

        Args:
            raw_pkt: A scapy packet that must contain IP and UDP layers.

        Returns:
            A `Packet` containing the parsed fields.

        Raises:
            MissingRequiredPacketFieldError: If required IP or time fields are absent.
            MissingPortError: If UDP src or dst port is absent.
            InvalidIPv4AddressError: If an IP field is not a valid IPv4 address.
            InvalidPortNumberError: If a port is out of the valid range.
            InvalidLengthNumericError: If frame length is invalid.
        """
        from scapy.layers.inet import IP as ScapyIP  # noqa: N811 PLC0415  # pylint: disable=import-outside-toplevel
        from scapy.layers.inet import UDP as ScapyUDP  # noqa: N811 PLC0415  # pylint: disable=import-outside-toplevel

        if not raw_pkt.haslayer(ScapyIP) or not raw_pkt.haslayer(ScapyUDP):
            raise MissingRequiredPacketFieldError

        ip_layer = raw_pkt[ScapyIP]
        udp_layer = raw_pkt[ScapyUDP]

        src_ip: str = ip_layer.src or ''
        dst_ip: str = ip_layer.dst or ''
        src_port: int | None = udp_layer.sport
        dst_port: int | None = udp_layer.dport

        if not all((src_ip, dst_ip)):
            raise MissingRequiredPacketFieldError

        if src_port is None or dst_port is None:
            raise MissingPortError

        return cls(
            datetime=_convert_epoch_time_to_datetime(float(raw_pkt.time)),
            ip=IP(
                src=_parse_and_validate_ip(src_ip),
                dst=_parse_and_validate_ip(dst_ip),
            ),
            port=Port(
                src=_parse_and_validate_port(src_port),
                dst=_parse_and_validate_port(dst_port),
            ),
            length=_parse_and_validate_length(len(raw_pkt)),
        )


type PacketCallback = Callable[[Packet], None]


@dataclass(frozen=True, kw_only=True, slots=True)
class CaptureConfig:
    """Configuration for packet capture using scapy.

    Attributes:
        interface: The selected network interface to capture packets from.
        callback: A callback function to process captured packets.
        broadcast_support: Whether the interface supports the `broadcast` capture filter.
        multicast_support: Whether the interface supports the `multicast` capture filter.
        capture_filter: An optional BPF capture filter string.
        display_filter_fn: An optional Python callable applied to each scapy packet before
            invoking `callback`. Return `True` to forward the packet, `False` to drop it.
        on_capture_lost: An optional callback invoked when the sniffer exits unexpectedly.
    """

    interface: SelectedInterfaceRow
    callback: PacketCallback
    broadcast_support: bool
    multicast_support: bool
    capture_filter: str | None = None
    display_filter_fn: Callable[[ScapyPacket], bool] | None = None
    on_capture_lost: Callable[[], None] | None = None


@dataclass(kw_only=True, slots=True)
class _CaptureState:
    """Internal state for managing the packet capture.

    Attributes:
        control_lock: A lock to synchronize access to the capture state.
        running_event: Set while capture is active; cleared on stop.
        restart_requested: Set to request an async restart of the sniffer.
        capture_thread: The background thread running the capture loop.
        sniffer: The active scapy `AsyncSniffer` instance.
    """

    control_lock: threading.Lock = field(default_factory=threading.Lock)
    running_event: threading.Event = field(default_factory=threading.Event)
    restart_requested: threading.Event = field(default_factory=threading.Event)
    capture_thread: threading.Thread | None = None
    sniffer: object | None = None  # AsyncSniffer; typed as object to avoid top-level scapy import


class PacketCapture:
    """Manage a background scapy sniffer and emit parsed packets via callback."""

    def __init__(self, config: CaptureConfig, /) -> None:
        """Initialize the `PacketCapture` class.

        Args:
            config: Configuration for the packet capture.
        """
        self.config = config
        self._state = _CaptureState()

    def start(self) -> None:
        """Start packet capture by launching a new scapy `AsyncSniffer`."""
        with self._state.control_lock:
            if self._state.running_event.is_set():
                raise CaptureAlreadyRunningError

            self._state.running_event.set()
            self._start_thread()

    def stop(self) -> None:
        """Stop packet capture and join the underlying sniffer thread."""
        with self._state.control_lock:
            if not self._state.running_event.is_set():
                raise CaptureNotRunningError

            self._state.running_event.clear()

        self._terminate_sniffer()

    def request_restart(self) -> None:
        """Request an async restart of the packet capture.

        Safe to call from within the packet callback.
        """
        self._state.restart_requested.set()

    def is_running(self) -> bool:
        """Return whether packet capture is currently active."""
        return self._state.running_event.is_set()

    def _terminate_sniffer(self) -> None:
        """Stop the scapy sniffer if one is active."""
        from scapy.sendrecv import AsyncSniffer  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

        sniffer = self._state.sniffer
        if sniffer is None:
            return

        if not isinstance(sniffer, AsyncSniffer):
            raise CaptureNoSnifferError

        if sniffer.running:
            sniffer.stop(join=True)

        with self._state.control_lock:
            if self._state.sniffer is sniffer:
                self._state.sniffer = None

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
        """Main capture loop — restarts the sniffer after each restart request."""
        while self._state.running_event.is_set():
            self._state.restart_requested.clear()

            try:
                self._capture_and_process()
            except CaptureExitError as exc:
                logger.warning('Packet capture stopped unexpectedly: %s', exc)
                with self._state.control_lock:
                    self._state.running_event.clear()
                if self.config.on_capture_lost is not None:
                    self.config.on_capture_lost()
                    break
                raise

        self._state.capture_thread = None

    def _capture_and_process(self) -> None:
        """Run one sniffer session until stopped, restarted, or crashed."""
        from scapy.layers.inet import IP as ScapyIP  # noqa: N811 PLC0415  # pylint: disable=import-outside-toplevel
        from scapy.layers.inet import UDP as ScapyUDP  # noqa: N811 PLC0415  # pylint: disable=import-outside-toplevel
        from scapy.sendrecv import AsyncSniffer  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

        device_name = self.config.interface.device_name
        if not device_name:
            msg = f'Interface "{self.config.interface.name}" has no device name; cannot open pcap handle'
            raise CaptureError(msg)

        def prn(raw_pkt: ScapyPacket) -> None:
            # NPcap on Windows applies BPF in userspace for some adapter types
            # (loopback, VPN/TAP, certain Wi-Fi drivers).  Raw frames that
            # scapy cannot parse as IP/UDP arrive here before the filter rejects
            # them.  Bail out cheaply rather than paying exception overhead.
            if not raw_pkt.haslayer(ScapyIP) or not raw_pkt.haslayer(ScapyUDP):
                return

            try:
                packet = Packet.from_scapy(raw_pkt)
            except MissingRequiredPacketFieldError:
                return
            except MalformedPacketError as exc:
                _log_malformed_packet_skip(str(exc), raw_pkt=raw_pkt)
                return

            if self.config.display_filter_fn is not None and not self.config.display_filter_fn(raw_pkt):
                return

            self.config.callback(packet)

        sniffer = AsyncSniffer(
            iface=device_name,
            filter=self.config.capture_filter or '',
            prn=prn,
            store=False,
        )
        sniffer.start()

        with self._state.control_lock:
            self._state.sniffer = sniffer

        # Scapy's start() returns immediately after spawning the sniffer thread;
        # sniffer.running is set to True at the very beginning of _run(), but the
        # thread may not have been scheduled yet.  Without this wait, the monitoring
        # loop below can observe running=False on its first iteration and incorrectly
        # conclude the sniffer died unexpectedly.
        _startup_deadline = time.monotonic() + 10.0
        while not sniffer.running:
            if sniffer.thread is not None and not sniffer.thread.is_alive():
                # Thread exited before ever becoming active.  This happens when an
                # exception is raised during pcap/socket setup (code that runs before
                # the try-block in scapy's _run(), so self.running = False is never
                # reached and the exception is silently stored in sniffer.exception).
                raise CaptureExitError(sniffer.exception)
            if time.monotonic() > _startup_deadline:
                raise CaptureExitError(None)
            time.sleep(0.05)

        died_unexpectedly = False
        try:
            while self._state.running_event.is_set() and not self._state.restart_requested.is_set():
                if not sniffer.running:
                    died_unexpectedly = True
                    break
                if sniffer.thread is not None and not sniffer.thread.is_alive():
                    # Thread died without clearing sniffer.running.  Scapy sets
                    # self.running = False only after the main sniffing loop exits
                    # cleanly; an unhandled exception before that point leaves
                    # running=True while the thread is dead.  Detect that here.
                    died_unexpectedly = True
                    break
                time.sleep(0.05)
        finally:
            if sniffer.running:
                sniffer.stop(join=True)
            with self._state.control_lock:
                if self._state.sniffer is sniffer:
                    self._state.sniffer = None

        logger.debug(
            'Scapy sniffer stopped. died_unexpectedly=%r, exception=%r',
            died_unexpectedly,
            sniffer.exception,
        )

        with self._state.control_lock:
            if (
                died_unexpectedly
                and self._state.running_event.is_set()
                and not self._state.restart_requested.is_set()
            ):
                raise CaptureExitError(sniffer.exception)


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

    def start(self) -> None:
        """Start the active capture."""
        self.get().start()

    def stop(self) -> None:
        """Stop the active capture."""
        self.get().stop()

    def request_restart(self) -> None:
        """Request a restart of the active capture."""
        self.get().request_restart()
