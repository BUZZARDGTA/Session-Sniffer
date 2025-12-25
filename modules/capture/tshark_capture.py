"""Module for packet capture using TShark, including packet processing and handling of TShark crashes."""
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NamedTuple, Self

from modules.capture.exceptions import (
    InvalidIPv4AddressFormatError,
    InvalidIPv4AddressMultipleError,
    InvalidLengthNumericError,
    InvalidPortMultipleError,
    InvalidPortNumberError,
    InvalidPortNumericError,
    MalformedPacketError,
    MissingPortError,
    MissingRequiredPacketFieldError,
    TSharkAlreadyRunningError,
    TSharkCrashExceptionError,
    TSharkNoProcessError,
    TSharkNotRunningError,
    TSharkProcessInitializationError,
    TSharkThreadAlreadyRunningError,
)
from modules.constants.external import LOCAL_TZ
from modules.constants.standalone import MAX_PORT, MIN_PORT
from modules.logging_setup import get_logger
from modules.networking.utils import is_ipv4_address

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from modules.capture.interface_selection import InterfaceSelectionData

_EXPECTED_TSHARK_PACKET_FIELD_COUNT = 6
logger = get_logger(__name__)


def _log_malformed_packet_skip(
    reason: str,
    /,
    *,
    raw_line: str,
) -> None:
    """Log a malformed packet including reason and full debug info."""
    logger.warning(
        '%s (Packet skipped). raw_line=%r',
        reason,
        raw_line,
    )


def _parse_and_validate_port(port_str: str, /) -> int:
    if ',' in port_str:
        raise InvalidPortMultipleError(port_str)

    if not port_str.isascii() or not port_str.isdecimal():
        raise InvalidPortNumericError(port_str)
    port = int(port_str)
    if not MIN_PORT <= port <= MAX_PORT:
        raise InvalidPortNumberError(port)
    return port


def _parse_and_validate_ip(ip: str, /) -> str:
    if ',' in ip:
        raise InvalidIPv4AddressMultipleError(ip)

    if not is_ipv4_address(ip):
        raise InvalidIPv4AddressFormatError(ip)
    return ip


def _parse_and_validate_length(length_str: str, /) -> int:
    if not length_str.isascii() or not length_str.isdecimal():
        raise InvalidLengthNumericError(length_str)
    return int(length_str)


def _convert_epoch_time_to_datetime(time_epoch: float, /) -> datetime:
    dt_utc = datetime.fromtimestamp(time_epoch, tz=UTC)
    return dt_utc.astimezone(LOCAL_TZ)


def _process_tshark_stdout(raw_line: str, /) -> PacketFields | None:
    """Process a line of TShark output and return a PacketFields object.

    Args:
        raw_line (str): A line of TShark output.

    Returns:
        (PacketFields | None): A named tuple containing the packet fields., or `None` if the packet is invalid.

    Raises:
        MalformedPacketError: If IPs or ports are invalid or the number of fields in the line is unexpected.
    """
    # Split the line into fields and limit the split based on the expected number of fields
    fields = tuple(field.strip() for field in raw_line.split('|', _EXPECTED_TSHARK_PACKET_FIELD_COUNT))
    if len(fields) != _EXPECTED_TSHARK_PACKET_FIELD_COUNT:
        _log_malformed_packet_skip(
            f'Malformed packet: unexpected field count (expected {_EXPECTED_TSHARK_PACKET_FIELD_COUNT}, got {len(fields)})',
            raw_line=raw_line,
        )
        return None

    return PacketFields(*fields)


class PacketFields(NamedTuple):
    time_epoch: str
    length: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str


class IP(NamedTuple):
    src: str
    dst: str


class Port(NamedTuple):
    src: int
    dst: int


class Packet(NamedTuple):
    datetime: datetime
    ip: IP
    port: Port
    length: int

    @classmethod
    def from_fields(cls, fields: PacketFields) -> Self:
        """Create a Packet object from TShark output fields.

        Args:
            fields (PacketFields): A named tuple containing the packet fields.

        Returns:
            Packet: A Packet object containing the parsed fields.

        Raises:
            InvalidIPv4AddressError: If the source or destination IP addresses are not valid IPv4 addresses.
            InvalidPortFormatError: If the source or destination ports are not digits.
            InvalidPortNumberError: If the source or destination ports are not valid.
        """
        if not all((fields.time_epoch, fields.length, fields.src_ip, fields.dst_ip)):
            raise MissingRequiredPacketFieldError
        if not all((fields.src_port, fields.dst_port)):
            raise MissingPortError

        return cls(
            datetime=_convert_epoch_time_to_datetime(float(fields.time_epoch)),
            ip=IP(
                src=_parse_and_validate_ip(fields.src_ip),
                dst=_parse_and_validate_ip(fields.dst_ip),
            ),
            port=Port(
                src=_parse_and_validate_port(fields.src_port),
                dst=_parse_and_validate_port(fields.dst_port),
            ),
            length=_parse_and_validate_length(fields.length),
        )


type PacketCallback = Callable[[Packet], None]
type PacketGenerator = Generator[Packet]


@dataclass(frozen=True, kw_only=True, slots=True)
class CaptureConfig:
    """Configuration for packet capture using TShark.

    Attributes:
        interface (InterfaceSelectionData): The selected network interface to capture packets from.
        tshark_path (Path): The path to the TShark executable.
        callback (PacketCallback): A callback function to process captured packets.
        capture_filter (str | None): An optional capture filter string for TShark.
        display_filter (str | None): An optional display filter string for TShark.
    """
    interface: InterfaceSelectionData
    tshark_path: Path
    callback: PacketCallback
    capture_filter: str | None = None
    display_filter: str | None = None

    def build_tshark_cmd(self) -> tuple[str, ...]:
        return (
            str(self.tshark_path),
            # Capture interface
            '-i', self.interface.name,
            *(('-f', self.capture_filter) if self.capture_filter else ()),
            # Processing
            *(('-Y', self.display_filter) if self.display_filter else ()),
            '-n',
            # Output
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-E', 'separator=|',
            '-l',
            '-Q',
            # Diagnostic output
            '--log-level', 'critical',
        )


@dataclass(kw_only=True, slots=True)
class _CaptureState:
    """Internal state for managing the packet capture process.

    Attributes:
        control_lock (threading.Lock): A lock to synchronize access to the capture state.
        running_event (threading.Event): An event indicating whether the capture is running.
        restart_requested (threading.Event): An event indicating whether a restart has been requested.
        capture_thread (threading.Thread | None): The thread running the packet capture.
        tshark_process (subprocess.Popen[str] | None): The TShark process used for packet capture.
    """
    control_lock: threading.Lock = field(default_factory=threading.Lock)
    running_event: threading.Event = field(default_factory=threading.Event)
    restart_requested: threading.Event = field(default_factory=threading.Event)
    capture_thread: threading.Thread | None = None
    tshark_process: subprocess.Popen[str] | None = None


class PacketCapture:
    def __init__(self, config: CaptureConfig, /) -> None:
        """Initialize the PacketCapture class.

        Args:
            config (CaptureConfig): Configuration for the packet capture.

        Raises:
            TSharkProcessInitializationError: If the TShark process could not be initialized.
        """
        self.config = config
        self._state = _CaptureState()

    def start(self) -> None:
        """Start the packet capture by launching a new TShark process."""
        with self._state.control_lock:
            if self._state.running_event.is_set():
                raise TSharkAlreadyRunningError

            self._state.running_event.set()
            self._start_thread()

    def stop(self) -> None:
        """Stop the packet capture by terminating the TShark process."""
        with self._state.control_lock:
            if not self._state.running_event.is_set():
                raise TSharkNotRunningError

            self._state.running_event.clear()
            self._terminate_process()

    def request_restart(self) -> None:
        """Request an async restart of the packet capture.

        This method is safe to call from within the packet callback.
        It signals the capture thread to restart itself at the next opportunity.
        """
        self._state.restart_requested.set()

    def is_running(self) -> bool:
        """Check if the packet capture is currently running."""
        return self._state.running_event.is_set()

    def _terminate_process(self) -> None:
        """Terminate the TShark process and wait for it to exit."""
        if not self._state.tshark_process:
            raise TSharkNoProcessError

        self._state.tshark_process.terminate()
        self._state.tshark_process.wait()
        self._state.tshark_process = None

    def _start_thread(self) -> None:
        """Create and start a new capture thread."""
        if self._state.capture_thread and self._state.capture_thread.is_alive():
            raise TSharkThreadAlreadyRunningError

        self._state.capture_thread = threading.Thread(
            target=self._run_capture_loop,
            name='TSharkCapture',
            daemon=True,
        )
        self._state.capture_thread.start()

    def _run_capture_loop(self) -> None:
        """Main capture loop that processes captured packets."""
        while self._state.running_event.is_set():
            self._state.restart_requested.clear()  # Clear any previous restart request before starting new capture iteration

            for packet in self._capture_packets():
                self.config.callback(packet)

                if self._state.restart_requested.is_set():  # Check if restart was requested (e.g., due to packet overflow)
                    logger.debug('Capture loop exiting due to restart request')
                    break

        self._state.capture_thread = None

    def _capture_packets(self) -> PacketGenerator:
        """Capture packets using TShark and process the output.

        Yields:
            Packet: A packet object containing the captured packet data.
        """
        tshark_cmd = self.config.build_tshark_cmd()

        with subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ) as process:
            with self._state.control_lock:
                self._state.tshark_process = process

            # stdout and stderr are always set when PIPE is used
            if process.stdout is None or process.stderr is None:
                raise TSharkProcessInitializationError

            # Iterate over stdout line by line as it is being produced
            for line in process.stdout:
                raw_line = line.rstrip()

                packet_fields = _process_tshark_stdout(raw_line)
                if packet_fields is None:
                    continue

                try:
                    yield Packet.from_fields(packet_fields)
                except MalformedPacketError as exc:
                    _log_malformed_packet_skip(
                        str(exc),
                        raw_line=raw_line,
                    )

            # After stdout is done, check if there were any errors in stderr
            stderr_output = process.stderr.read()
            if isinstance(process.returncode, int) and process.returncode:
                raise TSharkCrashExceptionError(process.returncode, stderr_output)
