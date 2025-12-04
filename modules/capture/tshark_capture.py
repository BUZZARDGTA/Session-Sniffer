"""Module for packet capture using TShark, including packet processing and handling of TShark crashes."""
import subprocess
import threading
from contextlib import suppress
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NamedTuple, Self

from modules.capture.exceptions import (
    InvalidIPv4AddressFormatError,
    InvalidIPv4AddressMultipleError,
    InvalidPortMultipleError,
    InvalidPortNumberError,
    InvalidPortNumericError,
    TSharkCrashExceptionError,
)
from modules.constants.external import LOCAL_TZ
from modules.constants.standalone import MAX_PORT, MIN_PORT
from modules.networking.utils import is_ipv4_address

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from modules.capture.interface_selection import InterfaceSelectionData

_EXPECTED_TSHARK_PACKET_FIELD_COUNT = 5


def _parse_and_validate_port(port_str: str, /) -> int:
    if ',' in port_str:
        print(f'[Tshark] Invalid port (multiple): {port_str}. Skipped.')
        raise InvalidPortMultipleError(port_str)

    if not port_str.isascii() or not port_str.isdecimal():
        print(f'[Tshark] Invalid port (not numeric): {port_str}. Skipped.')
        raise InvalidPortNumericError(port_str)
    port = int(port_str)
    if not MIN_PORT <= port <= MAX_PORT:
        print(f'[Tshark] Invalid port (out of range): {port}. Skipped.')
        raise InvalidPortNumberError(port)
    return port


def _parse_and_validate_ip(ip: str, /) -> str:
    if ',' in ip:
        print(f'[Tshark] Invalid IP (multiple): {ip}. Skipped.')
        raise InvalidIPv4AddressMultipleError(ip)

    if not is_ipv4_address(ip):
        print(f'[Tshark] Invalid IP format: {ip}. Skipped.')
        raise InvalidIPv4AddressFormatError(ip)
    return ip


def _convert_epoch_time_to_datetime(time_epoch: float, /) -> datetime:
    dt_utc = datetime.fromtimestamp(time_epoch, tz=UTC)
    return dt_utc.astimezone(LOCAL_TZ)


def _process_tshark_stdout(line: str, /) -> PacketFields | None:
    """Process a line of TShark output and return a PacketFields object.

    Args:
        line (str): A line of TShark output.

    Returns:
        (PacketFields | None): A named tuple containing the packet fields., or `None` if the packet is invalid.

    Raises:
        TSharkProcessingError: If IPs or ports are invalid or the number of fields in the line is unexpected.
    """
    # Split the line into fields and limit the split based on the expected number of fields
    fields = tuple(field.strip() for field in line.split('|', _EXPECTED_TSHARK_PACKET_FIELD_COUNT))
    if len(fields) != _EXPECTED_TSHARK_PACKET_FIELD_COUNT:
        print(f'[TShark] Unexpected number of fields in TShark output. Expected "{_EXPECTED_TSHARK_PACKET_FIELD_COUNT}", got "{len(fields)}": "{fields}"')
        return None

    # Ensure the first three fields are not empty
    if any(not field for field in fields[:3]):
        print(f'[TShark] One of the required first three fields is empty. Fields: {fields}')
        return None

    # TODO(BUZZARDGTA): It would be ideal to retain these packets instead of discarding them.
    # Displaying "None" in the Port column should be supported at some point in the future development.
    # Skip processing if source or destination port is missing (last two fields)
    if not fields[-2] or not fields[-1]:
        print(f'[TShark] Skipping packet with missing port(s): {fields}')
        return None

    return PacketFields(*fields)


class PacketFields(NamedTuple):
    time_epoch: str
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
        )


class PacketCapture:
    def __init__(
        self,
        *,
        interface: InterfaceSelectionData,
        tshark_path: Path,
        capture_filter: str | None = None,
        display_filter: str | None = None,
        callback: Callable[[Packet], None],
    ) -> None:
        """Initialize the PacketCapture class.

        Args:
            interface (InterfaceSelectionData): The selected network interface to capture packets from.
            tshark_path (Path): The path to the TShark executable.
            capture_filter (str | None): Optional capture filter for TShark.
            display_filter (str | None): Optional display filter for TShark.
            callback (Callable[[Packet], None]): A callback function to process each captured packet.
        """
        self.interface = interface
        self.tshark_path = tshark_path
        self.capture_filter = capture_filter
        self.display_filter = display_filter
        self._callback: Callable[[Packet], None] = callback

        self._control_lock = threading.Lock()
        self._running_event = threading.Event()
        self._tshark_cmd = (
            str(tshark_path),
            '-l', '-n', '-Q',
            '--log-level', 'critical',
            '-B', '1',
            '-i', interface.name,
            *(('-f', capture_filter) if capture_filter else ()),
            *(('-Y', display_filter) if display_filter else ()),
            '-T', 'fields',
            '-E', 'separator=|',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
        )
        self._capture_thread: threading.Thread | None = None
        self._tshark_process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        """Start the packet capture by launching a new TShark process."""
        with self._control_lock:
            if not self._running_event.is_set():
                self._running_event.set()

                self._capture_thread = threading.Thread(
                    target=self._run_capture_loop,
                    name='TSharkCapture',
                    daemon=True,
                )
                self._capture_thread.start()

    def stop(self) -> None:
        """Stop the packet capture by terminating the TShark process."""
        with self._control_lock:
            if self._running_event.is_set():
                self._running_event.clear()

                if self._tshark_process:
                    self._tshark_process.terminate()
                    self._tshark_process.wait()
                    self._tshark_process = None

    def restart(self) -> None:
        """Restart the packet capture by stopping and starting it again."""
        self.stop()
        self.start()

    def is_stopped(self) -> bool:
        """Check if the packet capture is currently stopped."""
        return not self._running_event.is_set()

    def wait(self) -> None:
        """Block until the packet capture is stopped."""
        while self._running_event.is_set():
            self._running_event.wait(timeout=0.1)

    def _run_capture_loop(self) -> None:
        """Main capture loop that processes captured packets."""
        for packet in self._capture_packets():
            if not self._running_event.is_set():
                return

            self._callback(packet)

    def _capture_packets(self) -> Generator[Packet]:
        """Capture packets using TShark and process the output.

        Yields:
            Packet: A packet object containing the captured packet data.
        """
        with subprocess.Popen(
            self._tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
        ) as process:
            self._tshark_process = process

            if process.stdout:
                for line in process.stdout:  # Iterate over stdout line by line as it is being produced
                    if not self._running_event.is_set():
                        return

                    packet_fields = _process_tshark_stdout(line.rstrip())
                    if packet_fields is None:
                        continue

                    with suppress(
                        InvalidIPv4AddressMultipleError,
                        InvalidIPv4AddressFormatError,
                        InvalidPortMultipleError,
                        InvalidPortNumericError,
                        InvalidPortNumberError,
                    ):
                        yield Packet.from_fields(packet_fields)

            if not self._running_event.is_set():
                return

            # After stdout is done, check if there were any errors in stderr
            if process.stderr:
                stderr_output = process.stderr.read()
                if isinstance(process.returncode, int) and process.returncode:
                    raise TSharkCrashExceptionError(process.returncode, stderr_output)
