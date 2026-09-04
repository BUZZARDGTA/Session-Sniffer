"""Native network diagnostics engine for ICMP, TCP port, and web pings."""

import ctypes
import ctypes.wintypes
import enum
import socket
import time
from dataclasses import dataclass, field
from typing import Final, Self, cast

from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.endpoint_ping_manager import PingResult, fetch_and_parse_ping
from session_sniffer.networking.http_session import session
from session_sniffer.settings import Settings

logger = get_logger(__name__)

# --- Windows ICMP Echo API Definitions ---
_IP_STATUS_DESCRIPTIONS: Final[dict[int, str]] = {
    0: 'Success',
    11001: 'Buffer too small',
    11002: 'Destination network unreachable',
    11003: 'Destination host unreachable',
    11004: 'Destination protocol unreachable',
    11005: 'Destination port unreachable',
    11006: 'No resources',
    11007: 'Bad option',
    11008: 'Hardware error',
    11009: 'Packet too big',
    11010: 'Request timed out',
    11011: 'Bad request',
    11012: 'Bad route',
    11013: 'TTL expired in transit',
    11014: 'TTL expired during reassembly',
    11015: 'Parameter problem',
    11016: 'Source quench',
    11017: 'Option too big',
    11018: 'Bad destination',
    11050: 'General failure',
}
_MIN_SAMPLES_FOR_MDEV: Final[int] = 2


class _IPOptionInformation(ctypes.Structure):
    _fields_ = [
        ('Ttl', ctypes.c_ubyte),
        ('Tos', ctypes.c_ubyte),
        ('Flags', ctypes.c_ubyte),
        ('OptionsSize', ctypes.c_ubyte),
        ('OptionsData', ctypes.c_void_p),
    ]


class _IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ('Address', ctypes.c_ulong),
        ('Status', ctypes.c_ulong),
        ('RoundTripTime', ctypes.c_ulong),
        ('DataSize', ctypes.c_ushort),
        ('Reserved', ctypes.c_ushort),
        ('Data', ctypes.c_void_p),
        ('Options', _IPOptionInformation),
    ]


class PingMode(enum.StrEnum):
    """Supported ping diagnostic modes."""

    ICMP = 'ICMP'
    TCP = 'TCP'
    WEB = 'Web (Check-Host)'


@dataclass(slots=True)
class PingProbeResult:
    """Represents the outcome of a single ping probe attempt."""

    sequence: int
    target_host: str
    target_ip: str
    port: int | None
    is_successful: bool
    round_trip_time_ms: float | None
    time_to_live: int | None
    status_message: str
    timestamp: float = field(default_factory=time.time)


@dataclass(slots=True)
class PingStatistics:
    """Aggregated statistics for a series of ping probes."""

    total_sent: int = 0
    total_received: int = 0
    total_failed: int = 0
    minimum_rtt_ms: float | None = None
    average_rtt_ms: float | None = None
    maximum_rtt_ms: float | None = None
    jitter_ms: float | None = None
    _rtt_history: list[float] = field(default_factory=list[float])

    @property
    def packet_loss_percentage(self) -> float:
        """Calculate packet loss percentage."""
        if self.total_sent == 0:
            return 0.0
        return (self.total_failed / self.total_sent) * 100.0

    def update(self, probe_result: PingProbeResult) -> None:
        """Update statistics with a new probe result."""
        self.total_sent += 1
        if probe_result.is_successful and probe_result.round_trip_time_ms is not None:
            self.total_received += 1
            round_trip_time = probe_result.round_trip_time_ms

            if self.minimum_rtt_ms is None or round_trip_time < self.minimum_rtt_ms:
                self.minimum_rtt_ms = round_trip_time
            if self.maximum_rtt_ms is None or round_trip_time > self.maximum_rtt_ms:
                self.maximum_rtt_ms = round_trip_time

            if self._rtt_history:
                previous_rtt = self._rtt_history[-1]
                instant_jitter = abs(round_trip_time - previous_rtt)
                if self.jitter_ms is None:
                    self.jitter_ms = instant_jitter
                else:
                    self.jitter_ms = (self.jitter_ms * 0.875) + (instant_jitter * 0.125)

            self._rtt_history.append(round_trip_time)
            self.average_rtt_ms = sum(self._rtt_history) / len(self._rtt_history)
        else:
            self.total_failed += 1


class IcmpEchoEngine:
    """Native Windows ICMP echo pinger using Win32 IcmpSendEcho."""

    def __init__(self) -> None:
        """Initialize the Win32 ICMP handle."""
        self._iphlpapi = ctypes.windll.iphlpapi
        self._iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
        self._iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        self._iphlpapi.IcmpSendEcho.restype = ctypes.wintypes.DWORD
        self._iphlpapi.IcmpSendEcho.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_char_p,
            ctypes.c_ushort,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
        ]
        self._handle: int | None = self._iphlpapi.IcmpCreateFile()
        if not self._handle or self._handle == -1:
            self._handle = None
            logger.error('Failed to create Win32 ICMP handle')

    def is_available(self) -> bool:
        """Return True if the native ICMP handle is valid."""
        return self._handle is not None

    def __enter__(self) -> Self:
        """Support context manager entry."""
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Support context manager exit by closing the native ICMP handle."""
        self.close()

    def close(self) -> None:
        """Close the native ICMP handle."""
        if self._handle is not None:
            self._iphlpapi.IcmpCloseHandle(self._handle)
            self._handle = None

    def ping(
        self,
        target_ip: str,
        *,
        timeout_seconds: float = 2.0,
        sequence: int = 1,
        payload_data: bytes = b'SessionSnifferEcho',
    ) -> PingProbeResult:
        """Send a single ICMP echo probe to target_ip."""
        if self._handle is None:
            return PingProbeResult(
                sequence=sequence,
                target_host=target_ip,
                target_ip=target_ip,
                port=None,
                is_successful=False,
                round_trip_time_ms=None,
                time_to_live=None,
                status_message='Win32 ICMP handle unavailable',
            )

        try:
            destination_address = int.from_bytes(socket.inet_aton(target_ip), 'little')
        except OSError:
            try:
                resolved_ip = socket.gethostbyname(target_ip)
                destination_address = int.from_bytes(socket.inet_aton(resolved_ip), 'little')
            except OSError as e:
                return PingProbeResult(
                    sequence=sequence,
                    target_host=target_ip,
                    target_ip=target_ip,
                    port=None,
                    is_successful=False,
                    round_trip_time_ms=None,
                    time_to_live=None,
                    status_message=f'Invalid host or IP address: {e}',
                )

        reply_buffer_size = ctypes.sizeof(_IcmpEchoReply) + len(payload_data) + 16
        reply_buffer = ctypes.create_string_buffer(reply_buffer_size)
        timeout_milliseconds = max(100, int(timeout_seconds * 1000))

        return_value = self._iphlpapi.IcmpSendEcho(
            self._handle,
            destination_address,
            payload_data,
            len(payload_data),
            None,
            reply_buffer,
            reply_buffer_size,
            timeout_milliseconds,
        )

        reply = _IcmpEchoReply.from_buffer_copy(reply_buffer)
        status_code = int(reply.Status)
        status_description = _IP_STATUS_DESCRIPTIONS.get(status_code, f'Error {status_code}')

        if return_value > 0 and status_code == 0:
            return PingProbeResult(
                sequence=sequence,
                target_host=target_ip,
                target_ip=target_ip,
                port=None,
                is_successful=True,
                round_trip_time_ms=float(reply.RoundTripTime),
                time_to_live=int(reply.Options.Ttl),
                status_message=status_description,
            )

        return PingProbeResult(
            sequence=sequence,
            target_host=target_ip,
            target_ip=target_ip,
            port=None,
            is_successful=False,
            round_trip_time_ms=None,
            time_to_live=None,
            status_message=status_description,
        )


class TcpPortProbeEngine:
    """TCP port connectivity probe using standard Python sockets."""

    @staticmethod
    def probe(
        target_ip: str,
        port: int,
        *,
        timeout_seconds: float = 2.0,
        sequence: int = 1,
    ) -> PingProbeResult:
        """Attempt a single TCP connection to target_ip:port."""
        start_time = time.perf_counter()
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(timeout_seconds)

        try:
            tcp_socket.connect((target_ip, port))
            round_trip_time_ms = (time.perf_counter() - start_time) * 1000.0
            return PingProbeResult(
                sequence=sequence,
                target_host=target_ip,
                target_ip=target_ip,
                port=port,
                is_successful=True,
                round_trip_time_ms=round_trip_time_ms,
                time_to_live=None,
                status_message='Connected',
            )
        except TimeoutError:
            return PingProbeResult(
                sequence=sequence,
                target_host=target_ip,
                target_ip=target_ip,
                port=port,
                is_successful=False,
                round_trip_time_ms=None,
                time_to_live=None,
                status_message='Connection timed out',
            )
        except ConnectionRefusedError:
            return PingProbeResult(
                sequence=sequence,
                target_host=target_ip,
                target_ip=target_ip,
                port=port,
                is_successful=False,
                round_trip_time_ms=None,
                time_to_live=None,
                status_message='Connection refused (Port closed)',
            )
        except OSError as e:
            return PingProbeResult(
                sequence=sequence,
                target_host=target_ip,
                target_ip=target_ip,
                port=port,
                is_successful=False,
                round_trip_time_ms=None,
                time_to_live=None,
                status_message=str(e),
            )
        finally:
            tcp_socket.close()


class CheckHostPingEngine:
    """Remote multi-vantage ping probe using the Check-Host.net API."""

    CHECK_HOST_API: Final = 'https://check-host.net'
    MIN_NODE_INFO_LENGTH_FOR_CITY: Final = 2
    MIN_HOP_FIELDS: Final = 2

    @classmethod
    def probe(cls, target_ip: str, *, sequence: int = 1) -> list[PingProbeResult]:
        """Request and retrieve ping results from Check-Host.net nodes."""
        results: list[PingProbeResult] = []
        try:
            request_response = session.get(
                f'{cls.CHECK_HOST_API}/check-ping?host={target_ip}',
                headers={'Accept': 'application/json'},
                timeout=10,
            )
            request_response.raise_for_status()
            request_data = cast('dict[str, object]', request_response.json())
            request_id = request_data.get('request_id')
            nodes = cast('dict[str, list[str]] | None', request_data.get('nodes'))

            if not isinstance(request_id, str) or not nodes:
                results.append(
                    PingProbeResult(
                        sequence=sequence,
                        target_host=target_ip,
                        target_ip=target_ip,
                        port=None,
                        is_successful=False,
                        round_trip_time_ms=None,
                        time_to_live=None,
                        status_message='Failed to initiate check-ping request',
                    ),
                )
                return results

            # Poll for results
            time.sleep(4.0)
            result_response = session.get(
                f'{cls.CHECK_HOST_API}/check-result/{request_id}',
                headers={'Accept': 'application/json'},
                timeout=10,
            )
            result_response.raise_for_status()
            result_data = cast('dict[str, object]', result_response.json())

            for node_name, node_info in nodes.items():
                country = node_info[1] if len(node_info) > 1 else 'Unknown'
                city = node_info[2] if len(node_info) > cls.MIN_NODE_INFO_LENGTH_FOR_CITY else ''
                node_label = f'{country} ({city})' if city else country

                node_result = result_data.get(node_name)
                if isinstance(node_result, list) and node_result and isinstance(node_result[0], list):
                    sample_hops = cast('list[list[object]]', node_result[0])
                    successful_rtts = [
                        float(hop[1]) * 1000.0
                        for hop in sample_hops
                        if len(hop) >= cls.MIN_HOP_FIELDS and hop[0] == 'OK' and isinstance(hop[1], (float, int))
                    ]

                    if successful_rtts:
                        average_rtt = sum(successful_rtts) / len(successful_rtts)
                        results.append(
                            PingProbeResult(
                                sequence=sequence,
                                target_host=node_label,
                                target_ip=target_ip,
                                port=None,
                                is_successful=True,
                                round_trip_time_ms=average_rtt,
                                time_to_live=None,
                                status_message=f'{len(successful_rtts)}/4 packets received',
                            ),
                        )
                    else:
                        results.append(
                            PingProbeResult(
                                sequence=sequence,
                                target_host=node_label,
                                target_ip=target_ip,
                                port=None,
                                is_successful=False,
                                round_trip_time_ms=None,
                                time_to_live=None,
                                status_message='Packet timeout',
                            ),
                        )
                else:
                    results.append(
                        PingProbeResult(
                            sequence=sequence,
                            target_host=node_label,
                            target_ip=target_ip,
                            port=None,
                            is_successful=False,
                            round_trip_time_ms=None,
                            time_to_live=None,
                            status_message='No response from node',
                        ),
                    )

        except (OSError, ValueError) as e:
            results.append(
                PingProbeResult(
                    sequence=sequence,
                    target_host=target_ip,
                    target_ip=target_ip,
                    port=None,
                    is_successful=False,
                    round_trip_time_ms=None,
                    time_to_live=None,
                    status_message=f'Web ping error: {e}',
                ),
            )

        return results


def ping_locally(
    target_ip: str,
    *,
    count: int = 3,
    timeout_seconds: float = 1.0,
    interval_seconds: float = 0.05,
) -> PingResult:
    """Send local ICMP echo requests to target_ip and return a structured PingResult."""
    ping_times: list[float] = []

    with IcmpEchoEngine() as engine:
        for sequence_number in range(1, count + 1):
            probe_result = engine.ping(target_ip, timeout_seconds=timeout_seconds, sequence=sequence_number)
            if probe_result.is_successful and probe_result.round_trip_time_ms is not None:
                ping_times.append(probe_result.round_trip_time_ms)
            if sequence_number < count and interval_seconds > 0:
                time.sleep(interval_seconds)

    packets_transmitted = count
    packets_received = len(ping_times)
    packets_failed = packets_transmitted - packets_received
    packet_loss = (packets_failed / packets_transmitted) * 100.0 if packets_transmitted > 0 else 0.0

    rtt_min = min(ping_times) if ping_times else None
    rtt_avg = (sum(ping_times) / packets_received) if packets_received > 0 else None
    rtt_max = max(ping_times) if ping_times else None

    rtt_mdev: float | None = None
    if len(ping_times) >= _MIN_SAMPLES_FOR_MDEV and rtt_avg is not None:
        variance = sum((time_ms - rtt_avg) ** 2 for time_ms in ping_times) / len(ping_times)
        rtt_mdev = variance ** 0.5

    return PingResult(
        ping_times=ping_times,
        packets_transmitted=packets_transmitted,
        packets_received=packets_received,
        packet_duplicates=0,
        packet_loss=packet_loss,
        packet_errors=packets_failed,
        rtt_min=rtt_min,
        rtt_avg=rtt_avg,
        rtt_max=rtt_max,
        rtt_mdev=rtt_mdev,
    )


def ping_player(target_ip: str) -> PingResult:
    """Perform player ping diagnostics using local ICMP or external endpoints depending on Settings."""
    if Settings.pinger_local:
        return ping_locally(target_ip)
    return fetch_and_parse_ping(target_ip)
