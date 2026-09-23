"""High-performance multi-threaded TCP and UDP port scanner engine."""

import enum
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

MIN_PORT: Final[int] = 1
MAX_PORT: Final[int] = 65535
DEFAULT_SCAN_TIMEOUT_SECONDS: Final[float] = 0.8
DEFAULT_SCAN_THREADS: Final[int] = 256
MAX_SCAN_THREADS: Final[int] = 1024
_MAX_BANNER_BYTES: Final[int] = 256
_MAX_BANNER_DISPLAY_LENGTH: Final[int] = 80

_COMMON_PORT_SERVICES: Final[dict[int, str]] = {
    # Standard System / Internet Services
    20: 'FTP (Data)',
    21: 'FTP (Control)',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP (Server)',
    68: 'DHCP (Client)',
    69: 'TFTP',
    80: 'HTTP',
    88: 'Kerberos / Xbox Auth',
    110: 'POP3',
    119: 'NNTP',
    123: 'NTP',
    135: 'MS RPC',
    137: 'NetBIOS (Name)',
    138: 'NetBIOS (Datagram)',
    139: 'NetBIOS (Session)',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP Trap',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'Microsoft SMB',
    465: 'SMTPS',
    500: 'IKE (IPsec VPN)',
    514: 'Syslog',
    587: 'SMTP (Submission)',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS Proxy',
    1194: 'OpenVPN',
    1200: 'Steam / Xbox',
    1433: 'MS SQL Server',
    1521: 'Oracle Database',
    1723: 'PPTP VPN',
    1883: 'MQTT',
    1935: 'RTMP / PSN',
    2049: 'NFS',
    2082: 'cPanel',
    2083: 'cPanel (SSL)',
    2375: 'Docker REST API',
    2376: 'Docker REST API (SSL)',
    3074: 'Xbox Live / PlayStation Network',
    3128: 'Squid Proxy',
    3306: 'MySQL',
    3389: 'Remote Desktop (RDP)',
    3478: 'STUN / PSN / Xbox',
    3479: 'PlayStation Network',
    3480: 'PlayStation Network',
    3544: 'Teredo (Xbox Live)',
    4380: 'Steam Client',
    4500: 'IPsec NAT-T (Xbox Live)',
    5000: 'UPnP / Synology DSM',
    5060: 'SIP (VoIP)',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    6672: 'GTA Online / RDR2 P2P',
    8000: 'HTTP Alt',
    8080: 'HTTP Proxy / Web',
    8443: 'HTTPS Alt',
    8888: 'HTTP Alt',
    9000: 'PHP-FPM / SonarQube',
    9090: 'Cockpit / Web Console',
    9100: 'Raw JetDirect Print',
    9200: 'Elasticsearch',
    27015: 'Steam Dedicated Server',
    27016: 'Steam Dedicated Server',
    27017: 'Steam Dedicated Server',
    27036: 'Steam Remote Play',
    50001: 'Discord Voice',
    50002: 'Discord Voice',
    50003: 'Discord Voice',
    50004: 'Discord Voice',
    61455: 'GTA Online PC',
    61456: 'GTA Online PC',
    61457: 'GTA Online PC',
    61458: 'GTA Online PC',
}

PORT_PRESETS: Final[dict[str, str]] = {
    'Top 20 Common': '21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080',
    'Top 100 Common': (
        '20-23, 25, 53, 67-69, 80, 88, 110, 119, 123, 135, 137-139, 143, 161-162, 389, 443, 445, '
        '465, 500, 514, 587, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 1935, 2049, 2082-2083, '
        '3074, 3128, 3306, 3389, 3478-3480, 4380, 5000, 5060, 5432, 5900, 6379, 6672, 8000, 8080, '
        '8443, 8888, 9000, 9090, 9200, 27015, 61455-61458'
    ),
    'Top 1024 (Standard)': '1-1024',
    'Gaming & Consoles': '88, 500, 1200, 1935, 3074, 3478-3480, 3544, 4380, 4500, 6672, 27000-27050, 50001-50004, 61455-61458',
    'Web & Proxies': '80, 443, 1080, 3128, 8000, 8080, 8443, 8888',
    'All Ports (1-65535)': '1-65535',
}


class PortScanProtocol(enum.StrEnum):
    """Supported port scan transport protocols."""

    TCP = 'TCP'
    UDP = 'UDP'
    BOTH = 'TCP + UDP'


class PortScanState(enum.StrEnum):
    """Status of a probed port."""

    OPEN = 'Open'
    CLOSED = 'Closed'
    FILTERED = 'Filtered'


@dataclass(slots=True)
class PortScanResult:
    """Outcome of a single port scan probe."""

    port: int
    protocol: str
    state: PortScanState
    service_name: str
    latency_ms: float | None = None
    banner: str | None = None


@dataclass(slots=True)
class PortScanConfiguration:
    """Configuration parameters for executing a port scan session."""

    target_host: str
    target_ip: str
    ports: list[int]
    protocol: PortScanProtocol = PortScanProtocol.TCP
    timeout_seconds: float = DEFAULT_SCAN_TIMEOUT_SECONDS
    threads: int = DEFAULT_SCAN_THREADS
    grab_banner: bool = True


@dataclass(slots=True)
class PortScanStatistics:
    """Aggregated progress statistics for an ongoing or completed port scan."""

    total_probes: int = 0
    completed_probes: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    start_time: float = field(default_factory=time.perf_counter)

    @property
    def progress_percentage(self) -> float:
        """Return completion percentage between 0.0 and 100.0."""
        if not self.total_probes:
            return 0.0
        return (self.completed_probes / self.total_probes) * 100.0

    @property
    def elapsed_seconds(self) -> float:
        """Return elapsed duration in seconds since scan initiation."""
        return max(0.001, time.perf_counter() - self.start_time)

    @property
    def scan_speed_ports_per_second(self) -> float:
        """Return average scan speed in ports probed per second."""
        return self.completed_probes / self.elapsed_seconds


def get_service_name(port: int) -> str:
    """Resolve standard service name for a given port number."""
    if port in _COMMON_PORT_SERVICES:
        return _COMMON_PORT_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return 'Unknown'


def parse_port_specification(port_string: str) -> list[int]:
    """Parse a flexible port range string into a sorted list of unique port numbers.

    Supports individual ports ('80'), comma-separated lists ('80, 443'), ranges ('1-1024'),
    and whitespace-separated tokens. Raises ValueError if input is empty or invalid.
    """
    clean_string = port_string.strip()
    if not clean_string:
        error_message = 'Port specification cannot be empty.'
        raise ValueError(error_message)

    ports: set[int] = set()
    tokens = re.split(r'[,;\s]+', clean_string)

    for token in tokens:
        if not token:
            continue
        if '-' in token:
            parts = token.split('-', 1)
            if not parts[0].isdigit() or not parts[1].isdigit():
                error_message = f"Invalid port range format: '{token}'"
                raise ValueError(error_message)
            start_port = int(parts[0])
            end_port = int(parts[1])
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            if start_port < MIN_PORT or end_port > MAX_PORT:
                error_message = f'Port numbers must be between {MIN_PORT} and {MAX_PORT} (got {token})'
                raise ValueError(error_message)
            ports.update(range(start_port, end_port + 1))
        else:
            if not token.isdigit():
                error_message = f"Invalid port number: '{token}'"
                raise ValueError(error_message)
            port = int(token)
            if not MIN_PORT <= port <= MAX_PORT:
                error_message = f'Port number must be between {MIN_PORT} and {MAX_PORT} (got {port})'
                raise ValueError(error_message)
            ports.add(port)

    if not ports:
        error_message = 'No valid ports found in input.'
        raise ValueError(error_message)

    return sorted(ports)


def probe_tcp_port(
    target_ip: str,
    port: int,
    *,
    timeout_seconds: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
    grab_banner: bool = True,
) -> PortScanResult:
    """Perform a TCP connect probe to target_ip:port with optional banner grab."""
    service_name = get_service_name(port)
    endpoint = (target_ip, port)
    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_socket.settimeout(timeout_seconds)
    start_time = time.perf_counter()

    try:
        probe_socket.connect(endpoint)
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        banner_text: str | None = None
        if grab_banner:
            banner_text = _attempt_tcp_banner_grab(probe_socket, port)

        return PortScanResult(
            port=port,
            protocol='TCP',
            state=PortScanState.OPEN,
            service_name=service_name,
            latency_ms=latency_ms,
            banner=banner_text,
        )
    except ConnectionRefusedError:
        return PortScanResult(
            port=port,
            protocol='TCP',
            state=PortScanState.CLOSED,
            service_name=service_name,
        )
    except TimeoutError:
        return PortScanResult(
            port=port,
            protocol='TCP',
            state=PortScanState.FILTERED,
            service_name=service_name,
        )
    except OSError:
        return PortScanResult(
            port=port,
            protocol='TCP',
            state=PortScanState.FILTERED,
            service_name=service_name,
        )
    finally:
        probe_socket.close()


def _attempt_tcp_banner_grab(connected_socket: socket.socket, port: int) -> str | None:
    """Attempt a non-intrusive banner grab on an already connected TCP socket."""
    connected_socket.settimeout(0.6)
    try:
        # Standard HTTP ports: send a minimal HTTP HEAD probe
        if port in (80, 8080, 8000, 8888, 3128):
            connected_socket.sendall(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
        # Some services (SSH, FTP, SMTP, POP3) send a banner immediately without client input
        raw_data = connected_socket.recv(_MAX_BANNER_BYTES)
        if raw_data:
            clean_text = raw_data.decode('utf-8', errors='replace').strip()
            # Sanitize control characters
            clean_text = re.sub(r'[\r\n\t]+', ' ', clean_text)
            if len(clean_text) > _MAX_BANNER_DISPLAY_LENGTH:
                clean_text = clean_text[:_MAX_BANNER_DISPLAY_LENGTH] + '…'
            return clean_text
    except (TimeoutError, OSError):
        pass
    return None


def probe_udp_port(
    target_ip: str,
    port: int,
    *,
    timeout_seconds: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> PortScanResult:
    """Perform a UDP probe to target_ip:port handling replies and ICMP Port Unreachable."""
    service_name = get_service_name(port)
    endpoint = (target_ip, port)
    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe_socket.settimeout(timeout_seconds)
    start_time = time.perf_counter()

    try:
        probe_socket.connect(endpoint)
        probe_socket.send(b'\x00' * 16)
        raw_data, _ = probe_socket.recvfrom(512)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        banner = f'Received {len(raw_data)} bytes'
        return PortScanResult(
            port=port,
            protocol='UDP',
            state=PortScanState.OPEN,
            service_name=service_name,
            latency_ms=latency_ms,
            banner=banner,
        )
    except (ConnectionResetError, ConnectionRefusedError):
        # Target OS responded with ICMP Port Unreachable -> Port is closed, host is up
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return PortScanResult(
            port=port,
            protocol='UDP',
            state=PortScanState.CLOSED,
            service_name=service_name,
            latency_ms=latency_ms,
        )
    except TimeoutError:
        # No reply received -> UDP port is open or filtered (standard UDP scanning behavior)
        return PortScanResult(
            port=port,
            protocol='UDP',
            state=PortScanState.FILTERED,
            service_name=service_name,
        )
    except OSError:
        return PortScanResult(
            port=port,
            protocol='UDP',
            state=PortScanState.FILTERED,
            service_name=service_name,
        )
    finally:
        probe_socket.close()


def probe_single_target(
    target_ip: str,
    port: int,
    protocol: str,
    timeout_seconds: float,
    *,
    grab_banner: bool = True,
) -> PortScanResult:
    """Dispatch a probe to the appropriate protocol handler."""
    if protocol == 'TCP':
        return probe_tcp_port(target_ip, port, timeout_seconds=timeout_seconds, grab_banner=grab_banner)
    return probe_udp_port(target_ip, port, timeout_seconds=timeout_seconds)
