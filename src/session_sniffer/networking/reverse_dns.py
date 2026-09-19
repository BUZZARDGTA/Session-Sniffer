"""The module provides functionality for performing reverse DNS lookups.

It includes `reverse_dns_lookup` which resolves hostnames from IP addresses,
querying public DNS servers (1.1.1.1 and 8.8.8.8) with automatic fallback
to the operating system resolver.
"""

import ipaddress
import secrets
import socket
import struct
import threading

from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)

PUBLIC_DNS_SERVERS: tuple[str, ...] = ('1.1.1.1', '8.8.8.8')

_DNS_HEADER_LENGTH = 12
_DNS_PTR_RECORD_TYPE = 12
_DNS_COMPRESSION_MASK = 0xC0
_MAX_DNS_LABEL_HOPS = 16


class _ResolverState:
    """Thread-safe state container tracking public DNS server availability."""

    def __init__(self) -> None:
        self.public_dns_available: bool | None = None
        self.lock = threading.Lock()

    def is_public_dns_reachable(self) -> bool:
        """Check whether public DNS servers (1.1.1.1 or 8.8.8.8) are reachable and not blocked."""
        if self.public_dns_available is not None:
            return self.public_dns_available

        with self.lock:
            if self.public_dns_available is not None:
                return self.public_dns_available

            probe_pointer = '1.1.1.1.in-addr.arpa'
            is_reachable = (
                _query_udp_dns('1.1.1.1', probe_pointer, timeout_seconds=1.0) is not None
                or _query_udp_dns('8.8.8.8', probe_pointer, timeout_seconds=1.0) is not None
            )
            self.public_dns_available = is_reachable
            return self.public_dns_available

    def reset(self) -> None:
        """Clear the cached DNS availability state, forcing a re-check on the next lookup."""
        with self.lock:
            self.public_dns_available = None


_resolver_state = _ResolverState()


def _build_dns_ptr_query(reverse_pointer: str, transaction_id: int) -> bytes:
    """Construct a raw DNS query packet for a PTR record."""
    labels = reverse_pointer.split('.')
    encoded_query_name = b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\x00'
    header = struct.pack('!HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0)
    question = encoded_query_name + struct.pack('!HH', _DNS_PTR_RECORD_TYPE, 1)
    return header + question


def _parse_dns_name(response_data: bytes, offset: int) -> tuple[str, int]:
    """Parse a sequence of DNS labels handling compression pointers."""
    labels: list[str] = []
    has_jumped = False
    original_offset = offset
    hops = 0

    while hops < _MAX_DNS_LABEL_HOPS:
        if offset >= len(response_data):
            break
        length = response_data[offset]
        if not length:
            offset += 1
            break
        if (length & _DNS_COMPRESSION_MASK) == _DNS_COMPRESSION_MASK:
            if offset + 1 >= len(response_data):
                break
            pointer: int = ((length & 0x3F) << 8) | response_data[offset + 1]
            if not has_jumped:
                original_offset = offset + 2
                has_jumped = True
            offset = pointer
            hops += 1
            continue
        offset += 1
        if offset + length > len(response_data):
            break
        labels.append(response_data[offset : offset + length].decode('ascii', errors='replace'))
        offset += length

    return '.'.join(labels), (original_offset if has_jumped else offset)


def _query_udp_dns(server_ip: str, reverse_pointer: str, timeout_seconds: float = 1.0) -> str | None:
    """Send a raw DNS PTR query over UDP to a specific DNS server."""
    address_family = socket.AF_INET6 if ':' in server_ip else socket.AF_INET
    udp_socket = socket.socket(address_family, socket.SOCK_DGRAM)
    udp_socket.settimeout(timeout_seconds)
    transaction_id = secrets.randbelow(65536)

    try:
        query_packet = _build_dns_ptr_query(reverse_pointer, transaction_id)
        udp_socket.sendto(query_packet, (server_ip, 53))
        response_bytes, _ = udp_socket.recvfrom(512)
    except OSError as e:
        logger.debug('UDP DNS query to %s for %s failed: %s', server_ip, reverse_pointer, e)
        return None
    finally:
        udp_socket.close()

    if len(response_bytes) < _DNS_HEADER_LENGTH:
        return None

    response_transaction_id, flags, question_count, answer_count, _, _ = struct.unpack('!HHHHHH', response_bytes[:_DNS_HEADER_LENGTH])
    if response_transaction_id != transaction_id or not (flags & 0x8000) or (flags & 0x000F) or not answer_count:
        return None

    offset = _DNS_HEADER_LENGTH
    for _ in range(question_count):
        _, offset = _parse_dns_name(response_bytes, offset)
        offset += 4

    for _ in range(answer_count):
        if offset + 10 > len(response_bytes):
            break
        _, offset = _parse_dns_name(response_bytes, offset)
        if offset + 10 > len(response_bytes):
            break
        record_type, _, _, resource_data_length = struct.unpack('!HHIH', response_bytes[offset : offset + 10])
        offset += 10
        if record_type == _DNS_PTR_RECORD_TYPE:
            resolved_name, _ = _parse_dns_name(response_bytes, offset)
            return resolved_name
        offset += resource_data_length

    return None


def reset_resolver_cache() -> None:
    """Clear the cached DNS availability state, forcing a re-check on the next lookup."""
    _resolver_state.reset()


def reverse_dns_lookup(target_ip: str) -> str:
    """Perform a reverse DNS lookup for the given IP address.

    Queries public DNS servers (1.1.1.1 and 8.8.8.8) first for public addresses,
    falling back to the operating system resolver if unreachable or unassigned.

    Args:
        target_ip: The IP address to look up.

    Returns:
        The resolved hostname, or the original IP address if no valid hostname is found.
    """
    try:
        ip_object = ipaddress.ip_address(target_ip)
    except ValueError:
        ip_object = None

    if ip_object is not None and not ip_object.is_private and not ip_object.is_loopback and _resolver_state.is_public_dns_reachable():
        for public_server in PUBLIC_DNS_SERVERS:
            resolved_hostname = _query_udp_dns(public_server, ip_object.reverse_pointer, timeout_seconds=1.0)
            if resolved_hostname:
                cleaned_hostname = resolved_hostname.rstrip('.')
                if cleaned_hostname:
                    return cleaned_hostname

    try:
        system_hostname, _ = socket.getnameinfo((target_ip, 0), 0)
    except (socket.gaierror, OSError) as e:
        logger.debug('System reverse DNS lookup for %s failed: %s', target_ip, e)
        return target_ip

    cleaned_system_hostname = system_hostname.rstrip('.')
    if not cleaned_system_hostname:
        return target_ip

    return cleaned_system_hostname
