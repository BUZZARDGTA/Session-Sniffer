"""Shared utilities for parsing and matching IP ranges in multiple formats."""

from dataclasses import dataclass
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

_IPV4_OCTET_COUNT = 4
_IPV4_MAX_OCTET = 255


@lru_cache(maxsize=65536)
def ipv4_to_int(ip: str) -> int | None:
    """Convert a canonical dotted-quad IPv4 string to a 32-bit int, or `None` if invalid."""
    if not ip or '/' in ip or '-' in ip or '*' in ip:
        return None
    try:
        return int(IPv4Address(ip))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class IPRange:
    """Represents a parsed IP range entry that can match individual addresses."""

    raw: str
    network: IPv4Network | None = None
    start: IPv4Address | None = None
    end: IPv4Address | None = None
    start_int: int = 0
    end_int: int = -1

    def __post_init__(self) -> None:
        """Cache integer address bounds for O(1) containment and overlap checks."""
        if self.network is not None:
            object.__setattr__(self, 'start_int', int(self.network.network_address))
            object.__setattr__(self, 'end_int', int(self.network.broadcast_address))
        elif self.start is not None and self.end is not None:
            object.__setattr__(self, 'start_int', int(self.start))
            object.__setattr__(self, 'end_int', int(self.end))

    def __contains__(self, ip: str | IPv4Address) -> bool:
        """Check whether the given IP address falls within this range."""
        if self.end_int < self.start_int:
            return False
        if isinstance(ip, str):
            addr_int = ipv4_to_int(ip)
            if addr_int is None:
                return False
        else:
            addr_int = int(ip)
        return self.start_int <= addr_int <= self.end_int

    @property
    def bounds(self) -> tuple[IPv4Address, IPv4Address] | None:
        """Return the inclusive `(start, end)` address bounds for this range."""
        if self.network is not None:
            return self.network.network_address, self.network.broadcast_address
        if self.start is not None and self.end is not None:
            return self.start, self.end
        return None

    def overlaps(self, other: IPRange) -> bool:
        """Return whether this range shares at least one IPv4 address with `other`."""
        if self.end_int < self.start_int or other.end_int < other.start_int:
            return False
        return self.start_int <= other.end_int and other.start_int <= self.end_int


@lru_cache(maxsize=65536)
def _parse_ip_range_cached(raw: str) -> IPRange:
    """Parse a stripped non-empty IP range string into a cached `IPRange`."""
    # Wildcard → CIDR
    if '*' in raw:
        return _parse_wildcard(raw)

    # Start-end notation
    if '-' in raw and '/' not in raw:
        return _parse_start_end(raw)

    # CIDR notation
    if '/' in raw:
        network = IPv4Network(raw, strict=False)
        return IPRange(raw=raw, network=network)

    # Single IP → /32 network
    addr = IPv4Address(raw)
    network = IPv4Network(f'{addr}/32', strict=False)
    return IPRange(raw=raw, network=network)


def parse_ip_range(raw: str) -> IPRange:
    """Parse a single IP range string into an `IPRange`.

    Supported formats:
    - Single IP: `192.168.1.1` (becomes /32 network)
    - CIDR: `192.168.1.0/24`
    - Start-end: `192.168.1.100-192.168.1.200`
    - Wildcard: `192.168.1.*` (becomes CIDR, e.g. `192.168.1.0/24`)

    Raises:
        ValueError: If the string cannot be parsed into any supported format.
    """
    raw = raw.strip()
    if not raw:
        message = 'Empty IP range string'
        raise ValueError(message)
    return _parse_ip_range_cached(raw)


def _parse_wildcard(raw: str) -> IPRange:
    """Parse wildcard notation (e.g. `192.168.1.*`) into a CIDR-based `IPRange`."""
    parts = raw.split('.')
    if len(parts) != _IPV4_OCTET_COUNT:
        message = f'Invalid wildcard format: {raw}'
        raise ValueError(message)
    cidr_parts: list[str] = []
    prefix_bits = 0
    wildcard_seen = False
    for part in parts:
        if part == '*':
            wildcard_seen = True
            cidr_parts.append('0')
        elif wildcard_seen:
            message = f'Invalid wildcard format (non-wildcard after wildcard): {raw}'
            raise ValueError(message)
        else:
            int_val = int(part)
            if not 0 <= int_val <= _IPV4_MAX_OCTET:
                message = f'Invalid octet value: {part}'
                raise ValueError(message)
            cidr_parts.append(part)
            prefix_bits += 8
    cidr_str = '.'.join(cidr_parts) + f'/{prefix_bits}'
    network = IPv4Network(cidr_str, strict=False)
    return IPRange(raw=raw, network=network)


def _parse_start_end(raw: str) -> IPRange:
    """Parse start-end notation (e.g. `192.168.1.100-192.168.1.200`) into an `IPRange`."""
    start_str, sep, end_str = raw.partition('-')
    if not sep:
        message = f'Invalid range format: {raw}'
        raise ValueError(message)
    start = IPv4Address(start_str.strip())
    end = IPv4Address(end_str.strip())
    if start > end:
        message = f'Start address {start} is greater than end address {end}'
        raise ValueError(message)
    return IPRange(raw=raw, start=start, end=end)


def check_ip_against_ranges(ip: str, ranges: Sequence[IPRange]) -> IPRange | None:
    """Check if an IP address matches any of the given ranges.

    Returns:
        The first matching `IPRange`, or `None` if no match.
    """
    addr_int = ipv4_to_int(ip)
    if addr_int is None:
        return None
    for ip_range in ranges:
        if ip_range.start_int <= addr_int <= ip_range.end_int:
            return ip_range
    return None


def is_valid_ip_range_entry(entry: str) -> bool:
    """Return whether the entry string is a valid IP range (any supported format)."""
    if ipv4_to_int(entry.strip()) is not None:
        return True
    try:
        parse_ip_range(entry)
    except ValueError:
        return False
    return True


def entry_ip_covers_ip(entry_ip: str, ip: str) -> bool:
    """Return whether `entry_ip` (exact IP or range entry) covers `ip`."""
    if entry_ip == ip:
        return True
    if '*' not in entry_ip and '-' not in entry_ip and '/' not in entry_ip:
        entry_int = ipv4_to_int(entry_ip.strip())
        return entry_int is not None and entry_int == ipv4_to_int(ip.strip())
    try:
        ip_range = parse_ip_range(entry_ip)
    except ValueError:
        return False
    return ip in ip_range
