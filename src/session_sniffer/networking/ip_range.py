"""Shared utilities for parsing and matching IP ranges in multiple formats."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

_IPV4_OCTET_COUNT = 4
_IPV4_MAX_OCTET = 255
_IPV4_SINGLE_HOST_PREFIX = 32
_IPV4_MIN_USABLE_PREFIX = 31
_IPV4_VERSION = 4


@dataclass(frozen=True, slots=True)
class IPRange:
    """Represents a parsed IP range entry that can match individual addresses."""

    raw: str
    network: IPv4Network | None = None
    start: IPv4Address | None = None
    end: IPv4Address | None = None

    def __contains__(self, ip: str | IPv4Address) -> bool:
        """Check whether the given IP address falls within this range."""
        addr = IPv4Address(ip) if isinstance(ip, str) else ip
        if self.network is not None:
            return addr in self.network
        if self.start is not None and self.end is not None:
            return self.start <= addr <= self.end
        return False


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


def parse_ip_range_entry(entry: str) -> list[IPRange]:
    """Parse an entry that may contain comma-separated IP ranges.

    Returns:
        A list of parsed `IPRange` objects.

    Raises:
        ValueError: If any sub-entry cannot be parsed.
    """
    results: list[IPRange] = []
    for raw_part in entry.split(','):
        stripped = raw_part.strip()
        if stripped:
            results.append(parse_ip_range(stripped))
    if not results:
        message = f'No valid IP ranges found in: {entry}'
        raise ValueError(message)
    return results


def check_ip_against_ranges(ip: str, ranges: list[IPRange]) -> IPRange | None:
    """Check if an IP address matches any of the given ranges.

    Returns:
        The first matching `IPRange`, or `None` if no match.
    """
    try:
        addr = IPv4Address(ip)
    except ValueError:
        return None
    for ip_range in ranges:
        if addr in ip_range:
            return ip_range
    return None


def is_valid_ip_range_entry(entry: str) -> bool:
    """Return whether the entry string is a valid IP range (any supported format)."""
    try:
        parse_ip_range_entry(entry)
    except ValueError:
        return False
    return True
