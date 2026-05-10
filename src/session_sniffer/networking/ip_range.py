"""Shared utilities for parsing and matching IP ranges in multiple formats."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


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
        msg = 'Empty IP range string'
        raise ValueError(msg)

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
    if len(parts) != 4:  # noqa: PLR2004
        msg = f'Invalid wildcard format: {raw}'
        raise ValueError(msg)
    cidr_parts: list[str] = []
    prefix_bits = 0
    wildcard_seen = False
    for part in parts:
        if part == '*':
            wildcard_seen = True
            cidr_parts.append('0')
        elif wildcard_seen:
            msg = f'Invalid wildcard format (non-wildcard after wildcard): {raw}'
            raise ValueError(msg)
        else:
            int_val = int(part)
            if not 0 <= int_val <= 255:  # noqa: PLR2004
                msg = f'Invalid octet value: {part}'
                raise ValueError(msg)
            cidr_parts.append(part)
            prefix_bits += 8
    cidr_str = '.'.join(cidr_parts) + f'/{prefix_bits}'
    network = IPv4Network(cidr_str, strict=False)
    return IPRange(raw=raw, network=network)


def _parse_start_end(raw: str) -> IPRange:
    """Parse start-end notation (e.g. `192.168.1.100-192.168.1.200`) into an `IPRange`."""
    start_str, sep, end_str = raw.partition('-')
    if not sep:
        msg = f'Invalid range format: {raw}'
        raise ValueError(msg)
    start = IPv4Address(start_str.strip())
    end = IPv4Address(end_str.strip())
    if start > end:
        msg = f'Start address {start} is greater than end address {end}'
        raise ValueError(msg)
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
        raw_part = raw_part.strip()  # noqa: PLW2901
        if raw_part:
            results.append(parse_ip_range(raw_part))
    if not results:
        msg = f'No valid IP ranges found in: {entry}'
        raise ValueError(msg)
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


def describe_range(r: IPRange) -> str:
    """Return a human-readable description of an `IPRange` for preview/tooltip use."""
    if r.start is not None and r.end is not None and r.network is None:
        count = int(r.end) - int(r.start) + 1
        return f'Range: {r.start} \u2013 {r.end}  ({count:,} addresses)'

    if r.network is not None:
        if r.network.prefixlen == 32:  # noqa: PLR2004
            return f'Single host: {r.network.network_address}'
        host_count = r.network.num_addresses
        usable = max(0, host_count - 2) if r.network.prefixlen < 31 and r.network.version == 4 else host_count  # noqa: PLR2004
        return (
            f'Network: {r.network.network_address}/{r.network.prefixlen}\n'
            f'Range: {r.network.network_address} \u2013 {r.network.broadcast_address}\n'
            f'Addresses: {host_count:,} total, {usable:,} usable\n'
            f'Netmask: {r.network.netmask}'
        )

    return r.raw


def is_valid_ip_range_entry(entry: str) -> bool:
    """Return whether the entry string is a valid IP range (any supported format)."""
    try:
        parse_ip_range_entry(entry)
    except ValueError:
        return False
    return True
