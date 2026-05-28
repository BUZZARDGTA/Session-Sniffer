"""Build BPF capture filters and Python display-filter callables from current application settings."""

from typing import TYPE_CHECKING

from scapy.layers.inet import UDP

from session_sniffer.constants.third_party_servers import ThirdPartyServers
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from scapy.packet import Packet as ScapyPacket

# https://en.wikipedia.org/wiki/Reserved_IP_addresses
_RESERVED_NETWORK_RANGES = (
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.88.99.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '233.252.0.0/24',
    '240.0.0.0/4',
    '255.255.255.255/32',
)
_RESERVED_NETWORKS_FILTER = ' or '.join(_RESERVED_NETWORK_RANGES)

_RTCP_RTP_VERSION = 2
_RTCP_PT_MIN = 200
_RTCP_PT_MAX = 204
_RTCP_MIN_PAYLOAD = 2
_DTLS_CONTENT_TYPE_MIN = 20
_DTLS_CONTENT_TYPE_MAX = 23


def _is_rtcp(pkt: ScapyPacket) -> bool:
    """Return `True` if the scapy packet looks like an RTCP packet.

    RTCP is identified by: RTP version == 2 (top 2 bits of first payload byte),
    and payload type (PT) in the range 200-204.
    """
    if not pkt.haslayer(UDP):
        return False
    payload = bytes(pkt[UDP].payload)
    if len(payload) < _RTCP_MIN_PAYLOAD:
        return False
    version = (payload[0] >> 6) & 0x3
    pt = payload[1] & 0x7F  # strip marker bit
    return version == _RTCP_RTP_VERSION and _RTCP_PT_MIN <= pt <= _RTCP_PT_MAX


def _is_dtls(pkt: ScapyPacket) -> bool:
    """Return `True` if the scapy packet looks like a DTLS record.

    DTLS content-type bytes (first byte of UDP payload): 20-23.
    """
    if not pkt.haslayer(UDP):
        return False
    payload = bytes(pkt[UDP].payload)
    return bool(payload) and _DTLS_CONTENT_TYPE_MIN <= payload[0] <= _DTLS_CONTENT_TYPE_MAX


def _build_display_filter_fn(
    excluded_protocols: list[str],
) -> Callable[[ScapyPacket], bool] | None:
    """Build a Python callable that returns `True` when a packet should be forwarded.

    Args:
        excluded_protocols: Protocol names that require Python-level inspection.

    Returns:
        A callable, or `None` if no Python-level filtering is needed.
    """
    checks: list[Callable[[ScapyPacket], bool]] = []

    if 'rtcp' in excluded_protocols:
        checks.append(lambda pkt: not _is_rtcp(pkt))

    if 'dtls' in excluded_protocols:
        checks.append(lambda pkt: not _is_dtls(pkt))

    if not checks:
        return None

    def display_filter_fn(pkt: ScapyPacket) -> bool:
        return all(check(pkt) for check in checks)

    return display_filter_fn


def build_capture_filters(
    *,
    capture_ip_address: str,
    broadcast_support: bool,
    multicast_support: bool,
) -> tuple[str | None, Callable[[ScapyPacket], bool] | None]:
    """Build a BPF capture filter string and an optional Python display-filter callable.

    Protocol exclusions that map cleanly to fixed port numbers are added directly
    to the BPF capture filter (strategy A).  Protocols requiring payload inspection
    (rtcp, dtls) are returned as a Python callable (strategy B).

    Args:
        capture_ip_address: The IP address of the capture interface to filter on.
        broadcast_support: Whether the interface supports the `broadcast` BPF term.
        multicast_support: Whether the interface supports the `multicast` BPF term.

    Returns:
        A `(capture_filter_str, display_filter_fn)` tuple.  Either element may be
        `None` when no filters of that kind are needed.
    """
    capture_filter: list[str] = ['ip', 'udp']

    capture_filter.append(
        f'((src host {capture_ip_address} and (not (dst net {_RESERVED_NETWORKS_FILTER}))) or '
        f'(dst host {capture_ip_address} and (not (src net {_RESERVED_NETWORKS_FILTER}))))',
    )

    if broadcast_support and multicast_support:
        capture_filter.append('not (broadcast or multicast)')
    elif broadcast_support:
        capture_filter.append('not broadcast')
    elif multicast_support:
        capture_filter.append('not multicast')

    capture_filter.append('not (portrange 0-1023 or port 5353)')

    # Protocols that need Python-level payload inspection (strategy B)
    python_excluded_protocols: list[str] = []

    if Settings.capture_game_preset:
        if Settings.capture_game_preset == 'GTA5':
            capture_filter.append('(len >= 71 and len <= 1032)')
        elif Settings.capture_game_preset == 'Minecraft':
            capture_filter.append('(len >= 49 and len <= 1498)')

    if Settings.capture_filter_block_rtcp:
        python_excluded_protocols.append('rtcp')
    if Settings.capture_filter_block_dtls:
        python_excluded_protocols.append('dtls')

    if Settings.capture_block_third_party_servers:
        blocked_ip_ranges = ThirdPartyServers.get_ip_ranges_for(Settings.capture_block_third_party_servers)
        if blocked_ip_ranges:
            capture_filter.append(f"not (net {' or '.join(blocked_ip_ranges)})")

    if Settings.capture_filter_block_ssdp:
        capture_filter.append('not port 1900')
    if Settings.capture_filter_block_raknet:
        capture_filter.append('not port 19132')
    if Settings.capture_filter_block_uaudp:
        capture_filter.append('not port 4569')
    if Settings.capture_filter_block_classicstun:
        capture_filter.append('not port 3478')
    if Settings.capture_filter_block_llmnr:
        capture_filter.append('not port 5355')

    if Settings.capture_blocked_ips:
        blocked_bpf: list[str] = []
        for raw in Settings.capture_blocked_ips:
            if '/' in raw:
                blocked_bpf.append(f'net {raw}')
            elif '-' not in raw and '*' not in raw:
                blocked_bpf.append(f'host {raw}')
            # Start-end ranges and wildcards are handled at the software level only
        if blocked_bpf:
            capture_filter.append(f"not ({' or '.join(blocked_bpf)})")

    if Settings.capture_prepend_custom_capture_filter:
        capture_filter.insert(0, f'({Settings.capture_prepend_custom_capture_filter})')

    capture_filter_str = ' and '.join(capture_filter) if capture_filter else None
    display_filter_fn = _build_display_filter_fn(
        python_excluded_protocols,
    )

    return (capture_filter_str, display_filter_fn)
