"""Build capture and display filter strings from current application settings."""

from session_sniffer.constants.third_party_servers import ThirdPartyServers
from session_sniffer.settings.settings import Settings

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


def build_capture_filters(
    *,
    broadcast_support: bool,
    multicast_support: bool,
) -> tuple[str | None, str | None]:
    """Build capture and display filter strings from current Settings.

    Args:
        broadcast_support: Whether the interface supports the `broadcast` capture filter.
        multicast_support: Whether the interface supports the `multicast` capture filter.

    Returns:
        A `(capture_filter, display_filter)` tuple.  Either element may be `None`
        when no filters of that kind are needed.
    """
    capture_filter: list[str] = ['ip', 'udp']

    if Settings.capture_ip_address:
        capture_filter.append(
            f'((src host {Settings.capture_ip_address} and (not (dst net {_RESERVED_NETWORKS_FILTER}))) or '
            f'(dst host {Settings.capture_ip_address} and (not (src net {_RESERVED_NETWORKS_FILTER}))))',
        )

    if broadcast_support and multicast_support:
        capture_filter.append('not (broadcast or multicast)')
    elif broadcast_support:
        capture_filter.append('not broadcast')
    elif multicast_support:
        capture_filter.append('not multicast')

    capture_filter.append('not (portrange 0-1023 or port 5353)')

    excluded_protocols: list[str] = []

    if Settings.capture_program_preset:
        if Settings.capture_program_preset == 'GTA5':
            capture_filter.append('(len >= 71 and len <= 1032)')
        elif Settings.capture_program_preset == 'Minecraft':
            capture_filter.append('(len >= 49 and len <= 1498)')

        # If the <CAPTURE_PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
        # In case RTCP can be useful to get someone IP, I decided not to block them without using a <CAPTURE_PROGRAM_PRESET>.
        # RTCP is known to be for example the Discord's server IP while you are in a call there.
        # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
        # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
        # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
        # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
        excluded_protocols.append('rtcp')

    if Settings.capture_block_third_party_servers:
        blocked_ip_ranges = ThirdPartyServers.get_ip_ranges_for(Settings.capture_block_third_party_servers)
        if blocked_ip_ranges:
            capture_filter.append(f"not (net {' or '.join(blocked_ip_ranges)})")

        # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
        # But there can be a lot more, those are just a couples I could find on my own usage.
        excluded_protocols.extend(['ssdp', 'raknet', 'dtls', 'nbns', 'pcp', 'bt-dht', 'uaudp', 'classicstun', 'dhcp', 'mdns', 'llmnr'])

    display_filter: list[str] = []

    if excluded_protocols:
        display_filter.append(
            f"not ({' or '.join(excluded_protocols)})",
        )

    if Settings.capture_prepend_custom_capture_filter:
        capture_filter.insert(0, f'({Settings.capture_prepend_custom_capture_filter})')

    if Settings.capture_prepend_custom_display_filter:
        display_filter.insert(0, f'({Settings.capture_prepend_custom_display_filter})')

    capture_filter_str = ' and '.join(capture_filter) if capture_filter else None
    display_filter_str = ' and '.join(display_filter) if display_filter else None

    return (capture_filter_str, display_filter_str)
