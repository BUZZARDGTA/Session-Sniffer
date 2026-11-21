"""Local network IPv4 address detection and URL formatting for the embedded web server."""

import socket
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address
from typing import Final

from session_sniffer.networking.adapters_info import IF_OPER_STATUS_UP, MEDIA_CONNECT_STATE_CONNECTED, get_adapters_info
from session_sniffer.networking.utils import is_ipv4_address

WEBSERVER_LOCAL_HOST: Final[str] = '127.0.0.1'
WEBSERVER_LAN_HOST: Final[str] = '0.0.0.0'  # noqa: S104
_HTTP_DEFAULT_PORT: Final[int] = 80
# RFC 5737 TEST-NET-1 destination used solely for a local OS routing table lookup via UDP connect (no packets sent).
_ROUTE_PROBE_TARGET: Final[tuple[str, int]] = ('192.0.2.1', 80)

_VIRTUAL_OR_VPN_MARKERS: Final[tuple[str, ...]] = (
    'vpn',
    'openvpn',
    'wireguard',
    'wintun',
    'tap-',
    'tap ',
    'tun',
    'nordlynx',
    'mullvad',
    'proton',
    'tailscale',
    'zerotier',
    'hamachi',
    'radmin',
    'vmware',
    'virtualbox',
    'vbox',
    'hyper-v',
    'vethernet',
    'wsl',
    'docker',
    'loopback',
    'virtual',
    'npcap',
)


@dataclass(frozen=True, slots=True)
class LocalNetworkAddress:
    """A detected local IPv4 address reachable from other devices on a network."""

    ip_address: str
    interface_name: str
    is_primary: bool = False


def _parse_ipv4(ip_address: str) -> IPv4Address | None:
    """Parse *ip_address* into an `IPv4Address`, or return `None` when invalid."""
    try:
        return IPv4Address(ip_address)
    except AddressValueError:
        return None


def is_loopback_ipv4(ip_address: str) -> bool:
    """Return True if *ip_address* is a valid IPv4 loopback address (`127.0.0.0/8`)."""
    parsed = _parse_ipv4(ip_address)
    return parsed is not None and parsed.is_loopback


def _is_usable_network_ipv4(ip_address: str) -> bool:
    """Return True if *ip_address* is a usable non-loopback, non-link-local unicast IPv4 address."""
    ip = _parse_ipv4(ip_address)
    return ip is not None and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved)


def _is_rfc1918_lan_ipv4(ip_address: str) -> bool:
    """Return True if *ip_address* is a standard RFC 1918 private LAN IPv4 address."""
    ip = _parse_ipv4(ip_address)
    return ip is not None and ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def _is_virtual_or_vpn_adapter(friendly_name: str, description: str) -> bool:
    """Return True when the adapter metadata indicates a virtual, loopback, or VPN interface."""
    combined = f'{friendly_name} {description}'.casefold()
    return any(marker in combined for marker in _VIRTUAL_OR_VPN_MARKERS)


def _detect_default_route_ipv4() -> str | None:
    """Ask the OS routing table for the preferred outbound IPv4 without sending any packets."""
    with suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_socket:
        probe_socket.connect(_ROUTE_PROBE_TARGET)
        local_ip = str(probe_socket.getsockname()[0])
        if _is_usable_network_ipv4(local_ip):
            return local_ip
    return None


def detect_local_ipv4_addresses(*, preferred_ip: str | None = None) -> tuple[LocalNetworkAddress, ...]:
    """Detect active local IPv4 addresses ordered so the best LAN address for phones appears first.

    Physical Wi-Fi/Ethernet adapters with a default gateway and RFC 1918 address are prioritized
    ahead of VPN tunnels and virtual interfaces so phones on the same home Wi-Fi receive a directly
    reachable address even when a VPN is active on this PC.
    """
    default_route_ip = _detect_default_route_ipv4()
    ranked_candidates: list[tuple[tuple[bool, bool, bool, bool, bool, int], str, str]] = []
    seen_ips: set[str] = set()

    with suppress(OSError):
        for adapter in get_adapters_info():
            if adapter.status.operational_status != IF_OPER_STATUS_UP:
                continue
            if adapter.status.media_connect_state != MEDIA_CONNECT_STATE_CONNECTED:
                continue
            friendly_name = adapter.identity.friendly_name.strip()
            description = adapter.identity.description.strip()
            is_virtual_or_vpn = _is_virtual_or_vpn_adapter(friendly_name, description)
            has_gateway = bool(adapter.gateway_addresses)
            for ip_address in adapter.ipv4_addresses:
                if ip_address in seen_ips or not _is_usable_network_ipv4(ip_address):
                    continue
                seen_ips.add(ip_address)
                sort_key = (
                    is_virtual_or_vpn,
                    not has_gateway,
                    not _is_rfc1918_lan_ipv4(ip_address),
                    ip_address != default_route_ip,
                    ip_address != preferred_ip,
                    len(ranked_candidates),
                )
                ranked_candidates.append((sort_key, ip_address, friendly_name))

    if default_route_ip is not None and default_route_ip not in seen_ips:
        ranked_candidates.append(
            (
                (False, False, not _is_rfc1918_lan_ipv4(default_route_ip), False, default_route_ip != preferred_ip, len(ranked_candidates)),
                default_route_ip,
                '',
            ),
        )

    ranked_candidates.sort(key=lambda entry: entry[0])
    return tuple(
        LocalNetworkAddress(ip_address=ip_address, interface_name=interface_name, is_primary=not index)
        for index, (_, ip_address, interface_name) in enumerate(ranked_candidates)
    )


def format_webserver_url(host: str, port: int) -> str:
    """Format an HTTP web panel URL, omitting `:80` for the default HTTP port."""
    if port == _HTTP_DEFAULT_PORT:
        return f'http://{host}'
    return f'http://{host}:{port}'


def resolve_local_access_url(host: str, port: int) -> str | None:
    """Return the browser URL for opening the web panel from this PC, or `None` if *host* is invalid."""
    normalized = host.strip()
    if normalized in (WEBSERVER_LOCAL_HOST, WEBSERVER_LAN_HOST):
        return format_webserver_url(WEBSERVER_LOCAL_HOST, port)
    if is_ipv4_address(normalized):
        return format_webserver_url(normalized, port)
    return None
