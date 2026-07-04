"""Third-party server IP ranges for traffic filtering."""
import bisect
import enum
import ipaddress
from functools import cached_property
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Self

from session_sniffer.networking.third_party_servers_ranges import (
    AKAMAI_CONNECTED_CLOUD_RANGES,
    AMAZON_RANGES,
    BATTLEYE_RANGES,
    CLOUDFLARE_RANGES,
    COMNET_INTERNATIONAL_BV_RANGES,
    COMVIVE_SERVIDORES_RANGES,
    DEMONWARE_RANGES,
    DIMENSION_DATA_RANGES,
    DISCORD_RANGES,
    EA_RANGES,
    FRIEND_IT_RANGES,
    G_CORE_LABS_RANGES,
    GOOGLE_LLC_RANGES,
    I3D_NET_RANGES,
    LATITUDE_SH_RANGES,
    LEVEL_3_PARENT_RANGES,
    LIMESTONE_NETWORKS_RANGES,
    MICROSOFT_RANGES,
    OVH_RANGES,
    PLAYSTATION_SONY_RANGES,
    SEFLOW_RANGES,
    SERVERS_COM_RANGES,
    TAKETWO_INTERACTIVE_RANGES,
    TELLAS_GREECE_RANGES,
    TENCENT_RANGES,
    THE_CONSTANT_COMPANY_RANGES,
    UK_MINISTRY_OF_DEFENCE_RANGES,
    US_DEPARTMENT_OF_DEFENSE_RANGES,
    VALVE_RANGES,
    ZENLAYER_RANGES,
    NamedRange,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

type CidrRange = str
type IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ThirdPartyServers(enum.Enum):
    """Define IP ranges to treat as third-party server traffic."""

    def __new__(
        cls,
        display_name: str,
        named_ranges: tuple[NamedRange, ...],
    ) -> Self:
        """Create an enum member with a display label and named CIDR ranges."""
        member = object.__new__(cls)
        member.display_name = display_name
        member.named_ranges = named_ranges
        return member

    display_name: str
    named_ranges: tuple[NamedRange, ...]
    value: tuple[str, tuple[NamedRange, ...]]

    # Flat, owner-based server ranges
    AKAMAI_CONNECTED_CLOUD = 'Akamai Connected Cloud', AKAMAI_CONNECTED_CLOUD_RANGES
    AMAZON = 'Amazon.com, Inc.', AMAZON_RANGES
    BATTLEYE = 'BattlEye', BATTLEYE_RANGES
    CLOUDFLARE = 'Cloudflare', CLOUDFLARE_RANGES
    COMNET_INTERNATIONAL_BV = 'Comnet Internetional BV', COMNET_INTERNATIONAL_BV_RANGES
    COMVIVE_SERVIDORES = 'Comvive Servidores S.L.', COMVIVE_SERVIDORES_RANGES
    DEMONWARE = 'Demonware Limited', DEMONWARE_RANGES
    DIMENSION_DATA = 'Dimension Data', DIMENSION_DATA_RANGES
    DISCORD = 'Discord', DISCORD_RANGES
    EA = 'Electronic Arts, Inc.', EA_RANGES
    FRIEND_IT = 'FRIEND IT Ltd', FRIEND_IT_RANGES
    G_CORE_LABS = 'G-Core Labs S.A.', G_CORE_LABS_RANGES
    GOOGLE_LLC = 'Google LLC', GOOGLE_LLC_RANGES
    I3D_NET = 'i3D.net B.V', I3D_NET_RANGES
    LATITUDE_SH = 'Latitude.sh', LATITUDE_SH_RANGES
    LEVEL_3_PARENT = 'Level 3 Parent, LLC', LEVEL_3_PARENT_RANGES
    LIMESTONE_NETWORKS = 'Limestone Networks, Inc.', LIMESTONE_NETWORKS_RANGES
    MICROSOFT = 'Microsoft', MICROSOFT_RANGES
    OVH = 'OVH', OVH_RANGES
    PLAYSTATION_SONY = 'PlayStation (Sony)', PLAYSTATION_SONY_RANGES
    RUSTDESK = 'RustDesk', THE_CONSTANT_COMPANY_RANGES
    SERVERS_COM = 'Servers.com', SERVERS_COM_RANGES
    TAKETWO_INTERACTIVE = 'Take-Two Interactive Software, Inc.', TAKETWO_INTERACTIVE_RANGES
    TELLAS_GREECE = 'Tellas Greece', TELLAS_GREECE_RANGES
    TENCENT = 'Tencent Building, Kejizhongyi Avenue', TENCENT_RANGES
    THE_CONSTANT_COMPANY = 'The Constant Company, LLC', THE_CONSTANT_COMPANY_RANGES
    SEFLOW = 'Seflow s.r.l.', SEFLOW_RANGES
    UK_MINISTRY_OF_DEFENCE = 'UK Ministry of Defence', UK_MINISTRY_OF_DEFENCE_RANGES
    US_DEPARTMENT_OF_DEFENSE = 'US Department of Defense', US_DEPARTMENT_OF_DEFENSE_RANGES
    VALVE = 'Valve', VALVE_RANGES
    ZENLAYER = 'Zenlayer Inc', ZENLAYER_RANGES

    @property
    def ip_ranges(self) -> tuple[CidrRange, ...]:
        """Return this server group's CIDR ranges as strings."""
        return tuple(named_range.cidr_range for named_range in self.named_ranges)

    @cached_property
    def ip_networks(self) -> tuple[IpNetwork, ...]:
        """Return this server group's CIDR ranges as parsed ipaddress networks."""
        return tuple(ipaddress.ip_network(ip_range) for ip_range in self.ip_ranges)

    @classmethod
    def get_ip_ranges_for(cls, server_names: Iterable[str]) -> list[CidrRange]:
        """Return a collapsed, minimal list of CIDR range strings for the specified server names."""
        names_set = set(server_names)
        networks: list[ipaddress.IPv4Network] = []

        for server in cls:
            if server.name in names_set:
                networks.extend(network for network in server.ip_networks if isinstance(network, ipaddress.IPv4Network))

        # Merge overlapping/adjacent ranges to keep the BPF filter small and efficient
        collapsed = list(ipaddress.collapse_addresses(networks))
        return [str(network) for network in collapsed]

    @classmethod
    def get_ip_obj_ranges_for(cls, server_names: Iterable[str]) -> list[tuple[IPv4Address, IPv4Address]]:
        """Return a collapsed, minimal list of IPv4Address tuple ranges for the specified server names."""
        names_set = set(server_names)
        networks = [
            network
            for server in cls
            if server.name in names_set
            for network in server.ip_networks
            if isinstance(network, ipaddress.IPv4Network)
        ]
        return _build_ip_obj_ranges(networks)


def _build_ip_obj_ranges(networks: Iterable[ipaddress.IPv4Network]) -> list[tuple[IPv4Address, IPv4Address]]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    ranges = [(net.network_address, net.broadcast_address) for net in collapsed]
    ranges.sort()
    return ranges


ALL_THIRD_PARTY_SERVER_NAMES: tuple[str, ...] = tuple(server.name for server in ThirdPartyServers)


_ALL_THIRD_PARTY_SERVER_NETWORKS = tuple(
    ipaddress.collapse_addresses([
        network
        for server in ThirdPartyServers
        for network in server.ip_networks
        if isinstance(network, ipaddress.IPv4Network)
    ])
)
_ALL_THIRD_PARTY_SERVER_OBJ_RANGES = _build_ip_obj_ranges(_ALL_THIRD_PARTY_SERVER_NETWORKS)

MAX_IPV4 = IPv4Address('255.255.255.255')


def is_ip_in_ranges(ip_obj: IPv4Address, ranges: list[tuple[IPv4Address, IPv4Address]]) -> bool:
    """Check if an IPv4Address falls within any of the given ranges."""
    if not ranges:
        return False
    idx = bisect.bisect_right(ranges, (ip_obj, MAX_IPV4))
    return bool(idx > 0 and ip_obj <= ranges[idx - 1][1])


def is_third_party_server_ip(ip: str) -> bool:
    """Return True if `ip` matches any known third-party server CIDR range."""
    try:
        ip_obj = IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    return is_ip_in_ranges(ip_obj, _ALL_THIRD_PARTY_SERVER_OBJ_RANGES)
