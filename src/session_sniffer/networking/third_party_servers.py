"""Third-party server IP ranges for traffic filtering."""

import enum
import ipaddress
from functools import cached_property
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Self

from session_sniffer.networking.third_party_servers_ranges import (
    BATTLEYE_RANGES,
    CLOUDFLARE_RANGES,
    DEMONWARE_RANGES,
    DISCORD_RANGES,
    FRIEND_IT_RANGES,
    GOOGLE_LLC_RANGES,
    LATITUDE_SH_RANGES,
    MICROSOFT_RANGES,
    OVH_RANGES,
    PLAYSTATION_SONY_RANGES,
    TAKETWO_INTERACTIVE_RANGES,
    TELLAS_GREECE_RANGES,
    TENCENT_RANGES,
    THE_CONSTANT_COMPANY_RANGES,
    TSEFLOW_RANGES,
    UK_MINISTRY_OF_DEFENCE_RANGES,
    US_DEPARTMENT_OF_DEFENSE_RANGES,
    VALVE_RANGES,
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
    BATTLEYE = 'BattlEye', BATTLEYE_RANGES
    CLOUDFLARE = 'Cloudflare', CLOUDFLARE_RANGES
    DEMONWARE = 'Demonware Limited', DEMONWARE_RANGES
    DISCORD = 'Discord', DISCORD_RANGES
    FRIEND_IT = 'FRIEND IT Ltd', FRIEND_IT_RANGES
    GOOGLE_LLC = 'Google LLC', GOOGLE_LLC_RANGES
    LATITUDE_SH = 'Latitude.sh', LATITUDE_SH_RANGES
    MICROSOFT = 'Microsoft', MICROSOFT_RANGES
    OVH = 'OVH', OVH_RANGES
    PLAYSTATION_SONY = 'PlayStation (Sony)', PLAYSTATION_SONY_RANGES
    RUSTDESK = 'RustDesk', THE_CONSTANT_COMPANY_RANGES
    TAKETWO_INTERACTIVE = 'Take-Two Interactive Software, Inc.', TAKETWO_INTERACTIVE_RANGES
    TELLAS_GREECE = 'Tellas Greece', TELLAS_GREECE_RANGES
    TENCENT = 'Tencent Building, Kejizhongyi Avenue', TENCENT_RANGES
    THE_CONSTANT_COMPANY = 'The Constant Company, LLC', THE_CONSTANT_COMPANY_RANGES
    TSEFLOW = 'TSeflow s.r.l.', TSEFLOW_RANGES
    UK_MINISTRY_OF_DEFENCE = 'UK Ministry of Defence', UK_MINISTRY_OF_DEFENCE_RANGES
    US_DEPARTMENT_OF_DEFENSE = 'US Department of Defense', US_DEPARTMENT_OF_DEFENSE_RANGES
    VALVE = 'Valve', VALVE_RANGES

    @property
    def ip_ranges(self) -> tuple[CidrRange, ...]:
        """Return this server group's CIDR ranges as strings."""
        return tuple(r.cidr for r in self.named_ranges)

    @cached_property
    def ip_networks(self) -> tuple[IpNetwork, ...]:
        """Return this server group's CIDR ranges as parsed ipaddress networks."""
        return tuple(ipaddress.ip_network(ip_range) for ip_range in self.ip_ranges)

    @classmethod
    def get_ip_ranges_for(cls, server_names: Iterable[str]) -> list[CidrRange]:
        """Return a collapsed, minimal list of CIDR range strings for the specified server names."""
        names_set = set(server_names)
        nets: list[ipaddress.IPv4Network] = []

        for server in cls:
            if server.name in names_set:
                nets.extend(net for net in server.ip_networks if isinstance(net, ipaddress.IPv4Network))

        # Merge overlapping/adjacent ranges to keep the BPF filter small and efficient
        collapsed = list(ipaddress.collapse_addresses(nets))
        return [str(net) for net in collapsed]


ALL_THIRD_PARTY_SERVER_NAMES: tuple[str, ...] = tuple(server.name for server in ThirdPartyServers)


_ALL_THIRD_PARTY_SERVER_NETWORKS = tuple(
    dict.fromkeys(network for server in ThirdPartyServers for network in server.ip_networks),
)


def is_third_party_server_ip(ip: str) -> bool:
    """Return True if `ip` matches any known third-party server CIDR range."""
    return any(IPv4Address(ip) in net for net in _ALL_THIRD_PARTY_SERVER_NETWORKS)
