"""Third-party server IP ranges for traffic filtering."""

import enum
import ipaddress
from functools import cached_property
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from collections.abc import Iterable

type CidrRange = str
type IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ThirdPartyServers(enum.Enum):
    """Define IP ranges to treat as third-party server traffic."""

    def __new__(cls, display_name: str, ip_ranges: tuple[CidrRange, ...]) -> Self:
        """Create an enum member with a display label and CIDR ranges."""
        member = object.__new__(cls)
        member._value_ = ip_ranges
        member.display_name = display_name
        return member

    display_name: str
    value: tuple[CidrRange, ...]

    PC_DISCORD = 'Discord', (
        '66.22.196.0/22', '66.22.200.0/21', '66.22.208.0/20', '66.22.224.0/20', '66.22.240.0/21', '66.22.248.0/24',
        '104.29.128.0/18', '34.1.224.0/20', '35.214.219.48/28', '35.214.128.0/18',
    )
    PC_VALVE = 'Valve (Steam)', ('103.10.124.0/23', '103.28.54.0/23', '146.66.152.0/21', '155.133.224.0/19', '162.254.192.0/21', '185.25.180.0/22', '205.196.6.0/24')
    PC_GOOGLE = 'Google', ('34.0.0.0/9', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/11', '35.224.0.0/12', '35.240.0.0/13')
    PC_MULTICAST = 'Multicast', ('224.0.0.0/4',)
    PC_SERVERS_COM = 'Servers.com', ('173.237.26.0/24',)
    PC_OTHERS = 'Others', ('113.117.15.193/32',)
    PC_RUSTDESK = 'RustDesk', ('209.250.240.0/20',)
    PS_SONY_INTERACTIVE = 'Sony Interactive (PS)', ('100.42.96.0/20', '104.142.128.0/17')
    PS_AMAZON = 'Amazon (PS)', ('34.192.0.0/10', '44.192.0.0/10', '52.0.0.0/10', '52.64.0.0/12', '52.80.0.0/13', '52.88.0.0/14')
    MICROSOFT = 'Microsoft', ('20.0.0.0/8', '52.139.128.0/18', '52.132.0.0/14', '52.136.0.0/13', '52.144.0.0/12', '52.160.0.0/11', '52.192.0.0/10')
    OMETV_OVH = 'OmeTV OVH', (
        '15.204.0.0/16', '15.235.208.0/20', '37.59.0.0/16', '46.105.0.0/16', '51.68.32.0/20', '51.89.0.0/16', '54.36.0.0/14', '57.128.0.0/14',
        '135.125.0.0/16', '135.148.136.0/23', '135.148.150.0/23', '141.94.0.0/15', '146.59.0.0/16', '148.113.0.0/16', '162.19.0.0/16',
    )
    OMETV_GOOGLE = 'OmeTV Google', ('74.125.0.0/16',)
    GTAV_TAKETWO_INTERACTIVE = 'Take-Two Interactive (GTA V)', ('104.255.104.0/22', '185.56.64.0/22', '192.81.240.0/21')
    GTAV_PC_UK_MINISTRY_OF_DEFENCE = 'UK Ministry of Defence (GTA V PC)', ('25.0.0.0/8',)
    GTAV_PC_US_DEPARTMENT_OF_DEFENSE = 'US Department of Defense (GTA V PC)', ('21.0.0.0/8', '22.0.0.0/8', '26.0.0.0/8')
    GTAV_PC_BATTLEYE = 'BattlEye (GTA V PC)', ('51.89.97.102/32', '51.89.99.255/32')
    GTAV_PS5_TELLAS_GREECE = 'Tellas Greece (GTA V PS5)', ('176.58.224.0/22',)
    GTAV_XBOXONE_MICROSOFT = 'Microsoft (GTA V Xbox One)', ('40.74.0.0/18', '52.159.128.0/17', '52.160.0.0/16')
    MINECRAFTBEDROCKEDITION_PC_PS4_MICROSOFT = 'Microsoft (Minecraft Bedrock)', ('168.61.142.128/25', '168.61.143.0/24', '168.61.144.0/20', '168.61.160.0/19')

    @property
    def ip_ranges(self) -> tuple[CidrRange, ...]:
        """Return this server group's CIDR ranges as strings."""
        return self.value

    @cached_property
    def ip_networks(self) -> tuple[IpNetwork, ...]:
        """Return this server group's CIDR ranges as parsed ipaddress networks."""
        return tuple(
            ipaddress.ip_network(ip_range)
            for ip_range in self.ip_ranges
        )

    @classmethod
    def get_ip_ranges_for(cls, server_names: Iterable[str]) -> list[CidrRange]:
        """Return a flat list of CIDR range strings for the specified server names."""
        names_set = set(server_names)
        return [
            ip_range
            for server in cls
            if server.name in names_set
            for ip_range in server.ip_ranges
        ]


ALL_THIRD_PARTY_SERVER_NAMES: tuple[str, ...] = tuple(
    server.name
    for server in ThirdPartyServers
)


_ALL_THIRD_PARTY_SERVER_NETWORKS = tuple(
    network
    for server in ThirdPartyServers
    for network in server.ip_networks
)


def is_third_party_server_ip(ip: str) -> bool:
    """Return True if `ip` matches any known third-party server CIDR range."""
    return any(IPv4Address(ip) in net for net in _ALL_THIRD_PARTY_SERVER_NETWORKS)
