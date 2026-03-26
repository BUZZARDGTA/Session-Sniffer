"""Third-party server IP ranges for traffic filtering."""

import enum


class ThirdPartyServers(enum.Enum):
    """Define IP ranges to treat as third-party server traffic."""

    PC_DISCORD = ('66.22.196.0/22', '66.22.200.0/21', '66.22.208.0/20', '66.22.224.0/20', '66.22.240.0/21', '66.22.248.0/24', '104.29.128.0/18')
    PC_VALVE = ('103.10.124.0/23', '103.28.54.0/23', '146.66.152.0/21', '155.133.224.0/19', '162.254.192.0/21', '185.25.180.0/22', '205.196.6.0/24')  # Valve = Steam
    PC_GOOGLE = ('34.0.0.0/9', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/11', '35.224.0.0/12', '35.240.0.0/13')
    PC_MULTICAST = ('224.0.0.0/4',)
    PC_ANDROID_OMETV_OVH = (
        '15.204.0.0/16', '15.235.208.0/20', '37.59.0.0/16', '46.105.0.0/16', '51.68.32.0/20', '51.89.0.0/16', '54.36.0.0/14', '57.128.0.0/14',
        '135.125.0.0/16', '135.148.136.0/23', '135.148.150.0/23', '141.94.0.0/15', '146.59.0.0/16', '148.113.0.0/16', '162.19.0.0/16',
    )
    PC_OMETV_GOOGLE = ('74.125.0.0/16',)
    PC_UK_MINISTRY_OF_DEFENCE = ('25.0.0.0/8',)
    PC_SERVERS_COM = ('173.237.26.0/24',)
    PC_OTHERS = ('113.117.15.193/32',)
    PC_RUSTDESK = ('209.250.240.0/20',)
    PS_SONY_INTERACTIVE = ('104.142.128.0/17',)
    PS_AMAZON = ('34.192.0.0/10', '44.192.0.0/10', '52.0.0.0/10', '52.64.0.0/12', '52.80.0.0/13', '52.88.0.0/14')
    GTAV_TAKETWO = ('104.255.104.0/22', '185.56.64.0/22', '192.81.240.0/21')
    GTAV_PC_MICROSOFT = ('52.139.128.0/18',)
    GTAV_PC_DOD_NETWORK_INFORMATION_CENTER = ('26.0.0.0/8',)
    GTAV_PC_BATTLEYE = ('51.89.97.102/32', '51.89.99.255/32')
    GTAV_PS5_TELLAS_GREECE = ('176.58.224.0/22',)
    GTAV_XBOXONE_MICROSOFT = ('40.74.0.0/18', '52.159.128.0/17', '52.160.0.0/16')
    MINECRAFTBEDROCKEDITION_PC_PS4_MICROSOFT = ('20.202.0.0/24', '20.224.0.0/16', '168.61.142.128/25', '168.61.143.0/24', '168.61.144.0/20', '168.61.160.0/19')

    @classmethod
    def get_all_ip_ranges(cls) -> list[str]:
        """Return a flat list of all IP ranges from the Enum."""
        return [ip_range for server in cls for ip_range in server.value]
