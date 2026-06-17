"""Third-party server IP ranges database."""

from typing import NamedTuple

type CidrRange = str


class NamedRange(NamedTuple):
    """An IP range associated with an owner company name."""

    owner: str

    cidr: CidrRange


BATTLEYE_RANGES: tuple[NamedRange, ...] = (
    NamedRange('BattlEye', '51.89.97.102/32'),
    NamedRange('BattlEye', '51.89.99.255/32'),
)

CLOUDFLARE_RANGES: tuple[NamedRange, ...] = (NamedRange('Cloudflare', '104.16.0.0/12'),)

DEMONWARE_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Demonware Limited', '185.34.104.0/22'),
)

DISCORD_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Discord', '66.22.192.0/19'),
    NamedRange('Discord', '66.22.224.0/22'),
    NamedRange('Discord', '66.22.230.0/23'),
    NamedRange('Discord', '66.22.232.0/21'),
    NamedRange('Discord', '66.22.240.0/20'),
)

FRIEND_IT_RANGES: tuple[NamedRange, ...] = (
    NamedRange('FRIEND IT Ltd', '193.169.173.0/24'),
)


# https://www.gstatic.com/ipranges/goog.json
GOOGLE_LLC_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Google LLC', '8.8.4.0/24'),
    NamedRange('Google LLC', '8.8.8.0/24'),
    NamedRange('Google LLC', '8.34.208.0/20'),
    NamedRange('Google LLC', '8.35.192.0/20'),
    NamedRange('Google LLC', '8.228.0.0/14'),
    NamedRange('Google LLC', '8.232.0.0/14'),
    NamedRange('Google LLC', '8.236.0.0/15'),
    NamedRange('Google LLC', '23.236.48.0/20'),
    NamedRange('Google LLC', '23.251.128.0/19'),
    NamedRange('Google LLC', '34.0.0.0/15'),
    NamedRange('Google LLC', '34.2.0.0/16'),
    NamedRange('Google LLC', '34.3.0.0/23'),
    NamedRange('Google LLC', '34.3.3.0/24'),
    NamedRange('Google LLC', '34.3.4.0/24'),
    NamedRange('Google LLC', '34.3.8.0/21'),
    NamedRange('Google LLC', '34.3.16.0/20'),
    NamedRange('Google LLC', '34.3.32.0/19'),
    NamedRange('Google LLC', '34.3.64.0/18'),
    NamedRange('Google LLC', '34.4.0.0/14'),
    NamedRange('Google LLC', '34.8.0.0/13'),
    NamedRange('Google LLC', '34.16.0.0/12'),
    NamedRange('Google LLC', '34.32.0.0/11'),
    NamedRange('Google LLC', '34.64.0.0/10'),
    NamedRange('Google LLC', '34.128.0.0/10'),
    NamedRange('Google LLC', '35.184.0.0/13'),
    NamedRange('Google LLC', '35.192.0.0/14'),
    NamedRange('Google LLC', '35.196.0.0/15'),
    NamedRange('Google LLC', '35.198.0.0/16'),
    NamedRange('Google LLC', '35.199.0.0/17'),
    NamedRange('Google LLC', '35.199.128.0/18'),
    NamedRange('Google LLC', '35.200.0.0/13'),
    NamedRange('Google LLC', '35.208.0.0/12'),
    NamedRange('Google LLC', '35.224.0.0/12'),
    NamedRange('Google LLC', '35.240.0.0/13'),
    NamedRange('Google LLC', '35.252.0.0/14'),
    NamedRange('Google LLC', '64.15.112.0/20'),
    NamedRange('Google LLC', '64.233.160.0/19'),
    NamedRange('Google LLC', '66.102.0.0/20'),
    NamedRange('Google LLC', '66.249.64.0/19'),
    NamedRange('Google LLC', '70.32.128.0/19'),
    NamedRange('Google LLC', '72.14.192.0/18'),
    NamedRange('Google LLC', '74.114.24.0/21'),
    NamedRange('Google LLC', '74.125.0.0/16'),
    NamedRange('Google LLC', '104.154.0.0/15'),
    NamedRange('Google LLC', '104.196.0.0/14'),
    NamedRange('Google LLC', '104.237.160.0/19'),
    NamedRange('Google LLC', '107.167.160.0/19'),
    NamedRange('Google LLC', '107.178.192.0/18'),
    NamedRange('Google LLC', '108.59.80.0/20'),
    NamedRange('Google LLC', '108.170.192.0/18'),
    NamedRange('Google LLC', '108.177.0.0/17'),
    NamedRange('Google LLC', '130.211.0.0/16'),
    NamedRange('Google LLC', '136.22.2.0/23'),
    NamedRange('Google LLC', '136.22.4.0/23'),
    NamedRange('Google LLC', '136.22.8.0/22'),
    NamedRange('Google LLC', '136.22.160.0/20'),
    NamedRange('Google LLC', '136.22.176.0/21'),
    NamedRange('Google LLC', '136.22.184.0/23'),
    NamedRange('Google LLC', '136.22.186.0/24'),
    NamedRange('Google LLC', '136.23.48.0/20'),
    NamedRange('Google LLC', '136.23.64.0/18'),
    NamedRange('Google LLC', '136.64.0.0/11'),
    NamedRange('Google LLC', '136.107.0.0/16'),
    NamedRange('Google LLC', '136.108.0.0/14'),
    NamedRange('Google LLC', '136.112.0.0/13'),
    NamedRange('Google LLC', '136.120.0.0/22'),
    NamedRange('Google LLC', '136.124.0.0/15'),
    NamedRange('Google LLC', '142.250.0.0/15'),
    NamedRange('Google LLC', '146.148.0.0/17'),
    NamedRange('Google LLC', '162.120.128.0/17'),
    NamedRange('Google LLC', '162.216.148.0/22'),
    NamedRange('Google LLC', '162.222.176.0/21'),
    NamedRange('Google LLC', '172.110.32.0/21'),
    NamedRange('Google LLC', '172.217.0.0/16'),
    NamedRange('Google LLC', '172.253.0.0/16'),
    NamedRange('Google LLC', '173.194.0.0/16'),
    NamedRange('Google LLC', '173.255.112.0/20'),
    NamedRange('Google LLC', '192.104.160.0/23'),
    NamedRange('Google LLC', '192.158.28.0/22'),
    NamedRange('Google LLC', '192.178.0.0/15'),
    NamedRange('Google LLC', '193.186.4.0/24'),
    NamedRange('Google LLC', '199.36.154.0/23'),
    NamedRange('Google LLC', '199.36.156.0/24'),
    NamedRange('Google LLC', '199.192.112.0/22'),
    NamedRange('Google LLC', '199.223.232.0/21'),
    NamedRange('Google LLC', '207.175.0.0/16'),
    NamedRange('Google LLC', '207.223.160.0/20'),
    NamedRange('Google LLC', '208.65.152.0/22'),
    NamedRange('Google LLC', '208.68.108.0/22'),
    NamedRange('Google LLC', '208.81.188.0/22'),
    NamedRange('Google LLC', '208.117.224.0/19'),
    NamedRange('Google LLC', '209.85.128.0/17'),
    NamedRange('Google LLC', '216.58.192.0/19'),
    NamedRange('Google LLC', '216.73.80.0/20'),
    NamedRange('Google LLC', '216.239.32.0/19'),
    NamedRange('Google LLC', '216.252.220.0/22'),
)

LATITUDE_SH_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Latitude.sh', '189.1.164.0/24'),
    NamedRange('Latitude.sh LTDA', '189.1.172.0/24'),
)

MICROSOFT_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Microsoft Corporation', '20.0.0.0/9'),
    NamedRange('Microsoft Corporation', '20.128.0.0/16'),
    NamedRange('Microsoft Corporation', '20.135.0.0/16'),
    NamedRange('Microsoft Corporation', '20.136.0.0/16'),
    NamedRange('Microsoft Corporation', '20.140.0.0/15'),
    NamedRange('Microsoft Corporation', '20.143.0.0/16'),
    NamedRange('Microsoft Corporation', '20.144.0.0/14'),
    NamedRange('Microsoft Corporation', '20.157.0.0/16'),
    NamedRange('Microsoft Corporation', '20.158.0.0/15'),
    NamedRange('Microsoft Corporation', '20.160.0.0/11'),
    NamedRange('Microsoft Corporation', '20.192.0.0/10'),
    NamedRange('Microsoft Corporation', '40.74.0.0/15'),
    NamedRange('Microsoft Corporation', '40.76.0.0/14'),
    NamedRange('Microsoft Corporation', '40.80.0.0/12'),
    NamedRange('Microsoft Corporation', '40.96.0.0/12'),
    NamedRange('Microsoft Corporation', '40.112.0.0/13'),
    NamedRange('Microsoft Corporation', '40.120.0.0/14'),
    NamedRange('Microsoft Corporation', '40.124.0.0/16'),
    NamedRange('Microsoft Corporation', '40.125.0.0/17'),
    NamedRange('Microsoft Corporation', '40.126.0.0/18'),
    NamedRange('Microsoft Corporation', '40.126.128.0/17'),
    NamedRange('Microsoft Corporation', '40.127.0.0/16'),
    NamedRange('Microsoft Corporation', '52.96.0.0/12'),
    NamedRange('Microsoft Corporation', '52.112.0.0/14'),
    NamedRange('Microsoft Corporation', '52.125.0.0/16'),
    NamedRange('Microsoft Corporation', '52.126.0.0/15'),
    NamedRange('Microsoft Corporation', '52.132.0.0/14'),
    NamedRange('Microsoft Corporation', '52.136.0.0/13'),
    NamedRange('Microsoft Corporation', '52.145.0.0/16'),
    NamedRange('Microsoft Corporation', '52.146.0.0/15'),
    NamedRange('Microsoft Corporation', '52.148.0.0/14'),
    NamedRange('Microsoft Corporation', '52.152.0.0/13'),
    NamedRange('Microsoft Corporation', '52.160.0.0/11'),
    NamedRange('Microsoft Corporation', '168.61.0.0/16'),
    NamedRange('Microsoft Corporation', '168.62.0.0/15'),
)

OVH_RANGES: tuple[NamedRange, ...] = (
    NamedRange('OVH SAS', '15.204.0.0/16'),
    NamedRange('OVH SAS', '15.235.0.0/16'),
    NamedRange('OVH SAS', '37.59.0.0/16'),
    NamedRange('OVH SAS', '46.105.0.0/16'),
    NamedRange('OVH SAS', '51.68.0.0/16'),
    NamedRange('OVH SAS', '51.89.0.0/16'),
    NamedRange('OVH SAS', '54.36.0.0/14'),
    NamedRange('OVH SAS', '57.128.0.0/14'),
    NamedRange('OVH SAS', '135.125.0.0/16'),
    NamedRange('OVH SAS', '135.148.0.0/16'),
    NamedRange('OVH SAS', '141.94.0.0/15'),
    NamedRange('OVH SAS', '146.59.0.0/16'),
    NamedRange('OVH SAS', '148.113.0.0/16'),
    NamedRange('OVH SAS', '162.19.0.0/16'),
)

PLAYSTATION_SONY_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Sony Interactive (PlayStation)', '100.42.96.0/20'),
    NamedRange('Sony Interactive (PlayStation)', '104.142.128.0/17'),
)

TAKETWO_INTERACTIVE_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Take-Two Interactive Software, Inc.', '104.255.104.0/22'),
    NamedRange('Take-Two Interactive Software, Inc.', '185.56.64.0/22'),
    NamedRange('Take-Two Interactive Software, Inc.', '192.81.240.0/21'),
)

TELLAS_GREECE_RANGES: tuple[NamedRange, ...] = (NamedRange('Tellas Greece', '176.58.224.0/22'),)

TENCENT_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.128.0.0/17'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.128.128.0/19'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.128.192.0/18'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.129.0.0/16'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.130.0.0/17'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.130.128.0/18'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.130.224.0/19'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.131.0.0/18'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.131.224.0/19'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.132.0.0/18'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.132.96.0/19'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.132.128.0/17'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.133.0.0/16'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.134.0.0/16'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.135.0.0/17'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.135.128.0/18'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.135.192.0/19'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.136.0.0/13'),
    NamedRange('Tencent Building, Kejizhongyi Avenue', '43.144.0.0/15'),
)

THE_CONSTANT_COMPANY_RANGES: tuple[NamedRange, ...] = (
    NamedRange('The Constant Company, LLC', '45.32.0.0/16'),
    NamedRange('The Constant Company, LLC', '45.63.0.0/17'),
    NamedRange('The Constant Company, LLC', '45.76.0.0/15'),
    NamedRange('The Constant Company, LLC', '65.20.64.0/18'),
    NamedRange('The Constant Company, LLC', '65.20.128.0/17'),
    NamedRange('The Constant Company, LLC', '66.42.32.0/19'),
    NamedRange('The Constant Company, LLC', '66.42.64.0/18'),
    NamedRange('The Constant Company, LLC', '66.42.128.0/18'),
    NamedRange('The Constant Company, LLC', '66.42.192.0/21'),
    NamedRange('The Constant Company, LLC', '66.42.200.0/22'),
    NamedRange('The Constant Company, LLC', '66.42.204.0/23'),
    NamedRange('The Constant Company, LLC', '66.42.207.0/24'),
    NamedRange('The Constant Company, LLC', '66.42.208.0/20'),
    NamedRange('The Constant Company, LLC', '66.42.224.0/19'),
    NamedRange('The Constant Company, LLC', '95.179.128.0/17'),
    NamedRange('The Constant Company, LLC', '103.43.72.0/22'),
    NamedRange('The Constant Company, LLC', '104.156.224.0/19'),
    NamedRange('The Constant Company, LLC', '104.238.128.0/18'),
    NamedRange('The Constant Company, LLC', '107.191.32.0/19'),
    NamedRange('The Constant Company, LLC', '108.61.0.0/16'),
    NamedRange('The Constant Company, LLC', '139.84.128.0/17'),
    NamedRange('The Constant Company, LLC', '144.202.0.0/17'),
    NamedRange('The Constant Company, LLC', '167.179.64.0/18'),
    NamedRange('The Constant Company, LLC', '173.199.64.0/18'),
    NamedRange('The Constant Company, LLC', '208.85.16.0/21'),
    NamedRange('The Constant Company, LLC', '209.250.224.0/19'),
    NamedRange('The Constant Company, LLC', '217.69.0.0/20'),
)

TSEFLOW_RANGES: tuple[NamedRange, ...] = (
    NamedRange('TSeflow s.r.l.', '95.141.36.0/24'),
    NamedRange('TSeflow s.r.l.', '95.141.40.0/24'),
)

UK_MINISTRY_OF_DEFENCE_RANGES: tuple[NamedRange, ...] = (
    NamedRange('UK Ministry of Defence', '25.0.0.0/12'),
    NamedRange('UK Ministry of Defence', '25.16.0.0/13'),
    NamedRange('UK Ministry of Defence', '25.24.0.0/16'),
    NamedRange('UK Ministry of Defence', '25.25.0.0/20'),
    NamedRange('UK Ministry of Defence', '25.25.16.0/21'),
    NamedRange('UK Ministry of Defence', '25.25.24.0/24'),
    NamedRange('UK Ministry of Defence', '25.25.26.0/23'),
    NamedRange('UK Ministry of Defence', '25.25.28.0/22'),
    NamedRange('UK Ministry of Defence', '25.25.32.0/19'),
    NamedRange('UK Ministry of Defence', '25.25.64.0/18'),
    NamedRange('UK Ministry of Defence', '25.25.128.0/17'),
    NamedRange('UK Ministry of Defence', '25.26.0.0/20'),
    NamedRange('UK Ministry of Defence', '25.26.16.0/21'),
    NamedRange('UK Ministry of Defence', '25.26.24.0/23'),
    NamedRange('UK Ministry of Defence', '25.26.26.0/24'),
    NamedRange('UK Ministry of Defence', '25.26.28.0/22'),
    NamedRange('UK Ministry of Defence', '25.26.32.0/19'),
    NamedRange('UK Ministry of Defence', '25.26.64.0/18'),
    NamedRange('UK Ministry of Defence', '25.26.128.0/17'),
    NamedRange('UK Ministry of Defence', '25.27.0.0/16'),
    NamedRange('UK Ministry of Defence', '25.28.0.0/14'),
    NamedRange('UK Ministry of Defence', '25.32.0.0/11'),
    NamedRange('UK Ministry of Defence', '25.64.0.0/10'),
    NamedRange('UK Ministry of Defence', '25.128.0.0/16'),
    NamedRange('UK Ministry of Defence', '25.129.0.0/17'),
    NamedRange('UK Ministry of Defence', '25.129.128.0/18'),
    NamedRange('UK Ministry of Defence', '25.129.192.0/22'),
    NamedRange('UK Ministry of Defence', '25.129.200.0/21'),
    NamedRange('UK Ministry of Defence', '25.129.208.0/20'),
    NamedRange('UK Ministry of Defence', '25.129.224.0/19'),
    NamedRange('UK Ministry of Defence', '25.130.0.0/15'),
    NamedRange('UK Ministry of Defence', '25.132.0.0/14'),
    NamedRange('UK Ministry of Defence', '25.136.0.0/13'),
    NamedRange('UK Ministry of Defence', '25.144.0.0/12'),
    NamedRange('UK Ministry of Defence', '25.160.0.0/11'),
    NamedRange('UK Ministry of Defence', '25.192.0.0/10'),
)

US_DEPARTMENT_OF_DEFENSE_RANGES: tuple[NamedRange, ...] = (
    NamedRange('US Department of Defense', '21.0.0.0/8'),
    NamedRange('US Department of Defense', '22.0.0.0/8'),
    NamedRange('US Department of Defense', '26.0.0.0/8'),
)

VALVE_RANGES: tuple[NamedRange, ...] = (
    NamedRange('Valve Corporation', '45.121.184.0/22'),
    NamedRange('Valve Corporation', '103.10.124.0/23'),
    NamedRange('Valve Corporation', '103.28.54.0/23'),
    NamedRange('Valve Corporation', '146.66.152.0/21'),
    NamedRange('Valve Corporation', '155.133.224.0/19'),
    NamedRange('Valve Corporation', '162.254.192.0/21'),
    NamedRange('Valve Corporation', '185.25.180.0/22'),
    NamedRange('Valve Corporation', '205.196.6.0/24'),
)
