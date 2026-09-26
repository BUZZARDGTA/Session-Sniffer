"""Module for defining constants that don't require imports or functions, using only pure Python."""

MIN_PORT: int = 1
MAX_PORT: int = 65535
WEBSERVER_DEFAULT_HOST: str = '0.0.0.0'  # noqa: S104
WEBSERVER_DEFAULT_PORT: int = 80
TITLE: str = 'Session Sniffer'
DISCORD_INVITE_URL: str = 'https://discord.gg/hMZ7MsPX7G'
LOOKY_BASE_HOST: str = 'https://looky-gta.cc'
GITHUB_REPO_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer'
GITHUB_ISSUES_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/issues'
GITHUB_RELEASES_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/releases'
GITHUB_VERSIONS_URL: str = 'https://raw.githubusercontent.com/BUZZARDGTA/Session-Sniffer/version/release_versions.json'
GITHUB_WIKI_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki'
GITHUB_WIKI_TIPS_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Tips-and-Tricks'
GITHUB_LICENSE_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/blob/main/COPYING'
GITHUB_WIKI_SCRIPT_CONFIG_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#script-settings-configuration'
GITHUB_WIKI_USERIP_CONFIG_URL: str = 'https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration'

# Shared bandwidth column → attribute-path mapping used in the table_model sort map.
BANDWIDTH_BASE_COLUMN_ATTRS: dict[str, str] = {
    'T. Bandwidth': 'bandwidth.total_exchanged',
    'Bandwidth': 'bandwidth.exchanged',
    'T. Download': 'bandwidth.total_download',
    'Download': 'bandwidth.download',
    'T. Upload': 'bandwidth.total_upload',
    'Upload': 'bandwidth.upload',
}

# Shared packet stat column names, used in Settings column lists and the search filter.
PACKET_STAT_COLUMNS: tuple[str, ...] = (
    'T. Packets',
    'Packets',
    'T. Packets Received',
    'Packets Received',
    'T. Packets Sent',
    'Packets Sent',
    'T. Min Packet Length',
    'Min Packet Length',
    'T. Avg Packet Length',
    'Avg Packet Length',
    'T. Max Packet Length',
    'Max Packet Length',
)

# Bandwidth column names derived from the attribute map above.
BANDWIDTH_STAT_COLUMNS: tuple[str, ...] = tuple(BANDWIDTH_BASE_COLUMN_ATTRS)

# Connected-table rate stat block: packets + PPS/PPM + bandwidth + BPS/BPM.
CONNECTED_RATE_STAT_COLUMNS: tuple[str, ...] = (*PACKET_STAT_COLUMNS, 'PPS', 'PPM', *BANDWIDTH_STAT_COLUMNS, 'BPS', 'BPM')

# Elapsed time + rejoin-count columns present in every all-columns list.
SESSION_TRACKING_COLUMNS: tuple[str, ...] = ('T. Session Time', 'Session Time', 'Rejoins')

# Timestamp columns that appear in both connected and disconnected rows.
DATETIME_TRACKING_COLUMNS: tuple[str, ...] = ('First Seen', 'Last Rejoin', 'Last Seen')

# Shared port column names.
PORT_COLUMNS: tuple[str, ...] = (
    'Ports',
    'Last Port',
    'Middle Ports',
    'First Port',
)

# Shared location column names.
LOCATION_COLUMNS: tuple[str, ...] = (
    'Continent',
    'Country',
    'Region',
    'R. Code',
    'City',
    'District',
    'ZIP Code',
    'Lat',
    'Lon',
    'Time Zone',
    'Offset',
    'Currency',
)

# Shared organization column names.
ORGANIZATION_COLUMNS: tuple[str, ...] = (
    'Organization',
    'ISP',
    'ASN / ISP',
    'AS',
    'ASN',
)

# Shared status column names.
STATUS_COLUMNS: tuple[str, ...] = (
    'Mobile',
    'VPN',
    'Hosting',
    'Pinging',
)

# Bandwidth columns including rates.
BANDWIDTH_RATE_STAT_COLUMNS: tuple[str, ...] = (*BANDWIDTH_STAT_COLUMNS, 'BPS', 'BPM')

# Hardcoded minimum column widths (in unscaled logical pixels).
MIN_COLUMN_WIDTHS: dict[str, int] = {
    '#': 59,
    '% of Total': 114,
    'AS': 67,
    'ASN': 77,
    'ASN / ISP': 110,
    'Application / Process Name': 222,
    'Avg Packet Length': 166,
    'BPM': 79,
    'BPS': 74,
    'Bandwidth': 117,
    'Banner': 160,
    'Banner / Details': 160,
    'City': 76,
    'Connection': 121,
    'Continent': 112,
    'Count': 88,
    'Country': 102,
    'Currency': 106,
    'Database': 108,
    'Date': 80,
    'Days': 81,
    'Description': 160,
    'Detection': 111,
    'Device / Hostname': 169,
    'District': 96,
    'Download': 114,
    'Duration': 106,
    'Executable Path': 220,
    'First Port': 108,
    'First Seen': 111,
    'Gateway IP': 135,
    'Hosting': 100,
    'Hostname': 140,
    'IP': 120,
    'IP Address': 135,
    'IPv4 Address': 135,
    'ISP': 70,
    'Last Port': 106,
    'Last Rejoin': 119,
    'Last Seen': 109,
    'Latency': 99,
    'Latency (ms)': 130,
    'Lat': 70,
    'Lon': 74,
    'MAC Address': 150,
    'Manufacturer / Vendor': 192,
    'Max Packet Length': 168,
    'Middle Ports': 130,
    'Min Packet Length': 166,
    'Mobile': 94,
    'Name': 110,
    'Offset': 89,
    'Organization': 131,
    'PID': 73,
    'PPM': 79,
    'PPS': 74,
    'Packets': 97,
    'Packets Received': 155,
    'Packets Sent': 128,
    'Period': 91,
    'Pinging': 99,
    'Player': 140,
    'Players': 95,
    'Port': 77,
    'Ports': 83,
    'Process Name': 137,
    'Protocol': 103,
    'R. Code': 98,
    'Range': 89,
    'Rank': 82,
    'Reconnections': 140,
    'Region': 94,
    'Rejoins': 96,
    'Service': 95,
    'Session Time': 132,
    'Sessions': 103,
    'State': 82,
    'Status': 89,
    'T. Avg Packet Length': 181,
    'T. Bandwidth': 132,
    'T. Download': 129,
    'T. Max Packet Length': 183,
    'T. Min Packet Length': 181,
    'T. Packets': 112,
    'T. Packets Received': 170,
    'T. Packets Sent': 143,
    'T. Session Time': 147,
    'T. Upload': 110,
    'Time': 82,
    'Time Zone': 117,
    'Total Time': 117,
    'Type': 115,
    'Unique Days': 129,
    'Upload': 95,
    'Usernames': 118,
    'VPN': 78,
    'Vendor Name': 135,
    'ZIP Code': 106,
}

DEFAULT_MIN_COLUMN_WIDTH: int = 60

# Hardcoded maximum column widths for auto-sizing (in unscaled logical pixels).
MAX_COLUMN_WIDTHS: dict[str, int] = {
    'Usernames': 240,
    'Ports': 140,
    'Middle Ports': 140,
}


# Flexible columns that absorb remaining table viewport space to eliminate empty right-hand space.
FLEXIBLE_STRETCH_COLUMNS: tuple[str, ...] = (
    'Usernames',
    'Hostname',
    'Country',
    'Region',
    'City',
    'District',
    'Continent',
    'Organization',
    'ISP',
    'ASN / ISP',
    'AS',
    'ASN',
    'Description',
    'Vendor Name',
    'Name',
    'Application / Process Name',
    'Process Name',
    'Executable Path',
    'Banner',
    'Banner / Details',
    'Service',
    'Player',
)

# Relative distribution weights for flexible stretch columns when allocating extra viewport width.
FLEXIBLE_COLUMN_WEIGHTS: dict[str, int] = {
    'Usernames': 3,
    'Hostname': 3,
    'Description': 3,
    'Vendor Name': 2,
    'Name': 1,
    'Application / Process Name': 2,
    'Process Name': 2,
    'Executable Path': 3,
    'Banner': 3,
    'Banner / Details': 3,
    'Service': 1,
    'Player': 3,
    'Organization': 2,
    'ISP': 2,
    'ASN / ISP': 2,
    'AS': 1,
    'ASN': 1,
    'Country': 1,
    'Region': 1,
    'City': 1,
    'District': 1,
    'Continent': 1,
}


# Columns omitted from chooser drop-downs because they are either fixed or not useful to search directly.
SEARCHABLE_COLUMN_EXCLUSIONS: frozenset[str] = frozenset(
    {
        *DATETIME_TRACKING_COLUMNS,
        *SESSION_TRACKING_COLUMNS,
        *CONNECTED_RATE_STAT_COLUMNS,
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
        'Lat',
        'Lon',
        'Offset',
    },
)


# Port numbers used by protocol-specific capture filters.
SSDPP_PORT: int = 1900
RAKNET_PORT: int = 19132
UAUDP_PORT: int = 4569
CLASSICSTUN_PORT: int = 3478
LLMNR_PORT: int = 5355

# Setting names for payload-inspection-based capture filters.
CAPTURE_FILTER_BLOCK_PAYLOAD_SETTINGS: tuple[str, ...] = (
    'CAPTURE_FILTER_BLOCK_RTCP',
    'CAPTURE_FILTER_BLOCK_DTLS',
)

# Setting names for port-based capture filters.
CAPTURE_FILTER_BLOCK_PORT_SETTINGS: tuple[str, ...] = (
    'CAPTURE_FILTER_BLOCK_SSDP',
    'CAPTURE_FILTER_BLOCK_RAKNET',
    'CAPTURE_FILTER_BLOCK_UAUDP',
    'CAPTURE_FILTER_BLOCK_CLASSICSTUN',
    'CAPTURE_FILTER_BLOCK_LLMNR',
)

# Combined tuple of all capture filter block settings (payload + port).
CAPTURE_FILTER_BLOCK_SETTINGS: tuple[str, ...] = (
    *CAPTURE_FILTER_BLOCK_PAYLOAD_SETTINGS,
    *CAPTURE_FILTER_BLOCK_PORT_SETTINGS,
)

# Maximum duration in seconds for suspend rules and actions.
MAX_SUSPEND_DURATION_SECONDS: int = 3600

# Default display color for detected server table rows.
DEFAULT_DETECTED_SERVER_COLOR: str = 'purple'
