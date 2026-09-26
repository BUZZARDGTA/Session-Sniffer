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
    'Rank': 45,
    'Status': 65,
    'Usernames': 110,
    'First Seen': 75,
    'Last Rejoin': 75,
    'Last Seen': 75,
    'Rejoins': 60,
    'Sessions': 65,
    'Packets': 60,
    'T. Packets': 70,
    'Packets Received': 135,
    'T. Packets Received': 135,
    'Packets Sent': 120,
    'T. Packets Sent': 120,
    'Min Packet Length': 110,
    'T. Min Packet Length': 120,
    'Avg Packet Length': 110,
    'T. Avg Packet Length': 120,
    'Max Packet Length': 115,
    'T. Max Packet Length': 125,
    'PPS': 45,
    'PPM': 45,
    'Bandwidth': 75,
    'T. Bandwidth': 85,
    'Download': 70,
    'T. Download': 80,
    'Upload': 65,
    'T. Upload': 75,
    'BPS': 50,
    'BPM': 50,
    'Session Time': 85,
    'T. Session Time': 95,
    'Total Time': 85,
    'Duration': 80,
    'Reconnections': 85,
    'IP Address': 135,
    'IPv4 Address': 135,
    'Hostname': 140,
    'Ports': 65,
    'First Port': 70,
    'Middle Ports': 85,
    'Last Port': 70,
    'Continent': 75,
    'Country': 85,
    'Region': 80,
    'R. Code': 60,
    'City': 75,
    'District': 75,
    'ZIP Code': 65,
    'Lat': 50,
    'Lon': 50,
    'Time Zone': 80,
    'Offset': 55,
    'Currency': 65,
    'Organization': 95,
    'ISP': 60,
    'ASN / ISP': 85,
    'AS': 50,
    'ASN': 50,
    'Mobile': 50,
    'VPN': 50,
    'Hosting': 60,
    'Pinging': 60,
    'Name': 110,
    'Description': 160,
    'Type': 115,
    'Gateway IP': 135,
    'MAC Address': 150,
    'Vendor Name': 120,
    'Application / Process Name': 130,
    'Process Name': 130,
    'PID': 60,
    'Executable Path': 220,
    'Port': 55,
    'Protocol': 65,
    'State': 60,
    'Service': 80,
    'Latency': 65,
    'Latency (ms)': 65,
    'Banner': 160,
    'Banner / Details': 160,
    'Player': 140,
    'IP': 120,
    'Count': 65,
    '% of Total': 75,
    'Players': 80,
}

DEFAULT_MIN_COLUMN_WIDTH: int = 50

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
