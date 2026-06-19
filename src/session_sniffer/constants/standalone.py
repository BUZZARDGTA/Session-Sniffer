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

# Shared bandwidth column → attribute-path mapping (first 6 entries identical in both
# table_model sort map and Settings.GUI_COLUMNS_MAPPING; BPS/BPM paths differ per usage).
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
