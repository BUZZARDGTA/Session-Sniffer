"""Constants for GUI tables, including column definitions, per-table widths, and auto-sizing constraints."""

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

# Shared bandwidth column names, used in Settings column lists and the search filter.
BANDWIDTH_STAT_COLUMNS: tuple[str, ...] = (
    'T. Bandwidth',
    'Bandwidth',
    'T. Download',
    'Download',
    'T. Upload',
    'Upload',
)

# Connected-table rate stat block: packets + PPS/PPM + bandwidth + BPS/BPM.
CONNECTED_RATE_STAT_COLUMNS: tuple[str, ...] = (*PACKET_STAT_COLUMNS, 'PPS', 'PPM', *BANDWIDTH_STAT_COLUMNS, 'BPS', 'BPM')

# Elapsed time + rejoin-count columns present in every all-columns list.
SESSION_TRACKING_COLUMNS: tuple[str, ...] = ('T. Session Time', 'Session Time', 'Biggest Session Time', 'Lowest Session Time', 'Rejoins')

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

# Numeric quantity columns right-aligned in session tables for easier vertical scanning.
NUMERIC_RIGHT_ALIGNED_COLUMNS: frozenset[str] = frozenset({
    'Rejoins',
    *CONNECTED_RATE_STAT_COLUMNS,
    'Lat',
    'Lon',
    'Offset',
})

# Hardcoded minimum column widths (in unscaled logical pixels) for columns whose content exceeds their header width.
SESSION_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Usernames': 118,
    'First Seen': 111,
    'Last Rejoin': 119,
    'Last Seen': 109,
    'T. Session Time': 147,
    'Session Time': 132,
    'Biggest Session Time': 175,
    'Lowest Session Time': 165,
    'IP Address': 135,
    'Hostname': 140,
    'Middle Ports': 130,
    'Continent': 112,
    'Country': 102,
    'Region': 94,
    'City': 76,
    'District': 96,
    'ZIP Code': 106,
    'Time Zone': 117,
    'Offset': 89,
    'Currency': 106,
    'Organization': 131,
    'ISP': 140,
    'ASN / ISP': 160,
    'AS': 95,
    'ASN': 120,
}

# Hardcoded maximum column widths for auto-sizing (in unscaled logical pixels) per table.
SESSION_TABLE_MAX_COLUMN_WIDTHS: dict[str, int] = {
    'Usernames': 240,
    'Ports': 140,
    'Middle Ports': 140,
}

INTERFACE_SELECTION_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Name': 110,
    'Description': 160,
    'Type': 115,
    'Packets Sent': 128,
    'Packets Received': 155,
    'Gateway IP': 135,
    'IP Address': 135,
    'MAC Address': 150,
    'Vendor Name': 135,
}

TARGET_PROCESS_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Application / Process Name': 222,
    'PID': 73,
    'Executable Path': 220,
}

PORT_SCANNER_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Port': 77,
    'Protocol': 103,
    'State': 82,
    'Service': 95,
    'Latency (ms)': 130,
    'Banner / Details': 160,
}

PLAYER_LEADERBOARD_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Rank': 82,
    'Status': 89,
    'Usernames': 118,
    'IP Address': 135,
    'Sessions': 103,
    'Days': 81,
    'First Seen': 111,
    'Last Seen': 109,
    'Country': 102,
    'ISP': 140,
    'Mobile': 94,
    'VPN': 78,
    'Hosting': 100,
}

LEADERBOARD_SEEN_STATS_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Period': 91,
    'Unique Days': 129,
    'Sessions': 103,
}

RECONNECT_FREQUENCY_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Rejoins': 96,
    'IP': 120,
    'Usernames': 118,
}

SESSION_DURATION_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Duration': 106,
    'IP': 120,
    'Usernames': 118,
}

SESSION_TIMELINE_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Player': 140,
    'Status': 89,
    'First Seen': 111,
    'Last Rejoin': 119,
    'Last Seen': 109,
    'Session Time': 132,
    'Total Time': 117,
    'Rejoins': 96,
}

PLAYER_JOINS_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    '#': 45,
    'Status': 89,
    'Rejoin Time': 120,
    'Last Seen': 120,
    'Session Time': 110,
    'First Port': 80,
    'Middle Ports': 110,
    'Last Port': 80,
    'Ports': 90,
    'Packets': 75,
    'Packets Received': 115,
    'Packets Sent': 95,
    'Min Packet Length': 120,
    'Avg Packet Length': 120,
    'Max Packet Length': 120,
    'Bandwidth': 90,
    'Download': 90,
    'Upload': 85,
}

COUNTRY_BREAKDOWN_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Country': 102,
    'Players': 95,
}

PORT_HEATMAP_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Port': 77,
    'Count': 88,
    '% of Total': 114,
}

DEFAULT_MIN_COLUMN_WIDTH: int = 60

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
    'Executable Path',
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
    'Executable Path': 3,
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

# Mapping of column-formatting setting keys to their affected table column names.
COLUMN_FORMAT_SETTING_TO_COLUMNS: dict[str, tuple[str, ...]] = {
    'gui_columns_timezone_display': ('Time Zone',),
    'gui_columns_datetime_show_date': DATETIME_TRACKING_COLUMNS,
    'gui_columns_datetime_show_time': DATETIME_TRACKING_COLUMNS,
    'gui_columns_datetime_show_elapsed_time': DATETIME_TRACKING_COLUMNS,
    'gui_columns_geo_country_append_alpha2': ('Country',),
    'gui_columns_geo_continent_append_alpha2': ('Continent',),
    'gui_columns_usernames_show_notes': ('Usernames',),
}

# Canonical English tooltip descriptions for session table column headers (translated via `tr()` at display time).
GUI_COLUMN_HEADERS_TOOLTIPS: dict[str, str] = {
    'Usernames': (
        'Displays the usernames of players, ordered from most recent to oldest seen (left to right).\n\n'
        'Usernames are resolved from your UserIP database files, Looky System, and mod menu logs.\n'
        'For GTA V PC users who have used the Session Sniffer mod menu plugin,\n'
        'it automatically resolves usernames while the plugin is running,\n'
        'or shows previously resolved players that were seen by the plugin.'
    ),
    'First Seen': 'The very first time the player was observed across all sessions.',
    'Last Rejoin': 'The most recent time the player rejoined your session.',
    'Last Seen': 'The most recent time the player was active in your session.',
    'T. Session Time': 'The total amount of time the player has been playing across all sessions.',
    'Session Time': 'The amount of time the player was playing in the last session before disconnecting.',
    'Biggest Session Time': 'The longest session duration for the player across all sessions.',
    'Lowest Session Time': 'The shortest session duration for the player across all sessions.',
    'Rejoins': 'The number of times the player has left and joined again your session across all sessions.',
    'T. Packets': 'The total number of packets exchanged with the player across all sessions.',
    'Packets': 'The number of packets exchanged (Received + Sent) with the player during the current session.',
    'T. Packets Received': 'The total number of packets received from the player across all sessions.',
    'Packets Received': 'The number of packets received from the player during the current session.',
    'T. Packets Sent': 'The total number of packets sent to the player across all sessions.',
    'Packets Sent': 'The number of packets sent to the player during the current session.',
    'T. Min Packet Length': 'The minimum packet length (in bytes) exchanged with the player across all sessions.',
    'Min Packet Length': 'The minimum packet length (in bytes) exchanged with the player during the current session.',
    'T. Avg Packet Length': 'The average packet length (in bytes) exchanged with the player across all sessions.',
    'Avg Packet Length': 'The average packet length (in bytes) exchanged with the player during the current session.',
    'T. Max Packet Length': 'The maximum packet length (in bytes) exchanged with the player across all sessions.',
    'Max Packet Length': 'The maximum packet length (in bytes) exchanged with the player during the current session.',
    'PPS': 'The number of Packets exchanged (Received + Sent) with the player Per Second during the current session.',
    'PPM': 'The number of Packets exchanged (Received + Sent) with the player Per Minute during the current session.',
    'T. Bandwidth': 'The total amount of bytes transferred (Download + Upload) with the player across all sessions.',
    'Bandwidth': 'The amount of bytes transferred (Download + Upload) with the player during the current session.',
    'T. Download': 'The total amount of bytes downloaded from the player across all sessions.',
    'Download': 'The amount of bytes downloaded from the player during the current session.',
    'T. Upload': 'The total amount of bytes uploaded to the player across all sessions.',
    'Upload': 'The amount of bytes uploaded to the player during the current session.',
    'BPS': 'The number of Bytes transferred (Downloaded + Uploaded) with the player Per Second during the current session.',
    'BPM': 'The number of Bytes transferred (Downloaded + Uploaded) with the player Per Minute during the current session.',
    'IP Address': 'The IP address of the player.',
    'Hostname': "The domain name associated with the player's IP address, resolved through a reverse DNS lookup.",
    'Ports': 'All ports used by the player, ordered from first to last discovered (left to right).',
    'Last Port': "The port used by the player's last captured packet.",
    'Middle Ports': 'The ports used by the player between the first and last captured packets, ordered from last to first discovered (left to right).',
    'First Port': "The port used by the player's first captured packet.",
    'Continent': "The continent of the player's IP location.",
    'Country': "The country of the player's IP location.",
    'Region': "The region of the player's IP location.",
    'R. Code': "The region code of the player's IP location.",
    'City': "The city associated with the player's IP location (typically representing the ISP or an intermediate location, not the player's home address city).",
    'District': "The district of the player's IP location.",
    'ZIP Code': "The ZIP/postal code of the player's IP location.",
    'Lat': "The latitude of the player's IP location.",
    'Lon': "The longitude of the player's IP location.",
    'Time Zone': "The time zone of the player's IP location.",
    'Offset': "The time zone offset of the player's IP location.",
    'Currency': "The currency associated with the player's IP location.",
    'Organization': "The organization associated with the player's IP address.",
    'ISP': "The Internet Service Provider of the player's IP address.",
    'ASN / ISP': 'The Autonomous System Number or Internet Service Provider of the player.',
    'AS': "The Autonomous System code of the player's IP.",
    'ASN': "The Autonomous System Number name associated with the player's IP.",
    'Mobile': 'Indicates if the player is using a mobile network (e.g., through a cellular hotspot or mobile data).',
    'VPN': 'Indicates if the player is using a VPN, Proxy, or Tor relay.',
    'Hosting': 'Indicates if the player is using a hosting provider (similar to VPN).',
    'Pinging': 'Indicates if the player is being actively pinged.',
}
