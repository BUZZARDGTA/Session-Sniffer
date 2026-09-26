"""Constants for GUI tables, including column definitions, per-table widths, and auto-sizing constraints."""

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

# Hardcoded minimum column widths (in unscaled logical pixels) per table.
CONNECTED_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Usernames': 118,
    'First Seen': 111,
    'Last Rejoin': 119,
    'T. Session Time': 147,
    'Session Time': 132,
    'Rejoins': 96,
    'T. Packets': 112,
    'Packets': 97,
    'T. Packets Received': 170,
    'Packets Received': 155,
    'T. Packets Sent': 143,
    'Packets Sent': 128,
    'T. Min Packet Length': 181,
    'Min Packet Length': 166,
    'T. Avg Packet Length': 181,
    'Avg Packet Length': 166,
    'T. Max Packet Length': 183,
    'Max Packet Length': 168,
    'PPS': 74,
    'PPM': 79,
    'T. Bandwidth': 132,
    'Bandwidth': 117,
    'T. Download': 129,
    'Download': 114,
    'T. Upload': 110,
    'Upload': 95,
    'BPS': 74,
    'BPM': 79,
    'IP Address': 135,
    'Hostname': 140,
    'Ports': 83,
    'Last Port': 106,
    'Middle Ports': 130,
    'First Port': 108,
    'Continent': 112,
    'Country': 102,
    'Region': 94,
    'R. Code': 98,
    'City': 76,
    'District': 96,
    'ZIP Code': 106,
    'Lat': 70,
    'Lon': 74,
    'Time Zone': 117,
    'Offset': 89,
    'Currency': 106,
    'Organization': 131,
    'ISP': 70,
    'ASN / ISP': 110,
    'AS': 67,
    'ASN': 77,
    'Mobile': 94,
    'VPN': 78,
    'Hosting': 100,
    'Pinging': 99,
}

DISCONNECTED_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Usernames': 118,
    'First Seen': 111,
    'Last Rejoin': 119,
    'Last Seen': 109,
    'T. Session Time': 147,
    'Session Time': 132,
    'Rejoins': 96,
    'T. Packets': 112,
    'Packets': 97,
    'T. Packets Received': 170,
    'Packets Received': 155,
    'T. Packets Sent': 143,
    'Packets Sent': 128,
    'T. Min Packet Length': 181,
    'Min Packet Length': 166,
    'T. Avg Packet Length': 181,
    'Avg Packet Length': 166,
    'T. Max Packet Length': 183,
    'Max Packet Length': 168,
    'T. Bandwidth': 132,
    'Bandwidth': 117,
    'T. Download': 129,
    'Download': 114,
    'T. Upload': 110,
    'Upload': 95,
    'IP Address': 135,
    'Hostname': 140,
    'Ports': 83,
    'Last Port': 106,
    'Middle Ports': 130,
    'First Port': 108,
    'Continent': 112,
    'Country': 102,
    'Region': 94,
    'R. Code': 98,
    'City': 76,
    'District': 96,
    'ZIP Code': 106,
    'Lat': 70,
    'Lon': 74,
    'Time Zone': 117,
    'Offset': 89,
    'Currency': 106,
    'Organization': 131,
    'ISP': 70,
    'ASN / ISP': 110,
    'AS': 67,
    'ASN': 77,
    'Mobile': 94,
    'VPN': 78,
    'Hosting': 100,
    'Pinging': 99,
}

# Hardcoded maximum column widths for auto-sizing (in unscaled logical pixels) per table.
CONNECTED_TABLE_MAX_COLUMN_WIDTHS: dict[str, int] = {
    'Usernames': 240,
    'Ports': 140,
    'Middle Ports': 140,
}

DISCONNECTED_TABLE_MAX_COLUMN_WIDTHS: dict[str, int] = {
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
    'Process Name': 137,
    'PID': 73,
    'Executable Path': 220,
}

PORT_SCANNER_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Port': 77,
    'Protocol': 103,
    'State': 82,
    'Service': 95,
    'Latency': 99,
    'Latency (ms)': 130,
    'Banner': 160,
    'Banner / Details': 160,
}

HOTSPOT_MANAGER_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Device / Hostname': 169,
    'IPv4 Address': 135,
    'MAC Address': 150,
    'Manufacturer / Vendor': 192,
    'Connection': 121,
}

USERIP_MANAGER_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    '#': 59,
    'Usernames': 118,
    'IP': 120,
    'Range': 89,
    'Database': 108,
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
    'ISP': 70,
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
    'Reconnections': 140,
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

COUNTRY_BREAKDOWN_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Country': 102,
    'Players': 95,
}

PORT_HEATMAP_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Port': 77,
    'Count': 88,
    '% of Total': 114,
}

LOGS_MANAGER_USERIP_LOG_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Database': 108,
    'Usernames': 118,
    'IP': 120,
    'Date': 80,
    'Time': 82,
    'Country': 102,
}

LOGS_MANAGER_DETECTION_LOG_TABLE_MIN_COLUMN_WIDTHS: dict[str, int] = {
    'Detection': 111,
    'Usernames': 118,
    'IP': 120,
    'Date': 80,
    'Time': 82,
    'Country': 102,
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
