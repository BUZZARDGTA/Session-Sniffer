"""Default setting values, metadata, and categories for Session Sniffer."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TypedDict

from session_sniffer.constants.standalone import (
    CLASSICSTUN_PORT,
    LLMNR_PORT,
    MAX_PORT,
    MIN_PORT,
    RAKNET_PORT,
    SSDPP_PORT,
    UAUDP_PORT,
    WEBSERVER_DEFAULT_HOST,
    WEBSERVER_DEFAULT_PORT,
)
from session_sniffer.networking.third_party_servers import ALL_THIRD_PARTY_SERVER_NAMES, ThirdPartyServers


class SettingType(Enum):
    """Enumeration of supported setting widget types."""

    BOOLEAN = auto()
    STRING = auto()
    INTEGER = auto()
    INTEGER_OR_ALL = auto()
    FLOAT = auto()
    ENUM = auto()
    BOOL_OR_ENUM = auto()
    IPV4 = auto()
    MAC_ADDRESS = auto()
    COLUMN_TUPLE = auto()
    IP_RANGE_TUPLE = auto()
    THIRD_PARTY_SERVERS_TUPLE = auto()


@dataclass(frozen=True, slots=True)
class SettingMeta:
    """Metadata describing a single application setting for the Settings dialog."""

    category: str
    display_label: str
    setting_type: SettingType
    tooltip: str = ''
    requires_capture_restart: bool = False
    allowed_values: tuple[str, ...] = ()
    min_value: float | None = None
    max_value: float | None = None
    step: float | None = None
    column_source: tuple[str, ...] = field(default_factory=tuple)
    allowed_columns_attr: str | None = None
    display_labels: dict[str, str] | None = None
    group: str | None = None
    subgroup: str | None = None
    hidden: bool = False
    special_value_text: str = 'All'
    max_length: int | None = None
    min_length: int | None = None
    validator_pattern: str | None = None
    secret: bool = False


SETTING_CATEGORIES_ORDER: tuple[str, ...] = (
    'Launcher',
    'Capture',
    'Session',
    'Columns',
    'Discord',
    'Web Server',
    'Looky System',
)


SETTING_METADATA: dict[str, SettingMeta] = {
    'capture_interface_name': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='Interface Name',
        setting_type=SettingType.STRING,
        tooltip='Network interface name for packet capture.',
        requires_capture_restart=True,
        hidden=True,
    ),
    'capture_ip_address': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='IP Address',
        setting_type=SettingType.IPV4,
        tooltip='Local IP address to bind for capture.',
        requires_capture_restart=True,
        hidden=True,
    ),
    'capture_mac_address': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='MAC Address',
        setting_type=SettingType.MAC_ADDRESS,
        tooltip='Local MAC address override for capture.',
        requires_capture_restart=True,
        hidden=True,
    ),
    'capture_arp_spoofing': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='ARP Spoofing',
        setting_type=SettingType.BOOLEAN,
        tooltip='Enable ARP spoofing for packet interception.',
        requires_capture_restart=True,
        hidden=True,
    ),
    'capture_feature_set': SettingMeta(
        category='Capture',
        group='General',
        display_label='Feature Set',
        setting_type=SettingType.ENUM,
        tooltip='Unlock specific tools and exclusive features tailored for the selected software/game.',
        requires_capture_restart=True,
        allowed_values=(
            'None',
            'GTA5',
        ),
    ),
    'capture_filter_exclusive_gta5_process': SettingMeta(
        category='Capture',
        group='General',
        display_label='Exclusive GTA5 Process Traffic',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            'When the GTA5 feature set is active and running locally on this PC, restrict\n'
            'the packet sniffer to only capture network traffic belonging directly to the\n'
            'detected GTA5 process PID by matching its active local UDP socket ports.\n\n'
            'Supports both GTA V Legacy (GTA5.exe) and Enhanced (GTA5_Enhanced.exe).\n\n'
            'All background noise and other applications on your computer (such as Discord,\n'
            'browsers, Steam, or other games) will be completely ignored.\n\n'
            'When GTA5 is not running locally, no player traffic is captured until GTA5 is launched.\n\n'
            'Note: This setting only applies to local PC captures. When scanning an external\n'
            'device (such as a console via ARP spoofing or a secondary adapter), external process\n'
            'inspection is not possible, so this restriction is automatically bypassed.'
        ),
        requires_capture_restart=False,
    ),
    'capture_overflow_timer': SettingMeta(
        category='Capture',
        group='General',
        display_label='Overflow Timer',
        setting_type=SettingType.INTEGER_OR_ALL,
        tooltip=(
            'When the capture falls behind real time (e.g. during a sudden spike of incoming packets),\n'
            'the capture engine buffers the backlog and delivers packets with increasing latency —\n'
            'meaning you are processing old traffic instead of live sessions.\n\n'
            'This threshold defines the maximum allowed packet latency (in seconds).\n'
            'If a packet arrives more than this many seconds late, the capture is automatically\n'
            'restarted to resync with real time and the stale backlog is discarded.\n\n'
            'Recommended: 3-5 seconds — low enough to recover quickly without triggering on brief spikes.\n\n'
            'Disabled (0): The capture never auto-restarts.\n'
            'Under heavy traffic the sniffer will keep falling further behind real time,\n'
            'showing outdated player data and missing live connections until traffic subsides or you restart manually.'
        ),
        requires_capture_restart=True,
        min_value=0,
        step=1,
        special_value_text='Disabled',
    ),
    'capture_ps3_name_resolver': SettingMeta(
        category='Capture',
        group='General',
        display_label='PS3 Name Resolver',
        setting_type=SettingType.BOOLEAN,
        tooltip='Extract and resolve PSN usernames directly from PS3 game packet payloads and display them in the Usernames column.',
        requires_capture_restart=True,
    ),
    'capture_block_third_party_servers': SettingMeta(
        category='Capture',
        group='IP Filters',
        display_label='Third-Party Providers',
        setting_type=SettingType.THIRD_PARTY_SERVERS_TUPLE,
        tooltip='Select which third-party server IP ranges to exclude from capture.',
        requires_capture_restart=True,
        allowed_columns_attr='ALL_THIRD_PARTY_SERVERS',
        display_labels={server.name: server.display_name for server in ThirdPartyServers},
    ),
    'capture_blocked_ips': SettingMeta(
        category='Capture',
        group='IP Filters',
        display_label='Custom Blocklist (IPs / Ranges)',
        setting_type=SettingType.IP_RANGE_TUPLE,
        tooltip='IP addresses and ranges blocked from appearing in the session. Add entries here or via the right-click context menu on any player.',
        requires_capture_restart=True,
    ),
    'capture_prepend_custom_capture_filter': SettingMeta(
        category='Capture',
        group='IP Filters',
        display_label='Custom Capture Filter',
        setting_type=SettingType.STRING,
        tooltip='Additional BPF filter prepended to the capture filter.',
        requires_capture_restart=True,
    ),
    'capture_filter_block_rtcp': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Payload Filters',
        display_label='Block RTCP',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Exclude RTCP (Real-Time Control Protocol) packets from capture.\n\n'
            'RTCP packets can reveal IPs of third-party services such as Discord voice servers.\n'
            'Enable this to hide those IPs; disable to see them in the session table.'
        ),
        requires_capture_restart=True,
    ),
    'capture_filter_block_ssdp': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Port Filters',
        display_label='Block SSDP',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            f'Exclude SSDP (Simple Service Discovery Protocol) packets from capture (port {SSDPP_PORT}).'
            ' These are local network device discovery broadcasts unrelated to gaming sessions.'
        ),
        requires_capture_restart=True,
    ),
    'capture_filter_block_raknet': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Port Filters',
        display_label='Block RakNet',
        setting_type=SettingType.BOOLEAN,
        tooltip=f'Exclude RakNet protocol packets from capture (port {RAKNET_PORT}). Used by Minecraft Bedrock Edition LAN discovery and similar services.',
        requires_capture_restart=True,
    ),
    'capture_filter_block_dtls': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Payload Filters',
        display_label='Block DTLS',
        setting_type=SettingType.BOOLEAN,
        tooltip='Exclude DTLS (Datagram Transport Layer Security) packets from capture. Identified by payload inspection.',
        requires_capture_restart=True,
    ),
    'capture_filter_block_uaudp': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Port Filters',
        display_label='Block UAUDP',
        setting_type=SettingType.BOOLEAN,
        tooltip=f'Exclude UAUDP (Avaya/UA audio over UDP) packets from capture (port {UAUDP_PORT}).',
        requires_capture_restart=True,
    ),
    'capture_filter_block_classicstun': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Port Filters',
        display_label='Block ClassicSTUN',
        setting_type=SettingType.BOOLEAN,
        tooltip=f'Exclude ClassicSTUN (Session Traversal Utilities for NAT) packets from capture (port {CLASSICSTUN_PORT}).',
        requires_capture_restart=True,
    ),
    'capture_filter_block_llmnr': SettingMeta(
        category='Capture',
        group='IP Filters',
        subgroup='Port Filters',
        display_label='Block LLMNR',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            f'Exclude LLMNR (Link-Local Multicast Name Resolution) packets from capture (port {LLMNR_PORT}).'
            ' These are Windows local network name resolution broadcasts unrelated to gaming sessions.'
        ),
        requires_capture_restart=True,
    ),
    'gui_interface_selection_auto_connect': SettingMeta(
        category='Launcher',
        group='Interface Selection',
        display_label='Auto Connect',
        setting_type=SettingType.BOOLEAN,
        tooltip='Automatically connect to the last used interface on startup.',
    ),
    'gui_interface_selection_hide_inactive': SettingMeta(
        category='Launcher',
        group='Interface Selection',
        display_label='Hide Inactive',
        setting_type=SettingType.BOOLEAN,
        tooltip='Hide network interfaces with no active traffic.',
    ),
    'gui_interface_selection_hide_neighbours': SettingMeta(
        category='Launcher',
        group='Interface Selection',
        display_label='Hide Neighbours',
        setting_type=SettingType.BOOLEAN,
        tooltip='Hide neighbour entries (devices discovered via ARP on the local network).',
    ),
    'gui_sessions_logging': SettingMeta(
        category='Session',
        group='Sessions Logging',
        display_label='Sessions Logging',
        setting_type=SettingType.BOOLEAN,
        tooltip='Log session data to the Sessions Logging folder.',
    ),
    'gui_sessions_logging_delete_empty_files': SettingMeta(
        category='Session',
        group='Sessions Logging',
        display_label='Delete Empty Files',
        setting_type=SettingType.BOOLEAN,
        tooltip='Automatically delete session log files with no players found.',
    ),
    'gui_sessions_logging_delete_empty_folders': SettingMeta(
        category='Session',
        group='Sessions Logging',
        display_label='Delete Empty Folders',
        setting_type=SettingType.BOOLEAN,
        tooltip='Automatically delete empty year, month, or day log folders.',
    ),
    'gui_reset_ports_on_rejoins': SettingMeta(
        category='Session',
        group='General',
        display_label='Reset Player Ports on Rejoin',
        setting_type=SettingType.BOOLEAN,
        tooltip='Clear recorded player ports when a player rejoins the session.',
    ),
    'gui_session_host_detection': SettingMeta(
        category='Session',
        group='General',
        display_label='Session Host Detection',
        setting_type=SettingType.BOOLEAN,
        tooltip='Detect and highlight the session host in the connected-players table (GTA5 feature set only).',
    ),
    'gui_columns_connected_shown': SettingMeta(
        category='Columns',
        group='Column Visibility',
        display_label='Connected Shown Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the connected-players table.',
        allowed_columns_attr='GUI_TOGGLEABLE_CONNECTED_COLUMNS',
    ),
    'gui_columns_disconnected_shown': SettingMeta(
        category='Columns',
        group='Column Visibility',
        display_label='Disconnected Shown Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the disconnected-players table.',
        allowed_columns_attr='GUI_TOGGLEABLE_DISCONNECTED_COLUMNS',
    ),
    'gui_columns_datetime_show_date': SettingMeta(
        category='Columns',
        group='Date & Time Formatting',
        display_label='Show Date',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display the date portion in datetime columns.',
    ),
    'gui_columns_datetime_show_time': SettingMeta(
        category='Columns',
        group='Date & Time Formatting',
        display_label='Show Time',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display the time portion in datetime columns.',
    ),
    'gui_columns_datetime_show_elapsed_time': SettingMeta(
        category='Columns',
        group='Date & Time Formatting',
        display_label='Show Elapsed Time',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display elapsed time in datetime columns.',
    ),
    'gui_columns_timezone_display': SettingMeta(
        category='Columns',
        group='Date & Time Formatting',
        display_label='Timezone Column Display',
        setting_type=SettingType.ENUM,
        tooltip=(
            "Controls what is shown in the Time Zone column. 'Timezone' shows only the timezone name, "
            "'Timezone + Local Time' appends the player's current local time, 'Local Time' shows only the local time."
        ),
        allowed_values=(
            'Timezone',
            'Timezone + Local Time',
            'Local Time',
        ),
    ),
    'gui_columns_geo_country_append_alpha2': SettingMeta(
        category='Columns',
        group='Geolocation Data',
        display_label='Append Country Code',
        setting_type=SettingType.BOOLEAN,
        tooltip='Append the two-letter ISO code to the country name (e.g. "United States (US)").',
    ),
    'gui_columns_geo_continent_append_alpha2': SettingMeta(
        category='Columns',
        group='Geolocation Data',
        display_label='Append Continent Code',
        setting_type=SettingType.BOOLEAN,
        tooltip='Append the two-letter ISO code to the continent name (e.g. "North America (NA)").',
    ),
    'gui_connected_table_rows_per_page': SettingMeta(
        category='Session',
        group='Table Pagination',
        display_label='Connected Rows Per Page',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum rows per page in the connected-players table. 0 = show all.',
        min_value=0,
        max_value=5000,
        step=10,
    ),
    'gui_disconnected_table_rows_per_page': SettingMeta(
        category='Session',
        group='Table Pagination',
        display_label='Disconnected Rows Per Page',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum rows per page in the disconnected-players table. 0 = show all.',
        min_value=0,
        max_value=5000,
        step=10,
    ),
    'gui_disconnected_players_timer': SettingMeta(
        category='Session',
        group='Disconnected Players',
        display_label='Disconnected Timer',
        setting_type=SettingType.INTEGER,
        tooltip='Seconds of inactivity before a player is marked disconnected.',
        min_value=3,
        step=1,
    ),
    'pinger_local': SettingMeta(
        category='Session',
        group='Player Pinging',
        display_label='Direct Ping (Fast)',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Choose whether to send ping requests directly from your PC or\n'
            'through third-party web servers.\n\n'
            'Direct Ping provides significantly faster response times with no\n'
            'third-party rate limits, but your public IP may be visible to the target.\n'
            'When disabled, ping requests are routed through external servers to help\n'
            'hide your IP, but may be slower and subject to server rate limits or downtime.'
        ),
    ),
    'gui_always_on_top': SettingMeta(
        category='Session',
        group='Application Window',
        display_label='Always on Top',
        setting_type=SettingType.BOOLEAN,
        tooltip='Keep the main application window above all other windows.',
    ),
    'gui_ignore_screen_resolution_warning': SettingMeta(
        category='Launcher',
        group='Application Popups',
        display_label='Ignore Screen Resolution Warning',
        setting_type=SettingType.BOOLEAN,
        tooltip='Ignore the warning when screen resolution is below 1024x768.',
        hidden=True,
    ),
    # ------------------------------------------------------------------
    'discord_presence': SettingMeta(
        category='Discord',
        group='Rich Presence (RPC)',
        display_label='Enabled',
        setting_type=SettingType.BOOLEAN,
        tooltip='Enable Discord Rich Presence (RPC) status updates.',
    ),
    'discord_presence_title': SettingMeta(
        category='Discord',
        group='Rich Presence (RPC)',
        display_label='Presence Title',
        setting_type=SettingType.STRING,
        tooltip='Custom title text displayed in your Discord Rich Presence status (leave empty to disable, or use 2+ characters).',
    ),
    'show_discord_popup': SettingMeta(
        category='Launcher',
        group='Application Popups',
        display_label='Show Discord Intro Popup',
        setting_type=SettingType.BOOLEAN,
        tooltip='Show the Discord intro popup on application startup.',
    ),
    'discord_webhook_enabled': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Enabled',
        setting_type=SettingType.BOOLEAN,
        tooltip='Mirror the live Connected/Disconnected players tables to a Discord channel via webhook.',
    ),
    'discord_webhook_url': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Webhook URL',
        setting_type=SettingType.STRING,
        tooltip='Discord channel webhook URL (e.g. https://discord.com/api/webhooks/<id>/<token>).',
    ),
    'discord_webhook_refresh_interval': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Refresh Interval (s)',
        setting_type=SettingType.INTEGER,
        tooltip='Seconds between webhook updates. Lower values risk Discord rate limits (minimum 5).',
        min_value=5,
        max_value=300,
        step=1,
    ),
    'discord_webhook_include_connected': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Include Connected Table',
        setting_type=SettingType.BOOLEAN,
        tooltip='Post the connected-players table.',
    ),
    'discord_webhook_include_disconnected': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Include Disconnected Table',
        setting_type=SettingType.BOOLEAN,
        tooltip='Post the disconnected-players table.',
    ),
    'discord_webhook_max_rows_per_table': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Max Rows Per Table',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum rows shown per table (extra rows are summarized as "… and N more").',
        min_value=1,
        max_value=100,
        step=1,
    ),
    'discord_webhook_max_connected_players': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Max Connected Players',
        setting_type=SettingType.INTEGER_OR_ALL,
        tooltip='Maximum number of connected players sent to the webhook. Set to 0 to include all players.',
        min_value=0,
        max_value=100,
        step=1,
    ),
    'discord_webhook_max_disconnected_players': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Max Disconnected Players',
        setting_type=SettingType.INTEGER_OR_ALL,
        tooltip='Maximum number of disconnected players sent to the webhook. Set to 0 to include all players.',
        min_value=0,
        max_value=100,
        step=1,
    ),
    'discord_webhook_format': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Output Format',
        setting_type=SettingType.ENUM,
        tooltip=(
            'Desktop: wide bordered table inside a code block (best on PC).\nMobile: per-player markdown blocks rendered inside a Discord embed (readable on phone Discord).'
        ),
        allowed_values=('Desktop', 'Mobile'),
    ),
    'discord_webhook_columns_connected': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Connected Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the connected-players webhook table.',
        allowed_columns_attr='GUI_ALL_CONNECTED_COLUMNS',
    ),
    'discord_webhook_columns_disconnected': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Disconnected Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the disconnected-players webhook table.',
        allowed_columns_attr='GUI_ALL_DISCONNECTED_COLUMNS',
    ),
    'discord_webhook_message_ids': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Message IDs (internal)',
        setting_type=SettingType.STRING,
        tooltip='Internal storage for webhook message IDs (do not edit).',
        hidden=True,
    ),
    'webserver_enabled': SettingMeta(
        category='Web Server',
        group='Connection',
        display_label='Enable Web Server',
        setting_type=SettingType.BOOLEAN,
        tooltip='Enable local web server for browser access to live session data.',
    ),
    'webserver_host': SettingMeta(
        category='Web Server',
        group='Connection',
        display_label='Host',
        setting_type=SettingType.IPV4,
        tooltip='IP address to bind the web server to (0.0.0.0 = all interfaces).',
    ),
    'webserver_port': SettingMeta(
        category='Web Server',
        group='Connection',
        display_label='Port',
        setting_type=SettingType.INTEGER,
        tooltip=f'Port number for the web server ({MIN_PORT}-{MAX_PORT}).',
        min_value=MIN_PORT,
        max_value=MAX_PORT,
        step=1,
    ),
    'webserver_username': SettingMeta(
        category='Web Server',
        group='Authentication',
        display_label='Username',
        setting_type=SettingType.STRING,
        tooltip='Optional HTTP Basic Auth username. Leave empty to disable authentication.',
    ),
    'webserver_password': SettingMeta(
        category='Web Server',
        group='Authentication',
        display_label='Password',
        setting_type=SettingType.STRING,
        tooltip='Optional HTTP Basic Auth password. Authentication is enabled only when both username and password are set.',
        secret=True,
    ),
    'updater_channel': SettingMeta(
        category='Launcher',
        group='Updater',
        display_label='Update Channel',
        setting_type=SettingType.ENUM,
        tooltip='Release channel to check for updates.',
        allowed_values=('Stable', 'Pre-release'),
    ),
    'looky_enabled': SettingMeta(
        category='Looky System',
        group='General',
        display_label='Enable Looky System',
        setting_type=SettingType.BOOLEAN,
        tooltip='Master toggle for all Looky System features. Disabling this prevents any Looky System API calls.',
    ),
    'looky_exclusive_gta5_process': SettingMeta(
        category='Looky System',
        group='General',
        display_label='Restrict to GTA5 Process',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Only perform Looky System auto-resolve queries when the GTA5 process is actively\n'
            'detected on this PC (Legacy GTA5.exe or Enhanced GTA5_Enhanced.exe), and restrict\n'
            'lookups exclusively to player IP addresses communicating with the GTA5 process.\n\n'
            'Note: This setting only applies to local PC captures. When scanning an external\n'
            'device (such as a console via ARP spoofing), external process inspection is not\n'
            'possible, so this restriction is automatically bypassed and queries run for all\n'
            'captured non-third-party player IPs.\n\n'
            'When disabled, queries run continuously regardless of GTA5 process status and include\n'
            'all captured non-third-party player IPs.'
        ),
    ),
    'looky_game_version': SettingMeta(
        category='Looky System',
        group='General',
        display_label='Game Version',
        setting_type=SettingType.ENUM,
        tooltip=(
            'Version filter applied to Looky System database queries (background auto-resolve and manual lookups). '
            'Crawler requests automatically target the active running game edition.'
        ),
        allowed_values=('Both', 'Legacy', 'Enhanced'),
    ),
    'looky_api_key': SettingMeta(
        category='Looky System',
        group='Authentication',
        display_label='API Key',
        setting_type=SettingType.STRING,
        tooltip='Your Looky System Bearer token. Required for all Looky System features — auto-resolve, manual lookups, and crawler requests.',
        validator_pattern=r'[A-Za-z0-9._\-]',
        secret=True,
    ),
}


class SettingDefaults(TypedDict):
    """Strongly-typed structure for all application setting default values."""

    capture_interface_name: str | None
    capture_ip_address: str | None
    capture_mac_address: str | None
    capture_arp_spoofing: bool
    capture_block_third_party_servers: tuple[str, ...]
    capture_feature_set: str | None
    capture_filter_exclusive_gta5_process: bool
    capture_overflow_timer: int
    capture_ps3_name_resolver: bool
    capture_prepend_custom_capture_filter: str | None
    capture_blocked_ips: tuple[str, ...]
    capture_filter_block_rtcp: bool
    capture_filter_block_ssdp: bool
    capture_filter_block_raknet: bool
    capture_filter_block_dtls: bool
    capture_filter_block_uaudp: bool
    capture_filter_block_classicstun: bool
    capture_filter_block_llmnr: bool
    gui_always_on_top: bool
    gui_interface_selection_auto_connect: bool
    gui_interface_selection_hide_inactive: bool
    gui_interface_selection_hide_neighbours: bool
    gui_sessions_logging: bool
    gui_sessions_logging_delete_empty_files: bool
    gui_sessions_logging_delete_empty_folders: bool
    gui_reset_ports_on_rejoins: bool
    gui_session_host_detection: bool
    gui_columns_connected_shown: tuple[str, ...]
    gui_columns_disconnected_shown: tuple[str, ...]
    gui_columns_datetime_show_date: bool
    gui_columns_datetime_show_time: bool
    gui_columns_datetime_show_elapsed_time: bool
    gui_columns_timezone_display: str
    gui_columns_geo_country_append_alpha2: bool
    gui_columns_geo_continent_append_alpha2: bool
    gui_connected_table_rows_per_page: int
    gui_disconnected_table_rows_per_page: int
    gui_disconnected_players_timer: int
    gui_ignore_screen_resolution_warning: bool
    pinger_local: bool
    discord_presence: bool
    discord_presence_title: str
    show_discord_popup: bool
    discord_webhook_enabled: bool
    discord_webhook_url: str | None
    discord_webhook_refresh_interval: int
    discord_webhook_include_connected: bool
    discord_webhook_include_disconnected: bool
    discord_webhook_max_rows_per_table: int
    discord_webhook_max_connected_players: int
    discord_webhook_max_disconnected_players: int
    discord_webhook_format: str
    discord_webhook_columns_connected: tuple[str, ...]
    discord_webhook_columns_disconnected: tuple[str, ...]
    discord_webhook_message_ids: str | None
    webserver_enabled: bool
    webserver_host: str
    webserver_port: int
    webserver_username: str | None
    webserver_password: str | None
    updater_channel: str | None
    looky_enabled: bool
    looky_exclusive_gta5_process: bool
    looky_game_version: str
    looky_api_key: str | None


SETTING_DEFAULTS: SettingDefaults = {
    'capture_interface_name': None,
    'capture_ip_address': None,
    'capture_mac_address': None,
    'capture_arp_spoofing': False,
    'capture_block_third_party_servers': ALL_THIRD_PARTY_SERVER_NAMES,
    'capture_feature_set': None,
    'capture_filter_exclusive_gta5_process': True,
    'capture_overflow_timer': 3,
    'capture_ps3_name_resolver': False,
    'capture_prepend_custom_capture_filter': None,
    'capture_blocked_ips': (),
    'capture_filter_block_rtcp': True,
    'capture_filter_block_ssdp': True,
    'capture_filter_block_raknet': True,
    'capture_filter_block_dtls': True,
    'capture_filter_block_uaudp': True,
    'capture_filter_block_classicstun': True,
    'capture_filter_block_llmnr': True,
    'gui_always_on_top': False,
    'gui_interface_selection_auto_connect': False,
    'gui_interface_selection_hide_inactive': True,
    'gui_interface_selection_hide_neighbours': False,
    'gui_sessions_logging': True,
    'gui_sessions_logging_delete_empty_files': False,
    'gui_sessions_logging_delete_empty_folders': False,
    'gui_reset_ports_on_rejoins': True,
    'gui_session_host_detection': True,
    'gui_columns_connected_shown': (
        'Packets',
        'PPS',
        'Bandwidth',
        'BPS',
        'Hostname',
        'Last Port',
        'Country',
        'Region',
        'ASN / ISP',
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
    ),
    'gui_columns_disconnected_shown': (
        'T. Session Time',
        'Session Time',
        'Packets',
        'Bandwidth',
        'Hostname',
        'Last Port',
        'Country',
        'Region',
        'ASN / ISP',
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
    ),
    'gui_columns_datetime_show_date': False,
    'gui_columns_datetime_show_time': False,
    'gui_columns_datetime_show_elapsed_time': True,
    'gui_columns_timezone_display': 'Timezone',
    'gui_columns_geo_country_append_alpha2': True,
    'gui_columns_geo_continent_append_alpha2': True,
    'gui_connected_table_rows_per_page': 0,
    'gui_disconnected_table_rows_per_page': 0,
    'gui_disconnected_players_timer': 10,
    'gui_ignore_screen_resolution_warning': False,
    'pinger_local': True,
    'discord_presence': True,
    'discord_presence_title': 'Sniffing session traffic',
    'show_discord_popup': True,
    'discord_webhook_enabled': False,
    'discord_webhook_url': None,
    'discord_webhook_refresh_interval': 15,
    'discord_webhook_include_connected': True,
    'discord_webhook_include_disconnected': True,
    'discord_webhook_max_rows_per_table': 25,
    'discord_webhook_max_connected_players': 0,
    'discord_webhook_max_disconnected_players': 0,
    'discord_webhook_format': 'Desktop',
    'discord_webhook_columns_connected': (
        'Usernames',
        'IP Address',
        'Country',
        'Last Port',
        'Packets',
        'Session Time',
        'Last Rejoin',
    ),
    'discord_webhook_columns_disconnected': (
        'Usernames',
        'IP Address',
        'Country',
        'Last Port',
        'Packets',
        'Session Time',
        'Last Seen',
    ),
    'discord_webhook_message_ids': None,
    'webserver_enabled': False,
    'webserver_host': WEBSERVER_DEFAULT_HOST,
    'webserver_port': WEBSERVER_DEFAULT_PORT,
    'webserver_username': None,
    'webserver_password': None,
    'updater_channel': 'Stable',
    'looky_enabled': True,
    'looky_exclusive_gta5_process': True,
    'looky_game_version': 'Both',
    'looky_api_key': None,
}
