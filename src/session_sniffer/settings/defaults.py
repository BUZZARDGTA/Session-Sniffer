"""Default setting values, metadata, and categories for Session Sniffer."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from session_sniffer.constants.standalone import (
    CLASSICSTUN_PORT,
    GTA5_PACKET_SIZE_MAX,
    GTA5_PACKET_SIZE_MIN,
    LLMNR_PORT,
    MAX_PORT,
    MIN_PORT,
    MINECRAFT_PACKET_SIZE_MAX,
    MINECRAFT_PACKET_SIZE_MIN,
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
    ),
    'capture_ip_address': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='IP Address',
        setting_type=SettingType.IPV4,
        tooltip='Local IP address to bind for capture.',
        requires_capture_restart=True,
    ),
    'capture_mac_address': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='MAC Address',
        setting_type=SettingType.MAC_ADDRESS,
        tooltip='Local MAC address override for capture.',
        requires_capture_restart=True,
    ),
    'capture_arp_spoofing': SettingMeta(
        category='Capture',
        group='Interface',
        display_label='ARP Spoofing',
        setting_type=SettingType.BOOLEAN,
        tooltip='Enable ARP spoofing for packet interception.',
        requires_capture_restart=True,
    ),
    'capture_game_preset': SettingMeta(
        category='Capture',
        group='General',
        display_label='Game Preset',
        setting_type=SettingType.ENUM,
        tooltip='Predefined capture profile name.',
        requires_capture_restart=True,
        allowed_values=(
            'None',
            'GTA5',
            'Minecraft',
        ),
    ),
    'capture_filter_preset_packet_size': SettingMeta(
        category='Capture',
        group='General',
        display_label='Preset Packet Size Filter',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            'When a Game Preset is active, restrict capture to packets within the expected size range for that game.\n'
            'This helps focus exclusively on P2P traffic by blocking packets outside these ranges.\n\n'
            f'GTA5: {GTA5_PACKET_SIZE_MIN} - {GTA5_PACKET_SIZE_MAX} bytes\n'
            f'Minecraft Bedrock: {MINECRAFT_PACKET_SIZE_MIN} - {MINECRAFT_PACKET_SIZE_MAX} bytes\n\n'
            'Note: these ranges were designed for P2P sessions. If you are scanning game servers,\n'
            'some of their packets may fall outside these bounds and get filtered out.\n'
            'Disable this if you want the preset behaviour (e.g. third-party server blocks, host detection)\n'
            'without the size-based packet filter.'
        ),
        requires_capture_restart=True,
    ),
    'capture_overflow_timer': SettingMeta(
        category='Capture',
        group='General',
        display_label='Overflow Timer',
        setting_type=SettingType.INTEGER_OR_ALL,
        tooltip=(
            'When the capture falls behind real time (e.g. during a sudden spike of incoming packets),\n'
            'scapy buffers the backlog and delivers packets with increasing latency —\n'
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
    'capture_block_third_party_servers': SettingMeta(
        category='Capture',
        group='IP Filters',
        display_label='Block Third-Party Servers',
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
        group='General',
        display_label='Sessions Logging',
        setting_type=SettingType.BOOLEAN,
        tooltip='Log session data to the Sessions Logging folder.',
    ),
    'gui_reset_ports_on_rejoins': SettingMeta(
        category='Session',
        group='General',
        display_label='Reset Ports on Rejoins',
        setting_type=SettingType.BOOLEAN,
        tooltip='Clear recorded ports when a player rejoins.',
    ),
    'gui_session_host_detection': SettingMeta(
        category='Session',
        group='General',
        display_label='Session Host Detection',
        setting_type=SettingType.BOOLEAN,
        tooltip='Detect and highlight the session host in the connected-players table (GTA5 preset only).',
    ),
    'gui_rate_graph_always_on_top': SettingMeta(
        category='Session',
        group='Rate Graph',
        display_label='Rate Graph Always on Top',
        setting_type=SettingType.BOOLEAN,
        tooltip='Keep rate graph windows above all other windows by default.',
    ),
    'gui_rate_graph_max_history': SettingMeta(
        category='Session',
        group='Rate Graph',
        display_label='Rate Graph Max History',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum number of seconds of rate history stored for the Rate Graph. Determines how far back in time you can scroll.',
        min_value=60,
        max_value=7200,
        step=60,
    ),
    'gui_columns_connected_shown': SettingMeta(
        category='Columns',
        group='Toggle Columns',
        display_label='Connected Shown Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the connected-players table.',
        allowed_columns_attr='GUI_TOGGLEABLE_CONNECTED_COLUMNS',
    ),
    'gui_columns_disconnected_shown': SettingMeta(
        category='Columns',
        group='Toggle Columns',
        display_label='Disconnected Shown Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the disconnected-players table.',
        allowed_columns_attr='GUI_TOGGLEABLE_DISCONNECTED_COLUMNS',
    ),
    'gui_columns_datetime_show_date': SettingMeta(
        category='Columns',
        group='Datetime',
        display_label='Show Date',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display the date portion in datetime columns.',
    ),
    'gui_columns_datetime_show_time': SettingMeta(
        category='Columns',
        group='Datetime',
        display_label='Show Time',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display the time portion in datetime columns.',
    ),
    'gui_columns_datetime_show_elapsed_time': SettingMeta(
        category='Columns',
        group='Datetime',
        display_label='Show Elapsed Time',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display elapsed time in datetime columns.',
    ),
    'gui_columns_timezone_display': SettingMeta(
        category='Columns',
        group='Datetime',
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
        group='Geo',
        display_label='Country Append Alpha-2',
        setting_type=SettingType.BOOLEAN,
        tooltip='Append ISO 3166-1 alpha-2 code to country names.',
    ),
    'gui_columns_geo_continent_append_alpha2': SettingMeta(
        category='Columns',
        group='Geo',
        display_label='Continent Append Alpha-2',
        setting_type=SettingType.BOOLEAN,
        tooltip='Append two-letter code to continent names.',
    ),
    'gui_connected_table_rows_per_page': SettingMeta(
        category='Session',
        group='Pagination',
        display_label='Connected Rows Per Page',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum rows per page in the connected-players table. 0 = show all.',
        min_value=0,
        max_value=5000,
        step=10,
    ),
    'gui_disconnected_table_rows_per_page': SettingMeta(
        category='Session',
        group='Pagination',
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
        group='Popups',
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
            'Desktop: wide bordered table inside a code block (best on PC).\n'
            'Mobile: per-player markdown blocks rendered inside a Discord embed (readable on phone Discord).'
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
    'looky_auto_resolve': SettingMeta(
        category='Looky System',
        group='General',
        display_label='Auto-resolve Usernames',
        setting_type=SettingType.BOOLEAN,
        tooltip='Continuously resolve player usernames via Looky System in the background and display them in the Usernames column.',
    ),
    'looky_game_version': SettingMeta(
        category='Looky System',
        group='General',
        display_label='Game Version',
        setting_type=SettingType.ENUM,
        tooltip='Version filter applied to all Looky System API queries. Affects both background auto-resolve and manual Looky System Lookup.',
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


SETTING_DEFAULTS: dict[str, Any] = {
    'capture_interface_name': None,
    'capture_ip_address': None,
    'capture_mac_address': None,
    'capture_arp_spoofing': False,
    'capture_block_third_party_servers': ALL_THIRD_PARTY_SERVER_NAMES,
    'capture_game_preset': None,
    'capture_filter_preset_packet_size': True,
    'capture_overflow_timer': 3,
    'capture_prepend_custom_capture_filter': None,
    'capture_blocked_ips': (),
    'capture_filter_block_rtcp': False,
    'capture_filter_block_ssdp': True,
    'capture_filter_block_raknet': True,
    'capture_filter_block_dtls': True,
    'capture_filter_block_uaudp': True,
    'capture_filter_block_classicstun': True,
    'capture_filter_block_llmnr': True,
    'gui_interface_selection_auto_connect': False,
    'gui_interface_selection_hide_inactive': True,
    'gui_interface_selection_hide_neighbours': False,
    'gui_sessions_logging': True,
    'gui_reset_ports_on_rejoins': True,
    'gui_session_host_detection': True,
    'gui_rate_graph_always_on_top': True,
    'gui_rate_graph_max_history': 3600,
    'gui_columns_connected_shown': (
        'Packets', 'PPS',
        'Min Packet Length', 'Avg Packet Length', 'Max Packet Length',
        'Bandwidth',
        'BPS',
        'Hostname', 'Last Port',
        'Country', 'Region',
        'ASN / ISP',
        'Mobile', 'VPN', 'Hosting', 'Pinging',
    ),
    'gui_columns_disconnected_shown': (
        'T. Session Time', 'Session Time',
        'Packets',
        'Min Packet Length', 'Avg Packet Length', 'Max Packet Length',
        'Bandwidth',
        'Hostname', 'Last Port',
        'Country', 'Region',
        'ASN / ISP',
        'Mobile', 'VPN', 'Hosting', 'Pinging',
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
        'Usernames', 'IP Address', 'Country', 'Last Port', 'Packets', 'Session Time', 'Last Rejoin',
    ),
    'discord_webhook_columns_disconnected': (
        'Usernames', 'IP Address', 'Country', 'Last Port', 'Packets', 'Session Time', 'Last Seen',
    ),
    'discord_webhook_message_ids': None,
    'webserver_enabled': False,
    'webserver_host': WEBSERVER_DEFAULT_HOST,
    'webserver_port': WEBSERVER_DEFAULT_PORT,
    'webserver_username': None,
    'webserver_password': None,
    'updater_channel': 'Stable',
    'looky_enabled': True,
    'looky_auto_resolve': True,
    'looky_game_version': 'Both',
    'looky_api_key': None,
}
