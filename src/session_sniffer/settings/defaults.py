"""Default setting values, metadata, and categories for Session Sniffer."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from session_sniffer.constants.third_party_servers import ALL_THIRD_PARTY_SERVER_NAMES, THIRD_PARTY_SERVER_DISPLAY_NAMES


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


@dataclass(frozen=True)
class SettingMeta:  # pylint: disable=too-many-instance-attributes
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
    hidden: bool = False


SETTING_CATEGORIES_ORDER: tuple[str, ...] = (
    'Launcher',
    'Capture',
    'Session',
    'Columns',
    'Discord',
)


SETTING_METADATA: dict[str, SettingMeta] = {
    'capture_interface_name': SettingMeta(
        category='Capture',
        display_label='Interface Name',
        setting_type=SettingType.STRING,
        tooltip='Network interface name for packet capture.',
        requires_capture_restart=True,
    ),
    'capture_ip_address': SettingMeta(
        category='Capture',
        display_label='IP Address',
        setting_type=SettingType.IPV4,
        tooltip='Local IP address to bind for capture.',
        requires_capture_restart=True,
    ),
    'capture_mac_address': SettingMeta(
        category='Capture',
        display_label='MAC Address',
        setting_type=SettingType.MAC_ADDRESS,
        tooltip='Local MAC address override for capture.',
        requires_capture_restart=True,
    ),
    'capture_arp_spoofing': SettingMeta(
        category='Capture',
        display_label='ARP Spoofing',
        setting_type=SettingType.BOOLEAN,
        tooltip='Enable ARP spoofing for packet interception.',
        requires_capture_restart=True,
    ),
    'capture_block_third_party_servers': SettingMeta(
        category='Capture',
        display_label='Block Third-Party Servers',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Select which third-party server IP ranges to exclude from capture.',
        requires_capture_restart=True,
        allowed_columns_attr='ALL_THIRD_PARTY_SERVERS',
        display_labels=THIRD_PARTY_SERVER_DISPLAY_NAMES,
    ),
    'capture_blocked_ips': SettingMeta(
        category='Capture',
        display_label='Blocked IPs / Ranges',
        setting_type=SettingType.IP_RANGE_TUPLE,
        tooltip='IP addresses and ranges blocked from appearing in the session. Add entries here or via the right-click context menu on any player.',
        requires_capture_restart=True,
    ),
    'capture_program_preset': SettingMeta(
        category='Capture',
        display_label='Program Preset',
        setting_type=SettingType.ENUM,
        tooltip='Predefined capture profile name.',
        requires_capture_restart=True,
        allowed_values=(
            'None',
            'GTA5',
            'Minecraft',
        ),
    ),
    'capture_overflow_timer': SettingMeta(
        category='Capture',
        display_label='Overflow Timer',
        setting_type=SettingType.INTEGER,
        tooltip='Seconds before resetting stale capture buffers.',
        requires_capture_restart=True,
        min_value=0,
        step=1,
    ),
    'capture_prepend_custom_capture_filter': SettingMeta(
        category='Capture',
        display_label='Custom Capture Filter',
        setting_type=SettingType.STRING,
        tooltip='Additional BPF filter prepended to the capture filter.',
        requires_capture_restart=True,
    ),
    'capture_prepend_custom_display_filter': SettingMeta(
        category='Capture',
        display_label='Custom Display Filter',
        setting_type=SettingType.STRING,
        tooltip='Additional display filter prepended to packet filtering.',
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
        group='General',
        display_label='Rate Graph Always on Top',
        setting_type=SettingType.BOOLEAN,
        tooltip='Keep rate graph windows above all other windows by default.',
    ),
    'gui_rate_graph_max_history': SettingMeta(
        category='Session',
        group='General',
        display_label='Rate Graph Max History',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum number of seconds of rate history stored for the Rate Graph. Determines how far back in time you can scroll.',
        min_value=60,
        max_value=7200,
        step=60,
    ),
    'gui_columns_connected_shown': SettingMeta(
        category='Columns',
        display_label='Connected Shown Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the connected-players table.',
        allowed_columns_attr='GUI_TOGGLEABLE_CONNECTED_COLUMNS',
    ),
    'gui_columns_disconnected_shown': SettingMeta(
        category='Columns',
        display_label='Disconnected Shown Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the disconnected-players table.',
        allowed_columns_attr='GUI_TOGGLEABLE_DISCONNECTED_COLUMNS',
    ),
    'gui_columns_datetime_show_date': SettingMeta(
        category='Columns',
        display_label='Show Date',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display the date portion in datetime columns.',
    ),
    'gui_columns_datetime_show_time': SettingMeta(
        category='Columns',
        display_label='Show Time',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display the time portion in datetime columns.',
    ),
    'gui_columns_datetime_show_elapsed_time': SettingMeta(
        category='Columns',
        display_label='Show Elapsed Time',
        setting_type=SettingType.BOOLEAN,
        tooltip='Display elapsed time in datetime columns.',
    ),
    'gui_columns_geo_country_append_alpha2': SettingMeta(
        category='Columns',
        display_label='Country Append Alpha-2',
        setting_type=SettingType.BOOLEAN,
        tooltip='Append ISO 3166-1 alpha-2 code to country names.',
    ),
    'gui_columns_geo_continent_append_alpha2': SettingMeta(
        category='Columns',
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
        group='Startup',
        display_label='Show Discord Intro Popup',
        setting_type=SettingType.BOOLEAN,
        tooltip='Show the Discord intro popup on application startup.',
    ),
    'discord_webhook_enabled': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Enabled',
        setting_type=SettingType.BOOLEAN,
        tooltip='Mirror the live Connected/Disconnected players tables to a Discord channel via webhook.',
    ),
    'discord_webhook_url': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Webhook URL',
        setting_type=SettingType.STRING,
        tooltip='Discord channel webhook URL (e.g. https://discord.com/api/webhooks/<id>/<token>).',
    ),
    'discord_webhook_refresh_interval': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Refresh Interval (s)',
        setting_type=SettingType.INTEGER,
        tooltip='Seconds between webhook updates. Lower values risk Discord rate limits (minimum 5).',
        min_value=5,
        max_value=300,
        step=1,
    ),
    'discord_webhook_include_connected': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Include Connected Table',
        setting_type=SettingType.BOOLEAN,
        tooltip='Post the connected-players table.',
    ),
    'discord_webhook_include_disconnected': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Include Disconnected Table',
        setting_type=SettingType.BOOLEAN,
        tooltip='Post the disconnected-players table.',
    ),
    'discord_webhook_max_rows_per_table': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Max Rows Per Table',
        setting_type=SettingType.INTEGER,
        tooltip='Maximum rows shown per table (extra rows are summarized as "… and N more").',
        min_value=1,
        max_value=100,
        step=1,
    ),
    'discord_webhook_max_connected_players': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Max Connected Players',
        setting_type=SettingType.INTEGER_OR_ALL,
        tooltip='Maximum number of connected players sent to the webhook. Set to 0 to include all players.',
        min_value=0,
        max_value=100,
        step=1,
    ),
    'discord_webhook_max_disconnected_players': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Max Disconnected Players',
        setting_type=SettingType.INTEGER_OR_ALL,
        tooltip='Maximum number of disconnected players sent to the webhook. Set to 0 to include all players.',
        min_value=0,
        max_value=100,
        step=1,
    ),
    'discord_webhook_format': SettingMeta(
        category='Discord',
        group='Server Webhook',
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
        group='Server Webhook',
        display_label='Connected Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the connected-players webhook table.',
        allowed_columns_attr='GUI_ALL_CONNECTED_COLUMNS',
    ),
    'discord_webhook_columns_disconnected': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Disconnected Columns',
        setting_type=SettingType.COLUMN_TUPLE,
        tooltip='Columns shown in the disconnected-players webhook table.',
        allowed_columns_attr='GUI_ALL_DISCONNECTED_COLUMNS',
    ),
    'discord_webhook_message_ids': SettingMeta(
        category='Discord',
        group='Server Webhook',
        display_label='Message IDs (internal)',
        setting_type=SettingType.STRING,
        tooltip='Internal storage for webhook message IDs (do not edit).',
        hidden=True,
    ),
    'updater_channel': SettingMeta(
        category='Launcher',
        group='Updater',
        display_label='Update Channel',
        setting_type=SettingType.ENUM,
        tooltip='Release channel to check for updates.',
        allowed_values=('Stable', 'Pre-release'),
    ),
}


SETTING_DEFAULTS: dict[str, Any] = {
    'capture_interface_name': None,
    'capture_ip_address': None,
    'capture_mac_address': None,
    'capture_arp_spoofing': False,
    'capture_block_third_party_servers': ALL_THIRD_PARTY_SERVER_NAMES,
    'capture_program_preset': None,
    'capture_overflow_timer': 3,
    'capture_prepend_custom_capture_filter': None,
    'capture_prepend_custom_display_filter': None,
    'capture_blocked_ips': (),
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
        'Bandwidth',
        'Hostname', 'Last Port',
        'Country', 'Region',
        'ASN / ISP',
        'Mobile', 'VPN', 'Hosting', 'Pinging',
    ),
    'gui_columns_datetime_show_date': False,
    'gui_columns_datetime_show_time': False,
    'gui_columns_datetime_show_elapsed_time': True,
    'gui_columns_geo_country_append_alpha2': True,
    'gui_columns_geo_continent_append_alpha2': True,
    'gui_connected_table_rows_per_page': 0,
    'gui_disconnected_table_rows_per_page': 0,
    'gui_disconnected_players_timer': 10,
    'discord_presence': True,
    'discord_presence_title': "Sniffin' my babies IPs",
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
    'updater_channel': 'Stable',
}
