"""Metadata definitions and category order for application settings."""

from session_sniffer.constants.standalone import (
    CLASSICSTUN_PORT,
    LLMNR_PORT,
    MAX_PORT,
    MIN_PORT,
    RAKNET_PORT,
    SSDPP_PORT,
    UAUDP_PORT,
    USERIP_BACKUP_FREQUENCIES,
)
from session_sniffer.i18n import SUPPORTED_LANGUAGE_CODES, SUPPORTED_LANGUAGES
from session_sniffer.models.themes import BUILTIN_THEMES
from session_sniffer.networking.third_party_servers import ThirdPartyServers
from session_sniffer.settings._metadata_gtav import GTAV_SESSION_SETTING_METADATA
from session_sniffer.settings.meta import SettingMeta, SettingType

SETTING_CATEGORIES_ORDER: tuple[str, ...] = ('General', 'Themes', 'Shortcuts', 'Capture', 'Session', 'Columns', 'Discord', 'Web Server', 'GTA V')


SETTING_METADATA: dict[str, SettingMeta] = {
    'gui_theme_follow_system': SettingMeta(
        category='Themes', group='Active Theme', display_label='Follow System Theme', setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Automatically apply the built-in Dark or Light theme to match your operating system color scheme.\n'
            'Uncheck this option (or click any theme preview card below) to select a theme manually.'
        ),
    ),
    'gui_theme': SettingMeta(
        category='Themes', group='Active Theme', display_label='Theme', setting_type=SettingType.ENUM,
        allowed_values=tuple(theme.name for theme in BUILTIN_THEMES),
        tooltip=(
            'Color theme for the application interface when Follow System Theme is disabled.\n'
            'Click any preview card below or select from the dropdown to preview the theme live;\n'
            'click Save to persist it, or Cancel to revert to the previous theme.'
        ),
    ),
    'gui_language_follow_system': SettingMeta(
        category='General', group='Language', display_label='Follow System Language', setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Automatically match the application language to your operating system display language,\n'
            'falling back to English if unsupported. Uncheck to choose a language manually.'
        ),
    ),
    'gui_language': SettingMeta(
        category='General', group='Language', display_label='Language', setting_type=SettingType.ENUM,
        allowed_values=SUPPORTED_LANGUAGE_CODES, display_labels=SUPPORTED_LANGUAGES,
        tooltip='Display language for the application interface and embedded web panel when Follow System Language is disabled.',
    ),
    'gui_always_on_top': SettingMeta(
        category='General', group='Application Window', display_label='Always on Top',
        setting_type=SettingType.BOOLEAN, tooltip='Keep the main application window above all other windows.',
    ),
    'gui_remember_window_layout': SettingMeta(
        category='General', group='Application Window', display_label='Remember Window & Tables Layout', setting_type=SettingType.BOOLEAN,
        tooltip=(
            'Save and restore the main window tables layout (connected/disconnected splitter,\n'
            'column widths, and column order), the UserIP Manager window geometry, splitter,\n'
            'and table columns, and the Logs Manager CSV table columns across application launches.'
        ),
    ),
    'gui_interface_selection_auto_connect': SettingMeta(
        category='General', group='Interface Selection', display_label='Auto Connect',
        setting_type=SettingType.BOOLEAN, tooltip='Automatically connect to the last used interface on startup.',
    ),
    'gui_interface_selection_hide_inactive': SettingMeta(
        category='General', group='Interface Selection', display_label='Hide Inactive',
        setting_type=SettingType.BOOLEAN, tooltip='Hide network interfaces with no active traffic.',
    ),
    'gui_interface_selection_hide_neighbours': SettingMeta(
        category='General', group='Interface Selection', display_label='Hide Neighbours',
        setting_type=SettingType.BOOLEAN, tooltip='Hide neighbour entries (devices discovered via ARP on the local network).',
    ),
    'gui_ignore_screen_resolution_warning': SettingMeta(
        category='General', group='Application Popups', display_label='Ignore Screen Resolution Warning',
        setting_type=SettingType.BOOLEAN, tooltip='Ignore the warning when screen resolution is below 1024x768.', hidden=True,
    ),
    'show_discord_popup': SettingMeta(
        category='General', group='Application Popups', display_label='Show Discord Intro Popup',
        setting_type=SettingType.BOOLEAN, tooltip='Show the Discord intro popup on application startup.',
    ),
    'updater_channel': SettingMeta(
        category='General', group='Updater', display_label='Update Channel',
        setting_type=SettingType.ENUM, tooltip='Release channel to check for updates.', allowed_values=('Stable', 'Pre-release'),
    ),
    'updater_skipped_version': SettingMeta(
        category='General', group='Updater', display_label='Skipped Version', setting_type=SettingType.STRING,
        tooltip='Specific version to skip when checking for updates automatically on startup. Leave empty to not skip any version.',
    ),
    'userip_backup_frequency': SettingMeta(
        category='General', group='UserIP Databases', display_label='Backup Frequency', setting_type=SettingType.ENUM,
        tooltip='Frequency for automatically backing up UserIP databases to ZIP archives in Roaming AppData.', allowed_values=USERIP_BACKUP_FREQUENCIES,
    ),
    'userip_backup_retention_limit': SettingMeta(
        category='General', group='UserIP Databases', display_label='Backup Retention Limit', setting_type=SettingType.INTEGER_OR_ALL,
        special_value_text='Keep All', min_value=0, max_value=100, step=1,
        tooltip='Maximum number of UserIP database backup archives to retain in Roaming AppData (0 = Keep All).',
    ),
    'userip_sync_known_alts': SettingMeta(
        category='General', group='UserIP Databases', display_label='Synchronize Known Alt Accounts', setting_type=SettingType.BOOLEAN,
        tooltip='When adding or resolving usernames for an IP, automatically include known alt accounts linked to those usernames across UserIP databases.',
    ),
    'userip_auto_feed_from_usernames': SettingMeta(
        category='General', group='UserIP Databases', display_label='Auto-Feed from Usernames', setting_type=SettingType.BOOLEAN,
        tooltip='Automatically resolve and append player IPs to matching UserIP databases when detected from mod menu logs or Looky System on PC.',
    ),
    'capture_interface_name': SettingMeta(
        category='Capture', group='Interface', display_label='Interface Name', setting_type=SettingType.STRING,
        tooltip='Network interface name for packet capture.', requires_capture_restart=True, hidden=True,
    ),
    'capture_ip_address': SettingMeta(
        category='Capture', group='Interface', display_label='IP Address', setting_type=SettingType.IPV4,
        tooltip='Local IP address to bind for capture.', requires_capture_restart=True, hidden=True,
    ),
    'capture_mac_address': SettingMeta(
        category='Capture', group='Interface', display_label='MAC Address', setting_type=SettingType.MAC_ADDRESS,
        tooltip='Local MAC address override for capture.', requires_capture_restart=True, hidden=True,
    ),
    'capture_arp_spoofing': SettingMeta(
        category='Capture', group='Interface', display_label='ARP Spoofing', setting_type=SettingType.BOOLEAN,
        tooltip='Enable ARP spoofing for packet interception.', requires_capture_restart=True, hidden=True,
    ),
    'capture_feature_set': SettingMeta(
        category='Capture', group='General', display_label='Feature Set', setting_type=SettingType.ENUM,
        tooltip='Unlock specific tools and exclusive features tailored for the selected software/game.',
        requires_capture_restart=True, allowed_values=('None', 'GTA V', 'RDR2'),
    ),
    'capture_filter_process_pid': SettingMeta(
        category='Capture',
        group='General',
        display_label='Capture Scope',
        setting_type=SettingType.INTEGER_OR_ALL,
        special_value_text='Disabled',
        min_value=0,
        max_value=4194304,
        step=1,
        tooltip=(
            'Choose to capture all traffic or restrict the packet sniffer to a specific process.\n'
            "Process filtering matches the selected process's active local UDP socket ports.\n\n"
            'All background noise and other applications on your computer (such as Discord,\n'
            'browsers, Steam, or other software) will be completely ignored.\n\n'
            'When disabled (0), all UDP network traffic is captured without process filtering.\n\n'
            'Note: This setting only applies to local PC captures. When scanning an external\n'
            'device (such as a console via ARP spoofing or a secondary adapter), external process\n'
            'inspection is not possible, so this restriction is automatically bypassed.'
        ),
        requires_capture_restart=False,
    ),
    'capture_filter_process_name': SettingMeta(
        category='Capture',
        group='General',
        display_label='Target Process Name',
        setting_type=SettingType.STRING,
        tooltip='Target process executable name to track across restarts.',
        hidden=True,
    ),
    'capture_filter_process_track_by_name': SettingMeta(
        category='Capture',
        group='General',
        display_label='Track Target Process By Name',
        setting_type=SettingType.BOOLEAN,
        tooltip=(
            'When enabled, tracks the selected target process executable name across\n'
            'game restarts and edition switches (such as between GTA V Legacy and Enhanced),\n'
            'automatically re-acquiring the process ID and UDP ports.'
        ),
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
            'If a packet arrives more than this many seconds late, stale packets are automatically\n'
            'dropped to catch up with real time without restarting the capture.\n\n'
            'Recommended: 3-5 seconds — low enough to recover quickly without triggering on brief spikes.\n\n'
            'Disabled (0): Stale packets are never auto-dropped.\n'
            'Under heavy traffic the sniffer will keep falling further behind real time,\n'
            'showing outdated player data and missing live connections until traffic subsides.'
        ),
        requires_capture_restart=False,
        min_value=0,
        step=1,
        suffix=' seconds',
        special_value_text='Disabled',
    ),
    'capture_ps3_name_resolver': SettingMeta(
        category='Capture',
        group='General',
        display_label='PS3 Name Resolver',
        setting_type=SettingType.BOOLEAN,
        tooltip='Extract and resolve PlayStation usernames directly from PS3 game packet payloads and display them in the Usernames column.',
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
    'capture_filtered_isps': SettingMeta(
        category='Capture',
        group='IP Filters',
        display_label='Filtered ISPs / ASNs',
        setting_type=SettingType.STRING_TUPLE,
        tooltip=(
            'Exclude players whose ISP or ASN matches any entry in this list. Enter full or partial ISP or ASN names'
            ' (e.g. Take-Two, Amazon, Hetzner, AS15169). Add entries here or via the right-click context menu on any player.'
        ),
        requires_capture_restart=False,
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
    'gui_connected_table_sort_column': SettingMeta(
        category='Columns',
        group='Table Sorting',
        display_label='Connected Sort Column',
        setting_type=SettingType.ENUM,
        tooltip='Default column used to sort the connected-players table.',
        allowed_columns_attr='GUI_ALL_CONNECTED_COLUMNS',
    ),
    'gui_connected_table_sort_order': SettingMeta(
        category='Columns',
        group='Table Sorting',
        display_label='Connected Sort Order',
        setting_type=SettingType.ENUM,
        tooltip='Default sort order (Ascending or Descending) for the connected-players table.',
        allowed_values=('Ascending', 'Descending'),
    ),
    'gui_disconnected_table_sort_column': SettingMeta(
        category='Columns',
        group='Table Sorting',
        display_label='Disconnected Sort Column',
        setting_type=SettingType.ENUM,
        tooltip='Default column used to sort the disconnected-players table.',
        allowed_columns_attr='GUI_ALL_DISCONNECTED_COLUMNS',
    ),
    'gui_disconnected_table_sort_order': SettingMeta(
        category='Columns',
        group='Table Sorting',
        display_label='Disconnected Sort Order',
        setting_type=SettingType.ENUM,
        tooltip='Default sort order (Ascending or Descending) for the disconnected-players table.',
        allowed_values=('Ascending', 'Descending'),
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
    'gui_columns_usernames_show_notes': SettingMeta(
        category='Columns',
        group='Usernames',
        display_label='Show UserIP Notes',
        setting_type=SettingType.BOOLEAN,
        tooltip='Append UserIP database notes in parentheses to the Usernames column (e.g. "Username (Note)").',
    ),
    'gui_connected_table_rows_per_page': SettingMeta(
        category='Session',
        group='Table Pagination',
        display_label='Connected Rows Per Page',
        setting_type=SettingType.INTEGER_OR_ALL,
        special_value_text='All',
        tooltip='Maximum rows per page in the connected-players table. 0 = show all.',
        min_value=0,
        max_value=5000,
        step=10,
    ),
    'gui_disconnected_table_rows_per_page': SettingMeta(
        category='Session',
        group='Table Pagination',
        display_label='Disconnected Rows Per Page',
        setting_type=SettingType.INTEGER_OR_ALL,
        special_value_text='All',
        tooltip='Maximum rows per page in the disconnected-players table. 0 = show all.',
        min_value=0,
        max_value=5000,
        step=10,
    ),
    'gui_disconnected_players_enabled': SettingMeta(
        category='Session',
        group='Disconnected Players',
        display_label='Enabled',
        setting_type=SettingType.BOOLEAN,
        tooltip='Enable tracking and displaying disconnected players in a separate table below connected players.',
    ),
    'gui_disconnected_players_timer': SettingMeta(
        category='Session',
        group='Disconnected Players',
        display_label='Disconnected Timer',
        setting_type=SettingType.INTEGER,
        tooltip='Seconds of inactivity before a player is marked disconnected.',
        min_value=3,
        step=1,
        suffix=' seconds',
    ),
    'gui_disconnected_players_limit': SettingMeta(
        category='Session',
        group='Disconnected Players',
        display_label='Disconnected Limit',
        setting_type=SettingType.INTEGER_OR_ALL,
        special_value_text='Unlimited',
        tooltip='Maximum number of disconnected players retained in memory and table. Set to 0 for unlimited. (Max: 20000)',
        min_value=0,
        max_value=20000,
        step=50,
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
    'ping_count': SettingMeta(
        category='Session',
        group='Player Pinging',
        display_label='Ping Count',
        setting_type=SettingType.INTEGER_OR_ALL,
        min_value=0,
        max_value=10000,
        step=1,
        special_value_text='Continuous',
        tooltip='Default number of ping requests to send per target in the Ping Diagnostics window. Set to 0 for continuous.',
    ),
    'ping_interval_ms': SettingMeta(
        category='Session',
        group='Player Pinging',
        display_label='Ping Interval',
        setting_type=SettingType.INTEGER,
        min_value=50,
        max_value=10000,
        step=50,
        suffix=' ms',
        tooltip='Default interval between ping requests in milliseconds in the Ping Diagnostics window. (Min: 50 ms, Max: 10000 ms)',
    ),
    'ping_timeout_ms': SettingMeta(
        category='Session',
        group='Player Pinging',
        display_label='Ping Timeout',
        setting_type=SettingType.INTEGER,
        min_value=100,
        max_value=10000,
        step=100,
        suffix=' ms',
        tooltip='Default timeout for each ping request in milliseconds in the Ping Diagnostics window. (Min: 100 ms, Max: 10000 ms)',
    ),
    'ping_payload_bytes': SettingMeta(
        category='Session',
        group='Player Pinging',
        display_label='Ping Payload Size',
        setting_type=SettingType.INTEGER,
        min_value=0,
        max_value=65500,
        step=32,
        suffix=' bytes',
        tooltip='Default payload size in bytes for ICMP and UDP probes in the Ping Diagnostics window. (Min: 0 bytes, Max: 65500 bytes)',
    ),
    'gui_servers_color_enabled': SettingMeta(
        category='Session',
        group='Detected Servers',
        display_label='Enabled',
        setting_type=SettingType.BOOLEAN,
        tooltip='Highlight detected game servers with a custom background color in the player tables.',
    ),
    'gui_servers_color': SettingMeta(
        category='Session',
        group='Detected Servers',
        display_label='Color',
        setting_type=SettingType.COLOR,
        tooltip='Background color used to highlight detected game servers in the player tables.',
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
        secret=True,
    ),
    'discord_webhook_refresh_interval': SettingMeta(
        category='Discord',
        group='Webhook',
        display_label='Refresh Interval',
        setting_type=SettingType.INTEGER,
        tooltip='Seconds between webhook updates. Lower values risk Discord rate limits (minimum 5).',
        min_value=5,
        max_value=300,
        step=1,
        suffix=' seconds',
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
        tooltip='Turn on the built-in web server to view live session data in a browser on this PC, your phone, or other devices.',
    ),
    'webserver_host': SettingMeta(
        category='Web Server',
        group='Connection',
        display_label='Network Access',
        setting_type=SettingType.IPV4,
        tooltip='Choose whether only this PC can open the web panel (127.0.0.1), any device on your local network (0.0.0.0), or a specific IPv4 address on this PC.',
    ),
    'webserver_port': SettingMeta(
        category='Web Server',
        group='Connection',
        display_label='Port',
        setting_type=SettingType.INTEGER,
        tooltip=(
            f'Network port used by the web server ({MIN_PORT}-{MAX_PORT}). '
            'Port 80 lets you omit the port from the URL; use 8080 or 8081 if port 80 is already in use.'
        ),
        min_value=MIN_PORT,
        max_value=MAX_PORT,
        step=1,
    ),
    'webserver_username': SettingMeta(
        category='Web Server',
        group='Authentication',
        display_label='Username',
        setting_type=SettingType.STRING,
        tooltip='Optional login username required to open the web panel. Leave empty to allow access without a password.',
    ),
    'webserver_password': SettingMeta(
        category='Web Server',
        group='Authentication',
        display_label='Password',
        setting_type=SettingType.STRING,
        tooltip='Optional login password required to open the web panel. Authentication is enabled only when both username and password are set.',
        secret=True,
    ),
    'looky_enabled': SettingMeta(
        category='GTA V',
        group='Looky System',
        display_label='Enable Looky System',
        setting_type=SettingType.BOOLEAN,
        tooltip='Master toggle for all Looky System features. Disabling this prevents any Looky System API calls.',
    ),
    'looky_game_version': SettingMeta(
        category='GTA V',
        group='Looky System',
        display_label='Game Version',
        setting_type=SettingType.ENUM,
        tooltip=(
            'Version filter applied to Looky System database queries (background auto-resolve and manual lookups). '
            'Crawler requests automatically target the active running game edition.'
        ),
        allowed_values=('Both', 'Legacy', 'Enhanced'),
    ),
    'looky_api_key': SettingMeta(
        category='GTA V',
        group='Looky System',
        display_label='API Key',
        setting_type=SettingType.STRING,
        tooltip='Your Looky System Bearer token. Required for all Looky System features — auto-resolve, manual lookups, and crawler requests.',
        validator_pattern=r'[A-Za-z0-9._\-]',
        secret=True,
        min_width=600,
        max_width=600,
    ),
    'solo_session_duration': SettingMeta(
        category='GTA V', group='Solo Public Session', display_label='Solo Session Suspend Duration', setting_type=SettingType.INTEGER,
        tooltip='Duration in seconds to suspend the game process to trigger a solo public session.', min_value=6, max_value=60, step=1, suffix=' seconds',
    ),
    'shortcuts_enabled': SettingMeta(
        category='Shortcuts', group='General', display_label='Enable Shortcuts', setting_type=SettingType.BOOLEAN,
        tooltip='Master toggle for all global hotkeys and main window keyboard shortcuts. Uncheck to temporarily disable all shortcuts while keeping their assigned keybinds.',
    ),
    'shortcut_focus_search_enabled': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Enable Focus Global Search', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Focus Global Search shortcut while keeping its assigned keybind.',
    ),
    'shortcut_focus_search': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Focus Global Search', setting_type=SettingType.HOTKEY,
        tooltip='Keyboard shortcut to focus the global search bar when the main window is active. Leave empty to disable.',
    ),
    'shortcut_merge_tables_enabled': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Enable Merge / Split Tables', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Merge / Split Tables shortcut while keeping its assigned keybind.',
    ),
    'shortcut_merge_tables': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Merge / Split Tables', setting_type=SettingType.HOTKEY,
        tooltip='Keyboard shortcut to merge or split the connected and disconnected player tables when the main window is active. Leave empty to disable.',
    ),
    'shortcut_open_settings_enabled': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Enable Open Settings', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Open Settings shortcut while keeping its assigned keybind.',
    ),
    'shortcut_open_settings': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Open Settings', setting_type=SettingType.HOTKEY,
        tooltip='Keyboard shortcut to open the Settings dialog when the main window is active. Leave empty to disable.',
    ),
    'shortcut_clear_connected_enabled': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Enable Clear Connected Players', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Clear Connected Players shortcut while keeping its assigned keybind.',
    ),
    'shortcut_clear_connected': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Clear Connected Players', setting_type=SettingType.HOTKEY,
        tooltip='Keyboard shortcut to clear all connected players when the main window is active. Leave empty to disable.',
    ),
    'shortcut_clear_disconnected_enabled': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Enable Clear Disconnected Players', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Clear Disconnected Players shortcut while keeping its assigned keybind.',
    ),
    'shortcut_clear_disconnected': SettingMeta(
        category='Shortcuts', group='Main Window', display_label='Clear Disconnected Players', setting_type=SettingType.HOTKEY,
        tooltip='Keyboard shortcut to clear all disconnected players when the main window is active. Leave empty to disable.',
    ),
    'toggle_capture_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Enable Start / Stop Capture', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Start / Stop Capture global hotkey while keeping its assigned keybind.',
    ),
    'toggle_capture_hotkey': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Start / Stop Capture', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to start or stop packet capture at any time (including while in-game). Leave empty to disable.',
    ),
    'toggle_visual_notifications_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Enable Toggle Visual Notifications', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Toggle Visual Notifications global hotkey while keeping its assigned keybind.',
    ),
    'toggle_visual_notifications_hotkey': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Toggle Visual Notifications', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to mute or enable visual popup notifications at any time (including while in-game). Leave empty to disable.',
    ),
    'toggle_voice_notifications_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Enable Toggle Voice Notifications', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Toggle Voice Notifications global hotkey while keeping its assigned keybind.',
    ),
    'toggle_voice_notifications_hotkey': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Toggle Voice Notifications', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to mute or enable voice notifications at any time (including while in-game). Leave empty to disable.',
    ),
    'toggle_all_notifications_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Enable Toggle All Notifications', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Toggle All Notifications global hotkey while keeping its assigned keybind.',
    ),
    'toggle_all_notifications_hotkey': SettingMeta(
        category='Shortcuts', group='Capture & Notifications', display_label='Toggle All Notifications', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to mute or enable all visual and voice notifications at any time (including while in-game). Leave empty to disable.',
    ),
    'solo_session_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Enable Solo Public Session', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Solo Public Session global hotkey while keeping its assigned keybind.',
    ),
    'solo_session_hotkey': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Solo Public Session', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to trigger a Solo Public Session at any time (including while in-game). Leave empty to disable.',
    ),
    'suspend_process_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Enable Suspend / Resume Process', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Suspend / Resume Process global hotkey while keeping its assigned keybind.',
    ),
    'suspend_process_hotkey': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Suspend / Resume Process', setting_type=SettingType.HOTKEY,
        tooltip=(
            'Global keyboard shortcut to manually suspend or resume the active game process (GTA5 / RDR2) at any time '
            '(including while in-game). Press once to suspend, press again to resume. Leave empty to disable.'
        ),
    ),
    'player_resolver_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Enable Player Resolver', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Player Resolver global hotkey while keeping its assigned keybind.',
    ),
    'player_resolver_hotkey': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Player Resolver', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to open or focus the Player Resolver window (GTA V / RDR2). Leave empty to disable.',
    ),
    'redetect_host_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Enable Re-detect Host', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Re-detect Host global hotkey while keeping its assigned keybind.',
    ),
    'redetect_host_hotkey': SettingMeta(
        category='Shortcuts', group='Game Process & Session', display_label='Re-detect Host', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to clear and immediately re-evaluate session host detection (GTA V / RDR2). Leave empty to disable.',
    ),
    'looky_crawler_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Looky System', display_label='Enable Request Crawler in My Session', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Request Crawler in My Session global hotkey while keeping its assigned keybind.',
    ),
    'looky_crawler_hotkey': SettingMeta(
        category='Shortcuts', group='Looky System', display_label='Request Crawler in My Session', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to request the Looky System crawler bot in your current GTA5 session. Leave empty to disable.',
    ),
    'looky_rescan_hotkey_enabled': SettingMeta(
        category='Shortcuts', group='Looky System', display_label='Enable Rescan All Players', setting_type=SettingType.BOOLEAN,
        tooltip='Enable or disable the Rescan All Players global hotkey while keeping its assigned keybind.',
    ),
    'looky_rescan_hotkey': SettingMeta(
        category='Shortcuts', group='Looky System', display_label='Rescan All Players', setting_type=SettingType.HOTKEY,
        tooltip='Global keyboard shortcut to immediately refresh Looky System data for all eligible GTA5 players. Leave empty to disable.',
    ),
    **GTAV_SESSION_SETTING_METADATA,
}
