"""Default setting values and type definitions for Session Sniffer."""

from typing import TypedDict

from session_sniffer.constants.standalone import (
    DEFAULT_DETECTED_SERVER_COLOR,
    WEBSERVER_DEFAULT_HOST,
    WEBSERVER_DEFAULT_PORT,
)
from session_sniffer.networking.third_party_servers import ALL_THIRD_PARTY_SERVER_NAMES


class SettingDefaults(TypedDict):
    """Strongly-typed structure for all application setting default values."""

    capture_interface_name: str | None
    capture_ip_address: str | None
    capture_mac_address: str | None
    capture_arp_spoofing: bool
    capture_block_third_party_servers: tuple[str, ...]
    capture_feature_set: str | None
    capture_filter_process_pid: int
    capture_filter_process_name: str | None
    capture_filter_process_track_by_name: bool
    capture_overflow_timer: int
    capture_ps3_name_resolver: bool
    capture_prepend_custom_capture_filter: str | None
    capture_blocked_ips: tuple[str, ...]
    capture_filtered_isps: tuple[str, ...]
    capture_filter_block_rtcp: bool
    capture_filter_block_ssdp: bool
    capture_filter_block_raknet: bool
    capture_filter_block_dtls: bool
    capture_filter_block_uaudp: bool
    capture_filter_block_classicstun: bool
    capture_filter_block_llmnr: bool
    gui_always_on_top: bool
    gui_remember_window_layout: bool
    gui_servers_color_enabled: bool
    gui_servers_color: str
    gui_interface_selection_auto_connect: bool
    gui_interface_selection_hide_inactive: bool
    gui_interface_selection_hide_neighbours: bool
    gui_sessions_logging: bool
    gui_sessions_logging_delete_empty_files: bool
    gui_sessions_logging_delete_empty_folders: bool
    gui_reset_ports_on_rejoins: bool
    gui_session_host_detection: bool
    gui_session_host_icon: bool
    gui_columns_connected_shown: tuple[str, ...]
    gui_columns_disconnected_shown: tuple[str, ...]
    gui_columns_datetime_show_date: bool
    gui_columns_datetime_show_time: bool
    gui_columns_datetime_show_elapsed_time: bool
    gui_columns_timezone_display: str
    gui_columns_geo_country_append_alpha2: bool
    gui_columns_geo_continent_append_alpha2: bool
    gui_connected_table_rows_per_page: int
    gui_connected_table_sort_column: str
    gui_connected_table_sort_order: str
    gui_disconnected_players_enabled: bool
    gui_disconnected_table_rows_per_page: int
    gui_disconnected_table_sort_column: str
    gui_disconnected_table_sort_order: str
    gui_disconnected_players_timer: int
    gui_disconnected_players_limit: int
    gui_ignore_screen_resolution_warning: bool
    voice_notifications_enabled: bool
    pinger_local: bool
    ping_count: int
    ping_interval_ms: int
    ping_timeout_ms: int
    ping_payload_bytes: int
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
    updater_skipped_version: str | None
    userip_backup_frequency: str
    userip_backup_retention_limit: int
    userip_sync_known_alts: bool
    looky_enabled: bool
    looky_exclusive_gta5_process: bool
    looky_game_version: str
    looky_api_key: str | None
    high_rate_monitor_mode: str
    high_rate_monitor_icon: bool
    high_rate_monitor_run_in_background: bool
    high_rate_monitor_auto_select: bool
    solo_session_duration: int
    high_rate_monitor_pps_threshold: int
    high_rate_monitor_bps_threshold: int
    high_rate_monitor_duration_threshold: int
    player_identifier_icon: bool
    player_identifier_spike_zscore: float
    player_identifier_spike_seconds: int
    player_identifier_baseline_seconds: int
    player_identifier_contamination_zscore: float
    player_identifier_contamination_seconds: int
    player_identifier_contamination_min_samples: int
    player_identifier_baseline_timeout: int
    player_identifier_session_drift_zscore: float


SETTING_DEFAULTS: SettingDefaults = {
    'capture_interface_name': None,
    'capture_ip_address': None,
    'capture_mac_address': None,
    'capture_arp_spoofing': False,
    'capture_block_third_party_servers': ALL_THIRD_PARTY_SERVER_NAMES,
    'capture_feature_set': None,
    'capture_filter_process_pid': 0,
    'capture_filter_process_name': None,
    'capture_filter_process_track_by_name': True,
    'capture_overflow_timer': 3,
    'capture_ps3_name_resolver': False,
    'capture_prepend_custom_capture_filter': None,
    'capture_blocked_ips': (),
    'capture_filtered_isps': (),
    'capture_filter_block_rtcp': True,
    'capture_filter_block_ssdp': True,
    'capture_filter_block_raknet': True,
    'capture_filter_block_dtls': True,
    'capture_filter_block_uaudp': True,
    'capture_filter_block_classicstun': True,
    'capture_filter_block_llmnr': True,
    'gui_always_on_top': False,
    'gui_remember_window_layout': False,
    'gui_servers_color_enabled': True,
    'gui_servers_color': DEFAULT_DETECTED_SERVER_COLOR,
    'gui_interface_selection_auto_connect': False,
    'gui_interface_selection_hide_inactive': True,
    'gui_interface_selection_hide_neighbours': False,
    'gui_sessions_logging': True,
    'gui_sessions_logging_delete_empty_files': False,
    'gui_sessions_logging_delete_empty_folders': False,
    'gui_reset_ports_on_rejoins': True,
    'gui_session_host_detection': True,
    'gui_session_host_icon': True,
    'gui_columns_connected_shown': (
        'Packets',
        'PPS',
        'Bandwidth',
        'BPS',
        'Hostname',
        'Ports',
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
        'Ports',
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
    'gui_connected_table_sort_column': 'Last Rejoin',
    'gui_connected_table_sort_order': 'Descending',
    'gui_disconnected_players_enabled': True,
    'gui_disconnected_table_rows_per_page': 0,
    'gui_disconnected_table_sort_column': 'Last Seen',
    'gui_disconnected_table_sort_order': 'Ascending',
    'gui_disconnected_players_timer': 10,
    'gui_disconnected_players_limit': 500,
    'gui_ignore_screen_resolution_warning': False,
    'voice_notifications_enabled': True,
    'pinger_local': True,
    'ping_count': 4,
    'ping_interval_ms': 250,
    'ping_timeout_ms': 1000,
    'ping_payload_bytes': 32,
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
        'Ports',
        'Packets',
        'Session Time',
        'Last Rejoin',
    ),
    'discord_webhook_columns_disconnected': (
        'Usernames',
        'IP Address',
        'Country',
        'Ports',
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
    'updater_skipped_version': None,
    'userip_backup_frequency': 'Daily',
    'userip_backup_retention_limit': 10,
    'userip_sync_known_alts': True,
    'looky_enabled': True,
    'looky_exclusive_gta5_process': True,
    'looky_game_version': 'Both',
    'looky_api_key': None,
    'high_rate_monitor_mode': 'Smart',
    'high_rate_monitor_icon': True,
    'high_rate_monitor_run_in_background': True,
    'high_rate_monitor_auto_select': True,
    'solo_session_duration': 6,
    'high_rate_monitor_pps_threshold': 30,
    'high_rate_monitor_bps_threshold': 5,
    'high_rate_monitor_duration_threshold': 3,
    'player_identifier_icon': True,
    'player_identifier_spike_zscore': 3.0,
    'player_identifier_spike_seconds': 3,
    'player_identifier_baseline_seconds': 10,
    'player_identifier_contamination_zscore': 10.0,
    'player_identifier_contamination_seconds': 5,
    'player_identifier_contamination_min_samples': 15,
    'player_identifier_baseline_timeout': 30,
    'player_identifier_session_drift_zscore': 6.0,
}
