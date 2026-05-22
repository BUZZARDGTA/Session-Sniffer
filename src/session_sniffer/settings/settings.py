"""Settings loading, validation, and persistence."""

import contextlib
import re
from typing import TYPE_CHECKING, Any, ClassVar

from session_sniffer import msgbox
from session_sniffer.constants.local import SETTINGS_PATH
from session_sniffer.constants.standalone import BANDWIDTH_BASE_COLUMN_ATTRS, TITLE
from session_sniffer.constants.third_party_servers import ALL_THIRD_PARTY_SERVER_NAMES
from session_sniffer.error_messages import ensure_instance, format_invalid_datetime_columns_settings_message
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.settings_ini_model import SettingsIniModel
from session_sniffer.networking.ip_range import IPRange, parse_ip_range
from session_sniffer.settings.defaults import SETTING_DEFAULTS
from session_sniffer.text_templates import build_settings_ini_header_text
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import validate_file

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

logger = get_logger(__name__)

RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)')


class Settings:
    """Load, validate, and persist user settings for the application."""

    capture_interface_name: str | None = SETTING_DEFAULTS['capture_interface_name']
    capture_ip_address: str | None = SETTING_DEFAULTS['capture_ip_address']
    capture_mac_address: str | None = SETTING_DEFAULTS['capture_mac_address']
    capture_arp_spoofing: bool = SETTING_DEFAULTS['capture_arp_spoofing']
    capture_block_third_party_servers: tuple[str, ...] = SETTING_DEFAULTS['capture_block_third_party_servers']
    capture_blocked_ips: tuple[str, ...] = SETTING_DEFAULTS['capture_blocked_ips']
    capture_program_preset: str | None = SETTING_DEFAULTS['capture_program_preset']
    capture_overflow_timer: int = SETTING_DEFAULTS['capture_overflow_timer']
    capture_prepend_custom_capture_filter: str | None = SETTING_DEFAULTS['capture_prepend_custom_capture_filter']
    capture_prepend_custom_display_filter: str | None = SETTING_DEFAULTS['capture_prepend_custom_display_filter']
    gui_interface_selection_auto_connect: bool = SETTING_DEFAULTS['gui_interface_selection_auto_connect']
    gui_interface_selection_hide_inactive: bool = SETTING_DEFAULTS['gui_interface_selection_hide_inactive']
    gui_interface_selection_hide_neighbours: bool = SETTING_DEFAULTS['gui_interface_selection_hide_neighbours']
    gui_sessions_logging: bool = SETTING_DEFAULTS['gui_sessions_logging']
    gui_reset_ports_on_rejoins: bool = SETTING_DEFAULTS['gui_reset_ports_on_rejoins']
    gui_session_host_detection: bool = SETTING_DEFAULTS['gui_session_host_detection']
    gui_rate_graph_always_on_top: bool = SETTING_DEFAULTS['gui_rate_graph_always_on_top']
    gui_rate_graph_max_history: int = SETTING_DEFAULTS['gui_rate_graph_max_history']
    gui_columns_connected_shown: tuple[str, ...] = SETTING_DEFAULTS['gui_columns_connected_shown']
    gui_columns_disconnected_shown: tuple[str, ...] = SETTING_DEFAULTS['gui_columns_disconnected_shown']
    gui_columns_datetime_show_date: bool = SETTING_DEFAULTS['gui_columns_datetime_show_date']
    gui_columns_datetime_show_time: bool = SETTING_DEFAULTS['gui_columns_datetime_show_time']
    gui_columns_datetime_show_elapsed_time: bool = SETTING_DEFAULTS['gui_columns_datetime_show_elapsed_time']
    gui_columns_geo_country_append_alpha2: bool = SETTING_DEFAULTS['gui_columns_geo_country_append_alpha2']
    gui_columns_geo_continent_append_alpha2: bool = SETTING_DEFAULTS['gui_columns_geo_continent_append_alpha2']
    gui_connected_table_rows_per_page: int = SETTING_DEFAULTS['gui_connected_table_rows_per_page']
    gui_disconnected_table_rows_per_page: int = SETTING_DEFAULTS['gui_disconnected_table_rows_per_page']
    gui_disconnected_players_timer: int = SETTING_DEFAULTS['gui_disconnected_players_timer']
    discord_presence: bool = SETTING_DEFAULTS['discord_presence']
    discord_presence_title: str = SETTING_DEFAULTS['discord_presence_title']
    show_discord_popup: bool = SETTING_DEFAULTS['show_discord_popup']
    discord_webhook_enabled: bool = SETTING_DEFAULTS['discord_webhook_enabled']
    discord_webhook_url: str | None = SETTING_DEFAULTS['discord_webhook_url']
    discord_webhook_refresh_interval: int = SETTING_DEFAULTS['discord_webhook_refresh_interval']
    discord_webhook_include_connected: bool = SETTING_DEFAULTS['discord_webhook_include_connected']
    discord_webhook_include_disconnected: bool = SETTING_DEFAULTS['discord_webhook_include_disconnected']
    discord_webhook_max_rows_per_table: int = SETTING_DEFAULTS['discord_webhook_max_rows_per_table']
    discord_webhook_max_connected_players: int = SETTING_DEFAULTS['discord_webhook_max_connected_players']
    discord_webhook_max_disconnected_players: int = SETTING_DEFAULTS['discord_webhook_max_disconnected_players']
    discord_webhook_format: str = SETTING_DEFAULTS['discord_webhook_format']
    discord_webhook_columns_connected: tuple[str, ...] = SETTING_DEFAULTS['discord_webhook_columns_connected']
    discord_webhook_columns_disconnected: tuple[str, ...] = SETTING_DEFAULTS['discord_webhook_columns_disconnected']
    discord_webhook_message_ids: str | None = SETTING_DEFAULTS['discord_webhook_message_ids']
    updater_channel: str | None = SETTING_DEFAULTS['updater_channel']

    MIN_GUI_DISCONNECTED_PLAYERS_TIMER_SECONDS: ClassVar[int] = 3
    MAX_GUI_TABLE_ROWS_PER_PAGE: ClassVar[int] = 5000
    blocked_ip_ranges: ClassVar[list[IPRange]] = []

    ALL_SETTINGS: ClassVar[tuple[str, ...]] = (
        'CAPTURE_INTERFACE_NAME',
        'CAPTURE_IP_ADDRESS',
        'CAPTURE_MAC_ADDRESS',
        'CAPTURE_ARP_SPOOFING',
        'CAPTURE_BLOCK_THIRD_PARTY_SERVERS',
        'CAPTURE_BLOCKED_IPS',
        'CAPTURE_PROGRAM_PRESET',
        'CAPTURE_OVERFLOW_TIMER',
        'CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER',
        'CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER',
        'GUI_INTERFACE_SELECTION_AUTO_CONNECT',
        'GUI_INTERFACE_SELECTION_HIDE_INACTIVE',
        'GUI_INTERFACE_SELECTION_HIDE_NEIGHBOURS',
        'GUI_SESSIONS_LOGGING',
        'GUI_RESET_PORTS_ON_REJOINS',
        'GUI_SESSION_HOST_DETECTION',
        'GUI_RATE_GRAPH_ALWAYS_ON_TOP',
        'GUI_RATE_GRAPH_MAX_HISTORY',
        'GUI_COLUMNS_CONNECTED_SHOWN',
        'GUI_COLUMNS_DISCONNECTED_SHOWN',
        'GUI_COLUMNS_DATETIME_SHOW_DATE',
        'GUI_COLUMNS_DATETIME_SHOW_TIME',
        'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME',
        'GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2',
        'GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2',
        'GUI_CONNECTED_TABLE_ROWS_PER_PAGE',
        'GUI_DISCONNECTED_TABLE_ROWS_PER_PAGE',
        'GUI_DISCONNECTED_PLAYERS_TIMER',
        'DISCORD_PRESENCE',
        'DISCORD_PRESENCE_TITLE',
        'SHOW_DISCORD_POPUP',
        'DISCORD_WEBHOOK_ENABLED',
        'DISCORD_WEBHOOK_URL',
        'DISCORD_WEBHOOK_REFRESH_INTERVAL',
        'DISCORD_WEBHOOK_INCLUDE_CONNECTED',
        'DISCORD_WEBHOOK_INCLUDE_DISCONNECTED',
        'DISCORD_WEBHOOK_MAX_ROWS_PER_TABLE',
        'DISCORD_WEBHOOK_MAX_CONNECTED_PLAYERS',
        'DISCORD_WEBHOOK_MAX_DISCONNECTED_PLAYERS',
        'DISCORD_WEBHOOK_FORMAT',
        'DISCORD_WEBHOOK_COLUMNS_CONNECTED',
        'DISCORD_WEBHOOK_COLUMNS_DISCONNECTED',
        'DISCORD_WEBHOOK_MESSAGE_IDS',
        'UPDATER_CHANNEL',
    )

    _ALL_SETTINGS_SET: ClassVar[frozenset[str]] = frozenset(ALL_SETTINGS)

    GUI_COLUMNS_MAPPING: ClassVar[dict[str, str]] = {
        'Usernames': 'usernames',
        'First Seen': 'datetime.first_seen',
        'Last Rejoin': 'datetime.last_rejoin',
        'Last Seen': 'datetime.last_seen',
        'T. Session Time': 'datetime.total_session_time',
        'Session Time': 'datetime.session_time',
        'Rejoins': 'rejoins',
        'T. Packets': 'total_packets',
        'Packets': 'packets',
        'T. Packets Received': 'total_packets_received',
        'Packets Received': 'packets_received',
        'T. Packets Sent': 'total_packets_sent',
        'Packets Sent': 'packets_sent',
        'PPS': 'pps.calculated_rate',
        'PPM': 'ppm.calculated_rate',
        **BANDWIDTH_BASE_COLUMN_ATTRS,
        'BPS': 'bps.calculated_rate',
        'BPM': 'bpm.calculated_rate',
        'IP Address': 'ip',
        'Hostname': 'reverse_dns.hostname',
        'Last Port': 'ports.last',
        'Middle Ports': 'ports.middle',
        'First Port': 'ports.first',
        'Continent': 'iplookup.ipapi.continent',
        'Country': 'iplookup.geolite2.country',
        'Region': 'iplookup.ipapi.region',
        'R. Code': 'iplookup.ipapi.region_code',
        'City': 'iplookup.geolite2.city',
        'District': 'iplookup.ipapi.district',
        'ZIP Code': 'iplookup.ipapi.zip_code',
        'Lat': 'iplookup.ipapi.lat',
        'Lon': 'iplookup.ipapi.lon',
        'Time Zone': 'iplookup.ipapi.time_zone',
        'Offset': 'iplookup.ipapi.offset',
        'Currency': 'iplookup.ipapi.currency',
        'Organization': 'iplookup.ipapi.org',
        'ISP': 'iplookup.ipapi.isp',
        'ASN / ISP': 'iplookup.geolite2.asn',
        'AS': 'iplookup.ipapi.asn',
        'ASN': 'iplookup.ipapi.as_name',
        'Mobile': 'iplookup.ipapi.mobile',
        'VPN': 'iplookup.ipapi.proxy',
        'Hosting': 'iplookup.ipapi.hosting',
        'Pinging': 'ping.is_pinging',
    }
    GUI_FORCED_COLUMNS: ClassVar[tuple[str, ...]] = ('Usernames', 'First Seen', 'Last Rejoin', 'Last Seen', 'Rejoins', 'IP Address')
    ALL_THIRD_PARTY_SERVERS: ClassVar[tuple[str, ...]] = ALL_THIRD_PARTY_SERVER_NAMES
    GUI_TOGGLEABLE_CONNECTED_COLUMNS: ClassVar[tuple[str, ...]] = (
        'T. Session Time',
        'Session Time',
        'T. Packets',
        'Packets',
        'T. Packets Received',
        'Packets Received',
        'T. Packets Sent',
        'Packets Sent',
        'PPS',
        'PPM',
        'T. Bandwidth',
        'Bandwidth',
        'T. Download',
        'Download',
        'T. Upload',
        'Upload',
        'BPS',
        'BPM',
        'Hostname',
        'Last Port',
        'Middle Ports',
        'First Port',
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
        'Organization',
        'ISP',
        'ASN / ISP',
        'AS',
        'ASN',
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
    )
    GUI_TOGGLEABLE_DISCONNECTED_COLUMNS: ClassVar[tuple[str, ...]] = (
        'T. Session Time',
        'Session Time',
        'T. Packets',
        'Packets',
        'T. Packets Received',
        'Packets Received',
        'T. Packets Sent',
        'Packets Sent',
        'T. Bandwidth',
        'Bandwidth',
        'T. Download',
        'Download',
        'T. Upload',
        'Upload',
        'Hostname',
        'Last Port',
        'Middle Ports',
        'First Port',
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
        'Organization',
        'ISP',
        'ASN / ISP',
        'AS',
        'ASN',
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
    )
    GUI_ALL_CONNECTED_COLUMNS: ClassVar[tuple[str, ...]] = (
        'Usernames',
        'First Seen',
        'Last Rejoin',
        'T. Session Time',
        'Session Time',
        'Rejoins',
        'T. Packets',
        'Packets',
        'T. Packets Received',
        'Packets Received',
        'T. Packets Sent',
        'Packets Sent',
        'PPS',
        'PPM',
        'T. Bandwidth',
        'Bandwidth',
        'T. Download',
        'Download',
        'T. Upload',
        'Upload',
        'BPS',
        'BPM',
        'IP Address',
        'Hostname',
        'Last Port',
        'Middle Ports',
        'First Port',
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
        'Organization',
        'ISP',
        'ASN / ISP',
        'AS',
        'ASN',
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
    )
    GUI_ALL_DISCONNECTED_COLUMNS: ClassVar[tuple[str, ...]] = (
        'Usernames',
        'First Seen',
        'Last Rejoin',
        'Last Seen',
        'T. Session Time',
        'Session Time',
        'Rejoins',
        'T. Packets',
        'Packets',
        'T. Packets Received',
        'Packets Received',
        'T. Packets Sent',
        'Packets Sent',
        'T. Bandwidth',
        'Bandwidth',
        'T. Download',
        'Download',
        'T. Upload',
        'Upload',
        'IP Address',
        'Hostname',
        'Last Port',
        'Middle Ports',
        'First Port',
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
        'Organization',
        'ISP',
        'ASN / ISP',
        'AS',
        'ASN',
        'Mobile',
        'VPN',
        'Hosting',
        'Pinging',
    )

    @classmethod
    def iterate_over_settings(cls) -> Iterator[tuple[str, Any]]:
        """Iterate over all settings and their current values."""
        for setting_name in cls.ALL_SETTINGS:
            yield setting_name, getattr(cls, setting_name.lower())

    @classmethod
    def get_settings_length(cls) -> int:
        """Get the total number of settings."""
        return len(cls.ALL_SETTINGS)

    @classmethod
    def has_setting(cls, setting_name: str) -> bool:
        """Check if a setting exists."""
        return setting_name in cls._ALL_SETTINGS_SET

    @classmethod
    def rebuild_blocked_ip_ranges(cls) -> None:
        """Rebuild the in-memory list of parsed IPRange objects from `capture_blocked_ips`."""
        ranges: list[IPRange] = []
        for raw in cls.capture_blocked_ips:
            with contextlib.suppress(ValueError, TypeError):
                ranges.append(parse_ip_range(raw))
        cls.blocked_ip_ranges = ranges

    @classmethod
    def rewrite_settings_file(cls) -> None:
        """Rewrite the settings file from current in-memory values."""
        text = build_settings_ini_header_text()

        for setting_name, setting_value in cls.iterate_over_settings():
            text += f'{setting_name}={setting_value}\n'

        tmp_path: Path = SETTINGS_PATH.with_suffix('.tmp')
        tmp_path.write_text(text, encoding='utf-8')
        tmp_path.replace(SETTINGS_PATH)

    @staticmethod
    def parse_settings_ini_file(ini_path: Path) -> tuple[dict[str, str], bool]:
        """Parse the settings INI file and report whether it should be rewritten."""
        def process_ini_line_output(line: str) -> str:
            return line.rstrip('\n')

        validate_file(ini_path)

        ini_data = ini_path.read_text('utf-8')

        need_rewrite_ini = False
        ini_database: dict[str, str] = {}

        for line in map(process_ini_line_output, ini_data.splitlines(keepends=False)):
            if (corrected_line := line.strip()) != line:
                need_rewrite_ini = True

            if not (match := RE_SETTINGS_INI_PARSER_PATTERN.search(corrected_line)):
                continue

            setting_name = ensure_instance(match.group('key'), str)
            setting_value = ensure_instance(match.group('value'), str)

            if not (corrected_setting_name := setting_name.strip()):
                continue

            if corrected_setting_name != setting_name:
                need_rewrite_ini = True

            if not (corrected_setting_value := setting_value.strip()):
                continue

            if corrected_setting_value != setting_value:
                need_rewrite_ini = True

            if corrected_setting_name in ini_database:
                need_rewrite_ini = True  # Settings file needs to be rewritten as it contains duplicate settings
                continue

            ini_database[corrected_setting_name] = corrected_setting_value

        return ini_database, need_rewrite_ini

    @classmethod
    def load_from_settings_file(cls, settings_path: Path) -> None:
        """Load settings from disk into `Settings` and rewrite when necessary."""
        try:
            raw_settings, need_rewrite_settings = cls.parse_settings_ini_file(settings_path)
        except FileNotFoundError:
            need_rewrite_settings = True
        else:
            # Build UPPER_CASE defaults dict for the model
            upper_defaults: dict[str, Any] = {k.upper(): v for k, v in SETTING_DEFAULTS.items()}

            validated, _ini_rewrites, flags = SettingsIniModel.validate_and_get_rewrites(
                raw_settings,
                defaults=upper_defaults,
                all_setting_names=cls.ALL_SETTINGS,
                toggleable_connected_columns=cls.GUI_TOGGLEABLE_CONNECTED_COLUMNS,
                toggleable_disconnected_columns=cls.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS,
                webhook_all_connected_columns=cls.GUI_ALL_CONNECTED_COLUMNS,
                webhook_all_disconnected_columns=cls.GUI_ALL_DISCONNECTED_COLUMNS,
                all_third_party_servers=cls.ALL_THIRD_PARTY_SERVERS,
                max_gui_table_rows_per_page=cls.MAX_GUI_TABLE_ROWS_PER_PAGE,
                min_gui_disconnected_players_timer=cls.MIN_GUI_DISCONNECTED_PLAYERS_TIMER_SECONDS,
            )

            # Apply all validated fields to Settings class attrs (UPPER model field → lower class attr)
            for field_name in cls.ALL_SETTINGS:
                setattr(cls, field_name.lower(), getattr(validated, field_name))

            if flags.get('should_rewrite'):
                need_rewrite_settings = True

            if flags.get('invalid_datetime_columns_corrected'):
                msgbox.show(
                    title=TITLE,
                    text=format_triple_quoted_text(format_invalid_datetime_columns_settings_message()),
                    style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                )

        if need_rewrite_settings:
            cls.rewrite_settings_file()
