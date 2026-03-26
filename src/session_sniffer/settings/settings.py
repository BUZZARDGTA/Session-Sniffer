"""Settings loading, validation, and persistence."""

import ast
import re
from typing import TYPE_CHECKING, Any, ClassVar, cast

from session_sniffer import msgbox
from session_sniffer.constants.local import SETTINGS_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import ensure_instance, format_invalid_datetime_columns_settings_message
from session_sniffer.logging_setup import console
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.settings.defaults import DefaultSettings
from session_sniffer.text_templates import SETTINGS_INI_HEADER_TEMPLATE
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import check_case_insensitive_and_exact_match, custom_str_to_bool, custom_str_to_nonetype, validate_and_strip_balanced_outer_parens, validate_file
from session_sniffer.utils_exceptions import InvalidBooleanValueError, InvalidNoneTypeValueError, NoMatchFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)')


class Settings(DefaultSettings):
    """Load, validate, and persist user settings for the application."""

    MIN_GUI_DISCONNECTED_PLAYERS_TIMER_SECONDS: ClassVar[float] = 3.0

    ALL_SETTINGS: ClassVar = (
        'CAPTURE_INTERFACE_NAME',
        'CAPTURE_IP_ADDRESS',
        'CAPTURE_MAC_ADDRESS',
        'CAPTURE_ARP_SPOOFING',
        'CAPTURE_BLOCK_THIRD_PARTY_SERVERS',
        'CAPTURE_PROGRAM_PRESET',
        'CAPTURE_OVERFLOW_TIMER',
        'CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER',
        'CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER',
        'GUI_INTERFACE_SELECTION_AUTO_CONNECT',
        'GUI_INTERFACE_SELECTION_HIDE_INACTIVE',
        'GUI_INTERFACE_SELECTION_HIDE_ARP',
        'GUI_SESSIONS_LOGGING',
        'GUI_RESET_PORTS_ON_REJOINS',
        'GUI_COLUMNS_CONNECTED_HIDDEN',
        'GUI_COLUMNS_DISCONNECTED_HIDDEN',
        'GUI_COLUMNS_DATETIME_SHOW_DATE',
        'GUI_COLUMNS_DATETIME_SHOW_TIME',
        'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME',
        'GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2',
        'GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2',
        'GUI_DISCONNECTED_PLAYERS_TIMER',
        'DISCORD_PRESENCE',
        'SHOW_DISCORD_POPUP',
        'UPDATER_CHANNEL',
    )

    _ALL_SETTINGS_SET: ClassVar = frozenset(ALL_SETTINGS)

    GUI_COLUMNS_MAPPING: ClassVar = {
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
        'T. Bandwith': 'bandwidth.total_exchanged',
        'Bandwith': 'bandwidth.exchanged',
        'T. Download': 'bandwidth.total_download',
        'Download': 'bandwidth.download',
        'T. Upload': 'bandwidth.total_upload',
        'Upload': 'bandwidth.upload',
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
    GUI_FORCED_COLUMNS: ClassVar = ('Usernames', 'First Seen', 'Last Rejoin', 'Last Seen', 'Rejoins', 'IP Address')
    GUI_HIDEABLE_CONNECTED_COLUMNS: ClassVar = (
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
        'T. Bandwith',
        'Bandwith',
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
    GUI_HIDEABLE_DISCONNECTED_COLUMNS: ClassVar = (
        'T. Session Time',
        'Session Time',
        'T. Packets',
        'Packets',
        'T. Packets Received',
        'Packets Received',
        'T. Packets Sent',
        'Packets Sent',
        'T. Bandwith',
        'Bandwith',
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
    GUI_ALL_CONNECTED_COLUMNS: ClassVar = (
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
        'T. Bandwith',
        'Bandwith',
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
    GUI_ALL_DISCONNECTED_COLUMNS: ClassVar = (
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
        'T. Bandwith',
        'Bandwith',
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
            yield setting_name, getattr(cls, setting_name)

    @classmethod
    def get_settings_length(cls) -> int:
        """Get the total number of settings."""
        return len(cls.ALL_SETTINGS)

    @classmethod
    def has_setting(cls, setting_name: str) -> bool:
        """Check if a setting exists."""
        return setting_name in cls._ALL_SETTINGS_SET

    @classmethod
    def rewrite_settings_file(cls) -> None:
        """Rewrite the settings file from current in-memory values."""
        console.print('Rewriting "Settings.ini" file ...', highlight=False)

        text = format_triple_quoted_text(
            SETTINGS_INI_HEADER_TEMPLATE.format(
                title=TITLE,
                configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#script-settings-configuration',
            ),
            add_trailing_newline=True,
        )

        for setting_name, setting_value in cls.iterate_over_settings():
            text += f'{setting_name}={setting_value}\n'

        SETTINGS_PATH.write_text(text, encoding='utf-8')

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
        matched_settings_count = 0

        try:
            settings, need_rewrite_settings = cls.parse_settings_ini_file(settings_path)
        except FileNotFoundError:
            need_rewrite_settings = True
        else:
            for setting_name, setting_value in settings.items():
                if not cls.has_setting(setting_name):
                    need_rewrite_settings = True
                    continue

                matched_settings_count += 1
                need_rewrite_current_setting = False

                if setting_name == 'CAPTURE_INTERFACE_NAME':
                    try:
                        Settings.CAPTURE_INTERFACE_NAME, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_INTERFACE_NAME = setting_value
                elif setting_name == 'CAPTURE_IP_ADDRESS':
                    try:
                        Settings.CAPTURE_IP_ADDRESS, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if is_ipv4_address(setting_value):
                            Settings.CAPTURE_IP_ADDRESS = setting_value
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_MAC_ADDRESS':
                    try:
                        Settings.CAPTURE_MAC_ADDRESS, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        formatted_mac_address = format_mac_address(setting_value)
                        if is_mac_address(formatted_mac_address):
                            if formatted_mac_address != setting_value:
                                need_rewrite_settings = True
                            Settings.CAPTURE_MAC_ADDRESS = formatted_mac_address
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_ARP_SPOOFING':
                    try:
                        Settings.CAPTURE_ARP_SPOOFING, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'CAPTURE_BLOCK_THIRD_PARTY_SERVERS':
                    try:
                        Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'CAPTURE_PROGRAM_PRESET':
                    try:
                        Settings.CAPTURE_PROGRAM_PRESET, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        try:
                            case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ('GTA5', 'Minecraft'))
                            Settings.CAPTURE_PROGRAM_PRESET = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        except NoMatchFoundError:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_OVERFLOW_TIMER':
                    try:
                        capture_overflow_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if capture_overflow_timer >= 1:
                            Settings.CAPTURE_OVERFLOW_TIMER = capture_overflow_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER':
                    try:
                        Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER = validate_and_strip_balanced_outer_parens(setting_value)
                        if setting_value != Settings.CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER:
                            need_rewrite_settings = True
                elif setting_name == 'CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER':
                    try:
                        Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER = validate_and_strip_balanced_outer_parens(setting_value)
                        if setting_value != Settings.CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER:
                            need_rewrite_settings = True
                elif setting_name == 'GUI_SESSIONS_LOGGING':
                    try:
                        Settings.GUI_SESSIONS_LOGGING, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_RESET_PORTS_ON_REJOINS':
                    try:
                        Settings.GUI_RESET_PORTS_ON_REJOINS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_COLUMNS_CONNECTED_HIDDEN':
                    (
                        normalized_hidden_columns,
                        should_rewrite_current_setting,
                        should_rewrite_settings,
                    ) = cls._normalize_hidden_gui_columns(setting_value, Settings.GUI_HIDEABLE_CONNECTED_COLUMNS)

                    if should_rewrite_current_setting:
                        need_rewrite_current_setting = True
                    if should_rewrite_settings:
                        need_rewrite_settings = True
                    if normalized_hidden_columns is not None:
                        Settings.GUI_COLUMNS_CONNECTED_HIDDEN = normalized_hidden_columns
                elif setting_name == 'GUI_COLUMNS_DISCONNECTED_HIDDEN':
                    (
                        normalized_hidden_columns,
                        should_rewrite_current_setting,
                        should_rewrite_settings,
                    ) = cls._normalize_hidden_gui_columns(setting_value, Settings.GUI_HIDEABLE_DISCONNECTED_COLUMNS)

                    if should_rewrite_current_setting:
                        need_rewrite_current_setting = True
                    if should_rewrite_settings:
                        need_rewrite_settings = True
                    if normalized_hidden_columns is not None:
                        Settings.GUI_COLUMNS_DISCONNECTED_HIDDEN = normalized_hidden_columns
                elif setting_name == 'GUI_COLUMNS_DATETIME_SHOW_DATE':
                    try:
                        Settings.GUI_COLUMNS_DATETIME_SHOW_DATE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_COLUMNS_DATETIME_SHOW_TIME':
                    try:
                        Settings.GUI_COLUMNS_DATETIME_SHOW_TIME, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME':
                    try:
                        Settings.GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2':
                    try:
                        Settings.GUI_COLUMNS_GEO_CONTINENT_APPEND_ALPHA2, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2':
                    try:
                        Settings.GUI_COLUMNS_GEO_COUNTRY_APPEND_ALPHA2, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_DISCONNECTED_PLAYERS_TIMER':
                    try:
                        player_disconnected_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if player_disconnected_timer >= cls.MIN_GUI_DISCONNECTED_PLAYERS_TIMER_SECONDS:
                            Settings.GUI_DISCONNECTED_PLAYERS_TIMER = player_disconnected_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == 'GUI_INTERFACE_SELECTION_AUTO_CONNECT':
                    try:
                        Settings.GUI_INTERFACE_SELECTION_AUTO_CONNECT, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_INTERFACE_SELECTION_HIDE_INACTIVE':
                    try:
                        Settings.GUI_INTERFACE_SELECTION_HIDE_INACTIVE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'GUI_INTERFACE_SELECTION_HIDE_ARP':
                    try:
                        Settings.GUI_INTERFACE_SELECTION_HIDE_ARP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'DISCORD_PRESENCE':
                    try:
                        Settings.DISCORD_PRESENCE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'SHOW_DISCORD_POPUP':
                    try:
                        Settings.SHOW_DISCORD_POPUP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == 'UPDATER_CHANNEL':
                    try:
                        Settings.UPDATER_CHANNEL, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        try:
                            case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ('Stable', 'RC'))
                            Settings.UPDATER_CHANNEL = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        except NoMatchFoundError:
                            need_rewrite_settings = True

                if need_rewrite_current_setting:
                    need_rewrite_settings = True

            if matched_settings_count != cls.get_settings_length():
                need_rewrite_settings = True

        if (
            Settings.GUI_COLUMNS_DATETIME_SHOW_DATE is False
            and Settings.GUI_COLUMNS_DATETIME_SHOW_TIME is False
            and Settings.GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME is False
        ):
            need_rewrite_settings = True

            msgbox.show(
                title=TITLE,
                text=format_triple_quoted_text(format_invalid_datetime_columns_settings_message()),
                style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
            )

            for setting_name in (
                'GUI_COLUMNS_DATETIME_SHOW_DATE',
                'GUI_COLUMNS_DATETIME_SHOW_TIME',
                'GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME',
            ):
                setattr(Settings, setting_name, getattr(DefaultSettings, setting_name))

        if need_rewrite_settings:
            cls.rewrite_settings_file()

    @staticmethod
    def _normalize_hidden_gui_columns(
        setting_value: str,
        allowed_columns: tuple[str, ...],
    ) -> tuple[tuple[str, ...] | None, bool, bool]:
        """Normalize hidden GUI columns and report whether settings should be rewritten."""
        try:
            gui_columns_to_hide: object = ast.literal_eval(setting_value)
        except (ValueError, SyntaxError):
            return None, False, True

        if not isinstance(gui_columns_to_hide, tuple):
            return None, False, True

        if not all(isinstance(item, str) for item in gui_columns_to_hide):  # pyright: ignore[reportUnknownVariableType]
            return None, False, True

        gui_columns_to_hide = cast('tuple[str, ...]', gui_columns_to_hide)

        filtered_gui_columns_to_hide: list[str] = []
        need_rewrite_current_setting = False
        need_rewrite_settings = False

        for value in gui_columns_to_hide:
            try:
                case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, allowed_columns)
            except NoMatchFoundError:
                need_rewrite_settings = True
                continue

            filtered_gui_columns_to_hide.append(normalized_match)
            if not case_sensitive_match:
                need_rewrite_current_setting = True

        sorted_gui_columns_to_hide = [
            column for column in allowed_columns
            if column in filtered_gui_columns_to_hide
        ]

        if filtered_gui_columns_to_hide != sorted_gui_columns_to_hide:
            need_rewrite_current_setting = True

        return tuple(sorted_gui_columns_to_hide), need_rewrite_current_setting, need_rewrite_settings
