"""Core rendering loop that compiles GUI payloads from runtime state."""

import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING, Any

import geoip2.errors
from prettytable import PrettyTable, TableStyle
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QIcon, QPixmap

from session_sniffer import msgbox
from session_sniffer.background.tasks import gui_closed__event, show_detection_warning_popup
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import IMAGES_DIR_PATH, SESSIONS_LOGGING_DIR_PATH, USERIP_DATABASES_DIR_PATH, VERSION
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import ScriptControl, ThreadsExceptionHandler
from session_sniffer.discord.rpc import DiscordRPC
from session_sniffer.error_messages import (
    format_type_error,
    format_userip_corrupted_settings_message,
    format_userip_invalid_ip_entry_message,
    format_userip_missing_settings_message,
)
from session_sniffer.guis.html_templates import CAPTURE_STOPPED_HTML, GUI_HEADER_HTML_TEMPLATE
from session_sniffer.models.player import Player, PlayerBandwidth, PlayerCountryFlag, PlayerModMenus
from session_sniffer.networking.utils import is_ipv4_address
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.player.userip import UserIPDatabases, UserIPSettings
from session_sniffer.player.warnings import GUIDetectionSettings, HostingWarnings, MobileWarnings, VPNWarnings
from session_sniffer.rendering_core.modmenu_logs_parser import ModMenuLogsParser
from session_sniffer.rendering_core.session_table_renderer import SessionTableRenderContext, build_session_table_snapshot
from session_sniffer.rendering_core.status_bar_renderer import build_gui_status_text
from session_sniffer.rendering_core.types import GeoIP2Readers, GUIRenderingSnapshot, GUIRenderingState, SessionTableSnapshot, TsharkStats
from session_sniffer.settings import Settings
from session_sniffer.text_templates import DEFAULT_USERIP_FILES_SETTINGS_INI, USERIP_DEFAULT_DB_FOOTER_TEMPLATE, USERIP_DEFAULT_DB_HEADER_TEMPLATE
from session_sniffer.text_utils import format_triple_quoted_text, pluralize
from session_sniffer.utils import check_case_insensitive_and_exact_match, custom_str_to_bool, custom_str_to_nonetype, dedup_preserve_order, get_session_log_path, validate_file
from session_sniffer.utils_exceptions import InvalidBooleanValueError, InvalidNoneTypeValueError, NoMatchFoundError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.capture.tshark_capture import PacketCapture

RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)')
RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')

USERIP_INI_SETTINGS = [
    'ENABLED', 'COLOR', 'NOTIFICATIONS', 'VOICE_NOTIFICATIONS', 'LOG', 'PROTECTION',
    'PROTECTION_PROCESS_PATH', 'PROTECTION_RESTART_PROCESS_PATH', 'PROTECTION_SUSPEND_PROCESS_MODE',
]

DISCORD_APPLICATION_ID = 1313304495958261781
COUNTRY_FLAGS_DIR_PATH = IMAGES_DIR_PATH / 'country_flags'
SESSIONS_LOGGING_PATH = get_session_log_path(SESSIONS_LOGGING_DIR_PATH, LOCAL_TZ)
SECONDS_PER_MINUTE = 60.0
DISCORD_PRESENCE_UPDATE_INTERVAL_SECONDS = 3.0


def generate_gui_header_html(*, capture: PacketCapture) -> str:
    """Generate the GUI header HTML based on capture state."""
    stop_status = '' if capture.is_running() else CAPTURE_STOPPED_HTML

    return GUI_HEADER_HTML_TEMPLATE.format(
        title=TITLE,
        version=VERSION,
        stop_status=stop_status,
    )


def rendering_core(
    capture: PacketCapture,
    geoip2_readers: GeoIP2Readers,
    *,
    vpn_mode_enabled: bool,
) -> None:
    """Compile GUI payloads from runtime state and emit updates."""
    with ThreadsExceptionHandler():
        def parse_userip_ini_file(ini_path: Path, unresolved_ip_invalid: set[str]) -> tuple[UserIPSettings | None, dict[str, list[str]] | None]:
            def process_ini_line_output(line: str) -> str:
                return line.strip()

            validate_file(ini_path)

            settings: dict[str, Any] = {}
            userip: dict[str, list[str]] = {}
            current_section = None
            matched_settings: list[str] = []
            ini_data = ini_path.read_text('utf-8')
            corrected_ini_data_lines: list[str] = []

            for line in map(process_ini_line_output, ini_data.splitlines(keepends=True)):
                corrected_ini_data_lines.append(line)

                if line.startswith('[') and line.endswith(']'):
                    # we basically adding a newline if the previous line is not a newline for eyes visiblitly or idk how we say that
                    if (
                        corrected_ini_data_lines
                        and len(corrected_ini_data_lines) > 1
                        and corrected_ini_data_lines[-2]
                    ):
                        corrected_ini_data_lines.insert(-1, '')  # Insert an empty string before the last line
                    current_section = line[1:-1]
                    continue

                if current_section is None:
                    continue

                if current_section == 'Settings':
                    if not (match := RE_SETTINGS_INI_PARSER_PATTERN.search(line)):
                        # If it's a newline or a comment we don't really care about rewritting at this point.
                        if not line.startswith((';', '#')) or not line:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    if (setting := match.group('key')) is None:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not isinstance(setting, str):
                        raise TypeError(format_type_error(setting, str))
                    if (value := match.group('value')) is None:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not isinstance(value, str):
                        raise TypeError(format_type_error(value, str))

                    if not (setting := setting.strip()):
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue
                    if not (value := value.strip()):
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    if setting not in USERIP_INI_SETTINGS:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    if setting in settings:
                        if corrected_ini_data_lines:
                            corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                        continue

                    matched_settings.append(setting)
                    need_rewrite_current_setting = False
                    is_setting_corrupted = False

                    if setting == 'ENABLED':
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                        except InvalidBooleanValueError:
                            is_setting_corrupted = True
                    elif setting == 'COLOR':
                        if (q_color := QColor(value)).isValid():
                            settings[setting] = q_color
                        else:
                            is_setting_corrupted = True
                    elif setting in {'LOG', 'NOTIFICATIONS'}:
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                        except InvalidBooleanValueError:
                            is_setting_corrupted = True
                    elif setting == 'VOICE_NOTIFICATIONS':
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                        except InvalidBooleanValueError:
                            try:
                                case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ('Male', 'Female'))
                                settings[setting] = normalized_match
                                if not case_sensitive_match:
                                    need_rewrite_current_setting = True
                            except NoMatchFoundError:
                                is_setting_corrupted = True
                    elif setting == 'PROTECTION':
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                        except InvalidBooleanValueError:
                            try:
                                case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(
                                    value, ('Suspend_Process', 'Exit_Process', 'Restart_Process', 'Shutdown_PC', 'Restart_PC'),
                                )
                                settings[setting] = normalized_match
                                if not case_sensitive_match:
                                    need_rewrite_current_setting = True
                            except NoMatchFoundError:
                                is_setting_corrupted = True
                    elif setting in {'PROTECTION_PROCESS_PATH', 'PROTECTION_RESTART_PROCESS_PATH'}:
                        try:
                            settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                        except InvalidNoneTypeValueError:
                            stripped_value = value.strip("\"'")
                            if value != stripped_value:
                                is_setting_corrupted = True
                            settings[setting] = Path(stripped_value)
                    elif setting == 'PROTECTION_SUSPEND_PROCESS_MODE':
                        try:
                            case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ('Auto', 'Manual'))
                            settings[setting] = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        except NoMatchFoundError:
                            try:
                                protection_suspend_process_mode = float(value) if '.' in value else int(value)
                            except (ValueError, TypeError):
                                is_setting_corrupted = True
                            else:
                                if protection_suspend_process_mode >= 0:
                                    settings[setting] = protection_suspend_process_mode
                                else:
                                    is_setting_corrupted = True

                    if is_setting_corrupted:
                        if ini_path not in UserIPDatabases.notified_settings_corrupted:
                            UserIPDatabases.notified_settings_corrupted.add(ini_path)
                            Thread(
                                target=msgbox.show,
                                name=f'UserIPConfigFileError-{ini_path.name}',
                                kwargs={
                                    'title': TITLE,
                                    'text': format_triple_quoted_text(format_userip_corrupted_settings_message(
                                        ini_path=ini_path,
                                        setting=setting,
                                        value=value,
                                        configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                                    )),
                                    'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                                },
                                daemon=True,
                            ).start()
                        return None, None

                    if need_rewrite_current_setting:
                        corrected_ini_data_lines[-1] = f'{setting}={settings[setting]}'

                elif current_section == 'UserIP':
                    if not (match := RE_USERIP_INI_PARSER_PATTERN.search(line)):
                        continue
                    if (username := match.group('username')) is None:
                        continue
                    if not isinstance(username, str):
                        raise TypeError(format_type_error(username, str))
                    if (ip := match.group('ip')) is None:
                        continue
                    if not isinstance(ip, str):
                        raise TypeError(format_type_error(ip, str))

                    if not (username := username.strip()):
                        continue
                    if not (ip := ip.strip()):
                        continue

                    if not is_ipv4_address(ip):
                        unresolved_ip_invalid.add(f'{ini_path}={username}={ip}')
                        if f'{ini_path}={username}={ip}' not in UserIPDatabases.notified_ip_invalid:
                            Thread(
                                target=msgbox.show,
                                name=f'UserIPInvalidEntryError-{ini_path.name}_{username}={ip}',
                                kwargs={
                                    'title': TITLE,
                                    'text': format_triple_quoted_text(format_userip_invalid_ip_entry_message(
                                        ini_path=ini_path,
                                        username=username,
                                        ip=ip,
                                        configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                                    )),
                                    'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                                },
                                daemon=True,
                            ).start()
                            UserIPDatabases.notified_ip_invalid.add(f'{ini_path}={username}={ip}')
                        continue

                    if username in userip:
                        if ip not in userip[username]:
                            userip[username].append(ip)
                    else:
                        userip[username] = [ip]

            list_of_missing_settings = [setting for setting in USERIP_INI_SETTINGS if setting not in matched_settings]
            number_of_settings_missing = len(list_of_missing_settings)

            if number_of_settings_missing > 0:
                if ini_path not in UserIPDatabases.notified_settings_corrupted:
                    UserIPDatabases.notified_settings_corrupted.add(ini_path)
                    Thread(
                        target=msgbox.show,
                        name=f'UserIPConfigFileError-{ini_path.name}',
                        kwargs={
                            'title': TITLE,
                            'text': format_triple_quoted_text(format_userip_missing_settings_message(
                                ini_path=ini_path,
                                missing_settings=list_of_missing_settings,
                                configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                            )),
                            'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SETFOREGROUND,
                        },
                        daemon=True,
                    ).start()
                return None, None

            if ini_path in UserIPDatabases.notified_settings_corrupted:
                UserIPDatabases.notified_settings_corrupted.remove(ini_path)

            # Basically always have a newline ending
            if (
                len(corrected_ini_data_lines) > 1
                and corrected_ini_data_lines[-1]
            ):
                corrected_ini_data_lines.append('')

            fixed_ini_data = '\n'.join(corrected_ini_data_lines)

            if ini_data != fixed_ini_data:
                ini_path.write_text(fixed_ini_data, encoding='utf-8')

            return UserIPSettings(
                settings['ENABLED'],
                settings['COLOR'],
                settings['LOG'],
                settings['NOTIFICATIONS'],
                settings['VOICE_NOTIFICATIONS'],
                settings['PROTECTION'],
                settings['PROTECTION_PROCESS_PATH'],
                settings['PROTECTION_RESTART_PROCESS_PATH'],
                settings['PROTECTION_SUSPEND_PROCESS_MODE'],
            ), userip

        def update_userip_databases() -> float:
            default_userip_file_header = format_triple_quoted_text(
                USERIP_DEFAULT_DB_HEADER_TEMPLATE.format(
                    title=TITLE,
                    configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                ),
            )

            default_userip_files_settings = {
                USERIP_DATABASES_DIR_PATH / ini_name: settings
                for ini_name, settings in DEFAULT_USERIP_FILES_SETTINGS_INI.items()
            }

            default_userip_file_footer = format_triple_quoted_text(USERIP_DEFAULT_DB_FOOTER_TEMPLATE, add_trailing_newline=True)

            USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)

            for userip_path, settings in default_userip_files_settings.items():
                if not userip_path.is_file():
                    file_content = f'{default_userip_file_header}\n\n{settings}\n\n{default_userip_file_footer}'
                    userip_path.write_text(file_content, encoding='utf-8')

            # Remove deleted files from notified settings conflicts
            # TODO(BUZZARDGTA): I should also warn again on another error, but it'd probably require a DICT then.
            for file_path in set(UserIPDatabases.notified_settings_corrupted):
                if not file_path.is_file():
                    UserIPDatabases.notified_settings_corrupted.remove(file_path)

            new_databases: list[tuple[Path, UserIPSettings, dict[str, list[str]]]] = []
            unresolved_ip_invalid: set[str] = set()

            for userip_path in USERIP_DATABASES_DIR_PATH.rglob('*.ini'):
                parsed_settings, parsed_data = parse_userip_ini_file(userip_path, unresolved_ip_invalid)
                if parsed_settings is None or parsed_data is None:
                    continue
                new_databases.append((userip_path, parsed_settings, parsed_data))

            UserIPDatabases.populate(new_databases)

            resolved_ip_invalids = UserIPDatabases.notified_ip_invalid - unresolved_ip_invalid
            for resolved_database_entry in resolved_ip_invalids:
                UserIPDatabases.notified_ip_invalid.remove(resolved_database_entry)

            UserIPDatabases.build()

            return time.monotonic()

        def get_country_info(ip_address: str) -> tuple[str, str]:
            country_name = 'N/A'
            country_code = 'N/A'

            if geoip2_readers.enabled and geoip2_readers.country_reader is not None:
                try:
                    response = geoip2_readers.country_reader.country(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    country_name = str(response.country.name) if response.country.name is not None else 'N/A'
                    country_code = str(response.country.iso_code) if response.country.iso_code is not None else 'N/A'

            return country_name, country_code

        def get_city_info(ip_address: str) -> str:
            city = 'N/A'

            if geoip2_readers.enabled and geoip2_readers.city_reader is not None:
                try:
                    response = geoip2_readers.city_reader.city(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    city = str(response.city.name) if response.city.name is not None else 'N/A'

            return city

        def get_asn_info(ip_address: str) -> str:
            asn = 'N/A'

            if geoip2_readers.enabled and geoip2_readers.asn_reader is not None:
                try:
                    response = geoip2_readers.asn_reader.asn(ip_address)
                except geoip2.errors.AddressNotFoundError:
                    pass
                else:
                    asn = str(response.autonomous_system_organization) if response.autonomous_system_organization is not None else 'N/A'

            return asn

        def format_elapsed_time(duration: timedelta) -> str:
            """Format a timedelta duration into a compact human-readable string."""
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, remainder = divmod(remainder, 60)
            seconds, milliseconds = divmod(remainder * 1000, 1000)

            duration_parts: list[str] = []
            if hours >= 1:
                duration_parts.append(f'{int(hours):02}h')
            if duration_parts or minutes >= 1:
                duration_parts.append(f'{int(minutes):02}m')
            if duration_parts or seconds >= 1:
                duration_parts.append(f'{int(seconds):02}s')
            if not duration_parts and milliseconds > 0:
                duration_parts.append(f'{int(milliseconds):03}ms')

            return ' '.join(duration_parts) if duration_parts else '000ms'

        def format_player_usernames(player: Player) -> str:
            """Format player usernames as comma-separated string."""
            return ', '.join(player.usernames) if player.usernames else ''

        def format_player_ip(player_ip: str) -> str:
            """Format player IP with crown emoji if session host."""
            if SessionHost.player and SessionHost.player.ip == player_ip:
                return f'{player_ip} 👑'
            return player_ip

        def format_player_middle_ports(player: Player) -> str:
            """Format player middle ports as comma-separated string in reverse order."""
            if player.ports.middle:
                return ', '.join(map(str, reversed(player.ports.middle)))
            return ''

        def process_session_logging() -> None:
            def format_player_logging_datetime(datetime_object: datetime) -> str:
                return datetime_object.strftime('%m/%d/%Y %H:%M:%S.%f')[:-3]

            def add_sort_arrow_char_to_sorted_logging_table_column(column_names: Sequence[str], sorted_column: str, sort_order: Qt.SortOrder) -> list[str]:
                arrow = ' \u2193' if sort_order == Qt.SortOrder.DescendingOrder else ' \u2191'  # Down arrow for descending, up arrow for ascending
                return [
                    column + arrow if column == sorted_column else column
                    for column in column_names
                ]

            def calculate_table_padding(connected_players: list[Player], disconnected_players: list[Player]) -> tuple[int, int, int, int]:
                """Calculate optimal padding for table columns based on player data."""
                table_country_column_length_threshold = 27
                table_continent_column_length_threshold = 13

                connected_country_padding = 0
                connected_continent_padding = 0
                disconnected_country_padding = 0
                disconnected_continent_padding = 0

                # Calculate optimal padding for connected players
                for player in connected_players:
                    country_len = len(player.iplookup.geolite2.country)
                    continent_len = len(player.iplookup.ipapi.continent)

                    # Only include in padding calculation if within threshold
                    if country_len <= table_country_column_length_threshold:
                        connected_country_padding = max(connected_country_padding, country_len)
                    if continent_len <= table_continent_column_length_threshold:
                        connected_continent_padding = max(connected_continent_padding, continent_len)

                # Calculate optimal padding for disconnected players
                for player in disconnected_players:
                    country_len = len(player.iplookup.geolite2.country)
                    continent_len = len(player.iplookup.ipapi.continent)

                    # Only include in padding calculation if within threshold
                    if country_len <= table_country_column_length_threshold:
                        disconnected_country_padding = max(disconnected_country_padding, country_len)
                    if continent_len <= table_continent_column_length_threshold:
                        disconnected_continent_padding = max(disconnected_continent_padding, continent_len)

                return connected_country_padding, connected_continent_padding, disconnected_country_padding, disconnected_continent_padding

            logging_connected_players__column_names__with_down_arrow = add_sort_arrow_char_to_sorted_logging_table_column(
                logging_connected_players_table__column_names, 'Last Rejoin', Qt.SortOrder.DescendingOrder,
            )
            logging_disconnected_players__column_names__with_down_arrow = add_sort_arrow_char_to_sorted_logging_table_column(
                logging_disconnected_players_table__column_names, 'Last Seen', Qt.SortOrder.AscendingOrder,
            )

            # Calculate optimal padding for both connected and disconnected players
            (session_connected__padding_country_name,
             session_connected__padding_continent_name,
             session_disconnected__padding_country_name,
             session_disconnected__padding_continent_name) = calculate_table_padding(session_connected, session_disconnected)

            logging_connected_players_table = PrettyTable()
            logging_connected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_connected_players_table.title = f'Player{pluralize(len(session_connected))} connected in your session ({len(session_connected)}):'
            logging_connected_players_table.field_names = logging_connected_players__column_names__with_down_arrow
            logging_connected_players_table.align = dict.fromkeys(logging_connected_players__column_names__with_down_arrow, 'l')
            for player in session_connected:
                connected_row_texts: list[str] = []
                connected_row_texts.append(f'{format_player_usernames(player)}')
                connected_row_texts.append(f'{format_player_logging_datetime(player.datetime.first_seen)}')
                connected_row_texts.append(f'{format_player_logging_datetime(player.datetime.last_rejoin)}')
                connected_row_texts.append(f'{format_elapsed_time(player.datetime.get_total_session_time())}')
                connected_row_texts.append(f'{format_elapsed_time(player.datetime.get_session_time())}')
                connected_row_texts.append(f'{player.rejoins}')
                connected_row_texts.append(f'{player.packets.total_exchanged}')
                connected_row_texts.append(f'{player.packets.exchanged}')
                connected_row_texts.append(f'{player.packets.total_received}')
                connected_row_texts.append(f'{player.packets.received}')
                connected_row_texts.append(f'{player.packets.total_sent}')
                connected_row_texts.append(f'{player.packets.sent}')
                connected_row_texts.append(f'{player.packets.pps.calculated_rate}')
                connected_row_texts.append(f'{player.packets.ppm.calculated_rate}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.exchanged)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.total_download)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.download)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.total_upload)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.upload)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate)}')
                connected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.bpm.calculated_rate)}')
                connected_row_texts.append(f'{format_player_ip(player.ip)}')
                connected_row_texts.append(f'{player.reverse_dns.hostname}')
                connected_row_texts.append(f'{player.ports.last}')
                connected_row_texts.append(f'{format_player_middle_ports(player)}')
                connected_row_texts.append(f'{player.ports.first}')
                connected_row_texts.append(f'{player.iplookup.ipapi.continent:<{session_connected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})')
                connected_row_texts.append(f'{player.iplookup.geolite2.country:<{session_connected__padding_country_name}} ({player.iplookup.geolite2.country_code})')
                connected_row_texts.append(f'{player.iplookup.ipapi.region}')
                connected_row_texts.append(f'{player.iplookup.ipapi.region_code}')
                connected_row_texts.append(f'{player.iplookup.geolite2.city}')
                connected_row_texts.append(f'{player.iplookup.ipapi.district}')
                connected_row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                connected_row_texts.append(f'{player.iplookup.ipapi.lat}')
                connected_row_texts.append(f'{player.iplookup.ipapi.lon}')
                connected_row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                connected_row_texts.append(f'{player.iplookup.ipapi.offset}')
                connected_row_texts.append(f'{player.iplookup.ipapi.currency}')
                connected_row_texts.append(f'{player.iplookup.ipapi.org}')
                connected_row_texts.append(f'{player.iplookup.ipapi.isp}')
                connected_row_texts.append(f'{player.iplookup.geolite2.asn}')
                connected_row_texts.append(f'{player.iplookup.ipapi.asn}')
                connected_row_texts.append(f'{player.iplookup.ipapi.as_name}')
                connected_row_texts.append(f'{player.iplookup.ipapi.mobile}')
                connected_row_texts.append(f'{player.iplookup.ipapi.proxy}')
                connected_row_texts.append(f'{player.iplookup.ipapi.hosting}')
                connected_row_texts.append(f'{player.ping.is_pinging}')
                logging_connected_players_table.add_row(connected_row_texts)

            logging_disconnected_players_table = PrettyTable()
            logging_disconnected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_disconnected_players_table.title = f"Player{pluralize(len(session_disconnected))} who've left your session ({len(session_disconnected)}):"
            logging_disconnected_players_table.field_names = logging_disconnected_players__column_names__with_down_arrow
            logging_disconnected_players_table.align = dict.fromkeys(logging_disconnected_players__column_names__with_down_arrow, 'l')
            for player in session_disconnected:
                disconnected_row_texts: list[str] = []
                disconnected_row_texts.append(f'{format_player_usernames(player)}')
                disconnected_row_texts.append(f'{format_player_logging_datetime(player.datetime.first_seen)}')
                disconnected_row_texts.append(f'{format_player_logging_datetime(player.datetime.last_rejoin)}')
                disconnected_row_texts.append(f'{format_player_logging_datetime(player.datetime.last_seen)}')
                disconnected_row_texts.append(f'{format_elapsed_time(player.datetime.get_total_session_time())}')
                disconnected_row_texts.append(f'{format_elapsed_time(player.datetime.get_session_time())}')
                disconnected_row_texts.append(f'{player.rejoins}')
                disconnected_row_texts.append(f'{player.packets.total_exchanged}')
                disconnected_row_texts.append(f'{player.packets.exchanged}')
                disconnected_row_texts.append(f'{player.packets.total_received}')
                disconnected_row_texts.append(f'{player.packets.received}')
                disconnected_row_texts.append(f'{player.packets.total_sent}')
                disconnected_row_texts.append(f'{player.packets.sent}')
                disconnected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged)}')
                disconnected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.exchanged)}')
                disconnected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.total_download)}')
                disconnected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.download)}')
                disconnected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.total_upload)}')
                disconnected_row_texts.append(f'{PlayerBandwidth.format_bytes(player.bandwidth.upload)}')
                disconnected_row_texts.append(f'{player.ip}')
                disconnected_row_texts.append(f'{player.reverse_dns.hostname}')
                disconnected_row_texts.append(f'{player.ports.last}')
                disconnected_row_texts.append(f'{format_player_middle_ports(player)}')
                disconnected_row_texts.append(f'{player.ports.first}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.continent:<{session_disconnected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})')
                disconnected_row_texts.append(f'{player.iplookup.geolite2.country:<{session_disconnected__padding_country_name}} ({player.iplookup.geolite2.country_code})')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.region}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.region_code}')
                disconnected_row_texts.append(f'{player.iplookup.geolite2.city}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.district}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.lat}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.lon}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.offset}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.currency}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.org}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.isp}')
                disconnected_row_texts.append(f'{player.iplookup.geolite2.asn}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.asn}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.as_name}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.mobile}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.proxy}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.hosting}')
                disconnected_row_texts.append(f'{player.ping.is_pinging}')
                logging_disconnected_players_table.add_row(disconnected_row_texts)

            # Check if the directories exist, if not create them
            if not SESSIONS_LOGGING_PATH.parent.is_dir():
                SESSIONS_LOGGING_PATH.parent.mkdir(parents=True)  # Create the directories if they don't exist

            # Check if the file exists, if not create it
            if not SESSIONS_LOGGING_PATH.is_file():
                SESSIONS_LOGGING_PATH.touch()  # Create the file if it doesn't exist

            SESSIONS_LOGGING_PATH.write_text(
                logging_connected_players_table.get_string() + '\n' + logging_disconnected_players_table.get_string(),
                encoding='utf-8',
            )

        def process_gui_session_tables_rendering() -> SessionTableSnapshot:
            return build_session_table_snapshot(
                SessionTableRenderContext(
                    session_connected=session_connected,
                    session_disconnected=session_disconnected,
                    connected_hidden_columns=connected_hidden_columns,
                    disconnected_hidden_columns=disconnected_hidden_columns,
                    connected_num_cols=connected_num_cols,
                    disconnected_num_cols=disconnected_num_cols,
                    connected_column_mapping=connected_column_mapping,
                ),
            )

        def generate_gui_status_text() -> tuple[str, str, str, str]:
            return build_gui_status_text(
                capture=capture,
                vpn_mode_enabled=vpn_mode_enabled,
                discord_rpc_manager=discord_rpc_manager,
            )

        logging_connected_players_table__column_names = list(Settings.GUI_ALL_CONNECTED_COLUMNS)
        logging_disconnected_players_table__column_names = list(Settings.GUI_ALL_DISCONNECTED_COLUMNS)
        last_userip_parse_time = None
        last_session_logging_processing_time = None
        discord_rpc_manager = None
        if Settings.DISCORD_PRESENCE:
            discord_rpc_manager = DiscordRPC(client_id=DISCORD_APPLICATION_ID)

        while not gui_closed__event.is_set():
            if ScriptControl.has_crashed():
                return

            if last_userip_parse_time is None or time.monotonic() - last_userip_parse_time >= 1.0:
                last_userip_parse_time = update_userip_databases()

            ModMenuLogsParser.refresh()

            global_bandwidth = 0
            global_download = 0
            global_upload = 0
            global_bps_rate = 0
            global_pps_rate = 0

            session_connected, session_disconnected = PlayersRegistry.get_default_sorted_connected_and_disconnected_players()
            for player in session_connected.copy():
                if (
                    not player.left_event.is_set()
                    and (datetime.now(tz=LOCAL_TZ) - player.datetime.last_seen).total_seconds() >= Settings.GUI_DISCONNECTED_PLAYERS_TIMER
                ):
                    player.mark_as_left()
                    session_connected.remove(player)
                    session_disconnected.append(player)

                    if GUIDetectionSettings.player_leave_notifications_enabled:
                        show_detection_warning_popup(player, 'player_left')

                    continue

                # Calculate PPS every second
                if (time.monotonic() - player.packets.pps.last_update_time) >= 1.0:
                    player.packets.pps.calculate_and_update_rate()

                # Calculate PPM every minute
                if (time.monotonic() - player.packets.ppm.last_update_time) >= SECONDS_PER_MINUTE:
                    player.packets.ppm.calculate_and_update_rate()

                # Calculate BPS every second
                if (time.monotonic() - player.bandwidth.bps.last_update_time) >= 1.0:
                    player.bandwidth.bps.calculate_and_update_rate()

                # Calculate BPM every minute
                if (time.monotonic() - player.bandwidth.bpm.last_update_time) >= SECONDS_PER_MINUTE:
                    player.bandwidth.bpm.calculate_and_update_rate()

                # Track current session bandwidth across all connected players
                global_bandwidth += player.bandwidth.exchanged
                global_download += player.bandwidth.download
                global_upload += player.bandwidth.upload
                global_bps_rate += player.bandwidth.bps.calculated_rate
                global_pps_rate += player.packets.pps.calculated_rate

            # Update global stats once after all calculations
            TsharkStats.global_bandwidth = global_bandwidth
            TsharkStats.global_download = global_download
            TsharkStats.global_upload = global_upload
            TsharkStats.global_bps_rate = global_bps_rate
            TsharkStats.global_pps_rate = global_pps_rate

            for player in session_connected + session_disconnected:
                if player.userip and player.ip not in UserIPDatabases.ips_set:
                    player.userip = None
                    player.userip_detection = None

                modmenu_usernames_for_player = ModMenuLogsParser.get_usernames_by_ip(player.ip)
                if modmenu_usernames_for_player:
                    if player.mod_menus is None:
                        player.mod_menus = PlayerModMenus(
                            usernames=modmenu_usernames_for_player,
                        )
                    else:
                        player.mod_menus.usernames[:] = modmenu_usernames_for_player
                else:
                    player.mod_menus = None

                player.usernames = dedup_preserve_order(
                    player.userip.usernames if player.userip else [],
                    player.mod_menus.usernames if player.mod_menus else [],
                )

                if player.country_flag is None:
                    country_code = (
                        player.iplookup.geolite2.country_code
                        if player.iplookup.geolite2.country_code not in ['...', 'N/A']
                        else player.iplookup.ipapi.country_code
                        if player.iplookup.ipapi.country_code not in ['...', 'N/A']
                        else None
                    )
                    if (
                        country_code
                        and (flag_path := COUNTRY_FLAGS_DIR_PATH / f'{country_code.upper()}.png').exists()
                    ):
                        pixmap = QPixmap()
                        pixmap.loadFromData(flag_path.read_bytes())
                        player.country_flag = PlayerCountryFlag(
                            pixmap=pixmap,
                            icon=QIcon(pixmap),
                        )

                if not player.iplookup.geolite2.is_initialized:
                    player.iplookup.geolite2.country, player.iplookup.geolite2.country_code = get_country_info(player.ip)
                    player.iplookup.geolite2.city = get_city_info(player.ip)
                    player.iplookup.geolite2.asn = get_asn_info(player.ip)
                    player.iplookup.geolite2.is_initialized = True

                if player in session_connected:
                    if (
                        player.iplookup.ipapi.mobile is True
                        and GUIDetectionSettings.mobile_detection_enabled
                        and not MobileWarnings.is_ip_notified(player.ip)
                        and MobileWarnings.add_notified_ip(player.ip)
                    ):
                        show_detection_warning_popup(player, 'mobile')

                    if (
                        player.iplookup.ipapi.proxy is True
                        and GUIDetectionSettings.vpn_detection_enabled
                        and not VPNWarnings.is_ip_notified(player.ip)
                        and VPNWarnings.add_notified_ip(player.ip)
                    ):
                        show_detection_warning_popup(player, 'vpn')

                    if (
                        player.iplookup.ipapi.hosting is True
                        and GUIDetectionSettings.hosting_detection_enabled
                        and not HostingWarnings.is_ip_notified(player.ip)
                        and HostingWarnings.add_notified_ip(player.ip)
                    ):
                        show_detection_warning_popup(player, 'hosting')

            if Settings.CAPTURE_PROGRAM_PRESET == 'GTA5':
                if SessionHost.player and SessionHost.player.left_event.is_set():
                    SessionHost.player = None
                # TODO(BUZZARDGTA): We should also potentially needs to check that not more then 1s passed before each disconnected
                if SessionHost.players_pending_for_disconnection and all(player.left_event.is_set() for player in SessionHost.players_pending_for_disconnection):
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()

                if not session_connected:
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()
                elif len(session_connected) >= 1 and all(
                    not player.packets.pps.is_first_calculation and not player.packets.pps.calculated_rate for player in session_connected
                ):
                    SessionHost.players_pending_for_disconnection = session_connected
                elif SessionHost.search_player:
                    SessionHost.get_host_player(session_connected)

            if Settings.GUI_SESSIONS_LOGGING and (last_session_logging_processing_time is None or (time.monotonic() - last_session_logging_processing_time) >= 1.0):
                last_session_logging_processing_time = time.monotonic()
                process_session_logging()

            if (Settings.DISCORD_PRESENCE and discord_rpc_manager is not None and
                (discord_rpc_manager.last_update_time is None or
                 (time.monotonic() - discord_rpc_manager.last_update_time) >= DISCORD_PRESENCE_UPDATE_INTERVAL_SECONDS)):
                discord_rpc_manager.update(f'{len(session_connected)} player{pluralize(len(session_connected))} connected')

            connected_hidden_columns = set(Settings.GUI_COLUMNS_CONNECTED_HIDDEN)
            disconnected_hidden_columns = set(Settings.GUI_COLUMNS_DISCONNECTED_HIDDEN)
            connected_column_names = [
                column_name
                for column_name in Settings.GUI_ALL_CONNECTED_COLUMNS
                if column_name not in connected_hidden_columns
            ]
            disconnected_column_names = [
                column_name
                for column_name in Settings.GUI_ALL_DISCONNECTED_COLUMNS
                if column_name not in disconnected_hidden_columns
            ]
            connected_num_cols = len(connected_column_names)
            disconnected_num_cols = len(disconnected_column_names)
            connected_column_mapping = {header: index for index, header in enumerate(connected_column_names)}
            header_text = generate_gui_header_html(capture=capture)
            (
                status_capture_text,
                status_config_text,
                status_issues_text,
                status_performance_text,
            ) = generate_gui_status_text()
            session_table_snapshot = process_gui_session_tables_rendering()

            GUIRenderingState.publish_rendering_snapshot(
                GUIRenderingSnapshot(
                    connected_hidden_columns=connected_hidden_columns,
                    disconnected_hidden_columns=disconnected_hidden_columns,
                    connected_column_names=connected_column_names,
                    disconnected_column_names=disconnected_column_names,
                    header_text=header_text,
                    status_capture_text=status_capture_text,
                    status_config_text=status_config_text,
                    status_issues_text=status_issues_text,
                    status_performance_text=status_performance_text,
                    connected_num_cols=connected_num_cols,
                    connected_num_rows=session_table_snapshot.connected_num,
                    connected_rows=session_table_snapshot.connected_rows,
                    connected_colors=session_table_snapshot.connected_colors,
                    disconnected_num_cols=disconnected_num_cols,
                    disconnected_num_rows=session_table_snapshot.disconnected_num,
                    disconnected_rows=session_table_snapshot.disconnected_rows,
                    disconnected_colors=session_table_snapshot.disconnected_colors,
                ),
            )

            gui_closed__event.wait(1)
