"""Core rendering loop that compiles GUI payloads from runtime state."""

import json
import re
import time
from datetime import datetime
from itertools import chain
from operator import attrgetter
from threading import Thread
from typing import TYPE_CHECKING

import geoip2.errors
from prettytable import PrettyTable, TableStyle
from pydantic import ValidationError
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QImage
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox

from session_sniffer.background.tasks import gui_closed__event, handle_detection_notification, process_userip_task
from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import IMAGES_DIR_PATH, SESSIONS_LOGGING_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.core import ScriptControl, ThreadsExceptionHandler
from session_sniffer.diagnostics import SlowdownDetector
from session_sniffer.discord.rpc import DiscordRPC
from session_sniffer.error_messages import (
    format_type_error,
    format_userip_corrupted_settings_message,
    format_userip_duplicate_entries_message,
    format_userip_invalid_ip_entry_message,
    format_userip_missing_settings_message,
)
from session_sniffer.guis.html_templates import generate_gui_header_html
from session_sniffer.logging_setup import get_logger
from session_sniffer.models.player import Player, PlayerBandwidth, PlayerCountryFlag, PlayerModMenus
from session_sniffer.models.userip_settings_model import UserIPSettingsModel
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.player.registry import MINIMUM_PACKETS_FOR_SESSION_HOST, SESSION_HOST_CANDIDATE_PLAYERS_COUNT, PlayersRegistry, SessionHost
from session_sniffer.player.userip import ProtectionSettings, UserIPDatabases, UserIPSettings, gui_dispatcher
from session_sniffer.rendering_core.modmenu_logs_parser import ModMenuLogsParser
from session_sniffer.rendering_core.session_table_renderer import (
    SessionTableRenderContext,
    build_session_table_snapshot,
    format_elapsed_time,
    format_player_ip,
    format_player_middle_ports,
    format_player_usernames,
)
from session_sniffer.rendering_core.status_bar_renderer import build_gui_status_text
from session_sniffer.rendering_core.types import (
    GeoIP2Readers,
    GUIColumnConfig,
    GUIRenderingSnapshot,
    GUIRenderingState,
    GUIStatusTexts,
    GUITableData,
    SessionTableSnapshot,
    TsharkStats,
)
from session_sniffer.settings import Settings
from session_sniffer.settings.settings import RE_SETTINGS_INI_PARSER_PATTERN
from session_sniffer.text_templates import DEFAULT_USERIP_FILES_SETTINGS_INI, USERIP_DEFAULT_DB_FOOTER_TEMPLATE, USERIP_DEFAULT_DB_HEADER_TEMPLATE
from session_sniffer.text_utils import format_triple_quoted_text, pluralize
from session_sniffer.utils import dedup_preserve_order, get_session_log_path, validate_file

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from session_sniffer.capture.tshark_capture import CaptureHolder

logger = get_logger(__name__)


def _warn_on_gui(text: str) -> None:
    """Show a non-modal PyQt6 warning dialog on the GUI thread from any thread."""
    def _show() -> None:
        parent = next(
            (w for w in QApplication.topLevelWidgets() if isinstance(w, QMainWindow) and w.isVisible()),
            None,
        )
        if parent is None:
            QTimer.singleShot(500, _show)
            return
        dlg = QMessageBox(parent)
        dlg.setWindowModality(Qt.WindowModality.NonModal)
        dlg.setWindowTitle(TITLE)
        dlg.setText(text)
        dlg.setIcon(QMessageBox.Icon.Warning)
        dlg.setStandardButtons(QMessageBox.StandardButton.Ok)
        dlg.show()
    gui_dispatcher.invoke(_show)


RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')

USERIP_INI_SETTINGS = [
    'ENABLED', 'COLOR', 'NOTIFICATIONS', 'VOICE_NOTIFICATIONS', 'LOG', 'PROTECTION',
    'PROTECTION_PROCESS_PATH', 'PROTECTION_SUSPEND_PROCESS_MODE',
]

DISCORD_APPLICATION_ID = 1313304495958261781
COUNTRY_FLAGS_DIR_PATH = IMAGES_DIR_PATH / 'country_flags'
SESSIONS_LOGGING_PATH = get_session_log_path(SESSIONS_LOGGING_DIR_PATH, LOCAL_TZ)
SECONDS_PER_MINUTE = 60.0
DISCORD_PRESENCE_UPDATE_INTERVAL_SECONDS = 3.0


def rendering_core(
    capture_holder: CaptureHolder,
    geoip2_readers: GeoIP2Readers,
) -> None:
    """Compile GUI payloads from runtime state and emit updates."""
    with ThreadsExceptionHandler():
        def parse_userip_ini_file(ini_path: Path, unresolved_ip_invalid: set[str]) -> tuple[UserIPSettings | None, dict[str, list[str]] | None]:
            def process_ini_line_output(line: str) -> str:
                return line.strip()

            validate_file(ini_path)

            raw_settings: dict[str, str] = {}
            setting_line_indices: dict[str, int] = {}
            userip: dict[str, list[str]] = {}
            all_seen_ips: set[str] = set()
            duplicate_entries: list[tuple[str, str]] = []
            current_section = None
            matched_settings: list[str] = []
            ini_data = ini_path.read_text('utf-8')
            corrected_ini_data_lines: list[str] = []

            for line in map(process_ini_line_output, ini_data.splitlines(keepends=True)):
                if line.startswith('[') and line.endswith(']'):
                    # Add a blank line before each section header for readability (unless the previous kept line is already blank).
                    if corrected_ini_data_lines and corrected_ini_data_lines[-1]:
                        corrected_ini_data_lines.append('')

                    corrected_ini_data_lines.append(line)
                    current_section = line[1:-1]
                    continue

                if current_section is None:
                    corrected_ini_data_lines.append(line)
                    continue

                if current_section == 'Settings':
                    if not (match := RE_SETTINGS_INI_PARSER_PATTERN.search(line)):
                        # Keep comments; drop other non-setting lines in [Settings] so the file can be normalized on rewrite.
                        if line.startswith((';', '#')):
                            corrected_ini_data_lines.append(line)
                        continue

                    if (setting := match.group('key')) is None:
                        continue
                    if not isinstance(setting, str):
                        raise TypeError(format_type_error(setting, str))
                    if (value := match.group('value')) is None:
                        continue
                    if not isinstance(value, str):
                        raise TypeError(format_type_error(value, str))

                    if not (setting := setting.strip()):
                        continue
                    if not (value := value.strip()):
                        continue

                    # Unknown keys are dropped from the corrected output.
                    if setting not in USERIP_INI_SETTINGS:
                        continue

                    # Duplicate keys: keep the first occurrence only.
                    if setting in raw_settings:
                        continue

                    corrected_ini_data_lines.append(line)
                    matched_settings.append(setting)
                    raw_settings[setting] = value
                    setting_line_indices[setting] = len(corrected_ini_data_lines) - 1

                elif current_section == 'UserIP':
                    if not (match := RE_USERIP_INI_PARSER_PATTERN.search(line)):
                        corrected_ini_data_lines.append(line)
                        continue
                    if (username := match.group('username')) is None:
                        corrected_ini_data_lines.append(line)
                        continue
                    if not isinstance(username, str):
                        raise TypeError(format_type_error(username, str))
                    if (ip := match.group('ip')) is None:
                        corrected_ini_data_lines.append(line)
                        continue
                    if not isinstance(ip, str):
                        raise TypeError(format_type_error(ip, str))

                    if not (username := username.strip()):
                        corrected_ini_data_lines.append(line)
                        continue
                    if not (ip := ip.strip()):
                        corrected_ini_data_lines.append(line)
                        continue

                    if not is_valid_ip_range_entry(ip):
                        unresolved_ip_invalid.add(f'{ini_path}={username}={ip}')
                        if f'{ini_path}={username}={ip}' not in UserIPDatabases.notified_ip_invalid:
                            _warn_on_gui(format_triple_quoted_text(format_userip_invalid_ip_entry_message(
                                ini_path=ini_path,
                                username=username,
                                ip=ip,
                                configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                            )))
                            UserIPDatabases.notified_ip_invalid.add(f'{ini_path}={username}={ip}')
                        continue

                    if ip in all_seen_ips:
                        # Duplicate IP entry (same or different username) — drop from corrected output.
                        duplicate_entries.append((username, ip))
                        continue

                    corrected_ini_data_lines.append(line)
                    all_seen_ips.add(ip)
                    if username in userip:
                        userip[username].append(ip)
                    else:
                        userip[username] = [ip]

            if duplicate_entries:
                if ini_path not in UserIPDatabases.notified_duplicate_entries:
                    UserIPDatabases.notified_duplicate_entries.add(ini_path)
                    _warn_on_gui(format_triple_quoted_text(format_userip_duplicate_entries_message(
                        ini_path=ini_path,
                        duplicates=duplicate_entries,
                    )))
            else:
                UserIPDatabases.notified_duplicate_entries.discard(ini_path)

            list_of_missing_settings = [setting for setting in USERIP_INI_SETTINGS if setting not in matched_settings]
            number_of_settings_missing = len(list_of_missing_settings)

            if number_of_settings_missing > 0:
                if ini_path not in UserIPDatabases.notified_settings_corrupted:
                    UserIPDatabases.notified_settings_corrupted.add(ini_path)
                    _warn_on_gui(format_triple_quoted_text(format_userip_missing_settings_message(
                        ini_path=ini_path,
                        missing_settings=list_of_missing_settings,
                        configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                    )))
                return None, None

            # Validate all collected settings via Pydantic model
            try:
                validated, ini_rewrites = UserIPSettingsModel.validate_settings(raw_settings)
            except ValidationError as exc:
                # Extract the first corrupted field for user notification
                first_error = exc.errors()[0]
                corrupted_setting = str(first_error['loc'][0]) if first_error['loc'] else 'UNKNOWN'
                corrupted_value = raw_settings.get(corrupted_setting, '')
                if ini_path not in UserIPDatabases.notified_settings_corrupted:
                    UserIPDatabases.notified_settings_corrupted.add(ini_path)
                    _warn_on_gui(format_triple_quoted_text(format_userip_corrupted_settings_message(
                        ini_path=ini_path,
                        setting=corrupted_setting,
                        value=corrupted_value,
                        configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#userip-ini-databases-configuration',
                    )))
                return None, None

            # Apply line rewrites from validated model
            for field_name, rewrite_value in ini_rewrites.items():
                if field_name in setting_line_indices:
                    corrected_ini_data_lines[setting_line_indices[field_name]] = f'{field_name}={rewrite_value}'

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
                enabled=validated.ENABLED,
                color=validated.COLOR,
                log=validated.LOG,
                notifications=validated.NOTIFICATIONS,
                voice_notifications=validated.VOICE_NOTIFICATIONS,
                protection=ProtectionSettings(
                    enabled=bool(validated.PROTECTION),
                    process_path=validated.PROTECTION_PROCESS_PATH,
                    suspend_process_mode=validated.PROTECTION_SUSPEND_PROCESS_MODE,
                ),
            ), userip

        def _snapshot_userip_database_mod_times() -> dict[Path, float]:
            """Return current modification times of all existing UserIP database INIs."""
            return {
                path.resolve(): path.stat().st_mtime
                for path in USERIP_DATABASES_DIR_PATH.rglob('*.ini')
                if path.is_file()
            }

        last_known_userip_db_mod_times: dict[Path, float] = {}

        def update_userip_databases() -> float:
            nonlocal last_known_userip_db_mod_times
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

            current_userip_db_mod_times = _snapshot_userip_database_mod_times()
            if current_userip_db_mod_times == last_known_userip_db_mod_times:
                # Files unchanged, but new players may have joined since the last rebuild.
                # This keeps per-player mapping up-to-date without re-validating/re-parsing INIs.
                UserIPDatabases.build()
                return time.monotonic()
            if last_known_userip_db_mod_times:
                logger.info('Detected changes in UserIP databases, re-parsing...')

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

            # INI parsing may have rewritten files; re-snapshot so we don't immediately re-parse next tick.
            last_known_userip_db_mod_times = _snapshot_userip_database_mod_times()

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
                    country_len = len(str(player.iplookup.geolite2.country))
                    continent_len = len(str(player.iplookup.ipapi.continent))

                    # Only include in padding calculation if within threshold
                    if country_len <= table_country_column_length_threshold:
                        connected_country_padding = max(connected_country_padding, country_len)
                    if continent_len <= table_continent_column_length_threshold:
                        connected_continent_padding = max(connected_continent_padding, continent_len)

                # Calculate optimal padding for disconnected players
                for player in disconnected_players:
                    country_len = len(str(player.iplookup.geolite2.country))
                    continent_len = len(str(player.iplookup.ipapi.continent))

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
            for field_name in logging_connected_players__column_names__with_down_arrow:
                logging_connected_players_table.align[field_name] = 'l'
            for player in session_connected:
                connected_row_texts: list[str] = []
                connected_row_texts.append(format_player_usernames(player))
                connected_row_texts.append(format_player_logging_datetime(player.datetime.first_seen))
                connected_row_texts.append(format_player_logging_datetime(player.datetime.last_rejoin))
                connected_row_texts.append(format_elapsed_time(player.datetime.get_total_session_time()))
                connected_row_texts.append(format_elapsed_time(player.datetime.get_session_time()))
                connected_row_texts.append(f'{player.rejoins}')
                connected_row_texts.append(f'{player.packets.total_exchanged}')
                connected_row_texts.append(f'{player.packets.exchanged}')
                connected_row_texts.append(f'{player.packets.total_received}')
                connected_row_texts.append(f'{player.packets.received}')
                connected_row_texts.append(f'{player.packets.total_sent}')
                connected_row_texts.append(f'{player.packets.sent}')
                connected_row_texts.append(f'{player.packets.pps.calculated_rate}')
                connected_row_texts.append(f'{player.packets.ppm.calculated_rate}')
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.exchanged))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_download))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.download))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_upload))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.upload))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate))
                connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.bpm.calculated_rate))
                connected_row_texts.append(format_player_ip(player.ip))
                connected_row_texts.append(player.reverse_dns.hostname)
                connected_row_texts.append(f'{player.ports.last}')
                connected_row_texts.append(format_player_middle_ports(player))
                connected_row_texts.append(f'{player.ports.first}')
                connected_row_texts.append(f'{player.iplookup.ipapi.continent:<{session_connected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})')
                connected_row_texts.append(f'{player.iplookup.geolite2.country:<{session_connected__padding_country_name}} ({player.iplookup.geolite2.country_code})')
                connected_row_texts.append(f'{player.iplookup.ipapi.region}')
                connected_row_texts.append(f'{player.iplookup.ipapi.region_code}')
                connected_row_texts.append(player.iplookup.geolite2.city)
                connected_row_texts.append(f'{player.iplookup.ipapi.district}')
                connected_row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                connected_row_texts.append(f'{player.iplookup.ipapi.lat}')
                connected_row_texts.append(f'{player.iplookup.ipapi.lon}')
                connected_row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                connected_row_texts.append(f'{player.iplookup.ipapi.offset}')
                connected_row_texts.append(f'{player.iplookup.ipapi.currency}')
                connected_row_texts.append(f'{player.iplookup.ipapi.org}')
                connected_row_texts.append(f'{player.iplookup.ipapi.isp}')
                connected_row_texts.append(player.iplookup.geolite2.asn)
                connected_row_texts.append(f'{player.iplookup.ipapi.asn}')
                connected_row_texts.append(f'{player.iplookup.ipapi.as_name}')
                connected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.mobile else 'No')
                connected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.proxy else 'No')
                connected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.hosting else 'No')
                connected_row_texts.append('...' if not player.ping.is_initialized else 'Yes' if player.ping.is_pinging else 'No')
                logging_connected_players_table.add_row(connected_row_texts)

            logging_disconnected_players_table = PrettyTable()
            logging_disconnected_players_table.set_style(TableStyle.SINGLE_BORDER)
            logging_disconnected_players_table.title = f"Player{pluralize(len(session_disconnected))} who've left your session ({len(session_disconnected)}):"
            logging_disconnected_players_table.field_names = logging_disconnected_players__column_names__with_down_arrow
            for field_name in logging_disconnected_players__column_names__with_down_arrow:
                logging_disconnected_players_table.align[field_name] = 'l'
            for player in session_disconnected:
                disconnected_row_texts: list[str] = []
                disconnected_row_texts.append(format_player_usernames(player))
                disconnected_row_texts.append(format_player_logging_datetime(player.datetime.first_seen))
                disconnected_row_texts.append(format_player_logging_datetime(player.datetime.last_rejoin))
                disconnected_row_texts.append(format_player_logging_datetime(player.datetime.last_seen))
                disconnected_row_texts.append(format_elapsed_time(player.datetime.get_total_session_time()))
                disconnected_row_texts.append(format_elapsed_time(player.datetime.get_session_time()))
                disconnected_row_texts.append(f'{player.rejoins}')
                disconnected_row_texts.append(f'{player.packets.total_exchanged}')
                disconnected_row_texts.append(f'{player.packets.exchanged}')
                disconnected_row_texts.append(f'{player.packets.total_received}')
                disconnected_row_texts.append(f'{player.packets.received}')
                disconnected_row_texts.append(f'{player.packets.total_sent}')
                disconnected_row_texts.append(f'{player.packets.sent}')
                disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged))
                disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.exchanged))
                disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_download))
                disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.download))
                disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_upload))
                disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.upload))
                disconnected_row_texts.append(player.ip)
                disconnected_row_texts.append(player.reverse_dns.hostname)
                disconnected_row_texts.append(f'{player.ports.last}')
                disconnected_row_texts.append(format_player_middle_ports(player))
                disconnected_row_texts.append(f'{player.ports.first}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.continent:<{session_disconnected__padding_continent_name}} ({player.iplookup.ipapi.continent_code})')
                disconnected_row_texts.append(f'{player.iplookup.geolite2.country:<{session_disconnected__padding_country_name}} ({player.iplookup.geolite2.country_code})')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.region}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.region_code}')
                disconnected_row_texts.append(player.iplookup.geolite2.city)
                disconnected_row_texts.append(f'{player.iplookup.ipapi.district}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.zip_code}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.lat}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.lon}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.time_zone}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.offset}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.currency}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.org}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.isp}')
                disconnected_row_texts.append(player.iplookup.geolite2.asn)
                disconnected_row_texts.append(f'{player.iplookup.ipapi.asn}')
                disconnected_row_texts.append(f'{player.iplookup.ipapi.as_name}')
                disconnected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.mobile else 'No')
                disconnected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.proxy else 'No')
                disconnected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.hosting else 'No')
                disconnected_row_texts.append('...' if not player.ping.is_initialized else 'Yes' if player.ping.is_pinging else 'No')
                logging_disconnected_players_table.add_row(disconnected_row_texts)

            # Check if the directories exist, if not create them
            SESSIONS_LOGGING_PATH.parent.mkdir(parents=True, exist_ok=True)

            SESSIONS_LOGGING_PATH.write_text(
                logging_connected_players_table.get_string() + '\n' + logging_disconnected_players_table.get_string(),
                encoding='utf-8',
            )

            # Write structured JSON sibling for programmatic analysis (e.g. Seen Stats)
            def _player_to_json_dict(player: Player) -> dict[str, object]:
                return {
                    'Usernames': player.usernames,
                    'First Seen': player.datetime.first_seen.isoformat(),
                    'Last Rejoin': player.datetime.last_rejoin.isoformat(),
                    'Last Seen': player.datetime.last_seen.isoformat(),
                    'Rejoins': player.rejoins,
                    'Packets': player.packets.total_exchanged,
                    'Country': str(player.iplookup.geolite2.country),
                    'Country Code': str(player.iplookup.geolite2.country_code),
                    'City': str(player.iplookup.geolite2.city),
                    'ISP': str(player.iplookup.ipapi.isp),
                    'ASN': str(player.iplookup.geolite2.asn),
                    'Hostname': player.reverse_dns.hostname,
                    'Mobile': player.iplookup.ipapi.mobile,
                    'VPN': player.iplookup.ipapi.proxy,
                    'Hosting': player.iplookup.ipapi.hosting,
                }

            json_snapshot: dict[str, dict[str, dict[str, object]]] = {
                'connected': {player.ip: _player_to_json_dict(player) for player in session_connected},
                'disconnected': {player.ip: _player_to_json_dict(player) for player in session_disconnected},
            }
            json_path = SESSIONS_LOGGING_PATH.with_suffix('.json')
            json_path.write_text(json.dumps(json_snapshot, ensure_ascii=False), encoding='utf-8')

        def process_gui_session_tables_rendering() -> SessionTableSnapshot:
            return build_session_table_snapshot(
                SessionTableRenderContext(
                    session_connected=session_connected,
                    session_disconnected=session_disconnected,
                    connected_shown_columns=connected_shown_columns,
                    disconnected_shown_columns=disconnected_shown_columns,
                    connected_num_cols=connected_num_cols,
                    disconnected_num_cols=disconnected_num_cols,
                    connected_column_mapping=connected_column_mapping,
                ),
            )

        def generate_gui_status_text() -> tuple[str, str, str, str]:
            return build_gui_status_text(
                capture=capture,
                vpn_mode_enabled=TsharkStats.vpn_mode_enabled,
                discord_rpc_manager=discord_rpc_manager,
            )

        logging_connected_players_table__column_names = list(Settings.GUI_ALL_CONNECTED_COLUMNS)
        logging_disconnected_players_table__column_names = list(Settings.GUI_ALL_DISCONNECTED_COLUMNS)
        last_userip_parse_time = None
        last_session_logging_processing_time = None
        discord_rpc_manager: DiscordRPC | None = None

        _rendering_slowdown = SlowdownDetector.get('rendering_loop')

        while not gui_closed__event.is_set():
            capture = capture_holder.get()  # Resolve the active capture each iteration
            _rendering_loop_start = time.monotonic()

            if ScriptControl.has_crashed():
                break

            if last_userip_parse_time is None or time.monotonic() - last_userip_parse_time >= 1.0:
                last_userip_parse_time = update_userip_databases()

            ModMenuLogsParser.refresh()

            global_bandwidth = 0
            global_download = 0
            global_upload = 0
            global_bps_rate = 0
            global_pps_rate = 0

            session_connected, session_disconnected = PlayersRegistry.get_default_sorted_connected_and_disconnected_players()
            connected_ips: set[str] = {p.ip for p in session_connected}
            players_to_disconnect: list[int] = []
            for idx, player in enumerate(session_connected):
                if (
                    not player.left_event.is_set()
                    and (datetime.now(tz=LOCAL_TZ) - player.datetime.last_seen).total_seconds() >= Settings.gui_disconnected_players_timer
                ):
                    player.mark_as_left()
                    players_to_disconnect.append(idx)
                    connected_ips.discard(player.ip)
                    session_disconnected.append(player)

                    if player.userip_detection and player.userip_detection.as_processed_task:
                        player.userip_detection.as_processed_task = False
                        Thread(
                            target=process_userip_task,
                            name=f'ProcessUserIPTask-{player.ip}-disconnected',
                            args=(player, 'disconnected'), daemon=True,
                        ).start()

                    handle_detection_notification(player, 'player_left_session')

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

            # Remove disconnected players from session_connected in reverse index order
            for idx in reversed(players_to_disconnect):
                del session_connected[idx]

            for player in chain(session_connected, session_disconnected):
                if player.userip and not UserIPDatabases.is_known_ip(player.ip):
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
                    country_code_value = (
                        player.iplookup.geolite2.country_code
                        if player.iplookup.geolite2.country_code not in {'...', 'N/A'}
                        else player.iplookup.ipapi.country_code
                        if player.iplookup.ipapi.country_code not in {'...', 'N/A'}
                        else None
                    )
                    country_code = country_code_value if isinstance(country_code_value, str) else None
                    if country_code:
                        flag_path = COUNTRY_FLAGS_DIR_PATH / f'{country_code.upper()}.png'
                        if flag_path.exists():
                            image = QImage()
                            image.loadFromData(flag_path.read_bytes())
                            player.country_flag = PlayerCountryFlag(image)

                if not player.iplookup.geolite2.is_initialized:
                    player.iplookup.geolite2.country, player.iplookup.geolite2.country_code = get_country_info(player.ip)
                    player.iplookup.geolite2.city = get_city_info(player.ip)
                    player.iplookup.geolite2.asn = get_asn_info(player.ip)
                    player.iplookup.geolite2.is_initialized = True

            if Settings.capture_program_preset == 'GTA5':
                if SessionHost.player and SessionHost.player.left_event.is_set():
                    logger.debug('[SessionHost] Current host %s left_event is set, clearing host', SessionHost.player.ip)
                    SessionHost.player = None
                # TODO(BUZZARDGTA): We should also potentially needs to check that not more then 1s passed before each disconnected
                if SessionHost.players_pending_for_disconnection and all(player.left_event.is_set() for player in SessionHost.players_pending_for_disconnection):
                    logger.debug(
                        '[SessionHost] All %d pending disconnection players have left, resetting host and triggering search',
                        len(SessionHost.players_pending_for_disconnection),
                    )
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()

                if not session_connected:
                    if SessionHost.player or not SessionHost.search_player:
                        logger.debug('[SessionHost] No connected players, resetting host and triggering search')
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection.clear()
                elif len(session_connected) >= 1 and all(
                    not player.packets.pps.is_first_calculation and not player.packets.pps.calculated_rate for player in session_connected
                ):
                    logger.debug(
                        '[SessionHost] All %d connected players have 0 PPS (past first calc), marking as pending for disconnection',
                        len(session_connected),
                    )
                    SessionHost.players_pending_for_disconnection = session_connected
                elif SessionHost.search_player:
                    logger.debug(
                        '[SessionHost] search_player=True, calling get_host_player with %d connected players',
                        len(session_connected),
                    )
                    SessionHost.get_host_player(session_connected)
                elif (
                    not SessionHost.player
                    and SessionHost.last_ambiguous_candidates is not None
                    and len(session_connected) >= SESSION_HOST_CANDIDATE_PLAYERS_COUNT
                ):
                    top2 = sorted(session_connected, key=attrgetter('datetime.last_rejoin'))[:SESSION_HOST_CANDIDATE_PLAYERS_COUNT]
                    current_pair = (top2[0].ip, top2[1].ip)
                    if current_pair != SessionHost.last_ambiguous_candidates:
                        logger.debug(
                            '[SessionHost] Top candidates changed from %s to %s, re-triggering search',
                            SessionHost.last_ambiguous_candidates, current_pair,
                        )
                        SessionHost.last_ambiguous_candidates = None
                        SessionHost.search_player = True
                    elif all(p.packets.exchanged >= MINIMUM_PACKETS_FOR_SESSION_HOST for p in top2):
                        logger.debug(
                            '[SessionHost] Both ambiguous candidates now have >= %d packets, re-triggering search for packet count tiebreaker',
                            MINIMUM_PACKETS_FOR_SESSION_HOST,
                        )
                        SessionHost.last_ambiguous_candidates = None
                        SessionHost.search_player = True

            if Settings.gui_sessions_logging and (last_session_logging_processing_time is None or (time.monotonic() - last_session_logging_processing_time) >= 1.0):
                last_session_logging_processing_time = time.monotonic()
                process_session_logging()

            # Runtime Discord RPC toggle: create or close based on current setting
            if Settings.discord_presence and discord_rpc_manager is None:
                discord_rpc_manager = DiscordRPC(client_id=DISCORD_APPLICATION_ID)
            elif not Settings.discord_presence and discord_rpc_manager is not None:
                discord_rpc_manager.close()
                discord_rpc_manager = None

            if (discord_rpc_manager is not None and
                (discord_rpc_manager.last_update_time is None or
                 (time.monotonic() - discord_rpc_manager.last_update_time) >= DISCORD_PRESENCE_UPDATE_INTERVAL_SECONDS)):
                discord_rpc_manager.update(
                    state_message=f'{len(session_connected)} player{pluralize(len(session_connected))} connected',
                    details=Settings.discord_presence_title or None,
                )

            connected_shown_columns = set(Settings.gui_columns_connected_shown)
            disconnected_shown_columns = set(Settings.gui_columns_disconnected_shown)
            connected_column_names = [
                column_name
                for column_name in Settings.GUI_ALL_CONNECTED_COLUMNS
                if column_name in connected_shown_columns or column_name in Settings.GUI_FORCED_COLUMNS
            ]
            disconnected_column_names = [
                column_name
                for column_name in Settings.GUI_ALL_DISCONNECTED_COLUMNS
                if column_name in disconnected_shown_columns or column_name in Settings.GUI_FORCED_COLUMNS
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
                    column_config=GUIColumnConfig(
                        connected_shown_columns=connected_shown_columns,
                        disconnected_shown_columns=disconnected_shown_columns,
                        connected_column_names=connected_column_names,
                        disconnected_column_names=disconnected_column_names,
                    ),
                    status=GUIStatusTexts(
                        header_text=header_text,
                        status_capture_text=status_capture_text,
                        status_config_text=status_config_text,
                        status_issues_text=status_issues_text,
                        status_performance_text=status_performance_text,
                    ),
                    connected=GUITableData(
                        num_cols=connected_num_cols,
                        num_rows=session_table_snapshot.connected_num,
                        rows=session_table_snapshot.connected_rows,
                        colors=session_table_snapshot.connected_colors,
                    ),
                    disconnected=GUITableData(
                        num_cols=disconnected_num_cols,
                        num_rows=session_table_snapshot.disconnected_num,
                        rows=session_table_snapshot.disconnected_rows,
                        colors=session_table_snapshot.disconnected_colors,
                    ),
                ),
            )

            _rendering_slowdown.check(time.monotonic() - _rendering_loop_start, 'rendering_loop')

            gui_closed__event.wait(1)

        if discord_rpc_manager is not None:
            discord_rpc_manager.close()
