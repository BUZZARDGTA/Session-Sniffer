"""Session table snapshot rendering helpers."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from PyQt6.QtGui import QColor
from qdarkstyle.colorsystem import Gray  # pyright: ignore[reportMissingTypeStubs]

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.guis.colors import TableColors
from session_sniffer.guis.exceptions import InvalidDateColumnConfigurationError
from session_sniffer.models.player import Player, PlayerBandwidth
from session_sniffer.player.registry import SessionHost
from session_sniffer.rendering_core.types import CellColor, SessionTableSnapshot
from session_sniffer.settings import Settings

PPS_MAX_THRESHOLD = 10
PPM_MAX_THRESHOLD = PPS_MAX_THRESHOLD * 60
BPS_MAX_THRESHOLD = 1024
BPM_MAX_THRESHOLD = BPS_MAX_THRESHOLD * 60
HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR = QColor(Gray.B10)


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


def _format_player_gui_datetime(datetime_object: datetime) -> str:
    formatted_elapsed = None

    if Settings.gui_columns_datetime_show_elapsed_time:
        elapsed_time = datetime.now(tz=LOCAL_TZ) - datetime_object
        formatted_elapsed = format_elapsed_time(elapsed_time)

        if Settings.gui_columns_datetime_show_date is False and Settings.gui_columns_datetime_show_time is False:
            return formatted_elapsed

    datetime_parts: list[str] = []
    if Settings.gui_columns_datetime_show_date:
        datetime_parts.append(datetime_object.strftime('%m/%d/%Y'))
    if Settings.gui_columns_datetime_show_time:
        datetime_parts.append(datetime_object.strftime('%H:%M:%S.%f')[:-3])
    if not datetime_parts:
        raise InvalidDateColumnConfigurationError

    formatted_datetime = ' '.join(datetime_parts)

    if formatted_elapsed:
        formatted_datetime += f' ({formatted_elapsed})'

    return formatted_datetime


def _get_rate_gradient_color(default_color: QColor, rate: int, threshold: int, *, is_first_calculation: bool = False) -> QColor:
    """Return a red-to-green gradient color based on rate relative to threshold."""
    if is_first_calculation:
        return default_color

    val = min(max(rate, 0), threshold) * 0xFF // threshold
    return QColor(0xFF - val, val, 0)


@dataclass(frozen=True, slots=True)
class SessionTableRenderContext:
    """Grouped inputs for session table snapshot rendering."""

    session_connected: list[Player]
    session_disconnected: list[Player]
    connected_shown_columns: set[str]
    disconnected_shown_columns: set[str]
    connected_num_cols: int
    disconnected_num_cols: int
    connected_column_mapping: dict[str, int]


def build_session_table_snapshot(
    context: SessionTableRenderContext,
) -> SessionTableSnapshot:
    """Build connected and disconnected table rows plus compiled colors."""
    session_connected = context.session_connected
    session_disconnected = context.session_disconnected
    connected_shown_columns = context.connected_shown_columns
    disconnected_shown_columns = context.disconnected_shown_columns
    connected_num_cols = context.connected_num_cols
    disconnected_num_cols = context.disconnected_num_cols
    connected_column_mapping = context.connected_column_mapping

    session_connected_table__processed_data: list[list[str]] = []
    session_connected_table__compiled_colors: list[list[CellColor]] = []
    session_disconnected_table__processed_data: list[list[str]] = []
    session_disconnected_table__compiled_colors: list[list[CellColor]] = []

    for player in session_connected:
        if player.userip and player.userip.usernames:
            row_fg_color = QColor(TableColors.CONNECTED_USERIP_TEXT)
            row_bg_color = player.userip.settings.color
        else:
            row_fg_color = QColor(TableColors.CONNECTED_TEXT)
            row_bg_color = HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR

        row_colors = [
            CellColor(foreground=row_fg_color, background=row_bg_color)
            for _ in range(connected_num_cols)
        ]

        connected_row_texts: list[str] = []
        connected_row_texts.append(f'{format_player_usernames(player)}')
        connected_row_texts.append(f'{_format_player_gui_datetime(player.datetime.first_seen)}')
        connected_row_texts.append(f'{_format_player_gui_datetime(player.datetime.last_rejoin)}')
        if 'T. Session Time' in connected_shown_columns:
            connected_row_texts.append(format_elapsed_time(player.datetime.get_total_session_time()))
        if 'Session Time' in connected_shown_columns:
            connected_row_texts.append(format_elapsed_time(player.datetime.get_session_time()))
        connected_row_texts.append(f'{player.rejoins}')
        if 'T. Packets' in connected_shown_columns:
            connected_row_texts.append(f'{player.packets.total_exchanged}')
        if 'Packets' in connected_shown_columns:
            connected_row_texts.append(f'{player.packets.exchanged}')
        if 'T. Packets Received' in connected_shown_columns:
            connected_row_texts.append(f'{player.packets.total_received}')
        if 'Packets Received' in connected_shown_columns:
            connected_row_texts.append(f'{player.packets.received}')
        if 'T. Packets Sent' in connected_shown_columns:
            connected_row_texts.append(f'{player.packets.total_sent}')
        if 'Packets Sent' in connected_shown_columns:
            connected_row_texts.append(f'{player.packets.sent}')
        if 'PPS' in connected_shown_columns:
            row_colors[connected_column_mapping['PPS']] = row_colors[connected_column_mapping['PPS']]._replace(
                foreground=_get_rate_gradient_color(
                    row_fg_color,
                    player.packets.pps.calculated_rate,
                    PPS_MAX_THRESHOLD,
                    is_first_calculation=player.packets.pps.is_first_calculation,
                ),
            )
            connected_row_texts.append(f'{player.packets.pps.calculated_rate}')
        if 'PPM' in connected_shown_columns:
            row_colors[connected_column_mapping['PPM']] = row_colors[connected_column_mapping['PPM']]._replace(
                foreground=_get_rate_gradient_color(
                    row_fg_color,
                    player.packets.ppm.calculated_rate,
                    PPM_MAX_THRESHOLD,
                    is_first_calculation=player.packets.ppm.is_first_calculation,
                ),
            )
            connected_row_texts.append(f'{player.packets.ppm.calculated_rate}')
        if 'T. Bandwith' in connected_shown_columns:
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged))
        if 'Bandwith' in connected_shown_columns:
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.exchanged))
        if 'T. Download' in connected_shown_columns:
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_download))
        if 'Download' in connected_shown_columns:
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.download))
        if 'T. Upload' in connected_shown_columns:
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_upload))
        if 'Upload' in connected_shown_columns:
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.upload))
        if 'BPS' in connected_shown_columns:
            row_colors[connected_column_mapping['BPS']] = row_colors[connected_column_mapping['BPS']]._replace(
                foreground=_get_rate_gradient_color(
                    row_fg_color,
                    player.bandwidth.bps.calculated_rate,
                    BPS_MAX_THRESHOLD,
                    is_first_calculation=player.bandwidth.bps.is_first_calculation,
                ),
            )
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate))
        if 'BPM' in connected_shown_columns:
            row_colors[connected_column_mapping['BPM']] = row_colors[connected_column_mapping['BPM']]._replace(
                foreground=_get_rate_gradient_color(
                    row_fg_color,
                    player.bandwidth.bpm.calculated_rate,
                    BPM_MAX_THRESHOLD,
                    is_first_calculation=player.bandwidth.bpm.is_first_calculation,
                ),
            )
            connected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.bpm.calculated_rate))
        connected_row_texts.append(f'{format_player_ip(player.ip)}')
        if 'Hostname' in connected_shown_columns:
            connected_row_texts.append(f'{player.reverse_dns.hostname}')
        if 'Last Port' in connected_shown_columns:
            connected_row_texts.append(f'{player.ports.last}')
        if 'Middle Ports' in connected_shown_columns:
            connected_row_texts.append(f'{format_player_middle_ports(player)}')
        if 'First Port' in connected_shown_columns:
            connected_row_texts.append(f'{player.ports.first}')
        if 'Continent' in connected_shown_columns:
            if Settings.gui_columns_geo_continent_append_alpha2:
                connected_row_texts.append(f'{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})')
            else:
                connected_row_texts.append(f'{player.iplookup.ipapi.continent}')
        if 'Country' in connected_shown_columns:
            if Settings.gui_columns_geo_country_append_alpha2:
                connected_row_texts.append(f'{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})')
            else:
                connected_row_texts.append(f'{player.iplookup.geolite2.country}')
        if 'Region' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.region}')
        if 'R. Code' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.region_code}')
        if 'City' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.geolite2.city}')
        if 'District' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.district}')
        if 'ZIP Code' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.zip_code}')
        if 'Lat' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.lat}')
        if 'Lon' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.lon}')
        if 'Time Zone' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.time_zone}')
        if 'Offset' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.offset}')
        if 'Currency' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.currency}')
        if 'Organization' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.org}')
        if 'ISP' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.isp}')
        if 'ASN / ISP' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.geolite2.asn}')
        if 'AS' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.asn}')
        if 'ASN' in connected_shown_columns:
            connected_row_texts.append(f'{player.iplookup.ipapi.as_name}')
        if 'Mobile' in connected_shown_columns:
            connected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.mobile else 'No')
        if 'VPN' in connected_shown_columns:
            connected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.proxy else 'No')
        if 'Hosting' in connected_shown_columns:
            connected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.hosting else 'No')
        if 'Pinging' in connected_shown_columns:
            connected_row_texts.append('...' if not player.ping.is_initialized else 'Yes' if player.ping.is_pinging else 'No')

        session_connected_table__processed_data.append(connected_row_texts)
        session_connected_table__compiled_colors.append(row_colors)

    for player in session_disconnected:
        if player.userip and player.userip.usernames:
            row_fg_color = QColor(TableColors.DISCONNECTED_USERIP_TEXT)
            row_bg_color = player.userip.settings.color
        else:
            row_fg_color = QColor(TableColors.DISCONNECTED_TEXT)
            row_bg_color = HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR

        row_colors = [CellColor(foreground=row_fg_color, background=row_bg_color) for _ in range(disconnected_num_cols)]

        disconnected_row_texts: list[str] = []
        disconnected_row_texts.append(f'{format_player_usernames(player)}')
        disconnected_row_texts.append(f'{_format_player_gui_datetime(player.datetime.first_seen)}')
        disconnected_row_texts.append(f'{_format_player_gui_datetime(player.datetime.last_rejoin)}')
        disconnected_row_texts.append(f'{_format_player_gui_datetime(player.datetime.last_seen)}')
        if 'T. Session Time' in disconnected_shown_columns:
            disconnected_row_texts.append(format_elapsed_time(player.datetime.get_total_session_time()))
        if 'Session Time' in disconnected_shown_columns:
            disconnected_row_texts.append(format_elapsed_time(player.datetime.get_session_time()))
        disconnected_row_texts.append(f'{player.rejoins}')
        if 'T. Packets' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.packets.total_exchanged}')
        if 'Packets' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.packets.exchanged}')
        if 'T. Packets Received' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.packets.total_received}')
        if 'Packets Received' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.packets.received}')
        if 'T. Packets Sent' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.packets.total_sent}')
        if 'Packets Sent' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.packets.sent}')
        if 'T. Bandwith' in disconnected_shown_columns:
            disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged))
        if 'Bandwith' in disconnected_shown_columns:
            disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.exchanged))
        if 'T. Download' in disconnected_shown_columns:
            disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_download))
        if 'Download' in disconnected_shown_columns:
            disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.download))
        if 'T. Upload' in disconnected_shown_columns:
            disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.total_upload))
        if 'Upload' in disconnected_shown_columns:
            disconnected_row_texts.append(PlayerBandwidth.format_bytes(player.bandwidth.upload))
        disconnected_row_texts.append(f'{player.ip}')
        if 'Hostname' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.reverse_dns.hostname}')
        if 'Last Port' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.ports.last}')
        if 'Middle Ports' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{format_player_middle_ports(player)}')
        if 'First Port' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.ports.first}')
        if 'Continent' in disconnected_shown_columns:
            if Settings.gui_columns_geo_continent_append_alpha2:
                disconnected_row_texts.append(f'{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})')
            else:
                disconnected_row_texts.append(f'{player.iplookup.ipapi.continent}')
        if 'Country' in disconnected_shown_columns:
            if Settings.gui_columns_geo_country_append_alpha2:
                disconnected_row_texts.append(f'{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})')
            else:
                disconnected_row_texts.append(f'{player.iplookup.geolite2.country}')
        if 'Region' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.region}')
        if 'R. Code' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.region_code}')
        if 'City' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.geolite2.city}')
        if 'District' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.district}')
        if 'ZIP Code' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.zip_code}')
        if 'Lat' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.lat}')
        if 'Lon' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.lon}')
        if 'Time Zone' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.time_zone}')
        if 'Offset' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.offset}')
        if 'Currency' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.currency}')
        if 'Organization' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.org}')
        if 'ISP' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.isp}')
        if 'ASN / ISP' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.geolite2.asn}')
        if 'AS' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.asn}')
        if 'ASN' in disconnected_shown_columns:
            disconnected_row_texts.append(f'{player.iplookup.ipapi.as_name}')
        if 'Mobile' in disconnected_shown_columns:
            disconnected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.mobile else 'No')
        if 'VPN' in disconnected_shown_columns:
            disconnected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.proxy else 'No')
        if 'Hosting' in disconnected_shown_columns:
            disconnected_row_texts.append('...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.hosting else 'No')
        if 'Pinging' in disconnected_shown_columns:
            disconnected_row_texts.append('...' if not player.ping.is_initialized else 'Yes' if player.ping.is_pinging else 'No')

        session_disconnected_table__processed_data.append(disconnected_row_texts)
        session_disconnected_table__compiled_colors.append(row_colors)

    connected_num = len(session_connected_table__processed_data)
    connected_rows = tuple(tuple(row) for row in session_connected_table__processed_data)
    connected_colors = tuple(tuple(row) for row in session_connected_table__compiled_colors)

    disconnected_num = len(session_disconnected_table__processed_data)
    disconnected_rows = tuple(tuple(row) for row in session_disconnected_table__processed_data)
    disconnected_colors = tuple(tuple(row) for row in session_disconnected_table__compiled_colors)

    return SessionTableSnapshot(
        connected_num=connected_num,
        connected_rows=connected_rows,
        connected_colors=connected_colors,
        disconnected_num=disconnected_num,
        disconnected_rows=disconnected_rows,
        disconnected_colors=disconnected_colors,
    )
