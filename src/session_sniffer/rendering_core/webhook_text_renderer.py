"""Webhook text rendering helpers (PrettyTable + mobile-friendly lists)."""

from datetime import datetime
from typing import TYPE_CHECKING

from prettytable import PrettyTable, TableStyle

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.models.player import Player, PlayerBandwidth
from session_sniffer.rendering_core.session_table_renderer import (
    format_elapsed_time,
    format_player_middle_ports,
    format_player_usernames,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def format_player_column_value(player: Player, column_name: str, now: datetime) -> str:
    """Return a compact webhook-friendly text value for any GUI column name.

    Falls back to '?' for unknown column names (should not happen in practice
    since the settings widget restricts choices to GUI_ALL_*_COLUMNS).
    """
    formatters: dict[str, Callable[[], str]] = {
        'Usernames': lambda: format_player_usernames(player) or '-',
        'First Seen': lambda: f'{format_elapsed_time(now - player.datetime.first_seen)} ago',
        'Last Rejoin': lambda: f'{format_elapsed_time(now - player.datetime.last_rejoin)} ago',
        'Last Seen': lambda: f'{format_elapsed_time(now - player.datetime.last_seen)} ago',
        'T. Session Time': lambda: format_elapsed_time(player.datetime.get_total_session_time()),
        'Session Time': lambda: format_elapsed_time(player.datetime.get_session_time()),
        'Rejoins': lambda: str(player.rejoins),
        'T. Packets': lambda: str(player.packets.total_exchanged),
        'Packets': lambda: str(player.packets.exchanged),
        'T. Packets Received': lambda: str(player.packets.total_received),
        'Packets Received': lambda: str(player.packets.received),
        'T. Packets Sent': lambda: str(player.packets.total_sent),
        'Packets Sent': lambda: str(player.packets.sent),
        'PPS': lambda: str(player.packets.pps.calculated_rate),
        'PPM': lambda: str(player.packets.ppm.calculated_rate),
        'T. Bandwidth': lambda: PlayerBandwidth.format_bytes(player.bandwidth.total_exchanged),
        'Bandwidth': lambda: PlayerBandwidth.format_bytes(player.bandwidth.exchanged),
        'T. Download': lambda: PlayerBandwidth.format_bytes(player.bandwidth.total_download),
        'Download': lambda: PlayerBandwidth.format_bytes(player.bandwidth.download),
        'T. Upload': lambda: PlayerBandwidth.format_bytes(player.bandwidth.total_upload),
        'Upload': lambda: PlayerBandwidth.format_bytes(player.bandwidth.upload),
        'BPS': lambda: PlayerBandwidth.format_bytes(player.bandwidth.bps.calculated_rate),
        'BPM': lambda: PlayerBandwidth.format_bytes(player.bandwidth.bpm.calculated_rate),
        'IP Address': lambda: player.ip,
        'Hostname': lambda: player.reverse_dns.hostname,
        'Last Port': lambda: str(player.ports.last),
        'Middle Ports': lambda: format_player_middle_ports(player),
        'First Port': lambda: str(player.ports.first),
        'Continent': lambda: f'{player.iplookup.ipapi.continent} ({player.iplookup.ipapi.continent_code})',
        'Country': lambda: f'{player.iplookup.geolite2.country} ({player.iplookup.geolite2.country_code})',
        'Region': lambda: player.iplookup.ipapi.region,
        'R. Code': lambda: player.iplookup.ipapi.region_code,
        'City': lambda: player.iplookup.geolite2.city,
        'District': lambda: player.iplookup.ipapi.district,
        'ZIP Code': lambda: player.iplookup.ipapi.zip_code,
        'Lat': lambda: str(player.iplookup.ipapi.lat),
        'Lon': lambda: str(player.iplookup.ipapi.lon),
        'Time Zone': lambda: player.iplookup.ipapi.time_zone,
        'Offset': lambda: str(player.iplookup.ipapi.offset),
        'Currency': lambda: player.iplookup.ipapi.currency,
        'Organization': lambda: player.iplookup.ipapi.org,
        'ISP': lambda: player.iplookup.ipapi.isp,
        'ASN / ISP': lambda: player.iplookup.geolite2.asn,
        'AS': lambda: player.iplookup.ipapi.asn,
        'ASN': lambda: player.iplookup.ipapi.as_name,
        'Mobile': lambda: '...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.mobile else 'No',
        'VPN': lambda: '...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.proxy else 'No',
        'Hosting': lambda: '...' if not player.iplookup.ipapi.is_initialized else 'Yes' if player.iplookup.ipapi.hosting else 'No',
        'Pinging': lambda: '...' if not player.ping.is_initialized else 'Yes' if player.ping.is_pinging else 'No',
    }

    formatter = formatters.get(column_name)
    return formatter() if formatter is not None else '?'


def build_webhook_table_text(players: list[Player], *, columns: tuple[str, ...], title: str) -> str | None:
    """Render a compact PrettyTable for the Discord webhook (None when empty)."""
    if not players or not columns:
        return None
    table = PrettyTable()
    table.set_style(TableStyle.SINGLE_BORDER)
    table.title = title
    table.field_names = list(columns)
    for column in columns:
        table.align[column] = 'l'
    now = datetime.now(tz=LOCAL_TZ)
    for player in players:
        table.add_row([format_player_column_value(player, column, now) for column in columns])
    return table.get_string()


def build_webhook_mobile_text(players: list[Player], columns: tuple[str, ...]) -> str | None:
    """Render a per-player block optimized for mobile Discord.

    Mobile Discord renders code blocks with a narrow fixed-width font that
    wraps long monospace lines mid-padding, so any aligned grid looks awful.
    This renderer drops the code block entirely and uses native Discord
    markdown so each line wraps cleanly in the device's proportional font:

        **#1 — PlayerOne, PlayerTwo**
        > **Last Rejoin:** 01m 40s ago
        > **Session Time:** 01m 40s
        > **Packets:** 4741
        > **IP:** 152.89.133.230
        > **Country:** Russia (RU)

    The `Usernames` column (when selected) is promoted to the header line
    next to the index. Remaining columns are listed one per blockquote line
    with a bold label followed by the value. Players are separated by a
    blank line.

    Returns `None` when no players or no columns are selected.
    """
    if not players or not columns:
        return None

    promote_header = 'Usernames' in columns
    body_columns = tuple(column for column in columns if column != 'Usernames') if promote_header else columns

    now = datetime.now(tz=LOCAL_TZ)
    blocks: list[str] = []
    for index, player in enumerate(players, start=1):
        lines: list[str] = []
        if promote_header:
            header_value = format_player_usernames(player)
            if header_value:
                lines.append(f'**#{index} — {player.ip}** (`{header_value}`)')
            else:
                lines.append(f'**#{index} — {player.ip}**')
        else:
            lines.append(f'**#{index} — {player.ip}**')

        for column_name in body_columns:
            value = format_player_column_value(player, column_name, now)
            # Escape any markdown-significant characters in user-supplied
            # text so e.g. an asterisk in a hostname doesn't break bolding.
            safe_value = value.replace('*', '\\*').replace('_', '\\_').replace('`', '\\`')
            lines.append(f'> **{column_name}:** {safe_value}')

        blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks)
