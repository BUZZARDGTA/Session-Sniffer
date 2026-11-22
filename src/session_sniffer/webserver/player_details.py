"""Read-only player details, joins history, and context-menu metadata builders for the web server."""

from typing import TYPE_CHECKING

from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH
from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.guis._high_rate_monitor_core import HighRateTracker
from session_sniffer.guis._player_identifier_core import PlayerIdentifierTracker
from session_sniffer.guis.looky_text import get_looky_restriction
from session_sniffer.guis.tables_player_actions import build_discord_player_report
from session_sniffer.guis.tables_player_actions._format import (
    format_bool,
    format_looky_last_seens,
    format_looky_rockstarids,
    format_looky_usernames,
    format_loss_pct,
    format_ms,
    format_packets_and_stats,
    format_ping_status,
    format_text,
    format_userip_database,
)
from session_sniffer.guis.utils import format_duration
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.networking.looky_system import get_looky_user_url
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.seen_stats import SEEN_STATS_LABELS, analyze_sessions_logging
from session_sniffer.player.session_host import SessionHost
from session_sniffer.rendering_core.country_flags import has_country_flag
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Mapping

    from session_sniffer.models.player import Player


def _is_looky_context_allowed(player: Player) -> bool:
    """Return whether the Looky System menu/section may be displayed for *player* (matching `looky.md`)."""
    return Settings.is_gta5_feature_set() and CaptureState.is_local_capture() and not player.is_third_party_server


def _extract_looky_profiles(player: Player) -> list[dict[str, str]]:
    """Extract already-resolved Looky profile links for *player* without performing any network requests."""
    if not _is_looky_context_allowed(player):
        return []
    with player.looky_system.lock:
        rockstar_ids = list(player.looky_system.rockstarids)
        entry_names = list(player.looky_system.entry_names)
    profiles: list[dict[str, str]] = []
    for i, rockstar_id in enumerate(rockstar_ids):
        user_name = entry_names[i] if i < len(entry_names) else ''
        label = f'{user_name} ({rockstar_id})' if user_name else str(rockstar_id)
        profiles.append({'label': label, 'url': get_looky_user_url(rockstar_id)})
    return profiles


def _is_player_looky_resolved(player: Player) -> bool:
    """Return True if *player* has been resolved with data by the Looky System."""
    if not Settings.looky_enabled or not _is_looky_context_allowed(player):
        return False
    with player.looky_system.lock:
        return player.looky_system.is_initialized and bool(player.looky_system.usernames or player.looky_system.rockstarids)


def _extract_looky_usernames(player: Player) -> list[str]:
    """Return the Looky-resolved usernames for *player* (used for per-token purple username highlighting)."""
    if not Settings.looky_enabled or not _is_looky_context_allowed(player):
        return []
    with player.looky_system.lock:
        if not player.looky_system.is_initialized or not player.looky_system.usernames:
            return []
        return sorted({name.strip() for name in player.looky_system.usernames if name.strip()})


def _is_session_host(ip_address: str, *, session_id: int | None = None) -> bool:
    """Return True if *ip_address* is the detected session host for *session_id* (or the active session)."""
    if not Settings.is_session_host_feature_set():
        return False
    if session_id is not None and 0 < session_id < SessionTracker.get_current_session_id():
        history = SessionHost.get_history(session_id=session_id)
        return bool(history and history[-1].ip == ip_address)
    return SessionHost.is_host(ip_address)


def _resolve_player(ip_address: str, *, session_id: int | None = None) -> Player | None:
    """Resolve *ip_address* from a past-session snapshot (if requested), the active registry, or latest recorded snapshot."""
    if session_id is not None and 0 < session_id < SessionTracker.get_current_session_id():
        snapshot_player = SessionTracker.get_session_snapshot_player(session_id, ip_address)
        if snapshot_player is not None:
            return snapshot_player
    player = PlayersRegistry.get_player_by_ip(ip_address)
    if player is not None:
        return player
    for snapshot_player in reversed(SessionTracker.get_all_snapshot_players()):
        if snapshot_player.ip == ip_address:
            return snapshot_player
    return None


def get_known_players_map(*, session_id: int | None = None) -> dict[str, Player]:
    """Return a merged IP -> Player lookup covering past session snapshots and the active registry."""
    known_players: dict[str, Player] = {player.ip: player for player in SessionTracker.get_all_snapshot_players()}
    known_players.update(PlayersRegistry.get_players_map())
    if session_id is not None and 0 < session_id < SessionTracker.get_current_session_id():
        for snapshot_player in SessionTracker.get_session_snapshots(session_id):
            known_players[snapshot_player.ip] = snapshot_player
    return known_players


def build_row_context_meta(
    ip_address: str,
    players_map: Mapping[str, Player],
    *,
    session_id: int | None = None,
    include_rates: bool = False,
) -> dict[str, object]:
    """Return compact per-row context-menu, badge, flag, and live rate metadata for *ip_address*."""
    player = players_map.get(ip_address)
    if player is None:
        return {}
    meta: dict[str, object] = {}
    country_code = player.iplookup.resolve_country_code().strip().upper()
    if has_country_flag(country_code):
        meta['country_code'] = country_code

    is_host = _is_session_host(ip_address, session_id=session_id)
    if is_host:
        meta['is_host'] = True

    badges: list[str] = []
    if is_host and Settings.gui_session_host_icon:
        badges.append('host')
    if Settings.gta5_relay_icon and Settings.is_gta5_feature_set() and player.is_gta5_relay:
        badges.append('relay')
    if Settings.high_rate_monitor_icon and HighRateTracker.is_high_rate(ip_address):
        badges.append('high_rate')
    if Settings.player_identifier_icon and PlayerIdentifierTracker.is_identified(ip_address):
        badges.append('identified')
    if _is_player_looky_resolved(player):
        badges.append('looky')
    if badges:
        meta['badges'] = badges

    looky_usernames = _extract_looky_usernames(player)
    if looky_usernames:
        meta['looky_usernames'] = looky_usernames

    if _is_looky_context_allowed(player):
        meta['looky_allowed'] = True
        profiles = _extract_looky_profiles(player)
        if profiles:
            meta['looky_profiles'] = profiles
    join_count = len(player.joins)
    if join_count > 0:
        meta['join_count'] = join_count
    is_disconnected = player.left_event.is_set()
    if is_disconnected:
        meta['is_disconnected'] = True
    if include_rates and not is_disconnected:
        meta['pps'] = player.packets.pps.calculated_rate
        meta['bps'] = player.bandwidth.bps.calculated_rate
    return meta


def _detail_row(label: str, value: str, *, ltr: bool = False, country_code: str | None = None) -> dict[str, object]:
    entry: dict[str, object] = {'label': label, 'value': value}
    if ltr:
        entry['ltr'] = True
    if country_code is not None and country_code:
        entry['country_code'] = country_code
    return entry


def _build_player_sections(player: Player) -> list[dict[str, object]]:
    """Build localized Player Info, Looky System, IP Lookup Details, and Ping Response sections."""
    hostname = tr('N/A') if player.reverse_dns.hostname == 'N/A' else format_text(player.reverse_dns.hostname)
    usernames_text = ', '.join(player.usernames) if player.usernames else tr('N/A')
    middle_ports_text = ', '.join(map(str, reversed(player.ports.middle))) or tr('N/A')
    first_seen = player.datetime.first_seen.strftime('%Y-%m-%d %H:%M:%S')
    last_seen = player.datetime.last_seen.strftime('%Y-%m-%d %H:%M:%S')

    player_info_rows = [
        _detail_row(tr('IP Address'), player.ip, ltr=True),
        _detail_row(tr('Hostname'), hostname, ltr=True),
        _detail_row(tr_plural('Username', 'Usernames', len(player.usernames)), usernames_text),
        _detail_row(tr('UserIP Database'), format_userip_database(player.userip)),
        _detail_row(tr('First Port'), str(player.ports.first), ltr=True),
        _detail_row(tr_plural('Middle Port', 'Middle Ports', len(player.ports.middle)), middle_ports_text, ltr=True),
        _detail_row(tr('Last Port'), str(player.ports.last), ltr=True),
        _detail_row(tr('First Seen'), first_seen, ltr=True),
        _detail_row(tr('Last Seen'), last_seen, ltr=True),
    ]

    sections: list[dict[str, object]] = [
        {'id': 'player_info', 'title': tr('Player Info'), 'rows': player_info_rows},
    ]

    if _is_looky_context_allowed(player):
        is_restricted = get_looky_restriction([player]) is not None
        with player.looky_system.lock:
            looky_name_count = len(player.looky_system.usernames)
            looky_rid_count = len(player.looky_system.rockstarids)
        looky_rows = [
            _detail_row(
                tr_plural('Username', 'Usernames', looky_name_count),
                format_looky_usernames(player.looky_system, is_restricted=is_restricted),
            ),
            _detail_row(
                tr_plural('Rockstar ID', 'Rockstar IDs', looky_rid_count),
                format_looky_rockstarids(player.looky_system, is_restricted=is_restricted),
                ltr=True,
            ),
            _detail_row(
                tr('Last Seen'),
                format_looky_last_seens(player.looky_system, is_restricted=is_restricted),
                ltr=True,
            ),
        ]
        sections.append({'id': 'looky', 'title': tr('Looky System'), 'rows': looky_rows})

    continent_name, continent_code = player.iplookup.resolve_continent()
    country_name, country_code = player.iplookup.resolve_country()
    continent_display = f'{format_text(continent_name)} ({continent_code})' if continent_code not in {'', '...', 'N/A'} else format_text(continent_name)
    country_display = f'{format_text(country_name)} ({country_code})' if country_code not in {'', '...', 'N/A'} else format_text(country_name)
    normalized_country_code = country_code.strip().upper()
    resolved_flag_code = normalized_country_code if has_country_flag(normalized_country_code) else None

    ip_lookup_rows = [
        _detail_row(tr('Continent'), continent_display),
        _detail_row(tr('Country'), country_display, country_code=resolved_flag_code),
        _detail_row(tr('Region'), format_text(player.iplookup.ipapi.region)),
        _detail_row(tr('R. Code'), format_text(player.iplookup.ipapi.region_code), ltr=True),
        _detail_row(tr('City'), format_text(player.iplookup.resolve_city())),
        _detail_row(tr('District'), format_text(player.iplookup.ipapi.district)),
        _detail_row(tr('ZIP Code'), format_text(player.iplookup.ipapi.zip_code), ltr=True),
        _detail_row(tr('Lat'), format_text(player.iplookup.ipapi.lat), ltr=True),
        _detail_row(tr('Lon'), format_text(player.iplookup.ipapi.lon), ltr=True),
        _detail_row(tr('Time Zone'), format_text(player.iplookup.ipapi.time_zone), ltr=True),
        _detail_row(tr('Offset'), format_text(player.iplookup.ipapi.offset), ltr=True),
        _detail_row(tr('Currency'), format_text(player.iplookup.ipapi.currency), ltr=True),
        _detail_row(tr('Organization'), format_text(player.iplookup.ipapi.org)),
        _detail_row(tr('ISP'), format_text(player.iplookup.ipapi.isp)),
        _detail_row(tr('ASN / ISP'), format_text(player.iplookup.geolite2.asn)),
        _detail_row(tr('AS'), format_text(player.iplookup.ipapi.asn), ltr=True),
        _detail_row(tr('ASN'), format_text(player.iplookup.ipapi.as_name)),
        _detail_row(tr('Mobile'), format_bool(player.iplookup.ipapi.mobile)),
        _detail_row(tr('Proxy/VPN/Tor'), format_bool(player.iplookup.ipapi.proxy)),
        _detail_row(tr('Hosting'), format_bool(player.iplookup.ipapi.hosting)),
    ]
    sections.append({'id': 'ip_lookup', 'title': tr('IP Lookup Details'), 'rows': ip_lookup_rows})

    ping_rows = [
        _detail_row(tr('Status'), format_ping_status(player.ping.is_pinging)),
        _detail_row(
            tr('Packets'),
            format_packets_and_stats(
                player.ping.packets_transmitted,
                player.ping.packets_received,
                player.ping.packet_loss,
                player.ping.packet_errors,
                player.ping.packet_duplicates,
            ),
        ),
        _detail_row(tr('Avg RTT'), format_ms(player.ping.rtt_avg), ltr=True),
        _detail_row(tr('Packet Loss'), format_loss_pct(player.ping.packet_loss), ltr=True),
    ]
    sections.append({'id': 'ping', 'title': tr('Ping Response'), 'rows': ping_rows})
    return sections


def _build_player_joins(player: Player) -> dict[str, object]:
    """Build localized join/rejoin history rows for *player*."""
    is_player_connected = PlayersRegistry.is_player_connected(player)
    columns = [
        tr('#'),
        tr('Status'),
        tr('Rejoin Time'),
        tr('Last Seen'),
        tr('Session Time'),
        tr('First Port'),
        tr('Middle Ports'),
        tr('Last Port'),
        tr('Ports'),
        tr('Packets'),
        tr('Bandwidth'),
    ]
    rows: list[dict[str, object]] = []
    for join in reversed(list(player.joins)):
        is_join_active = join.is_active and is_player_connected
        middle_ports = ', '.join(map(str, reversed(list(join.ports.middle)))) or '—'
        all_ports = ', '.join(map(str, list(join.ports.all)))
        rows.append(
            {
                'index': join.join_index,
                'active': is_join_active,
                'cells': [
                    str(join.join_index),
                    tr('Connected') if is_join_active else tr('Disconnected'),
                    join.joined_at.strftime('%Y-%m-%d %H:%M:%S'),
                    join.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                    format_duration(join.get_session_time().total_seconds()),
                    str(join.ports.first),
                    middle_ports,
                    str(join.ports.last),
                    all_ports,
                    f'{join.packets.exchanged:,}',
                    PlayerBandwidth.format_bytes(join.bandwidth.exchanged),
                ],
            },
        )
    return {'columns': columns, 'rows': rows}


def build_player_details_payload(ip_address: str, *, session_id: int | None = None) -> dict[str, object] | None:
    """Build the JSON payload for `GET /api/player/{ip}`, or `None` when *ip_address* is unknown."""
    player = _resolve_player(ip_address, session_id=session_id)
    if player is None:
        return None

    looky_allowed = _is_looky_context_allowed(player)
    return {
        'ip': player.ip,
        'usernames': list(player.usernames),
        'connected': PlayersRegistry.is_player_connected(player),
        'discord_report': build_discord_player_report(player),
        'looky': {
            'allowed': looky_allowed,
            'website_url': LOOKY_BASE_HOST,
            'profiles': _extract_looky_profiles(player) if looky_allowed else [],
        },
        'sections': _build_player_sections(player),
        'joins': _build_player_joins(player),
    }


def build_player_seen_stats_payload(ip_address: str) -> dict[str, object]:
    """Build the JSON payload for `GET /api/player/{ip}/seen-stats` from session log archives."""
    stats = analyze_sessions_logging(SESSIONS_LOGGING_DIR_PATH, ip_address)
    player = _resolve_player(ip_address)
    return {
        'ip': ip_address,
        'usernames': list(player.usernames) if player is not None else [],
        'title': tr('Session Encounters'),
        'rows': [
            {
                'key': scope,
                'label': tr(label),
                'value': int(getattr(stats, scope)),
            }
            for scope, label in SEEN_STATS_LABELS.items()
        ],
    }
