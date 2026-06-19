"""Historical IP encounter statistics from session log archives."""

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.logging_setup import get_logger

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


@dataclass(slots=True)
class SeenStats:
    """Counts how many sessions an IP appeared in across time ranges."""

    today: int = 0
    week: int = 0
    month: int = 0
    year: int = 0
    total: int = 0


def _get_player_from_session(
    data: dict[str, Any],
    ip: str,
) -> dict[str, Any] | None:
    """Look up an IP in both connected and disconnected sections."""
    for section in ('connected', 'disconnected'):
        players_raw: object = data.get(section)
        if not isinstance(players_raw, dict):
            continue
        players = cast('dict[str, Any]', players_raw)
        entry = players.get(ip)
        if isinstance(entry, dict):
            return cast('dict[str, Any]', entry)
    return None


def _parse_first_seen(player_info: dict[str, Any]) -> datetime | None:
    """Extract and parse the 'First Seen' ISO datetime from a player entry."""
    raw = player_info.get('First Seen')
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _update_stats(first_seen: datetime, stats: SeenStats, now: datetime) -> None:
    """Increment the appropriate counters based on how recent *first_seen* is."""
    stats.total += 1
    if first_seen.date() == now.date():
        stats.today += 1
    if first_seen.isocalendar()[:2] == now.isocalendar()[:2]:
        stats.week += 1
    if first_seen.year == now.year and first_seen.month == now.month:
        stats.month += 1
    if first_seen.year == now.year:
        stats.year += 1


type _SeenStatsScope = Literal['today', 'week', 'month', 'year', 'total']

SEEN_STATS_LABELS: dict[_SeenStatsScope, str] = {
    'today': 'Today',
    'week': 'This Week',
    'month': 'This Month',
    'year': 'This Year',
    'total': 'Total',
}


def analyze_sessions_logging(folder_path: Path, ip: str) -> SeenStats:
    """Scan all JSON session logs under *folder_path* and count appearances of *ip*.

    Each `.json` file represents one session snapshot. If the IP appears in either
    the `connected` or `disconnected` section, the session counts once.
    """
    stats = SeenStats()
    now = datetime.now(tz=LOCAL_TZ)

    for json_file in folder_path.rglob('*.json'):
        if not json_file.is_file():
            continue
        try:
            data: object = json.loads(json_file.read_text(encoding='utf-8'))
        except json.JSONDecodeError, OSError:
            continue
        if not isinstance(data, dict):
            continue

        player_info = _get_player_from_session(cast('dict[str, Any]', data), ip)
        if player_info is None:
            continue

        first_seen = _parse_first_seen(player_info)
        if first_seen is None:
            continue

        _update_stats(first_seen, stats, now)

    return stats


@dataclass(slots=True)
class LeaderboardEntry:
    """Aggregated stats for a single player IP across all session logs."""

    ip: str
    usernames: list[str] = field(default_factory=list[str])
    sessions_today: int = 0
    sessions_week: int = 0
    sessions_month: int = 0
    sessions_year: int = 0
    sessions_total: int = 0
    days_today: int = 0
    days_week: int = 0
    days_month: int = 0
    days_year: int = 0
    days_total: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    country: str = ''
    country_code: str = ''
    isp: str = ''
    mobile: bool | None = None
    vpn: bool | None = None
    hosting: bool | None = None


def _extract_all_players_from_session(
    data: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Extract all player entries (keyed by IP) from both connected and disconnected sections."""
    result: dict[str, dict[str, Any]] = {}
    for section in ('connected', 'disconnected'):
        players_raw: object = data.get(section)
        if not isinstance(players_raw, dict):
            continue
        players = cast('dict[str, Any]', players_raw)
        for ip, info in players.items():
            if isinstance(info, dict) and ip not in result:
                result[ip] = cast('dict[str, Any]', info)
    return result


def _to_str_list(raw: list[object]) -> list[str]:
    """Convert a raw JSON list to a list of strings."""
    return [str(item) for item in raw]


def _update_entry_metadata(entry: LeaderboardEntry, player_info: dict[str, Any]) -> None:
    """Update display metadata from a player entry."""
    raw_usernames = player_info.get('Usernames')
    if isinstance(raw_usernames, list) and raw_usernames:
        entry.usernames = _to_str_list(cast('list[object]', raw_usernames))

    raw_country = player_info.get('Country')
    if isinstance(raw_country, str) and raw_country != 'N/A':
        entry.country = raw_country

    raw_country_code = player_info.get('Country Code')
    if isinstance(raw_country_code, str) and raw_country_code != 'N/A':
        entry.country_code = raw_country_code

    raw_isp = player_info.get('ISP')
    if isinstance(raw_isp, str) and raw_isp != 'N/A':
        entry.isp = raw_isp

    raw_mobile = player_info.get('Mobile')
    if isinstance(raw_mobile, bool):
        entry.mobile = raw_mobile

    raw_vpn = player_info.get('VPN')
    if isinstance(raw_vpn, bool):
        entry.vpn = raw_vpn

    raw_hosting = player_info.get('Hosting')
    if isinstance(raw_hosting, bool):
        entry.hosting = raw_hosting


def build_leaderboard(folder_path: Path, *, limit: int = 1000) -> list[LeaderboardEntry]:
    """Scan all JSON session logs and build a leaderboard of all players sorted by total sessions."""
    entries: dict[str, LeaderboardEntry] = {}
    seen_dates: dict[str, set[date]] = {}
    now = datetime.now(tz=LOCAL_TZ)

    for json_file in folder_path.rglob('*.json'):
        if not json_file.is_file():
            continue
        try:
            data: object = json.loads(json_file.read_text(encoding='utf-8'))
        except json.JSONDecodeError, OSError:
            continue
        if not isinstance(data, dict):
            continue

        all_players = _extract_all_players_from_session(cast('dict[str, Any]', data))

        for ip, player_info in all_players.items():
            first_seen = _parse_first_seen(player_info)
            if first_seen is None:
                continue

            if ip not in entries:
                entries[ip] = LeaderboardEntry(ip=ip)
                seen_dates[ip] = set()
            entry = entries[ip]

            # Track unique calendar date for days-mode counting
            seen_dates[ip].add(first_seen.date())

            # Update session counts
            entry.sessions_total += 1
            if first_seen.date() == now.date():
                entry.sessions_today += 1
            if first_seen.isocalendar()[:2] == now.isocalendar()[:2]:
                entry.sessions_week += 1
            if first_seen.year == now.year and first_seen.month == now.month:
                entry.sessions_month += 1
            if first_seen.year == now.year:
                entry.sessions_year += 1

            # Track first/last seen and update metadata from the latest session
            if entry.first_seen is None or first_seen < entry.first_seen:
                entry.first_seen = first_seen

            if entry.last_seen is not None and first_seen <= entry.last_seen:
                continue

            entry.last_seen = first_seen
            _update_entry_metadata(entry, player_info)

    # Derive unique-days counts from the collected date sets
    today = now.date()
    current_week = now.isocalendar()[:2]
    for ip, dates in seen_dates.items():
        entry = entries[ip]
        for d in dates:
            entry.days_total += 1
            if d == today:
                entry.days_today += 1
            if d.isocalendar()[:2] == current_week:
                entry.days_week += 1
            if d.year == now.year and d.month == now.month:
                entry.days_month += 1
            if d.year == now.year:
                entry.days_year += 1

    return sorted(entries.values(), key=lambda e: e.sessions_total, reverse=True)[:limit]
