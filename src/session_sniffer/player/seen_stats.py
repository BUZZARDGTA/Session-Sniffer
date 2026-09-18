"""Historical IP encounter statistics from session log archives."""

from datetime import date, datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.logging_setup import get_logger
from session_sniffer.models import SessionLogFile

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = get_logger(__name__)


class SeenStats(BaseModel):
    """Counts how many sessions an IP appeared in across time ranges."""

    today: int = 0
    week: int = 0
    month: int = 0
    year: int = 0
    total: int = 0


def _get_player_from_session(
    session_log: SessionLogFile,
    ip: str,
) -> dict[str, Any] | None:
    """Look up an IP in both connected and disconnected sections."""
    entry = session_log.connected.get(ip)
    if entry is not None:
        return entry
    return session_log.disconnected.get(ip)


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
            session_log = SessionLogFile.model_validate_json(json_file.read_text(encoding='utf-8', errors='replace'))
        except (ValidationError, OSError):
            continue

        player_info = _get_player_from_session(session_log, ip)
        if player_info is None:
            continue

        first_seen = _parse_first_seen(player_info)
        if first_seen is None:
            continue

        _update_stats(first_seen, stats, now)

    return stats


class LeaderboardEntry(BaseModel):
    """Aggregated stats for a single player IP across all session logs."""

    ip: str
    usernames: list[str] = Field(default_factory=list[str])
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
    session_log: SessionLogFile,
) -> dict[str, dict[str, Any]]:
    """Extract all player entries (keyed by IP) from both connected and disconnected sections."""
    result: dict[str, dict[str, Any]] = {}
    for section in (session_log.connected, session_log.disconnected):
        for ip, info in section.items():
            if ip not in result:
                result[ip] = info
    return result


def _to_str_list(raw: list[object]) -> list[str]:
    """Convert a raw JSON list to a list of strings."""
    return [str(item) for item in raw]


# The '...' sentinel is written to session logs when a lookup field has not run yet. Such transient
# values are skipped so a later half-resolved snapshot can't clobber a previously-resolved value.
# A resolved 'N/A' (looked up, no data) is kept as-is; the display renders empty values as 'N/A' too.
_UNRESOLVED_LOOKUP = '...'


def _update_entry_metadata(entry: LeaderboardEntry, player_info: dict[str, Any]) -> None:
    """Update display metadata from a player entry."""
    raw_usernames = player_info.get('Usernames')
    if isinstance(raw_usernames, list) and raw_usernames:
        entry.usernames = _to_str_list(cast('list[object]', raw_usernames))

    raw_country = player_info.get('Country')
    if isinstance(raw_country, str) and raw_country != _UNRESOLVED_LOOKUP:
        entry.country = raw_country

    raw_country_code = player_info.get('Country Code')
    if isinstance(raw_country_code, str) and raw_country_code != _UNRESOLVED_LOOKUP:
        entry.country_code = raw_country_code

    raw_asn_isp = player_info.get('ASN / ISP')
    if isinstance(raw_asn_isp, str) and raw_asn_isp not in {_UNRESOLVED_LOOKUP, 'N/A'}:
        entry.isp = raw_asn_isp
    else:
        raw_isp = player_info.get('ISP')
        if isinstance(raw_isp, str) and raw_isp != _UNRESOLVED_LOOKUP:
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


class LeaderboardBaseline(BaseModel):
    """Historical leaderboard aggregation that can be cheaply overlaid with the live session.

    `entries` holds one `LeaderboardEntry` per IP with session counts from finished session logs
    only (the currently-active session file is excluded). `seen_dates` retains the set of unique
    calendar dates each IP was seen on, so the live overlay can decide whether today adds a new
    unique day. Day counts on the entries are intentionally left unfinalized (zero); they are
    computed by `_finalize_days` after the live session has been merged in.
    """

    entries: dict[str, LeaderboardEntry]
    seen_dates: dict[str, set[date]]

    model_config = ConfigDict(arbitrary_types_allowed=True)


def _accumulate_session(
    entries: dict[str, LeaderboardEntry],
    seen_dates: dict[str, set[date]],
    session_log: SessionLogFile,
    now: datetime,
) -> None:
    """Merge one parsed session snapshot into the running `entries`/`seen_dates` aggregation."""
    all_players = _extract_all_players_from_session(session_log)

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


def _finalize_days(
    entries: dict[str, LeaderboardEntry],
    seen_dates: dict[str, set[date]],
    now: datetime,
) -> None:
    """Derive each entry's unique-days counts from its collected set of calendar dates."""
    today = now.date()
    current_week = now.isocalendar()[:2]
    for ip, player_seen_dates in seen_dates.items():
        entry = entries[ip]
        for seen_date in player_seen_dates:
            entry.days_total += 1
            if seen_date == today:
                entry.days_today += 1
            if seen_date.isocalendar()[:2] == current_week:
                entry.days_week += 1
            if seen_date.year == now.year and seen_date.month == now.month:
                entry.days_month += 1
            if seen_date.year == now.year:
                entry.days_year += 1


def _copy_entry(entry: LeaderboardEntry) -> LeaderboardEntry:
    """Return a shallow copy of *entry* that is safe to mutate without affecting the baseline."""
    return entry.model_copy(update={'usernames': list(entry.usernames)})


def build_leaderboard_baseline(
    folder_path: Path,
    *,
    exclude_file: Path | None = None,
    should_cancel: Callable[[], bool] | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> LeaderboardBaseline:
    """Scan finished session logs into a reusable baseline, optionally skipping the live session file.

    `exclude_file` is the currently-active session snapshot, which is continuously rewritten and is
    instead merged live via `overlay_live_session`. Day counts are left unfinalized so the overlay can
    add today's live encounter before they are computed.

    `should_cancel`, when provided, is polled once per session file; if it returns True the scan stops
    early and returns whatever was accumulated so far (the caller is expected to discard it).
    """
    entries: dict[str, LeaderboardEntry] = {}
    seen_dates: dict[str, set[date]] = {}
    now = datetime.now(tz=LOCAL_TZ)

    json_files = list(folder_path.rglob('*.json'))
    total_files = len(json_files)

    for i, json_file in enumerate(json_files):
        if should_cancel is not None and should_cancel():
            break

        if progress_callback is not None:
            progress_callback(i, total_files)

        if not json_file.is_file():
            continue
        if exclude_file is not None and json_file == exclude_file:
            continue
        try:
            session_log = SessionLogFile.model_validate_json(json_file.read_text(encoding='utf-8', errors='replace'))
        except (ValidationError, OSError):
            continue

        _accumulate_session(entries, seen_dates, session_log, now)

    if progress_callback is not None and (should_cancel is None or not should_cancel()):
        progress_callback(total_files, total_files)

    return LeaderboardBaseline(entries=entries, seen_dates=seen_dates)


def overlay_live_session(
    baseline: LeaderboardBaseline,
    live_file: Path,
    *,
    limit: int = 1000,
    preserve_ips: frozenset[str] | set[str] | None = None,
) -> list[LeaderboardEntry]:
    """Overlay the live session file onto *baseline* and return the sorted, truncated leaderboard.

    The baseline is copied so it can be reused across repeated live refreshes. The live session file
    (a single continuously-rewritten snapshot) contributes at most one extra session per IP. If the
    file is missing or read mid-write, the baseline is returned unchanged. Any IPs in the live session
    file or in *preserve_ips* are preserved in the result even if they fall outside the top *limit*.
    """
    now = datetime.now(tz=LOCAL_TZ)
    entries: dict[str, LeaderboardEntry] = {ip: _copy_entry(entry) for ip, entry in baseline.entries.items()}
    seen_dates: dict[str, set[date]] = {ip: set(dates) for ip, dates in baseline.seen_dates.items()}

    try:
        session_log = SessionLogFile.model_validate_json(live_file.read_text(encoding='utf-8', errors='replace'))
    except (FileNotFoundError, ValidationError, OSError):
        session_log = None

    live_ips: set[str] = set()
    if session_log is not None:
        all_players = _extract_all_players_from_session(session_log)
        live_ips = set(all_players.keys())
        _accumulate_session(entries, seen_dates, session_log, now)

    if preserve_ips:
        live_ips.update(preserve_ips)
        for ip in preserve_ips:
            if ip not in entries:
                entries[ip] = LeaderboardEntry(
                    ip=ip,
                    sessions_today=1,
                    sessions_week=1,
                    sessions_month=1,
                    sessions_year=1,
                    sessions_total=1,
                    first_seen=now,
                    last_seen=now,
                )
                seen_dates[ip] = {now.date()}

    _finalize_days(entries, seen_dates, now)
    sorted_entries = sorted(entries.values(), key=lambda entry: entry.sessions_total, reverse=True)
    top_entries = sorted_entries[:limit]
    if live_ips:
        top_ips = {entry.ip for entry in top_entries}
        extra_entries = [entries[ip] for ip in live_ips if ip in entries and ip not in top_ips]
        if extra_entries:
            return top_entries + extra_entries
    return top_entries
