"""Historical IP encounter statistics from session log archives."""

import logging
from datetime import date, datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.models import SessionLogFile

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = logging.getLogger(__name__)


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


def _parse_iso_datetime(player_info: dict[str, Any], key: str) -> datetime | None:
    """Extract and parse an ISO datetime field from a player entry."""
    raw = player_info.get(key)
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _parse_first_seen(player_info: dict[str, Any]) -> datetime | None:
    """Extract and parse the 'First Seen' ISO datetime from a player entry."""
    return _parse_iso_datetime(player_info, 'First Seen')


def _calendar_period_increments(target_date: date, today: date, current_week: tuple[int, int]) -> tuple[int, int, int, int]:
    """Return `(today_inc, week_inc, month_inc, year_inc)` for *target_date* relative to *today* and *current_week*."""
    return (
        int(target_date == today),
        int(target_date.isocalendar()[:2] == current_week),
        int(target_date.year == today.year and target_date.month == today.month),
        int(target_date.year == today.year),
    )


def _update_stats(first_seen: datetime, stats: SeenStats, now: datetime) -> None:
    """Increment the appropriate counters based on how recent *first_seen* is."""
    today_inc, week_inc, month_inc, year_inc = _calendar_period_increments(first_seen.date(), now.date(), now.isocalendar()[:2])
    stats.total += 1
    stats.today += today_inc
    stats.week += week_inc
    stats.month += month_inc
    stats.year += year_inc


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
        except (ValidationError, OSError) as e:
            logger.warning('Failed to load session log from %s: %s', json_file, e)
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


def _update_entry_metadata(entry: LeaderboardEntry, player_info: dict[str, Any], *, overwrite: bool = True) -> None:
    """Update display metadata from a player entry."""
    raw_usernames = player_info.get('Usernames')
    if isinstance(raw_usernames, list) and raw_usernames and (overwrite or not entry.usernames):
        entry.usernames = _to_str_list(cast('list[object]', raw_usernames))

    raw_country = player_info.get('Country')
    if isinstance(raw_country, str) and raw_country != _UNRESOLVED_LOOKUP and (overwrite or not entry.country):
        entry.country = raw_country

    raw_country_code = player_info.get('Country Code')
    if isinstance(raw_country_code, str) and raw_country_code != _UNRESOLVED_LOOKUP and (overwrite or not entry.country_code):
        entry.country_code = raw_country_code

    if overwrite or not entry.isp:
        raw_asn_isp = player_info.get('ASN / ISP')
        if isinstance(raw_asn_isp, str) and raw_asn_isp not in {_UNRESOLVED_LOOKUP, 'N/A'}:
            entry.isp = raw_asn_isp
        else:
            raw_isp = player_info.get('ISP')
            if isinstance(raw_isp, str) and raw_isp != _UNRESOLVED_LOOKUP:
                entry.isp = raw_isp

    raw_mobile = player_info.get('Mobile')
    if isinstance(raw_mobile, bool) and (overwrite or entry.mobile is None):
        entry.mobile = raw_mobile

    raw_vpn = player_info.get('VPN')
    if isinstance(raw_vpn, bool) and (overwrite or entry.vpn is None):
        entry.vpn = raw_vpn

    raw_hosting = player_info.get('Hosting')
    if isinstance(raw_hosting, bool) and (overwrite or entry.hosting is None):
        entry.hosting = raw_hosting


class LeaderboardBaseline(BaseModel):
    """Historical leaderboard aggregation that can be cheaply overlaid with the live session.

    `entries` holds one fully-finalized `LeaderboardEntry` per IP with session and day counts from
    finished session logs only (the currently-active session file is excluded). `seen_dates` retains
    the set of unique calendar dates each IP was seen on, so the live overlay can re-derive the day
    counts of the few IPs present in the live session without touching the rest of the baseline.
    `reference_date` is the local calendar date the Today/Week/Month/Year counts were computed
    against; once the local date moves past it, those counts are stale and the baseline must be rebuilt.
    """

    entries: dict[str, LeaderboardEntry]
    seen_dates: dict[str, set[date]]
    reference_date: date

    model_config = ConfigDict(arbitrary_types_allowed=True)


def _accumulate_session(
    entries: dict[str, LeaderboardEntry],
    seen_dates: dict[str, set[date]],
    session_log: SessionLogFile,
    now: datetime,
) -> None:
    """Merge one parsed session snapshot into the running `entries`/`seen_dates` aggregation."""
    all_players = _extract_all_players_from_session(session_log)
    today = now.date()
    current_week = now.isocalendar()[:2]

    for ip, player_info in all_players.items():
        first_seen = _parse_first_seen(player_info)
        if first_seen is None:
            continue

        if ip not in entries:
            entries[ip] = LeaderboardEntry(ip=ip)
            seen_dates[ip] = set()
        entry = entries[ip]

        # Track unique calendar date for days-mode counting
        first_seen_date = first_seen.date()
        seen_dates[ip].add(first_seen_date)

        # Update session counts
        today_inc, week_inc, month_inc, year_inc = _calendar_period_increments(first_seen_date, today, current_week)
        entry.sessions_total += 1
        entry.sessions_today += today_inc
        entry.sessions_week += week_inc
        entry.sessions_month += month_inc
        entry.sessions_year += year_inc

        # Track first/last seen and update metadata from the latest session
        if entry.first_seen is None or first_seen < entry.first_seen:
            entry.first_seen = first_seen

        session_last_seen = _parse_iso_datetime(player_info, 'Last Seen') or first_seen
        if entry.last_seen is not None and session_last_seen <= entry.last_seen:
            _update_entry_metadata(entry, player_info, overwrite=False)
            continue

        entry.last_seen = session_last_seen
        _update_entry_metadata(entry, player_info, overwrite=True)


def _finalize_days(
    entries: dict[str, LeaderboardEntry],
    seen_dates: dict[str, set[date]],
    now: datetime,
) -> None:
    """Derive (or re-derive) each entry's unique-days counts from its collected set of calendar dates."""
    today = now.date()
    current_week = now.isocalendar()[:2]
    for ip, player_seen_dates in seen_dates.items():
        days_today = days_week = days_month = days_year = 0
        for seen_date in player_seen_dates:
            today_inc, week_inc, month_inc, year_inc = _calendar_period_increments(seen_date, today, current_week)
            days_today += today_inc
            days_week += week_inc
            days_month += month_inc
            days_year += year_inc
        entry = entries[ip]
        entry.days_total = len(player_seen_dates)
        entry.days_today = days_today
        entry.days_week = days_week
        entry.days_month = days_month
        entry.days_year = days_year


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
    instead merged live via `overlay_live_session`.

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
        except (ValidationError, OSError) as e:
            logger.warning('Failed to load session log from %s: %s', json_file, e)
            continue

        _accumulate_session(entries, seen_dates, session_log, now)

    if progress_callback is not None and (should_cancel is None or not should_cancel()):
        progress_callback(total_files, total_files)

    _finalize_days(entries, seen_dates, now)
    return LeaderboardBaseline(entries=entries, seen_dates=seen_dates, reference_date=now.date())


def overlay_live_session(
    baseline: LeaderboardBaseline,
    live_file: Path,
    *,
    preserve_ips: frozenset[str] | set[str] | None = None,
) -> list[LeaderboardEntry]:
    """Overlay the live session file onto *baseline* and return only the entries it affects.

    Only IPs present in the live session (plus any *preserve_ips* missing from both the baseline and
    the live session, included with an initial session count) are returned, as merged copies; every
    other IP is unchanged from `baseline.entries`. The baseline itself is never mutated, so it can be
    reused across repeated live refreshes. The live session file (a single continuously-rewritten
    snapshot) contributes at most one extra session per IP. If the file is missing or read mid-write,
    no live entries are returned.
    """
    now = datetime.now(tz=LOCAL_TZ)
    entries: dict[str, LeaderboardEntry] = {}
    seen_dates: dict[str, set[date]] = {}

    try:
        live_text = live_file.read_text(encoding='utf-8', errors='replace')
    except FileNotFoundError:
        live_text = None
    except OSError as e:
        logger.warning('Failed to read live session file %s: %s', live_file, e)
        live_text = None

    session_log: SessionLogFile | None = None
    if live_text is not None and live_text:
        try:
            session_log = SessionLogFile.model_validate_json(live_text)
        except ValidationError as e:
            logger.warning('Failed to parse live session file %s: %s', live_file, e)
    # An empty file is a normal transient race: the writer truncated before finishing the write.

    if session_log is not None:
        # Copy only the baseline entries the live session touches; `_accumulate_session` creates the rest.
        for ip in _extract_all_players_from_session(session_log):
            baseline_entry = baseline.entries.get(ip)
            if baseline_entry is not None:
                entries[ip] = _copy_entry(baseline_entry)
                seen_dates[ip] = set(baseline.seen_dates[ip])
        _accumulate_session(entries, seen_dates, session_log, now)

    if preserve_ips is not None and preserve_ips:
        for ip in preserve_ips:
            if ip not in entries and ip not in baseline.entries:
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
    return list(entries.values())
