"""UserIP database loading, file monitoring, and default file initialization."""

import contextlib
import csv
import json
import logging
import time
from bisect import bisect_left, bisect_right
from datetime import datetime
from ipaddress import IPv4Address
from threading import Lock
from typing import TYPE_CHECKING, ClassVar, NamedTuple, cast

from PySide6.QtGui import QColor

from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH, USERIP_DATABASES_DIR_PATH, USERIP_LOGGING_PATH
from session_sniffer.models.userip_settings_model import (
    DEFAULT_USERIP_FILES_SETTINGS,
    UserIPDatabaseFile,
    UserIPEntryModel,
    UserIPSettingsModel,
    pick_earliest_iso,
    pick_latest_iso,
)
from session_sniffer.networking.ip_range import entry_ip_covers_ip, is_valid_ip_range_entry, parse_ip_range_entry
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import ProtectionSettings, UserIPDatabases, UserIPSettings
from session_sniffer.text_utils import split_usernames
from session_sniffer.utils import custom_str_to_bool, get_file_signature, validate_file
from session_sniffer.utils_exceptions import InvalidBooleanValueError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path
    from typing import Any

    from session_sniffer.models.player import Player
    from session_sniffer.player.userip import UserIP

logger = logging.getLogger(__name__)

_update_userip_databases_lock = Lock()
_last_userip_db_mod_times: dict[Path, tuple[int, int]] = {}

DEFAULT_USERIP_FILES_SETTINGS_BY_PATH: dict[Path, UserIPSettingsModel] = {
    USERIP_DATABASES_DIR_PATH / json_name: settings for json_name, settings in DEFAULT_USERIP_FILES_SETTINGS.items()
}

_CSV_SESSION_MATCH_TOLERANCE_SECONDS = 60.0
_WINDOW_MERGE_TOLERANCE_SECONDS = 1.0


class _SessionWindow(NamedTuple):
    """Represent a player's presence window and encounter count within a single session."""

    first_seen_iso: str
    last_seen_iso: str
    start_ts: float
    end_ts: float
    encounters: int


class _LogIPStats(NamedTuple):
    """Aggregated log statistics for a single IP address or IP range."""

    first_seen_at: str
    last_seen_at: str
    detections_count: int


def _parse_log_datetime_str(raw_dt: str) -> tuple[str, float] | None:
    """Parse a local log timestamp string into a normalized ISO-8601 string and POSIX timestamp."""
    cleaned = raw_dt.strip()
    if not cleaned:
        return None
    try:
        dt = datetime.fromisoformat(cleaned).astimezone()
    except ValueError:
        return None
    return dt.isoformat(timespec='seconds'), dt.timestamp()


def _extract_session_window_from_dict(player_info: dict[str, Any]) -> _SessionWindow | None:
    """Build a `_SessionWindow` from a session JSON player record."""
    points: list[tuple[str, float]] = []
    for key in ('First Seen', 'Last Rejoin', 'Last Seen'):
        raw_val: object = player_info.get(key)
        if isinstance(raw_val, str) and (parsed := _parse_log_datetime_str(raw_val)) is not None:
            points.append(parsed)
    if not points:
        return None
    first_iso, start_ts = min(points, key=lambda item: item[1])
    last_iso, end_ts = max(points, key=lambda item: item[1])
    raw_rejoins: object = player_info.get('Rejoins', 0)
    rejoins = raw_rejoins if isinstance(raw_rejoins, int) and not isinstance(raw_rejoins, bool) and raw_rejoins >= 0 else 0
    return _SessionWindow(
        first_seen_iso=first_iso,
        last_seen_iso=last_iso,
        start_ts=start_ts,
        end_ts=end_ts,
        encounters=1 + rejoins,
    )


def _build_live_player_window(player: Player) -> _SessionWindow:
    """Build a `_SessionWindow` from a live `Player` in `PlayersRegistry`."""
    first_dt = player.datetime.first_seen.astimezone()
    rejoin_dt = player.datetime.last_rejoin.astimezone()
    last_dt = player.datetime.last_seen.astimezone()
    points = (
        (first_dt.isoformat(timespec='seconds'), first_dt.timestamp()),
        (rejoin_dt.isoformat(timespec='seconds'), rejoin_dt.timestamp()),
        (last_dt.isoformat(timespec='seconds'), last_dt.timestamp()),
    )
    first_iso, start_ts = min(points, key=lambda item: item[1])
    last_iso, end_ts = max(points, key=lambda item: item[1])
    return _SessionWindow(
        first_seen_iso=first_iso,
        last_seen_iso=last_iso,
        start_ts=start_ts,
        end_ts=end_ts,
        encounters=1 + max(0, player.rejoins),
    )


def _merge_overlapping_windows(windows: Sequence[_SessionWindow]) -> tuple[_SessionWindow, ...]:
    """Sort and merge overlapping or adjacent session windows for a single IP."""
    if not windows:
        return ()
    sorted_windows = sorted(windows, key=lambda w: (w.start_ts, w.end_ts))
    merged: list[_SessionWindow] = [sorted_windows[0]]
    for current in sorted_windows[1:]:
        prev = merged[-1]
        if current.start_ts <= prev.end_ts + _WINDOW_MERGE_TOLERANCE_SECONDS:
            first_iso = prev.first_seen_iso if prev.start_ts <= current.start_ts else current.first_seen_iso
            last_iso = prev.last_seen_iso if prev.end_ts >= current.end_ts else current.last_seen_iso
            merged[-1] = _SessionWindow(
                first_seen_iso=first_iso,
                last_seen_iso=last_iso,
                start_ts=min(prev.start_ts, current.start_ts),
                end_ts=max(prev.end_ts, current.end_ts),
                encounters=max(prev.encounters, current.encounters),
            )
        else:
            merged.append(current)
    return tuple(merged)


def _compute_ip_log_stats(
    merged_windows: Sequence[_SessionWindow],
    csv_events: Sequence[tuple[str, float]],
) -> _LogIPStats | None:
    """Combine merged session windows and CSV log timestamps into deduplicated `_LogIPStats`."""
    if not merged_windows and not csv_events:
        return None

    matched_csv_counts = [0] * len(merged_windows)
    unmatched_csv_count = 0
    for _csv_iso, csv_ts in csv_events:
        matched_idx = next(
            (
                idx
                for idx, window in enumerate(merged_windows)
                if window.start_ts - _CSV_SESSION_MATCH_TOLERANCE_SECONDS <= csv_ts <= window.end_ts + _CSV_SESSION_MATCH_TOLERANCE_SECONDS
            ),
            None,
        )
        if matched_idx is not None:
            matched_csv_counts[matched_idx] += 1
        else:
            unmatched_csv_count += 1

    detections_count = sum(max(w.encounters, matched_csv_counts[i]) for i, w in enumerate(merged_windows)) + unmatched_csv_count
    if detections_count <= 0:
        return None

    first_seen_at: str | None = merged_windows[0].first_seen_iso if merged_windows else None
    last_seen_at: str | None = max(merged_windows, key=lambda w: w.end_ts).last_seen_iso if merged_windows else None
    if csv_events:
        first_seen_at = pick_earliest_iso(first_seen_at, csv_events[0][0])
        last_seen_at = pick_latest_iso(last_seen_at, csv_events[-1][0])

    if first_seen_at is None or last_seen_at is None:
        return None
    return _LogIPStats(first_seen_at=first_seen_at, last_seen_at=last_seen_at, detections_count=detections_count)


class _UserIPLogHistoryCache:
    """Incremental cache of historical IP sightings from `Logging/Sessions/` and `UserIP_Logging.csv`."""

    _SCAN_THROTTLE_SECONDS: ClassVar[float] = 1.0
    _cache_lock: ClassVar[Lock] = Lock()
    _initialized: ClassVar[bool] = False
    _last_scan_monotonic: ClassVar[float] = 0.0
    _session_file_cache: ClassVar[dict[Path, tuple[float, int, dict[str, list[_SessionWindow]]]]] = {}
    _csv_file_state: ClassVar[tuple[float, int] | None] = None
    _csv_by_ip: ClassVar[dict[str, tuple[tuple[str, float], ...]]] = {}
    _windows_by_ip: ClassVar[dict[str, tuple[_SessionWindow, ...]]] = {}
    _stats_by_ip: ClassVar[dict[str, _LogIPStats]] = {}
    _sorted_ip_addresses: ClassVar[list[IPv4Address]] = []
    _sorted_ip_strings: ClassVar[list[str]] = []

    @staticmethod
    def _parse_session_json_file(json_path: Path) -> dict[str, list[_SessionWindow]]:
        """Extract per-IP `_SessionWindow` records from a single session `.json` file."""
        try:
            raw_data: object = json.loads(json_path.read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        if not isinstance(raw_data, dict):
            return {}

        typed_root = cast('dict[str, Any]', raw_data)
        windows_by_ip: dict[str, list[_SessionWindow]] = {}
        for section_key in ('connected', 'disconnected'):
            section_obj: object = typed_root.get(section_key)
            if not isinstance(section_obj, dict):
                continue
            for raw_ip, raw_info in cast('dict[object, object]', section_obj).items():
                if not isinstance(raw_ip, str) or not isinstance(raw_info, dict):
                    continue
                window = _extract_session_window_from_dict(cast('dict[str, Any]', raw_info))
                if window is not None:
                    windows_by_ip.setdefault(raw_ip.strip(), []).append(window)
        return windows_by_ip

    @staticmethod
    def _parse_userip_csv_file(csv_path: Path) -> dict[str, tuple[tuple[str, float], ...]]:
        """Extract sorted, deduplicated `(iso_str, posix_ts)` events per IP from `UserIP_Logging.csv`."""
        raw_events_by_ip: dict[str, list[tuple[str, float]]] = {}
        try:
            with csv_path.open('r', newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    raw_ip = row.get('IP')
                    raw_date = row.get('Date')
                    raw_time = row.get('Time')
                    if not isinstance(raw_ip, str) or not isinstance(raw_date, str) or not isinstance(raw_time, str):
                        continue
                    ip_val = raw_ip.strip()
                    date_val = raw_date.strip()
                    time_val = raw_time.strip()
                    if not ip_val or not date_val or not time_val:
                        continue
                    parsed = _parse_log_datetime_str(f'{date_val} {time_val}')
                    if parsed is not None:
                        raw_events_by_ip.setdefault(ip_val, []).append(parsed)
        except (OSError, UnicodeDecodeError, csv.Error):
            return {}

        deduped_by_ip: dict[str, tuple[tuple[str, float], ...]] = {}
        for ip_str, events in raw_events_by_ip.items():
            sorted_events = sorted(events, key=lambda item: item[1])
            collapsed: list[tuple[str, float]] = [sorted_events[0]]
            for item in sorted_events[1:]:
                if item[1] - collapsed[-1][1] > _WINDOW_MERGE_TOLERANCE_SECONDS:
                    collapsed.append(item)
            deduped_by_ip[ip_str] = tuple(collapsed)
        return deduped_by_ip

    @classmethod
    def _rebuild_aggregated_index(cls) -> None:
        """Rebuild merged per-IP windows, stats, and sorted IPv4 lookup arrays from cached file data."""
        raw_windows_by_ip: dict[str, list[_SessionWindow]] = {}
        for _mtime, _size, file_windows in cls._session_file_cache.values():
            for ip_str, windows in file_windows.items():
                raw_windows_by_ip.setdefault(ip_str, []).extend(windows)

        all_ips = set(raw_windows_by_ip) | set(cls._csv_by_ip)
        valid_ip_pairs: list[tuple[IPv4Address, str]] = []
        for ip_str in all_ips:
            with contextlib.suppress(ValueError):
                valid_ip_pairs.append((IPv4Address(ip_str), ip_str))
        valid_ip_pairs.sort(key=lambda pair: pair[0])

        new_windows_by_ip: dict[str, tuple[_SessionWindow, ...]] = {}
        new_stats_by_ip: dict[str, _LogIPStats] = {}
        new_sorted_addrs: list[IPv4Address] = []
        new_sorted_strs: list[str] = []

        for addr, ip_str in valid_ip_pairs:
            merged_windows = _merge_overlapping_windows(raw_windows_by_ip.get(ip_str, ()))
            if merged_windows:
                new_windows_by_ip[ip_str] = merged_windows
            stats = _compute_ip_log_stats(merged_windows, cls._csv_by_ip.get(ip_str, ()))
            if stats is not None:
                new_stats_by_ip[ip_str] = stats
                new_sorted_addrs.append(addr)
                new_sorted_strs.append(ip_str)

        cls._windows_by_ip = new_windows_by_ip
        cls._stats_by_ip = new_stats_by_ip
        cls._sorted_ip_addresses = new_sorted_addrs
        cls._sorted_ip_strings = new_sorted_strs
        cls._initialized = True

    @classmethod
    def _ensure_fresh(cls) -> None:
        """Scan log file metadata at most once per throttle window and re-parse only modified files."""
        now = time.monotonic()
        if cls._initialized and (now - cls._last_scan_monotonic) < cls._SCAN_THROTTLE_SECONDS:
            return

        with cls._cache_lock:
            now = time.monotonic()
            if cls._initialized and (now - cls._last_scan_monotonic) < cls._SCAN_THROTTLE_SECONDS:
                return

            changed = not cls._initialized
            current_session_files: set[Path] = set()
            if SESSIONS_LOGGING_DIR_PATH.is_dir():
                for json_path in SESSIONS_LOGGING_DIR_PATH.rglob('*.json'):
                    try:
                        st = json_path.stat()
                    except OSError:
                        continue
                    current_session_files.add(json_path)
                    cached = cls._session_file_cache.get(json_path)
                    if cached is None or cached[0] != st.st_mtime or cached[1] != st.st_size:
                        cls._session_file_cache[json_path] = (
                            st.st_mtime,
                            st.st_size,
                            cls._parse_session_json_file(json_path),
                        )
                        changed = True

            removed_files = set(cls._session_file_cache) - current_session_files
            if removed_files:
                for removed_path in removed_files:
                    cls._session_file_cache.pop(removed_path, None)
                changed = True

            csv_sig: tuple[float, int] | None = None
            if USERIP_LOGGING_PATH.is_file():
                with contextlib.suppress(OSError):
                    csv_stat = USERIP_LOGGING_PATH.stat()
                    csv_sig = (csv_stat.st_mtime, csv_stat.st_size)
            if csv_sig != cls._csv_file_state:
                cls._csv_by_ip = cls._parse_userip_csv_file(USERIP_LOGGING_PATH) if csv_sig is not None else {}
                cls._csv_file_state = csv_sig
                changed = True

            if changed:
                cls._rebuild_aggregated_index()
            cls._last_scan_monotonic = time.monotonic()

    @classmethod
    def get_single_ip_stats(cls, ip_str: str, live_player: Player | None = None) -> _LogIPStats | None:
        """Return `_LogIPStats` for a single IPv4 string, merging live session state when present."""
        player = live_player if live_player is not None else PlayersRegistry.get_player_by_ip(ip_str)
        if player is None:
            return cls._stats_by_ip.get(ip_str)
        live_window = _build_live_player_window(player)
        base_windows = cls._windows_by_ip.get(ip_str, ())
        merged_windows = _merge_overlapping_windows((*base_windows, live_window))
        return _compute_ip_log_stats(merged_windows, cls._csv_by_ip.get(ip_str, ()))

    @classmethod
    def get_stats_for_entry_ip(cls, entry_ip: str) -> _LogIPStats | None:
        """Resolve historical `_LogIPStats` for a single IP or IP range entry string."""
        cleaned = entry_ip.strip()
        if not cleaned:
            return None
        cls._ensure_fresh()

        try:
            IPv4Address(cleaned)
            is_single = True
        except ValueError:
            is_single = False

        if is_single:
            return cls.get_single_ip_stats(cleaned)

        try:
            ip_ranges = parse_ip_range_entry(cleaned)
        except ValueError:
            return None

        covered_ips: set[str] = set()
        sorted_addrs = cls._sorted_ip_addresses
        sorted_strs = cls._sorted_ip_strings
        for ip_range in ip_ranges:
            bounds = ip_range.bounds
            if bounds is None:
                continue
            lo = bisect_left(sorted_addrs, bounds[0])
            hi = bisect_right(sorted_addrs, bounds[1])
            covered_ips.update(sorted_strs[lo:hi])

        live_by_ip: dict[str, Player] = {}
        for player in PlayersRegistry.get_all_players():
            if any(player.ip in ip_range for ip_range in ip_ranges):
                covered_ips.add(player.ip)
                live_by_ip[player.ip] = player

        if not covered_ips:
            return None

        first_seen_at: str | None = None
        last_seen_at: str | None = None
        detections_count = 0
        for ip_str in covered_ips:
            stats = cls.get_single_ip_stats(ip_str, live_player=live_by_ip.get(ip_str))
            if stats is None:
                continue
            first_seen_at = pick_earliest_iso(first_seen_at, stats.first_seen_at)
            last_seen_at = pick_latest_iso(last_seen_at, stats.last_seen_at)
            detections_count += stats.detections_count

        if first_seen_at is None or last_seen_at is None or detections_count <= 0:
            return None
        return _LogIPStats(first_seen_at=first_seen_at, last_seen_at=last_seen_at, detections_count=detections_count)


def enrich_userip_entry_from_logs(entry: UserIPEntryModel) -> tuple[UserIPEntryModel, bool]:
    """Enrich a `UserIPEntryModel` with historical timestamps and detection counts from logs.

    Populates or widens `first_seen_at` and `last_seen_at`, raises `detections_count` to at least
    the logged encounter count, and clamps `added_at` so it is never later than `first_seen_at`
    or `last_seen_at`.

    Returns:
        A tuple of `(enriched_entry, was_modified)`.
    """
    cleaned_ip = entry.ip.strip()
    if not cleaned_ip:
        return entry, False

    log_stats = _UserIPLogHistoryCache.get_stats_for_entry_ip(cleaned_ip)
    first_seen_at = entry.first_seen_at
    last_seen_at = entry.last_seen_at
    detections_count = entry.detections_count

    if log_stats is not None:
        first_seen_at = pick_earliest_iso(first_seen_at, log_stats.first_seen_at)
        last_seen_at = pick_latest_iso(last_seen_at, log_stats.last_seen_at)
        detections_count = max(detections_count, log_stats.detections_count)

    earliest_seen = pick_earliest_iso(first_seen_at, last_seen_at)
    added_at = entry.added_at
    if earliest_seen is not None:
        added_at = pick_earliest_iso(added_at, earliest_seen) or added_at

    if (
        first_seen_at == entry.first_seen_at
        and last_seen_at == entry.last_seen_at
        and detections_count == entry.detections_count
        and added_at == entry.added_at
    ):
        return entry, False

    return (
        entry.model_copy(
            update={
                'first_seen_at': first_seen_at,
                'last_seen_at': last_seen_at,
                'detections_count': detections_count,
                'added_at': added_at,
            },
        ),
        True,
    )


def _ensure_default_userip_files() -> None:
    """Ensure the UserIP databases directory and default `.json` files exist."""
    USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
    for json_path, default_settings in DEFAULT_USERIP_FILES_SETTINGS_BY_PATH.items():
        if not json_path.is_file():
            db_file = UserIPDatabaseFile(settings=default_settings, entries=[])
            json_path.write_text(db_file.serialize_to_json(), encoding='utf-8')


def _parse_and_repair_single_raw_entry(
    raw_entry: object,
    json_name: str,
    repaired_entries: list[UserIPEntryModel],
    seen_pairs: dict[tuple[str, str], int],
) -> bool:
    """Validate and repair one raw entry dict from a UserIP `.json` database file.

    Returns:
        `True` if the entry required auto-repair (meaning the file should be rewritten).
    """
    if not isinstance(raw_entry, dict):
        return True

    entry_dict = cast('dict[str, Any]', raw_entry)
    raw_username: object = entry_dict.get('username')
    raw_ip: object = entry_dict.get('ip')
    raw_is_looky: object = entry_dict.get('is_looky', False)
    raw_notes: object = entry_dict.get('notes', '')

    if not isinstance(raw_username, str) or not isinstance(raw_ip, str):
        return True

    username = raw_username.strip()
    ip = raw_ip.strip()
    need_rewrite = username != raw_username or ip != raw_ip

    if not username or not ip:
        return True

    if not is_valid_ip_range_entry(ip):
        logger.info('Auto-removed invalid IP entry "%s=%s" from "%s".', username, ip, json_name)
        return True

    is_looky = False
    if isinstance(raw_is_looky, bool):
        is_looky = raw_is_looky
    elif isinstance(raw_is_looky, str):
        need_rewrite = True
        try:
            is_looky, _ = custom_str_to_bool(raw_is_looky.strip())
        except InvalidBooleanValueError:
            is_looky = False
    else:
        need_rewrite = True

    notes = ''
    if isinstance(raw_notes, str):
        notes = raw_notes.strip()
        if notes != raw_notes:
            need_rewrite = True
    else:
        need_rewrite = True

    split_names = split_usernames(username)
    if not split_names:
        return True

    was_split = len(split_names) > 1
    if was_split:
        need_rewrite = True

    base_entry, metadata_clean = UserIPEntryModel.from_raw_entry_dict(
        entry_dict,
        username=split_names[0],
        ip=ip,
        is_looky=is_looky,
        notes=notes,
    )
    base_entry, log_enriched = enrich_userip_entry_from_logs(base_entry)
    if not metadata_clean or log_enriched:
        need_rewrite = True

    for split_name in split_names:
        if was_split:
            logger.info('Auto-repaired split username entry "%s=%s" in "%s".', split_name, ip, json_name)
        candidate = base_entry if split_name == base_entry.username else base_entry.model_copy(update={'username': split_name})
        pair_key = (split_name.casefold(), ip)
        if pair_key in seen_pairs:
            need_rewrite = True
            existing_idx = seen_pairs[pair_key]
            repaired_entries[existing_idx] = repaired_entries[existing_idx].merge_duplicate(candidate)
            logger.info('Auto-removed duplicate IP entry "%s=%s" from "%s".', split_name, ip, json_name)
            continue

        seen_pairs[pair_key] = len(repaired_entries)
        repaired_entries.append(candidate)

    return need_rewrite


def parse_userip_json_file(json_path: Path) -> tuple[UserIPSettings | None, list[UserIPEntryModel] | None]:
    """Parse, validate, and auto-repair a UserIP `.json` database file."""
    validate_file(json_path)

    raw_text = json_path.read_text(encoding='utf-8')
    try:
        raw_data: object = json.loads(raw_text)
    except json.JSONDecodeError as e:
        logger.warning('Failed to parse UserIP database "%s": %s; skipping file.', json_path.name, e)
        return None, None

    if not isinstance(raw_data, dict):
        logger.warning('UserIP database "%s" root is not a JSON object; skipping file.', json_path.name)
        return None, None

    typed_data = cast('dict[str, Any]', raw_data)
    need_rewrite = list(typed_data.keys()) != ['settings', 'entries']

    raw_settings_obj: object = typed_data.get('settings')
    if isinstance(raw_settings_obj, dict):
        raw_settings = cast('dict[str, Any]', raw_settings_obj)
    else:
        need_rewrite = True
        default_model = DEFAULT_USERIP_FILES_SETTINGS_BY_PATH.get(json_path, UserIPSettingsModel())
        raw_settings = default_model.model_dump()

    validated_settings, settings_rewritten = UserIPSettingsModel.validate_settings(raw_settings)
    if settings_rewritten:
        need_rewrite = True

    raw_entries_obj: object = typed_data.get('entries')
    if isinstance(raw_entries_obj, list):
        raw_entries = cast('list[object]', raw_entries_obj)
    else:
        need_rewrite = True
        raw_entries = []

    repaired_entries: list[UserIPEntryModel] = []
    seen_pairs: dict[tuple[str, str], int] = {}

    for raw_entry in raw_entries:
        if _parse_and_repair_single_raw_entry(raw_entry, json_path.name, repaired_entries, seen_pairs):
            need_rewrite = True

    if need_rewrite:
        db_file = UserIPDatabaseFile(settings=validated_settings, entries=repaired_entries)
        json_path.write_text(db_file.serialize_to_json(), encoding='utf-8')
        logger.info('Rewrote "%s" after auto-repairs.', json_path.name)

    runtime_settings = UserIPSettings(
        enabled=validated_settings.ENABLED,
        color=QColor(validated_settings.COLOR) if validated_settings.COLOR else QColor('WHITE'),
        log=validated_settings.LOG,
        notifications=validated_settings.NOTIFICATIONS,
        voice_notifications=validated_settings.VOICE_NOTIFICATIONS,
        protection=ProtectionSettings(
            enabled=validated_settings.PROTECTION,
            suspend_process_mode=validated_settings.PROTECTION_SUSPEND_PROCESS_MODE,
        ),
    )

    return runtime_settings, repaired_entries


def invalidate_userip_db_mtime(db_path: Path | None = None) -> None:
    """Invalidate cached UserIP database modification signatures so the next poll forces a rebuild."""
    if db_path is None:
        _last_userip_db_mod_times.clear()
    else:
        _last_userip_db_mod_times.pop(db_path, None)


def _snapshot_db_mod_times() -> dict[Path, tuple[int, int]]:
    """Return a fresh `{path: (st_mtime_ns, st_size)}` snapshot for every `.json` file under the databases directory."""
    if not USERIP_DATABASES_DIR_PATH.exists():
        return {}
    snapshot: dict[Path, tuple[int, int]] = {}
    for path in USERIP_DATABASES_DIR_PATH.rglob('*.json'):
        if not path.is_file():
            continue
        sig = get_file_signature(path)
        if sig is not None:
            snapshot[path] = sig
    return snapshot


def _collect_userip_json_files() -> tuple[list[Path], dict[Path, tuple[int, int]]]:
    if not USERIP_DATABASES_DIR_PATH.exists():
        return [], {}
    files: list[Path] = []
    mod_times: dict[Path, tuple[int, int]] = {}
    for path in USERIP_DATABASES_DIR_PATH.rglob('*.json'):
        if not path.is_file():
            continue
        sig = get_file_signature(path)
        if sig is None:
            continue
        files.append(path)
        mod_times[path] = sig
    return files, mod_times


def update_userip_databases() -> tuple[float, bool]:
    """Check for changes in UserIP database files, re-parsing and rebuilding when modified.

    Returns:
        A tuple of (current monotonic timestamp, whether databases were rebuilt).
    """
    with _update_userip_databases_lock:
        _ensure_default_userip_files()

        current_json_files, current_userip_db_mod_times = _collect_userip_json_files()
        if current_userip_db_mod_times == _last_userip_db_mod_times:
            return time.monotonic(), False

        if _last_userip_db_mod_times:
            logger.debug('Detected changes in UserIP databases, re-parsing...')

        new_databases: list[tuple[Path, UserIPSettings, list[UserIPEntryModel]]] = []
        for userip_path in current_json_files:
            parsed_settings, parsed_entries = parse_userip_json_file(userip_path)
            if parsed_settings is None or parsed_entries is None:
                continue

            new_databases.append((userip_path, parsed_settings, parsed_entries))

        UserIPDatabases.populate(new_databases)
        UserIPDatabases.build()

        # Re-snapshot mod times *after* parsing, because parse_userip_json_file() may rewrite
        # files during auto-repair, advancing their mtimes beyond the pre-parse snapshot.
        _last_userip_db_mod_times.clear()
        _last_userip_db_mod_times.update(_snapshot_db_mod_times())

        return time.monotonic(), True


def _parse_existing_entry_dict(item_dict: dict[str, Any], entry_user: str, entry_ip: str) -> UserIPEntryModel:
    """Construct a `UserIPEntryModel` from a raw dictionary while preserving all metadata."""
    raw_is_looky: object = item_dict.get('is_looky', False)
    is_looky = False
    if isinstance(raw_is_looky, bool):
        is_looky = raw_is_looky
    elif isinstance(raw_is_looky, str):
        try:
            is_looky, _ = custom_str_to_bool(raw_is_looky.strip())
        except InvalidBooleanValueError:
            is_looky = False
    raw_notes: object = item_dict.get('notes', '')
    notes = raw_notes.strip() if isinstance(raw_notes, str) else ''
    entry, _ = UserIPEntryModel.from_raw_entry_dict(item_dict, username=entry_user, ip=entry_ip, is_looky=is_looky, notes=notes)
    return entry


def _load_raw_userip_db(db_path: Path, *, action_label: str) -> tuple[UserIPSettingsModel, list[object]] | None:
    """Read and validate the settings and raw entries list from a UserIP database file."""
    try:
        raw_data: object = json.loads(db_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning('Failed to read UserIP database "%s" for %s: %s', db_path, action_label, e)
        return None

    if not isinstance(raw_data, dict):
        return None

    typed_data = cast('dict[str, Any]', raw_data)
    raw_settings_obj: object = typed_data.get('settings')
    raw_settings = cast('dict[str, Any]', raw_settings_obj) if isinstance(raw_settings_obj, dict) else {}
    validated_settings, _ = UserIPSettingsModel.validate_settings(raw_settings)

    raw_entries_obj: object = typed_data.get('entries')
    raw_entries = cast('list[object]', raw_entries_obj) if isinstance(raw_entries_obj, list) else []
    return validated_settings, raw_entries


def _write_userip_db(db_path: Path, settings: UserIPSettingsModel, entries: list[UserIPEntryModel], *, action_label: str) -> bool:
    """Serialize and write a UserIP database file, invalidating its cached mtime."""
    db_file = UserIPDatabaseFile(settings=settings, entries=entries)
    try:
        db_path.write_text(db_file.serialize_to_json(), encoding='utf-8')
    except OSError as e:
        logger.warning('Failed to write UserIP database "%s" for %s: %s', db_path, action_label, e)
        return False
    invalidate_userip_db_mtime(db_path)
    return True


def append_userip_entry_if_missing(db_path: Path, username: str, ip: str) -> bool:
    """Append a `{username, ip}` entry to the UserIP `.json` database file if not already covered.

    Returns:
        `True` if the entry was added; `False` if already present or invalid.
    """
    cleaned_username = username.strip()
    cleaned_ip = ip.strip()
    if not cleaned_username or not cleaned_ip or not db_path.is_file():
        return False

    with _update_userip_databases_lock:
        loaded = _load_raw_userip_db(db_path, action_label='auto-feed')
        if loaded is None:
            return False
        validated_settings, raw_entries = loaded

        entries: list[UserIPEntryModel] = []
        username_cf = cleaned_username.casefold()
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            item_dict = cast('dict[str, Any]', item)
            raw_user: object = item_dict.get('username')
            raw_ip: object = item_dict.get('ip')
            entry_user = raw_user.strip() if isinstance(raw_user, str) else ''
            entry_ip = raw_ip.strip() if isinstance(raw_ip, str) else ''
            if not entry_user or not entry_ip:
                continue
            if entry_user.casefold() == username_cf and entry_ip_covers_ip(entry_ip, cleaned_ip):
                return False
            entries.append(_parse_existing_entry_dict(item_dict, entry_user, entry_ip))

        new_entry, _ = enrich_userip_entry_from_logs(
            UserIPEntryModel(
                username=cleaned_username,
                ip=cleaned_ip,
                is_looky=False,
                notes='',
                source='Auto-IP',
            ),
        )
        entries.append(new_entry)
        return _write_userip_db(db_path, validated_settings, entries, action_label='auto-feed')


def _update_matching_userip_entries(
    db_path: Path,
    ip_address: str,
    apply_update: Callable[[UserIPEntryModel], UserIPEntryModel],
) -> UserIP | None:
    """Rewrite every entry in `db_path` whose IP or range covers `ip_address` through `apply_update`.

    Args:
        db_path: Path to the matched UserIP `.json` database file.
        ip_address: The player's IPv4 address.
        apply_update: Returns the updated copy of a matching entry.

    Returns:
        The refreshed `UserIP` snapshot after updating the database, or `None` if unavailable.
    """
    cleaned_ip = ip_address.strip()
    if not cleaned_ip or not db_path.is_file():
        return None

    modified = False

    with _update_userip_databases_lock:
        loaded = _load_raw_userip_db(db_path, action_label='player activity')
        if loaded is None:
            return None
        validated_settings, raw_entries = loaded

        entries: list[UserIPEntryModel] = []
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            item_dict = cast('dict[str, Any]', item)
            raw_user: object = item_dict.get('username')
            raw_ip: object = item_dict.get('ip')
            entry_user = raw_user.strip() if isinstance(raw_user, str) else ''
            entry_ip = raw_ip.strip() if isinstance(raw_ip, str) else ''
            if not entry_user or not entry_ip:
                continue
            parsed_entry = _parse_existing_entry_dict(item_dict, entry_user, entry_ip)
            if entry_ip_covers_ip(entry_ip, cleaned_ip):
                parsed_entry = apply_update(parsed_entry)
                modified = True
            entries.append(parsed_entry)

        if modified and not _write_userip_db(db_path, validated_settings, entries, action_label='player activity'):
            return None

    if modified:
        update_userip_databases()
    return UserIPDatabases.resolve_userip(cleaned_ip)


def _apply_detection_to_entry(entry: UserIPEntryModel, timestamp: str) -> UserIPEntryModel:
    """Apply a live player join detection to `entry` while merging historical log statistics."""
    already_counted = (
        entry.detections_count > 0
        and entry.last_seen_at is not None
        and pick_latest_iso(entry.last_seen_at, timestamp) == entry.last_seen_at
    )
    incremented_count = entry.detections_count if already_counted else entry.detections_count + 1
    enriched_entry, _ = enrich_userip_entry_from_logs(entry)
    first_seen_at = pick_earliest_iso(enriched_entry.first_seen_at, timestamp)
    last_seen_at = pick_latest_iso(enriched_entry.last_seen_at, timestamp)
    earliest_seen = pick_earliest_iso(first_seen_at, last_seen_at)
    added_at = pick_earliest_iso(enriched_entry.added_at, earliest_seen) if earliest_seen is not None else enriched_entry.added_at
    return enriched_entry.model_copy(
        update={
            'detections_count': max(incremented_count, enriched_entry.detections_count),
            'first_seen_at': first_seen_at,
            'last_seen_at': last_seen_at,
            'added_at': added_at,
        },
    )


def record_userip_detection(db_path: Path, ip_address: str, joined_at: datetime) -> UserIP | None:
    """Increment `detections_count` and merge `joined_at` into `first_seen_at` / `last_seen_at` for entries matching `ip_address`.

    Args:
        db_path: Path to the matched UserIP `.json` database file.
        ip_address: The detected player's IPv4 address.
        joined_at: When the player joined the current session.

    Returns:
        The refreshed `UserIP` snapshot after updating the database, or `None` if unavailable.
    """
    timestamp = joined_at.isoformat(timespec='seconds')
    return _update_matching_userip_entries(
        db_path,
        ip_address,
        lambda entry: _apply_detection_to_entry(entry, timestamp),
    )


def record_userip_last_seen(db_path: Path, ip_address: str, last_seen: datetime) -> UserIP | None:
    """Merge the player's last activity time into `last_seen_at` for entries matching `ip_address`.

    Args:
        db_path: Path to the matched UserIP `.json` database file.
        ip_address: The departing player's IPv4 address.
        last_seen: When the player was last active in the session they just left.

    Returns:
        The refreshed `UserIP` snapshot after updating the database, or `None` if unavailable.
    """
    timestamp = last_seen.isoformat(timespec='seconds')
    return _update_matching_userip_entries(
        db_path,
        ip_address,
        lambda entry: enrich_userip_entry_from_logs(
            entry.model_copy(update={'last_seen_at': pick_latest_iso(entry.last_seen_at, timestamp)}),
        )[0],
    )
