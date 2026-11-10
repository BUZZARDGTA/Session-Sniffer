"""Incremental historical IP sighting cache from session logs and `UserIP_Logging.csv`."""

import contextlib
import csv
import json
import os
import re
import socket
import time
from bisect import bisect_left, bisect_right
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, ClassVar, NamedTuple, cast

from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH, USERIP_LOGGING_PATH
from session_sniffer.models.userip_settings_model import UserIPEntryModel, pick_earliest_iso, pick_latest_iso
from session_sniffer.networking.ip_range import parse_ip_range
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Any

    from session_sniffer.models.player import Player

_CSV_SESSION_MATCH_TOLERANCE_SECONDS = 60.0
_WINDOW_MERGE_TOLERANCE_SECONDS = 1.0
_SESSION_SCAN_WORKERS = 16
_IPV4_DOTTED_QUAD_SEPARATOR_COUNT = 3

_RE_SESSION_PLAYER_RECORD = re.compile(
    rb'"First Seen"\s*:\s*"(\d{4}-[^"]+)"\s*,\s*'
    rb'"Last Rejoin"\s*:\s*"([^"]+)"\s*,\s*'
    rb'"Last Seen"\s*:\s*"([^"]+)"'
    rb'[^{}]*?"Rejoins"\s*:\s*(\d+)',
)

type _RawSessionRecord = tuple[str, str, str, int]


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


def _ipv4_to_u32(ip_str: str) -> int | None:
    """Convert a dotted-quad IPv4 string to a 32-bit unsigned int, or `None` if invalid."""
    if '/' in ip_str or '-' in ip_str or '*' in ip_str or ',' in ip_str:
        return None
    try:
        packed = socket.inet_aton(ip_str)
    except OSError:
        return None
    if ip_str.count('.') != _IPV4_DOTTED_QUAD_SEPARATOR_COUNT:
        return None
    return int.from_bytes(packed, 'big')


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


def _raw_record_to_window(record: _RawSessionRecord) -> _SessionWindow | None:
    """Convert a lazy `_RawSessionRecord` tuple into a normalized `_SessionWindow`."""
    first_raw, rejoin_raw, last_raw, rejoins = record
    points = [parsed for raw_val in (first_raw, rejoin_raw, last_raw) if raw_val and (parsed := _parse_log_datetime_str(raw_val)) is not None]
    if not points:
        return None
    first_iso, start_ts = min(points, key=lambda item: item[1])
    last_iso, end_ts = max(points, key=lambda item: item[1])
    return _SessionWindow(first_iso, last_iso, start_ts, end_ts, 1 + max(0, rejoins))


def _build_live_player_window(player: Player) -> _SessionWindow:
    """Build a `_SessionWindow` from a live `Player` in `PlayersRegistry`."""
    points = [
        (dt.isoformat(timespec='seconds'), dt.timestamp())
        for dt in (player.datetime.first_seen.astimezone(), player.datetime.last_rejoin.astimezone(), player.datetime.last_seen.astimezone())
    ]
    first_iso, start_ts = min(points, key=lambda item: item[1])
    last_iso, end_ts = max(points, key=lambda item: item[1])
    return _SessionWindow(first_iso, last_iso, start_ts, end_ts, 1 + max(0, player.rejoins))


def _merge_overlapping_windows(windows: Sequence[_SessionWindow]) -> tuple[_SessionWindow, ...]:
    """Sort and merge overlapping or adjacent session windows for a single IP."""
    if not windows:
        return ()
    sorted_windows = sorted(windows, key=lambda window: (window.start_ts, window.end_ts))
    merged: list[_SessionWindow] = [sorted_windows[0]]
    for current in sorted_windows[1:]:
        prev = merged[-1]
        if current.start_ts <= prev.end_ts + _WINDOW_MERGE_TOLERANCE_SECONDS:
            first_iso = prev.first_seen_iso if prev.start_ts <= current.start_ts else current.first_seen_iso
            last_iso = prev.last_seen_iso if prev.end_ts >= current.end_ts else current.last_seen_iso
            merged[-1] = _SessionWindow(first_iso, last_iso, min(prev.start_ts, current.start_ts), max(prev.end_ts, current.end_ts), max(prev.encounters, current.encounters))
        else:
            merged.append(current)
    return tuple(merged)


def _compute_ip_log_stats(merged_windows: Sequence[_SessionWindow], csv_events: Sequence[tuple[str, float]]) -> _LogIPStats | None:
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

    detections_count = sum(max(window.encounters, matched_csv_counts[i]) for i, window in enumerate(merged_windows)) + unmatched_csv_count
    if detections_count <= 0:
        return None
    first_seen_at = merged_windows[0].first_seen_iso if merged_windows else None
    last_seen_at = max(merged_windows, key=lambda window: window.end_ts).last_seen_iso if merged_windows else None
    if csv_events:
        first_seen_at = pick_earliest_iso(first_seen_at, csv_events[0][0])
        last_seen_at = pick_latest_iso(last_seen_at, csv_events[-1][0])
    return _LogIPStats(first_seen_at, last_seen_at, detections_count) if first_seen_at is not None and last_seen_at is not None else None


def _parse_session_file_fallback(data: bytes) -> dict[str, list[_RawSessionRecord]]:
    """Fallback JSON parser for non-standard session log files."""
    try:
        raw_data: object = json.loads(data.decode('utf-8'))
    except UnicodeDecodeError, json.JSONDecodeError:
        return {}
    if not isinstance(raw_data, dict):
        return {}
    typed_root = cast('dict[str, Any]', raw_data)
    records_by_ip: dict[str, list[_RawSessionRecord]] = {}
    for section_key in ('connected', 'disconnected'):
        section_obj: object = typed_root.get(section_key)
        if not isinstance(section_obj, dict):
            continue
        for raw_ip, raw_info in cast('dict[object, object]', section_obj).items():
            if not isinstance(raw_ip, str) or not isinstance(raw_info, dict):
                continue
            info = cast('dict[str, Any]', raw_info)
            raw_rejoins = info.get('Rejoins', 0)
            rejoins = raw_rejoins if isinstance(raw_rejoins, int) and not isinstance(raw_rejoins, bool) and raw_rejoins >= 0 else 0
            first_str = info['First Seen'] if isinstance(info.get('First Seen'), str) else ''
            rejoin_str = info['Last Rejoin'] if isinstance(info.get('Last Rejoin'), str) else ''
            last_str = info['Last Seen'] if isinstance(info.get('Last Seen'), str) else ''
            if first_str or rejoin_str or last_str:
                records_by_ip.setdefault(raw_ip.strip(), []).append((first_str, rejoin_str, last_str, rejoins))
    return records_by_ip


def _parse_session_file_task(item: tuple[str, float, int]) -> tuple[str, float, int, dict[str, list[_RawSessionRecord]]]:
    """Fast byte-level extractor for a single session `.json` file."""
    path_str, mtime, size = item
    try:
        with Path(path_str).open('rb') as file:
            data = file.read()
    except OSError:
        return path_str, mtime, size, {}

    records_by_ip: dict[str, list[_RawSessionRecord]] = {}
    for match in _RE_SESSION_PLAYER_RECORD.finditer(data):
        u_pos = data.rfind(b'"Usernames"', 0, match.start())
        if u_pos <= 0 or (q2 := data.rfind(b'"', 0, u_pos)) <= 0 or (q1 := data.rfind(b'"', 0, q2)) < 0:
            continue
        ip_str = data[q1 + 1 : q2].decode('ascii', errors='ignore').strip()
        if ip_str:
            records_by_ip.setdefault(ip_str, []).append(
                (
                    match.group(1).decode('ascii', errors='ignore'),
                    match.group(2).decode('ascii', errors='ignore'),
                    match.group(3).decode('ascii', errors='ignore'),
                    int(match.group(4)),
                ),
            )

    if not records_by_ip and b'"First Seen"' in data:
        records_by_ip = _parse_session_file_fallback(data)
    return path_str, mtime, size, records_by_ip


class _UserIPLogHistoryCache:
    """Incremental lazy cache of historical IP sightings from `Logging/Sessions/` and `UserIP_Logging.csv`."""

    _SCAN_THROTTLE_SECONDS: ClassVar[float] = 1.0
    _FULL_TREE_SCAN_INTERVAL_SECONDS: ClassVar[float] = 30.0
    _cache_lock: ClassVar[Lock] = Lock()
    _initialized: ClassVar[bool] = False
    _last_scan_monotonic: ClassVar[float] = 0.0
    _last_full_tree_scan_monotonic: ClassVar[float] = 0.0
    _dir_mtimes: ClassVar[dict[str, float]] = {}
    _files_by_dir: ClassVar[dict[str, dict[str, tuple[float, int]]]] = {}
    _latest_leaf_dir: ClassVar[str | None] = None
    _session_file_cache: ClassVar[dict[str, tuple[float, int, dict[str, list[_RawSessionRecord]]]]] = {}
    _raw_records_by_ip: ClassVar[dict[str, list[_RawSessionRecord]]] = {}
    _csv_file_state: ClassVar[tuple[float, int] | None] = None
    _csv_by_ip: ClassVar[dict[str, tuple[tuple[str, float], ...]]] = {}
    _merged_windows_by_ip: ClassVar[dict[str, tuple[_SessionWindow, ...]]] = {}
    _stats_by_ip: ClassVar[dict[str, _LogIPStats | None]] = {}
    _sorted_ips_dirty: ClassVar[bool] = True
    _sorted_ip_ints: ClassVar[list[int]] = []
    _sorted_ip_strings: ClassVar[list[str]] = []

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
        except OSError, UnicodeDecodeError, csv.Error:
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
    def _remove_file_records(cls, file_map: dict[str, list[_RawSessionRecord]]) -> None:
        """Remove a single session file's records from `_raw_records_by_ip` and invalidate affected IPs."""
        for ip_str, old_recs in file_map.items():
            bucket = cls._raw_records_by_ip.get(ip_str)
            if bucket is not None:
                for rec in old_recs:
                    with contextlib.suppress(ValueError):
                        bucket.remove(rec)
                if not bucket:
                    del cls._raw_records_by_ip[ip_str]
                    cls._sorted_ips_dirty = True
            cls._merged_windows_by_ip.pop(ip_str, None)
            cls._stats_by_ip.pop(ip_str, None)

    @classmethod
    def _add_file_records(cls, file_map: dict[str, list[_RawSessionRecord]]) -> None:
        """Add a single session file's records into `_raw_records_by_ip` and invalidate affected IPs."""
        for ip_str, new_recs in file_map.items():
            bucket = cls._raw_records_by_ip.get(ip_str)
            if bucket is None:
                cls._raw_records_by_ip[ip_str] = list(new_recs)
                cls._sorted_ips_dirty = True
            else:
                bucket.extend(new_recs)
            cls._merged_windows_by_ip.pop(ip_str, None)
            cls._stats_by_ip.pop(ip_str, None)

    @classmethod
    def _collect_session_files(cls, *, full_tree: bool) -> dict[str, tuple[float, int]]:
        """Collect `{file_path: (mtime, size)}` across `SESSIONS_LOGGING_DIR_PATH`, skipping unchanged folders."""
        root_str = str(SESSIONS_LOGGING_DIR_PATH)
        if not SESSIONS_LOGGING_DIR_PATH.is_dir():
            cls._dir_mtimes.clear()
            cls._files_by_dir.clear()
            cls._latest_leaf_dir = None
            return {}

        if not full_tree and cls._latest_leaf_dir is not None:
            with contextlib.suppress(OSError):
                leaf = cls._latest_leaf_dir
                leaf_files: dict[str, tuple[float, int]] = {}
                with os.scandir(leaf) as it:
                    for entry in it:
                        if entry.name.endswith('.json') and entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            leaf_files[entry.path] = (st.st_mtime, st.st_size)
                cls._files_by_dir[leaf] = leaf_files
                return {fpath: sig for dir_files in cls._files_by_dir.values() for fpath, sig in dir_files.items()}

        seen_dirs: set[str] = set()
        newest_leaf: str | None = None
        stack = [root_str]
        while stack:
            cur_dir = stack.pop()
            try:
                st_dir = Path(cur_dir).stat()
            except OSError:
                continue
            seen_dirs.add(cur_dir)
            if cur_dir != cls._latest_leaf_dir and cls._dir_mtimes.get(cur_dir) == st_dir.st_mtime and cur_dir in cls._files_by_dir:
                if bool(cls._files_by_dir.get(cur_dir)) and (newest_leaf is None or cur_dir > newest_leaf):
                    newest_leaf = cur_dir
                continue

            dir_files: dict[str, tuple[float, int]] = {}
            has_subdirs = False
            try:
                with os.scandir(cur_dir) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            has_subdirs = True
                            stack.append(entry.path)
                        elif entry.name.endswith('.json') and entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            dir_files[entry.path] = (st.st_mtime, st.st_size)
            except OSError:
                continue
            if not has_subdirs:
                cls._dir_mtimes[cur_dir] = st_dir.st_mtime
            else:
                cls._dir_mtimes.pop(cur_dir, None)
            cls._files_by_dir[cur_dir] = dir_files
            if dir_files and (newest_leaf is None or cur_dir > newest_leaf):
                newest_leaf = cur_dir

        for stale_dir in set(cls._files_by_dir) - seen_dirs:
            cls._dir_mtimes.pop(stale_dir, None)
            cls._files_by_dir.pop(stale_dir, None)

        cls._latest_leaf_dir = newest_leaf
        return {fpath: sig for df in cls._files_by_dir.values() for fpath, sig in df.items()}

    @classmethod
    def _ensure_fresh(cls) -> None:
        """Scan log file metadata at most once per throttle window and incrementally update modified files."""
        now = time.monotonic()
        if cls._initialized and (now - cls._last_scan_monotonic) < cls._SCAN_THROTTLE_SECONDS:
            return

        with cls._cache_lock:
            now = time.monotonic()
            if cls._initialized and (now - cls._last_scan_monotonic) < cls._SCAN_THROTTLE_SECONDS:
                return

            do_full_tree = not cls._initialized or (now - cls._last_full_tree_scan_monotonic) >= cls._FULL_TREE_SCAN_INTERVAL_SECONDS
            current_files = cls._collect_session_files(full_tree=do_full_tree)
            if do_full_tree:
                cls._last_full_tree_scan_monotonic = now

            to_parse: list[tuple[str, float, int]] = []
            for fpath, (mtime, size) in current_files.items():
                cached = cls._session_file_cache.get(fpath)
                if cached is None or cached[0] != mtime or cached[1] != size:
                    to_parse.append((fpath, mtime, size))

            for removed_path in set(cls._session_file_cache) - set(current_files):
                old_cached = cls._session_file_cache.pop(removed_path, None)
                if old_cached is not None:
                    cls._remove_file_records(old_cached[2])

            if to_parse:
                if len(to_parse) == 1:
                    parsed_results = [_parse_session_file_task(to_parse[0])]
                else:
                    workers = min(_SESSION_SCAN_WORKERS, len(to_parse))
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        parsed_results = list(executor.map(_parse_session_file_task, to_parse, chunksize=max(1, len(to_parse) // (workers * 2))))

                for fpath, mtime, size, file_map in parsed_results:
                    old_cached = cls._session_file_cache.get(fpath)
                    if old_cached is not None:
                        cls._remove_file_records(old_cached[2])
                    cls._session_file_cache[fpath] = (mtime, size, file_map)
                    cls._add_file_records(file_map)

            csv_sig: tuple[float, int] | None = None
            if USERIP_LOGGING_PATH.is_file():
                with contextlib.suppress(OSError):
                    csv_stat = USERIP_LOGGING_PATH.stat()
                    csv_sig = (csv_stat.st_mtime, csv_stat.st_size)
            if csv_sig != cls._csv_file_state:
                new_csv_by_ip = cls._parse_userip_csv_file(USERIP_LOGGING_PATH) if csv_sig is not None else {}
                changed_csv_ips = set(cls._csv_by_ip) ^ set(new_csv_by_ip)
                for ip_str in set(cls._csv_by_ip) & set(new_csv_by_ip):
                    if cls._csv_by_ip[ip_str] != new_csv_by_ip[ip_str]:
                        changed_csv_ips.add(ip_str)
                if set(cls._csv_by_ip) != set(new_csv_by_ip):
                    cls._sorted_ips_dirty = True
                for ip_str in changed_csv_ips:
                    cls._stats_by_ip.pop(ip_str, None)
                cls._csv_by_ip = new_csv_by_ip
                cls._csv_file_state = csv_sig

            cls._initialized = True
            cls._last_scan_monotonic = time.monotonic()

    @classmethod
    def _get_merged_windows_locked(cls, ip_str: str) -> tuple[_SessionWindow, ...]:
        """Return memoized merged `_SessionWindow`s for `ip_str` (caller must hold `_cache_lock`)."""
        cached_windows = cls._merged_windows_by_ip.get(ip_str)
        if cached_windows is not None:
            return cached_windows
        raw_records = cls._raw_records_by_ip.get(ip_str)
        if raw_records is None or not raw_records:
            cls._merged_windows_by_ip[ip_str] = ()
            return ()
        windows = [window for rec in raw_records if (window := _raw_record_to_window(rec)) is not None]
        merged = _merge_overlapping_windows(windows)
        cls._merged_windows_by_ip[ip_str] = merged
        return merged

    @classmethod
    def _get_cached_ip_stats_locked(cls, ip_str: str) -> _LogIPStats | None:
        """Return memoized historical `_LogIPStats` for `ip_str` (caller must hold `_cache_lock`)."""
        if ip_str in cls._stats_by_ip:
            return cls._stats_by_ip[ip_str]
        if ip_str not in cls._raw_records_by_ip and ip_str not in cls._csv_by_ip:
            cls._stats_by_ip[ip_str] = None
            return None
        merged_windows = cls._get_merged_windows_locked(ip_str)
        stats = _compute_ip_log_stats(merged_windows, cls._csv_by_ip.get(ip_str, ()))
        cls._stats_by_ip[ip_str] = stats
        return stats

    @classmethod
    def _ensure_sorted_ips_locked(cls) -> tuple[list[int], list[str]]:
        """Lazily build and return sorted 32-bit IPv4 ints and strings for range queries."""
        if cls._sorted_ips_dirty:
            pairs = sorted((u32, ip_str) for ip_str in (set(cls._raw_records_by_ip) | set(cls._csv_by_ip)) if (u32 := _ipv4_to_u32(ip_str)) is not None)
            cls._sorted_ip_ints = [item[0] for item in pairs]
            cls._sorted_ip_strings = [item[1] for item in pairs]
            cls._sorted_ips_dirty = False
        return cls._sorted_ip_ints, cls._sorted_ip_strings

    @classmethod
    def get_single_ip_stats(cls, ip_str: str, live_player: Player | None = None) -> _LogIPStats | None:
        """Return `_LogIPStats` for a single IPv4 string, merging live session state when present."""
        player = live_player if live_player is not None else PlayersRegistry.get_player_by_ip(ip_str)
        with cls._cache_lock:
            if player is None:
                return cls._get_cached_ip_stats_locked(ip_str)
            live_window = _build_live_player_window(player)
            base_windows = cls._get_merged_windows_locked(ip_str)
            csv_events = cls._csv_by_ip.get(ip_str, ())
        return _compute_ip_log_stats(_merge_overlapping_windows((*base_windows, live_window)), csv_events)

    @classmethod
    def get_stats_for_entry_ip(cls, entry_ip: str) -> _LogIPStats | None:
        """Resolve historical `_LogIPStats` for a single IP or IP range entry string."""
        cleaned = entry_ip.strip()
        if not cleaned:
            return None
        cls._ensure_fresh()
        if _ipv4_to_u32(cleaned) is not None:
            return cls.get_single_ip_stats(cleaned)
        try:
            ip_range = parse_ip_range(cleaned)
        except ValueError:
            return None

        covered_ips: set[str] = set()
        with cls._cache_lock:
            sorted_ints, sorted_strs = cls._ensure_sorted_ips_locked()
            if (bounds := ip_range.bounds) is not None:
                covered_ips.update(sorted_strs[bisect_left(sorted_ints, int(bounds[0])) : bisect_right(sorted_ints, int(bounds[1]))])

        live_by_ip: dict[str, Player] = {}
        for player in PlayersRegistry.get_all_players():
            if player.ip in ip_range:
                covered_ips.add(player.ip)
                live_by_ip[player.ip] = player
        if not covered_ips:
            return None

        first_seen_at: str | None = None
        last_seen_at: str | None = None
        detections_count = 0
        for ip_str in covered_ips:
            if (stats := cls.get_single_ip_stats(ip_str, live_player=live_by_ip.get(ip_str))) is not None:
                first_seen_at = pick_earliest_iso(first_seen_at, stats.first_seen_at)
                last_seen_at = pick_latest_iso(last_seen_at, stats.last_seen_at)
                detections_count += stats.detections_count
        return _LogIPStats(first_seen_at, last_seen_at, detections_count) if first_seen_at is not None and last_seen_at is not None and detections_count > 0 else None


def enrich_userip_entry_from_logs(entry: UserIPEntryModel) -> tuple[UserIPEntryModel, bool]:
    """Enrich a `UserIPEntryModel` with historical timestamps and detection counts from logs."""
    cleaned_ip = entry.ip.strip()
    if not cleaned_ip:
        return entry, False
    log_stats = _UserIPLogHistoryCache.get_stats_for_entry_ip(cleaned_ip)
    first_seen_at = pick_earliest_iso(entry.first_seen_at, log_stats.first_seen_at) if log_stats is not None else entry.first_seen_at
    last_seen_at = pick_latest_iso(entry.last_seen_at, log_stats.last_seen_at) if log_stats is not None else entry.last_seen_at
    detections_count = max(entry.detections_count, log_stats.detections_count) if log_stats is not None else entry.detections_count
    earliest_seen = pick_earliest_iso(first_seen_at, last_seen_at)
    added_at = (pick_earliest_iso(entry.added_at, earliest_seen) or entry.added_at) if earliest_seen is not None else entry.added_at
    if (first_seen_at, last_seen_at, detections_count, added_at) == (entry.first_seen_at, entry.last_seen_at, entry.detections_count, entry.added_at):
        return entry, False
    return entry.model_copy(update={'first_seen_at': first_seen_at, 'last_seen_at': last_seen_at, 'detections_count': detections_count, 'added_at': added_at}), True
