"""Parse mod menu logs to update the mapping of IPs to usernames and session host state."""

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from operator import itemgetter
from pathlib import Path
from threading import Lock
from typing import ClassVar

from session_sniffer.error_messages import format_type_error
from session_sniffer.utils import FileSignature, get_documents_dir, get_file_signature

logger = logging.getLogger(__name__)

FileModTimes = dict[Path, FileSignature]
UsernamesByIP = defaultdict[str, list[str]]

RE_MODMENU_LOGS_USER_PATTERN = re.compile(
    r'^user:(?P<username>[\w._-]{1,16}), '
    r'scid:\d{1,9}, '
    r'ip:(?P<ip>(?:\d{1,3}\.){3}\d{1,3}), '
    r'timestamp:\d{10}$',
)

TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / 'AppData' / 'Roaming' / 'PopstarDevs' / '2Take1Menu' / 'scripts' / 'Session_Sniffer-plugin' / 'log.txt'
STAND__PLUGIN__LOG_PATH = Path.home() / 'AppData' / 'Roaming' / 'Stand' / 'Lua Scripts' / 'Session_Sniffer-plugin' / 'log.txt'
CHERAX__PLUGIN__LOG_PATH = get_documents_dir() / 'Cherax' / 'Lua' / 'Session_Sniffer-plugin' / 'log.txt'
LEXIS__PLUGIN__LOG_PATH = Path.home() / 'Lexis' / 'Grand Theft Auto V' / 'scripts' / 'Session_Sniffer-plugin' / 'log.txt'

TWO_TAKE_ONE__PLUGIN__HOST_PATH = TWO_TAKE_ONE__PLUGIN__LOG_PATH.with_name('session_host.txt')
STAND__PLUGIN__HOST_PATH = STAND__PLUGIN__LOG_PATH.with_name('session_host.txt')
CHERAX__PLUGIN__HOST_PATH = CHERAX__PLUGIN__LOG_PATH.with_name('session_host.txt')
LEXIS__PLUGIN__HOST_PATH = LEXIS__PLUGIN__LOG_PATH.with_name('session_host.txt')

LOGS_PATHS = (
    STAND__PLUGIN__LOG_PATH,
    CHERAX__PLUGIN__LOG_PATH,
    TWO_TAKE_ONE__PLUGIN__LOG_PATH,
    LEXIS__PLUGIN__LOG_PATH,
)

SESSION_HOST_PATHS: tuple[tuple[str, Path], ...] = (
    ('Stand', STAND__PLUGIN__HOST_PATH),
    ('Cherax', CHERAX__PLUGIN__HOST_PATH),
    ('2Take1', TWO_TAKE_ONE__PLUGIN__HOST_PATH),
    ('Lexis', LEXIS__PLUGIN__HOST_PATH),
)


@dataclass(frozen=True, slots=True)
class ModMenuSessionHostEntry:
    """Resolved session host entry reported by a mod menu Lua plugin."""

    menu_name: str
    username: str
    ip: str


class ModMenuLogsParser:
    """Thread-safe parser to extract and track IP-to-username mappings and session host state from mod menu logs."""

    _lock: ClassVar[Lock] = Lock()
    _last_mod_times: ClassVar[FileModTimes] = {}
    _last_host_mod_times: ClassVar[FileModTimes] = {}
    _ip_to_usernames_map: ClassVar[dict[str, list[str]]] = {}
    _host_ip_to_usernames_map: ClassVar[UsernamesByIP] = defaultdict(list)
    _session_host_entry: ClassVar[ModMenuSessionHostEntry | None] = None
    _active_host_menu_name: ClassVar[str | None] = None

    @staticmethod
    def _snapshot_file_mod_times() -> FileModTimes:
        """Return current file signatures of all existing log files."""
        return {path: sig for path in LOGS_PATHS if path.is_file() and (sig := get_file_signature(path)) is not None}

    @staticmethod
    def _snapshot_host_file_mod_times() -> FileModTimes:
        """Return current file signatures of all existing session host files."""
        return {path: sig for _, path in SESSION_HOST_PATHS if path.is_file() and (sig := get_file_signature(path)) is not None}

    @staticmethod
    def _parse_session_host_files(host_mod_times: FileModTimes) -> tuple[str | None, ModMenuSessionHostEntry | None, set[Path]]:
        """Parse the most recently modified session_host.txt file."""
        if not host_mod_times:
            return None, None, set()

        menu_by_path = {path: menu_name for menu_name, path in SESSION_HOST_PATHS}
        newest_path = max(host_mod_times.items(), key=itemgetter(1))[0]
        newest_menu_name = menu_by_path.get(newest_path)
        failed_paths: set[Path] = set()

        if not newest_path.is_file():
            failed_paths.add(newest_path)
            return newest_menu_name, None, failed_paths

        matched_entry: ModMenuSessionHostEntry | None = None
        try:
            with newest_path.open(encoding='utf-8') as file:
                for line in file:
                    match = RE_MODMENU_LOGS_USER_PATTERN.fullmatch(line.rstrip())
                    if not match:
                        continue

                    username, ip = match.group('username', 'ip')
                    if not isinstance(username, str):
                        raise TypeError(format_type_error(username, str))
                    if not isinstance(ip, str):
                        raise TypeError(format_type_error(ip, str))

                    matched_entry = ModMenuSessionHostEntry(
                        menu_name=menu_by_path[newest_path],
                        username=username,
                        ip=ip,
                    )
        except (OSError, UnicodeDecodeError) as e:
            logger.debug('Failed to read mod menu session host file "%s": %s', newest_path, e)
            failed_paths.add(newest_path)
        else:
            return newest_menu_name, matched_entry, failed_paths

        return newest_menu_name, None, failed_paths

    @classmethod
    def refresh(cls) -> None:
        """Re-parse logs and session host files only if any file changed."""
        current_mod_times = cls._snapshot_file_mod_times()
        current_host_mod_times = cls._snapshot_host_file_mod_times()

        # Step 1: skip parsing if nothing changed
        with cls._lock:
            logs_changed = current_mod_times != cls._last_mod_times
            host_changed = current_host_mod_times != cls._last_host_mod_times
            if not logs_changed and not host_changed:
                return  # nothing changed

            if logs_changed and cls._last_mod_times:  # skip logging on first run
                logger.debug('Detected changes in log files, re-parsing...')

        active_host_menu_name: str | None = None
        parsed_host_entry: ModMenuSessionHostEntry | None = None
        failed_host_paths: set[Path] = set()
        if host_changed:
            active_host_menu_name, parsed_host_entry, failed_host_paths = cls._parse_session_host_files(current_host_mod_times)

        # Step 2: parse logs into a temporary map outside the lock when logs changed
        frozen_map: dict[str, list[str]] | None = None
        failed_log_paths: set[Path] = set()
        if logs_changed:
            temp_map: UsernamesByIP = defaultdict(list)

            for path in LOGS_PATHS:
                if not path.is_file():
                    if path in current_mod_times:
                        failed_log_paths.add(path)
                    continue

                # Parse file line by line
                try:
                    with path.open(encoding='utf-8') as file:
                        for line in file:
                            match = RE_MODMENU_LOGS_USER_PATTERN.fullmatch(line.rstrip())
                            if not match:
                                continue

                            username, ip = match.group('username', 'ip')
                            if not isinstance(username, str):
                                raise TypeError(format_type_error(username, str))
                            if not isinstance(ip, str):
                                raise TypeError(format_type_error(ip, str))

                            # Preserve order and avoid duplicates
                            if username not in temp_map[ip]:
                                temp_map[ip].append(username)
                except (OSError, UnicodeDecodeError) as e:
                    logger.debug('Failed to read mod menu log file "%s": %s', path, e)
                    failed_log_paths.add(path)

            frozen_map = dict(temp_map)

        # Step 3: atomically update class variables under the lock
        with cls._lock:
            if host_changed:
                if not failed_host_paths:
                    cls._active_host_menu_name = active_host_menu_name
                    cls._session_host_entry = parsed_host_entry
                cls._last_host_mod_times = {p: (-1, -1, -1, -1) if p in failed_host_paths else sig for p, sig in current_host_mod_times.items()}
                if parsed_host_entry is not None and parsed_host_entry.username not in cls._host_ip_to_usernames_map[parsed_host_entry.ip]:
                    cls._host_ip_to_usernames_map[parsed_host_entry.ip].append(parsed_host_entry.username)
            if frozen_map is not None:
                if failed_log_paths and cls._ip_to_usernames_map:
                    for prev_ip, prev_users in cls._ip_to_usernames_map.items():
                        merged_users = frozen_map.setdefault(prev_ip, [])
                        for u in prev_users:
                            if u not in merged_users:
                                merged_users.append(u)
                cls._ip_to_usernames_map = frozen_map
                cls._last_mod_times = {p: (-1, -1, -1, -1) if p in failed_log_paths else sig for p, sig in current_mod_times.items()}
            if cls._host_ip_to_usernames_map:
                merged_map: dict[str, list[str]] | None = None
                for host_ip, host_usernames in cls._host_ip_to_usernames_map.items():
                    existing_usernames = (merged_map or cls._ip_to_usernames_map).get(host_ip)
                    if existing_usernames is None:
                        if merged_map is None:
                            merged_map = dict(cls._ip_to_usernames_map)
                        merged_map[host_ip] = list(host_usernames)
                    else:
                        missing = [u for u in host_usernames if u not in existing_usernames]
                        if missing:
                            if merged_map is None:
                                merged_map = dict(cls._ip_to_usernames_map)
                            merged_map[host_ip] = [*existing_usernames, *missing]
                if merged_map is not None:
                    cls._ip_to_usernames_map = merged_map

    @classmethod
    def get_all_ip_to_usernames_map(cls) -> dict[str, list[str]]:
        """Snapshot mapping of all IPs to lists of usernames."""
        return cls._ip_to_usernames_map

    @classmethod
    def get_session_host_entry(cls) -> ModMenuSessionHostEntry | None:
        """Return the current session host entry parsed from mod menu Lua files, if any."""
        return cls._session_host_entry

    @classmethod
    def get_active_host_menu_name(cls) -> str | None:
        """Return the name of the mod menu whose session_host.txt file is most recently active, if any."""
        return cls._active_host_menu_name
