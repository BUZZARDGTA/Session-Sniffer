"""Parse mod menu logs to update the mapping of IPs to usernames."""
import re
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import ClassVar

from modules.error_messages import format_type_error
from modules.logging_setup import get_logger
from modules.utils import get_documents_dir

logger = get_logger(__name__)

IPUserMap = defaultdict[str, set[str]]

RE_MODMENU_LOGS_USER_PATTERN = re.compile(
    r'^user:(?P<username>[\w._-]{1,16}), '
    r'scid:\d{1,9}, '
    r'ip:(?P<ip>(?:\d{1,3}\.){3}\d{1,3}), '
    r'timestamp:\d{10}$',
)

TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / 'AppData' / 'Roaming' / 'PopstarDevs' / '2Take1Menu' / 'scripts' / 'GTA_V_Session_Sniffer-plugin' / 'log.txt'
STAND__PLUGIN__LOG_PATH = Path.home() / 'AppData' / 'Roaming' / 'Stand' / 'Lua Scripts' / 'GTA_V_Session_Sniffer-plugin' / 'log.txt'
CHERAX__PLUGIN__LOG_PATH = get_documents_dir() / 'Cherax' / 'Lua' / 'GTA_V_Session_Sniffer-plugin' / 'log.txt'

LOGS_PATHS = (
    STAND__PLUGIN__LOG_PATH,
    CHERAX__PLUGIN__LOG_PATH,
    TWO_TAKE_ONE__PLUGIN__LOG_PATH,
)


class ModMenuLogsParser:
    """Thread-safe parser to extract and track IP-to-username mappings from mod menu logs."""

    _lock: ClassVar = Lock()
    _last_known_log_files_mod_times: ClassVar[dict[Path, float]] = {}
    _ip_to_usernames_map: ClassVar[IPUserMap] = defaultdict(set)

    @classmethod
    def _snapshot_and_parse_logs(cls) -> tuple[dict[Path, float], IPUserMap]:
        """Take a snapshot of all log file modification times and parse them."""
        ip_to_usernames_map: IPUserMap = defaultdict(set)
        current_mod_times: dict[Path, float] = {}

        for path in LOGS_PATHS:
            if not path.is_file():
                continue

            # Capture modification time
            current_mod_times[path] = path.stat().st_mtime

            # Parse file line by line
            with path.open(encoding='utf-8') as f:
                for line in f:
                    match = RE_MODMENU_LOGS_USER_PATTERN.fullmatch(line.rstrip())
                    if not match:
                        continue

                    username, ip = match.group('username', 'ip')
                    if not isinstance(username, str):
                        raise TypeError(format_type_error(username, str))
                    if not isinstance(ip, str):
                        raise TypeError(format_type_error(ip, str))

                    ip_to_usernames_map[match['ip']].add(match['username'])

        return current_mod_times, ip_to_usernames_map

    @classmethod
    def _has_log_files_changed(cls, current_log_files_mod_times: dict[Path, float]) -> bool:
        return current_log_files_mod_times != cls._last_known_log_files_mod_times

    @classmethod
    def refresh(cls) -> None:
        """Re-parse all logs if any file was added, removed, or modified."""
        # Step 1: snapshot and parse logs outside the lock
        current_mod_times, ip_to_usernames_map = cls._snapshot_and_parse_logs()

        # Step 2: acquire lock once to update shared state
        with cls._lock:
            if cls._has_log_files_changed(current_mod_times):
                if cls._last_known_log_files_mod_times:  # skip logging on first run
                    logger.info('Detected changes in log files, re-parsing...')
                cls._ip_to_usernames_map = ip_to_usernames_map
                cls._last_known_log_files_mod_times = current_mod_times

    @classmethod
    def has_ip(cls, ip: str) -> bool:
        """Thread-safe check if the given IP exists in any parsed log."""
        with cls._lock:
            return ip in cls._ip_to_usernames_map

    @classmethod
    def get_usernames_by_ip(cls, ip: str) -> list[str]:
        """Thread-safe retrieval of usernames associated with the given IP."""
        with cls._lock:
            return list(cls._ip_to_usernames_map.get(ip, set()))
