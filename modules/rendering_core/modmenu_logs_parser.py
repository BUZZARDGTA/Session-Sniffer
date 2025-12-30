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

FileModTimes = dict[Path, float]
UsernamesByIP = defaultdict[str, list[str]]

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
    _last_mod_times: ClassVar[FileModTimes] = {}
    _ip_to_usernames_map: ClassVar[UsernamesByIP] = defaultdict(list)

    @staticmethod
    def _snapshot_file_mod_times() -> FileModTimes:
        """Return current modification times of all existing log files."""
        return {path: path.stat().st_mtime for path in LOGS_PATHS if path.is_file()}

    @classmethod
    def refresh(cls) -> None:
        """Re-parse logs only if any file changed."""
        current_mod_times = cls._snapshot_file_mod_times()

        # Step 1: skip parsing if nothing changed
        with cls._lock:
            if current_mod_times == cls._last_mod_times:
                return  # nothing changed
            is_first_run = not cls._last_mod_times

        # Step 2: parse logs into a temporary map outside the lock
        temp_map: UsernamesByIP = defaultdict(list)

        for path in LOGS_PATHS:
            if not path.is_file():
                continue

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

                    # Preserve order and avoid duplicates
                    if username not in temp_map[ip]:
                        temp_map[ip].append(username)

        # Step 3: atomically update class variables under the same lock
        with cls._lock:
            cls._ip_to_usernames_map = temp_map
            cls._last_mod_times = current_mod_times

            if not is_first_run:
                logger.info('Detected changes in log files, re-parsing...')

    @classmethod
    def has_ip(cls, ip: str) -> bool:
        """Thread-safe check if the given IP exists in any parsed log."""
        with cls._lock:
            return ip in cls._ip_to_usernames_map

    @classmethod
    def get_usernames_by_ip(cls, ip: str) -> list[str]:
        """Thread-safe retrieval of usernames associated with the given IP."""
        with cls._lock:
            return cls._ip_to_usernames_map[ip].copy()  # return a copy to prevent external modification
