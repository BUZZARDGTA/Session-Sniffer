"""Parse mod menu logs to update the mapping of IPs to usernames."""
import re
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import ClassVar

from modules.logging_setup import get_logger
from modules.utils import format_type_error, get_documents_dir

logger = get_logger(__name__)

RE_MODMENU_LOGS_USER_PATTERN = re.compile(r'^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$')
TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / 'AppData' / 'Roaming' / 'PopstarDevs' / '2Take1Menu' / 'scripts' / 'GTA_V_Session_Sniffer-plugin' / 'log.txt'
STAND__PLUGIN__LOG_PATH = Path.home() / 'AppData' / 'Roaming' / 'Stand' / 'Lua Scripts' / 'GTA_V_Session_Sniffer-plugin' / 'log.txt'
CHERAX__PLUGIN__LOG_PATH = get_documents_dir() / 'Cherax' / 'Lua' / 'GTA_V_Session_Sniffer-plugin' / 'log.txt'

LOGS_PATHS = (
    STAND__PLUGIN__LOG_PATH,
    CHERAX__PLUGIN__LOG_PATH,
    TWO_TAKE_ONE__PLUGIN__LOG_PATH,
)


def _snapshot_file_mod_times() -> dict[Path, float]:
    """Return current modification times of all existing log files."""
    return {
        path.resolve(): path.stat().st_mtime
        for path in LOGS_PATHS
        if path.is_file()
    }


def _parse_log_file(log_path: Path) -> defaultdict[str, list[str]]:
    """Read and parse a single log file and return IP-to-usernames mapping."""
    ip_usernames: defaultdict[str, list[str]] = defaultdict(list)

    for line in log_path.read_text(encoding='utf-8').splitlines():
        match = RE_MODMENU_LOGS_USER_PATTERN.fullmatch(line)
        if not match:
            continue

        username = match.group('username')
        ip = match.group('ip')

        if username is None or ip is None:
            continue
        if not isinstance(username, str):
            raise TypeError(format_type_error(username, str))
        if not isinstance(ip, str):
            raise TypeError(format_type_error(ip, str))

        if username not in ip_usernames[ip]:
            ip_usernames[ip].append(username)

    return ip_usernames


class ModMenuLogsParser:
    """Thread-safe parser to extract and track IP-to-username mappings from mod menu logs."""

    _lock: ClassVar = Lock()
    _last_known_log_files_mod_times: ClassVar[dict[Path, float]] = {}
    _ip_to_usernames_map: ClassVar[defaultdict[str, list[str]]] = defaultdict(list)

    @classmethod
    def _has_log_files_changed(cls, current_log_files_mod_times: dict[Path, float]) -> bool:
        """Determine if any file was added, removed, or modified."""
        return current_log_files_mod_times != cls._last_known_log_files_mod_times

    @classmethod
    def refresh(cls) -> None:
        """If any file changed or was deleted, re-parse all logs."""
        with cls._lock:
            current_log_files_mod_times = _snapshot_file_mod_times()

            if not cls._has_log_files_changed(current_log_files_mod_times):
                return  # No changes

            # Only print the message if this isn't the initial run
            if cls._last_known_log_files_mod_times:
                logger.info('Detected changes in log files, re-parsing...')

            # Full reparse since something changed
            ip_to_usernames_map: defaultdict[str, list[str]] = defaultdict(list)
            for path in current_log_files_mod_times:
                log_data = _parse_log_file(path)
                for ip, usernames in log_data.items():
                    for username in usernames:
                        ip_to_usernames_map[ip].append(username)

            cls._ip_to_usernames_map = ip_to_usernames_map
            cls._last_known_log_files_mod_times = current_log_files_mod_times

    @classmethod
    def has_ip(cls, ip: str) -> bool:
        """Thread-safe check if the given IP exists in any parsed log."""
        with cls._lock:
            return ip in cls._ip_to_usernames_map

    @classmethod
    def get_usernames_by_ip(cls, ip: str) -> list[str]:
        """Thread-safe retrieval of usernames associated with a given IP."""
        with cls._lock:
            return cls._ip_to_usernames_map.get(ip, []).copy()
