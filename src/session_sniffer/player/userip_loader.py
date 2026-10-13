"""UserIP databases discovery, default file initialization, parsing, and mod-time tracking."""

import logging
import time
from threading import Lock
from typing import TYPE_CHECKING

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import GITHUB_WIKI_USERIP_CONFIG_URL, TITLE
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.userip_ini_parser import RE_USERIP_INI_PARSER_PATTERN, parse_userip_ini_file
from session_sniffer.text_templates import (
    DEFAULT_USERIP_FILES_SETTINGS_INI,
    USERIP_DEFAULT_DB_FOOTER_TEMPLATE,
    USERIP_DEFAULT_DB_HEADER_TEMPLATE,
)
from session_sniffer.text_utils import format_triple_quoted_text, split_usernames

if TYPE_CHECKING:
    from pathlib import Path

    from session_sniffer.player.userip import UserIPSettings

logger = logging.getLogger(__name__)

_DEFAULT_USERIP_FILE_HEADER = format_triple_quoted_text(
    USERIP_DEFAULT_DB_HEADER_TEMPLATE.format(
        title=TITLE,
        configuration_guide_url=GITHUB_WIKI_USERIP_CONFIG_URL,
    ),
)

_DEFAULT_USERIP_FILES_SETTINGS = {
    USERIP_DATABASES_DIR_PATH / ini_name: settings for ini_name, settings in DEFAULT_USERIP_FILES_SETTINGS_INI.items()
}

_DEFAULT_USERIP_FILE_FOOTER = format_triple_quoted_text(
    USERIP_DEFAULT_DB_FOOTER_TEMPLATE,
    add_trailing_newline=True,
)

_update_lock: Lock = Lock()
_last_known_userip_db_mod_times: dict[Path, float] = {}


def _snapshot_userip_database_mod_times() -> dict[Path, float]:
    """Return current modification times of all existing UserIP database INIs."""
    return {path: path.stat().st_mtime for path in USERIP_DATABASES_DIR_PATH.rglob('*.ini') if path.is_file()}


def _collect_userip_ini_files() -> tuple[list[Path], dict[Path, float]]:
    """Return discovered INI paths and their mod-times in a single `rglob` pass."""
    files: list[Path] = []
    mod_times: dict[Path, float] = {}

    for path in USERIP_DATABASES_DIR_PATH.rglob('*.ini'):
        if path.is_file():
            files.append(path)
            mod_times[path] = path.stat().st_mtime

    return files, mod_times


def _ensure_default_userip_files() -> None:
    """Ensure the UserIP databases directory and default INI files exist."""
    USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)

    for userip_path, settings in _DEFAULT_USERIP_FILES_SETTINGS.items():
        if not userip_path.is_file():
            file_content = f'{_DEFAULT_USERIP_FILE_HEADER}\n\n{settings}\n\n{_DEFAULT_USERIP_FILE_FOOTER}'
            userip_path.write_text(file_content, encoding='utf-8')


def update_userip_databases() -> tuple[float, bool]:
    """Check for changes in UserIP database files, re-parsing and rebuilding when modified.

    Returns:
        A tuple of (current monotonic timestamp, whether databases were rebuilt).
    """
    with _update_lock:
        _ensure_default_userip_files()

        current_ini_files, current_userip_db_mod_times = _collect_userip_ini_files()
        if current_userip_db_mod_times == _last_known_userip_db_mod_times:
            return time.monotonic(), False

        if _last_known_userip_db_mod_times:
            logger.debug('Detected changes in UserIP databases, re-parsing...')

        new_databases: list[tuple[Path, UserIPSettings, dict[str, list[str]]]] = []

        for userip_path in current_ini_files:
            parsed_settings, parsed_data = parse_userip_ini_file(userip_path)
            if parsed_settings is None or parsed_data is None:
                continue
            new_databases.append((userip_path, parsed_settings, parsed_data))

        UserIPDatabases.populate(new_databases)
        UserIPDatabases.build()

        # INI parsing may have rewritten files; re-snapshot so we don't immediately re-parse next tick.
        _last_known_userip_db_mod_times.clear()
        _last_known_userip_db_mod_times.update(_snapshot_userip_database_mod_times())

        return time.monotonic(), True


_userip_file_append_lock: Lock = Lock()


def append_userip_entry_if_missing(db_path: Path, username: str, ip: str) -> bool:
    """Append a `{username}={ip}` entry to the UserIP database file if not already present.

    Ensures CRLF line endings and proper section placement.

    Returns:
        True if the entry was added; False if already present or invalid.
    """
    cleaned_username = username.strip()
    cleaned_ip = ip.strip()
    if not cleaned_username or not cleaned_ip or not db_path.is_file():
        return False

    with _userip_file_append_lock:
        content = db_path.read_text(encoding='utf-8', newline='')

        for line in content.splitlines():
            match = RE_USERIP_INI_PARSER_PATTERN.search(line.strip())
            if match:
                entry_usernames = split_usernames(match.group('username'))
                entry_ip = match.group('ip').strip()
                if any(u.casefold() == cleaned_username.casefold() for u in entry_usernames) and entry_ip == cleaned_ip:
                    return False

        lines = content.splitlines()
        userip_section_index = -1
        next_section_index = -1
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if stripped_line.casefold() == '[userip]':
                userip_section_index = i
            elif userip_section_index != -1 and stripped_line.startswith('[') and stripped_line.endswith(']'):
                next_section_index = i
                break

        new_entry = f'{cleaned_username}={cleaned_ip}'
        if userip_section_index == -1:
            lines.extend(['', '[UserIP]', new_entry])
        elif next_section_index != -1:
            lines.insert(next_section_index, new_entry)
        else:
            lines.append(new_entry)

        new_content = '\r\n'.join(lines).strip('\r\n') + '\r\n'
        db_path.write_text(new_content, encoding='utf-8', newline='')
        return True
