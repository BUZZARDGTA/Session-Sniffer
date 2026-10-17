"""UserIP database loading, file monitoring, and default file initialization."""

import json
import logging
import time
from threading import Lock
from typing import TYPE_CHECKING, cast

from PySide6.QtGui import QColor

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.models.userip_settings_model import (
    DEFAULT_USERIP_FILES_SETTINGS,
    UserIPDatabaseFile,
    UserIPEntryModel,
    UserIPSettingsModel,
    pick_earliest_iso,
    pick_latest_iso,
)
from session_sniffer.networking.ip_range import entry_ip_covers_ip, is_valid_ip_range_entry
from session_sniffer.player.userip import ProtectionSettings, UserIPDatabases, UserIPSettings
from session_sniffer.text_utils import split_usernames
from session_sniffer.utils import custom_str_to_bool, validate_file
from session_sniffer.utils_exceptions import InvalidBooleanValueError

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path
    from typing import Any

    from session_sniffer.player.userip import UserIP

logger = logging.getLogger(__name__)

_update_userip_databases_lock = Lock()
_last_userip_db_mod_times: dict[Path, float] = {}

DEFAULT_USERIP_FILES_SETTINGS_BY_PATH: dict[Path, UserIPSettingsModel] = {
    USERIP_DATABASES_DIR_PATH / json_name: settings for json_name, settings in DEFAULT_USERIP_FILES_SETTINGS.items()
}


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
    if not metadata_clean:
        need_rewrite = True

    for split_name in split_names:
        if was_split:
            logger.info('Auto-repaired split username entry "%s=%s" in "%s".', split_name, ip, json_name)
        candidate = base_entry if split_name == base_entry.username else base_entry.model_copy(update={'username': split_name})
        pair_key = (split_name, ip)
        if pair_key in seen_pairs:
            need_rewrite = True
            existing_idx = seen_pairs[pair_key]
            repaired_entries[existing_idx] = repaired_entries[existing_idx].merge_duplicate(candidate, sum_detections=False)
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


def _snapshot_db_mod_times() -> dict[Path, float]:
    """Return a fresh `{path: mtime}` snapshot for every `.json` file under the databases directory."""
    if not USERIP_DATABASES_DIR_PATH.exists():
        return {}
    return {path: path.stat().st_mtime for path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if path.is_file()}


def _collect_userip_json_files() -> tuple[list[Path], dict[Path, float]]:
    if not USERIP_DATABASES_DIR_PATH.exists():
        return [], {}
    files: list[Path] = []
    mod_times: dict[Path, float] = {}
    for path in USERIP_DATABASES_DIR_PATH.rglob('*.json'):
        if not path.is_file():
            continue
        files.append(path)
        mod_times[path] = path.stat().st_mtime
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


_userip_file_append_lock: Lock = Lock()


def _parse_existing_entry_dict(item_dict: dict[str, Any], entry_user: str, entry_ip: str) -> UserIPEntryModel:
    """Construct a `UserIPEntryModel` from a raw dictionary while preserving all metadata."""
    is_looky = bool(item_dict.get('is_looky', False))
    notes = str(item_dict.get('notes', '')).strip()
    entry, _ = UserIPEntryModel.from_raw_entry_dict(item_dict, username=entry_user, ip=entry_ip, is_looky=is_looky, notes=notes)
    return entry


def append_userip_entry_if_missing(db_path: Path, username: str, ip: str) -> bool:
    """Append a `{username, ip}` entry to the UserIP `.json` database file if not already covered.

    Returns:
        `True` if the entry was added; `False` if already present or invalid.
    """
    cleaned_username = username.strip()
    cleaned_ip = ip.strip()
    if not cleaned_username or not cleaned_ip or not db_path.is_file():
        return False

    with _userip_file_append_lock:
        try:
            raw_data: object = json.loads(db_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning('Failed to read UserIP database "%s" for auto-feed: %s', db_path, e)
            return False

        if not isinstance(raw_data, dict):
            return False

        typed_data = cast('dict[str, Any]', raw_data)
        raw_settings_obj: object = typed_data.get('settings')
        raw_settings = cast('dict[str, Any]', raw_settings_obj) if isinstance(raw_settings_obj, dict) else {}
        validated_settings, _ = UserIPSettingsModel.validate_settings(raw_settings)

        raw_entries_obj: object = typed_data.get('entries')
        raw_entries = cast('list[object]', raw_entries_obj) if isinstance(raw_entries_obj, list) else []

        entries: list[UserIPEntryModel] = []
        username_cf = cleaned_username.casefold()
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            item_dict = cast('dict[str, Any]', item)
            entry_user = str(item_dict.get('username', '')).strip()
            entry_ip = str(item_dict.get('ip', '')).strip()
            if not entry_user or not entry_ip:
                continue
            if entry_user.casefold() == username_cf and entry_ip_covers_ip(entry_ip, cleaned_ip):
                return False
            entries.append(_parse_existing_entry_dict(item_dict, entry_user, entry_ip))

        entries.append(
            UserIPEntryModel(
                username=cleaned_username,
                ip=cleaned_ip,
                is_looky=False,
                notes='',
                source='Auto-IP',
            ),
        )
        db_file = UserIPDatabaseFile(settings=validated_settings, entries=entries)

        try:
            db_path.write_text(db_file.serialize_to_json(), encoding='utf-8')
        except OSError as e:
            logger.warning('Failed to write UserIP database "%s" for auto-feed: %s', db_path, e)
            return False

        return True


def record_userip_detection(db_path: Path, ip_address: str, seen_at: datetime) -> UserIP | None:
    """Increment `detections_count` and update `first_seen_at` / `last_seen_at` for entries matching `ip_address`.

    Args:
        db_path: Path to the matched UserIP `.json` database file.
        ip_address: The detected player's IPv4 address.
        seen_at: When the player joined the current session; merged chronologically into the stored timestamps.

    Returns:
        The refreshed `UserIP` snapshot after updating the database, or `None` if unavailable.
    """
    cleaned_ip = ip_address.strip()
    if not cleaned_ip or not db_path.is_file():
        return None

    timestamp = seen_at.isoformat(timespec='seconds')
    modified = False

    with _userip_file_append_lock:
        try:
            raw_data: object = json.loads(db_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning('Failed to read UserIP database "%s" to record detection: %s', db_path, e)
            return None

        if not isinstance(raw_data, dict):
            return None

        typed_data = cast('dict[str, Any]', raw_data)
        raw_settings_obj: object = typed_data.get('settings')
        raw_settings = cast('dict[str, Any]', raw_settings_obj) if isinstance(raw_settings_obj, dict) else {}
        validated_settings, _ = UserIPSettingsModel.validate_settings(raw_settings)

        raw_entries_obj: object = typed_data.get('entries')
        raw_entries = cast('list[object]', raw_entries_obj) if isinstance(raw_entries_obj, list) else []

        entries: list[UserIPEntryModel] = []
        for item in raw_entries:
            if not isinstance(item, dict):
                continue
            item_dict = cast('dict[str, Any]', item)
            entry_user = str(item_dict.get('username', '')).strip()
            entry_ip = str(item_dict.get('ip', '')).strip()
            if not entry_user or not entry_ip:
                continue
            parsed_entry = _parse_existing_entry_dict(item_dict, entry_user, entry_ip)
            if entry_ip_covers_ip(entry_ip, cleaned_ip):
                parsed_entry = parsed_entry.model_copy(
                    update={
                        'detections_count': parsed_entry.detections_count + 1,
                        'first_seen_at': pick_earliest_iso(parsed_entry.first_seen_at, timestamp),
                        'last_seen_at': pick_latest_iso(parsed_entry.last_seen_at, timestamp),
                    },
                )
                modified = True
            entries.append(parsed_entry)

        if modified:
            db_file = UserIPDatabaseFile(settings=validated_settings, entries=entries)
            try:
                db_path.write_text(db_file.serialize_to_json(), encoding='utf-8')
            except OSError as e:
                logger.warning('Failed to write UserIP database "%s" to record detection: %s', db_path, e)
                return None

    if modified:
        update_userip_databases()
    return UserIPDatabases.resolve_userip(cleaned_ip)
