"""UserIP database loading, file monitoring, and default file initialization."""

import contextlib
import hashlib
import json
import logging
import time
from contextlib import contextmanager
from threading import RLock
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
from session_sniffer.player.userip_groups import get_groups_state_token, remove_usernames_from_groups, rename_username_in_groups
from session_sniffer.player.userip_log_history import enrich_userip_entry_from_logs, warm_userip_log_history_cache_async
from session_sniffer.utils import FileSignature, atomic_write_text, get_file_signature, validate_file

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from datetime import datetime
    from pathlib import Path
    from typing import Any

    from session_sniffer.player.userip import UserIP

logger = logging.getLogger(__name__)

_update_userip_databases_lock = RLock()
_last_userip_db_mod_times: dict[Path, FileSignature] = {}
_last_in_app_db_digests: dict[Path, bytes] = {}
_last_userip_groups_token: list[tuple[int, FileSignature | None]] = []
_parsed_userip_databases: dict[Path, tuple[UserIPSettings, list[UserIPEntryModel]]] = {}
_parsed_userip_settings_models: dict[Path, UserIPSettingsModel] = {}
_pending_in_app_prev_entries: dict[Path, list[UserIPEntryModel] | None] = {}
_in_app_rebuild_pending: list[bool] = [False]

DEFAULT_USERIP_FILES_SETTINGS_BY_PATH: dict[Path, UserIPSettingsModel] = {
    USERIP_DATABASES_DIR_PATH / json_name: settings for json_name, settings in DEFAULT_USERIP_FILES_SETTINGS.items()
}


def _to_runtime_settings(validated_settings: UserIPSettingsModel) -> UserIPSettings:
    """Convert a persisted `UserIPSettingsModel` into a runtime `UserIPSettings` tuple."""
    return UserIPSettings(
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


def _compute_db_digest(content: str | bytes) -> bytes:
    """Return a 16-byte BLAKE2b digest for UserIP database *content* normalized across line endings."""
    raw_bytes = content.encode('utf-8') if isinstance(content, str) else content
    return hashlib.blake2b(raw_bytes.replace(b'\r\n', b'\n'), digest_size=16).digest()


def _normalize_db_key(db_path: Path) -> Path:
    """Normalize *db_path* under `USERIP_DATABASES_DIR_PATH` when it resolves inside that root."""
    with contextlib.suppress(OSError, ValueError):
        resolved_root = USERIP_DATABASES_DIR_PATH.resolve()
        resolved_path = db_path.resolve()
        if resolved_path.is_relative_to(resolved_root):
            return USERIP_DATABASES_DIR_PATH / resolved_path.relative_to(resolved_root)
    return db_path


def _record_in_app_db_write(db_path: Path, content: str | bytes | None = None) -> None:
    """Record the payload digest of an in-app write to *db_path* (caller must hold `_update_userip_databases_lock`)."""
    key = _normalize_db_key(db_path)
    if content is not None:
        _last_in_app_db_digests[key] = _compute_db_digest(content)
        return
    try:
        raw_bytes = db_path.read_bytes()
    except OSError:
        _last_in_app_db_digests.pop(key, None)
        return
    _last_in_app_db_digests[key] = _compute_db_digest(raw_bytes)


def is_in_app_userip_db_content(db_path: Path, content: str | bytes) -> bool:
    """Return whether *content* matches the last payload written in-app to *db_path*."""
    with _update_userip_databases_lock:
        expected = _last_in_app_db_digests.get(_normalize_db_key(db_path))
    return expected is not None and expected == _compute_db_digest(content)


def rebind_in_app_userip_db_path(old_path: Path, new_path: Path) -> None:
    """Update tracked in-app database state after an in-app file or directory rename/move."""
    old_key = _normalize_db_key(old_path)
    with _update_userip_databases_lock:
        for tracked_path in [path for path in _last_userip_db_mod_times if path == old_key or old_key in path.parents]:
            _last_userip_db_mod_times.pop(tracked_path, None)
            _parsed_userip_databases.pop(tracked_path, None)
            _parsed_userip_settings_models.pop(tracked_path, None)
            _pending_in_app_prev_entries.pop(tracked_path, None)
        for tracked_key in [path for path in _last_in_app_db_digests if path == old_key or old_key in path.parents]:
            _last_in_app_db_digests.pop(tracked_key, None)
        if new_path.is_file() and new_path.suffix.lower() == '.json':
            _record_in_app_db_write(new_path)
        elif new_path.is_dir():
            for json_file in new_path.rglob('*.json'):
                if json_file.is_file():
                    _record_in_app_db_write(json_file)


def _ensure_default_userip_files() -> None:
    """Ensure the UserIP databases directory and default `.json` files exist."""
    USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
    for json_path, default_settings in DEFAULT_USERIP_FILES_SETTINGS_BY_PATH.items():
        if not json_path.is_file():
            serialized = UserIPDatabaseFile(settings=default_settings, entries=[]).serialize_to_json()
            atomic_write_text(json_path, serialized)
            _record_in_app_db_write(json_path, serialized)


def _parse_and_repair_single_raw_entry(
    raw_entry: object,
    json_name: str,
    repaired_entries: list[UserIPEntryModel],
    seen_pairs: dict[tuple[str, str], int],
) -> tuple[bool, bool]:
    """Validate and repair one raw entry dict from a UserIP `.json` database file.

    Returns:
        A tuple of (whether the entry required a genuine auto-repair,
        whether the entry was updated from log history). Either one means the file should be rewritten.
    """
    parsed = UserIPEntryModel.parse_raw_entry(raw_entry)
    if parsed is None:
        return True, False

    base_entry, entry_clean = parsed
    ip = base_entry.ip
    if not is_valid_ip_range_entry(ip):
        logger.info('Auto-removed invalid IP entry "%s=%s" from "%s".', base_entry.username, ip, json_name)
        return True, False

    base_entry, log_enriched = enrich_userip_entry_from_logs(base_entry)

    pair_key = (base_entry.username.casefold(), ip)
    if pair_key in seen_pairs:
        existing_idx = seen_pairs[pair_key]
        repaired_entries[existing_idx] = repaired_entries[existing_idx].merge_duplicate(base_entry)
        logger.info('Auto-removed duplicate IP entry "%s=%s" from "%s".', base_entry.username, ip, json_name)
        return True, log_enriched

    seen_pairs[pair_key] = len(repaired_entries)
    repaired_entries.append(base_entry)
    return not entry_clean, log_enriched


def parse_userip_json_file(
    json_path: Path,
    *,
    raw_text: str | None = None,
    record_in_app_rewrite: bool = True,
) -> tuple[UserIPSettingsModel | None, UserIPSettings | None, list[UserIPEntryModel] | None]:
    """Parse, validate, and auto-repair a UserIP `.json` database file."""
    if raw_text is None:
        validate_file(json_path)
        raw_text = json_path.read_text(encoding='utf-8')
    try:
        raw_data: object = json.loads(raw_text)
    except json.JSONDecodeError as e:
        logger.warning('Failed to parse UserIP database "%s": %s; skipping file.', json_path.name, e)
        return None, None, None

    if not isinstance(raw_data, dict):
        logger.warning('UserIP database "%s" root is not a JSON object; skipping file.', json_path.name)
        return None, None, None

    typed_data = cast('dict[str, Any]', raw_data)
    # `need_repair` tracks genuine auto-repairs; `need_log_sync` tracks entries only refreshed from log history.
    need_repair = list(typed_data.keys()) != ['settings', 'entries']
    need_log_sync = False

    raw_settings_obj: object = typed_data.get('settings')
    if isinstance(raw_settings_obj, dict):
        raw_settings = cast('dict[str, Any]', raw_settings_obj)
    else:
        need_repair = True
        default_model = DEFAULT_USERIP_FILES_SETTINGS_BY_PATH.get(json_path, UserIPSettingsModel())
        raw_settings = default_model.model_dump()

    validated_settings, settings_rewritten = UserIPSettingsModel.validate_settings(raw_settings)
    if settings_rewritten:
        need_repair = True

    raw_entries_obj: object = typed_data.get('entries')
    if isinstance(raw_entries_obj, list):
        raw_entries = cast('list[object]', raw_entries_obj)
    else:
        need_repair = True
        raw_entries = []

    repaired_entries: list[UserIPEntryModel] = []
    seen_pairs: dict[tuple[str, str], int] = {}

    for raw_entry in raw_entries:
        entry_repaired, entry_log_synced = _parse_and_repair_single_raw_entry(raw_entry, json_path.name, repaired_entries, seen_pairs)
        need_repair = need_repair or entry_repaired
        need_log_sync = need_log_sync or entry_log_synced

    if need_repair or need_log_sync:
        serialized = UserIPDatabaseFile(settings=validated_settings, entries=repaired_entries).serialize_to_json()
        atomic_write_text(json_path, serialized)
        if record_in_app_rewrite:
            _record_in_app_db_write(json_path, serialized)
        if need_repair:
            logger.info('Rewrote "%s" after auto-repairs.', json_path.name)

    return validated_settings, _to_runtime_settings(validated_settings), repaired_entries


@contextmanager
def userip_databases_lock() -> Generator[None]:
    """Serialize multi-step UserIP database read-modify-write operations against background polling."""
    with _update_userip_databases_lock:
        yield


@contextmanager
def userip_database_write(db_path: Path, *, content: str | bytes | None = None) -> Generator[None]:
    """Guard an in-app write to a UserIP database file, invalidate its cached signature, and record its payload."""
    key = _normalize_db_key(db_path)
    with _update_userip_databases_lock:
        try:
            yield
        finally:
            _last_userip_db_mod_times.pop(key, None)
            _last_userip_db_mod_times.pop(db_path, None)
            _parsed_userip_databases.pop(key, None)
            _parsed_userip_databases.pop(db_path, None)
            _parsed_userip_settings_models.pop(key, None)
            _parsed_userip_settings_models.pop(db_path, None)
            _pending_in_app_prev_entries.pop(key, None)
            if db_path.is_file():
                _record_in_app_db_write(key, content)
            else:
                _last_in_app_db_digests.pop(key, None)


def write_userip_database_file(db_path: Path, db_model: UserIPDatabaseFile) -> str:
    """Atomically write *db_model* to *db_path*, updating in-memory UserIP caches in-place without disk re-parsing."""
    serialized = db_model.serialize_to_json()
    key = _normalize_db_key(db_path)
    with _update_userip_databases_lock:
        atomic_write_text(db_path, serialized)
        _record_in_app_db_write(key, serialized)
        new_sig = get_file_signature(key) if key.is_file() else get_file_signature(db_path)
        if (
            new_sig is not None
            and key.is_relative_to(USERIP_DATABASES_DIR_PATH)
            and (_parsed_userip_databases or _last_userip_db_mod_times)
        ):
            if key not in _pending_in_app_prev_entries:
                _pending_in_app_prev_entries[key] = list(_parsed_userip_databases[key][1]) if key in _parsed_userip_databases else None
            _parsed_userip_databases[key] = (_to_runtime_settings(db_model.settings), list(db_model.entries))
            _parsed_userip_settings_models[key] = db_model.settings.model_copy()
            _last_userip_db_mod_times[key] = new_sig
            _in_app_rebuild_pending[0] = True
        else:
            _last_userip_db_mod_times.pop(key, None)
            _last_userip_db_mod_times.pop(db_path, None)
            _parsed_userip_databases.pop(key, None)
            _parsed_userip_settings_models.pop(key, None)
    return serialized


def _snapshot_db_mod_times() -> dict[Path, FileSignature]:
    """Return a fresh `{path: FileSignature}` snapshot for every `.json` file under the databases directory."""
    if not USERIP_DATABASES_DIR_PATH.exists():
        return {}
    return {
        path: sig
        for path in USERIP_DATABASES_DIR_PATH.rglob('*.json')
        if path.is_file() and (sig := get_file_signature(path)) is not None
    }


def _sync_groups_with_db_changes(
    prev_by_db: Mapping[Path, Sequence[UserIPEntryModel]],
    new_databases: Sequence[tuple[Path, UserIPSettings, list[UserIPEntryModel]]],
) -> bool:
    """Propagate username renames and deletions from database changes into `userip_groups.json`."""
    if not prev_by_db:
        return False
    prev_exact = {cleaned for entries in prev_by_db.values() for e in entries if (cleaned := e.username.strip())}
    curr_exact = {cleaned for _, _, entries in new_databases for e in entries if (cleaned := e.username.strip())}
    if prev_exact == curr_exact:
        return False
    prev_cfs = {u.casefold() for u in prev_exact}
    curr_cfs = {u.casefold() for u in curr_exact}
    removed_cfs = prev_cfs - curr_cfs

    changed = False
    for new_u in curr_exact - prev_exact:
        if new_u.casefold() in prev_cfs and rename_username_in_groups(new_u, new_u):
            changed = True
    if not removed_cfs:
        return changed
    for db_path, _, new_entries in new_databases:
        if not (old_entries := prev_by_db.get(db_path, ())):
            continue
        old_cfs_by_ip: dict[str, set[str]] = {}
        for old_e in old_entries:
            if old_u := old_e.username.strip():
                old_cfs_by_ip.setdefault(old_e.ip, set()).add(old_u.casefold())
        unmatched_new = [
            new_e for new_e in new_entries if (new_u := new_e.username.strip()) and new_u.casefold() not in old_cfs_by_ip.get(new_e.ip, set())
        ]
        for old_e in old_entries:
            old_u = old_e.username.strip()
            if not old_u or old_u.casefold() not in removed_cfs:
                continue
            match_e = next(
                (e for e in unmatched_new if e.ip == old_e.ip and e.added_at == old_e.added_at),
                next(
                    (
                        e
                        for e in unmatched_new
                        if e.username.strip().casefold() not in prev_cfs and (e.ip == old_e.ip or (bool(old_e.added_at) and e.added_at == old_e.added_at))
                    ),
                    None,
                ),
            )
            if match_e is not None:
                unmatched_new.remove(match_e)
                changed = rename_username_in_groups(old_u, match_e.username.strip()) or changed
                removed_cfs.discard(old_u.casefold())

    return bool(removed_cfs and remove_usernames_from_groups(removed_cfs)) or changed


def _reparse_changed_userip_db(
    userip_path: Path,
    last_sig: FileSignature | None,
    file_sig: FileSignature,
) -> tuple[UserIPSettingsModel | None, UserIPSettings | None, list[UserIPEntryModel] | None]:
    """Read, classify (in-app vs external), and re-parse a modified UserIP `.json` file."""
    validate_file(userip_path)
    try:
        raw_bytes = userip_path.read_bytes()
    except OSError as e:
        logger.warning('Failed to read UserIP database "%s": %s; skipping file.', userip_path.name, e)
        return None, None, None
    db_key = _normalize_db_key(userip_path)
    was_in_app = _last_in_app_db_digests.get(db_key) == _compute_db_digest(raw_bytes)
    is_external = last_sig is not None and last_sig != file_sig and not was_in_app
    if is_external:
        _last_in_app_db_digests.pop(db_key, None)
        logger.info('Detected external changes to UserIP database "%s"; re-parsed it.', userip_path.name)
    try:
        raw_text = raw_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        logger.warning('Failed to decode UserIP database "%s": %s; skipping file.', userip_path.name, e)
        return None, None, None
    return parse_userip_json_file(userip_path, raw_text=raw_text, record_in_app_rewrite=not is_external)


def _update_userip_databases_locked() -> tuple[float, bool]:
    """Run database change detection and rebuild while `_update_userip_databases_lock` is held."""
    warm_userip_log_history_cache_async()
    _ensure_default_userip_files()

    current_userip_db_mod_times = _snapshot_db_mod_times()
    current_groups_token = get_groups_state_token()
    rebuild_pending = _in_app_rebuild_pending[0]
    if (
        not rebuild_pending
        and current_userip_db_mod_times == _last_userip_db_mod_times
        and _last_userip_groups_token == [current_groups_token]
    ):
        return time.monotonic(), False

    if _last_userip_db_mod_times and not rebuild_pending:
        logger.debug('Detected changes in UserIP databases, re-parsing...')

    prev_by_db = {path: list(entries) for path, (_, entries) in _parsed_userip_databases.items()}
    for pending_path, pending_entries in _pending_in_app_prev_entries.items():
        if pending_entries is None:
            prev_by_db.pop(pending_path, None)
        else:
            prev_by_db[pending_path] = pending_entries
    _pending_in_app_prev_entries.clear()
    _in_app_rebuild_pending[0] = False

    for removed_path in set(_parsed_userip_databases) - set(current_userip_db_mod_times):
        _parsed_userip_databases.pop(removed_path, None)
        _parsed_userip_settings_models.pop(removed_path, None)
        _last_in_app_db_digests.pop(_normalize_db_key(removed_path), None)

    new_databases: list[tuple[Path, UserIPSettings, list[UserIPEntryModel]]] = []
    parsed_mod_times: dict[Path, FileSignature] = {}
    for userip_path, file_sig in current_userip_db_mod_times.items():
        cached = _parsed_userip_databases.get(userip_path)
        last_sig = _last_userip_db_mod_times.get(userip_path)
        if cached is None or last_sig != file_sig:
            settings_model, parsed_settings, parsed_entries = _reparse_changed_userip_db(userip_path, last_sig, file_sig)
            if settings_model is None or parsed_settings is None or parsed_entries is None:
                _parsed_userip_databases.pop(userip_path, None)
                _parsed_userip_settings_models.pop(userip_path, None)
                prev_by_db.pop(userip_path, None)
                post_parse_sig = get_file_signature(userip_path)
                if post_parse_sig is not None:
                    parsed_mod_times[userip_path] = post_parse_sig
                continue
            cached = (parsed_settings, parsed_entries)
            _parsed_userip_databases[userip_path] = cached
            _parsed_userip_settings_models[userip_path] = settings_model
            # Re-snapshot mod time *after* parsing this file because parse_userip_json_file()
            # may rewrite the file during auto-repair, advancing its mtime beyond file_sig.
            parsed_mod_times[userip_path] = get_file_signature(userip_path) or file_sig
        else:
            parsed_mod_times[userip_path] = file_sig

        new_databases.append((userip_path, *cached))

    if _sync_groups_with_db_changes(prev_by_db, new_databases):
        current_groups_token = get_groups_state_token()

    UserIPDatabases.populate(new_databases)
    UserIPDatabases.build()

    _last_userip_db_mod_times.clear()
    _last_userip_db_mod_times.update(parsed_mod_times)
    _last_userip_groups_token[:] = [current_groups_token]

    return time.monotonic(), True


@contextmanager
def _try_userip_databases_lock(*, blocking: bool) -> Generator[bool]:
    """Acquire `_update_userip_databases_lock` with `blocking`, yielding whether it was acquired."""
    acquired = _update_userip_databases_lock.acquire(blocking=blocking)
    try:
        yield acquired
    finally:
        if acquired:
            _update_userip_databases_lock.release()


def update_userip_databases(*, blocking: bool = True) -> tuple[float, bool]:
    """Check for changes in UserIP database files, re-parsing and rebuilding when modified.

    Returns:
        A tuple of (current monotonic timestamp or `0.0` when skipped non-blocking, whether databases were rebuilt).
    """
    with _try_userip_databases_lock(blocking=blocking) as acquired:
        if not acquired:
            return 0.0, False
        return _update_userip_databases_locked()


def get_cached_userip_usernames() -> list[str]:
    """Return all non-empty usernames currently cached across parsed UserIP databases."""
    with _update_userip_databases_lock:
        if _parsed_userip_databases:
            return [cleaned for _, entries in _parsed_userip_databases.values() for entry in entries if (cleaned := entry.username.strip())]
        return [
            cleaned for db_entry in UserIPDatabases.userip_databases for entry in (*db_entry.single_entries, *db_entry.range_entries) if (cleaned := entry.username.strip())
        ]


def get_cached_userip_databases() -> list[tuple[Path, list[UserIPEntryModel]]]:
    """Return sorted `(database_path, entries)` pairs from cached UserIP databases, refreshing any stale files."""
    with _update_userip_databases_lock:
        update_userip_databases()
        return [(path, list(entries)) for path, (_, entries) in sorted(_parsed_userip_databases.items())]


def get_cached_userip_database_model(db_path: Path) -> UserIPDatabaseFile | None:
    """Return a cached `UserIPDatabaseFile` copy for *db_path* when its on-disk signature is unchanged."""
    key = _normalize_db_key(db_path)
    with _update_userip_databases_lock:
        cached = _parsed_userip_databases.get(key)
        settings_model = _parsed_userip_settings_models.get(key)
        if (
            cached is not None
            and settings_model is not None
            and (sig := get_file_signature(key)) is not None
            and _last_userip_db_mod_times.get(key) == sig
        ):
            return UserIPDatabaseFile(settings=settings_model.model_copy(), entries=list(cached[1]))
    return None


def _load_raw_userip_db(db_path: Path, *, action_label: str) -> tuple[UserIPSettingsModel, list[UserIPEntryModel]] | None:
    """Read and validate the settings and existing entries list from a UserIP database file, preferring in-memory cache."""
    if (cached_model := get_cached_userip_database_model(db_path)) is not None:
        return cached_model.settings, cached_model.entries
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
    entries = [parsed[0] for item in raw_entries if (parsed := UserIPEntryModel.parse_raw_entry(item)) is not None]
    return validated_settings, entries


def _write_userip_db(
    db_path: Path,
    settings: UserIPSettingsModel,
    entries: list[UserIPEntryModel],
    *,
    action_label: str,
    sync_groups: bool = True,
) -> bool:
    """Serialize and write a UserIP database file, updating in-memory caches in-place when available."""
    serialized = UserIPDatabaseFile(settings=settings, entries=entries).serialize_to_json()
    key = _normalize_db_key(db_path)
    try:
        with _update_userip_databases_lock:
            atomic_write_text(db_path, serialized)
            _record_in_app_db_write(key, serialized)
            new_sig = get_file_signature(key) if key.is_file() else get_file_signature(db_path)
            if (
                _parsed_userip_databases
                and new_sig is not None
                and key in _last_userip_db_mod_times
                and _last_userip_db_mod_times.keys() == _parsed_userip_databases.keys()
                and not _in_app_rebuild_pending[0]
            ):
                prev_by_db = {path: list(db_entries) for path, (_, db_entries) in _parsed_userip_databases.items()} if sync_groups else {}
                _parsed_userip_databases[key] = (_to_runtime_settings(settings), list(entries))
                _parsed_userip_settings_models[key] = settings.model_copy()
                _last_userip_db_mod_times[key] = new_sig
                new_databases = [(path, db_settings, db_entries) for path, (db_settings, db_entries) in _parsed_userip_databases.items()]
                if sync_groups and _sync_groups_with_db_changes(prev_by_db, new_databases):
                    _last_userip_groups_token[:] = [get_groups_state_token()]
                UserIPDatabases.populate(new_databases)
                UserIPDatabases.build()
            else:
                _last_userip_db_mod_times.pop(key, None)
                _last_userip_db_mod_times.pop(db_path, None)
                _parsed_userip_databases.pop(key, None)
                _parsed_userip_settings_models.pop(key, None)
    except OSError as e:
        logger.warning('Failed to write UserIP database "%s" for %s: %s', db_path, action_label, e)
        return False
    return True


def find_userip_insert_index(entries: Sequence[UserIPEntryModel], username: str, ip_or_range: str, *, anchor_username: str = '') -> int:
    """Return the index in *entries* immediately after the last matching IP, username, grouped cluster member, or covering range."""
    username_cf, anchor_cf = username.casefold(), anchor_username.casefold()
    cluster_cfs = {member.casefold() for member in UserIPDatabases.get_cluster_for_username(username)}
    if anchor_username:
        cluster_cfs.update(member.casefold() for member in UserIPDatabases.get_cluster_for_username(anchor_username))
    rev_indices = range(len(entries) - 1, -1, -1)
    for match_idx in (
        next((i for i in rev_indices if anchor_cf and entries[i].username.casefold() == anchor_cf and entries[i].ip == ip_or_range), None),
        next((i for i in rev_indices if entries[i].ip == ip_or_range), None),
        next((i for i in rev_indices if entries[i].username.casefold() in {username_cf, anchor_cf} - {''}), None),
        next((i for i in rev_indices if cluster_cfs and entries[i].username.casefold() in cluster_cfs), None),
        next((i for i in rev_indices if entry_ip_covers_ip(entries[i].ip, ip_or_range)), None),
    ):
        if match_idx is not None:
            return match_idx + 1
    return len(entries)


def append_userip_entry_if_missing(db_path: Path, username: str, ip: str, *, is_looky: bool = False) -> bool:
    """Append a `{username, ip}` entry to the UserIP `.json` database file if not already covered."""
    cleaned_username = username.strip()
    cleaned_ip = ip.strip()
    if not cleaned_username or not cleaned_ip or not db_path.is_file():
        return False

    with _update_userip_databases_lock:
        loaded = _load_raw_userip_db(db_path, action_label='auto-feed')
        if loaded is None:
            return False
        validated_settings, entries = loaded
        username_cf = cleaned_username.casefold()
        if any(entry.username.casefold() == username_cf and entry_ip_covers_ip(entry.ip, cleaned_ip) for entry in entries):
            return False
        new_entry, _ = enrich_userip_entry_from_logs(UserIPEntryModel(username=cleaned_username, ip=cleaned_ip, is_looky=is_looky, notes='', source='Auto-IP'))
        entries.insert(find_userip_insert_index(entries, cleaned_username, cleaned_ip), new_entry)
        return _write_userip_db(db_path, validated_settings, entries, action_label='auto-feed')


def _update_matching_userip_entries(
    db_path: Path,
    ip_address: str,
    apply_update: Callable[[UserIPEntryModel], UserIPEntryModel],
) -> UserIP | None:
    """Rewrite every entry in `db_path` whose IP or range covers `ip_address` through `apply_update`."""
    cleaned_ip = ip_address.strip()
    if not cleaned_ip or not db_path.is_file():
        return None

    modified = False
    key = _normalize_db_key(db_path)
    with _update_userip_databases_lock:
        loaded = _load_raw_userip_db(db_path, action_label='player activity')
        if loaded is None:
            return None
        validated_settings, entries = loaded
        for idx, entry in enumerate(entries):
            if entry_ip_covers_ip(entry.ip, cleaned_ip):
                updated_entry = apply_update(entry)
                if updated_entry != entry:
                    entries[idx] = updated_entry
                    modified = True
        if modified and not _write_userip_db(db_path, validated_settings, entries, action_label='player activity', sync_groups=False):
            return None

    if modified and key not in _last_userip_db_mod_times:
        update_userip_databases()
    return UserIPDatabases.resolve_userip(cleaned_ip)


def _apply_detection_to_entry(entry: UserIPEntryModel, timestamp: str) -> UserIPEntryModel:
    """Apply a live player join detection to `entry` while merging historical log statistics."""
    already_counted = entry.detections_count > 0 and entry.last_seen_at is not None and pick_latest_iso(entry.last_seen_at, timestamp) == entry.last_seen_at
    if already_counted and entry.first_seen_at is not None:
        return entry
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
    """Increment `detections_count` and merge `joined_at` into `first_seen_at` / `last_seen_at` for entries matching `ip_address`."""
    timestamp = joined_at.isoformat(timespec='seconds')
    return _update_matching_userip_entries(db_path, ip_address, lambda entry: _apply_detection_to_entry(entry, timestamp))


def record_userip_last_seen(db_path: Path, ip_address: str, last_seen: datetime) -> UserIP | None:
    """Merge the player's last activity time into `last_seen_at` for entries matching `ip_address`."""
    timestamp = last_seen.isoformat(timespec='seconds')
    return _update_matching_userip_entries(
        db_path, ip_address, lambda entry: enrich_userip_entry_from_logs(entry.model_copy(update={'last_seen_at': pick_latest_iso(entry.last_seen_at, timestamp)}))[0],
    )
