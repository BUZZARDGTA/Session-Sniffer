"""UserIP database backup management and automated backup scheduling."""

import logging
import threading
import time
import zipfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from session_sniffer.background.events import gui_closed__event
from session_sniffer.constants.local import USERIP_DATABASES_BACKUP_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_backup_lock = threading.RLock()

BACKUP_INTERVALS_SECONDS: dict[str, int] = {
    'Every 6 Hours': 6 * 3600,
    'Daily': 24 * 3600,
    'Weekly': 7 * 24 * 3600,
}


def prune_old_backups() -> None:
    """Retain only the most recent backup archives in the backup directory based on retention settings."""
    with _backup_lock:
        if not USERIP_DATABASES_BACKUP_DIR_PATH.is_dir():
            return

        # Clean up stale .tmp files
        for temporary_file in USERIP_DATABASES_BACKUP_DIR_PATH.glob('UserIP_Databases_*.tmp'):
            try:
                temporary_file.unlink()
            except OSError as e:
                logger.warning('Failed to remove stale UserIP backup temporary file %s: %s', temporary_file.name, e)

        limit = Settings.userip_backup_retention_limit
        if limit <= 0:
            return

        existing_backups = sorted(
            USERIP_DATABASES_BACKUP_DIR_PATH.glob('UserIP_Databases_*.zip'),
            key=lambda path: path.stat().st_mtime,
        )
        if len(existing_backups) > limit:
            backups_to_delete = existing_backups[:-limit]
            for old_backup in backups_to_delete:
                try:
                    old_backup.unlink()
                    logger.info('Pruned old UserIP backup: %s', old_backup.name)
                except OSError as e:
                    logger.warning('Failed to delete old UserIP backup %s: %s', old_backup.name, e)


def _has_database_changes_since(latest_backup: Path, json_files: list[Path]) -> bool:
    """Return `True` if any database file was modified or if the file set differs from the archive."""
    latest_backup_mtime = latest_backup.stat().st_mtime
    if any(json_path.stat().st_mtime > latest_backup_mtime for json_path in json_files):
        return True

    try:
        with zipfile.ZipFile(latest_backup, 'r') as archive:
            archived_names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return True

    current_relative_paths = {str(json_path.relative_to(USERIP_DATABASES_DIR_PATH)).replace('\\', '/') for json_path in json_files}
    return archived_names != current_relative_paths


def is_backup_due(json_files: list[Path]) -> bool:
    """Check whether a scheduled backup is due based on `Settings.userip_backup_frequency`."""
    frequency = Settings.userip_backup_frequency
    interval_seconds = BACKUP_INTERVALS_SECONDS.get(frequency)
    if interval_seconds is None:
        if frequency != 'Disabled':
            logger.warning('Unknown UserIP backup frequency: %r', frequency)
        return False

    if not USERIP_DATABASES_BACKUP_DIR_PATH.is_dir():
        return True

    existing_backups = sorted(
        USERIP_DATABASES_BACKUP_DIR_PATH.glob('UserIP_Databases_*.zip'),
        key=lambda path: path.stat().st_mtime,
    )
    if not existing_backups:
        return True

    latest_backup = existing_backups[-1]
    if time.time() - latest_backup.stat().st_mtime < interval_seconds:
        return False

    if _has_database_changes_since(latest_backup, json_files):
        return True

    logger.debug('Skipping scheduled UserIP backup: no database changes detected since last backup.')
    return False


def backup_userip_databases(*, force: bool = False) -> Path | None:
    """Create a ZIP archive backup of all UserIP databases in the backup directory.

    Args:
        force: If True, bypass elapsed interval and change detection checks.

    Returns:
        The Path to the created backup ZIP archive, or None if no backup was performed.
    """
    if gui_closed__event.is_set():
        return None

    with _backup_lock:
        if not USERIP_DATABASES_DIR_PATH.is_dir():
            return None

        prune_old_backups()

        json_files = sorted(USERIP_DATABASES_DIR_PATH.rglob('*.json'))
        if not json_files:
            logger.debug('No UserIP database files found to back up.')
            return None

        USERIP_DATABASES_BACKUP_DIR_PATH.mkdir(parents=True, exist_ok=True)

        if not force and not is_backup_due(json_files):
            return None

        now = datetime.now(tz=UTC)
        timestamp = now.strftime('%Y-%m-%d_%H-%M-%S')
        backup_filename = f'UserIP_Databases_{timestamp}.zip'
        backup_path = USERIP_DATABASES_BACKUP_DIR_PATH / backup_filename
        temporary_backup_path = backup_path.with_suffix('.tmp')

        try:
            with zipfile.ZipFile(temporary_backup_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for json_path in json_files:
                    arcname = json_path.relative_to(USERIP_DATABASES_DIR_PATH)
                    archive.write(str(json_path), str(arcname))
            temporary_backup_path.replace(backup_path)
        except OSError as e:
            try:
                temporary_backup_path.unlink(missing_ok=True)
            except OSError as unlink_error:
                logger.warning('Failed to remove temporary UserIP backup file %s: %s', temporary_backup_path.name, unlink_error)
            logger.warning('Failed to create UserIP database backup: %s', e)
            return None

        count = len(json_files)
        logger.info('Created UserIP database backup at "%s" containing %s database%s.', backup_path.name, count, pluralize(count))
        prune_old_backups()
        return backup_path


def run_userip_backup_async() -> None:
    """Execute `backup_userip_databases` asynchronously in a background thread."""
    if gui_closed__event.is_set():
        return

    thread = threading.Thread(
        target=backup_userip_databases,
        name='userip_backup',
        daemon=True,
    )
    thread.start()
