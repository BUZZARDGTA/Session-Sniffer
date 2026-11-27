"""Import and export mixin for the UserIP Databases Manager dialog."""

import logging
import lzma
import shutil
import zipfile
import zlib
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QStandardItemModel

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog, QFileDialog, QMessageBox

from session_sniffer.constants.local import USERIP_DATABASES_BACKUP_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._userip_tree_batch_ops import export_json_databases_to_zip, export_selected_tree_paths_as_zip, is_valid_tree_item_name
from session_sniffer.guis.loading_overlay import (
    LoadingOverlay,
    loading_overlay_scope,
    pump_active_loading_overlays,
    run_async_with_loading,
    run_with_active_loading,
)
from session_sniffer.guis.userip_manager_helpers import (
    extract_entry_model_from_row,
    load_userip_database_model,
    parse_userip_database_content,
    refresh_userip_and_wake_renderer,
    save_userip_database_model,
)
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.userip_settings_model import (
    DEFAULT_USERIP_FILES_SETTINGS,
    UserIPDatabaseFile,
    UserIPEntryModel,
    UserIPSettingsModel,
)
from session_sniffer.player import backup_userip_databases
from session_sniffer.player.userip_loader import find_userip_insert_index, userip_database_write, userip_databases_lock

logger = logging.getLogger(__name__)


def _resolve_zip_member_dest(member_filename: str, databases_root: Path) -> Path | None:
    """Validate a ZIP member path and return its destination under `USERIP_DATABASES_DIR_PATH`, or `None` if unsafe."""
    normalized = member_filename.replace('\\', '/')
    if normalized.startswith('/'):
        return None
    parts = [part for part in normalized.split('/') if part]
    if not parts or not all(is_valid_tree_item_name(part) for part in parts):
        return None
    candidate = USERIP_DATABASES_DIR_PATH.joinpath(*parts)
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(databases_root):
        return None
    return USERIP_DATABASES_DIR_PATH / resolved.relative_to(databases_root)


def _has_file_ancestor(dest: Path, root: Path) -> bool:
    """Return `True` if any parent directory of *dest* under *root* already exists as a regular file."""
    current = dest.parent
    while current not in (root, current.parent):
        if current.is_file():
            return True
        current = current.parent
    return False


class UserIPImportExportMixin(QDialog):
    """Mixin providing import, export, and backup operations for UserIP databases."""

    _next_index: int = 0

    _current_path: Path | None = None
    _global_search_active: bool = False

    if TYPE_CHECKING:
        _model: QStandardItemModel
        _get_selected_tree_directory: Callable[[], Path]
        read_settings_from_widgets: Callable[[], UserIPSettingsModel]

        def _set_status(self, text: str) -> None:
            del text

        def _load_database(self, path: Path) -> None:
            del path

        def _load_all_databases(self) -> None: ...
        def _rebuild_fs_watch(self) -> None: ...
        def _refresh_stats(self) -> None: ...
        def _mark_settings_dirty(self) -> None: ...
        def _mark_entries_dirty(self) -> None: ...
        def _refresh_after_tree_mutation(self) -> None: ...
        def _clear_open_database_view(self) -> None: ...

        def _unwatch_path(self, path: Path) -> None:
            del path

        def _refresh_tree_item_visual(self, path: Path | None = None, *, resort: bool = False) -> None:
            del path, resort

        def _append_row(
            self,
            entry: UserIPEntryModel,
            *,
            index: int = 0,
            persisted: bool = True,
        ) -> None:
            del entry, index, persisted

        def _save_database(self, *, show_errors: bool = True) -> None:
            del show_errors

        def populate_settings_widgets(self, settings: UserIPSettingsModel) -> None:
            """Populate the settings widgets from a model."""
            del settings

        def _highlight_duplicates(self) -> int:
            raise NotImplementedError

        _selected_tree_paths: Callable[[], list[Path]]

    def _is_current_database_file(self, path: Path) -> bool:
        """Return True if *path* refers to the database currently open in the entries view."""
        if self._current_path is None or self._global_search_active:
            return False
        if not path.is_file() or not self._current_path.is_file():
            return False
        return path.samefile(self._current_path)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_database_file(self, path: Path) -> None:
        """Copy a specific database file to a user-chosen destination."""
        dest_path, _ = QFileDialog.getSaveFileName(
            self,
            tr('Export Database'),
            path.name,
            tr('JSON files (*.json);;All Files (*)'),
        )
        if not dest_path:
            return

        dest = Path(dest_path)
        try:
            if dest.exists() and path.samefile(dest):
                QMessageBox.warning(
                    self,
                    TITLE,
                    tr('Cannot export "{name}" over itself. Please choose a different destination.', name=path.name),
                )
                return
            shutil.copy2(str(path), dest_path)
        except OSError as e:
            logger.warning('Failed to export UserIP database "%s" to "%s": %s', path, dest_path, e)
            QMessageBox.critical(self, tr('Export Error'), tr('Failed to export "{name}":\n{error}', name=path.name, error=e))
            return
        self._set_status(tr('Exported "{name}" to {dest}', name=path.name, dest=dest_path))

    def _export_selected_database(self) -> None:
        """Copy the open database file, or export multi-selected tree items as a ZIP archive."""
        selected_paths = self._selected_tree_paths()
        if len(selected_paths) > 1:
            export_selected_tree_paths_as_zip(self, selected_paths, self._set_status)
            return
        if self._current_path is None or not self._current_path.is_file():
            QMessageBox.information(self, TITLE, tr('No database is currently open. Select a database first.'))
            return

        self._export_database_file(self._current_path)

    def _export_all_as_zip(self) -> None:
        """Export all UserIP databases as a ZIP archive to a user-chosen destination."""
        json_files = sorted(USERIP_DATABASES_DIR_PATH.rglob('*.json'))
        if not json_files:
            QMessageBox.information(self, TITLE, tr('No database files found to export.'))
            return

        export_json_databases_to_zip(self, json_files, self._set_status)

    def _backup_databases_now(self) -> None:
        """Create a backup of all UserIP databases asynchronously."""

        def _on_backup_done(backup_path: Path | None) -> None:
            if backup_path is not None:
                self._set_status(tr('Backup created: {name}', name=backup_path.name))
                QMessageBox.information(self, TITLE, tr('UserIP databases backup successfully created at:\n{path}', path=backup_path))
            else:
                self._set_status(tr('Backup failed or no databases found.'))
                QMessageBox.warning(self, TITLE, tr('Could not create UserIP databases backup (no database files found).'))

        run_async_with_loading(
            self,
            tr('Creating Backup\u2026'),
            tr('Backing up UserIP databases\u2026'),
            lambda: backup_userip_databases(force=True),
            _on_backup_done,
        )

    def _open_backups_folder(self) -> None:
        """Open the UserIP databases backup directory."""
        USERIP_DATABASES_BACKUP_DIR_PATH.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(USERIP_DATABASES_BACKUP_DIR_PATH)))

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def _prompt_settings_conflict(self, src_name: str, *, target_db_name: str | None = None) -> Literal['keep', 'use'] | None:
        """Prompt whether to keep existing settings or use imported settings when merging."""
        message_box = QMessageBox(self)
        message_box.setWindowTitle(TITLE)
        message_box.setText(
            tr(
                'The settings in "{src}" differ from "{target}".\n\nWhich settings would you like to keep?',
                src=src_name,
                target=target_db_name,
            )
            if target_db_name is not None
            else tr(
                'The settings in "{src}" differ from the current database\'s settings.\n\nWhich settings would you like to keep?',
                src=src_name,
            ),
        )
        message_box.addButton(tr('Keep existing settings'), QMessageBox.ButtonRole.AcceptRole)
        use_button = message_box.addButton(tr('Use imported settings'), QMessageBox.ButtonRole.AcceptRole)
        message_box.addButton(QMessageBox.StandardButton.Cancel)
        for button in message_box.buttons():
            button.setMinimumWidth(scale_by_ui(160))
            button.setCursor(Qt.CursorShape.PointingHandCursor)
        message_box.exec()
        clicked = message_box.clickedButton()
        if not clicked or clicked is message_box.button(QMessageBox.StandardButton.Cancel):
            return None
        return 'use' if clicked is use_button else 'keep'

    def _merge_content_into_disk(
        self,
        src_content: str,
        dest_path: Path,
        src_name: str,
        *,
        overlay: LoadingOverlay | None = None,
    ) -> int | None:
        """Merge entries from *src_content* into an existing *dest_path* file on disk.

        Shows a settings-conflict prompt when the two files have differing `settings` values.
        Returns the number of new entries added, or `None` if the user cancelled via the
        settings-conflict dialog (treated as "skipped" by callers).
        """
        dest_db, src_db = run_with_active_loading(
            lambda: (load_userip_database_model(dest_path), parse_userip_database_content(src_content)),
        )

        use_imported_settings = False
        if src_db.settings != dest_db.settings:
            if overlay is not None:
                with overlay.suspended():
                    choice = self._prompt_settings_conflict(src_name, target_db_name=dest_path.name)
            else:
                choice = self._prompt_settings_conflict(src_name, target_db_name=dest_path.name)
            if choice is None:
                return None
            use_imported_settings = choice == 'use'

        def _write_merged() -> int:
            with userip_databases_lock():
                latest_dest = load_userip_database_model(dest_path)
                chosen_settings = src_db.settings if use_imported_settings else latest_dest.settings
                existing_set: set[tuple[str, str]] = {(entry.username.casefold(), entry.ip) for entry in latest_dest.entries}
                new_entries: list[UserIPEntryModel] = []
                for entry in src_db.entries:
                    key = (entry.username.casefold(), entry.ip)
                    if key in existing_set:
                        continue
                    existing_set.add(key)
                    new_entries.append(
                        entry.model_copy(update={'source': 'Import'}) if entry.source == 'Manual' and not entry.is_looky else entry,
                    )

                merged_entries = list(latest_dest.entries)
                for entry in new_entries:
                    merged_entries.insert(find_userip_insert_index(merged_entries, entry.username, entry.ip), entry)
                merged_db = UserIPDatabaseFile(settings=chosen_settings, entries=merged_entries)
                save_userip_database_model(dest_path, merged_db)
            return len(new_entries)

        return run_with_active_loading(_write_merged)

    def _import_database_files(self) -> None:
        """Copy external .json database files into the databases directory, or merge into the current database."""
        merge_mode = False
        if self._current_path is not None:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText(tr('How would you like to import the file(s)?'))
            msg_box.addButton(tr('Import as new database(s)'), QMessageBox.ButtonRole.AcceptRole)
            merge_button = msg_box.addButton(tr('Merge into "{name}"', name=self._current_path.stem), QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            for _button in msg_box.buttons():
                _button.setMinimumWidth(scale_by_ui(200))
                _button.setCursor(Qt.CursorShape.PointingHandCursor)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if not clicked or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            merge_mode = clicked is merge_button

        if merge_mode:
            src_path_str, _ = QFileDialog.getOpenFileName(
                self,
                tr('Choose a database file to merge from'),
                '',
                tr('JSON files (*.json);;All Files (*)'),
            )
            if not src_path_str:
                return
            src_path = Path(src_path_str)
            if src_path.is_file():
                self._merge_from_file(src_path)
            return

        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            tr('Import Database Files'),
            '',
            tr('JSON files (*.json);;All Files (*)'),
        )
        if not file_paths:
            return

        target_dir = self._get_selected_tree_directory()
        imported = 0
        merged = 0
        skipped = 0
        modified_on_disk = False
        reload_current_view = False

        with loading_overlay_scope(self, tr('Importing Databases\u2026'), tr('Importing UserIP database files\u2026')) as overlay:
            for file_path_str in file_paths:
                src = Path(file_path_str)
                if not src.is_file():
                    continue

                overlay.set_status(tr('Processing "{name}"\u2026', name=src.name))
                dest = target_dir / src.name

                is_same_file = False
                with suppress(OSError):
                    is_same_file = dest.exists() and src.samefile(dest)
                if is_same_file:
                    skipped += 1
                    continue

                if dest.is_dir():
                    with overlay.suspended():
                        QMessageBox.critical(
                            self,
                            tr('Import Error'),
                            tr('Cannot import "{name}" because a folder with the same name already exists in the destination.', name=src.name),
                        )
                    skipped += 1
                    continue

                if dest.exists():
                    with overlay.suspended():
                        msg_box = QMessageBox(self)
                        msg_box.setWindowTitle(TITLE)
                        msg_box.setText(tr('"{name}" already exists in the destination folder.\n\nWhat would you like to do?', name=src.name))
                        overwrite_button = msg_box.addButton(tr('Overwrite'), QMessageBox.ButtonRole.YesRole)
                        merge_button = msg_box.addButton(tr('Merge'), QMessageBox.ButtonRole.AcceptRole)
                        skip_button = msg_box.addButton(tr('Skip'), QMessageBox.ButtonRole.NoRole)
                        for _button in msg_box.buttons():
                            _button.setMinimumWidth(scale_by_ui(100))
                            _button.setCursor(Qt.CursorShape.PointingHandCursor)
                        msg_box.exec()
                        clicked = msg_box.clickedButton()
                    if clicked is skip_button:
                        skipped += 1
                        continue
                    if clicked is merge_button:
                        try:
                            src_text = run_with_active_loading(src.read_text, 'utf-8')
                            result = self._merge_content_into_disk(src_text, dest, src.name, overlay=overlay)
                        except (OSError, UnicodeDecodeError) as e:
                            logger.warning('Failed to import/merge UserIP database "%s" into "%s": %s', src, dest, e)
                            with overlay.suspended():
                                QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=src.name, error=e))
                            skipped += 1
                            continue
                        if result is None:
                            skipped += 1
                        else:
                            merged += result
                            modified_on_disk = True
                            if self._is_current_database_file(dest):
                                reload_current_view = True
                        continue
                    if not clicked:
                        skipped += 1
                        continue
                    _ = overwrite_button  # suppress unused-variable warning

                if self._is_current_database_file(dest):
                    reload_current_view = True

                def _copy_db_file(src_file: Path = src, dest_file: Path = dest) -> None:
                    target_dir.mkdir(parents=True, exist_ok=True)
                    with userip_database_write(dest_file):
                        shutil.copy2(str(src_file), str(dest_file))

                try:
                    run_with_active_loading(_copy_db_file)
                except OSError as e:
                    logger.warning('Failed to import UserIP database "%s" to "%s": %s', src, dest, e)
                    with overlay.suspended():
                        QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=src.name, error=e))
                    skipped += 1
                    continue
                modified_on_disk = True
                imported += 1

            if modified_on_disk:
                overlay.set_status(tr('Refreshing UserIP databases\u2026'))
                self._refresh_after_tree_mutation()
                if self._global_search_active:
                    self._load_all_databases()
                elif reload_current_view and self._current_path is not None:
                    self._load_database(self._current_path)

            parts: list[str] = []
            if imported:
                parts.append(tr_plural('Imported {count} file', 'Imported {count} files', imported))
            if merged:
                parts.append(tr_plural('Merged {count} entry', 'Merged {count} entries', merged))
            if skipped:
                parts.append(tr('{count} skipped', count=skipped))
            if parts:
                self._set_status('  |  '.join(parts))
                self._refresh_stats()

    def _merge_from_file(self, src_path: Path) -> None:
        """Merge entries from src_path into the currently open database."""
        if self._current_path is None:
            return

        with loading_overlay_scope(self, tr('Merging Database\u2026'), tr('Reading "{name}"\u2026', name=src_path.name)) as overlay:
            imported_db = run_with_active_loading(load_userip_database_model, src_path)
            imported_settings = imported_db.settings
            current_settings = self.read_settings_from_widgets()

            settings_changed = False
            if imported_settings != current_settings:
                with overlay.suspended():
                    choice = self._prompt_settings_conflict(src_path.name)
                if choice is None:
                    return
                if choice == 'use':
                    self.populate_settings_widgets(imported_settings)
                    self._mark_settings_dirty()
                    settings_changed = True

            overlay.set_status(tr('Merging entries from "{name}"\u2026', name=src_path.name))
            existing_set: set[tuple[str, str]] = set()
            for row in range(self._model.rowCount()):
                username, ip, _notes, _entry_model = extract_entry_model_from_row(self._model, row)
                if username and ip:
                    existing_set.add((username.casefold(), ip))
                if not row % 200:
                    pump_active_loading_overlays()

            added = 0
            for idx, entry in enumerate(imported_db.entries):
                key = (entry.username.casefold(), entry.ip)
                if key in existing_set:
                    continue
                existing_set.add(key)
                merged_entry = entry.model_copy(update={'source': 'Import'}) if entry.source == 'Manual' and not entry.is_looky else entry
                self._append_row(merged_entry, index=self._next_index)
                self._next_index += 1
                added += 1
                if not idx % 200:
                    pump_active_loading_overlays()

            if added or settings_changed:
                overlay.set_status(tr('Saving "{name}"\u2026', name=self._current_path.name))
                self._mark_entries_dirty()
                self._highlight_duplicates()
                self._save_database()

            self._set_status(
                tr_plural(
                    'Merged {count} entry from "{src}" into "{dest}".',
                    'Merged {count} entries from "{src}" into "{dest}".',
                    added,
                    src=src_path.name,
                    dest=self._current_path.name,
                ),
            )

    def _import_from_zip(self) -> None:
        """Extract .json database files from a ZIP archive into the databases directory."""
        zip_path_str, _ = QFileDialog.getOpenFileName(
            self,
            tr('Import Databases from ZIP'),
            '',
            tr('ZIP archives (*.zip);;All Files (*)'),
        )
        if not zip_path_str:
            return

        zip_path = Path(zip_path_str)
        if not zip_path.is_file():
            return

        databases_root = USERIP_DATABASES_DIR_PATH.resolve()

        with loading_overlay_scope(self, tr('Importing from ZIP\u2026'), tr('Reading "{name}"\u2026', name=zip_path.name)) as overlay:
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    json_members = [member for member in zf.infolist() if not member.is_dir() and member.filename.lower().endswith('.json')]

                    if not json_members:
                        with overlay.suspended():
                            QMessageBox.information(self, TITLE, tr('No .json database files found in the selected ZIP archive.'))
                        return

                    imported = 0
                    merged = 0
                    skipped = 0
                    overwrite_all = False
                    merge_all = False
                    modified_on_disk = False
                    reload_current_view = False

                    for member in json_members:
                        dest = _resolve_zip_member_dest(member.filename, databases_root)
                        if dest is None or _has_file_ancestor(dest, USERIP_DATABASES_DIR_PATH):
                            logger.warning('Skipping unsafe or colliding ZIP member path "%s".', member.filename)
                            skipped += 1
                            continue
                        if dest.is_dir():
                            with overlay.suspended():
                                QMessageBox.critical(
                                    self,
                                    tr('Import Error'),
                                    tr('Cannot import "{name}" because a folder with the same name already exists in the destination.', name=member.filename),
                                )
                            skipped += 1
                            continue
                        overlay.set_status(tr('Extracting "{name}"\u2026', name=member.filename))
                        try:
                            member_bytes = run_with_active_loading(zf.read, member.filename)
                        except (RuntimeError, zlib.error, lzma.LZMAError, zipfile.BadZipFile, EOFError, OSError) as e:
                            logger.warning('Failed to extract "%s" from ZIP "%s": %s', member.filename, zip_path, e)
                            with overlay.suspended():
                                QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=member.filename, error=e))
                            skipped += 1
                            break
                        src_content = member_bytes.decode('utf-8', errors='replace')

                        if dest.exists() and not overwrite_all:
                            if merge_all:
                                try:
                                    result = self._merge_content_into_disk(src_content, dest, member.filename, overlay=overlay)
                                except OSError as e:
                                    logger.warning('Failed to merge ZIP member "%s" into "%s": %s', member.filename, dest, e)
                                    with overlay.suspended():
                                        QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=member.filename, error=e))
                                    skipped += 1
                                    continue
                                if result is None:
                                    skipped += 1
                                else:
                                    merged += result
                                    modified_on_disk = True
                                    if self._is_current_database_file(dest):
                                        reload_current_view = True
                                continue

                            with overlay.suspended():
                                msg_box = QMessageBox(self)
                                msg_box.setWindowTitle(TITLE)
                                msg_box.setText(tr('"{name}" already exists.\n\nWhat would you like to do?', name=member.filename))
                                overwrite_button = msg_box.addButton(tr('Overwrite'), QMessageBox.ButtonRole.YesRole)
                                overwrite_all_button = msg_box.addButton(tr('Overwrite All'), QMessageBox.ButtonRole.YesRole)
                                merge_button = msg_box.addButton(tr('Merge'), QMessageBox.ButtonRole.AcceptRole)
                                merge_all_button = msg_box.addButton(tr('Merge All'), QMessageBox.ButtonRole.AcceptRole)
                                skip_button = msg_box.addButton(tr('Skip'), QMessageBox.ButtonRole.NoRole)
                                cancel_button = msg_box.addButton(tr('Cancel'), QMessageBox.ButtonRole.RejectRole)
                                for _button in msg_box.buttons():
                                    _button.setMinimumWidth(scale_by_ui(120))
                                    _button.setCursor(Qt.CursorShape.PointingHandCursor)
                                msg_box.exec()
                                clicked = msg_box.clickedButton()

                            if not clicked or clicked is cancel_button:
                                break
                            if clicked is skip_button:
                                skipped += 1
                                continue
                            if clicked is overwrite_all_button:
                                overwrite_all = True
                            elif clicked in (merge_button, merge_all_button):
                                if clicked is merge_all_button:
                                    merge_all = True
                                try:
                                    result = self._merge_content_into_disk(src_content, dest, member.filename, overlay=overlay)
                                except OSError as e:
                                    logger.warning('Failed to merge ZIP member "%s" into "%s": %s', member.filename, dest, e)
                                    with overlay.suspended():
                                        QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=member.filename, error=e))
                                    skipped += 1
                                    continue
                                if result is None:
                                    skipped += 1
                                else:
                                    merged += result
                                    modified_on_disk = True
                                    if self._is_current_database_file(dest):
                                        reload_current_view = True
                                continue
                            _ = overwrite_button  # suppress unused-variable warning

                        if self._is_current_database_file(dest):
                            reload_current_view = True

                        def _write_member_file(dest_file: Path = dest, raw_bytes: bytes = member_bytes) -> None:
                            dest_file.parent.mkdir(parents=True, exist_ok=True)
                            with userip_database_write(dest_file, content=raw_bytes):
                                tmp_dest = dest_file.with_name(f'{dest_file.name}.tmp')
                                try:
                                    tmp_dest.write_bytes(raw_bytes)
                                    tmp_dest.replace(dest_file)
                                except OSError:
                                    with suppress(OSError):
                                        tmp_dest.unlink(missing_ok=True)
                                    raise

                        try:
                            run_with_active_loading(_write_member_file)
                        except OSError as e:
                            logger.warning('Failed to write ZIP member "%s" to "%s": %s', member.filename, dest, e)
                            with overlay.suspended():
                                QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=member.filename, error=e))
                            skipped += 1
                            continue
                        modified_on_disk = True
                        imported += 1

            except zipfile.BadZipFile:
                with overlay.suspended():
                    QMessageBox.critical(self, TITLE, tr('"{name}" is not a valid ZIP archive.', name=zip_path.name))
                return
            except (NotImplementedError, EOFError, OSError) as e:
                logger.warning('Failed to open ZIP archive "%s": %s', zip_path, e)
                with overlay.suspended():
                    QMessageBox.critical(self, tr('Import Error'), tr('Failed to import "{name}":\n{error}', name=zip_path.name, error=e))
                return

            if modified_on_disk:
                overlay.set_status(tr('Refreshing UserIP databases\u2026'))
                self._refresh_after_tree_mutation()
                if self._global_search_active:
                    self._load_all_databases()
                elif reload_current_view and self._current_path is not None:
                    self._load_database(self._current_path)

            parts: list[str] = []
            if imported:
                parts.append(tr_plural('Imported {count} database from ZIP', 'Imported {count} databases from ZIP', imported))
            if merged:
                parts.append(tr_plural('Merged {count} entry from ZIP', 'Merged {count} entries from ZIP', merged))
            if skipped:
                parts.append(tr('{count} skipped', count=skipped))
            if parts:
                self._set_status('  |  '.join(parts))
                self._refresh_stats()

    def _reset_all_databases(self) -> None:
        """Delete every .json database file in the databases directory after user confirmation.

        Default databases (Blacklist, Enemylist, etc.) are restored to their factory content
        rather than deleted. User-created .json files and subdirectories are removed entirely.
        """
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
        json_files = sorted(USERIP_DATABASES_DIR_PATH.rglob('*.json'))
        if not json_files:
            QMessageBox.information(self, TITLE, tr('There are no database files to reset.'))
            return

        count = len(json_files)
        prompt = tr_plural(
            'This will permanently reset all {count} database file.\n\n'
            'Default databases will be restored to factory content.\nUser-created databases will be deleted.\n\nThis cannot be undone. Are you sure?',
            'This will permanently reset all {count} database files.\n\n'
            'Default databases will be restored to factory content.\nUser-created databases will be deleted.\n\nThis cannot be undone. Are you sure?',
            count,
        )
        result = QMessageBox.warning(self, TITLE, prompt, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if result != QMessageBox.StandardButton.Yes:
            return

        subdirs = [entry for entry in USERIP_DATABASES_DIR_PATH.iterdir() if entry.is_dir()]
        for subdir in subdirs:
            self._unwatch_path(subdir)

        default_db_names: set[str] = set(DEFAULT_USERIP_FILES_SETTINGS.keys())

        def _perform_reset() -> tuple[int, int]:
            deleted_count = 0
            restored_count = 0
            with userip_databases_lock():
                for json_path in json_files:
                    if json_path.parent == USERIP_DATABASES_DIR_PATH and json_path.name in default_db_names:
                        save_userip_database_model(json_path, UserIPDatabaseFile(settings=DEFAULT_USERIP_FILES_SETTINGS[json_path.name]))
                        restored_count += 1
                    else:
                        try:
                            json_path.unlink()
                            deleted_count += 1
                        except OSError as e:
                            logger.warning('Failed to delete user database file %s: %s', json_path, e)

                for subdir in subdirs:
                    try:
                        shutil.rmtree(subdir)
                    except OSError as e:
                        logger.warning('Failed to remove user database directory %s: %s', subdir, e)

                refresh_userip_and_wake_renderer()
            return restored_count, deleted_count

        with loading_overlay_scope(self, tr('Resetting Databases\u2026'), tr('Restoring factory UserIP databases\u2026')):
            restored, deleted = run_with_active_loading(_perform_reset)
            self._refresh_tree_item_visual(resort=True)
            self._refresh_stats()

            if self._global_search_active:
                self._load_all_databases()
                self._rebuild_fs_watch()
            elif self._current_path is not None:
                if self._current_path.is_file():
                    self._load_database(self._current_path)
                else:
                    self._clear_open_database_view()
                    self._rebuild_fs_watch()
            else:
                self._rebuild_fs_watch()

        status_parts = [tr('Reset complete')]
        if restored:
            status_parts.append(tr_plural('Restored {count} default file', 'Restored {count} default files', restored))
        if deleted:
            status_parts.append(tr_plural('Deleted {count} user file', 'Deleted {count} user files', deleted))
        self._set_status('  |  '.join(status_parts))
