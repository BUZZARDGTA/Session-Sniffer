"""Import and export mixin for the UserIP Databases Manager dialog."""

import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog, QFileDialog, QMessageBox

from session_sniffer.constants.local import USERIP_DATABASES_BACKUP_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.userip_manager_helpers import (
    SETTINGS_DEFAULTS,
    SETTINGS_KEYS_ORDER,
    iter_userip_entries,
    iter_userip_entries_with_metadata,
    parse_settings_from_content,
    parse_settings_from_lines,
    read_preserved_sections,
)
from session_sniffer.player import backup_userip_databases
from session_sniffer.text_utils import pluralize


class UserIPImportExportMixin(QDialog):
    """Mixin providing import, export, and backup operations for UserIP databases."""

    _next_index: int = 0

    _current_path: Path | None = None
    _global_search_active: bool = False

    def _set_status(self, text: str) -> None:
        raise NotImplementedError

    def _load_database(self, path: Path) -> None:
        raise NotImplementedError

    def _refresh_stats(self) -> None: ...

    def _mark_settings_dirty(self) -> None: ...

    def _append_row(
        self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None, is_looky: bool = False
    ) -> None:
        raise NotImplementedError

    def _mark_entries_dirty(self) -> None: ...

    if TYPE_CHECKING:
        _get_selected_tree_directory: Callable[[], Path]
        read_settings_from_widgets: Callable[[], dict[str, str]]
        populate_settings_widgets: Callable[[dict[str, str]], None]
        _highlight_duplicates: Callable[[], int]

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
            'Export Database',
            path.name,
            'INI files (*.ini);;All Files (*)',
        )
        if not dest_path:
            return

        shutil.copy2(str(path), dest_path)
        self._set_status(f'Exported "{path.name}" to {dest_path}')

    def _export_selected_database(self) -> None:
        """Copy the currently open database file to a user-chosen destination."""
        if self._current_path is None or not self._current_path.is_file():
            QMessageBox.information(self, TITLE, 'No database is currently open. Select a database first.')
            return

        self._export_database_file(self._current_path)

    def _export_all_as_zip(self) -> None:
        """Export all UserIP databases as a ZIP archive to a user-chosen destination."""
        ini_files = sorted(USERIP_DATABASES_DIR_PATH.rglob('*.ini'))
        if not ini_files:
            QMessageBox.information(self, TITLE, 'No database files found to export.')
            return

        dest_path, _ = QFileDialog.getSaveFileName(
            self,
            'Export All Databases as ZIP',
            'UserIP_Databases.zip',
            'ZIP archives (*.zip);;All Files (*)',
        )
        if not dest_path:
            return

        with zipfile.ZipFile(dest_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for ini_path in ini_files:
                arcname = ini_path.relative_to(USERIP_DATABASES_DIR_PATH)
                zf.write(str(ini_path), str(arcname))

        self._set_status(f'Exported {len(ini_files)} database{pluralize(len(ini_files))} to {dest_path}')

    def _backup_databases_now(self) -> None:
        """Create a backup of all UserIP databases immediately."""
        backup_path = backup_userip_databases(force=True)
        if backup_path is not None:
            self._set_status(f'Backup created: {backup_path.name}')
            QMessageBox.information(self, TITLE, f'UserIP databases backup successfully created at:\n{backup_path}')
        else:
            self._set_status('Backup failed or no databases found.')
            QMessageBox.warning(self, TITLE, 'Could not create UserIP databases backup (no database files found).')

    def _open_backups_folder(self) -> None:
        """Open the UserIP databases backup directory."""
        USERIP_DATABASES_BACKUP_DIR_PATH.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(USERIP_DATABASES_BACKUP_DIR_PATH)))

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def _merge_content_into_disk(self, src_content: str, dest_path: Path, src_name: str) -> int | None:
        """Merge `[UserIP]` entries from *src_content* into an existing *dest_path* file on disk.

        Shows a settings-conflict prompt when the two files have differing `[Settings]` values.
        Returns the number of new entries added, or `None` if the user cancelled via the
        settings-conflict dialog (treated as "skipped" by callers).
        """
        _, dest_settings_lines = read_preserved_sections(dest_path)
        dest_settings = parse_settings_from_lines(dest_settings_lines)
        src_settings = parse_settings_from_content(src_content)

        chosen_settings = dest_settings
        if src_settings != dest_settings:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText(
                f'The settings in "{src_name}" differ from "{dest_path.name}".\n\nWhich settings would you like to keep?',
            )
            keep_button = msg_box.addButton('Keep existing settings', QMessageBox.ButtonRole.AcceptRole)
            use_button = msg_box.addButton('Use imported settings', QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            for _button in msg_box.buttons():
                _button.setMinimumWidth(160)
                _button.setCursor(Qt.CursorShape.PointingHandCursor)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if not clicked or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return None
            if clicked is use_button:
                chosen_settings = src_settings
            _ = keep_button  # suppress unused-variable warning

        dest_content = dest_path.read_text('utf-8')
        existing_set: set[tuple[str, str]] = set(iter_userip_entries(dest_content))
        existing_entries = list(iter_userip_entries(dest_content))
        new_entries = [(username, ip) for username, ip in iter_userip_entries(src_content) if (username, ip) not in existing_set]

        header_lines, _ = read_preserved_sections(dest_path)

        output_lines: list[str] = [*header_lines]
        output_lines.append('[Settings]')
        output_lines.extend(f'{key}={chosen_settings.get(key, SETTINGS_DEFAULTS.get(key, ""))}' for key in SETTINGS_KEYS_ORDER)
        output_lines.append('')
        output_lines.append('[UserIP]')
        for username, ip in existing_entries:
            output_lines.append(f'{username}={ip}')
        for username, ip in new_entries:
            output_lines.append(f'{username}={ip}')
        output_lines.append('')

        dest_path.write_text('\n'.join(output_lines), encoding='utf-8')
        return len(new_entries)

    def _import_database_files(self) -> None:
        """Copy external .ini database files into the databases directory, or merge into the current database."""
        merge_mode = False
        if self._current_path is not None:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText('How would you like to import the file(s)?')
            msg_box.addButton('Import as new database(s)', QMessageBox.ButtonRole.AcceptRole)
            merge_button = msg_box.addButton(f'Merge into "{self._current_path.stem}"', QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            for _button in msg_box.buttons():
                _button.setMinimumWidth(200)
                _button.setCursor(Qt.CursorShape.PointingHandCursor)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if not clicked or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            merge_mode = clicked is merge_button

        if merge_mode:
            src_path_str, _ = QFileDialog.getOpenFileName(
                self,
                'Choose a database file to merge from',
                '',
                'INI files (*.ini);;All Files (*)',
            )
            if not src_path_str:
                return
            src_path = Path(src_path_str)
            if src_path.is_file():
                self._merge_from_file(src_path)
            return

        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            'Import Database Files',
            '',
            'INI files (*.ini);;All Files (*)',
        )
        if not file_paths:
            return

        target_dir = self._get_selected_tree_directory()
        imported = 0
        merged = 0
        skipped = 0
        reload_current_view = False

        for file_path_str in file_paths:
            src = Path(file_path_str)
            if not src.is_file():
                continue

            dest = target_dir / src.name

            if dest.exists():
                msg_box = QMessageBox(self)
                msg_box.setWindowTitle(TITLE)
                msg_box.setText(f'"{src.name}" already exists in the destination folder.\n\nWhat would you like to do?')
                overwrite_button = msg_box.addButton('Overwrite', QMessageBox.ButtonRole.YesRole)
                merge_button = msg_box.addButton('Merge', QMessageBox.ButtonRole.AcceptRole)
                skip_button = msg_box.addButton('Skip', QMessageBox.ButtonRole.NoRole)
                for _button in msg_box.buttons():
                    _button.setMinimumWidth(100)
                    _button.setCursor(Qt.CursorShape.PointingHandCursor)
                msg_box.exec()
                clicked = msg_box.clickedButton()
                if clicked is skip_button:
                    skipped += 1
                    continue
                if clicked is merge_button:
                    result = self._merge_content_into_disk(src.read_text('utf-8'), dest, src.name)
                    if result is None:
                        skipped += 1
                    else:
                        merged += result
                        if self._is_current_database_file(dest):
                            reload_current_view = True
                    continue
                if not clicked:
                    skipped += 1
                    continue
                _ = overwrite_button  # suppress unused-variable warning

            target_dir.mkdir(parents=True, exist_ok=True)
            if self._is_current_database_file(dest):
                reload_current_view = True
            shutil.copy2(str(src), str(dest))
            imported += 1

        if reload_current_view and self._current_path is not None:
            self._load_database(self._current_path)

        parts: list[str] = []
        if imported:
            parts.append(f'Imported {imported} file{pluralize(imported)}')
        if merged:
            parts.append(f'Merged {merged} entr{pluralize(merged, "ies", "y")}')
        if skipped:
            parts.append(f'{skipped} skipped')
        if parts:
            self._set_status('  |  '.join(parts))
            self._refresh_stats()

    def _merge_from_file(self, src_path: Path) -> None:
        """Merge [UserIP] entries from src_path into the currently open database."""
        if self._current_path is None:
            return

        content = src_path.read_text('utf-8')

        _, imported_settings_lines = read_preserved_sections(src_path)
        imported_settings = parse_settings_from_lines(imported_settings_lines)
        current_settings = self.read_settings_from_widgets()

        if imported_settings != current_settings:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText(
                f'The settings in "{src_path.name}" differ from the current database\'s settings.\n\nWhich settings would you like to keep?',
            )
            keep_button = msg_box.addButton('Keep existing settings', QMessageBox.ButtonRole.AcceptRole)
            use_button = msg_box.addButton('Use imported settings', QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            for _button in msg_box.buttons():
                _button.setMinimumWidth(160)
                _button.setCursor(Qt.CursorShape.PointingHandCursor)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if not clicked or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            if clicked is use_button:
                self.populate_settings_widgets(imported_settings)
                self._mark_settings_dirty()
            _ = keep_button  # suppress unused-variable warning

        added = 0
        for username, ip, is_looky in iter_userip_entries_with_metadata(content):
            self._append_row(username, ip, index=self._next_index, is_looky=is_looky)
            self._next_index += 1
            added += 1

        if added:
            self._mark_entries_dirty()
            self._highlight_duplicates()

        self._set_status(
            f'Merged {added} entr{pluralize(added, "ies", "y")} from "{src_path.name}" into "{self._current_path.name}".' + (' Remember to save.' if added else ''),
        )

    def _import_from_zip(self) -> None:
        """Extract .ini database files from a ZIP archive into the databases directory."""
        zip_path_str, _ = QFileDialog.getOpenFileName(
            self,
            'Import Databases from ZIP',
            '',
            'ZIP archives (*.zip);;All Files (*)',
        )
        if not zip_path_str:
            return

        zip_path = Path(zip_path_str)
        if not zip_path.is_file():
            return

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                ini_members = [member for member in zf.infolist() if not member.is_dir() and member.filename.lower().endswith('.ini')]

                if not ini_members:
                    QMessageBox.information(self, TITLE, 'No .ini database files found in the selected ZIP archive.')
                    return

                imported = 0
                merged = 0
                skipped = 0
                overwrite_all = False
                merge_all = False
                reload_current_view = False

                for member in ini_members:
                    dest = USERIP_DATABASES_DIR_PATH / member.filename
                    member_bytes = zf.read(member.filename)
                    src_content = member_bytes.decode('utf-8', errors='replace')

                    if dest.exists() and not overwrite_all:
                        if merge_all:
                            result = self._merge_content_into_disk(src_content, dest, member.filename)
                            if result is None:
                                skipped += 1
                            else:
                                merged += result
                                if self._is_current_database_file(dest):
                                    reload_current_view = True
                            continue

                        msg_box = QMessageBox(self)
                        msg_box.setWindowTitle(TITLE)
                        msg_box.setText(f'"{member.filename}" already exists.\n\nWhat would you like to do?')
                        overwrite_button = msg_box.addButton('Overwrite', QMessageBox.ButtonRole.YesRole)
                        overwrite_all_button = msg_box.addButton('Overwrite All', QMessageBox.ButtonRole.YesRole)
                        merge_button = msg_box.addButton('Merge', QMessageBox.ButtonRole.AcceptRole)
                        merge_all_button = msg_box.addButton('Merge All', QMessageBox.ButtonRole.AcceptRole)
                        skip_button = msg_box.addButton('Skip', QMessageBox.ButtonRole.NoRole)
                        cancel_button = msg_box.addButton('Cancel', QMessageBox.ButtonRole.RejectRole)
                        for _button in msg_box.buttons():
                            _button.setMinimumWidth(120)
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
                        elif clicked is merge_button or clicked is merge_all_button:
                            if clicked is merge_all_button:
                                merge_all = True
                            result = self._merge_content_into_disk(src_content, dest, member.filename)
                            if result is None:
                                skipped += 1
                            else:
                                merged += result
                                if self._is_current_database_file(dest):
                                    reload_current_view = True
                            continue
                        _ = overwrite_button  # suppress unused-variable warning

                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if self._is_current_database_file(dest):
                        reload_current_view = True
                    dest.write_bytes(member_bytes)
                    imported += 1

        except zipfile.BadZipFile:
            QMessageBox.critical(self, TITLE, f'"{zip_path.name}" is not a valid ZIP archive.')
            return

        if reload_current_view and self._current_path is not None:
            self._load_database(self._current_path)

        parts: list[str] = []
        if imported:
            parts.append(f'Imported {imported} database{pluralize(imported)} from ZIP')
        if merged:
            parts.append(f'Merged {merged} entr{pluralize(merged, "ies", "y")} from ZIP')
        if skipped:
            parts.append(f'{skipped} skipped')
        if parts:
            self._set_status('  |  '.join(parts))
            self._refresh_stats()
