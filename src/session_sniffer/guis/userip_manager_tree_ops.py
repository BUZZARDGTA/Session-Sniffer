"""Tree-panel operations mixin for the UserIP Databases Manager dialog."""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from PyQt6.QtCore import QPoint, Qt, QUrl
from PyQt6.QtGui import QAction, QDesktopServices, QFileSystemModel, QStandardItemModel
from PyQt6.QtWidgets import QDialog, QFileDialog, QInputDialog, QLineEdit, QMenu, QMessageBox, QPushButton, QTreeView

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.userip_manager_helpers import NEW_DATABASE_TEMPLATE, iter_userip_entries, parse_settings_from_lines, read_preserved_sections

_MixinBase = QDialog


class _TreeOperationsMixin(_MixinBase):  # pylint: disable=too-few-public-methods
    """Mixin providing tree-panel context menu and file-system operations.

    Expects these attributes on the concrete class:
        _tree, _fs_model, _current_path, _dirty, _model, _open_db_button
    And these methods:
        _set_status, _refresh_stats, _update_file_info
    """

    # -- Attribute stubs for type checkers --
    _tree: QTreeView
    _fs_model: QFileSystemModel
    _current_path: Path | None
    _dirty: bool
    _next_index: int
    _model: QStandardItemModel
    _open_db_button: QPushButton
    _export_selected_action: QAction | None

    def _set_status(self, text: str) -> None: ...  # pylint: disable=unused-argument
    def _refresh_stats(self) -> None: ...
    def _update_file_info(self, path: Path | None) -> None: ...  # pylint: disable=unused-argument
    def _append_row(self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None) -> None: ...  # pylint: disable=unused-argument
    def _populate_settings_widgets(self, settings_dict: dict[str, str]) -> None: ...  # pylint: disable=unused-argument

    def _highlight_duplicates(self) -> int:
        raise NotImplementedError

    def _read_settings_from_widgets(self) -> dict[str, str]:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Tree: context menu
    # ------------------------------------------------------------------

    def _show_tree_context_menu(self, position: QPoint) -> None:
        """Show a right-click context menu for the file tree."""
        index = self._tree.indexAt(position)
        menu = QMenu(self)

        if index.isValid():
            file_path = Path(self._fs_model.filePath(index))

            if file_path.is_dir():
                new_db_action = QAction('📄 New Database Here', self)
                new_db_action.triggered.connect(lambda: self._new_database(parent_dir=file_path))
                menu.addAction(new_db_action)

                new_folder_action = QAction('📁 New Folder Here', self)
                new_folder_action.triggered.connect(lambda: self._new_folder(parent_dir=file_path))
                menu.addAction(new_folder_action)

                menu.addSeparator()

            move_action = QAction('📦 Move to...', self)
            move_action.triggered.connect(lambda: self._move_tree_item(file_path))
            menu.addAction(move_action)

            rename_action = QAction('✏️ Rename', self)
            rename_action.triggered.connect(lambda: self._rename_tree_item(file_path))
            menu.addAction(rename_action)

            delete_action = QAction('🗑️ Delete', self)
            delete_action.triggered.connect(lambda: self._delete_path(file_path))
            menu.addAction(delete_action)

            menu.addSeparator()

            explorer_target = file_path
            open_explorer_action = QAction('📂 Open in Explorer', self)
            open_explorer_action.triggered.connect(lambda: self._open_in_explorer(explorer_target))
            menu.addAction(open_explorer_action)

            if file_path.is_file():
                open_editor_action = QAction('📝 Open in Text Editor', self)
                open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path))))
                menu.addAction(open_editor_action)

                menu.addSeparator()

                export_action = QAction('📤 Export Database…', self)
                export_action.triggered.connect(lambda: self._export_database_file(file_path))
                menu.addAction(export_action)
        else:
            new_db_action = QAction('📄 New Database', self)
            new_db_action.triggered.connect(self._new_database)
            menu.addAction(new_db_action)

            new_folder_action = QAction('📁 New Folder', self)
            new_folder_action.triggered.connect(self._new_folder)
            menu.addAction(new_folder_action)

            menu.addSeparator()

            import_action = QAction('📥 Import Database Files…', self)
            import_action.triggered.connect(self._import_database_files)
            menu.addAction(import_action)

        viewport = self._tree.viewport()
        if viewport is not None:
            menu.popup(viewport.mapToGlobal(position))

    # ------------------------------------------------------------------
    # Tree: operations
    # ------------------------------------------------------------------

    def _get_selected_tree_directory(self) -> Path:
        """Return the directory of the currently selected tree item, or the root."""
        indexes = self._tree.selectedIndexes()
        if indexes:
            item_path = Path(self._fs_model.filePath(indexes[0]))
            return item_path if item_path.is_dir() else item_path.parent
        return USERIP_DATABASES_DIR_PATH

    def _new_database(self, *, parent_dir: Path | None = None) -> None:
        """Create a new UserIP database .ini file."""
        target_dir = parent_dir or self._get_selected_tree_directory()

        name, ok = QInputDialog.getText(self, TITLE, 'New database name:')
        if not ok or not name.strip():
            return

        name = name.strip()
        if name.lower().endswith('.ini'):
            name = name[:-4]
        if not name:
            return
        name += '.ini'

        new_path = target_dir / name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{name}" already exists in that location.')
            return

        new_path.parent.mkdir(parents=True, exist_ok=True)
        new_path.write_text(NEW_DATABASE_TEMPLATE, encoding='utf-8')

        self._set_status(f'Created new database: {name}')
        self._refresh_stats()

    def _new_folder(self, *, parent_dir: Path | None = None) -> None:
        """Create a new folder inside the databases directory."""
        target_dir = parent_dir or self._get_selected_tree_directory()

        name, ok = QInputDialog.getText(self, TITLE, 'New folder name:')
        if not ok or not name.strip():
            return

        folder_name = name.strip()
        new_path = target_dir / folder_name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{folder_name}" already exists in that location.')
            return

        new_path.mkdir(parents=True, exist_ok=True)

        self._set_status(f'Created new folder: {folder_name}')

    def _delete_tree_item(self) -> None:
        """Delete the currently selected item in the file tree."""
        indexes = self._tree.selectedIndexes()
        if not indexes:
            QMessageBox.information(self, TITLE, 'No item selected in the tree.')
            return

        file_path = Path(self._fs_model.filePath(indexes[0]))
        self._delete_path(file_path)

    def _delete_path(self, path: Path) -> None:
        """Delete a file or folder with user confirmation."""
        if path.is_dir():
            children = list(path.iterdir())
            msg = (
                f'Folder "{path.name}" is not empty ({len(children)} items).\n\nDelete it and all its contents?'
                if children
                else f'Delete empty folder "{path.name}"?'
            )
        else:
            msg = f'Delete database "{path.name}"?'

        result = QMessageBox.warning(
            self, TITLE, msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

        if self._current_path is not None and (self._current_path == path or path in self._current_path.parents):
            self._model.removeRows(0, self._model.rowCount())
            self._current_path = None
            self._open_db_button.setEnabled(False)
            if self._export_selected_action is not None:
                self._export_selected_action.setEnabled(False)
            self._dirty = False
            self._update_file_info(None)

        self._set_status(f'Deleted: {path.name}')
        self._refresh_stats()

    def _rename_tree_item(self, path: Path) -> None:
        """Rename a file or folder via an input dialog."""
        old_name = path.stem if path.is_file() else path.name
        label = 'New name:' if path.is_file() else 'New folder name:'

        new_name, ok = QInputDialog.getText(self, TITLE, label, QLineEdit.EchoMode.Normal, old_name)
        if not ok or not new_name.strip():
            return

        new_name = new_name.strip()
        if path.is_file():
            if new_name.lower().endswith('.ini'):
                new_name = new_name[:-4]
            if not new_name:
                return
            new_name += '.ini'

        new_path = path.parent / new_name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{new_name}" already exists.')
            return

        # Use the model's rename to avoid file-watcher handle conflicts on Windows
        index = self._fs_model.index(str(path))
        if not index.isValid() or not self._fs_model.setData(index, new_name, Qt.ItemDataRole.EditRole):
            QMessageBox.critical(self, TITLE, f'Failed to rename "{path.name}".')
            return

        if self._current_path == path:
            self._current_path = new_path

        self._set_status(f'Renamed "{path.name}" \u2192 "{new_name}"')

    def _move_tree_item(self, path: Path) -> None:
        """Move a file or folder to a different directory via a folder picker."""
        target_dir = QFileDialog.getExistingDirectory(
            self,
            f'Move "{path.name}" to...',
            str(USERIP_DATABASES_DIR_PATH),
        )
        if not target_dir:
            return

        dest = Path(target_dir)

        # Ensure the destination is within the databases root
        try:
            dest.relative_to(USERIP_DATABASES_DIR_PATH)
        except ValueError:
            QMessageBox.warning(self, TITLE, 'Destination must be within the UserIP Databases directory.')
            return

        new_path = dest / path.name
        if new_path.exists():
            QMessageBox.warning(self, TITLE, f'"{path.name}" already exists in the destination folder.')
            return

        shutil.move(str(path), str(new_path))

        if self._current_path == path:
            self._current_path = new_path

        self._set_status(f'Moved "{path.name}" \u2192 {dest.relative_to(USERIP_DATABASES_DIR_PATH) or "root"}')

    @staticmethod
    def _open_in_explorer(path: Path) -> None:
        """Open the containing folder and highlight the item in Windows Explorer."""
        if path.exists():
            explorer_exe = Path(os.getenv('WINDIR', r'C:\Windows')) / 'explorer.exe'
            subprocess.run([str(explorer_exe), '/select,', str(path)], check=False)
        elif path.parent.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))

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

        self._set_status(f'Exported {len(ini_files)} database{"s" if len(ini_files) != 1 else ""} to {dest_path}')

    # ------------------------------------------------------------------
    # Import files
    # ------------------------------------------------------------------

    def _import_database_files(self) -> None:
        """Copy external .ini database files into the databases directory, or merge into the current database."""
        merge_mode = False
        if self._current_path is not None:
            current_name = self._current_path.stem
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText('How would you like to import the file(s)?')
            import_btn = msg_box.addButton('Import as new database(s)', QMessageBox.ButtonRole.AcceptRole)
            merge_btn = msg_box.addButton(f'Merge into "{current_name}"', QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            for _btn in msg_box.buttons():
                _btn.setMinimumWidth(200)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if clicked is None or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            merge_mode = clicked is merge_btn
            _ = import_btn  # suppress unused-variable warning

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
        skipped = 0

        for file_path_str in file_paths:
            src = Path(file_path_str)
            if not src.is_file():
                continue

            dest = target_dir / src.name

            if dest.exists():
                result = QMessageBox.warning(
                    self,
                    TITLE,
                    f'"{src.name}" already exists in the destination folder.\n\nOverwrite it?',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if result != QMessageBox.StandardButton.Yes:
                    skipped += 1
                    continue

            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            imported += 1

        parts: list[str] = []
        if imported:
            parts.append(f'Imported {imported} file{"s" if imported != 1 else ""}')
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
        current_settings = self._read_settings_from_widgets()

        if imported_settings != current_settings:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText(
                f'The settings in "{src_path.name}" differ from the current database\'s settings.\n\n'
                'Which settings would you like to keep?',
            )
            keep_button = msg_box.addButton('Keep existing settings', QMessageBox.ButtonRole.AcceptRole)
            use_button = msg_box.addButton('Use imported settings', QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if clicked is None or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            if clicked is use_button:
                self._populate_settings_widgets(imported_settings)
                self._dirty = True
            _ = keep_button  # suppress unused-variable warning

        added = 0
        for username, ip in iter_userip_entries(content):
            self._append_row(username, ip, index=self._next_index)  # pylint: disable=no-member
            self._next_index += 1  # pylint: disable=no-member
            added += 1

        if added:
            self._dirty = True
            self._highlight_duplicates()

        self._set_status(
            f'Merged {added} entr{"y" if added == 1 else "ies"} from "{src_path.name}" into "{self._current_path.name}".'
            + (' Remember to save.' if added else ''),
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
                ini_members = [m for m in zf.infolist() if not m.is_dir() and m.filename.lower().endswith('.ini')]

                if not ini_members:
                    QMessageBox.information(self, TITLE, 'No .ini database files found in the selected ZIP archive.')
                    return

                imported = 0
                skipped = 0
                overwrite_all = False

                for member in ini_members:
                    dest = USERIP_DATABASES_DIR_PATH / member.filename

                    if dest.exists() and not overwrite_all:
                        msg_box = QMessageBox(self)
                        msg_box.setWindowTitle(TITLE)
                        msg_box.setText(f'"{member.filename}" already exists.\n\nOverwrite it?')
                        overwrite_btn = msg_box.addButton('Overwrite', QMessageBox.ButtonRole.YesRole)
                        overwrite_all_btn = msg_box.addButton('Overwrite All', QMessageBox.ButtonRole.YesRole)
                        skip_btn = msg_box.addButton('Skip', QMessageBox.ButtonRole.NoRole)
                        msg_box.addButton('Cancel', QMessageBox.ButtonRole.RejectRole)
                        msg_box.exec()

                        clicked = msg_box.clickedButton()
                        if clicked is None or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                            break
                        if clicked is overwrite_all_btn:
                            overwrite_all = True
                        elif clicked is skip_btn:
                            skipped += 1
                            continue
                        _ = overwrite_btn  # suppress unused-variable warning

                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(zf.read(member.filename))
                    imported += 1

        except zipfile.BadZipFile:
            QMessageBox.critical(self, TITLE, f'"{zip_path.name}" is not a valid ZIP archive.')
            return

        parts: list[str] = []
        if imported:
            parts.append(f'Imported {imported} database{"s" if imported != 1 else ""} from ZIP')
        if skipped:
            parts.append(f'{skipped} skipped')
        if parts:
            self._set_status('  |  '.join(parts))
            self._refresh_stats()
