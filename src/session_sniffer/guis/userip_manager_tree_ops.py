"""Tree-panel operations mixin for the UserIP Databases Manager dialog."""

import contextlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from PyQt6.QtCore import QPoint, Qt, QUrl
from PyQt6.QtGui import QAction, QDesktopServices, QFileSystemModel, QStandardItemModel
from PyQt6.QtWidgets import QCheckBox, QDialog, QFileDialog, QFrame, QInputDialog, QLineEdit, QMenu, QMessageBox, QPushButton, QTreeView

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import GITHUB_WIKI_USERIP_CONFIG_URL, TITLE
from session_sniffer.guis.looky_text import (
    LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS,
    LOOKY_MENU_TOOLTIP_API_KEY_MISSING,
    LOOKY_MENU_TOOLTIP_DISABLED,
)
from session_sniffer.guis.tables_player_actions._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.userip_manager_helpers import (
    NEW_DATABASE_TEMPLATE,
    SETTINGS_DEFAULTS,
    SETTINGS_KEYS_ORDER,
    iter_userip_entries,
    parse_settings_from_content,
    parse_settings_from_lines,
    read_preserved_sections,
)
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_templates import DEFAULT_USERIP_FILES_SETTINGS_INI, USERIP_DEFAULT_DB_FOOTER_TEMPLATE, USERIP_DEFAULT_DB_HEADER_TEMPLATE
from session_sniffer.text_utils import format_triple_quoted_text


class TreeOperationsMixin(QDialog):
    """Mixin providing tree-panel context menu and file-system operations.

    Expects these attributes on the concrete class:
        _tree, _fs_model, _current_path, _dirty, _model, _open_db_button
    And these methods:
        _set_status, _refresh_stats, _load_database, _update_file_info
    """

    # -- Attribute stubs for type checkers --
    _tree: QTreeView
    _fs_model: QFileSystemModel
    _current_path: Path | None
    _dirty: bool
    _next_index: int = 0
    _model: QStandardItemModel
    _open_db_button: QPushButton
    _export_selected_action: QAction | None
    _settings_container: QFrame
    _save_button: QPushButton
    _add_button: QPushButton
    _edit_ip_button: QPushButton
    _delete_button: QPushButton
    _delete_tree_button: QPushButton
    _entries_dirty: bool
    _global_search_active: bool
    _global_search_checkbox: QCheckBox
    _settings_snapshot: dict[str, str]

    # pylint: disable=unused-argument
    def _mark_entries_dirty(self) -> None: ...
    def _mark_settings_dirty(self) -> None: ...
    def _refresh_protection_visibility(self) -> None: ...
    def _set_status(self, text: str) -> None: ...
    def _refresh_stats(self) -> None: ...
    def _load_database(self, path: Path) -> None: ...
    def _update_file_info(self, path: Path | None) -> None: ...
    def _append_row(self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None) -> None: ...

    # pylint: enable=unused-argument

    def populate_settings_widgets(self, settings_dict: dict[str, str]) -> None:
        """Populate settings widgets from *settings_dict*."""

    def _highlight_duplicates(self) -> int:
        raise NotImplementedError

    def read_settings_from_widgets(self) -> dict[str, str]:
        """Read current widget values and return them as a settings dict."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Tree: selection
    # ------------------------------------------------------------------

    def _on_tree_selection_changed(self) -> None:
        """Load the selected database when a .ini file is clicked in the tree."""
        indexes = self._tree.selectedIndexes()

        if not indexes:
            self._delete_tree_button.setEnabled(False)
            self._delete_tree_button.setText('🗑️ Delete')
            self._delete_tree_button.setToolTip('Delete the selected database or folder')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._delete_tree_item)
            return

        file_path_str = self._fs_model.filePath(indexes[0])
        if not file_path_str:
            self._delete_tree_button.setEnabled(True)
            self._delete_tree_button.setText('🗑️ Delete')
            self._delete_tree_button.setToolTip('Delete the selected database or folder')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._delete_tree_item)
            return

        path = Path(file_path_str)
        if path.parent == USERIP_DATABASES_DIR_PATH and path.name in DEFAULT_USERIP_FILES_SETTINGS_INI:
            self._delete_tree_button.setEnabled(True)
            self._delete_tree_button.setText('🔄 Reset')
            self._delete_tree_button.setToolTip('Reset this default database to factory content')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._reset_tree_item)
        else:
            self._delete_tree_button.setEnabled(True)
            self._delete_tree_button.setText('🗑️ Delete')
            self._delete_tree_button.setToolTip('Delete the selected database or folder')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._delete_tree_item)

        if not path.is_file() or path.suffix.lower() != '.ini':
            return

        if path == self._current_path and not self._global_search_active:
            return

        if self._global_search_active:
            self._global_search_checkbox.setChecked(False)

        if self._dirty and not self._confirm_discard():
            self._reselect_current_path()
            return

        self._current_path = path
        self._load_database(path)
        self._open_db_button.setEnabled(True)
        self._add_button.setEnabled(True)
        self._delete_button.setEnabled(True)
        self._save_button.setEnabled(True)
        if self._export_selected_action is not None:
            self._export_selected_action.setEnabled(True)

    def refresh_runtime_capabilities(self) -> None:
        """Refresh capability-gated controls after runtime preset/interface changes."""
        if self._global_search_active or self._current_path is None:
            return
        self._refresh_protection_visibility()

    def _reselect_current_path(self) -> None:
        """Revert the tree selection back to the currently loaded database file."""
        if self._current_path is None:
            return

        selection = self._tree.selectionModel()
        if selection is None:
            return

        current_index = self._fs_model.index(str(self._current_path))
        if not current_index.isValid():
            return

        selection.blockSignals(True)  # noqa: FBT003
        self._tree.setCurrentIndex(current_index)
        selection.blockSignals(False)  # noqa: FBT003

    # ------------------------------------------------------------------
    # Discard confirmation
    # ------------------------------------------------------------------

    def _confirm_discard(self) -> bool:
        """Ask the user whether to discard unsaved changes."""
        result = QMessageBox.warning(
            self,
            TITLE,
            'You have unsaved changes. Discard them?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return result == QMessageBox.StandardButton.Yes

    # ------------------------------------------------------------------
    # Tree: context menu
    # ------------------------------------------------------------------

    def _refresh_databases_looky(self, db_paths: list[Path]) -> None:
        """Collect all IPs from the given database files and refresh their usernames via Looky System."""
        entries: list[tuple[Path, list[str]]] = []
        for db_path in db_paths:
            if not db_path.is_file() or db_path.suffix.lower() != '.ini':
                continue
            try:
                content = db_path.read_text('utf-8')
            except OSError:
                continue
            ips = [ip for _, ip in iter_userip_entries(content)]
            if ips:
                entries.append((db_path, ips))

        if not entries:
            QMessageBox.information(self, TITLE, 'No IPs found in the selected database(s).')
            return

        looky_refresh_userip_entries(self, entries)

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

                if Settings.is_gta5_preset():
                    menu.addSeparator()
                    _dir_path = file_path
                    refresh_dir_action = QAction('👁 Add Usernames in Folder (Looky)', self)
                    refresh_dir_action.triggered.connect(lambda: self._refresh_databases_looky(list(_dir_path.rglob('*.ini'))))
                    if not Settings.looky_enabled:
                        refresh_dir_action.setEnabled(False)
                        refresh_dir_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
                    elif not Settings.looky_api_key:
                        refresh_dir_action.setEnabled(False)
                        refresh_dir_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
                    elif not LookyState.api_access:
                        refresh_dir_action.setEnabled(False)
                        refresh_dir_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
                    else:
                        refresh_dir_action.setToolTip('Look up all IPs in this folder via Looky System and add any new usernames.')
                    menu.addAction(refresh_dir_action)

                menu.addSeparator()

            move_action = QAction('📦 Move to...', self)
            move_action.triggered.connect(lambda: self._move_tree_item(file_path))
            menu.addAction(move_action)

            rename_action = QAction('✏️ Rename', self)
            rename_action.triggered.connect(lambda: self._rename_tree_item(file_path))
            menu.addAction(rename_action)

            if file_path.parent == USERIP_DATABASES_DIR_PATH and file_path.name in DEFAULT_USERIP_FILES_SETTINGS_INI:
                reset_default_action = QAction('🔄 Reset', self)
                reset_default_action.triggered.connect(lambda: self._reset_default_database(file_path))
                menu.addAction(reset_default_action)
            else:
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

                if Settings.is_gta5_preset() and file_path.suffix.lower() == '.ini':
                    _file_path = file_path
                    refresh_action = QAction('👁 Add Usernames (Looky)', self)
                    refresh_action.triggered.connect(lambda: self._refresh_databases_looky([_file_path]))
                    if not Settings.looky_enabled:
                        refresh_action.setEnabled(False)
                        refresh_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
                    elif not Settings.looky_api_key:
                        refresh_action.setEnabled(False)
                        refresh_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
                    elif not LookyState.api_access:
                        refresh_action.setEnabled(False)
                        refresh_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
                    else:
                        refresh_action.setToolTip('Look up all IPs in this database via Looky System and add any new usernames.')
                    menu.addAction(refresh_action)
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

            if Settings.is_gta5_preset():
                menu.addSeparator()
                refresh_all_action = QAction('👁 Add Usernames in All Databases (Looky)', self)
                refresh_all_action.triggered.connect(lambda: self._refresh_databases_looky(list(USERIP_DATABASES_DIR_PATH.rglob('*.ini'))))
                if not Settings.looky_enabled:
                    refresh_all_action.setEnabled(False)
                    refresh_all_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
                elif not Settings.looky_api_key:
                    refresh_all_action.setEnabled(False)
                    refresh_all_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
                elif not LookyState.api_access:
                    refresh_all_action.setEnabled(False)
                    refresh_all_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
                else:
                    refresh_all_action.setToolTip('Look up all IPs across all UserIP databases via Looky System and add any new usernames.')
                menu.addAction(refresh_all_action)

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

        name, success = QInputDialog.getText(self, TITLE, 'New database name:')
        if not success or not name.strip():
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

        name, success = QInputDialog.getText(self, TITLE, 'New folder name:')
        if not success or not name.strip():
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

        self._delete_path(Path(self._fs_model.filePath(indexes[0])))

    def _reset_tree_item(self) -> None:
        """Reset the currently selected default database to factory content."""
        indexes = self._tree.selectedIndexes()
        if not indexes:
            return

        self._reset_default_database(Path(self._fs_model.filePath(indexes[0])))

    def _delete_path(self, path: Path) -> None:
        """Delete a file or folder with user confirmation."""
        if path.is_dir():
            children = list(path.iterdir())
            message = f'Folder "{path.name}" is not empty ({len(children)} items).\n\nDelete it and all its contents?' if children else f'Delete empty folder "{path.name}"?'
        else:
            message = f'Delete database "{path.name}"?'

        result = QMessageBox.warning(
            self,
            TITLE,
            message,
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

    def _reset_default_database(self, path: Path) -> None:
        """Reset a single default database file to its factory content after user confirmation."""
        result = QMessageBox.warning(
            self,
            TITLE,
            f'Reset "{path.name}" to factory content?\n\nAll entries and settings in this file will be lost.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        default_file_header = format_triple_quoted_text(
            USERIP_DEFAULT_DB_HEADER_TEMPLATE.format(
                title=TITLE,
                configuration_guide_url=GITHUB_WIKI_USERIP_CONFIG_URL,
            ),
        )
        default_file_footer = format_triple_quoted_text(USERIP_DEFAULT_DB_FOOTER_TEMPLATE, add_trailing_newline=True)
        settings_block = DEFAULT_USERIP_FILES_SETTINGS_INI[path.name].strip()
        path.write_text(
            f'{default_file_header}\n\n{settings_block}\n\n{default_file_footer}',
            encoding='utf-8',
        )

        if self._current_path == path:
            self._load_database(path)

        self._set_status(f'Reset "{path.name}" to factory defaults.')
        self._refresh_stats()

    def _rename_tree_item(self, path: Path) -> None:
        """Rename a file or folder via an input dialog."""
        old_name = path.stem if path.is_file() else path.name
        label = 'New name:' if path.is_file() else 'New folder name:'

        new_name, success = QInputDialog.getText(self, TITLE, label, QLineEdit.EchoMode.Normal, old_name)
        if not success or not new_name.strip():
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

        self._set_status(f'Renamed "{path.name}" → "{new_name}"')

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

        self._set_status(f'Moved "{path.name}" → {dest.relative_to(USERIP_DATABASES_DIR_PATH) or "root"}')

    @staticmethod
    def _open_in_explorer(path: Path) -> None:
        """Open the containing folder and highlight the item in Windows Explorer."""
        if path.is_file():
            explorer_exe = Path(os.getenv('WINDIR', r'C:\Windows')) / 'explorer.exe'
            subprocess.Popen(f'"{explorer_exe}" /select,"{path}"')
        elif path.is_dir():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
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

    def _reset_all_databases(self) -> None:
        """Delete every .ini database file in the databases directory after user confirmation.

        Default databases (Blacklist, Enemylist, etc.) are restored to their factory content
        rather than deleted.  User-created .ini files and subdirectories are removed entirely.
        """
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
        ini_files = sorted(USERIP_DATABASES_DIR_PATH.rglob('*.ini'))
        if not ini_files:
            QMessageBox.information(self, TITLE, 'There are no database files to reset.')
            return

        count = len(ini_files)
        result = QMessageBox.warning(
            self,
            TITLE,
            f'This will permanently reset all {count} database file{"s" if count != 1 else ""}.\n\n'
            'Default databases will be restored to factory content.\n'
            'User-created databases will be deleted.\n\n'
            'This cannot be undone. Are you sure?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        default_db_names: set[str] = set(DEFAULT_USERIP_FILES_SETTINGS_INI.keys())
        default_file_header = format_triple_quoted_text(
            USERIP_DEFAULT_DB_HEADER_TEMPLATE.format(
                title=TITLE,
                configuration_guide_url=GITHUB_WIKI_USERIP_CONFIG_URL,
            ),
        )
        default_file_footer = format_triple_quoted_text(USERIP_DEFAULT_DB_FOOTER_TEMPLATE, add_trailing_newline=True)

        deleted = 0
        restored = 0
        for ini_path in ini_files:
            if ini_path.parent == USERIP_DATABASES_DIR_PATH and ini_path.name in default_db_names:
                settings_block = DEFAULT_USERIP_FILES_SETTINGS_INI[ini_path.name].strip()
                ini_path.write_text(
                    f'{default_file_header}\n\n{settings_block}\n\n{default_file_footer}',
                    encoding='utf-8',
                )
                restored += 1
            else:
                try:
                    ini_path.unlink()
                    deleted += 1
                except OSError:
                    pass

        # Remove user-created subdirectories
        for entry in USERIP_DATABASES_DIR_PATH.iterdir():
            if entry.is_dir():
                with contextlib.suppress(OSError):
                    shutil.rmtree(entry)

        self._set_status(
            'Reset complete'
            + (f'  |  Restored {restored} default file{"s" if restored != 1 else ""}' if restored else '')
            + (f'  |  Deleted {deleted} user file{"s" if deleted != 1 else ""}' if deleted else ''),
        )
        self._refresh_stats()

        if deleted > 0:
            self._current_path = None
            self._dirty = False
            self._model.removeRows(0, self._model.rowCount())
            self._update_file_info(None)
            self._settings_container.setVisible(False)
            self._save_button.setEnabled(False)
            self._add_button.setEnabled(False)
            self._edit_ip_button.setEnabled(False)
            self._delete_button.setEnabled(False)
            self._open_db_button.setEnabled(False)
            if self._export_selected_action is not None:
                self._export_selected_action.setEnabled(False)

    # ------------------------------------------------------------------
    # Import files
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
            if clicked is None or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
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
            current_name = self._current_path.stem
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(TITLE)
            msg_box.setText('How would you like to import the file(s)?')
            import_button = msg_box.addButton('Import as new database(s)', QMessageBox.ButtonRole.AcceptRole)
            merge_button = msg_box.addButton(f'Merge into "{current_name}"', QMessageBox.ButtonRole.AcceptRole)
            msg_box.addButton(QMessageBox.StandardButton.Cancel)
            for _button in msg_box.buttons():
                _button.setMinimumWidth(200)
                _button.setCursor(Qt.CursorShape.PointingHandCursor)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if clicked is None or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            merge_mode = clicked is merge_button
            _ = import_button  # suppress unused-variable warning

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
                    continue
                if clicked is None:
                    skipped += 1
                    continue
                _ = overwrite_button  # suppress unused-variable warning

            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            imported += 1

        parts: list[str] = []
        if imported:
            parts.append(f'Imported {imported} file{"s" if imported != 1 else ""}')
        if merged:
            parts.append(f'Merged {merged} entr{"y" if merged == 1 else "ies"}')
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
            if clicked is None or clicked is msg_box.button(QMessageBox.StandardButton.Cancel):
                return
            if clicked is use_button:
                self.populate_settings_widgets(imported_settings)
                self._mark_settings_dirty()
            _ = keep_button  # suppress unused-variable warning

        added = 0
        for username, ip in iter_userip_entries(content):
            self._append_row(username, ip, index=self._next_index)
            self._next_index += 1
            added += 1

        if added:
            self._mark_entries_dirty()
            self._highlight_duplicates()

        self._set_status(
            f'Merged {added} entr{"y" if added == 1 else "ies"} from "{src_path.name}" into "{self._current_path.name}".' + (' Remember to save.' if added else ''),
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
                        if clicked is None or clicked is cancel_button:
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
                            continue
                        _ = overwrite_button  # suppress unused-variable warning

                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(member_bytes)
                    imported += 1

        except zipfile.BadZipFile:
            QMessageBox.critical(self, TITLE, f'"{zip_path.name}" is not a valid ZIP archive.')
            return

        parts: list[str] = []
        if imported:
            parts.append(f'Imported {imported} database{"s" if imported != 1 else ""} from ZIP')
        if merged:
            parts.append(f'Merged {merged} entr{"y" if merged == 1 else "ies"} from ZIP')
        if skipped:
            parts.append(f'{skipped} skipped')
        if parts:
            self._set_status('  |  '.join(parts))
            self._refresh_stats()
