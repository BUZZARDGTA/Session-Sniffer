"""Tree-panel operations mixin for the UserIP Databases Manager dialog."""

import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, QSignalBlocker, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QStandardItemModel
from PySide6.QtWidgets import QCheckBox, QDialog, QFileDialog, QFileSystemModel, QFrame, QInputDialog, QLineEdit, QMenu, QMessageBox, QPushButton, QTreeView

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import GITHUB_WIKI_USERIP_CONFIG_URL, TITLE
from session_sniffer.guis.looky_text import (
    configure_looky_action,
)
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.userip_manager_helpers import (
    NEW_DATABASE_TEMPLATE,
    iter_userip_entries,
)
from session_sniffer.guis.utils import open_file_location
from session_sniffer.settings.settings import Settings
from session_sniffer.text_templates import DEFAULT_USERIP_FILES_SETTINGS_INI, USERIP_DEFAULT_DB_FOOTER_TEMPLATE, USERIP_DEFAULT_DB_HEADER_TEMPLATE
from session_sniffer.text_utils import format_triple_quoted_text

if TYPE_CHECKING:
    from session_sniffer.guis.file_watch import DebouncedFileWatcher

logger = logging.getLogger(__name__)


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
    _fs_watcher: DebouncedFileWatcher
    _global_search_active: bool
    _global_search_checkbox: QCheckBox
    _settings_snapshot: dict[str, str]

    def _clear_dirty_state(self) -> None: ...

    def _mark_entries_dirty(self) -> None: ...

    def _mark_settings_dirty(self) -> None: ...

    def _refresh_protection_visibility(self) -> None: ...

    def _set_status(self, text: str) -> None:
        raise NotImplementedError

    def _refresh_stats(self) -> None: ...

    def _load_database(self, path: Path) -> None:
        raise NotImplementedError

    def _update_file_info(self, path: Path | None) -> None:
        raise NotImplementedError

    def _append_row(self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None, is_looky: bool = False) -> None:
        raise NotImplementedError

    def _backup_databases_now(self) -> None: ...

    def _export_database_file(self, path: Path) -> None:
        raise NotImplementedError

    def _import_database_files(self) -> None: ...

    def _open_backups_folder(self) -> None: ...

    def _unwatch_path(self, path: Path) -> None:
        """Remove *path* and any of its descendants from the filesystem watcher."""
        self._fs_watcher.remove_paths([path])

    # ------------------------------------------------------------------
    # Tree selection
    # ------------------------------------------------------------------

    def _on_tree_selection_changed(self) -> None:
        """Load the selected database when a .ini file is clicked in the tree."""
        indexes = self._tree.selectedIndexes()

        if not indexes:
            self._delete_tree_button.setEnabled(False)
            self._delete_tree_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')))
            self._delete_tree_button.setText(' Delete')
            self._delete_tree_button.setToolTip('Delete the selected database or folder')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._delete_tree_item)
            return

        file_path_str = self._fs_model.filePath(indexes[0])
        if not file_path_str:
            self._delete_tree_button.setEnabled(True)
            self._delete_tree_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')))
            self._delete_tree_button.setText(' Delete')
            self._delete_tree_button.setToolTip('Delete the selected database or folder')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._delete_tree_item)
            return

        path = Path(file_path_str)
        if path.parent == USERIP_DATABASES_DIR_PATH and path.name in DEFAULT_USERIP_FILES_SETTINGS_INI:
            self._delete_tree_button.setEnabled(True)
            self._delete_tree_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')))
            self._delete_tree_button.setText(' Reset')
            self._delete_tree_button.setToolTip('Reset this default database to factory content')
            self._delete_tree_button.clicked.disconnect()
            self._delete_tree_button.clicked.connect(self._reset_tree_item)
        else:
            self._delete_tree_button.setEnabled(True)
            self._delete_tree_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')))
            self._delete_tree_button.setText(' Delete')
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
        self._save_button.setEnabled(self._dirty)
        if self._export_selected_action is not None:
            self._export_selected_action.setEnabled(True)

    def refresh_runtime_capabilities(self) -> None:
        """Refresh capability-gated controls after runtime feature set / interface changes."""
        if self._global_search_active or self._current_path is None:
            return
        self._refresh_protection_visibility()

    def _reselect_current_path(self) -> None:
        """Revert the tree selection back to the currently loaded database file."""
        if self._current_path is None:
            return

        selection = self._tree.selectionModel()
        if not selection:
            return

        current_index = self._fs_model.index(str(self._current_path))
        if not current_index.isValid():
            return

        with QSignalBlocker(selection):
            self._tree.setCurrentIndex(current_index)

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
            except OSError as e:
                logger.warning('Failed to read database file %s: %s', db_path, e)
                continue
            ip_addresses = [ip_address for _, ip_address in iter_userip_entries(content)]
            if ip_addresses:
                entries.append((db_path, ip_addresses))

        if not entries:
            QMessageBox.information(self, TITLE, 'No IPs found in the selected database(s).')
            return

        looky_refresh_userip_entries(self, entries)

    def _show_tree_context_menu(self, position: QPoint) -> None:
        """Show a right-click context menu for the file tree."""
        index = self._tree.indexAt(position)
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        if index.isValid():
            file_path = Path(self._fs_model.filePath(index))

            if file_path.is_dir():
                new_db_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'new_file.svg')), 'New Database Here', self)
                new_db_action.triggered.connect(lambda: self._new_database(parent_dir=file_path))
                menu.addAction(new_db_action)

                new_folder_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'New Folder Here', self)
                new_folder_action.triggered.connect(lambda: self._new_folder(parent_dir=file_path))
                menu.addAction(new_folder_action)

                if Settings.is_gta5_feature_set():
                    menu.addSeparator()
                    _dir_path = file_path
                    refresh_dir_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Add Usernames in Folder (Looky)', self)
                    refresh_dir_action.triggered.connect(lambda: self._refresh_databases_looky(list(_dir_path.rglob('*.ini'))))
                    configure_looky_action(refresh_dir_action, 'Look up all IPs in this folder via Looky System and add any new usernames.')
                    menu.addAction(refresh_dir_action)

                menu.addSeparator()

            move_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'move_box.svg')), 'Move to...', self)
            move_action.triggered.connect(lambda: self._move_tree_item(file_path))
            menu.addAction(move_action)

            rename_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')), 'Rename', self)
            rename_action.triggered.connect(lambda: self._rename_tree_item(file_path))
            menu.addAction(rename_action)

            menu.addSeparator()

            explorer_target = file_path
            open_explorer_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open in Explorer', self)
            open_explorer_action.triggered.connect(lambda: open_file_location(explorer_target))
            menu.addAction(open_explorer_action)

            if file_path.is_file():
                open_editor_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), 'Open in Text Editor', self)
                open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path))))
                menu.addAction(open_editor_action)

                menu.addSeparator()

                if Settings.is_gta5_feature_set() and file_path.suffix.lower() == '.ini':
                    _file_path = file_path
                    refresh_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Add Usernames (Looky System)', self)
                    refresh_action.triggered.connect(lambda: self._refresh_databases_looky([_file_path]))
                    configure_looky_action(refresh_action, 'Look up all IPs in this database via Looky System and add any new usernames.')
                    menu.addAction(refresh_action)
                    menu.addSeparator()

                export_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), 'Export Database…', self)
                export_action.triggered.connect(lambda: self._export_database_file(file_path))
                menu.addAction(export_action)

            menu.addSeparator()

            if file_path.parent == USERIP_DATABASES_DIR_PATH and file_path.name in DEFAULT_USERIP_FILES_SETTINGS_INI:
                reset_default_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), 'Reset', self)
                reset_default_action.triggered.connect(lambda: self._reset_default_database(file_path))
                menu.addAction(reset_default_action)
            else:
                delete_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), 'Delete', self)
                delete_action.triggered.connect(lambda: self._delete_path(file_path))
                menu.addAction(delete_action)
        else:
            new_db_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'new_file.svg')), 'New Database', self)
            new_db_action.triggered.connect(self._new_database)
            menu.addAction(new_db_action)

            new_folder_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'New Folder', self)
            new_folder_action.triggered.connect(self._new_folder)
            menu.addAction(new_folder_action)

            if Settings.is_gta5_feature_set():
                menu.addSeparator()
                refresh_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Add Usernames in All Databases (Looky)', self)
                refresh_all_action.triggered.connect(lambda: self._refresh_databases_looky(list(USERIP_DATABASES_DIR_PATH.rglob('*.ini'))))
                configure_looky_action(refresh_all_action, 'Look up all IPs across all UserIP databases via Looky System and add any new usernames.')
                menu.addAction(refresh_all_action)

            menu.addSeparator()

            import_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), 'Import Database Files…', self)
            import_action.triggered.connect(self._import_database_files)
            menu.addAction(import_action)

            menu.addSeparator()

            backup_now_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), 'Backup Databases Now', self)
            backup_now_action.triggered.connect(self._backup_databases_now)
            menu.addAction(backup_now_action)

            open_backups_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open Backups Folder', self)
            open_backups_action.triggered.connect(self._open_backups_folder)
            menu.addAction(open_backups_action)

        viewport = self._tree.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(position))

    # ------------------------------------------------------------------
    # Tree operations
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

        self._unwatch_path(path)

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
            self._clear_dirty_state()
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

        self._unwatch_path(path)

        shutil.move(str(path), str(new_path))

        if self._current_path == path:
            self._current_path = new_path

        self._set_status(f'Moved "{path.name}" → {dest.relative_to(USERIP_DATABASES_DIR_PATH) or "root"}')

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
                except OSError as e:
                    logger.warning('Failed to delete user database file %s: %s', ini_path, e)

        # Remove user-created subdirectories
        for entry in USERIP_DATABASES_DIR_PATH.iterdir():
            if entry.is_dir():
                self._unwatch_path(entry)
                try:
                    shutil.rmtree(entry)
                except OSError as e:
                    logger.warning('Failed to remove user database directory %s: %s', entry, e)

        self._set_status(
            'Reset complete'
            + (f'  |  Restored {restored} default file{"s" if restored != 1 else ""}' if restored else '')
            + (f'  |  Deleted {deleted} user file{"s" if deleted != 1 else ""}' if deleted else ''),
        )
        self._refresh_stats()

        if deleted > 0:
            self._current_path = None
            self._clear_dirty_state()
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
