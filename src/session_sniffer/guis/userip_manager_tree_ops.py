"""Tree-panel operations mixin for the UserIP Databases Manager dialog."""

import os
import shutil
import subprocess
from pathlib import Path

from PyQt6.QtCore import QPoint, Qt, QUrl
from PyQt6.QtGui import QAction, QDesktopServices, QFileSystemModel, QStandardItemModel
from PyQt6.QtWidgets import QDialog, QFileDialog, QInputDialog, QLineEdit, QMenu, QMessageBox, QPushButton, QTreeView

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.userip_manager_helpers import NEW_DATABASE_TEMPLATE

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
    _model: QStandardItemModel
    _open_db_button: QPushButton

    def _set_status(self, text: str) -> None: ...  # pylint: disable=unused-argument
    def _refresh_stats(self) -> None: ...
    def _update_file_info(self, path: Path | None) -> None: ...  # pylint: disable=unused-argument

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
        else:
            new_db_action = QAction('📄 New Database', self)
            new_db_action.triggered.connect(self._new_database)
            menu.addAction(new_db_action)

            new_folder_action = QAction('📁 New Folder', self)
            new_folder_action.triggered.connect(self._new_folder)
            menu.addAction(new_folder_action)

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
