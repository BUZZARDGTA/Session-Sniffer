"""Entries context-menu mixin for the UserIP Databases Manager dialog."""

from pathlib import Path

from PyQt6.QtCore import QItemSelectionModel, QModelIndex, QPoint, Qt, QUrl
from PyQt6.QtGui import QAction, QDesktopServices, QFileSystemModel, QStandardItemModel
from PyQt6.QtWidgets import QApplication, QCheckBox, QDialog, QMenu, QPushButton, QTreeView

from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    RANGE_COLUMN,
    RE_USERIP_INI_PARSER_PATTERN,
    SECTION_USERIP,
    USERNAME_COLUMN,
    EntriesSortProxy,
    handle_ini_section_header,
)

_MixinBase = QDialog


class EntriesContextMenuMixin(_MixinBase):  # pylint: disable=too-few-public-methods
    """Mixin providing entries-table context menu and related navigation helpers.

    Expects these attributes on the concrete class:
        _entries_table, _proxy, _model, _global_search_active, _current_path,
        _global_search_checkbox, _open_db_button, _tree, _fs_model
    And these methods:
        _add_entry, _insert_entry_at, _move_rows, _get_row_entry_value,
        _load_database, _open_in_explorer
    """

    # -- Attribute stubs for type checkers --
    _entries_table: QTreeView
    _proxy: EntriesSortProxy
    _model: QStandardItemModel
    _global_search_active: bool
    _current_path: Path | None
    _global_search_checkbox: QCheckBox
    _open_db_button: QPushButton
    _tree: QTreeView
    _fs_model: QFileSystemModel

    def _add_entry(self) -> None: ...

    def _edit_entry_ip(self, source_row: int) -> None: ...  # pylint: disable=unused-argument

    def _insert_entry_at(self, source_row: int) -> None: ...  # pylint: disable=unused-argument

    def _move_rows(self, proxy_index: QModelIndex, direction: int) -> None: ...  # pylint: disable=unused-argument

    def _get_row_entry_value(self, row: int) -> str:  # pylint: disable=unused-argument  # noqa: ARG002
        return ''

    def _load_database(self, path: Path) -> None: ...  # pylint: disable=unused-argument

    def _update_entry_counts(self) -> None: ...

    @staticmethod
    def _open_in_explorer(path: Path) -> None: ...  # pylint: disable=unused-argument

    # ------------------------------------------------------------------
    # Entries: context menu
    # ------------------------------------------------------------------

    def _show_entries_context_menu(self, position: QPoint) -> None:
        """Show a right-click context menu for the entries table."""
        menu = QMenu(self)
        index = self._entries_table.indexAt(position)

        if self._global_search_active:
            if not index.isValid():
                return
            self._build_global_search_context_menu(menu, index)
        else:
            if self._current_path is None:
                return
            if index.isValid():
                self._build_entry_context_menu(menu, index)
            else:
                add_action = QAction('+ Add Entry', self)
                add_action.triggered.connect(self._add_entry)
                menu.addAction(add_action)

        if menu.isEmpty():
            return

        viewport = self._entries_table.viewport()
        if viewport is not None:
            menu.popup(viewport.mapToGlobal(position))

    def _build_entry_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a single entry row in normal editing mode."""
        source_index = self._proxy.mapToSource(index)
        row = source_index.row()
        username_item = self._model.item(row, USERNAME_COLUMN)
        username = username_item.text() if username_item else ''
        ip_or_range = self._get_row_entry_value(row)

        if username:
            copy_user_action = QAction(f'📋 Copy Username  ({username})', self)
            copy_user_action.triggered.connect(lambda: self._copy_to_clipboard(username))
            menu.addAction(copy_user_action)
        if ip_or_range:
            range_item = self._model.item(row, RANGE_COLUMN)
            label = 'Range' if range_item is not None and range_item.text().strip() else 'IP'
            copy_ip_action = QAction(f'📋 Copy {label}  ({ip_or_range})', self)
            copy_ip_action.triggered.connect(lambda: self._copy_to_clipboard(ip_or_range))
            menu.addAction(copy_ip_action)
        if username and ip_or_range:
            copy_both_action = QAction('📋 Copy Username & Entry', self)
            copy_both_action.triggered.connect(lambda: self._copy_to_clipboard(f'{username}={ip_or_range}'))
            menu.addAction(copy_both_action)

        if not menu.isEmpty():
            menu.addSeparator()

        source_row = self._proxy.mapToSource(index).row()

        edit_ip_action = QAction('🔧 Edit IP/Range…', self)
        edit_ip_action.triggered.connect(lambda: self._edit_entry_ip(source_row))
        menu.addAction(edit_ip_action)

        menu.addSeparator()

        if source_row > 0:
            move_up_action = QAction('🔼 Move Up', self)
            move_up_action.triggered.connect(lambda: self._move_rows(index, -1))
            menu.addAction(move_up_action)
        if source_row < self._model.rowCount() - 1:
            move_down_action = QAction('🔽 Move Down', self)
            move_down_action.triggered.connect(lambda: self._move_rows(index, 1))
            menu.addAction(move_down_action)

        menu.addSeparator()

        insert_above_action = QAction('⬆ Insert Entry Above', self)
        insert_above_action.triggered.connect(lambda: self._insert_entry_at(source_row))
        menu.addAction(insert_above_action)

        insert_below_action = QAction('⬇ Insert Entry Below', self)
        insert_below_action.triggered.connect(lambda: self._insert_entry_at(source_row + 1))
        menu.addAction(insert_below_action)

        add_action = QAction('+ Add Entry to End', self)
        add_action.triggered.connect(self._add_entry)
        menu.addAction(add_action)

    def _build_global_search_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a row in global search (read-only) mode."""
        source_index = self._proxy.mapToSource(index)
        row = source_index.row()
        username_item = self._model.item(row, USERNAME_COLUMN)
        db_item = self._model.item(row, DATABASE_COLUMN)
        username = username_item.text() if username_item else ''
        ip_or_range = self._get_row_entry_value(row)
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None

        # --- Copy actions ---
        if username:
            copy_user_action = QAction(f'📋 Copy Username  ({username})', self)
            copy_user_action.triggered.connect(lambda: self._copy_to_clipboard(username))
            menu.addAction(copy_user_action)
        if ip_or_range:
            range_item = self._model.item(row, RANGE_COLUMN)
            label = 'Range' if range_item is not None and range_item.text().strip() else 'IP'
            copy_ip_action = QAction(f'📋 Copy {label}  ({ip_or_range})', self)
            copy_ip_action.triggered.connect(lambda: self._copy_to_clipboard(ip_or_range))
            menu.addAction(copy_ip_action)
        if username and ip_or_range:
            copy_both_action = QAction('📋 Copy Username & Entry', self)
            copy_both_action.triggered.connect(lambda: self._copy_to_clipboard(f'{username}={ip_or_range}'))
            menu.addAction(copy_both_action)

        # --- Database navigation actions ---
        if db_path_str:
            db_path = Path(db_path_str)
            menu.addSeparator()

            go_to_db_action = QAction(f'➡️ Go to Database  ({db_path.stem})', self)
            go_to_db_action.triggered.connect(lambda: self._navigate_to_database(db_path))
            menu.addAction(go_to_db_action)

            open_editor_action = QAction(f'📝 Open in Text Editor  ({db_path.stem})', self)
            open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db_path))))
            menu.addAction(open_editor_action)

            open_explorer_action = QAction(f'📂 Open in Explorer  ({db_path.stem})', self)
            open_explorer_action.triggered.connect(lambda: self._open_in_explorer(db_path))
            menu.addAction(open_explorer_action)

            if username and ip_or_range:
                menu.addSeparator()

                delete_action = QAction(f'🗑 Delete Entry  ({db_path.stem})', self)
                delete_action.triggered.connect(lambda: self._delete_global_search_entry(db_path, username, ip_or_range, row))
                menu.addAction(delete_action)

    def _delete_global_search_entry(self, db_path: Path, username: str, ip_or_range: str, source_row: int) -> None:
        """Remove a single entry from the database file and from the search results table."""
        content = db_path.read_text('utf-8')
        lines = content.splitlines()
        new_lines: list[str] = []
        in_userip_section = False
        removed = False

        for raw_line in lines:
            stripped = raw_line.strip()
            is_header, in_userip_section = handle_ini_section_header(raw_line, stripped, new_lines, in_section=in_userip_section, section_name=SECTION_USERIP)
            if is_header:
                continue

            if in_userip_section and not removed:
                m = RE_USERIP_INI_PARSER_PATTERN.search(stripped)
                if m:
                    u_raw = m.group('username')
                    ip_raw = m.group('ip')
                    if u_raw is not None and ip_raw is not None and u_raw.strip() == username and ip_raw.strip() == ip_or_range:
                        removed = True
                        continue

            new_lines.append(raw_line)

        if not removed:
            return

        db_path.write_text('\n'.join(new_lines), encoding='utf-8')
        self._model.removeRow(source_row)
        self._update_entry_counts()

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        """Copy the given text to the system clipboard."""
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)

    def _navigate_to_database(self, db_path: Path) -> None:
        """Exit global search mode and open the given database in the tree."""
        self._global_search_checkbox.setChecked(False)
        self._current_path = db_path
        self._load_database(db_path)
        self._open_db_button.setEnabled(True)

        # Select the database in the tree
        tree_index = self._fs_model.index(str(db_path))
        if tree_index.isValid():
            selection = self._tree.selectionModel()
            if selection is not None:
                selection.select(tree_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
                self._tree.scrollTo(tree_index)

    def _on_entry_double_clicked(self, index: QModelIndex) -> None:
        """Handle double-click on an entry row in global search mode."""
        if not self._global_search_active or not index.isValid():
            return
        source_index = self._proxy.mapToSource(index)
        db_item = self._model.item(source_index.row(), DATABASE_COLUMN)
        if db_item is None:
            return
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole)
        if db_path_str:
            self._navigate_to_database(Path(db_path_str))
