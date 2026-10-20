"""Entries context-menu mixin for the UserIP Databases Manager dialog."""

from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSignalBlocker, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QStandardItemModel
from PySide6.QtWidgets import QAbstractItemView, QCheckBox, QDialog, QFileSystemModel, QLineEdit, QMenu, QPushButton, QTreeView

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions import (
    create_ping_menu,
    scan_ports_ip,
    show_detailed_ip_lookup,
)
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    NOTES_COLUMN,
    RANGE_COLUMN,
    USERNAME_COLUMN,
    EntriesSortProxy,
    populate_userip_databases_menu,
)
from session_sniffer.guis.utils import copy_table_all_rows, copy_table_selection, open_file_location, set_clipboard_text
from session_sniffer.text_utils import pluralize


@dataclass(frozen=True, slots=True)
class _RowMenuContext:
    """Extracted source-row values and selection state for building an entries table context menu."""

    row: int
    username: str
    note: str
    ip_or_range: str
    selected_rows: list[QModelIndex]
    selected_count: int


class EntriesContextMenuMixin(QDialog):
    """Mixin providing entries-table context menu and related navigation helpers.

    Expects these attributes on the concrete class:
        _entries_table, _proxy, _model, _global_search_active, _current_path,
        _global_search_checkbox, _open_db_button, _tree, _fs_model
    And these methods:
        _add_entry, _add_username, _insert_entry_at, _move_rows, _get_row_entry_value,
        _load_database, _delete_selected
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
    _search_input: QLineEdit

    def _add_entry(self) -> None: ...

    def _delete_selected(self) -> None: ...

    def _rename_selected(self) -> None: ...

    def _edit_entry_ip(self, source_row: int) -> None:
        raise NotImplementedError

    def _edit_entry_note(self, source_row: int) -> None:
        raise NotImplementedError

    def _insert_entry_at(self, source_row: int) -> None:
        raise NotImplementedError

    def _add_username(self, source_row: int) -> None:
        raise NotImplementedError

    def _move_rows(self, proxy_index: QModelIndex, direction: int) -> None:
        raise NotImplementedError

    def _get_row_entry_value(self, row: int) -> str:
        raise NotImplementedError

    def _load_database(self, path: Path) -> None:
        raise NotImplementedError

    def _move_selected_to_database(self, target_db_path: Path) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Entries: context menu
    # ------------------------------------------------------------------

    def show_entries_context_menu(self, position: QPoint) -> None:
        """Show a right-click context menu for the entries table."""
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        index = self._entries_table.indexAt(position)

        selection_model = self._entries_table.selectionModel()
        if selection_model and index.isValid() and not selection_model.isSelected(index):
            selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

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
                add_entry_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')), 'Add Entry', self)
                add_entry_action.setToolTip('Open the IP Range Builder dialog and insert the result as a new entry.')
                add_entry_action.triggered.connect(self._add_entry)
                menu.addAction(add_entry_action)

        if menu.isEmpty():
            return

        viewport = self._entries_table.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(position))

    def _extract_row_context(self, index: QModelIndex) -> _RowMenuContext:
        """Return a `_RowMenuContext` for *index* and the current table selection."""
        row = self._proxy.mapToSource(index).row()
        username_item = self._model.item(row, USERNAME_COLUMN)
        notes_item = self._model.item(row, NOTES_COLUMN)
        username = username_item.text() if username_item else ''
        note = notes_item.text().strip() if notes_item else ''
        ip_or_range = self._get_row_entry_value(row)
        selection_model = self._entries_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        selected_count = len(selected_rows) if selected_rows else 1
        return _RowMenuContext(
            row=row,
            username=username,
            note=note,
            ip_or_range=ip_or_range,
            selected_rows=selected_rows,
            selected_count=selected_count,
        )

    def _add_copy_actions(self, menu: QMenu, context: _RowMenuContext) -> None:
        """Add row copy, Copy All, and cell-value copy actions to *menu*."""
        copy_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg'))
        copy_row_label = f'Copy Rows ({context.selected_count})' if context.selected_count > 1 else 'Copy Row'
        copy_row_action = QAction(copy_icon, copy_row_label, self)
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setToolTip(f'Copy selected row{pluralize(context.selected_count)} to the clipboard as tab-separated text.')
        copy_row_action.triggered.connect(self._copy_selected_entries)
        menu.addAction(copy_row_action)

        copy_all_action = QAction(copy_icon, 'Copy All', self)
        copy_all_action.setToolTip('Copy all visible entries to the clipboard as tab-separated text.')
        copy_all_action.setEnabled(self._proxy.rowCount() > 0)
        copy_all_action.triggered.connect(self._copy_all_entries)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        if context.selected_count <= 1:
            if context.username:
                copy_user_action = QAction(copy_icon, 'Copy Username', self)
                copy_user_action.triggered.connect(lambda: set_clipboard_text(context.username))
                menu.addAction(copy_user_action)
            if context.ip_or_range:
                range_item = self._model.item(context.row, RANGE_COLUMN)
                label = 'Range' if range_item and range_item.text().strip() else 'IP'
                copy_ip_action = QAction(copy_icon, f'Copy {label}', self)
                copy_ip_action.triggered.connect(lambda: set_clipboard_text(context.ip_or_range))
                menu.addAction(copy_ip_action)
            if context.note:
                copy_note_action = QAction(copy_icon, 'Copy Note', self)
                copy_note_action.triggered.connect(lambda: set_clipboard_text(context.note))
                menu.addAction(copy_note_action)
        else:
            all_usernames: list[str] = []
            all_ips_or_ranges: list[str] = []
            for selected_index in context.selected_rows:
                source_row = self._proxy.mapToSource(selected_index).row()
                username_item = self._model.item(source_row, USERNAME_COLUMN)
                if username_item and username_item.text():
                    all_usernames.append(username_item.text())
                entry_value = self._get_row_entry_value(source_row)
                if entry_value:
                    all_ips_or_ranges.append(entry_value)

            if all_usernames:
                copy_users_action = QAction(copy_icon, f'Copy Usernames ({len(all_usernames)})', self)
                copy_users_action.triggered.connect(lambda: set_clipboard_text('\n'.join(all_usernames)))
                menu.addAction(copy_users_action)
            if all_ips_or_ranges:
                copy_ips_action = QAction(copy_icon, f'Copy IPs / Ranges ({len(all_ips_or_ranges)})', self)
                copy_ips_action.triggered.connect(lambda: set_clipboard_text('\n'.join(all_ips_or_ranges)))
                menu.addAction(copy_ips_action)

    def _add_selection_actions(self, menu: QMenu, *, select_all_tooltip: str) -> None:
        """Add Select All and Clear Selection actions to *menu*."""
        select_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-check.svg')), 'Select All', self)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip(select_all_tooltip)
        select_all_action.setEnabled(self._proxy.rowCount() > 0)
        select_all_action.triggered.connect(self._entries_table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square.svg')), 'Clear Selection', self)
        clear_selection_action.setToolTip('Deselect all currently selected rows.')
        clear_selection_action.triggered.connect(self._entries_table.clearSelection)
        menu.addAction(clear_selection_action)

    def _collect_selected_ips(self, ip_or_range: str) -> tuple[bool, list[str]]:
        """Return `(is_single_ip, selected_ips)` for the clicked entry and current table selection."""
        is_single_ip = False
        if ip_or_range:
            try:
                IPv4Address(ip_or_range)
                is_single_ip = True
            except ValueError:
                is_single_ip = False

        selected_ips: list[str] = []
        selection_model = self._entries_table.selectionModel()
        if selection_model:
            for selected_index in selection_model.selectedRows():
                source_row = self._proxy.mapToSource(selected_index).row()
                ip_value = self._get_row_entry_value(source_row)
                try:
                    IPv4Address(ip_value)
                    if ip_value not in selected_ips:
                        selected_ips.append(ip_value)
                except ValueError:
                    pass
        return is_single_ip, selected_ips

    def _add_edit_actions(self, menu: QMenu, *, target_row: int, selected_count: int) -> None:
        """Add Rename, Edit IP/Range, and Edit Note actions to *menu*."""
        pen_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg'))
        rename_label = f'Rename Selected ({selected_count})' if selected_count > 1 else 'Rename'
        rename_action = QAction(pen_icon, rename_label, self)
        rename_action.setShortcut('F2')
        rename_action.setToolTip(f'Rename the username for the selected {pluralize(selected_count, "entry", "entries")}.')
        rename_action.triggered.connect(self._rename_selected)
        menu.addAction(rename_action)

        if selected_count <= 1:
            range_item = self._model.item(target_row, RANGE_COLUMN)
            edit_label = 'Edit Range…' if range_item and range_item.text().strip() else 'Edit IP…'
            edit_ip_action = QAction(pen_icon, edit_label, self)
            edit_ip_action.triggered.connect(lambda _checked=False, row=target_row: self._edit_entry_ip(row))
            menu.addAction(edit_ip_action)

            edit_note_action = QAction(pen_icon, 'Edit Note…', self)
            edit_note_action.setToolTip('Edit the note for this entry.')
            edit_note_action.triggered.connect(lambda _checked=False, row=target_row: self._edit_entry_note(row))
            menu.addAction(edit_note_action)

    def _add_move_to_database_menu(self, menu: QMenu, *, selected_count: int, disabled_path: Path | None) -> None:
        """Build and append the 'Move to Database' submenu to *menu*."""
        move_db_label = f'Move Selected to Database ({selected_count})' if selected_count > 1 else 'Move to Database'
        move_db_menu = QMenu(move_db_label, menu)
        move_db_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'box.svg')))
        move_db_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        move_db_menu.setToolTipsVisible(True)
        all_db_paths = [json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()]
        enabled_target_count = populate_userip_databases_menu(
            move_db_menu,
            all_db_paths,
            tooltip=f'Move selected {pluralize(selected_count, "entry", "entries")} to this database.',
            handler_factory=lambda target_path: lambda: self._move_selected_to_database(target_path),
            disabled_path=disabled_path,
        )
        if not enabled_target_count:
            move_db_menu.setEnabled(False)
            move_db_menu.setToolTip('No other databases available.')
        menu.addMenu(move_db_menu)

    def _add_network_actions(
        self,
        menu: QMenu,
        *,
        ip_or_range: str,
        is_single_ip: bool,
        selected_ips: list[str],
    ) -> None:
        """Add IP Lookup Details, Ping submenu, and Scan Ports actions when single IPs are selected."""
        if not (is_single_ip or len(selected_ips) > 1):
            return

        menu.addSeparator()

        if is_single_ip and len(selected_ips) <= 1:
            lookup_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'IP Lookup Details…', self)
            lookup_action.triggered.connect(lambda _checked=False, ip_address=ip_or_range: show_detailed_ip_lookup(ip_address))
            menu.addAction(lookup_action)

        create_ping_menu(self, menu, list(selected_ips) if len(selected_ips) > 1 else [ip_or_range])

        scan_ports_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'radar.svg')), 'Scan Ports…', self)
        scan_ports_action.setToolTip(f'Scan TCP and UDP ports on the selected host{pluralize(max(1, len(selected_ips)))}.')
        scan_target = list(selected_ips) if len(selected_ips) > 1 else ip_or_range
        scan_ports_action.triggered.connect(lambda _checked=False, target=scan_target: scan_ports_ip(target))
        menu.addAction(scan_ports_action)

    def _add_username_action(self, menu: QMenu, *, target_row: int, tooltip: str) -> None:
        """Add the 'Add Username' action with a preceding separator to *menu*."""
        menu.addSeparator()
        add_username_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')), 'Add Username', self)
        add_username_action.setToolTip(tooltip)
        add_username_action.triggered.connect(lambda _checked=False, row=target_row: self._add_username(row))
        menu.addAction(add_username_action)

    def _add_delete_selected_action(self, menu: QMenu) -> None:
        """Add the 'Delete Selected Row(s)' action with a preceding separator to *menu*."""
        selection_model = self._entries_table.selectionModel()
        selected_count = len(selection_model.selectedRows()) if selection_model else 1
        delete_label = f'Delete Selected Row{pluralize(selected_count)}'
        delete_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), delete_label, self)
        delete_action.triggered.connect(self._delete_selected)
        menu.addSeparator()
        menu.addAction(delete_action)

    def _build_entry_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a single entry row in normal editing mode."""
        context = self._extract_row_context(index)

        self._add_copy_actions(menu, context)
        menu.addSeparator()
        self._add_selection_actions(menu, select_all_tooltip='Select all rows in the database.')
        menu.addSeparator()

        if context.selected_count <= 1:
            go_to_entry_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-right.svg')), 'Go to Entry', self)
            go_to_entry_action.setToolTip('Clear the search filter and navigate to this entry in the full database list.')
            go_to_entry_action.setEnabled(bool(self._search_input.text().strip()))
            go_to_entry_action.triggered.connect(lambda: self._go_to_entry(context.row))
            menu.addAction(go_to_entry_action)
            menu.addSeparator()

        is_single_ip, selected_ips = self._collect_selected_ips(context.ip_or_range)

        if context.row > 0:
            move_up_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-up.svg')), 'Move Up', self)
            move_up_action.triggered.connect(lambda: self._move_rows(index, -1))
            menu.addAction(move_up_action)
        if context.row < self._model.rowCount() - 1:
            move_down_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-down.svg')), 'Move Down', self)
            move_down_action.triggered.connect(lambda: self._move_rows(index, 1))
            menu.addAction(move_down_action)

        if context.row > 0 or context.row < self._model.rowCount() - 1:
            menu.addSeparator()

        insert_above_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-up.svg')), 'Insert Entry Above', self)
        insert_above_action.triggered.connect(lambda: self._insert_entry_at(context.row))
        menu.addAction(insert_above_action)

        insert_below_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-down.svg')), 'Insert Entry Below', self)
        insert_below_action.triggered.connect(lambda: self._insert_entry_at(context.row + 1))
        menu.addAction(insert_below_action)

        menu.addSeparator()
        self._add_edit_actions(menu, target_row=context.row, selected_count=context.selected_count)
        menu.addSeparator()
        self._add_move_to_database_menu(menu, selected_count=context.selected_count, disabled_path=self._current_path)
        self._add_network_actions(menu, ip_or_range=context.ip_or_range, is_single_ip=is_single_ip, selected_ips=selected_ips)

        if context.ip_or_range and self._current_path is not None and context.selected_count <= 1:
            self._add_username_action(
                menu,
                target_row=context.row,
                tooltip='Add an additional username for this IP address or range in the current database.',
            )

        self._add_delete_selected_action(menu)

    def _build_global_search_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a row in global search (read-only) mode."""
        context = self._extract_row_context(index)
        db_item = self._model.item(context.row, DATABASE_COLUMN)
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None

        self._add_copy_actions(menu, context)
        menu.addSeparator()
        self._add_selection_actions(menu, select_all_tooltip='Select all rows in search results.')
        menu.addSeparator()

        if db_path_str:
            db_path = Path(db_path_str)

            go_to_db_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-right.svg')), 'Go to Database', self)
            go_to_db_action.setToolTip('Open this database and navigate to this entry.')
            go_to_db_action.triggered.connect(
                lambda: self.navigate_to_database(db_path, username=context.username, ip_or_range=context.ip_or_range),
            )
            menu.addAction(go_to_db_action)

            open_editor_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'Open in Text Editor', self)
            open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db_path))))
            menu.addAction(open_editor_action)

            open_explorer_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open in Explorer', self)
            open_explorer_action.triggered.connect(lambda: open_file_location(db_path))
            menu.addAction(open_explorer_action)

        menu.addSeparator()
        self._add_edit_actions(menu, target_row=context.row, selected_count=context.selected_count)

        selected_db_paths = {
            self._model.item(self._proxy.mapToSource(i).row(), DATABASE_COLUMN).data(Qt.ItemDataRole.UserRole)
            for i in context.selected_rows
            if self._model.item(self._proxy.mapToSource(i).row(), DATABASE_COLUMN)
        }
        disabled_gs_path = Path(next(iter(selected_db_paths))) if len(selected_db_paths) == 1 and next(iter(selected_db_paths)) else None
        self._add_move_to_database_menu(menu, selected_count=context.selected_count, disabled_path=disabled_gs_path)

        is_single_ip_gs, selected_ips_gs = self._collect_selected_ips(context.ip_or_range)
        self._add_network_actions(menu, ip_or_range=context.ip_or_range, is_single_ip=is_single_ip_gs, selected_ips=selected_ips_gs)

        if db_path_str and context.ip_or_range and context.selected_count <= 1:
            self._add_username_action(
                menu,
                target_row=context.row,
                tooltip='Add an additional username for this IP address or range in its UserIP database.',
            )

        if context.username and context.ip_or_range:
            self._add_delete_selected_action(menu)

    def _copy_selected_entries(self) -> None:
        """Copy selected rows from the UserIP entries table to the clipboard as tab-separated text."""
        copy_table_selection(self._entries_table)

    def _copy_all_entries(self) -> None:
        """Copy all visible rows from the UserIP entries table to the clipboard as tab-separated text."""
        copy_table_all_rows(self._entries_table)

    def _go_to_entry(self, source_row: int) -> None:
        """Clear the search filter and scroll to the entry in the full database list."""
        if source_row < 0 or source_row >= self._model.rowCount():
            return

        if self._search_input.text():
            self._search_input.clear()

        source_index = self._model.index(source_row, USERNAME_COLUMN)
        proxy_index = self._proxy.mapFromSource(source_index)
        if not proxy_index.isValid():
            return

        selection = self._entries_table.selectionModel()
        if selection:
            selection.select(proxy_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
        self._entries_table.setCurrentIndex(proxy_index)
        self._entries_table.scrollTo(proxy_index, QAbstractItemView.ScrollHint.PositionAtCenter)

    def navigate_to_database(self, db_path: Path, *, username: str = '', ip_or_range: str = '') -> None:
        """Exit global search mode, open the given database, and select the matching entry when available."""
        if self._search_input.text():
            self._search_input.clear()
        self._current_path = db_path
        if self._global_search_active:
            self._global_search_checkbox.setChecked(False)
        else:
            self._load_database(db_path)
            self._open_db_button.setEnabled(True)

        # Select the database in the tree
        tree_index = self._fs_model.index(str(db_path))
        if tree_index.isValid():
            selection = self._tree.selectionModel()
            if selection:
                with QSignalBlocker(selection):
                    selection.select(tree_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
                    self._tree.setCurrentIndex(tree_index)
                self._tree.scrollTo(tree_index)

        self._select_loaded_entry(username=username, ip_or_range=ip_or_range)

    def _select_loaded_entry(self, *, username: str, ip_or_range: str) -> None:
        """Select the first row matching `(username, ip_or_range)`, falling back to `ip_or_range` or `username`."""
        if not username and not ip_or_range:
            return

        fallback_row: int | None = None
        username_cf = username.casefold()
        for row in range(self._model.rowCount()):
            username_item = self._model.item(row, USERNAME_COLUMN)
            if not username_item:
                continue

            row_username = username_item.text().strip()
            row_ip_or_range = self._get_row_entry_value(row).strip()
            if username and ip_or_range and row_username == username and row_ip_or_range == ip_or_range:
                fallback_row = row
                break
            if fallback_row is None and ((ip_or_range and row_ip_or_range == ip_or_range) or (username_cf and row_username.casefold() == username_cf)):
                fallback_row = row

        if fallback_row is not None:
            self._go_to_entry(fallback_row)

    def on_entry_double_clicked(self, index: QModelIndex) -> None:
        """Handle double-click on an entry row in global search mode."""
        if not self._global_search_active or not index.isValid():
            return
        source_index = self._proxy.mapToSource(index)
        row = source_index.row()
        username_item = self._model.item(row, USERNAME_COLUMN)
        db_item = self._model.item(source_index.row(), DATABASE_COLUMN)
        if not db_item:
            return
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole)
        if db_path_str:
            username = username_item.text() if username_item else ''
            ip_or_range = self._get_row_entry_value(row)
            self.navigate_to_database(Path(db_path_str), username=username, ip_or_range=ip_or_range)
