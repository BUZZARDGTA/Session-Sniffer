"""Entries context-menu mixin for the UserIP Databases Manager dialog."""

from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSignalBlocker, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QStandardItemModel
from PySide6.QtWidgets import QAbstractItemView, QCheckBox, QDialog, QLineEdit, QMenu, QMessageBox, QPushButton, QTreeView

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._userip_tree_batch_ops import populate_userip_databases_menu
from session_sniffer.guis.select_usernames_dialog import SelectUsernamesDialog, UsernameSelectionConfig, prompt_username_input
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions import (
    create_ping_menu,
    scan_ports_ip,
    show_detailed_ip_lookup,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    IP_COLUMN,
    NOTES_COLUMN,
    RANGE_COLUMN,
    USERNAME_COLUMN,
    EntriesSortProxy,
    format_userip_db_display_name,
    refresh_userip_and_wake_renderer,
    set_row_updated_at,
)
from session_sniffer.guis.utils import copy_table_all_rows, copy_table_selection, open_file_location, set_clipboard_text
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import MIN_GROUP_USERNAMES, group_usernames, ungroup_usernames
from session_sniffer.player.userip_loader import collect_userip_account_groups, get_account_group_clusters_map, move_userip_entries_to_database
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from session_sniffer.guis.file_watch import DebouncedFileWatcher
    from session_sniffer.player.userip_groups import UserIPAccountGroup


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
    """Mixin providing entries-table context menu, grouping, cross-DB moves, and navigation helpers.

    Expects these attributes on the concrete class:
        _entries_table, _proxy, _model, _global_search_active, _current_path,
        _global_search_checkbox, _open_db_button, _fs_watcher, _last_seen_build_version
    And these methods:
        _add_entry, _add_username, _insert_entry_at, _move_rows,
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
    _search_input: QLineEdit
    _dirty: bool
    _fs_watcher: DebouncedFileWatcher
    _last_seen_build_version: int

    if TYPE_CHECKING:

        def _add_entry(self) -> None: ...
        def _delete_selected(self) -> None: ...
        def _rename_selected(self) -> None: ...
        def _rebuild_fs_watch(self) -> None: ...
        def _dedup_global_search_rows(self) -> None: ...
        def _renumber_indexes(self) -> None: ...
        def _update_entry_counts(self) -> None: ...
        def _highlight_duplicates(self) -> int: ...
        def _refresh_stats(self) -> None: ...
        def _save_on_close(self) -> bool: ...

        def _set_status(self, text: str) -> None:
            del text

        def _select_tree_path(self, path: Path) -> None:
            del path

        def _edit_entry_ip(self, source_row: int) -> None:
            del source_row

        def _edit_entry_note(self, source_row: int) -> None:
            del source_row

        def _insert_entry_at(self, source_row: int) -> None:
            del source_row

        def _add_username(self, source_row: int) -> None:
            del source_row

        def _move_rows(self, proxy_index: QModelIndex, direction: int) -> None:
            del proxy_index, direction

        def _load_database(self, path: Path) -> None:
            del path

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
                add_entry_action = QAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), tr('Add Entry'), self)
                add_entry_action.setToolTip(tr('Open the IP Range Builder dialog and insert the result as a new entry.'))
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
        copy_icon = QIcon(str(ICONS_DIR_PATH / 'copy.svg'))
        copy_row_label = tr('Copy Rows ({count})', count=context.selected_count) if context.selected_count > 1 else tr('Copy Row')
        copy_row_action = QAction(copy_icon, copy_row_label, self)
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setToolTip(
            tr_plural('Copy selected row to the clipboard as tab-separated text.', 'Copy selected rows to the clipboard as tab-separated text.', context.selected_count),
        )
        copy_row_action.triggered.connect(self._copy_selected_entries)
        menu.addAction(copy_row_action)

        copy_all_action = QAction(copy_icon, tr('Copy All'), self)
        copy_all_action.setToolTip(tr('Copy all visible entries to the clipboard as tab-separated text.'))
        copy_all_action.setEnabled(self._proxy.rowCount() > 0)
        copy_all_action.triggered.connect(self._copy_all_entries)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        if context.selected_count <= 1:
            if context.username:
                copy_user_action = QAction(copy_icon, tr('Copy Username'), self)
                copy_user_action.triggered.connect(lambda: set_clipboard_text(context.username))
                menu.addAction(copy_user_action)
            group_members = self._collect_group_members_for_rows([context.row])
            if len(group_members) >= MIN_GROUP_USERNAMES:
                group_text = '\n'.join(group_members)
                copy_group_action = QAction(copy_icon, tr('Copy Usernames ({count})', count=len(group_members)), self)
                copy_group_action.setToolTip(
                    tr(
                        'Copy all {count} usernames in this account group ({members}) to the clipboard.',
                        count=len(group_members),
                        members=', '.join(group_members),
                    ),
                )
                copy_group_action.triggered.connect(lambda: set_clipboard_text(group_text))
                menu.addAction(copy_group_action)
            if context.ip_or_range:
                range_item = self._model.item(context.row, RANGE_COLUMN)
                copy_ip_label = tr('Copy Range') if range_item and range_item.text().strip() else tr('Copy IP')
                copy_ip_action = QAction(copy_icon, copy_ip_label, self)
                copy_ip_action.triggered.connect(lambda: set_clipboard_text(context.ip_or_range))
                menu.addAction(copy_ip_action)
            if context.note:
                copy_note_action = QAction(copy_icon, tr('Copy Note'), self)
                copy_note_action.triggered.connect(lambda: set_clipboard_text(context.note))
                menu.addAction(copy_note_action)
        else:
            source_rows: list[int] = []
            distinct_usernames: list[str] = []
            seen_user_cf: set[str] = set()
            all_ips_or_ranges: list[str] = []
            seen_ips: set[str] = set()
            for selected_index in context.selected_rows:
                source_row = self._proxy.mapToSource(selected_index).row()
                source_rows.append(source_row)
                username_item = self._model.item(source_row, USERNAME_COLUMN)
                u_text = username_item.text().strip() if username_item else ''
                u_cf = u_text.casefold()
                if u_text and u_cf not in seen_user_cf:
                    seen_user_cf.add(u_cf)
                    distinct_usernames.append(u_text)
                entry_value = self._get_row_entry_value(source_row)
                if entry_value and entry_value not in seen_ips:
                    seen_ips.add(entry_value)
                    all_ips_or_ranges.append(entry_value)

            if distinct_usernames:
                users_text = '\n'.join(distinct_usernames)
                copy_users_action = QAction(copy_icon, tr('Copy Usernames ({count})', count=len(distinct_usernames)), self)
                copy_users_action.triggered.connect(lambda: set_clipboard_text(users_text))
                menu.addAction(copy_users_action)
            group_members = self._collect_group_members_for_rows(source_rows)
            if len(group_members) >= MIN_GROUP_USERNAMES and len(group_members) > len(distinct_usernames):
                group_text = '\n'.join(group_members)
                copy_group_action = QAction(copy_icon, tr('Copy Group Usernames ({count})', count=len(group_members)), self)
                copy_group_action.setToolTip(
                    tr(
                        'Copy all {count} usernames grouped with the selected rows ({members}) to the clipboard.',
                        count=len(group_members),
                        members=', '.join(group_members),
                    ),
                )
                copy_group_action.triggered.connect(lambda: set_clipboard_text(group_text))
                menu.addAction(copy_group_action)
            if all_ips_or_ranges:
                ips_text = '\n'.join(all_ips_or_ranges)
                copy_ips_action = QAction(copy_icon, tr('Copy IPs / Ranges ({count})', count=len(all_ips_or_ranges)), self)
                copy_ips_action.triggered.connect(lambda: set_clipboard_text(ips_text))
                menu.addAction(copy_ips_action)

    def _add_selection_actions(self, menu: QMenu, *, select_all_tooltip: str) -> None:
        """Add Select All and Clear Selection actions to *menu*."""
        select_all_action = QAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), tr('Select All'), self)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip(select_all_tooltip)
        select_all_action.setEnabled(self._proxy.rowCount() > 0)
        select_all_action.triggered.connect(self._entries_table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(ICONS_DIR_PATH / 'square.svg')), tr('Clear Selection'), self)
        clear_selection_action.setToolTip(tr('Deselect all currently selected rows.'))
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
        pen_icon = QIcon(str(ICONS_DIR_PATH / 'square-pen.svg'))
        rename_label = tr('Rename Selected ({count})', count=selected_count) if selected_count > 1 else tr('Rename')
        rename_action = QAction(pen_icon, rename_label, self)
        rename_action.setShortcut('F2')
        rename_action.setToolTip(
            tr_plural('Rename the username for the selected entry.', 'Rename the username for the selected entries.', selected_count),
        )
        rename_action.triggered.connect(self._rename_selected)
        menu.addAction(rename_action)

        if selected_count <= 1:
            range_item = self._model.item(target_row, RANGE_COLUMN)
            edit_label = tr('Edit Range…') if range_item and range_item.text().strip() else tr('Edit IP…')
            edit_ip_action = QAction(pen_icon, edit_label, self)
            edit_ip_action.triggered.connect(lambda _checked=False, row=target_row: self._edit_entry_ip(row))
            menu.addAction(edit_ip_action)

            notes_item = self._model.item(target_row, NOTES_COLUMN)
            has_note = bool(notes_item and notes_item.text().strip())
            note_label = tr('Edit Note…') if has_note else tr('Add Note…')
            note_icon = QIcon(str(ICONS_DIR_PATH / 'notepad-text.svg'))
            edit_note_action = QAction(note_icon, note_label, self)
            tooltip = tr('Edit the note for this entry.') if has_note else tr('Add a note to this entry.')
            edit_note_action.setToolTip(tooltip)
            edit_note_action.triggered.connect(lambda _checked=False, row=target_row: self._edit_entry_note(row))
            menu.addAction(edit_note_action)

    def _add_grouping_actions(self, menu: QMenu, context: _RowMenuContext) -> None:
        """Add Group Selected Usernames, Group With…, and Ungroup… actions to *menu*."""
        source_rows = sorted({self._proxy.mapToSource(idx).row() for idx in context.selected_rows}) if context.selected_rows else [context.row]
        distinct_usernames: list[str] = []
        seen_cf: set[str] = set()
        for r in source_rows:
            u_item = self._model.item(r, USERNAME_COLUMN)
            u_text = u_item.text().strip() if u_item else ''
            u_cf = u_text.casefold()
            if u_text and u_cf not in seen_cf:
                seen_cf.add(u_cf)
                distinct_usernames.append(u_text)

        if not distinct_usernames:
            return

        group_icon = QIcon(str(ICONS_DIR_PATH / 'user-plus.svg'))
        if len(distinct_usernames) >= MIN_GROUP_USERNAMES:
            group_selected_action = QAction(group_icon, tr('Group Selected Usernames ({count})', count=len(distinct_usernames)), self)
            group_selected_action.setToolTip(tr('Link all selected usernames into the same account group.'))
            group_selected_action.triggered.connect(self._group_selected_rows)
            menu.addAction(group_selected_action)

        group_with_action = QAction(group_icon, tr('Group With…'), self)
        group_with_action.setToolTip(tr('Type or select another username to link into the same account group.'))
        group_with_action.triggered.connect(self._group_rows_with)
        menu.addAction(group_with_action)

        group_members = self._collect_group_members_for_rows(source_rows)
        if len(group_members) >= MIN_GROUP_USERNAMES:
            ungroup_action = QAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), tr('Ungroup…'), self)
            ungroup_action.setToolTip(tr('Unlink usernames from this account group so false positives stay separated.'))
            ungroup_action.triggered.connect(self._ungroup_rows)
            menu.addAction(ungroup_action)

    def _add_move_to_database_menu(self, menu: QMenu, context: _RowMenuContext, *, disabled_path: Path | None) -> None:
        """Build and append the 'Move to Database' (and 'Move Group to Database' when applicable) submenu to *menu*."""
        box_icon = QIcon(str(ICONS_DIR_PATH / 'box.svg'))
        all_db_paths = [json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()]
        selected_count = context.selected_count
        move_db_label = tr('Move Selected to Database ({count})', count=selected_count) if selected_count > 1 else tr('Move to Database')
        move_db_menu = QMenu(move_db_label, menu)
        move_db_menu.setIcon(box_icon)
        move_db_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        move_db_menu.setToolTipsVisible(True)
        enabled_target_count = populate_userip_databases_menu(
            move_db_menu,
            all_db_paths,
            tooltip=tr_plural('Move selected entry to this database.', 'Move selected entries to this database.', selected_count),
            handler_factory=lambda target_path: lambda: self._move_selected_to_database(target_path),
            disabled_path=disabled_path,
        )
        if not enabled_target_count:
            move_db_menu.setEnabled(False)
            move_db_menu.setToolTip(tr('No other databases available.'))
        menu.addMenu(move_db_menu)

        source_rows = sorted({self._proxy.mapToSource(idx).row() for idx in context.selected_rows}) if context.selected_rows else [context.row]
        group_keys, selected_keys = self._collect_group_entry_keys_for_rows(source_rows)
        if len(group_keys) > 1 and group_keys != selected_keys:
            group_dbs = {db_path for db_path, _, _ in group_keys}
            group_disabled_path = next(iter(group_dbs)) if len(group_dbs) == 1 else None
            move_group_menu = QMenu(tr('Move Group to Database ({count})', count=len(group_keys)), menu)
            move_group_menu.setIcon(box_icon)
            move_group_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            move_group_menu.setToolTipsVisible(True)
            enabled_group_targets = populate_userip_databases_menu(
                move_group_menu,
                all_db_paths,
                tooltip=tr('Move all {count} entries in this account group to this database.', count=len(group_keys)),
                handler_factory=lambda target_path: lambda: self._move_group_to_database(source_rows, target_path),
                disabled_path=group_disabled_path,
            )
            if not enabled_group_targets:
                move_group_menu.setEnabled(False)
                move_group_menu.setToolTip(tr('No other databases available.'))
            menu.addMenu(move_group_menu)

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
            lookup_action = QAction(QIcon(str(ICONS_DIR_PATH / 'info.svg')), tr('IP Lookup Details…'), self)
            lookup_action.triggered.connect(lambda _checked=False, ip_address=ip_or_range: show_detailed_ip_lookup(ip_address))
            menu.addAction(lookup_action)

        create_ping_menu(self, menu, list(selected_ips) if len(selected_ips) > 1 else [ip_or_range])

        scan_ports_action = QAction(QIcon(str(ICONS_DIR_PATH / 'radar.svg')), tr('Scan Ports…'), self)
        scan_ports_action.setToolTip(
            tr_plural('Scan TCP and UDP ports on the selected host.', 'Scan TCP and UDP ports on the selected hosts.', max(1, len(selected_ips))),
        )
        scan_target = list(selected_ips) if len(selected_ips) > 1 else ip_or_range
        scan_ports_action.triggered.connect(lambda _checked=False, target=scan_target: scan_ports_ip(target))
        menu.addAction(scan_ports_action)

    def _add_username_action(self, menu: QMenu, *, target_row: int, tooltip: str) -> None:
        """Add the 'Add Username' action with a preceding separator to *menu*."""
        menu.addSeparator()
        add_username_action = QAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), tr('Add Username'), self)
        add_username_action.setToolTip(tooltip)
        add_username_action.triggered.connect(lambda _checked=False, row=target_row: self._add_username(row))
        menu.addAction(add_username_action)

    def _add_delete_selected_action(self, menu: QMenu) -> None:
        """Add the 'Delete Selected Row(s)' action with a preceding separator to *menu*."""
        delete_action = QAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), tr('Delete Selected Row(s)'), self)
        delete_action.triggered.connect(self._delete_selected)
        menu.addSeparator()
        menu.addAction(delete_action)

    def _build_entry_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a single entry row in normal editing mode."""
        context = self._extract_row_context(index)

        self._add_copy_actions(menu, context)
        menu.addSeparator()
        self._add_selection_actions(menu, select_all_tooltip=tr('Select all rows in the database.'))
        menu.addSeparator()

        if context.selected_count <= 1:
            go_to_entry_action = QAction(QIcon(str(ICONS_DIR_PATH / 'arrow-right.svg')), tr('Go to Entry'), self)
            go_to_entry_action.setToolTip(tr('Clear the search filter and navigate to this entry in the full database list.'))
            go_to_entry_action.setEnabled(bool(self._search_input.text().strip()))
            go_to_entry_action.triggered.connect(lambda: self._go_to_entry(context.row))
            menu.addAction(go_to_entry_action)
            menu.addSeparator()

        is_single_ip, selected_ips = self._collect_selected_ips(context.ip_or_range)
        can_reorder_rows = not self._proxy.group_sort_enabled and not self._proxy.sortColumn() and self._proxy.sortOrder() == Qt.SortOrder.AscendingOrder

        if can_reorder_rows and context.row > 0:
            move_up_action = QAction(QIcon(str(ICONS_DIR_PATH / 'arrow-up.svg')), tr('Move Up'), self)
            move_up_action.triggered.connect(lambda: self._move_rows(index, -1))
            menu.addAction(move_up_action)
        if can_reorder_rows and context.row < self._model.rowCount() - 1:
            move_down_action = QAction(QIcon(str(ICONS_DIR_PATH / 'arrow-down.svg')), tr('Move Down'), self)
            move_down_action.triggered.connect(lambda: self._move_rows(index, 1))
            menu.addAction(move_down_action)

        if can_reorder_rows and (context.row > 0 or context.row < self._model.rowCount() - 1):
            menu.addSeparator()

        insert_above_action = QAction(QIcon(str(ICONS_DIR_PATH / 'arrow-up.svg')), tr('Insert Entry Above'), self)
        insert_above_action.triggered.connect(lambda: self._insert_entry_at(context.row))
        menu.addAction(insert_above_action)

        insert_below_action = QAction(QIcon(str(ICONS_DIR_PATH / 'arrow-down.svg')), tr('Insert Entry Below'), self)
        insert_below_action.triggered.connect(lambda: self._insert_entry_at(context.row + 1))
        menu.addAction(insert_below_action)

        menu.addSeparator()
        self._add_edit_actions(menu, target_row=context.row, selected_count=context.selected_count)
        menu.addSeparator()
        self._add_grouping_actions(menu, context)
        menu.addSeparator()
        self._add_move_to_database_menu(menu, context, disabled_path=self._current_path)
        self._add_network_actions(menu, ip_or_range=context.ip_or_range, is_single_ip=is_single_ip, selected_ips=selected_ips)

        if context.ip_or_range and self._current_path is not None and context.selected_count <= 1:
            self._add_username_action(
                menu,
                target_row=context.row,
                tooltip=tr('Add an additional username for this IP address or range in the current database.'),
            )

        self._add_delete_selected_action(menu)

    def _build_global_search_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a row in global search (read-only) mode."""
        context = self._extract_row_context(index)
        db_item = self._model.item(context.row, DATABASE_COLUMN)
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None

        self._add_copy_actions(menu, context)
        menu.addSeparator()
        self._add_selection_actions(menu, select_all_tooltip=tr('Select all rows in search results.'))
        menu.addSeparator()

        if db_path_str:
            db_path = Path(db_path_str)

            go_to_db_action = QAction(QIcon(str(ICONS_DIR_PATH / 'arrow-right.svg')), tr('Go to Database'), self)
            go_to_db_action.setToolTip(tr('Open this database and navigate to this entry.'))
            go_to_db_action.triggered.connect(
                lambda: self.navigate_to_database(db_path, username=context.username, ip_or_range=context.ip_or_range),
            )
            menu.addAction(go_to_db_action)

            open_editor_action = QAction(QIcon(str(ICONS_DIR_PATH / 'file-text.svg')), tr('Open in Text Editor'), self)
            open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db_path))))
            menu.addAction(open_editor_action)

            open_explorer_action = QAction(QIcon(str(ICONS_DIR_PATH / 'folder.svg')), tr('Open in File Manager'), self)
            open_explorer_action.triggered.connect(lambda: open_file_location(db_path))
            menu.addAction(open_explorer_action)

        menu.addSeparator()
        self._add_edit_actions(menu, target_row=context.row, selected_count=context.selected_count)
        menu.addSeparator()
        self._add_grouping_actions(menu, context)
        menu.addSeparator()

        selected_db_paths = {
            self._model.item(self._proxy.mapToSource(i).row(), DATABASE_COLUMN).data(Qt.ItemDataRole.UserRole)
            for i in context.selected_rows
            if self._model.item(self._proxy.mapToSource(i).row(), DATABASE_COLUMN)
        }
        disabled_gs_path = Path(next(iter(selected_db_paths))) if len(selected_db_paths) == 1 and next(iter(selected_db_paths)) else None
        self._add_move_to_database_menu(menu, context, disabled_path=disabled_gs_path)

        is_single_ip_gs, selected_ips_gs = self._collect_selected_ips(context.ip_or_range)
        self._add_network_actions(menu, ip_or_range=context.ip_or_range, is_single_ip=is_single_ip_gs, selected_ips=selected_ips_gs)

        if db_path_str and context.ip_or_range and context.selected_count <= 1:
            self._add_username_action(
                menu,
                target_row=context.row,
                tooltip=tr('Add an additional username for this IP address or range in its UserIP database.'),
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

        self._select_tree_path(db_path)
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
            if username_cf and ip_or_range and row_username.casefold() == username_cf and row_ip_or_range == ip_or_range:
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

    # ------------------------------------------------------------------
    # Account grouping & cross-DB entry moves
    # ------------------------------------------------------------------

    def _current_model_override_entries(self) -> dict[Path, list[tuple[str, str]]] | None:
        """Return live `(username, ip)` pairs from `self._model` when editing a single database."""
        if self._global_search_active or self._current_path is None:
            return None
        pairs = [(u, ip) for r in range(self._model.rowCount()) if (u := self._get_row_username(r)) and (ip := self._get_row_entry_value(r))]
        return {self._current_path: pairs}

    def _account_group_clusters_map(self) -> dict[str, list[str]]:
        """Return `{username_cf: [canonical_member, ...]}` across all databases plus live model overrides."""
        return get_account_group_clusters_map(include_disabled=True, override_entries_by_db=self._current_model_override_entries())

    def _matching_groups_for_seeds(self, seeds: list[str]) -> list[UserIPAccountGroup]:
        """Return `UserIPAccountGroup`s overlapping *seeds* across active databases (plus live model overrides)."""
        if not seeds:
            return []
        seed_cfs = {u.casefold() for u in seeds}
        groups = collect_userip_account_groups(
            include_disabled=self._global_search_active, extra_seed_usernames=seeds, override_entries_by_db=self._current_model_override_entries(),
        )
        return [g for g in groups if g.usernames_cf & seed_cfs]

    def _collect_row_seed_usernames(self, source_rows: list[int]) -> list[str]:
        """Return deduplicated seed usernames from *source_rows* and their co-hosted/grouped table peers."""
        row_gids = self._proxy.get_source_row_group_ids()
        target_gids = {row_gids[r] for r in source_rows if 0 <= r < len(row_gids)}
        seed_rows = [r for r in range(self._model.rowCount()) if r in source_rows or (r < len(row_gids) and row_gids[r] in target_gids)]
        return dedup_preserve_order(self._get_row_username(r) for r in seed_rows if self._get_row_username(r))

    def _collect_row_entry_keys(self, source_rows: list[int]) -> frozenset[tuple[Path, str, str]]:
        """Return `(db_path, username_cf, ip)` entry keys for *source_rows*."""
        return frozenset(
            (db_path, u.casefold(), ip)
            for r in source_rows
            if (db_path := self._get_row_database_path(r) if self._global_search_active else self._current_path) is not None
            and (u := self._get_row_username(r))
            and (ip := self._get_row_entry_value(r))
        )

    def _collect_group_entry_keys_for_rows(self, source_rows: list[int]) -> tuple[frozenset[tuple[Path, str, str]], frozenset[tuple[Path, str, str]]]:
        """Return `(group_entry_keys, selected_entry_keys)` for the account group(s) of *source_rows*."""
        selected_keys = self._collect_row_entry_keys(source_rows)
        group_keys = frozenset(key for g in self._matching_groups_for_seeds(self._collect_row_seed_usernames(source_rows)) for key in g.entry_keys)
        return group_keys or selected_keys, selected_keys

    def _move_selected_to_database(self, target_db_path: Path) -> None:
        """Move the selected entries to a different UserIP database."""
        if not (source_rows := self._get_selected_source_rows(warn_if_empty=True)):
            return
        if not (entry_keys := self._collect_row_entry_keys(source_rows)):
            QMessageBox.information(self, TITLE, tr('No valid entries to move.'))
            return
        if self._global_search_active or not self._dirty or self._save_on_close():
            self._execute_entry_keys_move(entry_keys, target_db_path)

    def _move_group_to_database(self, seed_rows: list[int], target_db_path: Path) -> None:
        """Move all entries in the account group(s) of *seed_rows* to *target_db_path*."""
        seeds = self._collect_row_seed_usernames(seed_rows)
        if not seeds or (not self._global_search_active and self._dirty and not self._save_on_close()):
            return
        if entry_keys := frozenset(key for g in self._matching_groups_for_seeds(seeds) for key in g.entry_keys):
            self._execute_entry_keys_move(entry_keys, target_db_path)

    def _execute_entry_keys_move(self, entry_keys: frozenset[tuple[Path, str, str]], target_db_path: Path) -> None:
        """Move *entry_keys* into *target_db_path* via the shared backend and synchronize the table UI."""
        target_display_name = format_userip_db_display_name(target_db_path)
        moving_keys = frozenset(key for key in entry_keys if key[0] != target_db_path)
        if not moving_keys:
            QMessageBox.information(
                self,
                TITLE,
                tr_plural(
                    'Selected entry already belongs to "{db}".',
                    'Selected entries already belong to "{db}".',
                    len(entry_keys),
                    db=target_display_name,
                ),
            )
            return

        with QSignalBlocker(self._fs_watcher):
            result = move_userip_entries_to_database(target_db_path, entry_keys=moving_keys)
        self._last_seen_build_version = UserIPDatabases.build_version
        self._rebuild_fs_watch()
        if not result.moved_by_db:
            return

        if self._global_search_active:
            added_pairs_cf = {(u.casefold(), ip) for u, ip in result.added_pairs}
            rows_to_remove: list[int] = []
            updated_rows: list[int] = []
            with QSignalBlocker(self._model):
                for row in range(self._model.rowCount()):
                    row_db = self._get_row_database_path(row)
                    u_cf, ip_val = self._get_row_username(row).casefold(), self._get_row_entry_value(row)
                    if row_db is None or (row_db, u_cf, ip_val) not in moving_keys:
                        continue
                    pair = (u_cf, ip_val)
                    if pair in added_pairs_cf:
                        added_pairs_cf.discard(pair)
                        if db_item := self._model.item(row, DATABASE_COLUMN):
                            db_item.setText(target_db_path.stem)
                            db_item.setData(str(target_db_path), Qt.ItemDataRole.UserRole)
                        set_row_updated_at(self._model, row, result.updated_at)
                        updated_rows.append(row)
                    else:
                        rows_to_remove.append(row)

            for row in sorted(rows_to_remove, reverse=True):
                self._model.removeRow(row)
            if updated_rows:
                self._proxy.refresh_rows([r - sum(1 for rem in rows_to_remove if rem < r) for r in updated_rows])
            self._dedup_global_search_rows()
            self._renumber_indexes()
            self._update_entry_counts()
            self._highlight_duplicates()
            self._proxy.refresh_groups()
        elif self._current_path is not None and (self._current_path in result.moved_by_db or self._current_path == target_db_path):
            active_search = self._search_input.text()
            self._load_database(self._current_path)
            if active_search:
                self._search_input.setText(active_search)

        self._refresh_stats()
        self._set_status(
            tr_plural('Moved {count} entry to "{db}".', 'Moved {count} entries to "{db}".', result.total_moved, db=target_display_name),
        )

    def _get_selected_source_rows(self, *, warn_if_empty: bool = False) -> list[int]:
        """Return sorted source-model row indices for the current selection."""
        selection = self._entries_table.selectionModel()
        selected_indexes = selection.selectedRows() if selection else []
        if not selected_indexes:
            if warn_if_empty:
                QMessageBox.information(self, TITLE, tr('No entries selected.'))
            return []
        return sorted({self._proxy.mapToSource(index).row() for index in selected_indexes})

    def _get_row_database_path(self, row: int, /) -> Path | None:
        """Return the database file path stored on `row` in global search mode, if any."""
        db_item = self._model.item(row, DATABASE_COLUMN)
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
        return Path(str(db_path_str)) if db_path_str else None

    def _get_row_username(self, row: int, /) -> str:
        """Return the stripped username text from `row`."""
        username_item = self._model.item(row, USERNAME_COLUMN)
        return username_item.text().strip() if username_item else ''

    def _get_row_entry_value(self, row: int, /) -> str:
        """Return the effective IP or Range value from a row (whichever is non-empty)."""
        ip_item, range_item = self._model.item(row, IP_COLUMN), self._model.item(row, RANGE_COLUMN)
        return (ip_item.text().strip() if ip_item else '') or (range_item.text().strip() if range_item else '')

    def _collect_group_members_for_rows(self, source_rows: list[int]) -> list[str]:
        """Return all usernames currently grouped with the usernames on *source_rows*."""
        return dedup_preserve_order(*(g.usernames for g in self._matching_groups_for_seeds(self._collect_row_seed_usernames(source_rows))))

    def _refresh_table_after_grouping(self) -> None:
        """Rebuild UserIP databases and refresh the proxy's group sorting and alternating background shading."""
        refresh_userip_and_wake_renderer()
        self._last_seen_build_version = UserIPDatabases.build_version
        self._rebuild_fs_watch()
        self._refresh_stats()
        self._proxy.refresh_groups()
        if viewport := self._entries_table.viewport():
            viewport.update()

    def _group_selected_rows(self) -> None:
        """Group all distinct usernames across the currently selected rows together."""
        if not (source_rows := self._get_selected_source_rows(warn_if_empty=True)):
            return
        usernames = dedup_preserve_order(self._get_row_username(r) for r in source_rows if self._get_row_username(r))
        if len(usernames) < MIN_GROUP_USERNAMES:
            QMessageBox.information(self, TITLE, tr('Select at least two rows with distinct usernames to group them together.'))
            return
        with QSignalBlocker(self._fs_watcher):
            if not group_usernames(usernames, self._account_group_clusters_map()):
                return
            self._refresh_table_after_grouping()
        self._set_status(tr_plural('Grouped {count} username together', 'Grouped {count} usernames together', len(usernames)))

    def _group_rows_with(self) -> None:
        """Prompt for a username and group it with the selected row(s)' usernames."""
        source_rows = self._get_selected_source_rows(warn_if_empty=True)
        if not source_rows or not (usernames := dedup_preserve_order(self._get_row_username(r) for r in source_rows if self._get_row_username(r))):
            return
        max_preview = 3
        source_display = ', '.join(usernames[:max_preview]) + (f" {tr('(+{count} more)', count=len(usernames) - max_preview)}" if len(usernames) > max_preview else '')
        target_username, ok = prompt_username_input(self, tr('Group With - {title}', title=TITLE), tr('Enter the username to group with "{display}":', display=source_display))
        if not ok or not (target_clean := target_username.strip()):
            return
        combined = dedup_preserve_order(usernames, [target_clean])
        if len(combined) < MIN_GROUP_USERNAMES:
            QMessageBox.information(self, TITLE, tr('Please enter a different username to group with.'))
            return
        with QSignalBlocker(self._fs_watcher):
            if not group_usernames(combined, self._account_group_clusters_map()):
                return
            self._refresh_table_after_grouping()
        self._set_status(tr('Grouped "{target}" with {display}', target=target_clean, display=source_display))

    def _ungroup_rows(self) -> None:
        """Open a selection dialog to ungroup false-positive or unlinked usernames from the selected row(s)' group."""
        source_rows = self._get_selected_source_rows(warn_if_empty=True)
        if not source_rows or len(group_members := self._collect_group_members_for_rows(source_rows)) < MIN_GROUP_USERNAMES:
            return
        dlg = SelectUsernamesDialog(self, group_members, UsernameSelectionConfig.for_ungroup())
        if dlg.exec() != SelectUsernamesDialog.DialogCode.Accepted or not (chosen := dlg.selected_usernames()):
            return
        with QSignalBlocker(self._fs_watcher):
            if not ungroup_usernames(chosen, group_members):
                return
            self._refresh_table_after_grouping()
        self._set_status(tr('Ungrouped {names}', names=', '.join(f'{name!r}' for name in chosen)))
