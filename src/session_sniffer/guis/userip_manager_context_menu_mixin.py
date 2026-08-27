"""Entries context-menu mixin for the UserIP Databases Manager dialog."""

from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QStandardItemModel
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QFileSystemModel, QMenu, QPushButton, QTreeView

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.looky_text import (
    configure_looky_action,
)
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions import (
    ping_ip,
    show_detailed_ip_lookup,
    tcp_port_ping,
    tcp_port_ping_multi,
)
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    RANGE_COLUMN,
    RE_USERIP_INI_PARSER_PATTERN,
    SECTION_USERIP,
    USERNAME_COLUMN,
    EntriesSortProxy,
    handle_ini_section_header,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable


class EntriesContextMenuMixin(QDialog):
    """Mixin providing entries-table context menu and related navigation helpers.

    Expects these attributes on the concrete class:
        _entries_table, _proxy, _model, _global_search_active, _current_path,
        _global_search_checkbox, _open_db_button, _tree, _fs_model
    And these methods:
        _add_entry, _insert_entry_at, _move_rows, _get_row_entry_value,
        _load_database, _open_in_explorer, _delete_selected
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
    _open_in_explorer: Callable[[Path], None]

    def _add_entry(self) -> None: ...

    def _delete_selected(self) -> None: ...

    def _edit_entry_ip(self, source_row: int) -> None: ...  # pylint: disable=unused-argument

    def _insert_entry_at(self, source_row: int) -> None: ...  # pylint: disable=unused-argument

    def _move_rows(self, proxy_index: QModelIndex, direction: int) -> None: ...  # pylint: disable=unused-argument

    def _get_row_entry_value(self, row: int) -> str:  # pylint: disable=unused-argument  # noqa: ARG002
        return ''

    def _load_database(self, path: Path) -> None: ...  # pylint: disable=unused-argument

    def _update_entry_counts(self) -> None: ...

    # ------------------------------------------------------------------
    # Entries: context menu
    # ------------------------------------------------------------------

    def show_entries_context_menu(self, position: QPoint) -> None:
        """Show a right-click context menu for the entries table."""
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
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
                add_top_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_up.svg')), 'Add Entry to Top', self)
                add_top_action.triggered.connect(lambda: self._insert_entry_at(0))
                menu.addAction(add_top_action)

                add_end_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_down.svg')), 'Add Entry to End', self)
                add_end_action.triggered.connect(self._add_entry)
                menu.addAction(add_end_action)

        if menu.isEmpty():
            return

        viewport = self._entries_table.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(position))

    def _build_entry_context_menu(self, menu: QMenu, index: QModelIndex) -> None:
        """Populate context menu actions for a single entry row in normal editing mode."""
        source_index = self._proxy.mapToSource(index)
        row = source_index.row()
        username_item = self._model.item(row, USERNAME_COLUMN)
        username = username_item.text() if username_item else ''
        ip_or_range = self._get_row_entry_value(row)

        if username:
            copy_user_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Username', self)
            copy_user_action.triggered.connect(lambda: self._copy_to_clipboard(username))
            menu.addAction(copy_user_action)
        if ip_or_range:
            range_item = self._model.item(row, RANGE_COLUMN)
            label = 'Range' if range_item and range_item.text().strip() else 'IP'
            copy_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy {label}', self)
            copy_ip_action.triggered.connect(lambda: self._copy_to_clipboard(ip_or_range))
            menu.addAction(copy_ip_action)

        if not menu.isEmpty():
            menu.addSeparator()

        # Single IP check & Multi-selected IPs detection
        is_single_ip = False
        if ip_or_range:
            try:
                IPv4Address(ip_or_range)
                is_single_ip = True
            except ValueError:
                is_single_ip = False

        selected_ips: list[str] = []
        if self._entries_table.selectionModel():
            for sel_index in self._entries_table.selectionModel().selectedRows():
                src_idx = self._proxy.mapToSource(sel_index)
                ip_val = self._get_row_entry_value(src_idx.row())
                try:
                    IPv4Address(ip_val)
                    if ip_val not in selected_ips:
                        selected_ips.append(ip_val)
                except ValueError:
                    pass

        # Network / Ping & Lookup actions
        if is_single_ip or len(selected_ips) > 1:
            if is_single_ip and len(selected_ips) <= 1:
                _ip_target = ip_or_range
                matched_player = PlayersRegistry.get_player_by_ip(_ip_target)
                if matched_player is not None:
                    lookup_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'IP Lookup Details…', self)
                    lookup_action.triggered.connect(lambda _checked=False, player=matched_player: show_detailed_ip_lookup(self, player))
                    menu.addAction(lookup_action)

            ping_menu = QMenu('Ping', menu)
            ping_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            ping_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            ping_menu.setToolTipsVisible(True)

            if len(selected_ips) > 1:
                _ip_addresses_target = list(selected_ips)
                normal_ping_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), 'Normal (ICMP)', self)
                normal_ping_action.setToolTip('Checks if selected IP addresses respond to pings.')

                def _do_normal_ping_multi() -> None:
                    for ip_address in _ip_addresses_target:
                        ping_ip(ip_address)

                normal_ping_action.triggered.connect(_do_normal_ping_multi)
                ping_menu.addAction(normal_ping_action)

                tcp_menu = QMenu('TCP Port (paping.exe)', ping_menu)
                tcp_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')))
                tcp_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
                tcp_menu.setToolTipsVisible(True)

                tcp_one_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'One Port for All', tcp_menu)
                tcp_one_action.setToolTip('Ask for a port once, then TCP ping all selected IPs on that port.')

                def _do_tcp_ping_multi() -> None:
                    tcp_port_ping_multi(self, _ip_addresses_target)

                tcp_one_action.triggered.connect(_do_tcp_ping_multi)
                tcp_menu.addAction(tcp_one_action)

                tcp_indiv_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'Individual Port per IP', tcp_menu)
                tcp_indiv_action.setToolTip('Ask for a separate port for each selected IP.')

                def _do_tcp_ping_indiv() -> None:
                    for ip_address in _ip_addresses_target:
                        tcp_port_ping(self, ip_address)

                tcp_indiv_action.triggered.connect(_do_tcp_ping_indiv)
                tcp_menu.addAction(tcp_indiv_action)

                ping_menu.addMenu(tcp_menu)
            else:
                _ip_target = ip_or_range
                normal_ping_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), 'Normal (ICMP)', self)
                normal_ping_action.setToolTip('Checks if selected IP address responds to pings.')
                normal_ping_action.triggered.connect(lambda _checked=False, ip_address=_ip_target: ping_ip(ip_address))
                ping_menu.addAction(normal_ping_action)

                tcp_ping_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'TCP Port (paping.exe)', self)
                tcp_ping_action.setToolTip('Checks if selected IP address responds to TCP pings on a given port.')
                tcp_ping_action.triggered.connect(lambda _checked=False, ip_address=_ip_target: tcp_port_ping(self, ip_address))
                ping_menu.addAction(tcp_ping_action)

            menu.addMenu(ping_menu)
            menu.addSeparator()

        # Looky System refresh (only for single IPs in GTA5 feature set)
        if ip_or_range and self._current_path is not None and Settings.is_gta5_feature_set() and is_single_ip:
            refresh_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Add Username (Looky System)', self)
            refresh_action.triggered.connect(lambda _checked=False, d=self._current_path, i=ip_or_range: looky_refresh_userip_entries(self, [(d, [i])]))
            configure_looky_action(refresh_action, 'Look up this IP via Looky System and add any new usernames to its UserIP database.')
            menu.addAction(refresh_action)

        source_row = self._proxy.mapToSource(index).row()

        edit_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'Edit IP/Range…', self)
        edit_ip_action.triggered.connect(lambda: self._edit_entry_ip(source_row))
        menu.addAction(edit_ip_action)

        selected_count = len(self._entries_table.selectionModel().selectedRows()) if self._entries_table.selectionModel() else 1
        delete_label = f'Delete Selected Row{pluralize(selected_count)}'
        delete_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), delete_label, self)
        delete_action.triggered.connect(self._delete_selected)
        menu.addAction(delete_action)

        menu.addSeparator()

        if source_row > 0:
            move_up_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_up.svg')), 'Move Up', self)
            move_up_action.triggered.connect(lambda: self._move_rows(index, -1))
            menu.addAction(move_up_action)
        if source_row < self._model.rowCount() - 1:
            move_down_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_down.svg')), 'Move Down', self)
            move_down_action.triggered.connect(lambda: self._move_rows(index, 1))
            menu.addAction(move_down_action)

        menu.addSeparator()

        insert_above_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_up.svg')), 'Insert Entry Above', self)
        insert_above_action.triggered.connect(lambda: self._insert_entry_at(source_row))
        menu.addAction(insert_above_action)

        insert_below_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_down.svg')), 'Insert Entry Below', self)
        insert_below_action.triggered.connect(lambda: self._insert_entry_at(source_row + 1))
        menu.addAction(insert_below_action)

        menu.addSeparator()

        add_top_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_up.svg')), 'Add Entry to Top', self)
        add_top_action.triggered.connect(lambda: self._insert_entry_at(0))
        menu.addAction(add_top_action)

        add_end_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_down.svg')), 'Add Entry to End', self)
        add_end_action.triggered.connect(self._add_entry)
        menu.addAction(add_end_action)

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
            copy_user_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Username', self)
            copy_user_action.triggered.connect(lambda: self._copy_to_clipboard(username))
            menu.addAction(copy_user_action)
        if ip_or_range:
            range_item = self._model.item(row, RANGE_COLUMN)
            label = 'Range' if range_item and range_item.text().strip() else 'IP'
            copy_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy {label}', self)
            copy_ip_action.triggered.connect(lambda: self._copy_to_clipboard(ip_or_range))
            menu.addAction(copy_ip_action)

        # Single IP check & Multi-selected IPs detection for global search
        is_single_ip_gs = False
        if ip_or_range:
            try:
                IPv4Address(ip_or_range)
                is_single_ip_gs = True
            except ValueError:
                is_single_ip_gs = False

        selected_ips_gs: list[str] = []
        if self._entries_table.selectionModel():
            for sel_index in self._entries_table.selectionModel().selectedRows():
                src_idx = self._proxy.mapToSource(sel_index)
                ip_val = self._get_row_entry_value(src_idx.row())
                try:
                    IPv4Address(ip_val)
                    if ip_val not in selected_ips_gs:
                        selected_ips_gs.append(ip_val)
                except ValueError:
                    pass

        # Network / Ping & Lookup actions
        if is_single_ip_gs or len(selected_ips_gs) > 1:
            if is_single_ip_gs and len(selected_ips_gs) <= 1:
                _ip_gs = ip_or_range
                matched_player_gs = PlayersRegistry.get_player_by_ip(_ip_gs)
                if matched_player_gs is not None:
                    lookup_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'IP Lookup Details…', self)
                    lookup_gs_action.triggered.connect(lambda _checked=False, player=matched_player_gs: show_detailed_ip_lookup(self, player))
                    menu.addAction(lookup_gs_action)

            ping_menu_gs = QMenu('Ping', menu)
            ping_menu_gs.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            ping_menu_gs.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            ping_menu_gs.setToolTipsVisible(True)

            if len(selected_ips_gs) > 1:
                _ip_addresses_gs = list(selected_ips_gs)
                normal_ping_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), 'Normal (ICMP)', self)
                normal_ping_gs_action.setToolTip('Checks if selected IP addresses respond to pings.')

                def _do_normal_ping_multi_gs() -> None:
                    for ip_address in _ip_addresses_gs:
                        ping_ip(ip_address)

                normal_ping_gs_action.triggered.connect(_do_normal_ping_multi_gs)
                ping_menu_gs.addAction(normal_ping_gs_action)

                tcp_menu_gs = QMenu('TCP Port (paping.exe)', ping_menu_gs)
                tcp_menu_gs.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')))
                tcp_menu_gs.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
                tcp_menu_gs.setToolTipsVisible(True)

                tcp_one_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'One Port for All', tcp_menu_gs)
                tcp_one_gs_action.setToolTip('Ask for a port once, then TCP ping all selected IPs on that port.')

                def _do_tcp_ping_multi_gs() -> None:
                    tcp_port_ping_multi(self, _ip_addresses_gs)

                tcp_one_gs_action.triggered.connect(_do_tcp_ping_multi_gs)
                tcp_menu_gs.addAction(tcp_one_gs_action)

                tcp_indiv_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'Individual Port per IP', tcp_menu_gs)
                tcp_indiv_gs_action.setToolTip('Ask for a separate port for each selected IP.')

                def _do_tcp_ping_indiv_gs() -> None:
                    for ip_address in _ip_addresses_gs:
                        tcp_port_ping(self, ip_address)

                tcp_indiv_gs_action.triggered.connect(_do_tcp_ping_indiv_gs)
                tcp_menu_gs.addAction(tcp_indiv_gs_action)

                ping_menu_gs.addMenu(tcp_menu_gs)
            else:
                _ip_gs = ip_or_range
                normal_ping_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), 'Normal (ICMP)', self)
                normal_ping_gs_action.setToolTip('Checks if selected IP address responds to pings.')
                normal_ping_gs_action.triggered.connect(lambda _checked=False, ip_address=_ip_gs: ping_ip(ip_address))
                ping_menu_gs.addAction(normal_ping_gs_action)

                tcp_ping_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'TCP Port (paping.exe)', self)
                tcp_ping_gs_action.setToolTip('Checks if selected IP address responds to TCP pings on a given port.')
                tcp_ping_gs_action.triggered.connect(lambda _checked=False, ip_address=_ip_gs: tcp_port_ping(self, ip_address))
                ping_menu_gs.addAction(tcp_ping_gs_action)

            menu.addMenu(ping_menu_gs)

        # --- Database navigation actions ---
        if db_path_str:
            db_path = Path(db_path_str)
            menu.addSeparator()

            go_to_db_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_forward.svg')), 'Go to Database', self)
            go_to_db_action.triggered.connect(lambda: self._navigate_to_database(db_path, username=username, ip_or_range=ip_or_range))
            menu.addAction(go_to_db_action)

            open_editor_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), 'Open in Text Editor', self)
            open_editor_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db_path))))
            menu.addAction(open_editor_action)

            open_explorer_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open in Explorer', self)
            open_explorer_action.triggered.connect(lambda: self._open_in_explorer(db_path))
            menu.addAction(open_explorer_action)

            if username and ip_or_range:
                menu.addSeparator()

                # Looky System refresh (only for single IPs in GTA5 feature set)
                if Settings.is_gta5_feature_set():
                    try:
                        IPv4Address(ip_or_range)
                        is_single_ip = True
                    except ValueError:
                        is_single_ip = False
                    if is_single_ip:
                        _db_refresh = db_path
                        _ip_refresh = ip_or_range
                        refresh_gs_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')), 'Add Username (Looky System)', self)
                        refresh_gs_action.triggered.connect(lambda _checked=False, d=_db_refresh, i=_ip_refresh: looky_refresh_userip_entries(self, [(d, [i])]))
                        configure_looky_action(refresh_gs_action, 'Look up this IP via Looky System and add any new usernames to its UserIP database.')
                        menu.addAction(refresh_gs_action)

                selected_count = len(self._entries_table.selectionModel().selectedRows()) if self._entries_table.selectionModel() else 1
                delete_label = f'Delete Selected Row{pluralize(selected_count)}'
                delete_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), delete_label, self)
                delete_action.triggered.connect(self._delete_selected)
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
                match = RE_USERIP_INI_PARSER_PATTERN.search(stripped)
                if match:
                    u_raw = match.group('username')
                    ip_raw = match.group('ip')
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
        if clipboard:
            clipboard.setText(text)

    def _navigate_to_database(self, db_path: Path, *, username: str = '', ip_or_range: str = '') -> None:
        """Exit global search mode, open the given database, and select the matching entry when available."""
        self._global_search_checkbox.setChecked(False)
        self._current_path = db_path
        self._load_database(db_path)
        self._open_db_button.setEnabled(True)

        # Select the database in the tree
        tree_index = self._fs_model.index(str(db_path))
        if tree_index.isValid():
            selection = self._tree.selectionModel()
            if selection:
                selection.select(tree_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
                self._tree.scrollTo(tree_index)

        self._select_loaded_entry(username=username, ip_or_range=ip_or_range)

    def _select_loaded_entry(self, *, username: str, ip_or_range: str) -> None:
        """Select the first row in the loaded database matching the given username and entry value."""
        if not username or not ip_or_range:
            return

        for row in range(self._model.rowCount()):
            username_item = self._model.item(row, USERNAME_COLUMN)
            if not username_item:
                continue

            row_username = username_item.text().strip()
            row_ip_or_range = self._get_row_entry_value(row).strip()
            if row_username != username or row_ip_or_range != ip_or_range:
                continue

            source_index = self._model.index(row, USERNAME_COLUMN)
            proxy_index = self._proxy.mapFromSource(source_index)
            if not proxy_index.isValid():
                return

            selection = self._entries_table.selectionModel()
            if selection:
                selection.select(proxy_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
            self._entries_table.setCurrentIndex(proxy_index)
            self._entries_table.scrollTo(proxy_index)
            return

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
            self._navigate_to_database(Path(db_path_str), username=username, ip_or_range=ip_or_range)
