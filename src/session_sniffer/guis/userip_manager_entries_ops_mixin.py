"""Entries operations mixin for the UserIP Databases Manager dialog."""

from collections import defaultdict
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from PySide6.QtCore import QFileSystemWatcher, QItemSelectionModel, QModelIndex, QSignalBlocker, Qt, QTimer
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QTreeView,
)

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    DUPLICATE_HIGHLIGHT_BRUSH,
    INDEX_COLUMN,
    IP_COLUMN,
    RANGE_COLUMN,
    SETTINGS_DEFAULTS,
    SETTINGS_KEYS_ORDER,
    USERNAME_COLUMN,
    EntriesSortProxy,
    IPRangeBuilderDialog,
    append_userip_entries,
    iter_userip_databases,
    read_preserved_sections,
    rewrite_db_rename_entries,
    rewrite_db_without_entries,
)
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.text_utils import pluralize


class UserIPEntriesOperationsMixin(QDialog):
    """Mixin providing entry-level manipulation, editing, movement, deletion, saving, and filesystem synchronization.

    Expects these attributes on the concrete class:
        _entries_table, _proxy, _model, _current_path, _next_index,
        _global_search_active, _fs_watcher, _fs_sync_timer, _saving,
        _disk_snapshot, _settings_snapshot, _dirty, _search_input,
        _settings_container
    And these methods:
        _append_row, _mark_entries_dirty, _update_entry_counts, _set_status,
        _refresh_stats, _save_on_close, _clear_dirty_state, _update_file_info,
        _load_database, read_settings_from_widgets
    """

    # -- Attribute stubs for type checkers --
    _entries_table: QTreeView
    _proxy: EntriesSortProxy
    _model: QStandardItemModel
    _current_path: Path | None
    _next_index: int = 0
    _global_search_active: bool
    _fs_watcher: QFileSystemWatcher
    _fs_sync_timer: QTimer
    _saving: bool
    _disk_snapshot: str
    _settings_snapshot: dict[str, str]
    _dirty: bool
    _search_input: QLineEdit
    _settings_container: QFrame

    def _append_row(
        self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None, is_looky: bool = False
    ) -> None:
        raise NotImplementedError

    def _mark_entries_dirty(self) -> None: ...

    def _update_entry_counts(self) -> None: ...

    def _set_status(self, text: str) -> None:
        raise NotImplementedError

    def _refresh_stats(self) -> None: ...

    def _save_on_close(self) -> bool:
        return True

    def _clear_dirty_state(self) -> None: ...

    def _update_file_info(self, path: Path | None) -> None:
        raise NotImplementedError

    def _load_database(self, path: Path) -> None:
        raise NotImplementedError

    if TYPE_CHECKING:
        read_settings_from_widgets: Callable[[], dict[str, str]]

    # ------------------------------------------------------------------
    # Watch management
    # ------------------------------------------------------------------

    def _rebuild_fs_watch(self) -> None:
        """Point the filesystem watcher at the databases directory and the active file(s)."""
        watched = [*self._fs_watcher.files(), *self._fs_watcher.directories()]
        if watched:
            self._fs_watcher.removePaths(watched)

        paths: list[str] = [str(USERIP_DATABASES_DIR_PATH)]
        paths.extend(str(directory) for directory in USERIP_DATABASES_DIR_PATH.rglob('*') if directory.is_dir())

        if self._global_search_active:
            paths.extend(str(ini_path) for ini_path in USERIP_DATABASES_DIR_PATH.rglob('*.ini') if ini_path.is_file())
        elif self._current_path is not None and self._current_path.is_file():
            paths.append(str(self._current_path))

        self._fs_watcher.addPaths(paths)

    def _on_fs_changed(self, _path: str) -> None:
        """Coalesce rapid filesystem notifications before reconciling with disk."""
        self._fs_sync_timer.start()

    def _sync_from_disk(self) -> None:
        """Reconcile the entries view and stats with the current on-disk state."""
        if self._global_search_active:
            self._rebuild_fs_watch()
            self._refresh_stats()
            self._load_all_databases()
            return

        if self._current_path is None:
            self._rebuild_fs_watch()
            self._refresh_stats()
            return

        if not self._current_path.is_file():
            self._rebuild_fs_watch()
            self._refresh_stats()
            self._model.removeRows(0, self._model.rowCount())
            self._settings_container.setVisible(False)
            self._clear_dirty_state()
            self._set_status(f'"{self._current_path.name}" was removed on disk.')
            self._current_path = None
            self._update_file_info(None)
            return

        current_text = self._current_path.read_text('utf-8')
        if current_text == self._disk_snapshot:
            return  # No real change (or our own write).

        self._rebuild_fs_watch()
        self._refresh_stats()

        if self._dirty:
            self._update_file_info(self._current_path)
            self._set_status(f'"{self._current_path.name}" changed on disk. Save to overwrite, or reselect it to discard your edits and reload.')
            return

        self._load_database(self._current_path)
        self._set_status(f'Reloaded "{self._current_path.name}" after an external change.')

    # ------------------------------------------------------------------
    # Global search load
    # ------------------------------------------------------------------

    def _load_all_databases(self) -> None:
        """Parse all .ini files and populate the table with entries from every database."""
        self._model.removeRows(0, self._model.rowCount())

        total_entries = 0
        total_files = 0

        for ini_path, entries in iter_userip_databases():
            total_files += 1
            for username, ip, is_looky in entries:
                total_entries += 1
                self._append_row(username, ip, index=total_entries, database=(ini_path.stem, ini_path), is_looky=is_looky)

        self._set_status(f'Global search: {total_entries} entries across {total_files} databases')
        self._proxy.setFilterFixedString(self._search_input.text())
        self._update_entry_counts()

    # ------------------------------------------------------------------
    # Add / delete entries
    # ------------------------------------------------------------------

    def _add_entry(self) -> None:
        """Open the IP Range Builder dialog and insert the result as a new entry."""
        if self._current_path is None:
            return

        dialog = IPRangeBuilderDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        ip_text = dialog.result_entry()
        if not ip_text:
            return

        self._append_row('', ip_text, index=self._next_index)
        self._next_index += 1
        self._mark_entries_dirty()
        self._update_entry_counts()

        # Scroll to the new row and start editing the Username column
        last_source_row = self._model.rowCount() - 1
        proxy_index = self._proxy.mapFromSource(self._model.index(last_source_row, USERNAME_COLUMN))
        if proxy_index.isValid():
            self._entries_table.scrollTo(proxy_index)
            self._entries_table.setCurrentIndex(proxy_index)
            self._entries_table.edit(proxy_index)

    def _edit_selected_entry_ip(self) -> None:
        """Edit the IP/range of the currently selected entry via the builder button."""
        selection = self._entries_table.selectionModel()
        if not selection:
            return
        selected_rows = selection.selectedRows()
        if len(selected_rows) != 1:
            return
        source_row = self._proxy.mapToSource(selected_rows[0]).row()
        self._edit_entry_ip(source_row)

    def _edit_entry_ip(self, source_row: int) -> None:
        """Open the IP Range Builder dialog to edit the IP/range of an existing entry."""
        if self._current_path is None:
            return

        current_entry = self._get_row_entry_value(source_row)
        dialog = IPRangeBuilderDialog(self, initial_entry=current_entry or None)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        new_ip_text = dialog.result_entry()
        if not new_ip_text:
            return

        try:
            IPv4Address(new_ip_text)
            is_single = True
        except ValueError:
            is_single = False

        ip_item = self._model.item(source_row, IP_COLUMN)
        range_item = self._model.item(source_row, RANGE_COLUMN)
        if ip_item:
            ip_item.setText(new_ip_text if is_single else '')
        if range_item:
            range_item.setText('' if is_single else new_ip_text)

        self._mark_entries_dirty()
        self._highlight_duplicates()

    def _insert_entry_at(self, source_row: int) -> None:
        """Insert a blank row at a specific position in the source model."""
        if self._current_path is None:
            return

        index_item = QStandardItem('')
        index_item.setData(0, Qt.ItemDataRole.UserRole)
        index_item.setFlags(index_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        username_item = QStandardItem('')
        db_item = QStandardItem('')
        self._model.insertRow(source_row, [index_item, username_item, QStandardItem(''), QStandardItem(''), db_item])

        self._renumber_indexes()
        self._mark_entries_dirty()
        self._update_entry_counts()

        proxy_index = self._proxy.mapFromSource(self._model.index(source_row, USERNAME_COLUMN))
        if proxy_index.isValid():
            self._entries_table.scrollTo(proxy_index)
            self._entries_table.setCurrentIndex(proxy_index)
            self._entries_table.edit(proxy_index)

    def _add_username(self, source_row: int) -> None:
        """Insert a row below source_row with its IP or Range pre-filled, and start editing the username."""
        if self._current_path is None:
            return

        ip_item = self._model.item(source_row, IP_COLUMN)
        range_item = self._model.item(source_row, RANGE_COLUMN)
        ip_text = ip_item.text().strip() if ip_item else ''
        range_text = range_item.text().strip() if range_item else ''

        index_item = QStandardItem('')
        index_item.setData(0, Qt.ItemDataRole.UserRole)
        index_item.setFlags(index_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        username_item = QStandardItem('')
        db_item = QStandardItem('')

        self._model.insertRow(
            source_row + 1,
            [index_item, username_item, QStandardItem(ip_text), QStandardItem(range_text), db_item],
        )

        self._renumber_indexes()
        self._mark_entries_dirty()
        self._highlight_duplicates()
        self._update_entry_counts()

        proxy_index = self._proxy.mapFromSource(self._model.index(source_row + 1, USERNAME_COLUMN))
        if proxy_index.isValid():
            self._entries_table.scrollTo(proxy_index)
            self._entries_table.setCurrentIndex(proxy_index)
            selection_model = self._entries_table.selectionModel()
            if selection_model:
                selection_model.select(
                    proxy_index,
                    QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows,
                )
            self._entries_table.edit(proxy_index)

    def _move_rows(self, proxy_index: QModelIndex, direction: int) -> None:
        """Move selected rows up (direction=-1) or down (direction=+1) in the source model."""
        selection = self._entries_table.selectionModel()
        if not selection:
            return

        selected_proxy_rows = selection.selectedRows()
        if not selected_proxy_rows:
            selected_proxy_rows = [proxy_index]

        source_rows = sorted({self._proxy.mapToSource(i).row() for i in selected_proxy_rows})

        if direction < 0:
            if source_rows[0] <= 0:
                return
            for src_row in source_rows:
                items = self._model.takeRow(src_row)
                self._model.insertRow(src_row - 1, items)
        else:
            if source_rows[-1] >= self._model.rowCount() - 1:
                return
            for src_row in reversed(source_rows):
                items = self._model.takeRow(src_row)
                self._model.insertRow(src_row + 1, items)

        self._renumber_indexes()
        self._mark_entries_dirty()

        # Reselect the moved rows
        new_source_rows = [row + direction for row in source_rows]
        selection_model = self._entries_table.selectionModel()
        if selection_model:
            selection_model.clearSelection()
            for src_row in new_source_rows:
                p_index = self._proxy.mapFromSource(self._model.index(src_row, 0))
                if p_index.isValid():
                    selection_model.select(
                        p_index,
                        QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
                    )
            # Scroll to the first moved row
            first_proxy = self._proxy.mapFromSource(self._model.index(new_source_rows[0], 0))
            if first_proxy.isValid():
                self._entries_table.scrollTo(first_proxy)

    def _renumber_indexes(self) -> None:
        """Reassign sequential index numbers (1-based) to all rows in the source model."""
        for row in range(self._model.rowCount()):
            index_item = self._model.item(row, INDEX_COLUMN)
            if index_item:
                index_item.setText(str(row + 1))
                index_item.setData(row + 1, Qt.ItemDataRole.UserRole)
        self._next_index = self._model.rowCount() + 1

    def _rename_selected(self) -> None:
        """Rename the username of the selected entry or entries."""
        selection = self._entries_table.selectionModel()
        if not selection:
            return

        selected_indexes = selection.selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, TITLE, 'No entries selected.')
            return

        source_rows = sorted({self._proxy.mapToSource(index).row() for index in selected_indexes})
        count = len(source_rows)
        if not count:
            return

        if count == 1:
            first_row = source_rows[0]
            username_item = self._model.item(first_row, USERNAME_COLUMN)
            initial_name = username_item.text().strip() if username_item else ''
            title = 'Rename Username'
            prompt = 'Enter the new username:'
        else:
            usernames = {username for row in source_rows if (username := self._model.item(row, USERNAME_COLUMN).text().strip())}
            initial_name = next(iter(usernames)) if len(usernames) == 1 else ''
            title = f'Rename Selected ({count})'
            prompt = f'Enter the new username for {count} selected {pluralize(count, "entry", "entries")}:'

        new_username, success = QInputDialog.getText(
            self,
            title,
            prompt,
            QLineEdit.EchoMode.Normal,
            initial_name,
        )
        new_username = new_username.strip() if success else ''
        if not success:
            return

        if not new_username:
            QMessageBox.warning(self, TITLE, 'No username was provided.')
            return

        if count == 1 and new_username == initial_name:
            return

        if self._global_search_active:
            rows_by_database: dict[Path, list[tuple[int, str, str]]] = defaultdict(list)
            for row in source_rows:
                database_item = self._model.item(row, DATABASE_COLUMN)
                database_path_str = database_item.data(Qt.ItemDataRole.UserRole) if database_item else None
                if not database_path_str:
                    continue
                username_item = self._model.item(row, USERNAME_COLUMN)
                old_username = username_item.text().strip() if username_item else ''
                entry_ip_or_range = self._get_row_entry_value(row).strip()
                if old_username and entry_ip_or_range:
                    rows_by_database[Path(database_path_str)].append((row, old_username, entry_ip_or_range))

            with QSignalBlocker(self._fs_watcher):
                for database_path, entries in rows_by_database.items():
                    if database_path.is_file():
                        rename_pairs = [(old_name, ip_value) for _, old_name, ip_value in entries]
                        rewrite_db_rename_entries(database_path, rename_pairs, new_username)
            self._rebuild_fs_watch()

            for row in source_rows:
                username_item = self._model.item(row, USERNAME_COLUMN)
                if username_item:
                    username_item.setText(new_username)

            self._highlight_duplicates()
            self._update_entry_counts()
            self._set_status(f'Renamed {count} {pluralize(count, "entry", "entries")} to "{new_username}" in database files.')
        else:
            for row in source_rows:
                username_item = self._model.item(row, USERNAME_COLUMN)
                if username_item:
                    username_item.setText(new_username)

            self._mark_entries_dirty()
            self._highlight_duplicates()
            self._update_entry_counts()
            self._set_status(f'Renamed {count} {pluralize(count, "entry", "entries")} to "{new_username}". Remember to save.')

    def _delete_selected(self) -> None:
        """Delete selected rows after confirmation."""
        selection = self._entries_table.selectionModel()
        if not selection:
            return

        selected_indexes = selection.selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, TITLE, 'No entries selected.')
            return

        count = len(selected_indexes)
        source_rows = sorted(
            {self._proxy.mapToSource(i).row() for i in selected_indexes},
            reverse=True,
        )

        consequence = 'This will immediately write the changes to the database files.' if self._global_search_active else 'This action cannot be undone after saving.'

        result = QMessageBox.warning(
            self,
            TITLE,
            f'Are you sure you want to delete {count} selected {pluralize(count, "entry", "entries")}?\n\n{consequence}',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        if self._global_search_active:
            self._delete_global_search_rows(count, source_rows)
        else:
            for row in source_rows:
                self._model.removeRow(row)
            self._renumber_indexes()
            self._mark_entries_dirty()
            self._set_status(f'Deleted {count} {pluralize(count, "entry", "entries")}. Remember to save.')

    def _delete_global_search_rows(self, count: int, source_rows: list[int]) -> None:
        """Write deletions directly to database files and remove rows from the global search model."""
        rows_by_db: dict[str, list[int]] = defaultdict(list)
        for row in source_rows:
            db_item = self._model.item(row, DATABASE_COLUMN)
            db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
            if db_path_str:
                rows_by_db[db_path_str].append(row)

        for db_path_str, rows in rows_by_db.items():
            db_path = Path(db_path_str)
            if not db_path.is_file():
                continue
            to_remove: set[tuple[str, str]] = set()
            for row in rows:
                u_item = self._model.item(row, USERNAME_COLUMN)
                username = u_item.text() if u_item else ''
                ip = self._get_row_entry_value(row)
                if username and ip:
                    to_remove.add((username, ip))
            rewrite_db_without_entries(db_path, to_remove)

        for row in source_rows:
            self._model.removeRow(row)
        self._update_entry_counts()
        self._set_status(f'Deleted {count} {pluralize(count, "entry", "entries")} from database files.')

    def _move_selected_to_database(self, target_db_path: Path) -> None:
        """Move the selected entries to a different UserIP database."""
        selection = self._entries_table.selectionModel()
        if not selection:
            return

        selected_indexes = selection.selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, TITLE, 'No entries selected.')
            return

        source_rows = sorted({self._proxy.mapToSource(i).row() for i in selected_indexes})

        entries_to_move: list[tuple[str, str, bool, int]] = []
        for row in source_rows:
            u_item = self._model.item(row, USERNAME_COLUMN)
            username = u_item.text().strip() if u_item else ''
            ip_or_range = self._get_row_entry_value(row).strip()
            if not username or not ip_or_range:
                continue
            is_looky = bool(u_item.data(Qt.ItemDataRole.UserRole)) if u_item else False
            entries_to_move.append((username, ip_or_range, is_looky, row))

        if not entries_to_move:
            QMessageBox.information(self, TITLE, 'No valid entries to move.')
            return

        target_display_name = target_db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        count = len(entries_to_move)

        if self._global_search_active:
            entries_by_src: dict[Path, set[tuple[str, str]]] = defaultdict(set)
            valid_moves: list[tuple[str, str, bool, int]] = []

            for username, ip_or_range, is_looky, row in entries_to_move:
                db_item = self._model.item(row, DATABASE_COLUMN)
                db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
                if not db_path_str:
                    continue
                src_db_path = Path(db_path_str)
                if src_db_path == target_db_path:
                    continue
                entries_by_src[src_db_path].add((username, ip_or_range))
                valid_moves.append((username, ip_or_range, is_looky, row))

            if not valid_moves:
                QMessageBox.information(self, TITLE, f'Selected {pluralize(count, "entry", "entries")} already belong to "{target_display_name}".')
                return

            append_userip_entries(target_db_path, [(u, ip, lk) for u, ip, lk, _ in valid_moves])

            for src_db_path, to_remove in entries_by_src.items():
                if src_db_path.is_file():
                    rewrite_db_without_entries(src_db_path, to_remove)

            for _username, _ip, _is_looky, row in valid_moves:
                db_item = self._model.item(row, DATABASE_COLUMN)
                if db_item:
                    db_item.setText(str(target_display_name))
                    db_item.setData(str(target_db_path), Qt.ItemDataRole.UserRole)

            self._highlight_duplicates()
            self._refresh_stats()
            self._set_status(f'Moved {len(valid_moves)} {pluralize(len(valid_moves), "entry", "entries")} to "{target_display_name}".')
            self._rebuild_fs_watch()
        else:
            if self._current_path is None or target_db_path == self._current_path:
                return

            if self._dirty and not self._save_on_close():
                return

            append_userip_entries(target_db_path, [(u, ip, lk) for u, ip, lk, _ in entries_to_move])

            for row in sorted({r for _, _, _, r in entries_to_move}, reverse=True):
                self._model.removeRow(row)

            self._renumber_indexes()
            self._save_database()
            self._set_status(f'Moved {count} {pluralize(count, "entry", "entries")} to "{target_display_name}".')

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save_database(self) -> None:
        """Validate entries and write the database file back to disk."""
        if self._current_path is None or self._global_search_active:
            return

        self._saving = True
        self._fs_sync_timer.stop()
        try:
            with QSignalBlocker(self._fs_watcher):
                # Commit and close any active delegate editor before inspecting entries
                self._entries_table.setCurrentIndex(QModelIndex())
                self._entries_table.clearFocus()

                # --- Validate all entries ---
                errors: list[str] = []
                entries: list[tuple[str, str, bool]] = []

                for row in range(self._model.rowCount()):
                    username_item = self._model.item(row, USERNAME_COLUMN)
                    if not username_item:
                        continue

                    username = username_item.text().strip()
                    ip = self._get_row_entry_value(row)

                    if not username and not ip:
                        continue  # skip completely empty rows

                    if not username:
                        errors.append(f'Row {row + 1}: Username is empty.')
                    if not ip:
                        errors.append(f'Row {row + 1}: IP or Range is empty.')
                    elif not is_valid_ip_range_entry(ip):
                        errors.append(f'Row {row + 1}: "{ip}" is not a valid IP address or range.')

                    if username and ip:
                        is_looky = bool(username_item.data(Qt.ItemDataRole.UserRole))
                        entries.append((username, ip, is_looky))

                if errors:
                    QMessageBox.critical(self, TITLE, '\n'.join(errors))
                    return

                # --- Deduplicate exact (username, ip) pairs ---
                seen: set[tuple[str, str]] = set()
                unique_entries: list[tuple[str, str, bool]] = []
                duplicate_count = 0
                for entry in entries:
                    base_entry = (entry[0], entry[1])
                    if base_entry in seen:
                        duplicate_count += 1
                        continue
                    seen.add(base_entry)
                    unique_entries.append(entry)
                entries = unique_entries

                if duplicate_count > 0:
                    QMessageBox.information(
                        self,
                        TITLE,
                        f'{duplicate_count} exact duplicate entr{"y was" if duplicate_count == 1 else "ies were"} removed before saving.',
                    )

                # --- Read existing file to preserve header ---
                header_lines, _ = read_preserved_sections(self._current_path)

                # --- Build settings from widgets ---
                settings_values = self.read_settings_from_widgets()

                # --- Validate COLOR ---
                color_value = settings_values.get('COLOR', '')
                if color_value and not QColor(color_value).isValid():
                    QMessageBox.critical(self, TITLE, f'Invalid color value: "{color_value}"\n\nUse a Qt color name (e.g. RED, GREEN) or hex (e.g. #ff00ff).')
                    return

                # --- Build new file content ---
                output_lines: list[str] = [*header_lines]

                output_lines.append('[Settings]')
                output_lines.extend(f'{key}={settings_values.get(key, SETTINGS_DEFAULTS[key])}' for key in SETTINGS_KEYS_ORDER)
                output_lines.append('')

                output_lines.append('[UserIP]')
                for username, ip, is_looky in entries:
                    suffix = ' ; looky' if is_looky else ''
                    output_lines.append(f'{username}={ip}{suffix}')
                output_lines.append('')  # trailing newline

                written_content = '\r\n'.join(output_lines)
                self._current_path.write_text(written_content, encoding='utf-8', newline='')
                self._disk_snapshot = self._current_path.read_text('utf-8')

                self._settings_snapshot = settings_values.copy()
                self._clear_dirty_state()
                self._update_file_info(self._current_path)
                self._set_status(f'Saved {len(entries)} entries to {self._current_path.name}')
                self._refresh_stats()
                self._rebuild_fs_watch()
                if duplicate_count > 0:
                    self._load_database(self._current_path)
        finally:
            self._saving = False

    # ------------------------------------------------------------------
    # Duplicate highlighting
    # ------------------------------------------------------------------

    def _highlight_duplicates(self) -> int:
        """Scan all rows for exact (username, ip) duplicates and highlight them.

        Returns:
            The number of duplicate rows found.
        """
        seen: dict[tuple[str, str], int] = {}
        duplicate_rows: set[int] = set()

        for row in range(self._model.rowCount()):
            username_item = self._model.item(row, USERNAME_COLUMN)
            if not username_item:
                continue

            username = username_item.text().strip()
            ip = self._get_row_entry_value(row)
            if not username or not ip:
                continue

            key = (username, ip)
            if key in seen:
                duplicate_rows.add(row)
                duplicate_rows.add(seen[key])
            else:
                seen[key] = row

        with QSignalBlocker(self._model):
            for row in range(self._model.rowCount()):
                for column in range(DATABASE_COLUMN):
                    item = self._model.item(row, column)
                    if not item:
                        continue
                    if row in duplicate_rows:
                        item.setBackground(DUPLICATE_HIGHLIGHT_BRUSH)
                    else:
                        item.setData(None, Qt.ItemDataRole.BackgroundRole)

        return len(duplicate_rows)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_row_entry_value(self, row: int) -> str:
        """Return the effective IP or Range value from a row (whichever is non-empty)."""
        ip_item = self._model.item(row, IP_COLUMN)
        ip_text = ip_item.text().strip() if ip_item else ''
        if ip_text:
            return ip_text
        range_item = self._model.item(row, RANGE_COLUMN)
        return range_item.text().strip() if range_item else ''
