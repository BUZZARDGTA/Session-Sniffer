"""Entries operations mixin for the UserIP Databases Manager dialog."""

from collections import defaultdict
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QSignalBlocker, Qt
from PySide6.QtWidgets import QAbstractItemView, QDialog, QFrame, QInputDialog, QLineEdit, QMessageBox, QTreeView

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.select_usernames_dialog import prompt_username_input, prompt_usernames_input
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    DUPLICATE_HIGHLIGHT_BRUSH,
    INDEX_COLUMN,
    IP_COLUMN,
    NOTES_COLUMN,
    RANGE_COLUMN,
    USERNAME_COLUMN,
    EntriesSortProxy,
    IPRangeBuilderDialog,
    append_userip_entries,
    build_entry_row_items,
    clear_row_looky_badge,
    dedup_userip_entries,
    extract_entry_model_from_row,
    is_row_persisted,
    iter_userip_databases,
    mark_row_persisted,
    refresh_userip_and_wake_renderer,
    rewrite_db_edit_entry_ip,
    rewrite_db_edit_entry_note,
    rewrite_db_rename_entries,
    rewrite_db_without_entries,
    save_userip_database_model,
    set_row_updated_at,
)
from session_sniffer.models.userip_settings_model import (
    UserIPDatabaseFile,
    UserIPEntryModel,
    UserIPSettingsModel,
    get_current_iso_timestamp,
)
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_loader import enrich_userip_entry_from_logs, update_userip_databases
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.text_utils import pluralize, split_usernames

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QIcon, QStandardItemModel

    from session_sniffer.guis.file_watch import DebouncedFileWatcher


class UserIPEntriesOperationsMixin(QDialog):
    """Mixin providing entry-level manipulation, editing, movement, deletion, saving, and filesystem synchronization.

    Expects these attributes on the concrete class:
        _entries_table, _proxy, _model, _current_path, _next_index,
        _global_search_active, _fs_watcher, _saving,
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
    _fs_watcher: DebouncedFileWatcher
    _saving: bool
    _disk_snapshot: str
    _settings_snapshot: UserIPSettingsModel
    _dirty: bool
    _search_input: QLineEdit
    _settings_container: QFrame
    _looky_icon: QIcon

    def _append_row(
        self,
        entry: UserIPEntryModel,
        *,
        index: int = 0,
        database: tuple[str, Path] | None = None,
        persisted: bool = True,
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
        read_settings_from_widgets: Callable[[], UserIPSettingsModel]

    # ------------------------------------------------------------------
    # Watch management
    # ------------------------------------------------------------------

    def _rebuild_fs_watch(self) -> None:
        """Point the filesystem watcher at the databases directory and all database files."""
        directories: list[Path] = [USERIP_DATABASES_DIR_PATH]
        directories.extend(directory for directory in USERIP_DATABASES_DIR_PATH.rglob('*') if directory.is_dir())
        files = [json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()]
        self._fs_watcher.watch(files=files, directories=directories)

    def _sync_from_disk(self) -> None:
        """Reconcile the entries view and stats with the current on-disk state."""
        _, databases_rebuilt = update_userip_databases()
        if databases_rebuilt:
            wake_rendering_core()
        self._rebuild_fs_watch()
        self._refresh_stats()

        if self._global_search_active:
            self._load_all_databases()
            return

        if self._current_path is None:
            return

        if not self._current_path.is_file():
            self._model.removeRows(0, self._model.rowCount())
            self._settings_container.setVisible(False)
            self._clear_dirty_state()
            self._set_status(f'"{self._current_path.name}" was removed on disk.')
            self._current_path = None
            self._update_file_info(None)
            return

        try:
            current_text = self._current_path.read_text('utf-8')
        except OSError:
            return
        if current_text == self._disk_snapshot:
            return  # No real change (or our own write).

        if self._dirty or self._entries_table.state() == QAbstractItemView.State.EditingState:
            self._update_file_info(self._current_path)
            self._set_status(f'"{self._current_path.name}" changed on disk. Save to overwrite, or reselect it to discard your edits and reload.')
            return

        active_search = self._search_input.text()
        self._load_database(self._current_path)
        if active_search:
            self._search_input.setText(active_search)
        self._set_status(f'Reloaded "{self._current_path.name}" after an external change.')

    # ------------------------------------------------------------------
    # Global search load
    # ------------------------------------------------------------------

    def _load_all_databases(self) -> None:
        """Parse all .json files and populate the table with entries from every database."""
        self._model.removeRows(0, self._model.rowCount())

        total_entries = 0
        total_files = 0

        for json_path, entries in iter_userip_databases():
            total_files += 1
            for entry in entries:
                total_entries += 1
                self._append_row(
                    entry,
                    index=total_entries,
                    database=(json_path.stem, json_path),
                )

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

        self._append_row(UserIPEntryModel(username='', ip=ip_text), index=self._next_index, persisted=False)
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
        source_rows = self._get_selected_source_rows()
        if len(source_rows) == 1:
            self._edit_entry_ip(source_rows[0])

    def _set_row_ip_or_range(self, source_row: int, new_ip_text: str, *, is_single: bool) -> None:
        """Update the IP and Range column cells for `source_row` and clear its Looky badge."""
        ip_item = self._model.item(source_row, IP_COLUMN)
        range_item = self._model.item(source_row, RANGE_COLUMN)
        if ip_item:
            ip_item.setText(new_ip_text if is_single else '')
        if range_item:
            range_item.setText('' if is_single else new_ip_text)
        clear_row_looky_badge(self._model, source_row)

    def _edit_entry_ip(self, source_row: int) -> None:
        """Open the IP Range Builder dialog to edit the IP/range of an existing entry."""
        if not self._global_search_active and self._current_path is None:
            return

        current_entry = self._get_row_entry_value(source_row)
        dialog = IPRangeBuilderDialog(self, initial_entry=current_entry or None)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        new_ip_text = dialog.result_entry()
        if not new_ip_text or new_ip_text == current_entry:
            return

        try:
            IPv4Address(new_ip_text)
            is_single = True
        except ValueError:
            is_single = False

        if self._global_search_active:
            database_path = self._get_row_database_path(source_row)
            username = self._get_row_username(source_row)
            if not database_path or not database_path.is_file() or not username:
                return

            with QSignalBlocker(self._fs_watcher):
                success = bool(rewrite_db_edit_entry_ip(database_path, current_entry, new_ip_text, username=username))
                if success:
                    refresh_userip_and_wake_renderer()
            self._rebuild_fs_watch()

            if not success:
                return

            self._set_row_ip_or_range(source_row, new_ip_text, is_single=is_single)
            set_row_updated_at(self._model, source_row)
            extract_entry_model_from_row(self._model, source_row)

            self._dedup_global_search_rows()
            self._highlight_duplicates()
            self._refresh_stats()
            self._update_entry_counts()
            self._set_status(f'Updated entry to "{new_ip_text}" in {database_path.name}.')
        else:
            with QSignalBlocker(self._model):
                self._set_row_ip_or_range(source_row, new_ip_text, is_single=is_single)
                if is_row_persisted(self._model, source_row):
                    set_row_updated_at(self._model, source_row)

            self._mark_entries_dirty()
            self._highlight_duplicates()
            self._update_entry_counts()
            self._save_database()
            if not self._dirty:
                self._set_status(f'Updated entry to "{new_ip_text}".')
        UserIPDatabases.renotify_if_conflicting([new_ip_text])

    def _edit_entry_note(self, source_row: int) -> None:
        """Open a text input dialog to edit the note of an existing entry."""
        if not self._global_search_active and self._current_path is None:
            return

        notes_item = self._model.item(source_row, NOTES_COLUMN)
        current_note = notes_item.text().strip() if notes_item else ''

        dialog_title = 'Edit Note' if current_note else 'Add Note'
        note_prompt = 'Enter the note' if current_note else 'Enter a note'
        new_note, accepted = QInputDialog.getText(
            self,
            dialog_title,
            f'{note_prompt} for this entry (leave empty to clear):',
            QLineEdit.EchoMode.Normal,
            current_note,
        )
        if not accepted:
            return
        new_note = new_note.strip()
        if new_note == current_note:
            return

        if self._global_search_active:
            database_path = self._get_row_database_path(source_row)
            username = self._get_row_username(source_row)
            entry_ip_or_range = self._get_row_entry_value(source_row)
            if not database_path or not database_path.is_file() or not username or not entry_ip_or_range:
                return

            with QSignalBlocker(self._fs_watcher):
                success = rewrite_db_edit_entry_note(database_path, username, entry_ip_or_range, new_note)
                if success:
                    refresh_userip_and_wake_renderer()
            self._rebuild_fs_watch()

            if not success:
                return

            if notes_item:
                notes_item.setText(new_note)
            set_row_updated_at(self._model, source_row)

            self._set_status(f'Updated note for "{username}" in {database_path.name}.')
        else:
            with QSignalBlocker(self._model):
                if notes_item:
                    notes_item.setText(new_note)
                if is_row_persisted(self._model, source_row):
                    set_row_updated_at(self._model, source_row)

            self._mark_entries_dirty()
            self._save_database()
            if not self._dirty:
                self._set_status('Updated note.')

    def _insert_entry_at(self, source_row: int) -> None:
        """Insert a blank row at a specific position in the source model."""
        if self._current_path is None:
            return

        self._model.insertRow(
            source_row,
            build_entry_row_items(UserIPEntryModel(username='', ip=''), persisted=False),
        )

        self._renumber_indexes()
        self._mark_entries_dirty()
        self._update_entry_counts()

        proxy_index = self._proxy.mapFromSource(self._model.index(source_row, USERNAME_COLUMN))
        if proxy_index.isValid():
            self._entries_table.scrollTo(proxy_index)
            self._entries_table.setCurrentIndex(proxy_index)
            self._entries_table.edit(proxy_index)

    def _prompt_new_usernames(self, prompt: str | Callable[[int], str]) -> list[str]:
        """Prompt the user for one or more usernames."""
        entered_usernames, accepted = prompt_usernames_input(self, 'Add Username(s)', prompt)
        return entered_usernames if accepted else []

    def _add_username_global_search(self, source_row: int, ip_text: str, range_text: str) -> None:
        """Prompt for usernames and append them directly to the entry's database in global search mode."""
        entry_value = ip_text or range_text
        database_item = self._model.item(source_row, DATABASE_COLUMN)
        database_path = self._get_row_database_path(source_row)
        if not database_path or not database_path.is_file():
            return

        new_usernames = self._prompt_new_usernames(
            lambda count: f'Enter the username{pluralize(count)} to add for {entry_value} in "{database_path.stem}":',
        )
        if not new_usernames:
            return

        new_entry_models = [
            enrich_userip_entry_from_logs(UserIPEntryModel(username=name, ip=entry_value))[0]
            for name in new_usernames
        ]
        with QSignalBlocker(self._fs_watcher):
            added_pairs = append_userip_entries(database_path, new_entry_models)
            if added_pairs:
                refresh_userip_and_wake_renderer()
        self._rebuild_fs_watch()

        if not added_pairs:
            QMessageBox.information(
                self,
                TITLE,
                f'All specified username{pluralize(len(new_usernames))} already exist for {entry_value} in "{database_path.stem}".',
            )
            return

        database_label = database_item.text() if database_item else database_path.stem
        insert_at = source_row + 1
        for entry_model in new_entry_models:
            if (entry_model.username, entry_value) not in added_pairs:
                continue
            self._model.insertRow(
                insert_at,
                build_entry_row_items(entry_model, database=(database_label, database_path), persisted=True),
            )
            insert_at += 1

        self._renumber_indexes()
        self._highlight_duplicates()
        self._refresh_stats()
        self._update_entry_counts()
        added_count = len(added_pairs)
        self._set_status(f'Added {added_count} username{pluralize(added_count)} for {entry_value} in {database_path.name}.')
        UserIPDatabases.renotify_if_conflicting([entry_value])

    def _add_username_filtered(self, source_row: int, ip_text: str, range_text: str) -> None:
        """Prompt for usernames and insert rows into the single-DB model when a search filter is active."""
        entry_value = ip_text or range_text
        new_usernames = self._prompt_new_usernames(
            lambda count: f'Enter the username{pluralize(count)} to add for {entry_value}:',
        )
        if not new_usernames:
            return

        before_count = self._model.rowCount()
        insert_at = source_row + 1
        for added_name in new_usernames:
            enriched_entry, _ = enrich_userip_entry_from_logs(UserIPEntryModel(username=added_name, ip=entry_value))
            self._model.insertRow(
                insert_at,
                build_entry_row_items(enriched_entry, persisted=True),
            )
            insert_at += 1

        self._renumber_indexes()
        self._mark_entries_dirty()
        self._highlight_duplicates()
        self._update_entry_counts()
        self._save_database()
        if not self._dirty:
            added_count = max(0, self._model.rowCount() - before_count)
            if added_count > 0:
                self._set_status(f'Added {added_count} username{pluralize(added_count)} for {entry_value}.')
                UserIPDatabases.renotify_if_conflicting([entry_value])

    def _add_username(self, source_row: int) -> None:
        """Insert a row below source_row with its IP or Range pre-filled, or prompt in global search / filtered view."""
        if not self._global_search_active and self._current_path is None:
            return

        ip_item = self._model.item(source_row, IP_COLUMN)
        range_item = self._model.item(source_row, RANGE_COLUMN)
        ip_text = ip_item.text().strip() if ip_item else ''
        range_text = range_item.text().strip() if range_item else ''
        if not (ip_text or range_text):
            return

        if self._global_search_active:
            self._add_username_global_search(source_row, ip_text, range_text)
            return

        if self._search_input.text().strip():
            self._add_username_filtered(source_row, ip_text, range_text)
            return

        self._model.insertRow(
            source_row + 1,
            build_entry_row_items(UserIPEntryModel(username='', ip=ip_text or range_text), persisted=False),
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

        selected_proxy_rows = selection.selectedRows() or [proxy_index]
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
        self._save_database(show_errors=False)

        # Reselect the moved rows
        new_source_rows = [row + direction for row in source_rows]
        selection.clearSelection()
        for src_row in new_source_rows:
            p_index = self._proxy.mapFromSource(self._model.index(src_row, 0))
            if p_index.isValid():
                selection.select(
                    p_index,
                    QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
                )
        first_proxy = self._proxy.mapFromSource(self._model.index(new_source_rows[0], 0))
        if first_proxy.isValid():
            self._entries_table.scrollTo(first_proxy)

    def _renumber_indexes(self) -> None:
        """Reassign sequential index numbers (1-based) to all rows in the source model."""
        with QSignalBlocker(self._model):
            for row in range(self._model.rowCount()):
                index_item = self._model.item(row, INDEX_COLUMN)
                if index_item:
                    index_item.setText(str(row + 1))
                    index_item.setData(row + 1, Qt.ItemDataRole.UserRole)
        self._next_index = self._model.rowCount() + 1

    def _rename_selected(self) -> None:
        """Rename the username of the selected entry or entries."""
        source_rows = self._get_selected_source_rows(warn_if_empty=True)
        if not source_rows:
            return
        count = len(source_rows)

        if count == 1:
            initial_name = self._get_row_username(source_rows[0])
            title = 'Rename Username'
            prompt = 'Enter the new username:'
        else:
            usernames = {username for row in source_rows if (username := self._get_row_username(row))}
            initial_name = next(iter(usernames)) if len(usernames) == 1 else ''
            title = f'Rename Selected ({count})'
            prompt = f'Enter the new username for {count} selected {pluralize(count, "entry", "entries")}:'

        new_username, success = prompt_username_input(self, title, prompt, initial_name)
        new_username = new_username.strip() if success else ''
        if not success:
            return

        if not new_username:
            QMessageBox.warning(self, TITLE, 'No username was provided.')
            return

        if count == 1 and new_username == initial_name:
            return

        renamed_entries = [val for row in source_rows if (val := self._get_row_entry_value(row))]
        if self._global_search_active:
            rows_by_database: dict[Path, list[tuple[int, str, str]]] = defaultdict(list)
            for row in source_rows:
                database_path = self._get_row_database_path(row)
                old_username = self._get_row_username(row)
                entry_ip_or_range = self._get_row_entry_value(row)
                if database_path and old_username and old_username != new_username and entry_ip_or_range:
                    rows_by_database[database_path].append((row, old_username, entry_ip_or_range))

            renamed_count = 0
            with QSignalBlocker(self._fs_watcher):
                for database_path, entries in rows_by_database.items():
                    if database_path.is_file():
                        rename_pairs = [(old_name, ip_value) for _, old_name, ip_value in entries]
                        renamed_count += rewrite_db_rename_entries(database_path, rename_pairs, new_username)
                if renamed_count:
                    refresh_userip_and_wake_renderer()
            self._rebuild_fs_watch()

            if not renamed_count:
                return

            for row in source_rows:
                self._model.item(row, USERNAME_COLUMN).setText(new_username)
                clear_row_looky_badge(self._model, row)
                set_row_updated_at(self._model, row)

            self._dedup_global_search_rows()
            self._highlight_duplicates()
            self._refresh_stats()
            self._update_entry_counts()
            self._set_status(f'Renamed {renamed_count} {pluralize(renamed_count, "entry", "entries")} to "{new_username}" in database files.')
        else:
            with QSignalBlocker(self._model):
                for row in source_rows:
                    self._model.item(row, USERNAME_COLUMN).setText(new_username)
                    clear_row_looky_badge(self._model, row)
                    if is_row_persisted(self._model, row):
                        set_row_updated_at(self._model, row)

            self._mark_entries_dirty()
            self._highlight_duplicates()
            self._update_entry_counts()
            self._save_database()
            if not self._dirty:
                self._set_status(f'Renamed {count} {pluralize(count, "entry", "entries")} to "{new_username}".')
        UserIPDatabases.renotify_if_conflicting(renamed_entries)

    def _delete_selected(self) -> None:
        """Delete selected rows after confirmation."""
        source_rows = list(reversed(self._get_selected_source_rows(warn_if_empty=True)))
        if not source_rows:
            return
        count = len(source_rows)

        result = QMessageBox.warning(
            self,
            TITLE,
            f'Are you sure you want to delete {count} selected {pluralize(count, "entry", "entries")}?\n\n'
            'This will immediately write the changes to the database files.',
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
            self._highlight_duplicates()
            self._update_entry_counts()
            self._mark_entries_dirty()
            self._save_database()
            if not self._dirty:
                self._set_status(f'Deleted {count} {pluralize(count, "entry", "entries")}.')

    def _delete_global_search_rows(self, count: int, source_rows: list[int]) -> None:
        """Write deletions directly to database files and remove rows from the global search model."""
        rows_by_db: dict[Path, list[int]] = defaultdict(list)
        for row in source_rows:
            if (db_path := self._get_row_database_path(row)) is not None:
                rows_by_db[db_path].append(row)

        with QSignalBlocker(self._fs_watcher):
            for db_path, rows in rows_by_db.items():
                if not db_path.is_file():
                    continue
                to_remove = {
                    (username, ip)
                    for row in rows
                    if (username := self._get_row_username(row)) and (ip := self._get_row_entry_value(row))
                }
                rewrite_db_without_entries(db_path, to_remove)
            refresh_userip_and_wake_renderer()
        self._rebuild_fs_watch()

        for row in source_rows:
            self._model.removeRow(row)
        self._renumber_indexes()
        self._highlight_duplicates()
        self._refresh_stats()
        self._update_entry_counts()
        self._set_status(f'Deleted {count} {pluralize(count, "entry", "entries")} from database files.')

    def _move_selected_to_database(self, target_db_path: Path) -> None:
        """Move the selected entries to a different UserIP database."""
        source_rows = self._get_selected_source_rows(warn_if_empty=True)
        if not source_rows:
            return
        now_iso = get_current_iso_timestamp()

        entries_to_move: list[tuple[UserIPEntryModel, int]] = []
        for row in source_rows:
            _, _, _, entry_model = extract_entry_model_from_row(self._model, row)
            if entry_model is not None:
                entries_to_move.append((entry_model.model_copy(update={'updated_at': now_iso}), row))

        if not entries_to_move:
            QMessageBox.information(self, TITLE, 'No valid entries to move.')
            return

        target_display_name = target_db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        count = len(entries_to_move)

        if self._global_search_active:
            entries_by_src: dict[Path, set[tuple[str, str]]] = defaultdict(set)
            valid_moves: list[tuple[UserIPEntryModel, int]] = []

            for entry_model, row in entries_to_move:
                src_db_path = self._get_row_database_path(row)
                if src_db_path is None or src_db_path == target_db_path:
                    continue
                entries_by_src[src_db_path].add((entry_model.username, entry_model.ip))
                valid_moves.append((entry_model, row))

            if not valid_moves:
                QMessageBox.information(self, TITLE, f'Selected {pluralize(count, "entry", "entries")} already belong to "{target_display_name}".')
                return

            with QSignalBlocker(self._fs_watcher):
                added_pairs = append_userip_entries(target_db_path, [entry_model for entry_model, _ in valid_moves])
                for src_db_path, to_remove in entries_by_src.items():
                    if src_db_path.is_file():
                        rewrite_db_without_entries(src_db_path, to_remove)
                refresh_userip_and_wake_renderer()
            self._rebuild_fs_watch()

            added_pairs_cf = {(u.casefold(), ip) for u, ip in added_pairs}
            rows_to_remove: list[int] = []
            for entry_model, row in valid_moves:
                pair = (entry_model.username.casefold(), entry_model.ip)
                if pair in added_pairs_cf:
                    added_pairs_cf.discard(pair)
                    if db_item := self._model.item(row, DATABASE_COLUMN):
                        db_item.setText(str(target_display_name))
                        db_item.setData(str(target_db_path), Qt.ItemDataRole.UserRole)
                    set_row_updated_at(self._model, row, now_iso)
                else:
                    rows_to_remove.append(row)

            for row in sorted(rows_to_remove, reverse=True):
                self._model.removeRow(row)

            if rows_to_remove:
                self._renumber_indexes()
                self._update_entry_counts()
            self._highlight_duplicates()
            self._refresh_stats()
            self._set_status(f'Moved {len(valid_moves)} {pluralize(len(valid_moves), "entry", "entries")} to "{target_display_name}".')
        else:
            if self._current_path is None or target_db_path == self._current_path:
                return

            if self._dirty and not self._save_on_close():
                return

            append_userip_entries(target_db_path, [entry_model for entry_model, _ in entries_to_move])

            for row in sorted({r for _, r in entries_to_move}, reverse=True):
                self._model.removeRow(row)

            self._renumber_indexes()
            self._highlight_duplicates()
            self._update_entry_counts()
            self._save_database()
            self._set_status(f'Moved {count} {pluralize(count, "entry", "entries")} to "{target_display_name}".')
        UserIPDatabases.renotify_if_conflicting([entry_model.ip for entry_model, _ in entries_to_move])

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save_database(self, *, show_errors: bool = True) -> None:
        """Validate entries and write the database file back to disk."""
        if self._current_path is None or self._global_search_active:
            return

        self._saving = True
        try:
            with QSignalBlocker(self._fs_watcher):
                if show_errors and self._entries_table.state() == QAbstractItemView.State.EditingState:
                    # Commit and close any active delegate editor before inspecting entries
                    self._entries_table.setCurrentIndex(QModelIndex())
                    self._entries_table.clearFocus()

                # --- Validate all entries ---
                errors: list[str] = []
                entries: list[UserIPEntryModel] = []
                persisted_rows: list[int] = []
                split_or_repaired = False

                for row in range(self._model.rowCount()):
                    username, ip, notes, entry_model = extract_entry_model_from_row(self._model, row)

                    if not username and not ip and not notes:
                        continue  # skip completely empty rows

                    split_names = split_usernames(username)
                    if not split_names:
                        errors.append(f'Row {row + 1}: Username is empty.')
                    if not ip:
                        errors.append(f'Row {row + 1}: IP or Range is empty.')
                    elif not is_valid_ip_range_entry(ip):
                        errors.append(f'Row {row + 1}: "{ip}" is not a valid IP address or range.')

                    if entry_model is not None and split_names and is_valid_ip_range_entry(ip):
                        if len(split_names) > 1 or split_names[0] != entry_model.username:
                            split_or_repaired = True
                        entries.extend(
                            entry_model if split_name == entry_model.username else entry_model.model_copy(update={'username': split_name})
                            for split_name in split_names
                        )
                        persisted_rows.append(row)

                if errors:
                    if show_errors:
                        QMessageBox.critical(self, TITLE, '\n'.join(errors))
                    return

                # --- Deduplicate exact (username, ip) pairs ---
                total_before_dedup = len(entries)
                entries = dedup_userip_entries(entries)
                duplicate_count = total_before_dedup - len(entries)

                if duplicate_count > 0:
                    QMessageBox.information(
                        self,
                        TITLE,
                        f'{duplicate_count} exact duplicate entr{pluralize(duplicate_count, "y was", "ies were")} removed before saving.',
                    )

                with QSignalBlocker(self._model):
                    for row in persisted_rows:
                        mark_row_persisted(self._model, row)

                # --- Build settings from widgets ---
                settings_model = self.read_settings_from_widgets()

                # --- Write new JSON file content ---
                db_model = UserIPDatabaseFile(settings=settings_model, entries=entries)
                save_userip_database_model(self._current_path, db_model)
                refresh_userip_and_wake_renderer()
                self._disk_snapshot = self._current_path.read_text('utf-8')

                self._settings_snapshot = settings_model.model_copy()
                self._clear_dirty_state()
                self._update_file_info(self._current_path)
                self._set_status(f'Saved {len(entries)} entries to {self._current_path.name}')
                self._refresh_stats()
                self._rebuild_fs_watch()
                if duplicate_count > 0 or split_or_repaired:
                    active_search = self._search_input.text()
                    self._load_database(self._current_path)
                    if active_search:
                        self._search_input.setText(active_search)
        finally:
            self._saving = False

    # ------------------------------------------------------------------
    # Duplicate highlighting
    # ------------------------------------------------------------------

    def _dedup_global_search_rows(self) -> None:
        """Merge and remove duplicate `(database, username, ip)` rows in-place in global search mode."""
        seen_rows: dict[tuple[str, str, str], int] = {}
        duplicate_pairs: list[tuple[int, int]] = []

        for row in range(self._model.rowCount()):
            db_path = self._get_row_database_path(row)
            username = self._get_row_username(row)
            ip = self._get_row_entry_value(row)
            if not db_path or not username or not ip:
                continue
            key = (str(db_path), username.casefold(), ip)
            if key in seen_rows:
                duplicate_pairs.append((seen_rows[key], row))
            else:
                seen_rows[key] = row

        if not duplicate_pairs:
            return

        merged_by_row: dict[int, UserIPEntryModel] = {}
        rows_to_remove: list[int] = []
        for first_row, dup_row in duplicate_pairs:
            base_model = merged_by_row.get(first_row) or extract_entry_model_from_row(self._model, first_row)[3]
            dup_model = extract_entry_model_from_row(self._model, dup_row)[3]
            if base_model is not None and dup_model is not None:
                merged_by_row[first_row] = base_model.merge_duplicate(dup_model)
                rows_to_remove.append(dup_row)

        if not rows_to_remove:
            return

        with QSignalBlocker(self._model):
            for first_row, merged_model in merged_by_row.items():
                db_item = self._model.item(first_row, DATABASE_COLUMN)
                db_label = db_item.text() if db_item else ''
                db_path = self._get_row_database_path(first_row) or Path()
                row_index = int(self._model.item(first_row, INDEX_COLUMN).data(Qt.ItemDataRole.UserRole) or (first_row + 1))
                new_items = build_entry_row_items(
                    merged_model,
                    index=row_index,
                    database=(db_label, db_path),
                    looky_icon=self._looky_icon,
                    persisted=True,
                )
                for col, item in enumerate(new_items):
                    self._model.setItem(first_row, col, item)
            for row in sorted(rows_to_remove, reverse=True):
                self._model.removeRow(row)

        self._renumber_indexes()

    def _highlight_duplicates(self) -> int:
        """Scan all rows for exact (username, ip) duplicates and highlight them.

        Returns:
            The number of duplicate rows found.
        """
        seen: dict[tuple[str, str], int] = {}
        duplicate_rows: set[int] = set()

        for row in range(self._model.rowCount()):
            username = self._get_row_username(row)
            ip = self._get_row_entry_value(row)
            if not username or not ip:
                continue

            key = (username.casefold(), ip)
            if key in seen:
                duplicate_rows.add(row)
                duplicate_rows.add(seen[key])
            else:
                seen[key] = row

        with QSignalBlocker(self._model):
            for row in range(self._model.rowCount()):
                for column in range(self._model.columnCount()):
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

    def _get_selected_source_rows(self, *, warn_if_empty: bool = False) -> list[int]:
        """Return sorted source-model row indices for the current selection."""
        selection = self._entries_table.selectionModel()
        selected_indexes = selection.selectedRows() if selection else []
        if not selected_indexes:
            if warn_if_empty:
                QMessageBox.information(self, TITLE, 'No entries selected.')
            return []
        return sorted({self._proxy.mapToSource(index).row() for index in selected_indexes})

    def _get_row_database_path(self, row: int) -> Path | None:
        """Return the database file path stored on `row` in global search mode, if any."""
        db_item = self._model.item(row, DATABASE_COLUMN)
        db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
        return Path(str(db_path_str)) if db_path_str else None

    def _get_row_username(self, row: int) -> str:
        """Return the stripped username text from `row`."""
        username_item = self._model.item(row, USERNAME_COLUMN)
        return username_item.text().strip() if username_item else ''

    def _get_row_entry_value(self, row: int) -> str:
        """Return the effective IP or Range value from a row (whichever is non-empty)."""
        ip_item = self._model.item(row, IP_COLUMN)
        ip_text = ip_item.text().strip() if ip_item else ''
        if ip_text:
            return ip_text
        range_item = self._model.item(row, RANGE_COLUMN)
        return range_item.text().strip() if range_item else ''
