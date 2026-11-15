"""Entries operations mixin for the UserIP Databases Manager dialog."""

from collections import defaultdict
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPersistentModelIndex, QSignalBlocker, Qt
from PySide6.QtWidgets import QAbstractItemView, QDialog, QFrame, QInputDialog, QLineEdit, QMessageBox, QTreeView

from session_sniffer.constants.local import APP_DIR_ROAMING, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.select_usernames_dialog import prompt_username_input, prompt_usernames_and_notes_input
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
    append_entry_rows,
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
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.userip_settings_model import UserIPDatabaseFile, UserIPEntryModel, UserIPSettingsModel
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import MIN_GROUP_USERNAMES, USERIP_GROUPS_PATH, are_usernames_unlinked, group_usernames
from session_sniffer.player.userip_loader import (
    append_userip_entries,
    is_in_app_userip_db_content,
    update_userip_databases,
    userip_databases_lock,
)
from session_sniffer.player.userip_log_history import enrich_userip_entry_from_logs
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QIcon, QStandardItem, QStandardItemModel

    from session_sniffer.guis.file_watch import DebouncedFileWatcher


class UserIPEntriesOperationsMixin(QDialog):
    """Mixin providing entry-level manipulation, editing, movement, deletion, saving, and filesystem synchronization."""

    # -- Attribute stubs for type checkers --
    _entries_table: QTreeView
    _proxy: EntriesSortProxy
    _model: QStandardItemModel
    _current_path: Path | None
    _next_index: int = 0
    _last_seen_build_version: int = 0
    _global_search_active: bool
    _fs_watcher: DebouncedFileWatcher
    _saving: bool
    _disk_snapshot: str
    _settings_snapshot: UserIPSettingsModel
    _dirty: bool
    _search_input: QLineEdit
    _settings_container: QFrame
    _looky_icon: QIcon

    if TYPE_CHECKING:
        read_settings_from_widgets: Callable[[], UserIPSettingsModel]
        _account_group_clusters_map: Callable[[], dict[str, list[str]]]
        _get_selected_source_rows: Callable[..., list[int]]
        _get_row_database_path: Callable[[int], Path | None]
        _get_row_username: Callable[[int], str]
        _get_row_entry_value: Callable[[int], str]

        def _mark_entries_dirty(self) -> None: ...
        def _update_entry_counts(self) -> None: ...
        def _refresh_stats(self) -> None: ...
        def _clear_dirty_state(self) -> None: ...
        def _refresh_tree_visuals(self) -> None: ...
        def _refresh_table_after_grouping(self) -> None: ...

        def _set_status(self, text: str) -> None:
            del text

        def _save_on_close(self) -> bool:
            raise NotImplementedError

        def _update_file_info(self, path: Path | None) -> None:
            del path

        def _load_database(self, path: Path) -> None:
            del path

    def _rebuild_fs_watch(self) -> None:
        """Point the filesystem watcher at the databases directory and all database files."""
        directories: list[Path] = [APP_DIR_ROAMING, USERIP_DATABASES_DIR_PATH]
        directories.extend(directory for directory in USERIP_DATABASES_DIR_PATH.rglob('*') if directory.is_dir())
        files = [p for p in (*USERIP_DATABASES_DIR_PATH.rglob('*.json'), USERIP_GROUPS_PATH) if p.is_file()]
        self._fs_watcher.watch(files=files, directories=directories)

    def _sync_from_disk(self) -> None:
        """Reconcile the entries view and stats with the current on-disk state."""
        self._refresh_tree_visuals()
        _, databases_rebuilt = update_userip_databases()
        if databases_rebuilt:
            wake_rendering_core()
        build_version_changed = UserIPDatabases.build_version != self._last_seen_build_version
        self._last_seen_build_version = UserIPDatabases.build_version
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
            self._set_status(tr('"{name}" was removed on disk.', name=self._current_path.name))
            self._current_path = None
            self._update_file_info(None)
            return
        try:
            current_text = self._current_path.read_text('utf-8')
        except OSError:
            return
        if current_text == self._disk_snapshot:
            if databases_rebuilt or build_version_changed:
                self._proxy.refresh_groups()
                if viewport := self._entries_table.viewport():
                    viewport.update()
            return
        if self._dirty or self._entries_table.state() == QAbstractItemView.State.EditingState:
            self._update_file_info(self._current_path)
            self._set_status(
                tr('"{name}" changed on disk. Save to overwrite, or reselect it to discard your edits and reload.', name=self._current_path.name),
            )
            return

        active_search = self._search_input.text()
        self._load_database(self._current_path)
        if active_search:
            self._search_input.setText(active_search)
        if is_in_app_userip_db_content(self._current_path, current_text):
            self._set_status(tr('Reloaded "{name}".', name=self._current_path.name))
        else:
            self._set_status(tr('Reloaded "{name}" after an external change.', name=self._current_path.name))

    def _load_all_databases(self) -> None:
        """Populate the table with all cached UserIP database entries."""
        self._model.removeRows(0, self._model.rowCount())
        rows: list[list[QStandardItem]] = []
        total_entries, total_files = 0, 0
        for json_path, entries in iter_userip_databases():
            total_files += 1
            db_info = (json_path.stem, json_path)
            for entry in entries:
                total_entries += 1
                rows.append(build_entry_row_items(entry, index=total_entries, database=db_info, looky_icon=self._looky_icon))

        dynamic_sort_filter = self._proxy.dynamicSortFilter()
        self._proxy.setDynamicSortFilter(False)
        try:
            append_entry_rows(self._model, rows)
            self._proxy.setFilterFixedString(self._search_input.text())
        finally:
            self._proxy.prepare_sort_and_invalidate()
            self._proxy.setDynamicSortFilter(dynamic_sort_filter)
        self._last_seen_build_version = UserIPDatabases.build_version

        self._set_status(
            tr(
                'Global search: {entries_part} across {files_part}',
                entries_part=tr_plural('{count} entry', '{count} entries', total_entries),
                files_part=tr_plural('{count} database', '{count} databases', total_files),
            ),
        )
        self._update_entry_counts()

    # ------------------------------------------------------------------
    # Add / delete entries
    # ------------------------------------------------------------------

    def _add_entry(self) -> None:
        """Open the IP Range Builder and username(s) input dialogs and insert the new entries."""
        if self._current_path is None:
            return
        self._insert_entry_at(self._model.rowCount())

    def _edit_selected_entry_ip(self) -> None:
        """Edit the IP/range of the currently selected entry via the builder button."""
        source_rows = self._get_selected_source_rows()
        if len(source_rows) == 1:
            self._edit_entry_ip(source_rows[0])

    def _set_row_ip_or_range(self, source_row: int, new_ip_text: str, *, is_single: bool) -> None:
        """Update the IP and Range column cells for `source_row` and clear its Looky badge."""
        if ip_item := self._model.item(source_row, IP_COLUMN):
            ip_item.setText(new_ip_text if is_single else '')
        if range_item := self._model.item(source_row, RANGE_COLUMN):
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
            self._last_seen_build_version = UserIPDatabases.build_version
            self._rebuild_fs_watch()
            if not success:
                return
            with QSignalBlocker(self._model):
                self._set_row_ip_or_range(source_row, new_ip_text, is_single=is_single)
                set_row_updated_at(self._model, source_row)
                extract_entry_model_from_row(self._model, source_row)
            self._proxy.refresh_rows((source_row,))
            self._dedup_global_search_rows()
            self._proxy.refresh_groups()
            self._highlight_duplicates()
            self._refresh_stats()
            self._update_entry_counts()
            self._set_status(tr('Updated entry to "{value}" in {db}.', value=new_ip_text, db=database_path.name))
        else:
            with QSignalBlocker(self._model):
                self._set_row_ip_or_range(source_row, new_ip_text, is_single=is_single)
                if is_row_persisted(self._model, source_row):
                    set_row_updated_at(self._model, source_row)
            self._proxy.refresh_rows((source_row,))
            self._mark_entries_dirty()
            self._highlight_duplicates()
            self._update_entry_counts()
            self._save_database()
            if not self._dirty:
                self._set_status(tr('Updated entry to "{value}".', value=new_ip_text))
        UserIPDatabases.renotify_if_conflicting([new_ip_text])

    def _edit_entry_note(self, source_row: int) -> None:
        """Open a text input dialog to edit the note of an existing entry."""
        if not self._global_search_active and self._current_path is None:
            return
        notes_item = self._model.item(source_row, NOTES_COLUMN)
        current_note = notes_item.text().strip() if notes_item else ''
        dialog_title = tr('Edit Note') if current_note else tr('Add Note')
        note_prompt = (
            tr('Enter the note for this entry (leave empty to clear):')
            if current_note
            else tr('Enter a note for this entry (leave empty to clear):')
        )
        new_note, accepted = QInputDialog.getText(self, dialog_title, note_prompt, QLineEdit.EchoMode.Normal, current_note)
        if not accepted or (new_note := new_note.strip()) == current_note:
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
            self._last_seen_build_version = UserIPDatabases.build_version
            self._rebuild_fs_watch()
            if not success:
                return
            with QSignalBlocker(self._model):
                if notes_item:
                    notes_item.setText(new_note)
                set_row_updated_at(self._model, source_row)
            self._proxy.refresh_rows((source_row,))
            self._set_status(tr('Updated note for "{username}" in {db}.', username=username, db=database_path.name))
        else:
            with QSignalBlocker(self._model):
                if notes_item:
                    notes_item.setText(new_note)
                if is_row_persisted(self._model, source_row):
                    set_row_updated_at(self._model, source_row)
            self._proxy.refresh_rows((source_row,))
            self._mark_entries_dirty()
            self._save_database()
            if not self._dirty:
                self._set_status(tr('Updated note.'))

    def _insert_entry_at(self, source_row: int) -> None:
        """Prompt for an IP/range and username(s) and insert the resulting rows at *source_row*."""
        if self._current_path is None:
            return
        insert_before = QPersistentModelIndex(self._model.index(source_row, 0))
        dialog = IPRangeBuilderDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted or not (ip_text := dialog.result_entry()):
            return
        self._insert_usernames_single_db(ip_text, insert_before=insert_before)

    def _prompt_new_usernames(self, prompt: str | Callable[[int], str]) -> tuple[list[str], dict[str, str]]:
        """Prompt the user for one or more usernames and their optional notes."""
        entered_usernames, entered_notes, accepted = prompt_usernames_and_notes_input(self, tr('Input Username(s)'), prompt)
        return (entered_usernames, entered_notes) if accepted else ([], {})

    def _collect_existing_usernames_for_entry(self, entry_value: str, *, database_path: Path | None = None) -> list[str]:
        """Return existing usernames in the table model for *entry_value* (scoped to *database_path* when provided)."""
        return dedup_preserve_order(
            username
            for row in range(self._model.rowCount())
            if self._get_row_entry_value(row) == entry_value
            and (database_path is None or self._get_row_database_path(row) == database_path)
            and (username := self._get_row_username(row))
        )

    def _add_username_global_search(self, source_row: int, ip_text: str, range_text: str) -> None:
        """Prompt for usernames and append them directly to the entry's database in global search mode."""
        entry_value, anchor_username = ip_text or range_text, self._get_row_username(source_row)
        database_item = self._model.item(source_row, DATABASE_COLUMN)
        database_path = self._get_row_database_path(source_row)
        if not database_path or not database_path.is_file():
            return
        # The modal prompt below may let a disk reload rebuild the model (deleting this row's items), so snapshot by value.
        database_label = database_item.text() if database_item else database_path.stem
        insert_before = QPersistentModelIndex(self._model.index(source_row + 1, 0))

        existing_names = self._collect_existing_usernames_for_entry(entry_value, database_path=database_path)

        def _prompt_text(count: int) -> str:
            body = tr_plural(
                'Enter the new username to add for {value} in "{db}":',
                'Enter the new usernames to add for {value} in "{db}":',
                count,
                value=entry_value,
                db=database_path.stem,
            )
            if not existing_names:
                return body
            current_header = tr_plural(
                'Current username for {value}: {names}',
                'Current usernames for {value}: {names}',
                len(existing_names),
                value=entry_value,
                names=', '.join(existing_names),
            )
            return f'{current_header}\n\n{body}'

        new_usernames, entered_notes = self._prompt_new_usernames(_prompt_text)
        if not new_usernames:
            return

        existing_cf = {name.casefold() for name in existing_names}
        added_usernames = [name for name in new_usernames if name.casefold() not in existing_cf]
        if not added_usernames:
            QMessageBox.information(
                self,
                TITLE,
                tr_plural(
                    'The specified username already exists for {value} in "{db}".',
                    'All specified usernames already exist for {value} in "{db}".',
                    len(new_usernames),
                    value=entry_value,
                    db=database_path.stem,
                ),
            )
            return

        new_entry_models = [enrich_userip_entry_from_logs(UserIPEntryModel(username=name, ip=entry_value, notes=entered_notes.get(name, '')))[0] for name in added_usernames]
        with QSignalBlocker(self._fs_watcher):
            added_pairs = append_userip_entries(database_path, new_entry_models, anchor_usernames_by_ip={entry_value: anchor_username} if anchor_username else None)
            if added_pairs:
                group_candidates = dedup_preserve_order(([anchor_username] if anchor_username else ()), added_usernames)
                if len(group_candidates) >= MIN_GROUP_USERNAMES:
                    group_usernames(group_candidates, self._account_group_clusters_map())
                refresh_userip_and_wake_renderer()
        self._last_seen_build_version = UserIPDatabases.build_version
        self._rebuild_fs_watch()

        if not added_pairs:
            already_exists_text = tr_plural(
                'The specified username already exists for {value} in "{db}".',
                'All specified usernames already exist for {value} in "{db}".',
                len(new_usernames),
                value=entry_value,
                db=database_path.stem,
            )
            QMessageBox.information(self, TITLE, already_exists_text)
            return

        insert_at = insert_before.row() if insert_before.isValid() else self._model.rowCount()
        for offset, entry_model in enumerate(model for model in new_entry_models if (model.username, entry_value) in added_pairs):
            self._model.insertRow(insert_at + offset, build_entry_row_items(entry_model, database=(database_label, database_path), looky_icon=self._looky_icon, persisted=True))

        self._renumber_indexes()
        self._highlight_duplicates()
        self._refresh_stats()
        self._update_entry_counts()
        added_count = len(added_pairs)
        self._set_status(
            tr_plural(
                'Added {count} username for {value} in {db}.',
                'Added {count} usernames for {value} in {db}.',
                added_count,
                value=entry_value,
                db=database_path.name,
            ),
        )
        UserIPDatabases.renotify_if_conflicting([entry_value])

    def _insert_usernames_single_db(self, entry_value: str, *, insert_before: QPersistentModelIndex, anchor_username: str = '') -> None:
        """Prompt for usernames + notes and insert enriched rows before *insert_before* (appended if invalidated by a disk reload)."""
        database_path, existing_names = self._current_path, self._collect_existing_usernames_for_entry(entry_value)

        def _prompt_text(count: int) -> str:
            body = tr_plural(
                'Enter the new username to add for {value}:',
                'Enter the new usernames to add for {value}:',
                count,
                value=entry_value,
            )
            if not existing_names:
                return body
            current_header = tr_plural(
                'Current username for {value}: {names}',
                'Current usernames for {value}: {names}',
                len(existing_names),
                value=entry_value,
                names=', '.join(existing_names),
            )
            return f'{current_header}\n\n{body}'

        new_usernames, entered_notes = self._prompt_new_usernames(_prompt_text)
        if not new_usernames or self._current_path != database_path:
            return

        existing_names = self._collect_existing_usernames_for_entry(entry_value)
        existing_cf = {name.casefold() for name in existing_names}
        added_usernames = [name for name in new_usernames if name.casefold() not in existing_cf]
        if not added_usernames:
            QMessageBox.information(
                self,
                TITLE,
                tr_plural(
                    'The specified username already exists for {value}.',
                    'All specified usernames already exist for {value}.',
                    len(new_usernames),
                    value=entry_value,
                ),
            )
            return

        insert_at, before_count = (insert_before.row() if insert_before.isValid() else self._model.rowCount()), self._model.rowCount()
        for offset, added_name in enumerate(added_usernames):
            enriched_entry, _ = enrich_userip_entry_from_logs(UserIPEntryModel(username=added_name, ip=entry_value, notes=entered_notes.get(added_name, '')))
            self._model.insertRow(insert_at + offset, build_entry_row_items(enriched_entry, looky_icon=self._looky_icon, persisted=False))

        self._renumber_indexes()
        self._mark_entries_dirty()
        self._highlight_duplicates()
        self._update_entry_counts()
        self._save_database()
        if not self._dirty:
            ref_anchor = anchor_username or (existing_names[0] if existing_names else '')
            linked_existing = [name for name in existing_names if not ref_anchor or not are_usernames_unlinked(name, ref_anchor)]
            group_candidates = dedup_preserve_order(linked_existing, ([anchor_username] if anchor_username else ()), added_usernames)
            if len(group_candidates) >= MIN_GROUP_USERNAMES:
                with QSignalBlocker(self._fs_watcher):
                    if group_usernames(group_candidates, self._account_group_clusters_map()):
                        self._refresh_table_after_grouping()
            added_count = max(0, self._model.rowCount() - before_count)
            if added_count > 0:
                self._set_status(
                    tr_plural('Added {count} username for {value}.', 'Added {count} usernames for {value}.', added_count, value=entry_value),
                )
                UserIPDatabases.renotify_if_conflicting([entry_value])
                target_row = min(insert_at, self._model.rowCount() - 1)
                proxy_index = self._proxy.mapFromSource(self._model.index(target_row, USERNAME_COLUMN))
                if proxy_index.isValid():
                    self._entries_table.scrollTo(proxy_index)
                    self._entries_table.setCurrentIndex(proxy_index)
                    if selection_model := self._entries_table.selectionModel():
                        selection_model.select(proxy_index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

    def _add_username(self, source_row: int) -> None:
        """Prompt for one or more usernames + notes for the IP/range on *source_row* and add them to the database."""
        if not self._global_search_active and self._current_path is None:
            return
        ip_item, range_item = self._model.item(source_row, IP_COLUMN), self._model.item(source_row, RANGE_COLUMN)
        ip_text = ip_item.text().strip() if ip_item else ''
        range_text = range_item.text().strip() if range_item else ''
        if not (ip_text or range_text):
            return
        if self._global_search_active:
            self._add_username_global_search(source_row, ip_text, range_text)
            return
        insert_before = QPersistentModelIndex(self._model.index(source_row + 1, 0))
        self._insert_usernames_single_db(ip_text or range_text, insert_before=insert_before, anchor_username=self._get_row_username(source_row))

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
                selection.select(p_index, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
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
        self._proxy.refresh_groups()

    def _rename_selected(self) -> None:
        """Rename the username of the selected entry or entries."""
        source_rows = self._get_selected_source_rows(warn_if_empty=True)
        if not source_rows:
            return
        count = len(source_rows)

        if count == 1:
            initial_name, title, prompt = self._get_row_username(source_rows[0]), tr('Rename Username'), tr('Enter the new username:')
        else:
            usernames = {username for row in source_rows if (username := self._get_row_username(row))}
            initial_name = next(iter(usernames)) if len(usernames) == 1 else ''
            title = tr('Rename Selected ({count})', count=count)
            prompt = tr_plural('Enter the new username for {count} selected entry:', 'Enter the new username for {count} selected entries:', count)

        new_username, success = prompt_username_input(self, title, prompt, initial_name)
        if not success:
            return
        if not (new_username := new_username.strip()):
            QMessageBox.warning(self, TITLE, tr('No username was provided.'))
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
            self._last_seen_build_version = UserIPDatabases.build_version
            self._rebuild_fs_watch()

            if not renamed_count:
                return

            with QSignalBlocker(self._model):
                for row in source_rows:
                    self._model.item(row, USERNAME_COLUMN).setText(new_username)
                    clear_row_looky_badge(self._model, row)
                    set_row_updated_at(self._model, row)
            self._proxy.refresh_rows(source_rows)
            self._dedup_global_search_rows()
            self._proxy.refresh_groups()
            self._highlight_duplicates()
            self._refresh_stats()
            self._update_entry_counts()
            self._set_status(
                tr_plural(
                    'Renamed {count} entry to "{username}" in database files.',
                    'Renamed {count} entries to "{username}" in database files.',
                    renamed_count,
                    username=new_username,
                ),
            )
        else:
            with QSignalBlocker(self._model):
                for row in source_rows:
                    self._model.item(row, USERNAME_COLUMN).setText(new_username)
                    clear_row_looky_badge(self._model, row)
                    if is_row_persisted(self._model, row):
                        set_row_updated_at(self._model, row)
            self._proxy.refresh_rows(source_rows)

            self._mark_entries_dirty()
            self._highlight_duplicates()
            self._update_entry_counts()
            self._save_database()
            if not self._dirty:
                self._set_status(
                    tr_plural(
                        'Renamed {count} entry to "{username}".',
                        'Renamed {count} entries to "{username}".',
                        count,
                        username=new_username,
                    ),
                )
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
            tr_plural(
                'Are you sure you want to delete {count} selected entry?\n\nThis will immediately write the changes to the database files.',
                'Are you sure you want to delete {count} selected entries?\n\nThis will immediately write the changes to the database files.',
                count,
            ),
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
                self._set_status(tr_plural('Deleted {count} entry.', 'Deleted {count} entries.', count))

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
                to_remove = {(username, ip) for row in rows if (username := self._get_row_username(row)) and (ip := self._get_row_entry_value(row))}
                rewrite_db_without_entries(db_path, to_remove)
            refresh_userip_and_wake_renderer()
        self._last_seen_build_version = UserIPDatabases.build_version
        self._rebuild_fs_watch()

        for row in source_rows:
            self._model.removeRow(row)
        self._renumber_indexes()
        self._highlight_duplicates()
        self._refresh_stats()
        self._update_entry_counts()
        self._set_status(tr_plural('Deleted {count} entry from database files.', 'Deleted {count} entries from database files.', count))

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

                for row in range(self._model.rowCount()):
                    username, ip, notes, entry_model = extract_entry_model_from_row(self._model, row)

                    if not username and not ip and not notes:
                        continue  # skip completely empty rows

                    if not username:
                        errors.append(tr('Row {row}: Username is empty.', row=row + 1))
                    valid_ip = bool(ip) and is_valid_ip_range_entry(ip)
                    if not ip:
                        errors.append(tr('Row {row}: IP or Range is empty.', row=row + 1))
                    elif not valid_ip:
                        errors.append(tr('Row {row}: "{ip}" is not a valid IP address or range.', row=row + 1, ip=ip))

                    if entry_model is not None and valid_ip:
                        entries.append(entry_model)
                        persisted_rows.append(row)

                if errors:
                    if show_errors:
                        QMessageBox.critical(self, TITLE, '\n'.join(errors))
                    return

                # --- Deduplicate exact (username, ip) pairs ---
                total_before_dedup = len(entries)
                entries = dedup_userip_entries(entries)
                duplicate_count = total_before_dedup - len(entries)
                if duplicate_count > 0 and show_errors:
                    QMessageBox.information(
                        self,
                        TITLE,
                        tr_plural(
                            '{count} exact duplicate entry was removed before saving.',
                            '{count} exact duplicate entries were removed before saving.',
                            duplicate_count,
                        ),
                    )

                with QSignalBlocker(self._model):
                    for row in persisted_rows:
                        mark_row_persisted(self._model, row)

                # --- Build settings from widgets and write new JSON file content ---
                settings_model = self.read_settings_from_widgets()
                db_model = UserIPDatabaseFile(settings=settings_model, entries=entries)
                with userip_databases_lock():
                    serialized = save_userip_database_model(self._current_path, db_model)
                    refresh_userip_and_wake_renderer()
                self._last_seen_build_version = UserIPDatabases.build_version
                self._proxy.refresh_groups()
                self._disk_snapshot = serialized
                self._settings_snapshot = settings_model.model_copy()
                self._clear_dirty_state()
                self._update_file_info(self._current_path)
                self._set_status(
                    tr_plural('Saved {count} entry to {db}', 'Saved {count} entries to {db}', len(entries), db=self._current_path.name),
                )
                self._refresh_stats()
                self._rebuild_fs_watch()
                if duplicate_count > 0:
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
                db_label, db_path = (db_item.text() if db_item else ''), (self._get_row_database_path(first_row) or Path())
                row_index = int(self._model.item(first_row, INDEX_COLUMN).data(Qt.ItemDataRole.UserRole) or (first_row + 1))
                new_items = build_entry_row_items(merged_model, index=row_index, database=(db_label, db_path), looky_icon=self._looky_icon, persisted=True)
                for col, item in enumerate(new_items):
                    self._model.setItem(first_row, col, item)

        for row in sorted(rows_to_remove, reverse=True):
            self._model.removeRow(row)
        self._renumber_indexes()

    def _highlight_duplicates(self) -> int:
        """Scan all rows for exact (username, ip) duplicates and highlight them."""
        seen: dict[tuple[str, str, str], int] = {}
        duplicate_rows: set[int] = set()
        for row in range(self._model.rowCount()):
            username, ip = self._get_row_username(row), self._get_row_entry_value(row)
            if not username or not ip:
                continue
            db_key = str(self._get_row_database_path(row) or '') if self._global_search_active else ''
            key = (db_key, username.casefold(), ip)
            if key in seen:
                duplicate_rows.add(row)
                duplicate_rows.add(seen[key])
            else:
                seen[key] = row

        with QSignalBlocker(self._model):
            for row in range(self._model.rowCount()):
                is_dup = row in duplicate_rows
                for column in range(self._model.columnCount()):
                    item = self._model.item(row, column)
                    if not item:
                        continue
                    if is_dup:
                        item.setBackground(DUPLICATE_HIGHLIGHT_BRUSH)
                    elif item.data(Qt.ItemDataRole.BackgroundRole) is not None:
                        item.setData(None, Qt.ItemDataRole.BackgroundRole)

        return len(duplicate_rows)
