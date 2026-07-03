"""Real-time filesystem synchronization mixin for the UserIP Databases Manager dialog."""

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QDialog

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.guis.userip_manager_helpers import iter_userip_databases

if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtCore import QFileSystemWatcher, QTimer
    from PyQt6.QtGui import QStandardItemModel
    from PyQt6.QtWidgets import QFrame, QLineEdit

    from session_sniffer.guis.userip_manager_helpers import EntriesSortProxy


class FileSyncMixin(QDialog):  # pylint: disable=too-few-public-methods
    """Mixin that keeps the entries view and stats in sync with on-disk database changes.

    Expects these attributes on the concrete class:
        _fs_watcher, _fs_sync_timer, _current_path, _global_search_active, _disk_snapshot,
        _dirty, _model, _proxy, _search_input, _settings_container
    And these methods:
        _refresh_stats, _clear_dirty_state, _set_status, _update_file_info, _load_database,
        _append_row, _update_entry_counts
    """

    # -- Attribute stubs for type checkers --
    _fs_watcher: QFileSystemWatcher
    _fs_sync_timer: QTimer
    _current_path: Path | None
    _global_search_active: bool
    _disk_snapshot: str
    _dirty: bool
    _model: QStandardItemModel
    _proxy: EntriesSortProxy
    _search_input: QLineEdit
    _settings_container: QFrame

    # pylint: disable=unused-argument
    def _refresh_stats(self) -> None: ...
    def _clear_dirty_state(self) -> None: ...
    def _set_status(self, text: str) -> None: ...
    def _update_file_info(self, path: Path | None) -> None: ...
    def _load_database(self, path: Path) -> None: ...
    def _append_row(self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None) -> None: ...
    def _update_entry_counts(self) -> None: ...

    # pylint: enable=unused-argument

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

        current_text = self._current_path.read_text('utf-8')
        if current_text == self._disk_snapshot:
            return  # No real change (or our own write).

        if self._dirty:
            self._update_file_info(self._current_path)
            self._set_status(f'⚠ "{self._current_path.name}" changed on disk. Save to overwrite, or reselect it to discard your edits and reload.')
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
            for username, ip in entries:
                total_entries += 1
                self._append_row(username, ip, index=total_entries, database=(ini_path.stem, ini_path))

        self._set_status(f'Global search: {total_entries} entries across {total_files} databases')
        self._proxy.setFilterFixedString(self._search_input.text())
        self._update_entry_counts()
