"""Reusable debounced filesystem watcher for auto-refreshing GUI views from disk."""

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QTimer

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


class DebouncedFileWatcher(QObject):
    """Watch files and/or directories and invoke a callback (debounced) when they change.

    Tracks file and directory modification timestamps and sizes periodically using a lightweight
    `QTimer`.  Coalesces rapid bursts through a single-shot debounce timer and calls the supplied
    callback once the dust settles.

    Does not use `QFileSystemWatcher`, avoiding the unreliability of native change handles on
    atomic file replacements, background watcher threads, and unwanted native event filter registrations.
    """

    def __init__(
        self,
        parent: QObject | None,
        on_change: Callable[[], None],
        *,
        interval_ms: int = 250,
        poll_interval_ms: int = 250,
    ) -> None:
        """Create a watcher that calls *on_change* at most once per *interval_ms* burst."""
        super().__init__(parent)
        self._on_change = on_change
        self._files: set[str] = set()
        self._directories: set[str] = set()
        self._path_snapshots: dict[str, tuple[bool, int, int]] = {}

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._fire)

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(poll_interval_ms)
        self._poll_timer.timeout.connect(self._check_polling)

    def files(self) -> list[str]:
        """Return the list of currently watched file paths."""
        return sorted(self._files)

    def directories(self) -> list[str]:
        """Return the list of currently watched directory paths."""
        return sorted(self._directories)

    def watch(self, *, files: Iterable[Path | str] = (), directories: Iterable[Path | str] = ()) -> None:
        """Replace the set of watched *files* and *directories* and arm the watcher."""
        self.stop()
        self._files = {str(file) for file in files}
        self._directories = {str(directory) for directory in directories}
        self._path_snapshots = {path_str: self._get_path_snapshot(path_str) for path_str in self._files | self._directories}
        if (self._files or self._directories) and self._poll_timer.interval() > 0:
            self._poll_timer.start()

    def add_paths(self, paths: Iterable[Path | str]) -> None:
        """Add *paths* (files or directories) to the watch list and start polling if needed."""
        for raw_path in paths:
            path_str = str(raw_path)
            path_obj = Path(path_str)
            if path_obj.is_dir():
                self._directories.add(path_str)
            else:
                self._files.add(path_str)
            self._path_snapshots[path_str] = self._get_path_snapshot(path_str)
        if (self._files or self._directories) and self._poll_timer.interval() > 0 and not self._poll_timer.isActive():
            self._poll_timer.start()

    def remove_paths(self, paths: Iterable[Path | str]) -> None:
        """Remove *paths* from the watch list and stop polling if no paths remain."""
        for raw_path in paths:
            path_str = str(raw_path)
            self._files.discard(path_str)
            self._directories.discard(path_str)
            self._path_snapshots.pop(path_str, None)
        if not self._files and not self._directories:
            self._poll_timer.stop()

    def stop(self) -> None:
        """Stop the debounce timer, polling timer, and clear all watched paths."""
        self._timer.stop()
        self._poll_timer.stop()
        self._files.clear()
        self._directories.clear()
        self._path_snapshots.clear()

    @staticmethod
    def _get_path_snapshot(path_str: str) -> tuple[bool, int, int]:
        """Return existence, size, and modification timestamp for a path."""
        try:
            stat_result = Path(path_str).stat()
        except OSError:
            return False, 0, 0
        return True, stat_result.st_size, stat_result.st_mtime_ns

    def _check_polling(self) -> None:
        """Poll watched files and directories for size, modification time, or existence changes."""
        if self.signalsBlocked():
            return
        changed = False
        all_paths = self._files | self._directories
        for path_str in all_paths:
            snapshot = self._get_path_snapshot(path_str)
            if snapshot != self._path_snapshots.get(path_str):
                self._path_snapshots[path_str] = snapshot
                changed = True
        if changed:
            self._schedule()

    def _schedule(self) -> None:
        """Coalesce a filesystem notification into the pending debounce window."""
        if self.signalsBlocked():
            return
        if not self._timer.isActive():
            self._timer.start()

    def _fire(self) -> None:
        """Notify the consumer of the settled change."""
        if self.signalsBlocked():
            return
        for path_str in self._files | self._directories:
            self._path_snapshots[path_str] = self._get_path_snapshot(path_str)
        self._on_change()
