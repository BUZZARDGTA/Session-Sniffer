"""Background worker threads for the Most Seen Players leaderboard window."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from PySide6.QtCore import Signal

from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.player.seen_stats import LeaderboardBaseline, LeaderboardEntry, build_leaderboard_baseline, overlay_live_session

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class SessionScanResult:
    """Snapshot of the sessions directory: a change-signature plus every directory in the tree.

    `signature` holds a `(path, mtime, size)` tuple for every session file except the live one, so any
    add/remove/edit of an older file changes it. `directories` is used to (re-)arm the filesystem watcher.
    """

    signature: frozenset[tuple[str, float, int]]
    directories: frozenset[str]


class LeaderboardBaselineWorker(CrashingQThread):
    """Background thread that scans finished session logs into a reusable leaderboard baseline.

    Emits `finished_ok` with the resulting `LeaderboardBaseline`.
    """

    finished_ok: Signal = Signal(object)
    progress: Signal = Signal(int, int)

    def __init__(self, folder_path: Path, exclude_file: Path) -> None:
        super().__init__()
        self._folder_path = folder_path
        self._exclude_file = exclude_file

    @override
    def _run(self) -> None:
        """Scan the session logs into a baseline and emit it."""

        def on_progress(current: int, total: int) -> None:
            # Throttle emission to avoid flooding the event loop on huge archives
            if not current % 10 or current == total:
                self.progress.emit(current, total)

        baseline = build_leaderboard_baseline(
            self._folder_path,
            exclude_file=self._exclude_file,
            should_cancel=self.isInterruptionRequested,
            progress_callback=on_progress,
        )
        if self.isInterruptionRequested():
            return
        self.finished_ok.emit(baseline)


class SessionFilesScanWorker(CrashingQThread):
    """Background thread that inventories the session JSON files without parsing them.

    Emits `finished_ok` with a `SessionScanResult` describing every session file (path, mtime, size)
    except the live session file, plus every directory in the tree. Running the directory walk off
    the GUI thread keeps the cursor and event loop responsive on large session archives.
    """

    finished_ok: Signal = Signal(object)

    def __init__(self, folder_path: Path, exclude_file: Path) -> None:
        super().__init__()
        self._folder_path = folder_path
        self._exclude_file = exclude_file

    @override
    def _run(self) -> None:
        """Inventory the session files/directories on disk and emit the resulting snapshot."""
        signature: set[tuple[str, float, int]] = set()
        directories: set[str] = {str(self._folder_path)}
        for path in self._folder_path.rglob('*'):
            if self.isInterruptionRequested():
                return
            if path.is_dir():
                directories.add(str(path))
            elif path.suffix == '.json' and path != self._exclude_file and path.is_file():
                stat_result = path.stat()
                signature.add((str(path), stat_result.st_mtime, stat_result.st_size))
        if self.isInterruptionRequested():
            return
        self.finished_ok.emit(SessionScanResult(signature=frozenset(signature), directories=frozenset(directories)))


# Memoized third-party-server classification, keyed by IP. The CIDR scan is expensive, so each IP is
# classified at most once and reused across every live refresh.
_server_ip_classification: dict[str, bool] = {}


def server_ips_for(entries: list[LeaderboardEntry]) -> frozenset[str]:
    """Return the subset of IPs in *entries* that are known third-party game/relay servers.

    Runs the expensive CIDR classification off the GUI thread (in the overlay worker) or once behind
    the loading dialog, so toggling the 'Hide game servers' filter is a cheap set-membership test.
    """
    server_ips: set[str] = set()
    for entry in entries:
        cached = _server_ip_classification.get(entry.ip)
        if cached is None:
            cached = is_third_party_server_ip(entry.ip)
            _server_ip_classification[entry.ip] = cached
        if cached:
            server_ips.add(entry.ip)
    return frozenset(server_ips)


@dataclass(frozen=True, slots=True)
class OverlayResult:
    """Result of a background overlay: the sorted leaderboard plus the server IPs found within it."""

    entries: list[LeaderboardEntry]
    server_ips: frozenset[str]


class LeaderboardOverlayWorker(CrashingQThread):
    """Background thread that overlays the live session snapshot onto the cached baseline.

    Emits `finished_ok` with an `_OverlayResult` (sorted entries plus their server IPs). Running this
    off the GUI thread keeps the cursor and event loop responsive even for large baselines.
    """

    finished_ok: Signal = Signal(object)

    def __init__(self, baseline: LeaderboardBaseline, live_file: Path, limit: int) -> None:
        super().__init__()
        self._baseline = baseline
        self._live_file = live_file
        self._limit = limit

    @override
    def _run(self) -> None:
        """Overlay the live session onto the baseline and emit the resulting leaderboard."""
        entries = overlay_live_session(self._baseline, self._live_file, limit=self._limit)
        self.finished_ok.emit(OverlayResult(entries=entries, server_ips=server_ips_for(entries)))
