"""UserIP settings, database loading, and IP-to-user resolution."""

from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import format_userip_ip_conflict_message
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.ip_range import IPRange, parse_ip_range
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import format_triple_quoted_text

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


class _GUIThreadDispatcher(QObject):
    """Schedule callables on the GUI thread from any thread via Qt's auto-queued connection."""

    _call: ClassVar[pyqtSignal] = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self._call.connect(lambda fn: fn())  # pyright: ignore[reportUnknownLambdaType]

    def invoke(self, fn: Callable[[], None]) -> None:
        """Emit `fn` as a signal — Qt will queue it to the GUI thread automatically."""
        self._call.emit(fn)


# Module-level singleton created on the main thread at import time.
gui_dispatcher = _GUIThreadDispatcher()


class ProtectionSettings(NamedTuple):
    """Protection-related settings for a UserIP entry."""
    enabled: bool
    process_path: Path | None
    suspend_process_mode: int | Literal['Auto', 'Manual', 'Adaptive']


class UserIPSettings(NamedTuple):
    """Represent settings with attributes for each setting key."""
    enabled: bool
    color: QColor
    log: bool
    notifications: bool
    voice_notifications: Literal['Male', 'Female', False]
    protection: ProtectionSettings


class UserIP(NamedTuple):
    """Class representing information associated with a specific IP, including settings and usernames."""
    ip: str
    database_path: Path
    settings: UserIPSettings
    usernames: list[str]


class _RangeEntry(NamedTuple):
    """A parsed IP range entry associated with a specific UserIP database."""
    ip_range: IPRange
    database_path: Path
    settings: UserIPSettings
    usernames: list[str]


class UserIPDatabases:
    """Load and cache enabled UserIP databases and resolve IP-to-user mappings."""

    _update_userip_database_lock: ClassVar[Lock] = Lock()

    userip_databases: ClassVar[list[tuple[Path, UserIPSettings, dict[str, list[str]]]]] = []
    ips_set: ClassVar[set[str]] = set()
    _ip_to_userip: ClassVar[dict[str, UserIP]] = {}
    _range_entries: ClassVar[list[_RangeEntry]] = []
    notified_settings_corrupted: ClassVar[set[Path]] = set()
    notified_ip_invalid: ClassVar[set[str]] = set()
    notified_ip_conflicts: ClassVar[set[str]] = set()
    notified_duplicate_entries: ClassVar[set[Path]] = set()
    _open_conflict_dialogs: ClassVar[dict[str, QMessageBox]] = {}

    @staticmethod
    def _notify_ip_conflict(
        *,
        existing_userip: UserIP,
        conflicting_database_path: Path,
        conflicting_username: str,
    ) -> None:
        ip = existing_userip.ip
        text = format_triple_quoted_text(format_userip_ip_conflict_message(
            existing_userip=existing_userip,
            conflicting_database_path=conflicting_database_path,
            conflicting_username=conflicting_username,
            userip_databases_dir=USERIP_DATABASES_DIR_PATH,
        ))

        def _show_on_gui() -> None:
            parent = next(
                (w for w in QApplication.topLevelWidgets() if isinstance(w, QMainWindow) and w.isVisible()),
                None,
            )
            if parent is None:
                QTimer.singleShot(500, _show_on_gui)
                return
            dlg = QMessageBox(parent)
            dlg.setWindowModality(Qt.WindowModality.NonModal)
            dlg.setWindowTitle(TITLE)
            dlg.setText(text)
            dlg.setIcon(QMessageBox.Icon.Warning)
            dlg.setStandardButtons(QMessageBox.StandardButton.Ok)
            dlg.finished.connect(lambda _result: UserIPDatabases._open_conflict_dialogs.pop(ip, None))  # pyright: ignore[reportUnknownLambdaType]
            UserIPDatabases._open_conflict_dialogs[ip] = dlg
            dlg.show()

        gui_dispatcher.invoke(_show_on_gui)

    @classmethod
    def _close_conflict_dialog(cls, ip: str) -> None:
        dlg = cls._open_conflict_dialogs.pop(ip, None)
        if dlg is not None:
            dlg.accept()

    @classmethod
    def populate(cls, database_entries: list[tuple[Path, UserIPSettings, dict[str, list[str]]]]) -> None:
        """Replace `cls.userip_databases` with a new set of databases.

        Args:
            database_entries: A list of tuples containing database_path, settings, and user_ips.
        """
        with cls._update_userip_database_lock:
            cls.userip_databases = [
                (database_path, settings, user_ips)
                for database_path, settings, user_ips in database_entries
                if settings.enabled
            ]

    @classmethod
    def _process_single_ip(  # noqa: PLR0913  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        entry: str,
        username: str,
        database_path: Path,
        settings: UserIPSettings,
        ips_set: set[str],
        ip_to_userip: dict[str, UserIP],
        unresolved_conflicts: set[str],
    ) -> None:
        """Process a single IP entry during build."""
        if entry in ip_to_userip and ip_to_userip[entry].database_path != database_path:
            if entry not in cls.notified_ip_conflicts:
                cls._notify_ip_conflict(
                    existing_userip=ip_to_userip[entry],
                    conflicting_database_path=database_path,
                    conflicting_username=username,
                )
                cls.notified_ip_conflicts.add(entry)
            unresolved_conflicts.add(entry)
            return

        ips_set.add(entry)

        if entry not in ip_to_userip:
            ip_to_userip[entry] = UserIP(
                ip=entry,
                database_path=database_path,
                settings=settings,
                usernames=[username],
            )
        elif username not in ip_to_userip[entry].usernames:
            ip_to_userip[entry].usernames.append(username)

        if matched_player := PlayersRegistry.get_player_by_ip(entry):
            matched_player.userip = ip_to_userip[entry]

    @staticmethod
    def _process_range_entry(
        entry: str,
        username: str,
        database_path: Path,
        settings: UserIPSettings,
        range_entries: list[_RangeEntry],
    ) -> None:
        """Process a range entry (CIDR, start-end, wildcard) during build."""
        try:
            ip_range = parse_ip_range(entry)
        except (ValueError, TypeError):
            logger.warning('Skipping unparseable UserIP range entry: %r', entry)
            return

        existing = next(
            (re for re in range_entries if re.ip_range.raw == entry and re.database_path == database_path),
            None,
        )
        if existing is not None:
            if username not in existing.usernames:
                existing.usernames.append(username)
        else:
            range_entries.append(_RangeEntry(
                ip_range=ip_range,
                database_path=database_path,
                settings=settings,
                usernames=[username],
            ))

    @classmethod
    def build(cls) -> None:
        """Rebuild the `ips_set` and `_range_entries` caches dynamically from the current databases.

        Single IPs go into `ips_set` for O(1) lookup.
        Range entries (CIDR, start-end, wildcard) go into `_range_entries` for iteration.
        """
        with cls._update_userip_database_lock:
            ips_set: set[str] = set()
            ip_to_userip: dict[str, UserIP] = {}
            range_entries: list[_RangeEntry] = []
            unresolved_conflicts: set[str] = set()

            for database_path, settings, user_ips in cls.userip_databases:
                for username, entries in user_ips.items():
                    for entry in entries:
                        is_single_ip = False
                        try:
                            IPv4Address(entry)
                            is_single_ip = True
                        except (ValueError, TypeError):
                            pass

                        if is_single_ip:
                            cls._process_single_ip(entry, username, database_path, settings, ips_set, ip_to_userip, unresolved_conflicts)
                        else:
                            cls._process_range_entry(entry, username, database_path, settings, range_entries)

            # Assign range-matched UserIP to players that don't already have a match
            for player in PlayersRegistry.get_default_sorted_players():
                if player.userip is not None:
                    continue
                for range_entry in range_entries:
                    try:
                        if player.ip in range_entry.ip_range:
                            player.userip = UserIP(
                                ip=player.ip,
                                database_path=range_entry.database_path,
                                settings=range_entry.settings,
                                usernames=list(range_entry.usernames),
                            )
                            break
                    except (ValueError, TypeError):
                        continue

            # Strip conflicting IPs from the lookup structures so they are fully ignored.
            # Also retroactively clear any player that already has a conflicting userip assigned.
            for conflict_ip in unresolved_conflicts:
                ips_set.discard(conflict_ip)
                ip_to_userip.pop(conflict_ip, None)
                if matched_player := PlayersRegistry.get_player_by_ip(conflict_ip):
                    matched_player.userip = None

            # Remove resolved conflicts and auto-close their dialogs
            resolved_conflicts = cls.notified_ip_conflicts - unresolved_conflicts
            cls.notified_ip_conflicts -= resolved_conflicts
            if resolved_conflicts:
                _to_close = frozenset(resolved_conflicts)

                def _close_resolved() -> None:
                    for _ip in _to_close:
                        UserIPDatabases._close_conflict_dialog(_ip)

                gui_dispatcher.invoke(_close_resolved)

            cls.ips_set = ips_set
            cls._ip_to_userip = ip_to_userip
            cls._range_entries = range_entries

    @classmethod
    def is_known_ip(cls, ip: str) -> bool:
        """Check if an IP address matches any entry (exact or range).

        Checks the O(1) `ips_set` first, then iterates over range entries.
        """
        if ip in cls.ips_set:
            return True
        try:
            addr = IPv4Address(ip)
        except (ValueError, TypeError):
            return False
        return any(addr in re.ip_range for re in cls._range_entries)

    @classmethod
    def get_userip_database_filepaths(cls) -> list[Path]:
        """Return all enabled UserIP database file paths."""
        with cls._update_userip_database_lock:
            return [database_path for database_path, _, _ in cls.userip_databases]
