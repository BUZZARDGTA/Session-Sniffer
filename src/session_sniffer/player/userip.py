"""UserIP settings, database loading, and IP-to-user resolution."""

import dataclasses
from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtGui import QColor

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.error_messages import format_userip_ip_conflict_message
from session_sniffer.guis.utils import create_nonmodal_warning, find_main_window
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.ip_range import IPRange, parse_ip_range
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import format_triple_quoted_text

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QMessageBox

logger = get_logger(__name__)


class _GUIThreadDispatcher(QObject):
    """Schedule callables on the GUI thread from any thread via Qt's auto-queued connection."""

    _call: ClassVar[pyqtSignal] = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()

        def _dispatch_fn(fn: Callable[[], None]) -> None:
            fn()

        self._call.connect(_dispatch_fn)

    def invoke(self, fn: Callable[[], None]) -> None:
        """Emit `fn` as a signal — Qt will queue it to the GUI thread automatically."""
        self._call.emit(fn)


# Module-level singleton created on the main thread at import time.
gui_dispatcher = _GUIThreadDispatcher()


class ProtectionSettings(NamedTuple):
    """Protection-related settings for a UserIP entry."""

    enabled: bool
    suspend_process_mode: int | Literal['Auto']


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
    db_path: Path
    settings: UserIPSettings
    usernames: list[str]


class _RangeEntry(NamedTuple):
    """A parsed IP range entry associated with a specific UserIP database."""

    ip_range: IPRange
    db_path: Path
    settings: UserIPSettings
    usernames: list[str]


class _UserIPDatabaseEntry(NamedTuple):
    """Pre-classified UserIP database entry for efficient build."""

    db_path: Path
    settings: UserIPSettings
    single_ips: dict[str, list[str]]
    range_ips: dict[str, list[str]]


@dataclasses.dataclass(slots=True)
class _BuildState:
    """Mutable accumulator passed through single-IP processing during `UserIPDatabases.build`."""

    ips_set: set[str]
    ip_to_userip: dict[str, UserIP]
    unresolved_conflicts: set[str]


class UserIPDatabases:
    """Load and cache enabled UserIP databases and resolve IP-to-user mappings."""

    _update_userip_database_lock: ClassVar[Lock] = Lock()

    userip_databases: ClassVar[list[_UserIPDatabaseEntry]] = []
    ips_set: ClassVar[set[str]] = set()
    _ip_to_userip: ClassVar[dict[str, UserIP]] = {}
    _range_entries: ClassVar[list[_RangeEntry]] = []
    notified_ip_conflicts: ClassVar[set[str]] = set()
    _open_conflict_dialogs: ClassVar[dict[str, QMessageBox]] = {}
    build_version: ClassVar[int] = 0

    @staticmethod
    def _notify_ip_conflict(
        *,
        existing_userip: UserIP,
        conflicting_database_path: Path,
        conflicting_username: str,
    ) -> None:
        text = format_triple_quoted_text(
            format_userip_ip_conflict_message(
                existing_userip=existing_userip,
                conflicting_database_path=conflicting_database_path,
                conflicting_username=conflicting_username,
                userip_databases_dir=USERIP_DATABASES_DIR_PATH,
            ),
        )

        def _show_on_gui() -> None:
            parent = find_main_window()
            if parent is None:
                QTimer.singleShot(500, _show_on_gui)
                return
            dlg = create_nonmodal_warning(parent, text)

            def _on_finished(_result: int) -> None:
                UserIPDatabases._open_conflict_dialogs.pop(existing_userip.ip, None)

            dlg.finished.connect(_on_finished)
            UserIPDatabases._open_conflict_dialogs[existing_userip.ip] = dlg
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
            database_entries: A list of tuples containing db_path, settings, and user_ips.
        """
        classified: list[_UserIPDatabaseEntry] = []
        for db_path, settings, user_ips in database_entries:
            if not settings.enabled:
                continue
            single_ips: dict[str, list[str]] = {}
            range_ips: dict[str, list[str]] = {}
            for username, entries in user_ips.items():
                for entry in entries:
                    try:
                        IPv4Address(entry)
                        single_ips.setdefault(username, []).append(entry)
                    except ValueError:
                        range_ips.setdefault(username, []).append(entry)
            classified.append(
                _UserIPDatabaseEntry(
                    db_path=db_path,
                    settings=settings,
                    single_ips=single_ips,
                    range_ips=range_ips,
                ),
            )
        with cls._update_userip_database_lock:
            cls.userip_databases = classified

    @classmethod
    def _process_single_ip(
        cls,
        entry: str,
        username: str,
        db_entry: _UserIPDatabaseEntry,
        build_state: _BuildState,
    ) -> None:
        """Process a single IP entry during build."""
        if entry in build_state.ip_to_userip and build_state.ip_to_userip[entry].db_path != db_entry.db_path:
            if entry not in cls.notified_ip_conflicts:
                cls._notify_ip_conflict(
                    existing_userip=build_state.ip_to_userip[entry],
                    conflicting_database_path=db_entry.db_path,
                    conflicting_username=username,
                )
                cls.notified_ip_conflicts.add(entry)
            build_state.unresolved_conflicts.add(entry)
            return

        build_state.ips_set.add(entry)

        if entry not in build_state.ip_to_userip:
            build_state.ip_to_userip[entry] = UserIP(
                ip=entry,
                db_path=db_entry.db_path,
                settings=db_entry.settings,
                usernames=[username],
            )
        elif username not in build_state.ip_to_userip[entry].usernames:
            build_state.ip_to_userip[entry].usernames.append(username)

        if matched_player := PlayersRegistry.get_player_by_ip(entry):
            matched_player.userip = build_state.ip_to_userip[entry]

    @staticmethod
    def _process_range_entry(
        entry: str,
        username: str,
        db_path: Path,
        settings: UserIPSettings,
        range_entries: list[_RangeEntry],
    ) -> None:
        """Process a range entry (CIDR, start-end, wildcard) during build."""
        try:
            ip_range = parse_ip_range(entry)
        except ValueError:
            logger.warning('Skipping unparseable UserIP range entry: %r', entry)
            return

        existing = next(
            (re for re in range_entries if re.ip_range.raw == entry and re.db_path == db_path),
            None,
        )
        if existing is not None:
            if username not in existing.usernames:
                existing.usernames.append(username)
        else:
            range_entries.append(
                _RangeEntry(
                    ip_range=ip_range,
                    db_path=db_path,
                    settings=settings,
                    usernames=[username],
                ),
            )

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

            build_state = _BuildState(ips_set=ips_set, ip_to_userip=ip_to_userip, unresolved_conflicts=unresolved_conflicts)

            for db_entry in cls.userip_databases:
                for username, ips in db_entry.single_ips.items():
                    for ip in ips:
                        cls._process_single_ip(ip, username, db_entry, build_state)
                for username, ranges in db_entry.range_ips.items():
                    for range_str in ranges:
                        cls._process_range_entry(range_str, username, db_entry.db_path, db_entry.settings, range_entries)

            # Assign or refresh range-matched UserIP for players not covered by single-IP entries.
            if range_entries:
                for player in PlayersRegistry.get_default_sorted_players():
                    if player.ip in ip_to_userip:
                        continue
                    for range_entry in range_entries:
                        if player.ip in range_entry.ip_range:
                            player.userip = UserIP(
                                ip=player.ip,
                                db_path=range_entry.db_path,
                                settings=range_entry.settings,
                                usernames=list(range_entry.usernames),
                            )
                            break

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
            cls.build_version += 1

    @classmethod
    def is_known_ip(cls, ip: str) -> bool:
        """Check if an IP address matches any entry (exact or range).

        Checks the O(1) `ips_set` first, then iterates over range entries.
        """
        if ip in cls.ips_set:
            return True
        try:
            addr = IPv4Address(ip)
        except ValueError:
            return False
        return any(addr in re.ip_range for re in cls._range_entries)

    @classmethod
    def resolve_userip(cls, ip: str) -> UserIP | None:
        """Look up a single IP against the already-built structures without triggering a rebuild."""
        if ip in cls._ip_to_userip:
            return cls._ip_to_userip[ip]
        addr = IPv4Address(ip)
        for entry in cls._range_entries:
            if addr in entry.ip_range:
                return UserIP(ip=ip, db_path=entry.db_path, settings=entry.settings, usernames=entry.usernames)
        return None

    @classmethod
    def get_matching_range_raws(cls, ip: str) -> list[str]:
        """Return the raw strings of every range entry that covers `ip` (empty when none match)."""
        try:
            addr = IPv4Address(ip)
        except ValueError:
            return []
        return [entry.ip_range.raw for entry in cls._range_entries if addr in entry.ip_range]

    @classmethod
    def get_userip_database_filepaths(cls) -> list[Path]:
        """Return all enabled UserIP database file paths."""
        with cls._update_userip_database_lock:
            return [db_entry.db_path for db_entry in cls.userip_databases]
