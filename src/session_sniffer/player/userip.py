"""UserIP settings, database loading, and IP-to-user resolution."""

import dataclasses
import logging
from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QColor

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.error_messages import format_userip_ip_conflict_message
from session_sniffer.guis.dialogs import create_nonmodal_warning
from session_sniffer.guis.utils import find_main_window
from session_sniffer.networking.ip_range import IPRange, parse_ip_range
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtWidgets import QMessageBox

logger = logging.getLogger(__name__)


class _GUIThreadDispatcher(QObject):
    """Schedule callables on the GUI thread from any thread via Qt's auto-queued connection."""

    _call: ClassVar[Signal] = Signal(object)

    def __init__(self) -> None:
        super().__init__()

        def _dispatch_fn(fn: Callable[[], None]) -> None:
            try:
                fn()
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception('Unhandled exception in GUI thread dispatcher')

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


class UserIPConflict(NamedTuple):
    """Represents a conflict where an IP is assigned to multiple databases."""

    existing_userip: UserIP
    conflicting_database_path: Path
    conflicting_username: str


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
    conflicts: list[UserIPConflict]


class UserIPDatabases:
    """Load and cache enabled UserIP databases and resolve IP-to-user mappings."""

    _update_userip_database_lock: ClassVar[Lock] = Lock()

    userip_databases: ClassVar[list[_UserIPDatabaseEntry]] = []
    ips_set: ClassVar[set[str]] = set()
    _ip_to_userip: ClassVar[dict[str, UserIP]] = {}
    _range_entries: ClassVar[list[_RangeEntry]] = []
    _known_alts_clusters: ClassVar[dict[str, list[str]]] = {}
    _known_usernames: ClassVar[set[str]] = set()
    notified_ip_conflicts: ClassVar[set[str]] = set()
    _open_conflict_dialog: ClassVar[QMessageBox | None] = None
    build_version: ClassVar[int] = 0

    @classmethod
    def _notify_ip_conflicts(cls, conflicts: Sequence[UserIPConflict], *, newly_detected_ips: set[str] | None = None) -> None:
        if not conflicts:
            return

        summary_template, detailed_text = format_userip_ip_conflict_message(
            conflicts=conflicts,
            userip_databases_dir=USERIP_DATABASES_DIR_PATH,
        )
        text = format_triple_quoted_text(summary_template)

        for conflict in conflicts:
            if newly_detected_ips is None or conflict.existing_userip.ip in newly_detected_ips:
                logger.warning(
                    'UserIP IP conflict for %s: "%s" (%s) vs "%s" (%s)',
                    conflict.existing_userip.ip,
                    conflict.existing_userip.db_path.name,
                    ', '.join(conflict.existing_userip.usernames),
                    conflict.conflicting_database_path.name,
                    conflict.conflicting_username,
                )

        def _show_on_gui() -> None:
            parent = find_main_window()
            if parent is None:
                QTimer.singleShot(500, _show_on_gui)
                return

            if UserIPDatabases._open_conflict_dialog is not None:
                dlg = UserIPDatabases._open_conflict_dialog
                dlg.setText(text)
                dlg.setDetailedText(detailed_text or '')
                dlg.show()
                dlg.raise_()
                dlg.activateWindow()
                return

            dlg = create_nonmodal_warning(parent, text)
            if detailed_text is not None:
                dlg.setDetailedText(detailed_text)

            def _on_finished(_result: int) -> None:
                UserIPDatabases._open_conflict_dialog = None

            dlg.finished.connect(_on_finished)
            UserIPDatabases._open_conflict_dialog = dlg
            dlg.show()

        gui_dispatcher.invoke(_show_on_gui)

    @classmethod
    def _close_conflict_dialog(cls) -> None:
        dlg = cls._open_conflict_dialog
        cls._open_conflict_dialog = None
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
            if entry not in build_state.unresolved_conflicts:
                build_state.conflicts.append(
                    UserIPConflict(
                        existing_userip=build_state.ip_to_userip[entry],
                        conflicting_database_path=db_entry.db_path,
                        conflicting_username=username,
                    ),
                )
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

    @staticmethod
    def _resolve_from_built_structures(
        ip: str,
        ip_to_userip: dict[str, UserIP],
        range_entries: list[_RangeEntry],
    ) -> UserIP | None:
        """Resolve a UserIP object by combining single-IP and covering range entries."""
        single_userip = ip_to_userip.get(ip)
        matching_ranges: list[_RangeEntry] = []
        if range_entries:
            try:
                address = IPv4Address(ip)
                matching_ranges = [entry for entry in range_entries if address in entry.ip_range]
            except ValueError:
                matching_ranges = []

        if single_userip is None and not matching_ranges:
            return None

        primary_db_path = single_userip.db_path if single_userip is not None else matching_ranges[0].db_path
        primary_settings = single_userip.settings if single_userip is not None else matching_ranges[0].settings

        combined_usernames: list[str] = []
        if single_userip is not None:
            combined_usernames.extend(single_userip.usernames)
        for range_entry in matching_ranges:
            combined_usernames.extend(range_entry.usernames)

        return UserIP(
            ip=ip,
            db_path=primary_db_path,
            settings=primary_settings,
            usernames=dedup_preserve_order(combined_usernames),
        )

    @classmethod
    def build(cls) -> None:
        """Rebuild the `ips_set` and `_range_entries` caches dynamically from the current databases.

        Single IPs go into `ips_set` for O(1) lookup.
        Range entries (CIDR, start-end, wildcard) go into `_range_entries` for iteration.
        """
        with cls._update_userip_database_lock:
            # Take a reference to the current databases to avoid holding the lock during building
            current_databases = cls.userip_databases

        ips_set: set[str] = set()
        ip_to_userip: dict[str, UserIP] = {}
        range_entries: list[_RangeEntry] = []
        unresolved_conflicts: set[str] = set()
        conflicts: list[UserIPConflict] = []

        build_state = _BuildState(
            ips_set=ips_set,
            ip_to_userip=ip_to_userip,
            unresolved_conflicts=unresolved_conflicts,
            conflicts=conflicts,
        )

        for db_entry in current_databases:
            for username, ip_addresses in db_entry.single_ips.items():
                for ip in ip_addresses:
                    cls._process_single_ip(ip, username, db_entry, build_state)
            for username, ranges in db_entry.range_ips.items():
                for range_str in ranges:
                    cls._process_range_entry(range_str, username, db_entry.db_path, db_entry.settings, range_entries)

        # Strip conflicting IPs from the lookup structures so they are fully ignored.
        for conflict_ip in unresolved_conflicts:
            ips_set.discard(conflict_ip)
            ip_to_userip.pop(conflict_ip, None)

        # Build known alts clusters from all entries with multiple usernames
        adj: dict[str, set[str]] = {}
        canonical_names: dict[str, str] = {}

        def _register_entry_usernames(names: list[str]) -> None:
            clean_names = [name.strip() for name in names if name.strip()]
            unique_cfs: list[str] = []
            for name in clean_names:
                cf = name.casefold()
                if cf not in canonical_names:
                    canonical_names[cf] = name
                if cf not in unique_cfs:
                    unique_cfs.append(cf)
            if len(unique_cfs) > 1:
                first_cf = unique_cfs[0]
                for other_cf in unique_cfs[1:]:
                    adj.setdefault(first_cf, set()).add(other_cf)
                    adj.setdefault(other_cf, set()).add(first_cf)

        for userip_obj in ip_to_userip.values():
            _register_entry_usernames(userip_obj.usernames)
        for range_obj in range_entries:
            _register_entry_usernames(range_obj.usernames)

        visited: set[str] = set()
        known_alts_clusters: dict[str, list[str]] = {}
        for root in adj:
            if root not in visited:
                component: list[str] = []
                queue = [root]
                visited.add(root)
                while queue:
                    curr = queue.pop()
                    component.append(curr)
                    for neighbor in adj.get(curr, ()):
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                if len(component) > 1:
                    canonical_cluster = [canonical_names[cf] for cf in component]
                    for cf in component:
                        known_alts_clusters[cf] = canonical_cluster

        if Settings.userip_sync_known_alts:
            for ip, userip_obj in list(ip_to_userip.items()):
                expanded = cls._expand_usernames_with_cluster_dict(userip_obj.usernames, known_alts_clusters)
                if expanded != userip_obj.usernames:
                    ip_to_userip[ip] = userip_obj._replace(usernames=expanded)

            for index, range_obj in enumerate(range_entries):
                expanded = cls._expand_usernames_with_cluster_dict(range_obj.usernames, known_alts_clusters)
                if expanded != range_obj.usernames:
                    range_entries[index] = range_obj._replace(usernames=expanded)

        # Assign or refresh UserIP for all players in a single pass.
        for player in PlayersRegistry.get_all_players():
            player.userip = cls._resolve_from_built_structures(player.ip, ip_to_userip, range_entries)
            if player.userip is None:
                player.userip_detection = None

        has_new_conflicts = bool(unresolved_conflicts - cls.notified_ip_conflicts)
        conflicts_changed = unresolved_conflicts != cls.notified_ip_conflicts
        newly_detected_ips = unresolved_conflicts - cls.notified_ip_conflicts

        with cls._update_userip_database_lock:
            # Auto-close the open dialog when all conflicts are resolved
            if not unresolved_conflicts and cls._open_conflict_dialog is not None:
                gui_dispatcher.invoke(cls._close_conflict_dialog)

            # Record all currently active conflicts
            cls.notified_ip_conflicts = set(unresolved_conflicts)

            cls._known_alts_clusters = known_alts_clusters
            cls.ips_set = ips_set
            cls._ip_to_userip = ip_to_userip
            cls._range_entries = range_entries
            cls._known_usernames = set(canonical_names.keys())
            cls.build_version += 1

        if unresolved_conflicts and (has_new_conflicts or (conflicts_changed and cls._open_conflict_dialog is not None)):
            cls._notify_ip_conflicts(conflicts, newly_detected_ips=newly_detected_ips)

    @classmethod
    def is_known_ip(cls, ip: str) -> bool:
        """Check if an IP address matches any entry (exact or range).

        Checks the O(1) `ips_set` first, then iterates over range entries.
        """
        if ip in cls.ips_set:
            return True
        if not cls._range_entries:
            return False
        try:
            address = IPv4Address(ip)
        except ValueError:
            return False
        return any(address in entry.ip_range for entry in cls._range_entries)

    @classmethod
    def is_known_username(cls, username: str) -> bool:
        """Check if a username exists in any enabled UserIP database."""
        stripped = username.strip()
        if not stripped:
            return False
        with cls._update_userip_database_lock:
            return stripped.casefold() in cls._known_usernames

    @classmethod
    def resolve_userip(cls, ip: str) -> UserIP | None:
        """Look up a single IP against the already-built structures without triggering a rebuild."""
        return cls._resolve_from_built_structures(ip, cls._ip_to_userip, cls._range_entries)

    @classmethod
    def get_matching_range_raws(cls, ip: str) -> list[str]:
        """Return the raw strings of every range entry that covers `ip` (empty when none match)."""
        try:
            address = IPv4Address(ip)
        except ValueError:
            return []
        return dedup_preserve_order([entry.ip_range.raw for entry in cls._range_entries if address in entry.ip_range])

    @classmethod
    def get_userip_database_filepaths(cls) -> list[Path]:
        """Return all enabled UserIP database file paths."""
        with cls._update_userip_database_lock:
            return [db_entry.db_path for db_entry in cls.userip_databases]

    @staticmethod
    def _expand_usernames_with_cluster_dict(
        usernames: Sequence[str],
        clusters: dict[str, list[str]],
    ) -> list[str]:
        """Expand usernames using a cluster mapping, preserving original order and casing."""
        expanded: list[str] = []
        seen: set[str] = set()
        for name in usernames:
            stripped = name.strip()
            if not stripped:
                continue
            cf = stripped.casefold()
            if cf not in seen:
                seen.add(cf)
                expanded.append(stripped)

        for name in list(expanded):
            for alt in clusters.get(name.casefold(), ()):
                alt_cf = alt.casefold()
                if alt_cf not in seen:
                    seen.add(alt_cf)
                    expanded.append(alt)

        return expanded

    @classmethod
    def expand_with_known_alts(cls, usernames: Sequence[str]) -> list[str]:
        """Expand a sequence of usernames with any known alt accounts from the database clusters."""
        with cls._update_userip_database_lock:
            clusters = cls._known_alts_clusters
        return cls._expand_usernames_with_cluster_dict(usernames, clusters)
