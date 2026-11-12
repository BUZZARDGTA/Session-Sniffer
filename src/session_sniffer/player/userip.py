"""UserIP settings, database loading, and IP-to-user resolution."""

import dataclasses
import logging
from bisect import bisect_left, bisect_right
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QMessageBox

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.error_messages import format_userip_ip_conflict_message
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.dialogs import create_nonmodal_warning
from session_sniffer.guis.utils import find_main_window
from session_sniffer.models.userip_settings_model import EntrySource, UserIPEntryModel, pick_earliest_iso, pick_latest_iso
from session_sniffer.networking.ip_range import IPRange, ipv4_to_int, parse_ip_range
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.userip_groups import are_usernames_unlinked, build_known_alts_clusters, is_searchlist_database
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_triple_quoted_text, split_usernames
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from session_sniffer.models.player import Player

logger = logging.getLogger(__name__)


class _GUIThreadDispatcher(QObject):
    """Schedule callables on the GUI thread from any thread via Qt's auto-queued connection."""

    _call: ClassVar[Signal] = Signal(object)
    conflict_resolver_requested: ClassVar[Signal] = Signal()  # Emitted by the conflict warning; the GUI opens the UserIP Conflict Resolver

    def __init__(self) -> None:
        super().__init__()
        self._call.connect(self._dispatch)

    @staticmethod
    def _dispatch(fn: Callable[[], None]) -> None:
        fn()

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
    """Class representing information associated with a specific IP, including settings, usernames, notes, and metadata."""

    ip: str
    db_path: Path
    settings: UserIPSettings
    usernames: list[str]
    notes: list[str]
    sources: list[EntrySource]
    detections_count: int
    added_at: str | None
    updated_at: str | None
    first_seen_at: str | None
    last_seen_at: str | None
    known_alts: tuple[str, ...] = ()


class UserIPConflict(NamedTuple):
    """Represents a conflict where an IP or IP range is assigned to multiple databases."""

    existing_userip: UserIP
    conflicting_database_path: Path
    conflicting_username: str
    conflicting_ip: str


def _conflict_ip_label(conflict: UserIPConflict) -> str:
    """Return a human-readable IP or range label for a `UserIPConflict`."""
    if conflict.existing_userip.ip == conflict.conflicting_ip:
        return conflict.existing_userip.ip
    return f'{conflict.existing_userip.ip} vs {conflict.conflicting_ip}'


def _conflict_key(conflict: UserIPConflict) -> str:
    """Return a unique identifier string for a `UserIPConflict`."""
    return f'{conflict.existing_userip.db_path}:{conflict.existing_userip.ip} vs {conflict.conflicting_database_path}:{conflict.conflicting_ip}'


class _RangeEntry(NamedTuple):
    """A parsed IP range entry associated with a specific UserIP database."""

    ip_range: IPRange
    db_path: Path
    settings: UserIPSettings
    usernames: list[str]
    notes: list[str]
    sources: list[EntrySource]
    detections_count: int
    added_at: str | None
    updated_at: str | None
    first_seen_at: str | None
    last_seen_at: str | None
    known_alts: tuple[str, ...] = ()


class _UsernameMeta(NamedTuple):
    """Aggregated metadata for a single non-ambiguous username across a UserIP database."""

    db_path: Path
    settings: UserIPSettings
    canonical_name: str
    notes: list[str]
    sources: list[EntrySource]
    detections_count: int
    added_at: str | None
    updated_at: str | None
    first_seen_at: str | None
    last_seen_at: str | None


class _UserIPDatabaseEntry(NamedTuple):
    """Pre-classified UserIP database entry for efficient build."""

    db_path: Path
    settings: UserIPSettings
    single_entries: list[UserIPEntryModel]
    range_entries: list[UserIPEntryModel]


@dataclasses.dataclass(slots=True)
class _BuildState:
    """Mutable accumulator passed through single-IP and range conflict processing during `UserIPDatabases.build`."""

    ips_set: set[str]
    ip_to_userip: dict[str, UserIP]
    single_userips_by_db: dict[tuple[Path, str], UserIP]
    conflicting_ips: set[str]
    conflicts: list[UserIPConflict]
    conflict_index_by_key: dict[tuple[str, Path], int] = dataclasses.field(default_factory=dict[tuple[str, Path], int])
    range_index_by_key: dict[tuple[Path, str], int] = dataclasses.field(default_factory=dict[tuple[Path, str], int])


_NEGATIVE_IPS_CACHE_MAX = 65536


class UserIPDatabases:
    """Load and cache enabled UserIP databases and resolve IP-to-user mappings."""

    _update_userip_database_lock: ClassVar[Lock] = Lock()

    userip_databases: ClassVar[list[_UserIPDatabaseEntry]] = []
    ips_set: ClassVar[set[str]] = set()
    _ip_to_userip: ClassVar[dict[str, UserIP]] = {}
    _range_entries: ClassVar[list[_RangeEntry]] = []
    _known_alts_clusters: ClassVar[dict[str, list[str]]] = {}
    _username_to_meta: ClassVar[dict[str, _UsernameMeta]] = {}
    _pending_resolvable_usernames: ClassVar[set[str]] = set()
    notified_ip_conflicts: ClassVar[set[str]] = set()
    _conflicting_ips: ClassVar[set[str]] = set()
    _conflicting_ranges: ClassVar[list[IPRange]] = []
    _last_notified_conflicts: ClassVar[list[UserIPConflict]] = []
    _negative_known_ips: ClassVar[set[str]] = set()
    _open_conflict_dialog: ClassVar[QMessageBox | None] = None
    build_version: ClassVar[int] = 0

    @classmethod
    def _notify_ip_conflicts(cls, conflicts: Sequence[UserIPConflict], *, newly_detected_ips: set[str] | None = None) -> None:
        if not conflicts:
            return

        summary_template, detailed_text = format_userip_ip_conflict_message(conflicts=conflicts, userip_databases_dir=USERIP_DATABASES_DIR_PATH)
        text = format_triple_quoted_text(summary_template)

        for conflict in conflicts:
            conflict_key = _conflict_key(conflict)
            if newly_detected_ips is None or conflict_key in newly_detected_ips:
                logger.warning(
                    'UserIP IP conflict for %s: "%s" (%s) vs "%s" (%s)',
                    _conflict_ip_label(conflict),
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
            resolve_button = dlg.addButton('Resolve Conflicts…', QMessageBox.ButtonRole.ActionRole)
            resolve_button.clicked.connect(gui_dispatcher.conflict_resolver_requested)
            dlg.setDefaultButton(resolve_button)

            def _on_finished(_result: int) -> None:
                UserIPDatabases._open_conflict_dialog = None

            dlg.finished.connect(_on_finished)
            UserIPDatabases._open_conflict_dialog = dlg
            dlg.show()
            dlg.raise_()
            dlg.activateWindow()

        gui_dispatcher.invoke(_show_on_gui)

    @classmethod
    def get_conflicts(cls) -> list[UserIPConflict]:
        """Return a copy of the UserIP conflicts detected by the most recent build."""
        return list(cls._last_notified_conflicts)

    @classmethod
    def _close_conflict_dialog(cls) -> None:
        dlg = cls._open_conflict_dialog
        cls._open_conflict_dialog = None
        if dlg is not None:
            dlg.accept()

    @classmethod
    def populate(cls, database_entries: list[tuple[Path, UserIPSettings, list[UserIPEntryModel]]]) -> None:
        """Replace `cls.userip_databases` with a new set of databases.

        Args:
            database_entries: A list of tuples containing db_path, settings, and entries.
        """
        classified: list[_UserIPDatabaseEntry] = []
        for db_path, settings, entries in database_entries:
            if not settings.enabled:
                continue
            single_entries: list[UserIPEntryModel] = []
            range_entries: list[UserIPEntryModel] = []
            for entry in entries:
                if ipv4_to_int(entry.ip) is not None:
                    single_entries.append(entry)
                else:
                    range_entries.append(entry)
            classified.append(_UserIPDatabaseEntry(db_path=db_path, settings=settings, single_entries=single_entries, range_entries=range_entries))
        with cls._update_userip_database_lock:
            cls.userip_databases = classified

    @staticmethod
    def _merge_single_entry_into_userip(existing: UserIP | None, entry_model: UserIPEntryModel, db_entry: _UserIPDatabaseEntry) -> UserIP:
        """Create or update a `UserIP` by merging `entry_model` into `existing`."""
        entry, username, note = entry_model.ip, entry_model.username, entry_model.notes.strip()
        if existing is None:
            return UserIP(
                ip=entry, db_path=db_entry.db_path, settings=db_entry.settings, usernames=[username], notes=[note] if note else [],
                sources=[entry_model.source], detections_count=entry_model.detections_count, added_at=entry_model.added_at,
                updated_at=entry_model.updated_at, first_seen_at=entry_model.first_seen_at, last_seen_at=entry_model.last_seen_at,
            )
        if username not in existing.usernames:
            existing.usernames.append(username)
        if note and note not in existing.notes:
            existing.notes.append(note)
        if entry_model.source not in existing.sources:
            existing.sources.append(entry_model.source)
        return existing._replace(
            detections_count=max(existing.detections_count, entry_model.detections_count),
            added_at=pick_earliest_iso(existing.added_at, entry_model.added_at), updated_at=pick_latest_iso(existing.updated_at, entry_model.updated_at),
            first_seen_at=pick_earliest_iso(existing.first_seen_at, entry_model.first_seen_at), last_seen_at=pick_latest_iso(existing.last_seen_at, entry_model.last_seen_at),
        )

    @classmethod
    def _process_single_ip(cls, entry_model: UserIPEntryModel, db_entry: _UserIPDatabaseEntry, build_state: _BuildState) -> None:
        """Process a single IP entry during build."""
        entry, username = entry_model.ip, entry_model.username
        db_key = (db_entry.db_path, entry)
        merged_db_userip = cls._merge_single_entry_into_userip(build_state.single_userips_by_db.get(db_key), entry_model, db_entry)
        build_state.single_userips_by_db[db_key] = merged_db_userip

        if entry in build_state.ip_to_userip and build_state.ip_to_userip[entry].db_path != db_entry.db_path:
            conflict_lookup_key = (entry, db_entry.db_path)
            existing_index = build_state.conflict_index_by_key.get(conflict_lookup_key)
            if existing_index is not None:
                existing_conflict = build_state.conflicts[existing_index]
                if username not in split_usernames(existing_conflict.conflicting_username):
                    build_state.conflicts[existing_index] = existing_conflict._replace(
                        conflicting_username=f'{existing_conflict.conflicting_username}, {username}',
                    )
            else:
                build_state.conflict_index_by_key[conflict_lookup_key] = len(build_state.conflicts)
                build_state.conflicts.append(
                    UserIPConflict(
                        existing_userip=build_state.ip_to_userip[entry], conflicting_database_path=db_entry.db_path,
                        conflicting_username=username, conflicting_ip=entry,
                    ),
                )
            build_state.conflicting_ips.add(entry)
            return

        build_state.ips_set.add(entry)
        build_state.ip_to_userip[entry] = merged_db_userip

    @staticmethod
    def _range_entry_to_userip(range_entry: _RangeEntry) -> UserIP:
        """Convert a `_RangeEntry` into a `UserIP` snapshot for conflict reporting."""
        return UserIP(
            ip=range_entry.ip_range.raw, db_path=range_entry.db_path, settings=range_entry.settings, usernames=list(range_entry.usernames),
            notes=list(range_entry.notes), sources=list(range_entry.sources), detections_count=range_entry.detections_count,
            added_at=range_entry.added_at, updated_at=range_entry.updated_at, first_seen_at=range_entry.first_seen_at, last_seen_at=range_entry.last_seen_at,
        )

    @classmethod
    def _detect_range_conflicts(
        cls, current_databases: Sequence[_UserIPDatabaseEntry], build_state: _BuildState, range_entries: Sequence[_RangeEntry],
    ) -> set[tuple[Path, str]]:
        """Detect cross-database single-IP-vs-range and range-vs-range conflicts.

        Returns:
            The set of `(db_path, raw_range)` pairs involved in at least one conflict.
        """
        conflicting_range_keys: set[tuple[Path, str]] = set()
        if not range_entries:
            return conflicting_range_keys

        db_order = {db_entry.db_path: idx for idx, db_entry in enumerate(current_databases)}
        sorted_singles = sorted(
            ((addr_int, single_userip) for single_userip in build_state.single_userips_by_db.values() if (addr_int := ipv4_to_int(single_userip.ip)) is not None),
            key=lambda item: (item[0], db_order.get(item[1].db_path, 0)),
        )
        if sorted_singles:
            sorted_single_ints = [item[0] for item in sorted_singles]
            for range_entry in range_entries:
                ip_range = range_entry.ip_range
                if ip_range.end_int < ip_range.start_int:
                    continue
                lo = bisect_left(sorted_single_ints, ip_range.start_int)
                hi = bisect_right(sorted_single_ints, ip_range.end_int)
                for _, single_userip in sorted_singles[lo:hi]:
                    if single_userip.db_path == range_entry.db_path:
                        continue
                    ip = single_userip.ip
                    if db_order.get(single_userip.db_path, 0) < db_order.get(range_entry.db_path, 0):
                        conflict = UserIPConflict(
                            existing_userip=single_userip, conflicting_database_path=range_entry.db_path,
                            conflicting_username=', '.join(range_entry.usernames), conflicting_ip=ip_range.raw,
                        )
                    else:
                        conflict = UserIPConflict(
                            existing_userip=cls._range_entry_to_userip(range_entry), conflicting_database_path=single_userip.db_path,
                            conflicting_username=', '.join(single_userip.usernames), conflicting_ip=ip,
                        )
                    build_state.conflicts.append(conflict)
                    build_state.conflicting_ips.add(ip)
                    conflicting_range_keys.add((range_entry.db_path, ip_range.raw))

        sorted_ranges = sorted(
            ((entry.ip_range.start_int, idx, entry) for idx, entry in enumerate(range_entries) if entry.ip_range.start_int <= entry.ip_range.end_int),
            key=lambda item: (item[0], item[1]),
        )
        for pos, (_, idx_a, range_a) in enumerate(sorted_ranges):
            end_a = range_a.ip_range.end_int
            for start_b, idx_b, range_b in sorted_ranges[pos + 1 :]:
                if start_b > end_a:
                    break
                if range_a.db_path == range_b.db_path:
                    continue
                first, second = (range_a, range_b) if idx_a < idx_b else (range_b, range_a)
                build_state.conflicts.append(
                    UserIPConflict(
                        existing_userip=cls._range_entry_to_userip(first), conflicting_database_path=second.db_path,
                        conflicting_username=', '.join(second.usernames), conflicting_ip=second.ip_range.raw,
                    ),
                )
                conflicting_range_keys.add((first.db_path, first.ip_range.raw))
                conflicting_range_keys.add((second.db_path, second.ip_range.raw))

        return conflicting_range_keys

    @staticmethod
    def _process_range_entry(
        entry_model: UserIPEntryModel, db_path: Path, settings: UserIPSettings, range_entries: list[_RangeEntry], range_index_by_key: dict[tuple[Path, str], int],
    ) -> None:
        """Process a range entry (CIDR, start-end, wildcard) during build."""
        entry = entry_model.ip
        username = entry_model.username
        note = entry_model.notes.strip()

        try:
            ip_range = parse_ip_range(entry)
        except ValueError:
            logger.warning('Skipping unparseable UserIP range entry: %r', entry)
            return

        range_key = (db_path, ip_range.raw)
        existing_index = range_index_by_key.get(range_key)
        if existing_index is not None:
            existing = range_entries[existing_index]
            if username not in existing.usernames:
                existing.usernames.append(username)
            if note and note not in existing.notes:
                existing.notes.append(note)
            if entry_model.source not in existing.sources:
                existing.sources.append(entry_model.source)
            range_entries[existing_index] = existing._replace(
                detections_count=max(existing.detections_count, entry_model.detections_count),
                added_at=pick_earliest_iso(existing.added_at, entry_model.added_at),
                updated_at=pick_latest_iso(existing.updated_at, entry_model.updated_at),
                first_seen_at=pick_earliest_iso(existing.first_seen_at, entry_model.first_seen_at),
                last_seen_at=pick_latest_iso(existing.last_seen_at, entry_model.last_seen_at),
            )
        else:
            range_index_by_key[range_key] = len(range_entries)
            range_entries.append(
                _RangeEntry(
                    ip_range=ip_range, db_path=db_path, settings=settings, usernames=[username], notes=[note] if note else [],
                    sources=[entry_model.source], detections_count=entry_model.detections_count, added_at=entry_model.added_at,
                    updated_at=entry_model.updated_at, first_seen_at=entry_model.first_seen_at, last_seen_at=entry_model.last_seen_at,
                ),
            )

    @staticmethod
    def _resolve_from_built_structures(
        ip: str, ip_to_userip: dict[str, UserIP], range_entries: list[_RangeEntry], conflicting_ips: set[str], conflicting_ranges: Sequence[IPRange] = (),
    ) -> UserIP | None:
        """Resolve a UserIP object by combining single-IP and covering range entries."""
        if ip in conflicting_ips:
            return None

        single_userip = ip_to_userip.get(ip)
        matching_ranges: list[_RangeEntry] = []
        if range_entries or conflicting_ranges:
            addr_int = ipv4_to_int(ip)
            if addr_int is not None:
                if any(ip_range.start_int <= addr_int <= ip_range.end_int for ip_range in conflicting_ranges):
                    return None
                matching_ranges = [entry for entry in range_entries if entry.ip_range.start_int <= addr_int <= entry.ip_range.end_int]

        matched_entries: list[UserIP | _RangeEntry] = [*([single_userip] if single_userip is not None else ()), *matching_ranges]
        if not matched_entries:
            return None
        return UserIPDatabases._combine_userip_entries(ip, matched_entries)

    @staticmethod
    def _combine_userip_entries(ip: str, matched_entries: Sequence[UserIP | _RangeEntry]) -> UserIP:
        """Combine one or more `UserIP` or `_RangeEntry` snapshots from the same database into a single `UserIP`."""
        primary = matched_entries[0]
        combined_usernames: list[str] = []
        combined_known_alts: list[str] = []
        direct_cfs: set[str] = set()
        combined_notes: list[str] = []
        combined_sources: list[EntrySource] = []
        detections_count = 0
        added_at = updated_at = first_seen_at = last_seen_at = None

        for matched in matched_entries:
            direct_cfs.update({u.casefold() for u in matched.usernames} - {a.casefold() for a in matched.known_alts})
            combined_usernames.extend(matched.usernames)
            combined_known_alts.extend(matched.known_alts)
            combined_notes.extend(matched.notes)
            combined_sources.extend(matched.sources)
            detections_count = max(detections_count, matched.detections_count)
            added_at = pick_earliest_iso(added_at, matched.added_at)
            updated_at = pick_latest_iso(updated_at, matched.updated_at)
            first_seen_at = pick_earliest_iso(first_seen_at, matched.first_seen_at)
            last_seen_at = pick_latest_iso(last_seen_at, matched.last_seen_at)

        return UserIP(
            ip=ip, db_path=primary.db_path, settings=primary.settings, usernames=dedup_preserve_order(combined_usernames),
            notes=dedup_preserve_order(combined_notes), sources=dedup_preserve_order(combined_sources), detections_count=detections_count,
            added_at=added_at, updated_at=updated_at, first_seen_at=first_seen_at, last_seen_at=last_seen_at,
            known_alts=tuple(alt for alt in dedup_preserve_order(combined_known_alts) if alt.casefold() not in direct_cfs),
        )

    @staticmethod
    def _build_username_meta(
        current_databases: list[_UserIPDatabaseEntry], ambiguous_usernames: set[str], canonical_names: dict[str, str], known_alts_clusters: dict[str, list[str]],
    ) -> dict[str, _UsernameMeta]:
        """Build a lookup table mapping non-ambiguous casefolded usernames to their aggregated metadata."""
        username_to_meta: dict[str, _UsernameMeta] = {}
        for db_entry in current_databases:
            for entry_model in (*db_entry.single_entries, *db_entry.range_entries):
                stripped = entry_model.username.strip()
                if not stripped:
                    continue
                cf = stripped.casefold()
                if cf in ambiguous_usernames:
                    continue
                canonical = canonical_names.get(cf, stripped)
                note = entry_model.notes.strip()
                existing_meta = username_to_meta.get(cf)
                if existing_meta is None:
                    username_to_meta[cf] = _UsernameMeta(
                        db_path=db_entry.db_path, settings=db_entry.settings, canonical_name=canonical, notes=[note] if note else [],
                        sources=[entry_model.source], detections_count=entry_model.detections_count, added_at=entry_model.added_at,
                        updated_at=entry_model.updated_at, first_seen_at=entry_model.first_seen_at, last_seen_at=entry_model.last_seen_at,
                    )
                else:
                    if note and note not in existing_meta.notes:
                        existing_meta.notes.append(note)
                    if entry_model.source not in existing_meta.sources:
                        existing_meta.sources.append(entry_model.source)
                    username_to_meta[cf] = existing_meta._replace(
                        detections_count=max(existing_meta.detections_count, entry_model.detections_count),
                        added_at=pick_earliest_iso(existing_meta.added_at, entry_model.added_at),
                        updated_at=pick_latest_iso(existing_meta.updated_at, entry_model.updated_at),
                        first_seen_at=pick_earliest_iso(existing_meta.first_seen_at, entry_model.first_seen_at),
                        last_seen_at=pick_latest_iso(existing_meta.last_seen_at, entry_model.last_seen_at),
                    )

        for cf, cluster in known_alts_clusters.items():
            if cf in username_to_meta and len({username_to_meta[m.casefold()].db_path for m in cluster if m.casefold() in username_to_meta}) == 1:
                meta = username_to_meta[cf]
                for alt_name in cluster:
                    alt_cf = alt_name.casefold()
                    if alt_cf not in ambiguous_usernames and alt_cf not in username_to_meta:
                        username_to_meta[alt_cf] = meta._replace(canonical_name=alt_name, notes=list(meta.notes), sources=list(meta.sources))
        return username_to_meta

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
        single_userips_by_db: dict[tuple[Path, str], UserIP] = {}
        range_entries: list[_RangeEntry] = []
        conflicting_ips: set[str] = set()
        conflicts: list[UserIPConflict] = []

        build_state = _BuildState(ips_set=ips_set, ip_to_userip=ip_to_userip, single_userips_by_db=single_userips_by_db, conflicting_ips=conflicting_ips, conflicts=conflicts)

        for db_entry in current_databases:
            for single_entry in db_entry.single_entries:
                cls._process_single_ip(single_entry, db_entry, build_state)
            for range_entry in db_entry.range_entries:
                cls._process_range_entry(range_entry, db_entry.db_path, db_entry.settings, range_entries, build_state.range_index_by_key)

        conflicting_range_keys = cls._detect_range_conflicts(current_databases, build_state, range_entries)
        unresolved_conflicts = {_conflict_key(conflict) for conflict in conflicts}

        # Strip conflicting single IPs and range entries from the lookup structures so they are fully ignored.
        for conflict_ip in conflicting_ips:
            ips_set.discard(conflict_ip)
            ip_to_userip.pop(conflict_ip, None)

        conflicting_ranges = [entry.ip_range for entry in range_entries if (entry.db_path, entry.ip_range.raw) in conflicting_range_keys]
        if conflicting_range_keys:
            range_entries = [entry for entry in range_entries if (entry.db_path, entry.ip_range.raw) not in conflicting_range_keys]

        conflicting_ip_usernames: set[str] = set()
        username_databases: dict[str, set[Path]] = {}
        for db_entry in current_databases:
            for single_entry in db_entry.single_entries:
                stripped = single_entry.username.strip()
                if not stripped:
                    continue
                cf = stripped.casefold()
                username_databases.setdefault(cf, set()).add(db_entry.db_path)
                if single_entry.ip in conflicting_ips:
                    conflicting_ip_usernames.add(cf)
            for range_entry in db_entry.range_entries:
                stripped = range_entry.username.strip()
                if stripped:
                    cf = stripped.casefold()
                    username_databases.setdefault(cf, set()).add(db_entry.db_path)
                    if (db_entry.db_path, range_entry.ip.strip()) in conflicting_range_keys:
                        conflicting_ip_usernames.add(cf)
        ambiguous_usernames: set[str] = {cf for cf, paths in username_databases.items() if len(paths) > 1} | conflicting_ip_usernames
        single_db_by_cf = {cf: next(iter(paths)) for cf, paths in username_databases.items() if cf not in ambiguous_usernames and len(paths) == 1}
        # Searchlist IPs are unconfirmed candidates, so usernames sharing one must not be linked as known alts.
        canonical_names, known_alts_clusters = build_known_alts_clusters(
            [
                *(u.usernames for u in ip_to_userip.values() if not is_searchlist_database(u.db_path)),
                *(r.usernames for r in range_entries if not is_searchlist_database(r.db_path)),
            ],
            ambiguous_usernames,
            single_db_by_cf,
        )

        if Settings.userip_sync_known_alts:
            for ip, userip_obj in list(ip_to_userip.items()):
                expanded = cls._expand_usernames_with_cluster_dict(userip_obj.usernames, known_alts_clusters)
                if expanded != userip_obj.usernames:
                    existing_names = set(userip_obj.usernames)
                    ip_to_userip[ip] = userip_obj._replace(usernames=expanded, known_alts=tuple(n for n in expanded if n not in existing_names))

            for index, range_obj in enumerate(range_entries):
                expanded = cls._expand_usernames_with_cluster_dict(range_obj.usernames, known_alts_clusters)
                if expanded != range_obj.usernames:
                    existing_names = set(range_obj.usernames)
                    range_entries[index] = range_obj._replace(usernames=expanded, known_alts=tuple(n for n in expanded if n not in existing_names))

        include_looky_for_snapshots = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()

        # Assign or refresh UserIP for all players in a single pass.
        for player in PlayersRegistry.get_all_players():
            prev_userip = player.userip
            new_userip = cls.filter_userip_for_player(
                player,
                cls._resolve_from_built_structures(player.ip, ip_to_userip, range_entries, conflicting_ips, conflicting_ranges),
            )
            player.userip = new_userip
            with player.looky_system.lock:
                player_looky = list(player.looky_system.usernames) if include_looky_for_snapshots and player.looky_system.is_initialized else ()
            player.rebuild_usernames(looky_usernames=player_looky)
            if new_userip is None:
                player.userip_detection = None
                if prev_userip is not None:
                    GTASuspendManager.release_reason_global(f'userip:{player.ip}')
                    if not player.left_event.is_set():
                        player.detection_checked = False
            else:
                if prev_userip is not None and prev_userip.settings.protection.enabled and not new_userip.settings.protection.enabled:
                    GTASuspendManager.release_reason_global(f'userip:{player.ip}')
                if (
                    prev_userip is not None
                    and player.userip_detection is not None
                    and player.userip_detection.as_processed_task
                    and cls._should_retrigger_userip_detection(prev_userip, new_userip)
                ):
                    player.userip_detection.as_processed_task = False

        for snapshot_player in SessionTracker.get_all_snapshot_players():
            snapshot_player.userip = cls.filter_userip_for_player(
                snapshot_player,
                cls._resolve_from_built_structures(snapshot_player.ip, ip_to_userip, range_entries, conflicting_ips, conflicting_ranges),
            )
            with snapshot_player.looky_system.lock:
                snapshot_looky_usernames = (
                    list(snapshot_player.looky_system.usernames)
                    if include_looky_for_snapshots and snapshot_player.looky_system.is_initialized
                    else ()
                )
            snapshot_player.rebuild_usernames(looky_usernames=snapshot_looky_usernames)

        username_to_meta = cls._build_username_meta(current_databases, ambiguous_usernames, canonical_names, known_alts_clusters)

        newly_detected_ips = cls._find_newly_detected_conflict_keys(conflicts, cls._last_notified_conflicts)
        has_new_conflicts = bool(newly_detected_ips)
        conflicts_changed = conflicts != cls._last_notified_conflicts

        with cls._update_userip_database_lock:
            # Auto-close the open dialog when all conflicts are resolved
            if not unresolved_conflicts and cls._open_conflict_dialog is not None:
                gui_dispatcher.invoke(cls._close_conflict_dialog)

            # Record all currently active conflicts
            cls.notified_ip_conflicts = set(unresolved_conflicts)
            cls._conflicting_ips = set(conflicting_ips)
            cls._conflicting_ranges = list(conflicting_ranges)
            cls._last_notified_conflicts = list(conflicts)

            old_username_targets = {cf: (meta.db_path, meta.canonical_name) for cf, meta in cls._username_to_meta.items()}
            for cf, meta in username_to_meta.items():
                if old_username_targets.get(cf) != (meta.db_path, meta.canonical_name):
                    cls._pending_resolvable_usernames.add(cf)

            cls._known_alts_clusters = known_alts_clusters
            cls.ips_set = ips_set
            cls._ip_to_userip = ip_to_userip
            cls._range_entries = range_entries
            cls._username_to_meta = username_to_meta
            cls._negative_known_ips = set()
            cls.build_version += 1

        if unresolved_conflicts and (has_new_conflicts or (conflicts_changed and cls._open_conflict_dialog is not None)):
            cls._notify_ip_conflicts(conflicts, newly_detected_ips=newly_detected_ips)

    @staticmethod
    def _should_retrigger_userip_detection(prev_userip: UserIP, new_userip: UserIP) -> bool:
        """Return whether a change between `prev_userip` and `new_userip` warrants re-running connected detection actions."""
        if prev_userip.db_path != new_userip.db_path:
            return True
        prev_settings = prev_userip.settings
        new_settings = new_userip.settings
        return (
            (not prev_settings.protection.enabled and new_settings.protection.enabled)
            or (
                new_settings.protection.enabled
                and prev_settings.protection.suspend_process_mode != new_settings.protection.suspend_process_mode
            )
            or (not prev_settings.notifications and new_settings.notifications)
            or (prev_settings.voice_notifications != new_settings.voice_notifications and bool(new_settings.voice_notifications))
            or (not prev_settings.log and new_settings.log)
        )

    @classmethod
    def consume_newly_resolvable_usernames(cls) -> frozenset[str]:
        """Return and clear the set of casefolded usernames whose target database/canonical mapping was added or changed."""
        if not cls._pending_resolvable_usernames:
            return frozenset(())
        with cls._update_userip_database_lock:
            if not cls._pending_resolvable_usernames:
                return frozenset(())
            result = frozenset(cls._pending_resolvable_usernames)
            cls._pending_resolvable_usernames.clear()
            return result

    @staticmethod
    def _find_newly_detected_conflict_keys(conflicts: Sequence[UserIPConflict], previous_conflicts: Sequence[UserIPConflict]) -> set[str]:
        """Return conflict keys for conflicts that are newly introduced or have newly added usernames."""
        prev_usernames: dict[tuple[Path, str], set[str]] = {}
        for prev in previous_conflicts:
            prev_usernames.setdefault((prev.existing_userip.db_path, prev.existing_userip.ip), set()).update(prev.existing_userip.usernames)
            prev_usernames.setdefault((prev.conflicting_database_path, prev.conflicting_ip), set()).update(split_usernames(prev.conflicting_username))
        newly_detected: set[str] = set()
        for conflict in conflicts:
            key_a = (conflict.existing_userip.db_path, conflict.existing_userip.ip)
            key_b = (conflict.conflicting_database_path, conflict.conflicting_ip)
            if (
                key_a not in prev_usernames
                or key_b not in prev_usernames
                or not set(conflict.existing_userip.usernames).issubset(prev_usernames[key_a])
                or not set(split_usernames(conflict.conflicting_username)).issubset(prev_usernames[key_b])
            ):
                newly_detected.add(_conflict_key(conflict))
        return newly_detected

    @classmethod
    def is_conflicting_ip(cls, ip: str) -> bool:
        """Return whether `ip` matches any conflicting single-IP or range entry."""
        if ip in cls._conflicting_ips:
            return True
        if not cls._conflicting_ranges or (addr_int := ipv4_to_int(ip)) is None:
            return False
        return any(ip_range.start_int <= addr_int <= ip_range.end_int for ip_range in cls._conflicting_ranges)

    @classmethod
    def is_conflicting_entry(cls, entry: str) -> bool:
        """Return whether a single-IP or range entry string is currently involved in a conflict."""
        if ipv4_to_int(entry) is not None:
            return cls.is_conflicting_ip(entry)
        try:
            ip_range = parse_ip_range(entry)
        except ValueError:
            return False
        if any((conflict_int := ipv4_to_int(c_ip)) is not None and ip_range.start_int <= conflict_int <= ip_range.end_int for c_ip in cls._conflicting_ips):
            return True
        return any(ip_range.overlaps(conflict_range) for conflict_range in cls._conflicting_ranges)

    @classmethod
    def renotify_if_conflicting(cls, entries: Sequence[str]) -> None:
        """Re-show the conflict warning dialog if any entry in `entries` is currently in conflict."""
        if not cls._last_notified_conflicts:
            return
        if any(cls.is_conflicting_entry(entry) for entry in entries):
            cls._notify_ip_conflicts(cls._last_notified_conflicts, newly_detected_ips=set())

    @classmethod
    def is_known_ip(cls, ip: str) -> bool:
        """Check if an IP address matches any entry (exact or range).

        Checks the O(1) `ips_set` first, then iterates over range entries.
        """
        neg = cls._negative_known_ips
        if ip in neg:
            return False
        if cls.is_conflicting_ip(ip):
            if len(neg) < _NEGATIVE_IPS_CACHE_MAX:
                neg.add(ip)
            return False
        if ip in cls.ips_set:
            return True
        if cls._range_entries and (addr_int := ipv4_to_int(ip)) is not None and any(e.ip_range.start_int <= addr_int <= e.ip_range.end_int for e in cls._range_entries):
            return True
        if len(neg) < _NEGATIVE_IPS_CACHE_MAX:
            neg.add(ip)
        return False

    @classmethod
    def resolve_userip(cls, ip: str) -> UserIP | None:
        """Look up a single IP against the already-built structures without triggering a rebuild."""
        return cls._resolve_from_built_structures(ip, cls._ip_to_userip, cls._range_entries, cls._conflicting_ips, cls._conflicting_ranges)

    @classmethod
    def filter_userip_for_player(cls, player: Player, userip: UserIP | None) -> UserIP | None:
        """Filter unlinked or explicitly detached usernames from `userip` for `player`."""
        if userip is None or (len(userip.usernames) <= 1 and not userip.known_alts and not player.detached_userip_usernames_cf):
            return userip

        include_looky = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
        live_usernames = player.get_live_non_userip_usernames(include_looky=include_looky)
        excluded_cf = set(player.detached_userip_usernames_cf)
        live_candidates = [u for u in live_usernames if u.casefold() not in excluded_cf]
        userip_cfs = {u.casefold() for u in userip.usernames}
        anchors = [u for u in live_candidates if u.casefold() in userip_cfs] or live_candidates

        candidates = [u for u in userip.usernames if u.casefold() not in excluded_cf]
        if anchors:
            candidates = [u for u in candidates if not any(are_usernames_unlinked(u, anchor) for anchor in anchors)]

        if len(candidates) > 1:
            seed = max(candidates, key=lambda u: sum(1 for v in candidates if u.casefold() != v.casefold() and not are_usernames_unlinked(u, v)))
            cluster = [seed]
            for candidate in candidates:
                if candidate.casefold() != seed.casefold() and not any(are_usernames_unlinked(candidate, existing) for existing in cluster):
                    cluster.append(candidate)
            cluster_cfs = {u.casefold() for u in cluster}
            kept_usernames = [u for u in candidates if u.casefold() in cluster_cfs]
        else:
            kept_usernames = candidates

        if not kept_usernames and userip.usernames:
            kept_usernames = [next((u for u in userip.usernames if u.casefold() not in excluded_cf), userip.usernames[0])]

        kept_cfs = {u.casefold() for u in kept_usernames}
        anchor_and_kept = dedup_preserve_order(anchors, kept_usernames)
        kept_alts = tuple(
            alt for alt in userip.known_alts
            if alt.casefold() not in excluded_cf and alt.casefold() not in kept_cfs and not any(are_usernames_unlinked(alt, ref) for ref in anchor_and_kept)
        )
        return userip if kept_usernames == userip.usernames and kept_alts == userip.known_alts else userip._replace(usernames=kept_usernames, known_alts=kept_alts)

    @classmethod
    def resolve_userip_for_player(cls, player: Player) -> UserIP | None:
        """Resolve and filter a `UserIP` entry for `player`."""
        return cls.filter_userip_for_player(player, cls.resolve_userip(player.ip))

    @classmethod
    def resolve_userip_by_username(cls, username: str, player_ip: str) -> tuple[UserIP, str] | None:
        """Resolve a UserIP snapshot and canonical username for a single candidate username.

        Args:
            username: The candidate username to look up.
            player_ip: The IP address of the player being checked.

        Returns:
            A tuple of (UserIP, canonical_username) or None if no match is found.
        """
        if cls.is_conflicting_ip(player_ip):
            return None
        stripped = username.strip()
        if not stripped:
            return None
        cf = stripped.casefold()
        with cls._update_userip_database_lock:
            meta = cls._username_to_meta.get(cf)
            if meta is None:
                return None
            clusters = cls._known_alts_clusters

        usernames = (
            cls._expand_usernames_with_cluster_dict([meta.canonical_name], clusters)
            if Settings.userip_sync_known_alts
            else [meta.canonical_name]
        )
        return (
            UserIP(
                ip=player_ip, db_path=meta.db_path, settings=meta.settings, usernames=usernames, notes=list(meta.notes),
                sources=list(meta.sources), detections_count=meta.detections_count, added_at=meta.added_at,
                updated_at=meta.updated_at, first_seen_at=meta.first_seen_at, last_seen_at=meta.last_seen_at, known_alts=tuple(usernames[1:]),
            ),
            meta.canonical_name,
        )

    @classmethod
    def resolve_userip_by_usernames(cls, usernames: Sequence[str], player_ip: str) -> tuple[UserIP, list[str]] | None:
        """Resolve a UserIP snapshot and matched canonical usernames from a sequence of candidate usernames.

        Returns the combined matching database resolution and deduplicated canonical usernames,
        or None if none match or if candidate usernames resolve to multiple different databases.
        """
        matched_userips: list[UserIP] = []
        matched_usernames: list[str] = []
        seen_canonical_cf: set[str] = set()
        matched_db_path: Path | None = None
        for username in usernames:
            resolved = cls.resolve_userip_by_username(username, player_ip)
            if resolved is None:
                continue
            userip, canonical_username = resolved
            if matched_db_path is None:
                matched_db_path = userip.db_path
            elif userip.db_path != matched_db_path:
                return None
            canonical_cf = canonical_username.casefold()
            if canonical_cf not in seen_canonical_cf:
                seen_canonical_cf.add(canonical_cf)
                matched_userips.append(userip)
                matched_usernames.append(canonical_username)
        if not matched_userips:
            return None
        combined = matched_userips[0] if len(matched_userips) == 1 else cls._combine_userip_entries(player_ip, matched_userips)
        return combined, matched_usernames

    @classmethod
    def get_matching_range_raws(cls, ip: str) -> list[str]:
        """Return the raw strings of every range entry that covers `ip` (empty when none match)."""
        addr_int = ipv4_to_int(ip)
        if addr_int is None:
            return []
        return dedup_preserve_order([entry.ip_range.raw for entry in cls._range_entries if entry.ip_range.start_int <= addr_int <= entry.ip_range.end_int])

    @classmethod
    def get_userip_database_filepaths(cls) -> list[Path]:
        """Return all enabled UserIP database file paths."""
        with cls._update_userip_database_lock:
            return [db_entry.db_path for db_entry in cls.userip_databases]

    @staticmethod
    def _expand_usernames_with_cluster_dict(usernames: Sequence[str], clusters: dict[str, list[str]]) -> list[str]:
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

    @classmethod
    def get_cluster_for_username(cls, username: str) -> list[str]:
        """Return all canonical usernames in the cluster containing `username` (or `[username]` if ungrouped)."""
        stripped = username.strip()
        if not stripped:
            return []
        with cls._update_userip_database_lock:
            cluster = cls._known_alts_clusters.get(stripped.casefold())
        return list(cluster) if cluster is not None and cluster else [stripped]

    @classmethod
    def get_known_username_dbs_cf(cls) -> dict[str, Path]:
        """Return a mapping of casefolded usernames to their target database path for all indexed usernames."""
        with cls._update_userip_database_lock:
            return {cf: meta.db_path for cf, meta in cls._username_to_meta.items()}
