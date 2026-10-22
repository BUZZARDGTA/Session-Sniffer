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
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.dialogs import create_nonmodal_warning
from session_sniffer.guis.utils import find_main_window
from session_sniffer.models.userip_settings_model import EntrySource, UserIPEntryModel, pick_earliest_iso, pick_latest_iso
from session_sniffer.networking.ip_range import IPRange, parse_ip_range
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_triple_quoted_text, split_usernames
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
    detections_count: int = 0
    added_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None


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
    detections_count: int = 0
    added_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None


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

            def _on_finished(_result: int) -> None:
                UserIPDatabases._open_conflict_dialog = None

            dlg.finished.connect(_on_finished)
            UserIPDatabases._open_conflict_dialog = dlg
            dlg.show()
            dlg.raise_()
            dlg.activateWindow()

        gui_dispatcher.invoke(_show_on_gui)

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
                try:
                    IPv4Address(entry.ip)
                    single_entries.append(entry)
                except ValueError:
                    range_entries.append(entry)
            classified.append(_UserIPDatabaseEntry(db_path=db_path, settings=settings, single_entries=single_entries, range_entries=range_entries))
        with cls._update_userip_database_lock:
            cls.userip_databases = classified

    @staticmethod
    def _merge_single_entry_into_userip(existing: UserIP | None, entry_model: UserIPEntryModel, db_entry: _UserIPDatabaseEntry) -> UserIP:
        """Create or update a `UserIP` by merging `entry_model` into `existing`."""
        entry = entry_model.ip
        username = entry_model.username
        note = entry_model.notes.strip()
        if existing is None:
            return UserIP(
                ip=entry,
                db_path=db_entry.db_path,
                settings=db_entry.settings,
                usernames=[username],
                notes=[note] if note else [],
                sources=[entry_model.source],
                detections_count=entry_model.detections_count,
                added_at=entry_model.added_at,
                updated_at=entry_model.updated_at,
                first_seen_at=entry_model.first_seen_at,
                last_seen_at=entry_model.last_seen_at,
            )
        if username not in existing.usernames:
            existing.usernames.append(username)
        if note and note not in existing.notes:
            existing.notes.append(note)
        if entry_model.source not in existing.sources:
            existing.sources.append(entry_model.source)
        return existing._replace(
            detections_count=max(existing.detections_count, entry_model.detections_count),
            added_at=pick_earliest_iso(existing.added_at, entry_model.added_at),
            updated_at=pick_latest_iso(existing.updated_at, entry_model.updated_at),
            first_seen_at=pick_earliest_iso(existing.first_seen_at, entry_model.first_seen_at),
            last_seen_at=pick_latest_iso(existing.last_seen_at, entry_model.last_seen_at),
        )

    @classmethod
    def _process_single_ip(cls, entry_model: UserIPEntryModel, db_entry: _UserIPDatabaseEntry, build_state: _BuildState) -> None:
        """Process a single IP entry during build."""
        entry = entry_model.ip
        username = entry_model.username
        db_key = (db_entry.db_path, entry)
        merged_db_userip = cls._merge_single_entry_into_userip(build_state.single_userips_by_db.get(db_key), entry_model, db_entry)
        build_state.single_userips_by_db[db_key] = merged_db_userip

        if entry in build_state.ip_to_userip and build_state.ip_to_userip[entry].db_path != db_entry.db_path:
            existing_index = next(
                (
                    i
                    for i, conflict in enumerate(build_state.conflicts)
                    if conflict.existing_userip.ip == entry
                    and conflict.conflicting_ip == entry
                    and conflict.conflicting_database_path == db_entry.db_path
                ),
                None,
            )
            if existing_index is not None:
                existing_conflict = build_state.conflicts[existing_index]
                existing_names = split_usernames(existing_conflict.conflicting_username)
                if username not in existing_names:
                    build_state.conflicts[existing_index] = existing_conflict._replace(
                        conflicting_username=f'{existing_conflict.conflicting_username}, {username}',
                    )
            else:
                build_state.conflicts.append(
                    UserIPConflict(
                        existing_userip=build_state.ip_to_userip[entry], conflicting_database_path=db_entry.db_path, conflicting_username=username, conflicting_ip=entry,
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
            ip=range_entry.ip_range.raw,
            db_path=range_entry.db_path,
            settings=range_entry.settings,
            usernames=list(range_entry.usernames),
            notes=list(range_entry.notes),
            sources=list(range_entry.sources),
            detections_count=range_entry.detections_count,
            added_at=range_entry.added_at,
            updated_at=range_entry.updated_at,
            first_seen_at=range_entry.first_seen_at,
            last_seen_at=range_entry.last_seen_at,
        )

    @classmethod
    def _detect_range_conflicts(
        cls,
        current_databases: Sequence[_UserIPDatabaseEntry],
        build_state: _BuildState,
        range_entries: Sequence[_RangeEntry],
    ) -> set[tuple[Path, str]]:
        """Detect cross-database single-IP-vs-range and range-vs-range conflicts.

        Returns:
            The set of `(db_path, raw_range)` pairs involved in at least one conflict.
        """
        conflicting_range_keys: set[tuple[Path, str]] = set()
        if not range_entries:
            return conflicting_range_keys

        db_order = {db_entry.db_path: idx for idx, db_entry in enumerate(current_databases)}

        for single_userip in build_state.single_userips_by_db.values():
            ip = single_userip.ip
            try:
                address = IPv4Address(ip)
            except ValueError:
                continue
            for range_entry in range_entries:
                if single_userip.db_path == range_entry.db_path or address not in range_entry.ip_range:
                    continue
                if db_order.get(single_userip.db_path, 0) < db_order.get(range_entry.db_path, 0):
                    build_state.conflicts.append(
                        UserIPConflict(
                            existing_userip=single_userip,
                            conflicting_database_path=range_entry.db_path,
                            conflicting_username=', '.join(range_entry.usernames),
                            conflicting_ip=range_entry.ip_range.raw,
                        ),
                    )
                else:
                    build_state.conflicts.append(
                        UserIPConflict(
                            existing_userip=cls._range_entry_to_userip(range_entry),
                            conflicting_database_path=single_userip.db_path,
                            conflicting_username=', '.join(single_userip.usernames),
                            conflicting_ip=ip,
                        ),
                    )
                build_state.conflicting_ips.add(ip)
                conflicting_range_keys.add((range_entry.db_path, range_entry.ip_range.raw))

        for index, range_a in enumerate(range_entries):
            for range_b in range_entries[index + 1 :]:
                if range_a.db_path == range_b.db_path or not range_a.ip_range.overlaps(range_b.ip_range):
                    continue
                build_state.conflicts.append(
                    UserIPConflict(
                        existing_userip=cls._range_entry_to_userip(range_a),
                        conflicting_database_path=range_b.db_path,
                        conflicting_username=', '.join(range_b.usernames),
                        conflicting_ip=range_b.ip_range.raw,
                    ),
                )
                conflicting_range_keys.add((range_a.db_path, range_a.ip_range.raw))
                conflicting_range_keys.add((range_b.db_path, range_b.ip_range.raw))

        return conflicting_range_keys

    @staticmethod
    def _process_range_entry(entry_model: UserIPEntryModel, db_path: Path, settings: UserIPSettings, range_entries: list[_RangeEntry]) -> None:
        """Process a range entry (CIDR, start-end, wildcard) during build."""
        entry = entry_model.ip
        username = entry_model.username
        note = entry_model.notes.strip()

        try:
            ip_range = parse_ip_range(entry)
        except ValueError:
            logger.warning('Skipping unparseable UserIP range entry: %r', entry)
            return

        existing_index = next(
            (i for i, re in enumerate(range_entries) if re.ip_range.raw == entry and re.db_path == db_path),
            None,
        )
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
            range_entries.append(
                _RangeEntry(
                    ip_range=ip_range,
                    db_path=db_path,
                    settings=settings,
                    usernames=[username],
                    notes=[note] if note else [],
                    sources=[entry_model.source],
                    detections_count=entry_model.detections_count,
                    added_at=entry_model.added_at,
                    updated_at=entry_model.updated_at,
                    first_seen_at=entry_model.first_seen_at,
                    last_seen_at=entry_model.last_seen_at,
                ),
            )

    @staticmethod
    def _resolve_from_built_structures(
        ip: str,
        ip_to_userip: dict[str, UserIP],
        range_entries: list[_RangeEntry],
        conflicting_ips: set[str],
        conflicting_ranges: Sequence[IPRange] = (),
    ) -> UserIP | None:
        """Resolve a UserIP object by combining single-IP and covering range entries."""
        if ip in conflicting_ips:
            return None

        single_userip = ip_to_userip.get(ip)
        matching_ranges: list[_RangeEntry] = []
        if range_entries or conflicting_ranges:
            try:
                address = IPv4Address(ip)
            except ValueError:
                address = None
            if address is not None:
                if any(address in ip_range for ip_range in conflicting_ranges):
                    return None
                matching_ranges = [entry for entry in range_entries if address in entry.ip_range]

        if single_userip is None and not matching_ranges:
            return None

        primary_db_path = single_userip.db_path if single_userip is not None else matching_ranges[0].db_path
        primary_settings = single_userip.settings if single_userip is not None else matching_ranges[0].settings

        combined_usernames: list[str] = []
        combined_notes: list[str] = []
        combined_sources: list[EntrySource] = []
        detections_count = 0
        added_at: str | None = None
        updated_at: str | None = None
        first_seen_at: str | None = None
        last_seen_at: str | None = None

        if single_userip is not None:
            combined_usernames.extend(single_userip.usernames)
            combined_notes.extend(single_userip.notes)
            combined_sources.extend(single_userip.sources)
            detections_count = max(detections_count, single_userip.detections_count)
            added_at = pick_earliest_iso(added_at, single_userip.added_at)
            updated_at = pick_latest_iso(updated_at, single_userip.updated_at)
            first_seen_at = pick_earliest_iso(first_seen_at, single_userip.first_seen_at)
            last_seen_at = pick_latest_iso(last_seen_at, single_userip.last_seen_at)

        for range_entry in matching_ranges:
            combined_usernames.extend(range_entry.usernames)
            combined_notes.extend(range_entry.notes)
            combined_sources.extend(range_entry.sources)
            detections_count = max(detections_count, range_entry.detections_count)
            added_at = pick_earliest_iso(added_at, range_entry.added_at)
            updated_at = pick_latest_iso(updated_at, range_entry.updated_at)
            first_seen_at = pick_earliest_iso(first_seen_at, range_entry.first_seen_at)
            last_seen_at = pick_latest_iso(last_seen_at, range_entry.last_seen_at)

        return UserIP(
            ip=ip,
            db_path=primary_db_path,
            settings=primary_settings,
            usernames=dedup_preserve_order(combined_usernames),
            notes=dedup_preserve_order(combined_notes),
            sources=dedup_preserve_order(combined_sources),
            detections_count=detections_count,
            added_at=added_at,
            updated_at=updated_at,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
        )

    @staticmethod
    def _build_username_meta(
        current_databases: list[_UserIPDatabaseEntry],
        ambiguous_usernames: set[str],
        canonical_names: dict[str, str],
        known_alts_clusters: dict[str, list[str]],
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
                        db_path=db_entry.db_path,
                        settings=db_entry.settings,
                        canonical_name=canonical,
                        notes=[note] if note else [],
                        sources=[entry_model.source],
                        detections_count=entry_model.detections_count,
                        added_at=entry_model.added_at,
                        updated_at=entry_model.updated_at,
                        first_seen_at=entry_model.first_seen_at,
                        last_seen_at=entry_model.last_seen_at,
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
            if cf in username_to_meta:
                meta = username_to_meta[cf]
                for alt_name in cluster:
                    alt_cf = alt_name.casefold()
                    if alt_cf not in ambiguous_usernames and alt_cf not in username_to_meta:
                        username_to_meta[alt_cf] = meta._replace(
                            canonical_name=alt_name,
                            notes=list(meta.notes),
                            sources=list(meta.sources),
                        )
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
                cls._process_range_entry(range_entry, db_entry.db_path, db_entry.settings, range_entries)

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
                    if (db_entry.db_path, range_entry.ip) in conflicting_range_keys:
                        conflicting_ip_usernames.add(cf)
        ambiguous_usernames: set[str] = {cf for cf, paths in username_databases.items() if len(paths) > 1} | conflicting_ip_usernames

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
                if cf not in ambiguous_usernames and cf not in unique_cfs:
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
            prev_userip = player.userip
            new_userip = cls._resolve_from_built_structures(player.ip, ip_to_userip, range_entries, conflicting_ips, conflicting_ranges)
            player.userip = new_userip
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

        include_looky_for_snapshots = Settings.looky_enabled and Settings.is_gta5_feature_set()
        for snapshot_player in SessionTracker.get_all_snapshot_players():
            snapshot_player.userip = cls._resolve_from_built_structures(snapshot_player.ip, ip_to_userip, range_entries, conflicting_ips, conflicting_ranges)
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
        if not cls._conflicting_ranges:
            return False
        try:
            address = IPv4Address(ip)
        except ValueError:
            return False
        return any(address in ip_range for ip_range in cls._conflicting_ranges)

    @classmethod
    def is_conflicting_entry(cls, entry: str) -> bool:
        """Return whether a single-IP or range entry string is currently involved in a conflict."""
        try:
            IPv4Address(entry)
        except ValueError:
            try:
                ip_range = parse_ip_range(entry)
            except ValueError:
                return False
            for conflict_ip in cls._conflicting_ips:
                try:
                    if IPv4Address(conflict_ip) in ip_range:
                        return True
                except ValueError:
                    continue
            return any(ip_range.overlaps(conflict_range) for conflict_range in cls._conflicting_ranges)
        return cls.is_conflicting_ip(entry)

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
        if cls.is_conflicting_ip(ip):
            return False
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
    def resolve_userip(cls, ip: str) -> UserIP | None:
        """Look up a single IP against the already-built structures without triggering a rebuild."""
        return cls._resolve_from_built_structures(ip, cls._ip_to_userip, cls._range_entries, cls._conflicting_ips, cls._conflicting_ranges)

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
                ip=player_ip,
                db_path=meta.db_path,
                settings=meta.settings,
                usernames=usernames,
                notes=list(meta.notes),
                sources=list(meta.sources),
                detections_count=meta.detections_count,
                added_at=meta.added_at,
                updated_at=meta.updated_at,
                first_seen_at=meta.first_seen_at,
                last_seen_at=meta.last_seen_at,
            ),
            meta.canonical_name,
        )

    @classmethod
    def resolve_userip_by_usernames(cls, usernames: Sequence[str], player_ip: str) -> tuple[UserIP, str] | None:
        """Resolve a UserIP snapshot and matched username from a sequence of candidate usernames.

        Returns the first matching database resolution, or None if none match or if candidate
        usernames resolve to multiple different databases.
        """
        first_match: tuple[UserIP, str] | None = None
        matched_db_path: Path | None = None
        for username in usernames:
            resolved = cls.resolve_userip_by_username(username, player_ip)
            if resolved is not None:
                if first_match is None:
                    first_match = resolved
                    matched_db_path = resolved[0].db_path
                elif resolved[0].db_path != matched_db_path:
                    return None
        return first_match

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
