"""UserIP Conflict Resolver dialog for reviewing and fixing IPs or ranges claimed by multiple UserIP databases."""

import html
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, override

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QSignalBlocker, Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStyleOptionViewItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.select_usernames_dialog import configure_username_cell_editor
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.table_column_resizing import setup_table_header_context_menu
from session_sniffer.guis.userip_manager_helpers import (
    IPRangeBuilderDialog,
    dedup_userip_entries,
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    rewrite_db_edit_entry_ip,
    save_userip_database_model,
)
from session_sniffer.guis.utils import ActiveDialogRegistry, find_main_window, scale_by_ui, set_dialog_window_flags
from session_sniffer.models.userip_settings_model import (
    UserIPEntryModel,
    format_iso_timestamp_display,
    get_current_iso_timestamp,
    pick_earliest_iso,
    pick_latest_iso,
)
from session_sniffer.networking.ip_range import entry_ip_covers_ip, parse_ip_range
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_loader import enrich_userip_entry_from_logs, find_userip_insert_index
from session_sniffer.text_utils import pluralize, split_usernames

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.player.userip import UserIPConflict

_REFRESH_INTERVAL_MS = 1000
_SIDE_ROLE = Qt.ItemDataRole.UserRole
_DATABASE_COLUMN = 0
_IP_RANGE_COLUMN = 1
_USERNAMES_COLUMN = 2
_NOTES_COLUMN = 3
_SOURCE_COLUMN = 4
_DETECTIONS_COLUMN = 5
_ADDED_COLUMN = 6
_UPDATED_COLUMN = 7
_FIRST_SEEN_COLUMN = 8
_LAST_SEEN_COLUMN = 9
_NO_USERNAME_TEXT = '(no username)'

_CONFLICT_TABLE_HEADERS: list[str] = [
    'Database',
    'IP / Range',
    'Usernames',
    'Notes',
    'Source',
    'Detections',
    'Added',
    'Updated',
    'First Seen',
    'Last Seen',
]

_CONFLICT_HEADER_TOOLTIPS: dict[str, str] = {
    'Database': 'The UserIP database file that claims this IP or range.',
    'IP / Range': 'The IPv4 address, range, or CIDR subnet claimed by this entry (double-click to edit).',
    'Usernames': (
        'The username(s) associated with this entry (double-click to edit).\n'
        'Purple entries with a Looky icon were automatically added or confirmed via Looky System.'
    ),
    'Notes': 'Optional user notes or comments attached to this entry (double-click to edit).',
    'Source': 'How this entry was added to the database (e.g., Manual, Looky, Session, or Import).',
    'Detections': 'The number of times this entry has been matched across sessions.',
    'Added': 'The date and time when this entry was first added to the database.',
    'Updated': 'The date and time when this entry was last modified.',
    'First Seen': 'The very first time a player matching this entry was observed in a session.',
    'Last Seen': 'The most recent time a player matching this entry was active in a session.',
}

_DEFAULT_CONFLICT_COLUMN_WIDTHS: dict[int, int] = {
    _DATABASE_COLUMN: 170,
    _IP_RANGE_COLUMN: 155,
    _USERNAMES_COLUMN: 200,
    _NOTES_COLUMN: 160,
    _SOURCE_COLUMN: 85,
    _DETECTIONS_COLUMN: 85,
    _ADDED_COLUMN: 145,
    _UPDATED_COLUMN: 145,
    _FIRST_SEEN_COLUMN: 145,
    _LAST_SEEN_COLUMN: 145,
}


class _ConflictSide(NamedTuple):
    """One IP or range entry string in a specific UserIP database that takes part in a conflict."""

    db_path: Path
    entry: str


class _ConflictGroup(NamedTuple):
    """A connected set of conflicting entries."""

    sides: list[_ConflictSide]


@dataclass(slots=True)
class _SideDetails:
    """Aggregated usernames, notes, Looky state, and timestamps for a `_ConflictSide`."""

    usernames: list[str]
    looky_usernames: set[str]
    notes: list[str]
    sources: list[str]
    detections_count: int = 0
    added_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None


class _ConflictTreeDelegate(SearchHighlightDelegate):
    """Item delegate for the conflict tree supporting Looky username styling and inline editing."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent, lambda: '')

    @override
    def createEditor(
        self,
        parent: QWidget,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> QWidget:
        editor = super().createEditor(parent, option, index)
        configure_username_cell_editor(editor, index, username_column=_USERNAMES_COLUMN)
        return editor

    @override
    def setEditorData(self, editor: QWidget, index: QModelIndex | QPersistentModelIndex) -> None:
        if (
            index.column() == _USERNAMES_COLUMN
            and isinstance(editor, QLineEdit)
            and index.data(Qt.ItemDataRole.DisplayRole) == _NO_USERNAME_TEXT
        ):
            editor.setText('')
            return
        super().setEditorData(editor, index)


def _build_conflict_groups(conflicts: Sequence[UserIPConflict]) -> list[_ConflictGroup]:
    """Group conflicts into connected sets of entries so each set can be resolved together."""
    parents: dict[_ConflictSide, _ConflictSide] = {}

    def _find(side: _ConflictSide) -> _ConflictSide:
        while parents[side] != side:
            parents[side] = parents[parents[side]]
            side = parents[side]
        return side

    for conflict in conflicts:
        side_a = _ConflictSide(conflict.existing_userip.db_path, conflict.existing_userip.ip)
        side_b = _ConflictSide(conflict.conflicting_database_path, conflict.conflicting_ip)
        for side in (side_a, side_b):
            parents.setdefault(side, side)
        root_a, root_b = _find(side_a), _find(side_b)
        if root_a != root_b:
            parents[root_b] = root_a

    sides_by_root: dict[_ConflictSide, list[_ConflictSide]] = {}
    for side in parents:
        sides_by_root.setdefault(_find(side), []).append(side)
    return [_ConflictGroup(sides=sides) for sides in sides_by_root.values()]


def _find_sides_conflicting_with(group: _ConflictGroup, kept_side: _ConflictSide) -> list[_ConflictSide]:
    """Return every entry from another database in `group` whose IP or range overlaps `kept_side`.

    Conflicts are only reported against the first claiming database, so the same IP in three databases yields
    two pairs; using overlap instead of reported pairs ensures keeping an entry resolves all of its conflicts at once.
    """
    kept_range = parse_ip_range(kept_side.entry)
    return [side for side in group.sides if side.db_path != kept_side.db_path and parse_ip_range(side.entry).overlaps(kept_range)]


def _format_database_name(db_path: Path) -> str:
    """Return the database path relative to the UserIP databases directory, without extension."""
    return str(db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))


def _aggregate_side_entries(entries: Sequence[UserIPEntryModel], target_entry: str) -> _SideDetails:
    """Aggregate all `UserIPEntryModel` records matching `target_entry` into a `_SideDetails` snapshot."""
    usernames: list[str] = []
    looky_usernames: set[str] = set()
    notes: list[str] = []
    sources: list[str] = []
    detections_count = 0
    added_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None

    for entry in entries:
        if entry.ip.strip() != target_entry:
            continue
        if entry.username not in usernames:
            usernames.append(entry.username)
        if entry.is_looky:
            looky_usernames.add(entry.username)
        cleaned_note = entry.notes.strip()
        if cleaned_note and cleaned_note not in notes:
            notes.append(cleaned_note)
        if entry.source not in sources:
            sources.append(entry.source)
        detections_count = max(detections_count, entry.detections_count)
        added_at = pick_earliest_iso(added_at, entry.added_at)
        updated_at = pick_latest_iso(updated_at, entry.updated_at)
        first_seen_at = pick_earliest_iso(first_seen_at, entry.first_seen_at)
        last_seen_at = pick_latest_iso(last_seen_at, entry.last_seen_at)

    return _SideDetails(
        usernames=usernames,
        looky_usernames=looky_usernames,
        notes=notes,
        sources=sources,
        detections_count=detections_count,
        added_at=added_at,
        updated_at=updated_at,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
    )


def _collect_side_details(sides: Sequence[_ConflictSide]) -> dict[_ConflictSide, _SideDetails]:
    """Read the aggregated entry metadata currently stored on disk for each conflicting side."""
    entries_by_db: dict[Path, list[UserIPEntryModel]] = {}
    details_by_side: dict[_ConflictSide, _SideDetails] = {}
    for side in sides:
        if side.db_path not in entries_by_db:
            entries_by_db[side.db_path] = load_userip_database_model(side.db_path).entries
        details_by_side[side] = _aggregate_side_entries(entries_by_db[side.db_path], side.entry)
    return details_by_side


def _rewrite_side_usernames(side: _ConflictSide, new_usernames: Sequence[str]) -> _SideDetails | None:
    """Update the username(s) for `side` in its UserIP database file on disk and return updated `_SideDetails`."""
    if not side.db_path.is_file() or not new_usernames:
        return None
    db_model = load_userip_database_model(side.db_path)
    matching_indices = [i for i, entry in enumerate(db_model.entries) if entry.ip.strip() == side.entry]
    if not matching_indices:
        return None

    old_entries = [db_model.entries[i] for i in matching_indices]
    existing_by_cf: dict[str, UserIPEntryModel] = {}
    for entry in old_entries:
        existing_by_cf.setdefault(entry.username.casefold(), entry)

    new_cf_set = {name.casefold() for name in new_usernames}
    reusable_old = [entry for entry in old_entries if entry.username.casefold() not in new_cf_set]
    now_iso = get_current_iso_timestamp()

    replacement_entries: list[UserIPEntryModel] = []
    for name in new_usernames:
        kept = existing_by_cf.get(name.casefold())
        if kept is not None:
            if kept.username == name:
                replacement_entries.append(kept)
            else:
                new_source = 'Manual' if kept.source == 'Looky' else kept.source
                updated = kept.model_copy(update={'username': name, 'is_looky': False, 'source': new_source, 'updated_at': now_iso})
                replacement_entries.append(enrich_userip_entry_from_logs(updated)[0])
        elif reusable_old:
            reused = reusable_old.pop(0)
            new_source = 'Manual' if reused.source == 'Looky' else reused.source
            updated = reused.model_copy(update={'username': name, 'is_looky': False, 'source': new_source, 'updated_at': now_iso})
            replacement_entries.append(enrich_userip_entry_from_logs(updated)[0])
        else:
            replacement_entries.append(enrich_userip_entry_from_logs(UserIPEntryModel(username=name, ip=side.entry))[0])

    updated_entries: list[UserIPEntryModel] = []
    last_match_index = matching_indices[-1]
    matching_index_set = set(matching_indices)
    rep_iter = iter(replacement_entries)

    for i, entry in enumerate(db_model.entries):
        if i in matching_index_set:
            if (next_rep := next(rep_iter, None)) is not None:
                updated_entries.append(next_rep)
            if i == last_match_index:
                updated_entries.extend(rep_iter)
        else:
            updated_entries.append(entry)

    db_model.entries = dedup_userip_entries(updated_entries)
    save_userip_database_model(side.db_path, db_model)
    return _aggregate_side_entries(db_model.entries, side.entry)


def _rewrite_side_notes(side: _ConflictSide, new_note: str) -> _SideDetails | None:
    """Update the `notes` field for all entries of `side` in its UserIP database file on disk."""
    if not side.db_path.is_file():
        return None
    db_model = load_userip_database_model(side.db_path)
    cleaned_note = new_note.strip()
    matched = False
    modified = False
    now_iso = get_current_iso_timestamp()

    for i, entry in enumerate(db_model.entries):
        if entry.ip.strip() == side.entry:
            matched = True
            if entry.notes != cleaned_note:
                db_model.entries[i] = entry.model_copy(update={'notes': cleaned_note, 'updated_at': now_iso})
                modified = True

    if not matched:
        return None
    if modified:
        save_userip_database_model(side.db_path, db_model)
    return _aggregate_side_entries(db_model.entries, side.entry)


def _merge_and_delete_sides(kept_side: _ConflictSide, sides_to_delete: Sequence[_ConflictSide]) -> None:
    """Merge usernames, notes, and metadata from `sides_to_delete` into `kept_side`, then delete `sides_to_delete`."""
    entries_to_delete_by_db: dict[Path, set[str]] = {}
    for side in sides_to_delete:
        entries_to_delete_by_db.setdefault(side.db_path, set()).add(side.entry)

    incoming_entries: list[UserIPEntryModel] = []
    for db_path, entries_to_delete in entries_to_delete_by_db.items():
        if not db_path.is_file():
            continue
        db_model = load_userip_database_model(db_path)
        incoming_entries.extend(
            entry.model_copy(update={'ip': kept_side.entry})
            for entry in db_model.entries
            if entry.ip.strip() in entries_to_delete
        )

    if incoming_entries and kept_side.db_path.is_file():
        kept_db_model = load_userip_database_model(kept_side.db_path)
        existing_index_by_cf: dict[str, int] = {
            entry.username.casefold(): idx
            for idx, entry in enumerate(kept_db_model.entries)
            if entry.ip.strip() == kept_side.entry
        }
        anchor_username = next(
            (entry.username for entry in reversed(kept_db_model.entries) if entry.ip.strip() == kept_side.entry),
            '',
        )
        modified = False
        for incoming in incoming_entries:
            cf_name = incoming.username.casefold()
            existing_idx = existing_index_by_cf.get(cf_name)
            if existing_idx is not None:
                merged = kept_db_model.entries[existing_idx].merge_duplicate(incoming)
                if merged != kept_db_model.entries[existing_idx]:
                    kept_db_model.entries[existing_idx] = merged
                    modified = True
            else:
                insert_idx = find_userip_insert_index(
                    kept_db_model.entries,
                    incoming.username,
                    kept_side.entry,
                    anchor_username=anchor_username,
                )
                enriched, _ = enrich_userip_entry_from_logs(incoming)
                kept_db_model.entries.insert(insert_idx, enriched)
                anchor_username = enriched.username
                existing_index_by_cf = {
                    entry.username.casefold(): idx
                    for idx, entry in enumerate(kept_db_model.entries)
                    if entry.ip.strip() == kept_side.entry
                }
                modified = True

        if modified:
            kept_db_model.entries = dedup_userip_entries(kept_db_model.entries)
            save_userip_database_model(kept_side.db_path, kept_db_model)

    _delete_sides(sides_to_delete)


def _delete_sides(sides: Sequence[_ConflictSide]) -> None:
    """Delete every entry of the given IP or range strings from their UserIP databases, then rebuild."""
    entries_to_delete_by_db: dict[Path, set[str]] = {}
    for side in sides:
        entries_to_delete_by_db.setdefault(side.db_path, set()).add(side.entry)

    for db_path, entries_to_delete in entries_to_delete_by_db.items():
        if not db_path.is_file():
            continue
        db_model = load_userip_database_model(db_path)
        kept_entries = [entry for entry in db_model.entries if entry.ip.strip() not in entries_to_delete]
        if len(kept_entries) != len(db_model.entries):
            db_model.entries = kept_entries
            save_userip_database_model(db_path, db_model)

    refresh_userip_and_wake_renderer()


def _format_side_html(side: _ConflictSide, usernames: Sequence[str]) -> str:
    """Return an HTML list item describing one conflicting entry."""
    usernames_text = ', '.join(usernames) if usernames else _NO_USERNAME_TEXT
    return f'<li>"{html.escape(_format_database_name(side.db_path))}": {html.escape(usernames_text)} = {html.escape(side.entry)}</li>'


class UserIPConflictResolverDialog(QDialog):
    """Non-modal window listing UserIP conflicts and letting the user keep, edit, or delete the conflicting entries."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the UserIP Conflict Resolver dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'UserIP Conflict Resolver - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(780), scale_by_ui(420))

        self._groups: list[_ConflictGroup] = []
        self._side_rows: list[tuple[_ConflictGroup, _ConflictSide]] = []
        self._details_by_side: dict[_ConflictSide, _SideDetails] = {}
        self._pending_focus_entry: str | None = None
        self._last_build_version = -1
        self._looky_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg'))

        layout = QVBoxLayout(self)

        self._summary_label = QLabel()
        self._summary_label.setWordWrap(True)
        layout.addWidget(self._summary_label)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(len(_CONFLICT_TABLE_HEADERS))
        self._tree.setHeaderLabels(_CONFLICT_TABLE_HEADERS)
        if header_item := self._tree.headerItem():
            for col, label in enumerate(_CONFLICT_TABLE_HEADERS):
                if (tooltip := _CONFLICT_HEADER_TOOLTIPS.get(label)) is not None:
                    header_item.setToolTip(col, tooltip)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setItemDelegate(_ConflictTreeDelegate(self._tree))
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.setWordWrap(False)
        self._tree.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._reset_column_sizes()
        setup_table_header_context_menu(self._tree, on_reset=self._reset_column_sizes)
        self._tree.itemSelectionChanged.connect(self._update_buttons)
        self._tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        self._tree.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._tree, stretch=1)

        buttons_layout = QHBoxLayout()

        self._keep_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'check.svg')), ' Keep This Entry…')
        self._keep_button.setAutoDefault(False)
        self._keep_button.setToolTip('Keep the selected entry and delete the entries that conflict with it (you will be asked to confirm)')
        self._keep_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._keep_button.clicked.connect(self._keep_selected)
        buttons_layout.addWidget(self._keep_button)

        self._keep_merge_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-round-check.svg')), ' Keep && Merge…')
        self._keep_merge_button.setAutoDefault(False)
        self._keep_merge_button.setToolTip(
            'Keep the selected entry, merge usernames, notes, and metadata from the conflicting entries into it, '
            'and delete the conflicting entries (you will be asked to confirm)',
        )
        self._keep_merge_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._keep_merge_button.clicked.connect(self._keep_and_merge_selected)
        buttons_layout.addWidget(self._keep_merge_button)

        self._edit_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')), ' Edit Entry…')
        self._edit_button.setAutoDefault(False)
        self._edit_button.setToolTip('Change the IP or range of the selected entry using the builder')
        self._edit_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._edit_button.clicked.connect(self._edit_selected)
        buttons_layout.addWidget(self._edit_button)

        self._delete_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete This Entry…')
        self._delete_button.setAutoDefault(False)
        self._delete_button.setToolTip('Delete only the selected entry from its database (you will be asked to confirm)')
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.clicked.connect(self._delete_selected)
        buttons_layout.addWidget(self._delete_button)

        buttons_layout.addStretch()

        close_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'x.svg')), ' Close')
        close_button.setAutoDefault(False)
        close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_button.clicked.connect(self.close)
        buttons_layout.addWidget(close_button)

        layout.addLayout(buttons_layout)

        # Follow rebuilds triggered elsewhere (UserIP Manager edits, external file changes, ...)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(_REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self._refresh_if_rebuilt)
        self._refresh_timer.start()

        self.resize(scale_by_ui(1120), scale_by_ui(520))
        self._refresh()

    def _reset_column_sizes(self) -> None:
        header = self._tree.header()
        if not header:
            return
        header.setStretchLastSection(True)
        for col, width in _DEFAULT_CONFLICT_COLUMN_WIDTHS.items():
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            self._tree.setColumnWidth(col, scale_by_ui(width))

    def _populate_side_item(self, item: QTreeWidgetItem, side: _ConflictSide, details: _SideDetails) -> None:
        item.setText(_DATABASE_COLUMN, _format_database_name(side.db_path))
        item.setText(_IP_RANGE_COLUMN, side.entry)
        item.setText(_USERNAMES_COLUMN, ', '.join(details.usernames) or _NO_USERNAME_TEXT)
        if details.looky_usernames:
            item.setIcon(_USERNAMES_COLUMN, self._looky_icon)
            item.setData(_USERNAMES_COLUMN, Qt.ItemDataRole.UserRole, set(details.looky_usernames))
        else:
            item.setIcon(_USERNAMES_COLUMN, QIcon())
            item.setData(_USERNAMES_COLUMN, Qt.ItemDataRole.UserRole, None)
        item.setText(_NOTES_COLUMN, ', '.join(details.notes))
        item.setText(_SOURCE_COLUMN, ', '.join(details.sources))
        item.setText(_DETECTIONS_COLUMN, str(details.detections_count))
        for col, raw_iso in (
            (_ADDED_COLUMN, details.added_at),
            (_UPDATED_COLUMN, details.updated_at),
            (_FIRST_SEEN_COLUMN, details.first_seen_at),
            (_LAST_SEEN_COLUMN, details.last_seen_at),
        ):
            item.setText(col, format_iso_timestamp_display(raw_iso))
            item.setToolTip(col, raw_iso or '')

    def focus_on_entry(self, entry: str | None) -> None:
        """Select the first conflicting entry covering `entry` (an IP or range), if any."""
        self._pending_focus_entry = entry
        self._refresh()

    def _refresh_if_rebuilt(self) -> None:
        if (
            UserIPDatabases.build_version != self._last_build_version
            and self._tree.state() != QAbstractItemView.State.EditingState
        ):
            self._refresh()

    def _selected_side(self) -> tuple[_ConflictGroup, _ConflictSide] | None:
        selected_items = self._tree.selectedItems()
        if not selected_items:
            return None
        side_row = selected_items[0].data(0, _SIDE_ROLE)
        if not isinstance(side_row, int) or not 0 <= side_row < len(self._side_rows):
            return None
        return self._side_rows[side_row]

    def _refresh(self) -> None:
        """Rebuild the conflict list from the latest UserIP build, preserving or applying the selection."""
        self._last_build_version = UserIPDatabases.build_version
        previous_selection = self._selected_side()
        previous_side = previous_selection[1] if previous_selection is not None else None

        conflicts = UserIPDatabases.get_conflicts()
        self._groups = _build_conflict_groups(conflicts)
        self._side_rows = [(group, side) for group in self._groups for side in group.sides]
        self._details_by_side = _collect_side_details([side for group in self._groups for side in group.sides])

        item_to_select: QTreeWidgetItem | None = None
        focus_entry = self._pending_focus_entry
        self._pending_focus_entry = None

        with QSignalBlocker(self._tree):
            self._tree.clear()
            for group_index, group in enumerate(self._groups, start=1):
                group_entries = list(dict.fromkeys(side.entry for side in group.sides))
                group_item = QTreeWidgetItem([f'Conflict {group_index}: {" vs ".join(group_entries)}'])
                font = group_item.font(0)
                font.setBold(True)
                group_item.setFont(0, font)
                self._tree.addTopLevelItem(group_item)
                group_item.setFirstColumnSpanned(True)

                for side in group.sides:
                    details = self._details_by_side.get(
                        side,
                        _SideDetails(usernames=[], looky_usernames=set(), notes=[], sources=[]),
                    )
                    side_item = QTreeWidgetItem()
                    self._populate_side_item(side_item, side, details)
                    side_item.setFlags(side_item.flags() | Qt.ItemFlag.ItemIsEditable)
                    side_item.setData(0, _SIDE_ROLE, self._side_rows.index((group, side)))
                    group_item.addChild(side_item)
                    if item_to_select is None and (
                        (focus_entry is not None and entry_ip_covers_ip(side.entry, focus_entry))
                        or (focus_entry is None and side == previous_side)
                    ):
                        item_to_select = side_item

            self._tree.expandAll()

        if item_to_select is not None:
            self._tree.setCurrentItem(item_to_select)
            self._tree.scrollToItem(item_to_select)

        conflict_group_count = len(self._groups)
        if conflict_group_count:
            conflict_pair_count = len(conflicts)
            self._summary_label.setText(
                f'{conflict_group_count} UserIP conflict group{pluralize(conflict_group_count)} '
                f'({conflict_pair_count} conflicting pair{pluralize(conflict_pair_count)}) found. '
                'An IP or range claimed by several databases is ignored until only one database claims it.\n'
                'Select an entry, then keep it (or keep & merge), edit its IP or range, or delete it.',
            )
        else:
            self._summary_label.setText('No UserIP conflicts. Every IP and range belongs to a single database.')
        self._update_buttons()

    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        if item.data(0, _SIDE_ROLE) is None:
            return
        if column in (_USERNAMES_COLUMN, _NOTES_COLUMN):
            self._tree.editItem(item, column)
        elif column == _IP_RANGE_COLUMN:
            self._tree.setCurrentItem(item)
            self._edit_selected()

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if column not in (_USERNAMES_COLUMN, _NOTES_COLUMN):
            return
        side_row = item.data(0, _SIDE_ROLE)
        if not isinstance(side_row, int) or not 0 <= side_row < len(self._side_rows):
            return
        _, side = self._side_rows[side_row]
        details = self._details_by_side.get(
            side,
            _SideDetails(usernames=[], looky_usernames=set(), notes=[], sources=[]),
        )

        if column == _USERNAMES_COLUMN:
            seen_cf: set[str] = set()
            new_usernames: list[str] = []
            for raw_name in split_usernames(item.text(_USERNAMES_COLUMN)):
                if (cleaned := raw_name.strip()) and (folded := cleaned.casefold()) not in seen_cf:
                    seen_cf.add(folded)
                    new_usernames.append(cleaned)

            if not new_usernames or new_usernames == details.usernames:
                with QSignalBlocker(self._tree):
                    self._populate_side_item(item, side, details)
                return

            updated_details = _rewrite_side_usernames(side, new_usernames)
        else:
            new_note = item.text(_NOTES_COLUMN).strip()
            if new_note == ', '.join(details.notes):
                with QSignalBlocker(self._tree):
                    self._populate_side_item(item, side, details)
                return
            updated_details = _rewrite_side_notes(side, new_note)

        if updated_details is None:
            QMessageBox.warning(self, TITLE, 'The selected entry no longer exists in its database, nothing was changed.')
            QTimer.singleShot(0, self._refresh)
            return

        self._details_by_side[side] = updated_details
        with QSignalBlocker(self._tree):
            self._populate_side_item(item, side, updated_details)
        refresh_userip_and_wake_renderer()
        self._last_build_version = UserIPDatabases.build_version

    def _update_buttons(self) -> None:
        has_side = self._selected_side() is not None
        self._keep_button.setEnabled(has_side)
        self._keep_merge_button.setEnabled(has_side)
        self._edit_button.setEnabled(has_side)
        self._delete_button.setEnabled(has_side)

    def _confirm_deletion(self, header: str, sides: Sequence[_ConflictSide]) -> bool:
        items_html = ''.join(
            _format_side_html(side, self._details_by_side[side].usernames if side in self._details_by_side else [])
            for side in sides
        )
        message_box = QMessageBox(QMessageBox.Icon.Warning, TITLE, f'{header}<ul>{items_html}</ul>Continue?', parent=self)
        message_box.setTextFormat(Qt.TextFormat.RichText)
        message_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        message_box.setDefaultButton(QMessageBox.StandardButton.No)
        return message_box.exec() == QMessageBox.StandardButton.Yes

    def _keep_selected(self) -> None:
        selection = self._selected_side()
        if selection is None:
            return
        group, kept_side = selection
        sides_to_delete = _find_sides_conflicting_with(group, kept_side)
        if not sides_to_delete:
            return
        kept_html = html.escape(f'{kept_side.entry} in "{_format_database_name(kept_side.db_path)}"')
        entry_word = pluralize(len(sides_to_delete), 'entry', 'entries')
        if not self._confirm_deletion(f'Keep <b>{kept_html}</b> and delete the following conflicting {entry_word}?', sides_to_delete):
            return
        _delete_sides(sides_to_delete)
        self._refresh()

    def _keep_and_merge_selected(self) -> None:
        selection = self._selected_side()
        if selection is None:
            return
        group, kept_side = selection
        sides_to_delete = _find_sides_conflicting_with(group, kept_side)
        if not sides_to_delete:
            return
        kept_html = html.escape(f'{kept_side.entry} in "{_format_database_name(kept_side.db_path)}"')
        entry_word = pluralize(len(sides_to_delete), 'entry', 'entries')
        prompt = f'Keep <b>{kept_html}</b>, merge usernames and metadata from the following conflicting {entry_word} into it, and delete the conflicting {entry_word}?'
        if not self._confirm_deletion(prompt, sides_to_delete):
            return
        _merge_and_delete_sides(kept_side, sides_to_delete)
        self._refresh()

    def _edit_selected(self) -> None:
        selection = self._selected_side()
        if selection is None:
            return
        _, side = selection
        dialog = IPRangeBuilderDialog(self, initial_entry=side.entry)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        new_entry = dialog.result_entry()
        if not new_entry or new_entry == side.entry:
            return
        if not rewrite_db_edit_entry_ip(side.db_path, side.entry, new_entry):
            QMessageBox.warning(self, TITLE, 'The selected entry no longer exists in its database, nothing was changed.')
            self._refresh()
            return
        refresh_userip_and_wake_renderer()
        self._refresh()

    def _delete_selected(self) -> None:
        selection = self._selected_side()
        if selection is None:
            return
        _, side = selection
        if not self._confirm_deletion('Delete the following entry?', [side]):
            return
        _delete_sides([side])
        self._refresh()


_active_resolver_dialogs: ActiveDialogRegistry[str, UserIPConflictResolverDialog] = ActiveDialogRegistry()


def open_userip_conflict_resolver(focus_entry: str | None = None) -> None:
    """Open (or focus) the UserIP Conflict Resolver, optionally selecting the conflict covering `focus_entry`."""
    dialog = _active_resolver_dialogs.show_or_focus('userip_conflict_resolver', lambda: UserIPConflictResolverDialog(find_main_window()))
    if focus_entry is not None:
        dialog.focus_on_entry(focus_entry)
