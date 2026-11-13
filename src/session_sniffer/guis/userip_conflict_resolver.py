"""UserIP Conflict Resolver dialog for reviewing and fixing conflicting IPs/ranges and split account groups."""

import html
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from PySide6.QtCore import QPoint, QSignalBlocker, Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._userip_split_groups_tab import (
    NO_USERNAME_TEXT,
    NOTES_COLUMN,
    SIDE_ROLE,
    USERNAMES_COLUMN,
    ResolverTreeCallbacks,
    SideDetails,
    SplitGroupsResolverTab,
    add_resolver_group_header,
    aggregate_matching_entries,
    create_configured_resolver_tree,
    create_resolver_tail_buttons,
    finish_resolver_tree_refresh,
    parse_deduped_usernames_cell,
    populate_resolver_common_menu_prefix,
    populate_resolver_ip_tools_menu,
    populate_resolver_side_item,
    prompt_selected_resolver_ip,
    resolver_edited_side_details,
    rewrite_matching_entry_notes,
    select_resolver_item_at,
    selected_resolver_side_row,
)
from session_sniffer.guis.select_usernames_dialog import prompt_usernames_and_notes_input
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import (
    dedup_userip_entries,
    format_userip_db_display_name,
    load_userip_database_model,
    populate_userip_databases_menu,
    refresh_userip_and_wake_renderer,
    rewrite_db_edit_entry_ip,
    save_userip_database_model,
)
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    add_icon_menu_action,
    create_styled_context_menu,
    find_main_window,
    scale_by_ui,
    set_dialog_window_flags,
)
from session_sniffer.models.userip_settings_model import (
    UserIPEntryModel,
    get_current_iso_timestamp,
)
from session_sniffer.networking.ip_range import entry_ip_covers_ip, parse_ip_range
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_loader import (
    append_userip_entries,
    collect_split_account_groups,
    find_userip_insert_index,
    move_userip_entries_to_database,
    userip_databases_lock,
)
from session_sniffer.player.userip_log_history import enrich_userip_entry_from_logs
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.player.userip import UserIPConflict

_REFRESH_INTERVAL_MS = 1000
_CONFLICTS_TAB_INDEX = 0
_SPLIT_GROUPS_TAB_INDEX = 1


class _ConflictSide(NamedTuple):
    """One IP or range entry string in a specific UserIP database that takes part in a conflict."""

    db_path: Path
    entry: str


class _ConflictGroup(NamedTuple):
    """A connected set of conflicting entries."""

    sides: list[_ConflictSide]


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


def _aggregate_side_entries(entries: Sequence[UserIPEntryModel], target_entry: str) -> SideDetails:
    """Aggregate all `UserIPEntryModel` records matching `target_entry` into a `SideDetails` snapshot."""
    return aggregate_matching_entries(entries, lambda entry: entry.ip.strip() == target_entry)


def _collect_side_details(sides: Sequence[_ConflictSide]) -> dict[_ConflictSide, SideDetails]:
    """Read the aggregated entry metadata currently stored on disk for each conflicting side."""
    entries_by_db: dict[Path, list[UserIPEntryModel]] = {}
    details_by_side: dict[_ConflictSide, SideDetails] = {}
    for side in sides:
        if side.db_path not in entries_by_db:
            entries_by_db[side.db_path] = load_userip_database_model(side.db_path).entries
        details_by_side[side] = _aggregate_side_entries(entries_by_db[side.db_path], side.entry)
    return details_by_side


def _rewrite_side_usernames(side: _ConflictSide, new_usernames: Sequence[str]) -> SideDetails | None:
    """Update the username(s) for `side` in its UserIP database file on disk and return updated `SideDetails`."""
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


def _rewrite_side_notes(side: _ConflictSide, new_note: str) -> SideDetails | None:
    """Update the `notes` field for all entries of `side` in its UserIP database file on disk."""
    return rewrite_matching_entry_notes(side.db_path, lambda entry: entry.ip.strip() == side.entry, new_note)


def _merge_and_delete_sides(kept_side: _ConflictSide, sides_to_delete: Sequence[_ConflictSide]) -> None:
    """Merge usernames, notes, and metadata from `sides_to_delete` into `kept_side`, then delete `sides_to_delete`."""
    with userip_databases_lock():
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


def _move_side_to_database(side: _ConflictSide, target_db_path: Path) -> bool:
    """Move all entries of `side` from `side.db_path` to `target_db_path`."""
    if not side.db_path.is_file() or side.db_path == target_db_path:
        return False
    keys = {
        (side.db_path, entry.username.strip().casefold(), entry.ip.strip())
        for entry in load_userip_database_model(side.db_path).entries
        if entry.ip.strip() == side.entry
    }
    return bool(keys and move_userip_entries_to_database(target_db_path, entry_keys=keys, extra_conflict_check_ips=[side.entry]).moved_by_db)


def _delete_sides(sides: Sequence[_ConflictSide]) -> None:
    """Delete every entry of the given IP or range strings from their UserIP databases, then rebuild."""
    entries_to_delete_by_db: dict[Path, set[str]] = {}
    for side in sides:
        entries_to_delete_by_db.setdefault(side.db_path, set()).add(side.entry)

    with userip_databases_lock():
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
    usernames_text = ', '.join(usernames) if usernames else NO_USERNAME_TEXT
    return f'<li>"{html.escape(format_userip_db_display_name(side.db_path))}": {html.escape(usernames_text)} = {html.escape(side.entry)}</li>'


class UserIPConflictResolverDialog(QDialog):
    """Non-modal window listing UserIP IP conflicts and split account groups across databases."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the UserIP Conflict Resolver dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'UserIP Conflict Resolver - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(780), scale_by_ui(450))

        self._groups: list[_ConflictGroup] = []
        self._side_rows: list[tuple[_ConflictGroup, _ConflictSide]] = []
        self._details_by_side: dict[_ConflictSide, SideDetails] = {}
        self._pending_focus_entry: str | None = None
        self._last_build_version = -1
        self._looky_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg'))

        root_layout = QVBoxLayout(self)
        self._tabs = QTabWidget()
        root_layout.addWidget(self._tabs)

        conflicts_tab = QWidget()
        layout = QVBoxLayout(conflicts_tab)

        self._summary_label = QLabel()
        self._summary_label.setWordWrap(True)
        layout.addWidget(self._summary_label)

        self._tree, self._edit_selected_usernames, self._edit_selected_note = create_configured_resolver_tree(
            layout,
            ResolverTreeCallbacks(self._show_context_menu, self._update_buttons, self._on_item_changed, self._edit_selected, self._delete_selected),
        )

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

        self._edit_button, self._delete_button = create_resolver_tail_buttons(
            buttons_layout,
            on_edit=self._edit_selected,
            on_delete=self._delete_selected,
            on_close=self.close,
        )

        layout.addLayout(buttons_layout)

        self._split_groups_tab = SplitGroupsResolverTab(
            self,
            on_count_changed=self._update_split_groups_tab_title,
            on_close=self.close,
        )

        self._tabs.addTab(conflicts_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'scale.svg')), 'IP Conflicts')
        self._tabs.addTab(self._split_groups_tab, QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'link.svg')), 'Split Groups')

        # Follow rebuilds triggered elsewhere (UserIP Manager edits, external file changes, ...)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(_REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self._refresh_if_rebuilt)
        self._refresh_timer.start()

        self.resize(scale_by_ui(1120), scale_by_ui(540))
        self._refresh()
        self.select_most_relevant_tab()

    def _update_split_groups_tab_title(self, count: int) -> None:
        self._tabs.setTabText(_SPLIT_GROUPS_TAB_INDEX, f'Split Groups ({count})')

    def _populate_side_item(self, item: QTreeWidgetItem, side: _ConflictSide, details: SideDetails) -> None:
        populate_resolver_side_item(item, format_userip_db_display_name(side.db_path), side.entry, details, self._looky_icon)

    def select_most_relevant_tab(self) -> None:
        """Select IP Conflicts when conflicts exist, otherwise Split Groups when split groups exist."""
        if self._groups:
            self._tabs.setCurrentIndex(_CONFLICTS_TAB_INDEX)
        elif self._split_groups_tab.group_count > 0:
            self._tabs.setCurrentIndex(_SPLIT_GROUPS_TAB_INDEX)

    def focus_on_entry(self, entry: str | None) -> None:
        """Switch to IP Conflicts and select the first conflicting entry covering `entry`, if any."""
        self._pending_focus_entry = entry
        self._refresh()
        self._tabs.setCurrentIndex(_CONFLICTS_TAB_INDEX)

    def focus_on_split_username(self, username: str) -> None:
        """Switch to Split Groups and select the split account group containing `username`, if any."""
        self._tabs.setCurrentIndex(_SPLIT_GROUPS_TAB_INDEX)
        self._split_groups_tab.focus_on_username(username)

    def _refresh_if_rebuilt(self) -> None:
        if (
            UserIPDatabases.build_version != self._last_build_version
            and self._tree.state() != QAbstractItemView.State.EditingState
            and not self._split_groups_tab.is_editing
        ):
            self._refresh()

    def _selected_side(self) -> tuple[_ConflictGroup, _ConflictSide] | None:
        return selected_resolver_side_row(self._tree, self._side_rows)

    def _refresh(self) -> None:
        """Rebuild both resolver tabs from the latest UserIP build, preserving or applying selection."""
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
        scroll_value = self._tree.verticalScrollBar().value() if focus_entry is None else None

        with QSignalBlocker(self._tree):
            self._tree.clear()
            for group_index, group in enumerate(self._groups, start=1):
                group_entries = list(dict.fromkeys(side.entry for side in group.sides))
                group_item = add_resolver_group_header(self._tree, f'Conflict {group_index}: {" vs ".join(group_entries)}')

                for side in group.sides:
                    details = self._details_by_side.get(side) or SideDetails()
                    side_item = QTreeWidgetItem()
                    self._populate_side_item(side_item, side, details)
                    side_item.setFlags(side_item.flags() | Qt.ItemFlag.ItemIsEditable)
                    side_item.setData(0, SIDE_ROLE, self._side_rows.index((group, side)))
                    group_item.addChild(side_item)
                    if item_to_select is None and (
                        (focus_entry is not None and entry_ip_covers_ip(side.entry, focus_entry)) or (focus_entry is None and side == previous_side)
                    ):
                        item_to_select = side_item

        finish_resolver_tree_refresh(self._tree, item_to_select, scroll_value=scroll_value)

        conflict_group_count = len(self._groups)
        self._tabs.setTabText(_CONFLICTS_TAB_INDEX, f'IP Conflicts ({conflict_group_count})')
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
        self._split_groups_tab.refresh()

    def _add_username_to_side(self, side: _ConflictSide) -> None:
        if not side.db_path.is_file():
            return
        db_name = format_userip_db_display_name(side.db_path)
        new_usernames, entered_notes, accepted = prompt_usernames_and_notes_input(
            self,
            'Add Username(s)',
            lambda count: f'Enter the username{pluralize(count)} to add for {side.entry} in "{db_name}":',
        )
        if not accepted or not new_usernames:
            return
        new_entry_models = [
            enrich_userip_entry_from_logs(UserIPEntryModel(username=name, ip=side.entry, notes=entered_notes.get(name, '')))[0]
            for name in new_usernames
        ]
        added_pairs = append_userip_entries(side.db_path, new_entry_models)
        if not added_pairs:
            QMessageBox.information(
                self,
                TITLE,
                f'All specified username{pluralize(len(new_usernames))} already exist for {side.entry} in "{db_name}".',
            )
            return
        refresh_userip_and_wake_renderer()
        self._refresh()

    def _move_side(self, side: _ConflictSide, target_db_path: Path) -> None:
        if _move_side_to_database(side, target_db_path):
            self._refresh()

    def _show_context_menu(self, position: QPoint) -> None:
        selection = select_resolver_item_at(self._tree, position, self._side_rows)
        if selection is None:
            return
        _, side = selection
        details = self._details_by_side.get(side) or SideDetails()

        menu = create_styled_context_menu(self)
        single_ip = populate_resolver_common_menu_prefix(
            menu,
            self._tree,
            db_path=side.db_path,
            entry_ip=side.entry,
            details=details,
        )
        self._populate_resolution_menu_actions(menu, side, details, is_single_ip=single_ip)

        if viewport := self._tree.viewport():
            menu.popup(viewport.mapToGlobal(position))

    def _populate_resolution_menu_actions(self, menu: QMenu, side: _ConflictSide, details: SideDetails, *, is_single_ip: bool) -> None:
        add_icon_menu_action(menu, 'check.svg', 'Keep This Entry…', self._keep_selected)
        add_icon_menu_action(menu, 'user-round-check.svg', 'Keep && Merge…', self._keep_and_merge_selected)
        menu.addSeparator()

        rename_action = add_icon_menu_action(menu, 'square-pen.svg', 'Rename', self._edit_selected_usernames)
        rename_action.setShortcut('F2')
        add_icon_menu_action(menu, 'square-pen.svg', 'Edit IP…' if is_single_ip else 'Edit Range…', self._edit_selected)
        add_icon_menu_action(menu, 'notepad-text.svg', 'Edit Note…' if details.notes else 'Add Note…', self._edit_selected_note)

        move_db_menu = create_styled_context_menu(menu, title='Move to Database', icon_name='box.svg')
        all_db_paths = [json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()]
        enabled_targets = populate_userip_databases_menu(
            move_db_menu,
            all_db_paths,
            tooltip='Move this entry to this database.',
            handler_factory=lambda target_path: lambda: self._move_side(side, target_path),
            disabled_path=side.db_path,
        )
        if not enabled_targets:
            move_db_menu.setEnabled(False)
        menu.addMenu(move_db_menu)

        populate_resolver_ip_tools_menu(self, menu, side.entry, single_ip=is_single_ip)

        menu.addSeparator()
        add_icon_menu_action(menu, 'plus.svg', 'Add Username…', lambda: self._add_username_to_side(side))

        menu.addSeparator()
        delete_action = add_icon_menu_action(menu, 'remove.svg', 'Delete This Entry…', self._delete_selected)
        delete_action.setShortcut('Delete')

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        edited = resolver_edited_side_details(item, column, self._side_rows, self._details_by_side)
        if edited is None:
            return
        side, details = edited

        if column == USERNAMES_COLUMN:
            new_usernames = parse_deduped_usernames_cell(item.text(USERNAMES_COLUMN))
            if not new_usernames or new_usernames == details.usernames:
                with QSignalBlocker(self._tree):
                    self._populate_side_item(item, side, details)
                return
            updated_details = _rewrite_side_usernames(side, new_usernames)
        else:
            new_note = item.text(NOTES_COLUMN).strip()
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
        self._split_groups_tab.refresh()

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
        kept_html = html.escape(f'{kept_side.entry} in "{format_userip_db_display_name(kept_side.db_path)}"')
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
        kept_html = html.escape(f'{kept_side.entry} in "{format_userip_db_display_name(kept_side.db_path)}"')
        entry_word = pluralize(len(sides_to_delete), 'entry', 'entries')
        prompt = f'Keep <b>{kept_html}</b>, merge usernames and metadata from the following conflicting {entry_word} into it, and delete the conflicting {entry_word}?'
        if not self._confirm_deletion(prompt, sides_to_delete):
            return
        _merge_and_delete_sides(kept_side, sides_to_delete)
        self._refresh()

    def _edit_selected(self) -> None:
        prompted = prompt_selected_resolver_ip(self, self._selected_side(), lambda s: s.entry)
        if prompted is None:
            return
        side, new_entry = prompted
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


def count_userip_resolver_issues() -> tuple[int, int]:
    """Return `(ip_conflict_group_count, split_account_group_count)` across enabled UserIP databases."""
    conflict_groups = _build_conflict_groups(UserIPDatabases.get_conflicts())
    split_groups, _ = collect_split_account_groups(include_disabled=False)
    return len(conflict_groups), len(split_groups)


def update_resolve_conflicts_button(button: QPushButton) -> None:
    """Refresh the label and tooltip of a 'Resolve Conflicts…' button with active conflict and split-group counts."""
    conflicts_n, split_n = count_userip_resolver_issues()
    total = conflicts_n + split_n
    button.setText(f' Resolve Conflicts ({total})…' if total else ' Resolve Conflicts…')
    if total:
        button.setToolTip(
            f'{conflicts_n} IP conflict group{pluralize(conflicts_n)}, '
            f'{split_n} split account group{pluralize(split_n)} — click to review and resolve',
        )
    else:
        button.setToolTip('Open the UserIP Conflict Resolver to review IP/range conflicts or account groups split across databases')


def open_userip_conflict_resolver(focus_entry: str | None = None, *, focus_split_username: str | None = None) -> None:
    """Open (or focus) the UserIP Conflict Resolver on the IP Conflicts or Split Groups tab."""
    dialog = _active_resolver_dialogs.show_or_focus('userip_conflict_resolver', lambda: UserIPConflictResolverDialog(find_main_window()))
    if focus_split_username is not None:
        dialog.focus_on_split_username(focus_split_username)
    elif focus_entry is not None:
        dialog.focus_on_entry(focus_entry)
    else:
        dialog.select_most_relevant_tab()
