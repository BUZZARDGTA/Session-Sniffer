"""UserIP Conflict Resolver dialog for reviewing and fixing IPs or ranges claimed by multiple UserIP databases."""

import html
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import (
    IPRangeBuilderDialog,
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    rewrite_db_edit_entry_ip,
    save_userip_database_model,
)
from session_sniffer.guis.utils import ActiveDialogRegistry, find_main_window, scale_by_ui, set_dialog_window_flags
from session_sniffer.networking.ip_range import entry_ip_covers_ip, parse_ip_range
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.player.userip import UserIPConflict

_REFRESH_INTERVAL_MS = 1000
_SIDE_ROLE = Qt.ItemDataRole.UserRole


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


def _format_database_name(db_path: Path) -> str:
    """Return the database path relative to the UserIP databases directory, without extension."""
    return str(db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))


def _collect_side_usernames(sides: Sequence[_ConflictSide]) -> dict[_ConflictSide, list[str]]:
    """Read the usernames currently stored on disk for each conflicting entry."""
    entries_by_db: dict[Path, list[tuple[str, str]]] = {}
    usernames_by_side: dict[_ConflictSide, list[str]] = {}
    for side in sides:
        if side.db_path not in entries_by_db:
            entries_by_db[side.db_path] = [(entry.username, entry.ip.strip()) for entry in load_userip_database_model(side.db_path).entries]
        usernames: list[str] = []
        for username, entry_ip in entries_by_db[side.db_path]:
            if entry_ip == side.entry and username not in usernames:
                usernames.append(username)
        usernames_by_side[side] = usernames
    return usernames_by_side


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
    usernames_text = ', '.join(usernames) if usernames else '(no username)'
    return f'<li>"{html.escape(_format_database_name(side.db_path))}": {html.escape(usernames_text)} = {html.escape(side.entry)}</li>'


class UserIPConflictResolverDialog(QDialog):
    """Non-modal window listing UserIP conflicts and letting the user keep, edit, or delete the conflicting entries."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the UserIP Conflict Resolver dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'UserIP Conflict Resolver - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(760), scale_by_ui(420))

        self._groups: list[_ConflictGroup] = []
        self._side_rows: list[tuple[_ConflictGroup, _ConflictSide]] = []
        self._usernames_by_side: dict[_ConflictSide, list[str]] = {}
        self._pending_focus_entry: str | None = None
        self._last_build_version = -1

        layout = QVBoxLayout(self)

        self._summary_label = QLabel()
        self._summary_label.setWordWrap(True)
        layout.addWidget(self._summary_label)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(3)
        self._tree.setHeaderLabels(['Database', 'IP / Range', 'Usernames'])
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setUniformRowHeights(True)
        self._tree.setColumnWidth(0, scale_by_ui(220))
        self._tree.setColumnWidth(1, scale_by_ui(200))
        self._tree.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self._tree, stretch=1)

        buttons_layout = QHBoxLayout()

        self._keep_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'check.svg')), ' Keep This Entry…')
        self._keep_button.setAutoDefault(False)
        self._keep_button.setToolTip('Keep the selected entry and delete the entries that conflict with it (you will be asked to confirm)')
        self._keep_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._keep_button.clicked.connect(self._keep_selected)
        buttons_layout.addWidget(self._keep_button)

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

        self.resize(scale_by_ui(860), scale_by_ui(480))
        self._refresh()

    def focus_on_entry(self, entry: str | None) -> None:
        """Select the first conflicting entry covering `entry` (an IP or range), if any."""
        self._pending_focus_entry = entry
        self._refresh()

    def _refresh_if_rebuilt(self) -> None:
        if UserIPDatabases.build_version != self._last_build_version:
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
        self._usernames_by_side = _collect_side_usernames([side for group in self._groups for side in group.sides])

        self._tree.clear()
        item_to_select: QTreeWidgetItem | None = None
        focus_entry = self._pending_focus_entry
        self._pending_focus_entry = None

        for group_index, group in enumerate(self._groups, start=1):
            group_entries = list(dict.fromkeys(side.entry for side in group.sides))
            group_item = QTreeWidgetItem([f'Conflict {group_index}: {" vs ".join(group_entries)}'])
            font = group_item.font(0)
            font.setBold(True)
            group_item.setFont(0, font)
            self._tree.addTopLevelItem(group_item)
            group_item.setFirstColumnSpanned(True)

            for side in group.sides:
                usernames = self._usernames_by_side.get(side, [])
                side_item = QTreeWidgetItem([_format_database_name(side.db_path), side.entry, ', '.join(usernames) or '(no username)'])
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
                'Select an entry, then keep it (deletes the entries that conflict with it), edit its IP or range, or delete it.',
            )
        else:
            self._summary_label.setText('No UserIP conflicts. Every IP and range belongs to a single database.')
        self._update_buttons()

    def _update_buttons(self) -> None:
        has_side = self._selected_side() is not None
        self._keep_button.setEnabled(has_side)
        self._edit_button.setEnabled(has_side)
        self._delete_button.setEnabled(has_side)

    def _confirm_deletion(self, header: str, sides: Sequence[_ConflictSide]) -> bool:
        items_html = ''.join(_format_side_html(side, self._usernames_by_side.get(side, [])) for side in sides)
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
