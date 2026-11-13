"""Split Account Groups tab and shared tree helpers for the UserIP Conflict Resolver."""

import html
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast, override

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QPoint, QSignalBlocker, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
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
from session_sniffer.guis.select_usernames_dialog import SelectUsernamesDialog, UsernameSelectionConfig, configure_username_cell_editor
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.table_column_resizing import setup_table_header_context_menu
from session_sniffer.guis.tables_player_actions import create_ping_menu, scan_ports_ip, show_detailed_ip_lookup
from session_sniffer.guis.userip_manager_helpers import (
    USERIP_METADATA_HEADER_TOOLTIPS,
    IPRangeBuilderDialog,
    dedup_userip_entries,
    format_userip_db_display_name,
    load_userip_database_model,
    populate_userip_databases_menu,
    refresh_userip_and_wake_renderer,
    save_userip_database_model,
)
from session_sniffer.guis.utils import (
    add_icon_menu_action,
    create_styled_context_menu,
    find_main_window,
    open_file_location,
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.models.userip_settings_model import (
    USERIP_SOURCE_TOOLTIPS,
    EntrySource,
    UserIPDatabaseFile,
    UserIPEntryModel,
    format_iso_timestamp_display,
    get_current_iso_timestamp,
    pick_earliest_iso,
    pick_latest_iso,
)
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import MIN_GROUP_USERNAMES, UserIPAccountGroup, ungroup_usernames
from session_sniffer.player.userip_loader import collect_split_account_groups, move_userip_entries_to_database, userip_databases_lock
from session_sniffer.player.userip_log_history import enrich_userip_entry_from_logs
from session_sniffer.text_utils import pluralize, split_usernames

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from collections.abc import Set as AbstractSet

    from session_sniffer.guis._main_window_files_mixin import FilesMixin

SIDE_ROLE = Qt.ItemDataRole.UserRole
DATABASE_COLUMN, IP_RANGE_COLUMN, USERNAMES_COLUMN, NOTES_COLUMN, SOURCE_COLUMN = 0, 1, 2, 3, 4
DETECTIONS_COLUMN, ADDED_COLUMN, UPDATED_COLUMN, FIRST_SEEN_COLUMN, LAST_SEEN_COLUMN = 5, 6, 7, 8, 9
NO_USERNAME_TEXT = '(no username)'

RESOLVER_TABLE_HEADERS: list[str] = [
    'Database', 'IP / Range', 'Usernames', 'Notes', 'Source', 'Detections', 'Added', 'Updated', 'First Seen', 'Last Seen',
]

RESOLVER_HEADER_TOOLTIPS: dict[str, str] = {
    'Database': 'The UserIP database file that contains this entry.',
    'IP / Range': 'The IPv4 address, range, or CIDR subnet claimed by this entry (double-click to edit).',
    'Usernames': (
        'The username(s) associated with this entry (double-click to edit).\n'
        'Purple entries with a Looky icon were automatically added or confirmed via Looky System.'
    ),
    'Notes': 'Optional user notes or comments attached to this entry (double-click to edit).',
    **USERIP_METADATA_HEADER_TOOLTIPS,
}

DEFAULT_RESOLVER_COLUMN_WIDTHS: dict[int, int] = {
    DATABASE_COLUMN: 170, IP_RANGE_COLUMN: 155, USERNAMES_COLUMN: 200, NOTES_COLUMN: 160, SOURCE_COLUMN: 85,
    DETECTIONS_COLUMN: 85, ADDED_COLUMN: 145, UPDATED_COLUMN: 145, FIRST_SEEN_COLUMN: 145, LAST_SEEN_COLUMN: 145,
}


@dataclass(slots=True)
class SideDetails:
    """Aggregated usernames, notes, Looky state, and timestamps for a resolver tree row."""

    usernames: list[str] = field(default_factory=list[str])
    looky_usernames: set[str] = field(default_factory=set[str])
    notes: list[str] = field(default_factory=list[str])
    sources: list[EntrySource] = field(default_factory=list[EntrySource])
    detections_count: int = 0
    added_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None


class ResolverTreeDelegate(SearchHighlightDelegate):
    """Item delegate for resolver trees supporting Looky username styling and inline editing."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent, lambda: '')

    @override
    def createEditor(self, parent: QWidget, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> QWidget:
        editor = super().createEditor(parent, option, index)
        configure_username_cell_editor(editor, index, username_column=USERNAMES_COLUMN)
        return editor

    @override
    def setEditorData(self, editor: QWidget, index: QModelIndex | QPersistentModelIndex) -> None:
        if index.column() == USERNAMES_COLUMN and isinstance(editor, QLineEdit) and index.data(Qt.ItemDataRole.DisplayRole) == NO_USERNAME_TEXT:
            editor.setText('')
            return
        super().setEditorData(editor, index)


def is_single_ipv4(entry_text: str) -> bool:
    """Return `True` if `entry_text` is a single IPv4 address rather than a range or CIDR subnet."""
    if not entry_text or '/' in entry_text or '-' in entry_text or '*' in entry_text:
        return False
    try:
        IPv4Address(entry_text)
    except ValueError:
        return False
    return True


def navigate_to_database_in_manager(db_path: Path, *, username: str = '', ip_or_range: str = '') -> None:
    """Open or focus the UserIP Databases Manager on `db_path` and select the matching entry."""
    main_window = cast('FilesMixin | None', find_main_window())
    if main_window is not None:
        main_window.open_userip_manager_and_navigate(db_path, username=username, ip_or_range=ip_or_range)


def reset_resolver_column_sizes(tree: QTreeWidget) -> None:
    """Reset column widths and interactive resize modes on *tree*."""
    header = tree.header()
    if not header:
        return
    header.setStretchLastSection(True)
    for col, width in DEFAULT_RESOLVER_COLUMN_WIDTHS.items():
        header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        tree.setColumnWidth(col, scale_by_ui(width))


def _configure_resolver_tree(tree: QTreeWidget) -> None:
    """Apply common headers, tooltips, delegate, and scroll settings to a resolver `QTreeWidget`."""
    tree.setColumnCount(len(RESOLVER_TABLE_HEADERS))
    tree.setHeaderLabels(RESOLVER_TABLE_HEADERS)
    if header_item := tree.headerItem():
        for col, label in enumerate(RESOLVER_TABLE_HEADERS):
            if (tooltip := RESOLVER_HEADER_TOOLTIPS.get(label)) is not None:
                header_item.setToolTip(col, tooltip)
    tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    tree.setItemDelegate(ResolverTreeDelegate(tree))
    tree.setUniformRowHeights(True)
    tree.setAlternatingRowColors(True)
    tree.setWordWrap(False)
    tree.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    def _reset_cols() -> None:
        reset_resolver_column_sizes(tree)

    _reset_cols()
    setup_table_header_context_menu(tree, on_reset=_reset_cols)
    tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)


def populate_resolver_side_item(item: QTreeWidgetItem, db_label: str, entry_ip: str, details: SideDetails, looky_icon: QIcon) -> None:
    """Populate all display, icon, and tooltip columns on a child `QTreeWidgetItem`."""
    item.setText(DATABASE_COLUMN, db_label)
    item.setText(IP_RANGE_COLUMN, entry_ip)
    item.setText(USERNAMES_COLUMN, ', '.join(details.usernames) or NO_USERNAME_TEXT)
    if details.looky_usernames:
        item.setIcon(USERNAMES_COLUMN, looky_icon)
        item.setData(USERNAMES_COLUMN, Qt.ItemDataRole.UserRole, set(details.looky_usernames))
    else:
        item.setIcon(USERNAMES_COLUMN, QIcon())
        item.setData(USERNAMES_COLUMN, Qt.ItemDataRole.UserRole, None)
    item.setText(NOTES_COLUMN, ', '.join(details.notes))
    item.setText(SOURCE_COLUMN, ', '.join(details.sources))
    item.setToolTip(
        SOURCE_COLUMN,
        '\n'.join(f'{src}: {desc}' if len(details.sources) > 1 else desc for src in details.sources if (desc := USERIP_SOURCE_TOOLTIPS.get(src)) is not None),
    )
    item.setText(DETECTIONS_COLUMN, str(details.detections_count))
    for col, raw_iso in (
        (ADDED_COLUMN, details.added_at),
        (UPDATED_COLUMN, details.updated_at),
        (FIRST_SEEN_COLUMN, details.first_seen_at),
        (LAST_SEEN_COLUMN, details.last_seen_at),
    ):
        item.setText(col, format_iso_timestamp_display(raw_iso))
        item.setToolTip(col, raw_iso or '')


def copy_resolver_selected_row(tree: QTreeWidget) -> None:
    """Copy visible cell values of the selected child row in *tree* as tab-separated text."""
    selected_items = tree.selectedItems()
    if not selected_items or selected_items[0].data(0, SIDE_ROLE) is None:
        return
    item = selected_items[0]
    header = tree.header()
    cells = [item.text(col) for col in range(tree.columnCount()) if not header.isSectionHidden(col)]
    set_clipboard_text('\t'.join(cells))


def resolver_side_row_for_item[T](item: QTreeWidgetItem, side_rows: Sequence[T]) -> T | None:
    """Return the row record stored on *item*, or `None` for group headers or stale items."""
    side_row = item.data(0, SIDE_ROLE)
    if not isinstance(side_row, int) or not 0 <= side_row < len(side_rows):
        return None
    return side_rows[side_row]


def selected_resolver_side_row[T](tree: QTreeWidget, side_rows: Sequence[T]) -> T | None:
    """Return the row record of the currently selected child item in *tree*, or `None`."""
    selected_items = tree.selectedItems()
    return resolver_side_row_for_item(selected_items[0], side_rows) if selected_items else None


def select_resolver_item_at[T](tree: QTreeWidget, position: QPoint, side_rows: Sequence[T]) -> T | None:
    """Select the child row at *position* in *tree* and return its row record, or `None`."""
    item = tree.itemAt(position)
    if item is None or item.data(0, SIDE_ROLE) is None:
        return None
    tree.setCurrentItem(item)
    return selected_resolver_side_row(tree, side_rows)


def add_resolver_group_header(tree: QTreeWidget, title: str) -> QTreeWidgetItem:
    """Append and return a bold, full-width top-level group header item in *tree*."""
    group_item = QTreeWidgetItem([title])
    font = group_item.font(0)
    font.setBold(True)
    group_item.setFont(0, font)
    tree.addTopLevelItem(group_item)
    group_item.setFirstColumnSpanned(True)
    return group_item


def finish_resolver_tree_refresh(tree: QTreeWidget, item_to_select: QTreeWidgetItem | None, *, scroll_value: int | None) -> None:
    """Expand all groups in *tree*, restore the vertical *scroll_value* when provided, and select/scroll to *item_to_select*."""
    tree.expandAll()
    if scroll_value is not None:
        tree.doItemsLayout()
        tree.verticalScrollBar().setValue(scroll_value)
    if item_to_select is not None:
        tree.setCurrentItem(item_to_select)
        tree.scrollToItem(item_to_select)


def parse_deduped_usernames_cell(raw_text: str) -> list[str]:
    """Parse and case-insensitively deduplicate usernames entered into an inline `Usernames` cell."""
    seen_cf: set[str] = set()
    usernames: list[str] = []
    for raw_name in split_usernames(raw_text):
        if (cleaned := raw_name.strip()) and (folded := cleaned.casefold()) not in seen_cf:
            seen_cf.add(folded)
            usernames.append(cleaned)
    return usernames


def aggregate_matching_entries(entries: Sequence[UserIPEntryModel], predicate: Callable[[UserIPEntryModel], bool]) -> SideDetails:
    """Aggregate all `UserIPEntryModel` records matching *predicate* into a `SideDetails` snapshot."""
    details = SideDetails()
    for entry in entries:
        if not predicate(entry):
            continue
        if entry.username not in details.usernames:
            details.usernames.append(entry.username)
        if entry.is_looky:
            details.looky_usernames.add(entry.username)
        cleaned_note = entry.notes.strip()
        if cleaned_note and cleaned_note not in details.notes:
            details.notes.append(cleaned_note)
        if entry.source not in details.sources:
            details.sources.append(entry.source)
        details.detections_count = max(details.detections_count, entry.detections_count)
        details.added_at = pick_earliest_iso(details.added_at, entry.added_at)
        details.updated_at = pick_latest_iso(details.updated_at, entry.updated_at)
        details.first_seen_at = pick_earliest_iso(details.first_seen_at, entry.first_seen_at)
        details.last_seen_at = pick_latest_iso(details.last_seen_at, entry.last_seen_at)
    return details


def rewrite_matching_entry_notes(
    db_path: Path,
    predicate: Callable[[UserIPEntryModel], bool],
    new_note: str,
) -> SideDetails | None:
    """Update `notes` on all entries matching *predicate* in *db_path* and return refreshed `SideDetails`."""
    if not db_path.is_file():
        return None
    cleaned = new_note.strip()
    matched = modified = False
    now_iso = get_current_iso_timestamp()
    with userip_databases_lock():
        db_model = load_userip_database_model(db_path)
        for i, entry in enumerate(db_model.entries):
            if predicate(entry):
                matched = True
                if entry.notes != cleaned:
                    db_model.entries[i] = entry.model_copy(update={'notes': cleaned, 'updated_at': now_iso})
                    modified = True
        if not matched:
            return None
        if modified:
            save_userip_database_model(db_path, db_model)
    return aggregate_matching_entries(db_model.entries, predicate)


def resolver_edited_side_details[G, S](
    item: QTreeWidgetItem,
    column: int,
    side_rows: Sequence[tuple[G, S]],
    details_by_side: Mapping[S, SideDetails],
) -> tuple[S, SideDetails] | None:
    """Return `(side, details)` when *column* is inline-editable and *item* maps to a valid row, else `None`."""
    if column not in (USERNAMES_COLUMN, NOTES_COLUMN):
        return None
    row = resolver_side_row_for_item(item, side_rows)
    if row is None:
        return None
    _, side = row
    return side, details_by_side.get(side) or SideDetails()


def prompt_selected_resolver_ip[G, S](
    parent: QWidget,
    selection: tuple[G, S] | None,
    get_entry: Callable[[S], str],
) -> tuple[S, str] | None:
    """Prompt for a changed IP/range on *selection* and return `(side, new_entry)`, or `None`."""
    if selection is None:
        return None
    _, side = selection
    initial_entry = get_entry(side)
    dialog = IPRangeBuilderDialog(parent, initial_entry=initial_entry)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    new_entry = dialog.result_entry()
    return (side, new_entry) if new_entry and new_entry != initial_entry else None


@dataclass(frozen=True, slots=True)
class ResolverTreeCallbacks:
    """Signal and action callbacks wired onto a resolver `QTreeWidget`."""

    on_context_menu: Callable[[QPoint], object]
    on_selection_changed: Callable[[], object]
    on_item_changed: Callable[[QTreeWidgetItem, int], object]
    on_edit_ip: Callable[[], object]
    on_delete: Callable[[], object]


def create_configured_resolver_tree(
    layout: QVBoxLayout,
    callbacks: ResolverTreeCallbacks,
) -> tuple[QTreeWidget, Callable[[], None], Callable[[], None]]:
    """Create, configure, wire signals/shortcuts on, and add a resolver `QTreeWidget` to *layout*."""
    tree = QTreeWidget()
    _configure_resolver_tree(tree)
    tree.customContextMenuRequested.connect(callbacks.on_context_menu)
    tree.itemSelectionChanged.connect(callbacks.on_selection_changed)
    tree.itemChanged.connect(callbacks.on_item_changed)

    def _edit_selected_column(column: int) -> None:
        selected_items = tree.selectedItems()
        if selected_items and selected_items[0].data(0, SIDE_ROLE) is not None:
            tree.editItem(selected_items[0], column)

    def _edit_usernames() -> None:
        _edit_selected_column(USERNAMES_COLUMN)

    def _edit_note() -> None:
        _edit_selected_column(NOTES_COLUMN)

    def _on_double_clicked(item: QTreeWidgetItem, column: int) -> None:
        if item.data(0, SIDE_ROLE) is None:
            return
        if column in (USERNAMES_COLUMN, NOTES_COLUMN):
            tree.editItem(item, column)
        elif column == IP_RANGE_COLUMN:
            tree.setCurrentItem(item)
            callbacks.on_edit_ip()

    tree.itemDoubleClicked.connect(_on_double_clicked)
    QShortcut(QKeySequence('Ctrl+C'), tree).activated.connect(lambda: copy_resolver_selected_row(tree))
    QShortcut(QKeySequence('F2'), tree).activated.connect(_edit_usernames)
    QShortcut(QKeySequence('Delete'), tree).activated.connect(callbacks.on_delete)
    layout.addWidget(tree, stretch=1)
    return tree, _edit_usernames, _edit_note


def create_resolver_tail_buttons(
    buttons_layout: QHBoxLayout, *, on_edit: Callable[[], object], on_delete: Callable[[], object], on_close: Callable[[], object],
) -> tuple[QPushButton, QPushButton]:
    """Append `Edit Entry…`, `Delete This Entry…`, stretch, and `Close` buttons; return `(edit_btn, delete_btn)`."""
    edit_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')), ' Edit Entry…')
    edit_button.setAutoDefault(False)
    edit_button.setToolTip('Change the IP or range of the selected entry using the builder')
    edit_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    edit_button.clicked.connect(on_edit)
    buttons_layout.addWidget(edit_button)

    delete_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete This Entry…')
    delete_button.setAutoDefault(False)
    delete_button.setToolTip('Delete only the selected entry from its database (you will be asked to confirm)')
    delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
    delete_button.clicked.connect(on_delete)
    buttons_layout.addWidget(delete_button)

    buttons_layout.addStretch()

    close_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'x.svg')), ' Close')
    close_button.setAutoDefault(False)
    close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
    close_button.clicked.connect(on_close)
    buttons_layout.addWidget(close_button)
    return edit_button, delete_button


def populate_resolver_common_menu_prefix(
    menu: QMenu, tree: QTreeWidget, *, db_path: Path, entry_ip: str, details: SideDetails,
) -> bool:
    """Append standard Copy and Database navigation actions to *menu* and return `is_single_ipv4(entry_ip)`."""
    single_ip = is_single_ipv4(entry_ip)
    copy_row = add_icon_menu_action(menu, 'copy.svg', 'Copy Row', lambda: copy_resolver_selected_row(tree))
    copy_row.setShortcut('Ctrl+C')
    if details.usernames:
        names_txt = ', '.join(details.usernames)
        add_icon_menu_action(menu, 'copy.svg', f'Copy Username{pluralize(len(details.usernames))}', lambda: set_clipboard_text(names_txt))
    add_icon_menu_action(menu, 'copy.svg', 'Copy IP' if single_ip else 'Copy Range', lambda: set_clipboard_text(entry_ip))
    if details.notes:
        notes_txt = ', '.join(details.notes)
        add_icon_menu_action(menu, 'copy.svg', 'Copy Note', lambda: set_clipboard_text(notes_txt))

    menu.addSeparator()
    first_user = details.usernames[0] if details.usernames else ''
    add_icon_menu_action(
        menu, 'arrow-right.svg', 'Go to Database',
        lambda: navigate_to_database_in_manager(db_path, username=first_user, ip_or_range=entry_ip),
        tooltip='Open this database in the UserIP Databases Manager and navigate to this entry.',
    )
    add_icon_menu_action(menu, 'file-text.svg', 'Open in Text Editor', lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db_path))))
    add_icon_menu_action(menu, 'folder.svg', 'Open in File Manager', lambda: open_file_location(db_path))
    menu.addSeparator()
    return single_ip


def populate_resolver_ip_tools_menu(parent: QWidget, menu: QMenu, entry_ip: str, *, single_ip: bool) -> None:
    """Append IP Lookup, Ping, and Scan Ports actions when *single_ip* is `True`."""
    if single_ip:
        menu.addSeparator()
        add_icon_menu_action(menu, 'info.svg', 'IP Lookup Details…', lambda: show_detailed_ip_lookup(entry_ip))
        create_ping_menu(parent, menu, [entry_ip])
        add_icon_menu_action(menu, 'radar.svg', 'Scan Ports…', lambda: scan_ports_ip(entry_ip))


class _SplitSide(NamedTuple):
    """One `(db_path, ip_or_range)` slice belonging to a specific `UserIPAccountGroup`."""

    db_path: Path
    entry: str
    usernames_cf: frozenset[str]


def _matches_split_side(entry: UserIPEntryModel, side: _SplitSide) -> bool:
    return entry.ip.strip() == side.entry and entry.username.strip().casefold() in side.usernames_cf


def _build_group_sides(group: UserIPAccountGroup) -> list[_SplitSide]:
    db_order = {db_path: idx for idx, db_path in enumerate(group.databases)}
    cfs_by_db_ip: dict[tuple[Path, str], set[str]] = {}
    for db_path, u_cf, ip_val in group.entry_keys:
        cfs_by_db_ip.setdefault((db_path, ip_val), set()).add(u_cf)
    ordered = sorted(cfs_by_db_ip.items(), key=lambda item: (db_order.get(item[0][0], 0), item[0][1]))
    return [_SplitSide(db_path, ip_val, frozenset(cfs)) for (db_path, ip_val), cfs in ordered]


def _aggregate_split_side(entries: Sequence[UserIPEntryModel], side: _SplitSide) -> SideDetails:
    """Aggregate all `UserIPEntryModel` records matching *side* into a `SideDetails` snapshot."""
    return aggregate_matching_entries(entries, lambda entry: _matches_split_side(entry, side))


def _delete_entry_keys(keys_to_delete: AbstractSet[tuple[Path, str, str]]) -> None:
    """Delete specific `(db_path, username_cf, ip)` entries from their UserIP databases and rebuild."""
    dbs = {db_path for db_path, _, _ in keys_to_delete}
    with userip_databases_lock():
        for db_path in sorted(dbs):
            if not db_path.is_file():
                continue
            db_model = load_userip_database_model(db_path)
            kept = [e for e in db_model.entries if (db_path, e.username.strip().casefold(), e.ip.strip()) not in keys_to_delete]
            if len(kept) != len(db_model.entries):
                save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept))
        refresh_userip_and_wake_renderer()


def _rewrite_split_side_usernames(side: _SplitSide, new_usernames: Sequence[str]) -> tuple[_SplitSide, SideDetails] | None:
    """Update the username(s) for *side* in its database file while preserving unrelated usernames on that IP."""
    if not side.db_path.is_file() or not new_usernames:
        return None
    with userip_databases_lock():
        db_model = load_userip_database_model(side.db_path)
        matching_indices = [
            i for i, e in enumerate(db_model.entries) if e.ip.strip() == side.entry and e.username.strip().casefold() in side.usernames_cf
        ]
        if not matching_indices:
            return None
        template = db_model.entries[matching_indices[0]]
        existing_by_cf = {db_model.entries[i].username.casefold(): db_model.entries[i] for i in matching_indices}
        now_iso = get_current_iso_timestamp()
        replacements: list[UserIPEntryModel] = []
        for name in new_usernames:
            existing = existing_by_cf.get(name.casefold())
            if existing is not None:
                replacements.append(existing if existing.username == name else existing.model_copy(update={'username': name, 'updated_at': now_iso}))
            else:
                new_src: EntrySource = 'Manual' if template.source == 'Looky' else template.source
                enriched, _ = enrich_userip_entry_from_logs(
                    template.model_copy(update={'username': name, 'is_looky': False, 'source': new_src, 'updated_at': now_iso}),
                )
                replacements.append(enriched)

        first_idx = matching_indices[0]
        matched_set = set(matching_indices)
        updated_entries: list[UserIPEntryModel] = []
        for i, entry in enumerate(db_model.entries):
            if i == first_idx:
                updated_entries.extend(replacements)
            if i not in matched_set:
                updated_entries.append(entry)

        db_model.entries = dedup_userip_entries(updated_entries)
        save_userip_database_model(side.db_path, db_model)

    new_side = _SplitSide(side.db_path, side.entry, frozenset(n.casefold() for n in new_usernames))
    return new_side, _aggregate_split_side(db_model.entries, new_side)


def _rewrite_split_side_notes(side: _SplitSide, new_note: str) -> SideDetails | None:
    """Update the `notes` field for entries matching *side* in its database file."""
    return rewrite_matching_entry_notes(side.db_path, lambda entry: _matches_split_side(entry, side), new_note)


def _rewrite_split_side_ip(side: _SplitSide, new_entry: str) -> bool:
    """Replace the IP or range for entries matching *side* while preserving unrelated usernames on that IP."""
    if not side.db_path.is_file():
        return False
    replaced = False
    now_iso = get_current_iso_timestamp()
    with userip_databases_lock():
        db_model = load_userip_database_model(side.db_path)
        updated: list[UserIPEntryModel] = []
        for entry in db_model.entries:
            if _matches_split_side(entry, side):
                replaced = True
                new_src: EntrySource = 'Manual' if entry.source == 'Looky' else entry.source
                updated.append(enrich_userip_entry_from_logs(entry.model_copy(update={'ip': new_entry, 'is_looky': False, 'source': new_src, 'updated_at': now_iso}))[0])
            else:
                updated.append(entry)
        if replaced:
            db_model.entries = dedup_userip_entries(updated)
            save_userip_database_model(side.db_path, db_model)
    if replaced:
        UserIPDatabases.renotify_if_conflicting([new_entry])
    return replaced


class SplitGroupsResolverTab(QWidget):
    """Tab widget listing account groups split across multiple UserIP databases and offering consolidation or ungrouping."""

    def __init__(self, parent: QWidget, *, on_count_changed: Callable[[int], None], on_close: Callable[[], object]) -> None:
        """Build the Split Groups resolver tab."""
        super().__init__(parent)
        self._on_count_changed = on_count_changed
        self._groups: list[UserIPAccountGroup] = []
        self._disabled_dbs: frozenset[Path] = frozenset()
        self._side_rows: list[tuple[UserIPAccountGroup, _SplitSide]] = []
        self._details_by_side: dict[_SplitSide, SideDetails] = {}
        self._pending_focus_username_cf: str | None = None
        self._looky_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg'))

        layout = QVBoxLayout(self)

        top_bar = QHBoxLayout()
        self._summary_label = QLabel()
        self._summary_label.setWordWrap(True)
        top_bar.addWidget(self._summary_label, stretch=1)

        self._include_disabled_checkbox = QCheckBox('Include disabled databases')
        self._include_disabled_checkbox.setToolTip('Also scan disabled UserIP databases for account groups split across multiple files')
        self._include_disabled_checkbox.toggled.connect(self.refresh)
        top_bar.addWidget(self._include_disabled_checkbox, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addLayout(top_bar)

        self._tree, self._edit_selected_usernames, self._edit_selected_note = create_configured_resolver_tree(
            layout,
            ResolverTreeCallbacks(self._show_context_menu, self._update_buttons, self._on_item_changed, self._edit_selected, self._delete_selected),
        )

        buttons_layout = QHBoxLayout()

        self._consolidate_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'check.svg')), ' Move Group Here…')
        self._consolidate_button.setAutoDefault(False)
        self._consolidate_button.setToolTip("Move all entries of this account group from other databases into the selected entry's database")
        self._consolidate_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._consolidate_button.clicked.connect(self._consolidate_into_selected)
        buttons_layout.addWidget(self._consolidate_button)

        self._ungroup_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-round-x.svg')), ' Ungroup…')
        self._ungroup_button.setAutoDefault(False)
        self._ungroup_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._ungroup_button.clicked.connect(self._ungroup_selected)
        buttons_layout.addWidget(self._ungroup_button)

        self._edit_button, self._delete_button = create_resolver_tail_buttons(
            buttons_layout,
            on_edit=self._edit_selected,
            on_delete=self._delete_selected,
            on_close=on_close,
        )

        layout.addLayout(buttons_layout)

    @property
    def group_count(self) -> int:
        """Return the number of currently listed split account groups."""
        return len(self._groups)

    @property
    def is_editing(self) -> bool:
        """Return True while an inline cell editor is open on the tree."""
        return self._tree.state() == QAbstractItemView.State.EditingState

    def focus_on_username(self, username: str | None) -> None:
        """Select the first split group containing *username*, if any."""
        self._pending_focus_username_cf = username.strip().casefold() if username is not None and username.strip() else None
        self.refresh()

    def _format_db_label(self, db_path: Path) -> str:
        name = format_userip_db_display_name(db_path)
        return f'{name} (disabled)' if db_path in self._disabled_dbs else name

    def _selected_side(self) -> tuple[UserIPAccountGroup, _SplitSide] | None:
        return selected_resolver_side_row(self._tree, self._side_rows)

    def refresh(self, *_args: object) -> None:
        """Rebuild the split account groups tree from the current UserIP databases."""
        prev = self._selected_side()
        prev_key = (prev[1].db_path, prev[1].entry) if prev is not None else None
        focus_cf = self._pending_focus_username_cf
        self._pending_focus_username_cf = None

        self._groups, self._disabled_dbs = collect_split_account_groups(include_disabled=self._include_disabled_checkbox.isChecked())
        entries_by_db: dict[Path, list[UserIPEntryModel]] = {}
        self._side_rows = []
        self._details_by_side = {}
        sides_per_group: list[list[_SplitSide]] = []

        for group in self._groups:
            group_sides = _build_group_sides(group)
            for side in group_sides:
                if side.db_path not in entries_by_db:
                    entries_by_db[side.db_path] = load_userip_database_model(side.db_path).entries
                self._side_rows.append((group, side))
                self._details_by_side[side] = _aggregate_split_side(entries_by_db[side.db_path], side)
            sides_per_group.append(group_sides)

        item_to_select: QTreeWidgetItem | None = None
        row_cursor = 0
        scroll_value = self._tree.verticalScrollBar().value() if focus_cf is None else None
        with QSignalBlocker(self._tree):
            self._tree.clear()
            for idx, (group, group_sides) in enumerate(zip(self._groups, sides_per_group, strict=True), start=1):
                db_names = ' vs '.join(self._format_db_label(p) for p in group.databases)
                n_entries = len(group.entry_keys)
                group_item = add_resolver_group_header(
                    self._tree,
                    f'Group {idx}: {", ".join(group.usernames)}  —  {db_names} ({n_entries} {pluralize(n_entries, "entry", "entries")})',
                )

                for side in group_sides:
                    details = self._details_by_side.get(side) or SideDetails()
                    side_item = QTreeWidgetItem()
                    populate_resolver_side_item(side_item, self._format_db_label(side.db_path), side.entry, details, self._looky_icon)
                    side_item.setFlags(side_item.flags() | Qt.ItemFlag.ItemIsEditable)
                    side_item.setData(0, SIDE_ROLE, row_cursor)
                    row_cursor += 1
                    group_item.addChild(side_item)
                    if item_to_select is None and (
                        (focus_cf is not None and focus_cf in group.usernames_cf)
                        or (focus_cf is None and (side.db_path, side.entry) == prev_key)
                    ):
                        item_to_select = side_item

        finish_resolver_tree_refresh(self._tree, item_to_select, scroll_value=scroll_value)

        count = len(self._groups)
        if count:
            total_entries = sum(len(g.entry_keys) for g in self._groups)
            self._summary_label.setText(
                f'{count} split account group{pluralize(count)} ({total_entries} {pluralize(total_entries, "entry", "entries")}) found. '
                'An account group spread across multiple databases suppresses username matching and cross-database alt syncing.\n'
                'Select an entry to consolidate the whole group into its database, or ungroup unrelated accounts.',
            )
        else:
            self._summary_label.setText('No split account groups. Every account group belongs to a single database.')

        self._update_buttons()
        self._on_count_changed(count)

    def _update_buttons(self) -> None:
        selection = self._selected_side()
        has_side = selection is not None
        can_ungroup = selection is not None and len(selection[0].usernames) >= MIN_GROUP_USERNAMES
        self._consolidate_button.setEnabled(has_side)
        self._ungroup_button.setEnabled(can_ungroup)
        self._ungroup_button.setToolTip(
            'Unlink false-positive or separate accounts from this group so they can remain in different databases'
            if can_ungroup
            else 'Ungrouping requires at least 2 distinct usernames in the group (this group uses the same username across databases)',
        )
        self._edit_button.setEnabled(has_side)
        self._delete_button.setEnabled(has_side)

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        edited = resolver_edited_side_details(item, column, self._side_rows, self._details_by_side)
        if edited is None:
            return
        side, details = edited
        db_label = self._format_db_label(side.db_path)
        if column == USERNAMES_COLUMN:
            self._apply_usernames_edit(item, side, details, db_label)
        else:
            self._apply_notes_edit(item, side, details, db_label)

    def _apply_usernames_edit(self, item: QTreeWidgetItem, side: _SplitSide, details: SideDetails, db_label: str) -> None:
        new_usernames = parse_deduped_usernames_cell(item.text(USERNAMES_COLUMN))
        if not new_usernames or new_usernames == details.usernames:
            with QSignalBlocker(self._tree):
                populate_resolver_side_item(item, db_label, side.entry, details, self._looky_icon)
            return
        if _rewrite_split_side_usernames(side, new_usernames) is None:
            QMessageBox.warning(self, TITLE, 'The selected entry no longer exists in its database, nothing was changed.')
            QTimer.singleShot(0, self.refresh)
            return
        refresh_userip_and_wake_renderer()
        QTimer.singleShot(0, self.refresh)

    def _apply_notes_edit(self, item: QTreeWidgetItem, side: _SplitSide, details: SideDetails, db_label: str) -> None:
        new_note = item.text(NOTES_COLUMN).strip()
        if new_note == ', '.join(details.notes):
            with QSignalBlocker(self._tree):
                populate_resolver_side_item(item, db_label, side.entry, details, self._looky_icon)
            return
        updated_details = _rewrite_split_side_notes(side, new_note)
        if updated_details is None:
            QMessageBox.warning(self, TITLE, 'The selected entry no longer exists in its database, nothing was changed.')
            QTimer.singleShot(0, self.refresh)
            return
        self._details_by_side[side] = updated_details
        with QSignalBlocker(self._tree):
            populate_resolver_side_item(item, db_label, side.entry, updated_details, self._looky_icon)
        refresh_userip_and_wake_renderer()

    def _format_side_html(self, side: _SplitSide) -> str:
        details = self._details_by_side.get(side)
        usernames_text = ', '.join(details.usernames) if details and details.usernames else NO_USERNAME_TEXT
        return f'<li>"{html.escape(self._format_db_label(side.db_path))}": {html.escape(usernames_text)} = {html.escape(side.entry)}</li>'

    def _consolidate_group_into(self, group: UserIPAccountGroup, target_db_path: Path) -> None:
        moving_sides = [side for g, side in self._side_rows if g == group and side.db_path != target_db_path]
        if not moving_sides:
            return
        target_label = html.escape(self._format_db_label(target_db_path))
        items_html = ''.join(self._format_side_html(s) for s in moving_sides)
        entry_count = sum(1 for db_path, _, _ in group.entry_keys if db_path != target_db_path)
        entry_word = pluralize(entry_count, 'entry', 'entries')
        prompt = f'Move the following {entry_count} {entry_word} into <b>"{target_label}"</b> so this account group resides in a single database?<ul>{items_html}</ul>Continue?'
        box = QMessageBox(QMessageBox.Icon.Question, TITLE, prompt, parent=self)
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.Yes)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        if move_userip_entries_to_database(target_db_path, entry_keys=group.entry_keys).moved_by_db:
            self.refresh()

    def _consolidate_into_selected(self) -> None:
        selection = self._selected_side()
        if selection is not None:
            group, side = selection
            self._consolidate_group_into(group, side.db_path)

    def _move_single_side(self, side: _SplitSide, target_db_path: Path) -> None:
        keys = frozenset((side.db_path, u_cf, side.entry) for u_cf in side.usernames_cf)
        if move_userip_entries_to_database(target_db_path, entry_keys=keys).moved_by_db:
            self.refresh()

    def _ungroup_selected(self) -> None:
        selection = self._selected_side()
        if selection is None:
            return
        group, side = selection
        members = list(group.usernames)
        if len(members) < MIN_GROUP_USERNAMES:
            return
        selected_ips = [side.entry] if is_single_ipv4(side.entry) else None
        dlg = SelectUsernamesDialog(
            self,
            members,
            UsernameSelectionConfig(
                title='Ungroup Usernames',
                instructions='Select username(s) to unlink from this account group (prevents false-positive grouping):',
                action_button_text='Ungroup',
                multiple=True,
                default_checked=False,
                selected_ips=selected_ips,
            ),
        )
        if dlg.exec() != SelectUsernamesDialog.DialogCode.Accepted:
            return
        chosen = dlg.selected_usernames()
        if chosen:
            ungroup_usernames(chosen, members)
            refresh_userip_and_wake_renderer()
            self.refresh()

    def _edit_selected(self) -> None:
        prompted = prompt_selected_resolver_ip(self, self._selected_side(), lambda s: s.entry)
        if prompted is None:
            return
        side, new_entry = prompted
        if not _rewrite_split_side_ip(side, new_entry):
            QMessageBox.warning(self, TITLE, 'The selected entry no longer exists in its database, nothing was changed.')
            self.refresh()
            return
        refresh_userip_and_wake_renderer()
        self.refresh()

    def _delete_selected(self) -> None:
        selection = self._selected_side()
        if selection is None:
            return
        _, side = selection
        items_html = self._format_side_html(side)
        box = QMessageBox(QMessageBox.Icon.Warning, TITLE, f'Delete the following entry?<ul>{items_html}</ul>Continue?', parent=self)
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        keys = frozenset((side.db_path, u_cf, side.entry) for u_cf in side.usernames_cf)
        _delete_entry_keys(keys)
        self.refresh()

    def _show_context_menu(self, position: QPoint) -> None:
        selection = select_resolver_item_at(self._tree, position, self._side_rows)
        if selection is None:
            return
        group, side = selection
        details = self._details_by_side.get(side) or SideDetails()

        menu = create_styled_context_menu(self)
        single_ip = populate_resolver_common_menu_prefix(menu, self._tree, db_path=side.db_path, entry_ip=side.entry, details=details)
        self._populate_resolution_menu(menu, group, side, details, single_ip=single_ip)

        if viewport := self._tree.viewport():
            menu.popup(viewport.mapToGlobal(position))

    def _populate_resolution_menu(self, menu: QMenu, group: UserIPAccountGroup, side: _SplitSide, details: SideDetails, *, single_ip: bool) -> None:
        all_db_paths = [json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()]
        add_icon_menu_action(menu, 'check.svg', 'Move Group Here…', self._consolidate_into_selected)

        move_group_menu = create_styled_context_menu(menu, title=f'Move Group to Database ({len(group.entry_keys)})', icon_name='box.svg')
        if not populate_userip_databases_menu(
            move_group_menu,
            all_db_paths,
            tooltip=f'Move all {len(group.entry_keys)} entries in this account group to this database.',
            handler_factory=lambda target_path: lambda: self._consolidate_group_into(group, target_path),
            disabled_path=None,
        ):
            move_group_menu.setEnabled(False)
        menu.addMenu(move_group_menu)

        move_entry_menu = create_styled_context_menu(menu, title='Move This Entry to Database', icon_name='box.svg')
        if not populate_userip_databases_menu(
            move_entry_menu,
            all_db_paths,
            tooltip='Move only this entry to this database.',
            handler_factory=lambda target_path: lambda: self._move_single_side(side, target_path),
            disabled_path=side.db_path,
        ):
            move_entry_menu.setEnabled(False)
        menu.addMenu(move_entry_menu)

        if len(group.usernames) >= MIN_GROUP_USERNAMES:
            add_icon_menu_action(menu, 'user-round-x.svg', 'Ungroup…', self._ungroup_selected)

        menu.addSeparator()
        rename_action = add_icon_menu_action(menu, 'square-pen.svg', 'Rename', self._edit_selected_usernames)
        rename_action.setShortcut('F2')
        add_icon_menu_action(menu, 'square-pen.svg', 'Edit IP…' if single_ip else 'Edit Range…', self._edit_selected)
        add_icon_menu_action(menu, 'notepad-text.svg', 'Edit Note…' if details.notes else 'Add Note…', self._edit_selected_note)

        populate_resolver_ip_tools_menu(self, menu, side.entry, single_ip=single_ip)

        menu.addSeparator()
        del_action = add_icon_menu_action(menu, 'remove.svg', 'Delete This Entry…', self._delete_selected)
        del_action.setShortcut('Delete')
