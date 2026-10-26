"""Unified dialog for selecting username(s) for adding, renaming, or removing UserIP entries."""

import html
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self, override

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPersistentModelIndex, QSortFilterProxyModel, QStringListModel, Qt
from PySide6.QtGui import QFocusEvent, QIcon, QKeyEvent, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.stylesheets import (
    COMPACT_BUTTON_STYLESHEET,
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
)
from session_sniffer.guis.utils import apply_search_icon, scale_by_ui
from session_sniffer.networking.looky_system import get_cached_looky_usernames
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.userip_loader import get_cached_userip_usernames
from session_sniffer.rendering_core.modmenu_logs_parser import ModMenuLogsParser
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import pluralize, split_usernames
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

_MAX_DISPLAY_SELECTED_IPS = 3
_USERNAME_COMPLETER_MAX_VISIBLE_ITEMS = 12
_INLINE_SUGGESTIONS_MAX_VISIBLE_ROWS = 8


def collect_known_usernames() -> list[str]:
    """Collect deduplicated known usernames from cached UserIP databases and session players."""
    seen_casefolded: set[str] = set()
    usernames: list[str] = []

    def _add_name(raw_name: str) -> None:
        cleaned = raw_name.strip()
        if not cleaned:
            return
        folded = cleaned.casefold()
        if folded not in seen_casefolded:
            seen_casefolded.add(folded)
            usernames.append(cleaned)

    include_looky = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
    for name in get_cached_userip_usernames():
        _add_name(name)
    for modmenu_names in ModMenuLogsParser.get_all_ip_to_usernames_map().values():
        for name in modmenu_names:
            _add_name(name)
    if include_looky:
        for name in get_cached_looky_usernames():
            _add_name(name)
    for player in (*PlayersRegistry.get_all_players(), *SessionTracker.get_all_snapshot_players()):
        if player.userip is not None:
            for name in player.userip.usernames:
                _add_name(name)
        if player.ps3_username is not None and player.ps3_username:
            _add_name(player.ps3_username)
        if player.mod_menus is not None:
            for name in player.mod_menus.usernames:
                _add_name(name)
        if include_looky:
            with player.looky_system.lock:
                looky_names = list(player.looky_system.usernames) if player.looky_system.is_initialized else []
            for name in looky_names:
                _add_name(name)
        for name in player.usernames:
            _add_name(name)

    usernames.sort(key=lambda name: (name.casefold(), name))
    return usernames


def attach_username_completer(line_edit: QLineEdit) -> QCompleter:
    """Attach a case-insensitive substring `QCompleter` populated with known usernames to `line_edit`."""
    completer = QCompleter(collect_known_usernames(), line_edit)
    completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
    completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    completer.setFilterMode(Qt.MatchFlag.MatchContains)
    completer.setMaxVisibleItems(_USERNAME_COMPLETER_MAX_VISIBLE_ITEMS)
    popup = completer.popup()
    if popup is not None:
        popup.setObjectName('CompleterPopup')
    line_edit.setCompleter(completer)
    return completer


def configure_username_cell_editor(
    editor: QWidget,
    index: QModelIndex | QPersistentModelIndex,
    username_column: int = 1,
) -> None:
    """Attach username autocomplete when inline-editing a cell in `username_column`."""
    if index.column() == username_column and isinstance(editor, QLineEdit):
        attach_username_completer(editor)


class _SuggestionLineEdit(QLineEdit):
    """Line edit that delegates Up/Down arrow keys to an inline suggestion list and notifies on focus."""

    def __init__(
        self,
        initial_text: str,
        on_navigate: Callable[[int], bool],
        on_focused: Callable[[_SuggestionLineEdit], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(initial_text, parent)
        self._on_navigate = on_navigate
        self._on_focused = on_focused

    @override
    def focusInEvent(self, event: QFocusEvent) -> None:
        super().focusInEvent(event)
        self._on_focused(self)

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if key in (Qt.Key.Key_Down, Qt.Key.Key_Up) and self._on_navigate(1 if key == Qt.Key.Key_Down else -1):
            event.accept()
            return
        super().keyPressEvent(event)


class _UsernameSuggestionProxyModel(QSortFilterProxyModel):
    """Case-insensitive substring filter that excludes usernames already entered in other rows."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._query_cf: str = ''
        self._excluded_cf: set[str] = set()

    def set_query_and_excluded(self, query: str, excluded_cf: set[str]) -> None:
        """Update the active substring query and excluded casefolded usernames."""
        self._query_cf = query.casefold()
        self._excluded_cf = excluded_cf
        self.invalidateFilter()

    @override
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex) -> bool:
        if not self._query_cf:
            return False
        source_model = self.sourceModel()
        index = source_model.index(source_row, 0, source_parent)
        value = source_model.data(index, Qt.ItemDataRole.DisplayRole)
        if not isinstance(value, str):
            return False
        value_cf = value.casefold()
        return self._query_cf in value_cf and value_cf not in self._excluded_cf


def _run_username_input_dialog(
    parent: QWidget,
    title: str,
    label: str | Callable[[int], str],
    initial_usernames: Sequence[str],
    *,
    allow_multiple: bool,
) -> tuple[list[str], bool]:
    """Run the username input dialog supporting either a single field or dynamic multi-username rows."""
    dialog = QDialog(parent)
    dialog.setWindowModality(Qt.WindowModality.WindowModal)
    dialog.setWindowTitle(title)
    dialog.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)
    dialog.setMinimumWidth(scale_by_ui(380))

    layout = QVBoxLayout(dialog)

    initial_label = label if isinstance(label, str) else label(1)
    prompt_label = QLabel(initial_label, dialog)
    layout.addWidget(prompt_label)

    rows_layout = QVBoxLayout()
    rows_layout.setContentsMargins(0, 0, 0, 0)
    rows_layout.setSpacing(6)
    layout.addLayout(rows_layout)

    source_model = QStringListModel(collect_known_usernames(), dialog)
    proxy_model = _UsernameSuggestionProxyModel(dialog)
    proxy_model.setSourceModel(source_model)

    row_entries: list[tuple[QWidget, _SuggestionLineEdit, QPushButton | None]] = []
    active_line_edit: _SuggestionLineEdit | None = None
    active_query = ''

    suggestions_list = QListView(dialog)
    suggestions_list.setModel(proxy_model)
    suggestions_list.setSelectionMode(QListView.SelectionMode.SingleSelection)
    suggestions_list.setEditTriggers(QListView.EditTrigger.NoEditTriggers)
    suggestions_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    suggestions_list.setAlternatingRowColors(True)
    suggestions_list.setUniformItemSizes(True)
    suggestions_list.setWordWrap(False)
    suggestions_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    suggestions_list.setVerticalScrollMode(QListView.ScrollMode.ScrollPerPixel)
    suggestions_list.setItemDelegate(SearchHighlightDelegate(suggestions_list, lambda: active_query))
    suggestions_list.setVisible(False)

    add_row_button: QPushButton | None = None
    if allow_multiple:
        add_row_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')), ' Add another username', dialog)
        add_row_button.setAutoDefault(False)
        add_row_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_row_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        add_row_button.setToolTip('Add another username field.')
        layout.addWidget(add_row_button)

    layout.addWidget(suggestions_list)

    button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dialog)
    button_box.accepted.connect(dialog.accept)
    button_box.rejected.connect(dialog.reject)
    layout.addWidget(button_box)
    ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)

    def _sync_dialog_height() -> None:
        suggestions_list.updateGeometry()
        rows_layout.invalidate()
        layout.invalidate()
        layout.activate()
        target_width = max(dialog.width(), layout.totalSizeHint().width(), scale_by_ui(380))
        target_height = layout.totalHeightForWidth(target_width) if layout.hasHeightForWidth() else layout.totalSizeHint().height()
        target_height = max(target_height, layout.totalMinimumSize().height())
        dialog.setFixedHeight(target_height)
        dialog.resize(target_width, target_height)

    def _update_row_placeholders_and_buttons() -> None:
        total = len(row_entries)
        row_tokens = [split_usernames(edit.text()) for _, edit, _ in row_entries]
        if allow_multiple:
            all_non_empty = bool(row_tokens) and all(row_tokens)
            flat_tokens = [token for tokens in row_tokens for token in tokens]
            all_unique = len({token.casefold() for token in flat_tokens}) == len(flat_tokens)
            can_proceed = all_non_empty and all_unique
            effective_count = max(total, len(flat_tokens), 1)
            dialog.setWindowTitle(f'{title}s' if effective_count > 1 and title.endswith('Username') else title)
            if not isinstance(label, str):
                prompt_label.setText(label(effective_count))
        else:
            can_proceed = bool(row_tokens) and all(
                len(tokens) == 1 and tokens[0] == edit.text().strip()
                for (_, edit, _), tokens in zip(row_entries, row_tokens, strict=True)
            )

        for idx, (_, edit, remove_btn) in enumerate(row_entries, start=1):
            edit.setPlaceholderText(f'Username {idx}…' if allow_multiple and total > 1 else 'Enter username…')
            if remove_btn is not None:
                remove_btn.setToolTip('Remove this username field' if total > 1 else 'Clear username')
                remove_btn.setEnabled(total > 1 or bool(edit.text()))

        if add_row_button is not None:
            add_row_button.setEnabled(can_proceed)
        ok_button.setEnabled(can_proceed)

    def _apply_chosen_suggestion(target_edit: _SuggestionLineEdit, chosen: str) -> None:
        raw_text = target_edit.text()
        if allow_multiple and ',' in raw_text:
            prefix_tokens = split_usernames(raw_text.rsplit(',', 1)[0])
            target_edit.setText(f'{", ".join(prefix_tokens)}, {chosen}' if prefix_tokens else chosen)
        else:
            target_edit.setText(chosen)

    def _refresh_suggestions_for(target_edit: _SuggestionLineEdit) -> None:
        nonlocal active_line_edit, active_query
        active_line_edit = target_edit
        raw_text = target_edit.text()
        if allow_multiple and ',' in raw_text:
            prefix_part, last_part = raw_text.rsplit(',', 1)
            active_query = last_part.strip()
            same_row_prefix_tokens = split_usernames(prefix_part)
        else:
            active_query = raw_text.strip()
            same_row_prefix_tokens = []
        if not active_query:
            if suggestions_list.isVisible():
                suggestions_list.setVisible(False)
                _sync_dialog_height()
            return

        excluded_cf: set[str] = {
            *(token.casefold() for token in same_row_prefix_tokens),
            *(
                token.casefold()
                for _, other_edit, _ in row_entries
                if other_edit is not target_edit
                for token in split_usernames(other_edit.text())
            ),
        }
        proxy_model.set_query_and_excluded(active_query, excluded_cf)
        match_count = proxy_model.rowCount()
        if match_count <= 0:
            if suggestions_list.isVisible():
                suggestions_list.setVisible(False)
                _sync_dialog_height()
            return

        suggestions_list.clearSelection()
        visible_rows = min(match_count, _INLINE_SUGGESTIONS_MAX_VISIBLE_ROWS)
        row_height = max(suggestions_list.sizeHintForRow(0), scale_by_ui(20))
        frame_margins = suggestions_list.frameWidth() * 2
        suggestions_list.setFixedHeight(row_height * visible_rows + frame_margins)
        suggestions_list.setVisible(True)
        if viewport := suggestions_list.viewport():
            viewport.update()
        _sync_dialog_height()

    def _navigate_suggestions(step: int) -> bool:
        if not suggestions_list.isVisible() or active_line_edit is None:
            return False
        row_count = proxy_model.rowCount()
        if row_count <= 0:
            return False
        selection_model = suggestions_list.selectionModel()
        if not selection_model:
            return False
        selected_indexes = selection_model.selectedIndexes()
        next_row = (0 if step > 0 else row_count - 1) if not selected_indexes else (selected_indexes[0].row() + step) % row_count
        target_index = proxy_model.index(next_row, 0)
        if not target_index.isValid():
            return False
        selection_model.select(target_index, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        suggestions_list.setCurrentIndex(target_index)
        suggestions_list.scrollTo(target_index)
        chosen = proxy_model.data(target_index, Qt.ItemDataRole.DisplayRole)
        if isinstance(chosen, str):
            _apply_chosen_suggestion(active_line_edit, chosen)
        return True

    def _on_line_edit_focused(focused_edit: _SuggestionLineEdit) -> None:
        if focused_edit is not active_line_edit:
            _refresh_suggestions_for(focused_edit)

    def _add_row(initial_value: str = '', *, focus: bool = False) -> _SuggestionLineEdit:
        row_widget = QWidget(dialog)
        row_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        row_hbox = QHBoxLayout(row_widget)
        row_hbox.setContentsMargins(0, 0, 0, 0)
        row_hbox.setSpacing(6)

        edit = _SuggestionLineEdit(initial_value, _navigate_suggestions, _on_line_edit_focused, row_widget)

        def _on_row_text_edited(_text: str) -> None:
            _refresh_suggestions_for(edit)

        def _on_row_text_changed(_text: str) -> None:
            _update_row_placeholders_and_buttons()

        edit.textEdited.connect(_on_row_text_edited)
        edit.textChanged.connect(_on_row_text_changed)
        row_hbox.addWidget(edit, stretch=1)

        remove_btn: QPushButton | None = None
        if allow_multiple:
            remove_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), '', row_widget)
            remove_btn.setAutoDefault(False)
            remove_btn.setMaximumWidth(scale_by_ui(36))
            remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)

            def _on_remove_clicked() -> None:
                if len(row_entries) <= 1:
                    edit.clear()
                    edit.setFocus()
                    _refresh_suggestions_for(edit)
                    return
                for idx, (widget, row_edit, _) in enumerate(row_entries):
                    if row_edit is edit:
                        row_entries.pop(idx)
                        rows_layout.removeWidget(widget)
                        widget.hide()
                        widget.setParent(None)
                        widget.deleteLater()
                        next_idx = min(idx, len(row_entries) - 1)
                        next_edit = row_entries[next_idx][1]
                        _update_row_placeholders_and_buttons()
                        next_edit.setFocus()
                        _refresh_suggestions_for(next_edit)
                        _sync_dialog_height()
                        break

            remove_btn.clicked.connect(_on_remove_clicked)
            row_hbox.addWidget(remove_btn)

        row_entries.append((row_widget, edit, remove_btn))
        rows_layout.addWidget(row_widget)
        if dialog.isVisible():
            row_widget.show()
        _update_row_placeholders_and_buttons()
        if focus:
            edit.setFocus()
            _refresh_suggestions_for(edit)
            _sync_dialog_height()
        return edit

    seed_values = [name for name in initial_usernames if name.strip()] or ['']
    if not allow_multiple:
        seed_values = [seed_values[0]]
    for seed in seed_values:
        _add_row(seed)

    first_edit = row_entries[0][1]
    active_line_edit = first_edit
    first_edit.selectAll()

    if add_row_button is not None:
        add_row_button.clicked.connect(lambda: _add_row('', focus=True))

    def _on_suggestion_clicked(index: QModelIndex) -> None:
        chosen = proxy_model.data(index, Qt.ItemDataRole.DisplayRole)
        if isinstance(chosen, str) and active_line_edit is not None:
            _apply_chosen_suggestion(active_line_edit, chosen)
            active_line_edit.setFocus()

    def _on_suggestion_double_clicked(index: QModelIndex) -> None:
        chosen = proxy_model.data(index, Qt.ItemDataRole.DisplayRole)
        if isinstance(chosen, str) and active_line_edit is not None:
            _apply_chosen_suggestion(active_line_edit, chosen)
            if ok_button.isEnabled():
                dialog.accept()

    suggestions_list.clicked.connect(_on_suggestion_clicked)
    suggestions_list.doubleClicked.connect(_on_suggestion_double_clicked)

    accepted = dialog.exec() == QDialog.DialogCode.Accepted
    collected = dedup_preserve_order(
        token for _, edit, _ in row_entries for token in split_usernames(edit.text())
    )
    return collected, accepted


def prompt_username_input(
    parent: QWidget,
    title: str,
    label: str,
    initial_text: str = '',
) -> tuple[str, bool]:
    """Prompt the user for a single username with an inline expandable real-time suggestion list."""
    usernames, accepted = _run_username_input_dialog(
        parent,
        title,
        label,
        [initial_text] if initial_text else [],
        allow_multiple=False,
    )
    return (usernames[0] if usernames else ''), accepted


def prompt_usernames_input(
    parent: QWidget,
    title: str,
    label: str | Callable[[int], str],
    initial_usernames: Sequence[str] | None = None,
) -> tuple[list[str], bool]:
    """Prompt the user for one or more usernames using dynamic input rows and real-time suggestions."""
    return _run_username_input_dialog(
        parent,
        title,
        label,
        initial_usernames or (),
        allow_multiple=True,
    )


@dataclass(frozen=True, slots=True)
class UsernameSelectionConfig:
    """Configuration options for SelectUsernamesDialog."""

    title: str = 'Select Usernames'
    instructions: str | None = None
    action_button_text: str = 'Add'
    multiple: bool = True
    default_checked: bool = False
    allow_custom: bool = False
    database: str | None = None
    selected_ips: list[str] | None = None
    current_username: str | None = None


class SelectUsernamesDialog(QDialog):
    """Dialog for selecting username(s) for adding, renaming, or removing UserIP entries."""

    def __init__(
        self,
        parent: QWidget | None,
        usernames: list[str],
        config: UsernameSelectionConfig | None = None,
    ) -> None:
        """Build the username selection dialog."""
        super().__init__(parent)
        dialog_config = config or UsernameSelectionConfig()
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(f'{dialog_config.title} - {TITLE}')
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)
        self.setMinimumSize(340, 420)
        self.resize(380, 480)

        self._multiple: bool = dialog_config.multiple
        self._action_button_text: str = dialog_config.action_button_text
        self._total_count: int = len(usernames)
        self._custom_requested: bool = False
        self._double_clicked_username: str | None = None

        layout = QVBoxLayout(self)

        if dialog_config.database is not None:
            layout.addWidget(QLabel(f'Database:  <b>{html.escape(dialog_config.database)}</b>'))

        if dialog_config.selected_ips is not None and dialog_config.selected_ips:
            ip_addresses = dialog_config.selected_ips
            ips_text = ', '.join(ip_addresses) if len(ip_addresses) <= _MAX_DISPLAY_SELECTED_IPS else f'{len(ip_addresses)} selected IPs'
            layout.addWidget(QLabel(f'IP address{pluralize(len(ip_addresses), plural="es")}:  <b>{html.escape(ips_text)}</b>'))

        if dialog_config.current_username is not None:
            layout.addWidget(QLabel(f'Current:  <b>{html.escape(dialog_config.current_username)}</b>'))

        instructions = dialog_config.instructions if dialog_config.instructions is not None else f'Select username{pluralize(len(usernames))}:'
        layout.addWidget(QLabel(instructions))

        self._search = QLineEdit()
        self._search.setPlaceholderText('Filter usernames…')
        apply_search_icon(self._search)
        layout.addWidget(self._search)

        if self._multiple:
            quick_select_row = QHBoxLayout()
            select_all_button = QPushButton('Select All')
            select_all_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
            select_all_button.setCursor(Qt.CursorShape.PointingHandCursor)
            select_all_button.clicked.connect(self._select_all)
            quick_select_row.addWidget(select_all_button)

            deselect_all_button = QPushButton('Deselect All')
            deselect_all_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
            deselect_all_button.setCursor(Qt.CursorShape.PointingHandCursor)
            deselect_all_button.clicked.connect(self._deselect_all)
            quick_select_row.addWidget(deselect_all_button)
            quick_select_row.addStretch()
            layout.addLayout(quick_select_row)

        self._list_model = QStandardItemModel()
        initial_check_state = Qt.CheckState.Checked if dialog_config.default_checked else Qt.CheckState.Unchecked
        for name in sorted(set(usernames), key=str.lower):
            item = QStandardItem(name)
            if self._multiple:
                item.setCheckable(True)
                item.setCheckState(initial_check_state)
            self._list_model.appendRow(item)

        proxy_model = QSortFilterProxyModel(self)
        proxy_model.setSourceModel(self._list_model)
        proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy = proxy_model

        usernames_list = QListView()
        usernames_list.setModel(self._proxy)
        usernames_list.setSelectionMode(
            QListView.SelectionMode.ExtendedSelection if self._multiple else QListView.SelectionMode.SingleSelection,
        )
        usernames_list.setAlternatingRowColors(True)
        usernames_list.setWordWrap(False)
        usernames_list.setItemDelegate(SearchHighlightDelegate(usernames_list, self._search.text))
        usernames_list.setHorizontalScrollMode(QListView.ScrollMode.ScrollPerPixel)
        usernames_list.setVerticalScrollMode(QListView.ScrollMode.ScrollPerPixel)
        self._list = usernames_list
        layout.addWidget(self._list, stretch=1)

        self._search.textChanged.connect(self._on_search_changed)
        self._list.doubleClicked.connect(self._on_double_clicked)
        if self._multiple:
            self._list_model.itemChanged.connect(self._on_item_changed)
        if selection_model := self._list.selectionModel():
            selection_model.selectionChanged.connect(self._on_selection_changed)

        button_row = QHBoxLayout()

        if dialog_config.allow_custom:
            custom_button = QPushButton('Custom…')
            custom_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            custom_button.setCursor(Qt.CursorShape.PointingHandCursor)
            custom_button.setToolTip('Enter a custom username manually instead.')
            custom_button.clicked.connect(self._on_custom_clicked)
            button_row.addWidget(custom_button)

        button_row.addStretch()

        self._action_button = QPushButton(self._action_button_text)
        self._action_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._action_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._action_button.setEnabled(False)
        self._action_button.clicked.connect(self.accept)
        button_row.addWidget(self._action_button)

        dismiss_button = QPushButton('Cancel')
        dismiss_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        dismiss_button.setCursor(Qt.CursorShape.PointingHandCursor)
        dismiss_button.clicked.connect(self.reject)
        button_row.addWidget(dismiss_button)

        layout.addLayout(button_row)

        if not self._multiple and self._list_model.rowCount() > 0:
            first_index = self._proxy.index(0, 0)
            if first_index.isValid() and (selection_model := self._list.selectionModel()):
                selection_model.select(first_index, QItemSelectionModel.SelectionFlag.ClearAndSelect)
                self._list.setCurrentIndex(first_index)

        self._update_action_button()

    @classmethod
    def for_add(
        cls,
        parent: QWidget | None,
        usernames: list[str],
        database: str | None = None,
        selected_ips: list[str] | None = None,
    ) -> Self:
        """Create a dialog configured for picking username(s) to add to UserIP."""
        config = UsernameSelectionConfig(
            title='Select Usernames',
            instructions=f'Multiple usernames found. Select the username{pluralize(len(usernames))} to add:',
            action_button_text='Add',
            multiple=True,
            default_checked=True,
            allow_custom=True,
            database=database,
            selected_ips=selected_ips,
        )
        return cls(parent, usernames, config)

    @classmethod
    def for_rename(
        cls,
        parent: QWidget | None,
        usernames: list[str],
        current_username: str,
        database: str,
        ip_address: str,
    ) -> Self:
        """Create a dialog configured for picking which username to rename."""
        config = UsernameSelectionConfig(
            title='Rename Username',
            instructions='Select the username to rename:',
            action_button_text='Rename',
            multiple=False,
            allow_custom=False,
            database=database,
            selected_ips=[ip_address],
            current_username=current_username,
        )
        return cls(parent, usernames, config)

    @classmethod
    def for_remove(
        cls,
        parent: QWidget | None,
        usernames: list[str],
        database: str,
        ip_address: str,
    ) -> Self:
        """Create a dialog configured for picking which username(s) to remove."""
        config = UsernameSelectionConfig(
            title='Remove Username',
            instructions=f'Select username{pluralize(len(usernames))} to remove:',
            action_button_text='Remove',
            multiple=True,
            allow_custom=False,
            database=database,
            selected_ips=[ip_address],
        )
        return cls(parent, usernames, config)

    def _on_search_changed(self, search_text: str) -> None:
        self._proxy.setFilterFixedString(search_text)
        if viewport := self._list.viewport():
            viewport.update()

    def _select_all(self) -> None:
        model = self._list_model
        for row_index in range(model.rowCount()):
            model.item(row_index).setCheckState(Qt.CheckState.Checked)

    def _deselect_all(self) -> None:
        model = self._list_model
        for row_index in range(model.rowCount()):
            model.item(row_index).setCheckState(Qt.CheckState.Unchecked)
        if selection_model := self._list.selectionModel():
            selection_model.clearSelection()

    def _on_item_changed(self, _item: QStandardItem) -> None:
        self._update_action_button()

    def _on_selection_changed(self, *_args: object) -> None:
        self._update_action_button()

    def _update_action_button(self) -> None:
        if self._multiple:
            checked_count = len(self._get_checked_usernames())
            if checked_count > 0:
                self._action_button.setEnabled(True)
                self._action_button.setText(f'{self._action_button_text} ({checked_count})' if checked_count > 1 else self._action_button_text)
                return

            selected_count = len(self._get_selected_row_usernames())
            if selected_count > 0:
                self._action_button.setEnabled(True)
                self._action_button.setText(f'{self._action_button_text} ({selected_count})' if selected_count > 1 else self._action_button_text)
                return

            self._action_button.setEnabled(False)
            self._action_button.setText(self._action_button_text)
        else:
            has_selection = len(self._get_selected_row_usernames()) > 0
            self._action_button.setEnabled(has_selection)
            self._action_button.setText(self._action_button_text)

    def _on_double_clicked(self, index: QModelIndex) -> None:
        source_index = self._proxy.mapToSource(index)
        self._double_clicked_username = self._list_model.itemFromIndex(source_index).text()
        self.accept()

    def _on_custom_clicked(self) -> None:
        self._custom_requested = True
        self.accept()

    def custom_requested(self) -> bool:
        """Return True if the user requested entering a custom username."""
        return self._custom_requested

    def _get_checked_usernames(self) -> list[str]:
        result: list[str] = []
        for row in range(self._list_model.rowCount()):
            item = self._list_model.item(row)
            if item.checkState() == Qt.CheckState.Checked:
                result.append(item.text())
        return result

    def _get_selected_row_usernames(self) -> list[str]:
        result: list[str] = []
        for index in self._list.selectedIndexes():
            data = self._proxy.data(index, Qt.ItemDataRole.DisplayRole)
            if data:
                result.append(str(data))
        return result

    def selected_usernames(self) -> list[str]:
        """Return the list of selected or checked usernames."""
        if self._double_clicked_username is not None and self._double_clicked_username:
            return [self._double_clicked_username]
        if self._multiple:
            checked = self._get_checked_usernames()
            if checked:
                return checked
            return self._get_selected_row_usernames()
        return self._get_selected_row_usernames()

    def selected_username(self) -> str | None:
        """Return the single selected username, or None if nothing selected."""
        usernames = self.selected_usernames()
        return usernames[0] if usernames else None

    def is_all_selected(self) -> bool:
        """Return True if every username in the list is selected."""
        selected = self.selected_usernames()
        return bool(selected) and len(selected) >= self._total_count
