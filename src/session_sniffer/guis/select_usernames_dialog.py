"""Unified dialog for selecting username(s) for adding, renaming, or removing UserIP entries."""

from dataclasses import dataclass
from typing import Self

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import (
    COMPACT_BUTTON_STYLESHEET,
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
)
from session_sniffer.guis.utils import SearchHighlightDelegate, apply_search_icon
from session_sniffer.text_utils import pluralize

_MAX_DISPLAY_SELECTED_IPS = 3


@dataclass(frozen=True, slots=True)
class UsernameSelectionConfig:
    """Configuration options for SelectUsernamesDialog."""

    title: str = 'Select Usernames'
    instructions: str | None = None
    action_button_text: str = 'Add'
    multiple: bool = True
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
            layout.addWidget(QLabel(f'Database:  <b>{dialog_config.database}</b>'))

        if dialog_config.selected_ips is not None and dialog_config.selected_ips:
            ips = dialog_config.selected_ips
            ips_text = ', '.join(ips) if len(ips) <= _MAX_DISPLAY_SELECTED_IPS else f'{len(ips)} selected IPs'
            layout.addWidget(QLabel(f'IP address{pluralize(len(ips), plural="es")}:  <b>{ips_text}</b>'))

        if dialog_config.current_username is not None:
            layout.addWidget(QLabel(f'Current:  <b>{dialog_config.current_username}</b>'))

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
        for name in sorted(set(usernames), key=str.lower):
            item = QStandardItem(name)
            if self._multiple:
                item.setCheckable(True)
                item.setCheckState(Qt.CheckState.Unchecked)
            self._list_model.appendRow(item)

        proxy_model = QSortFilterProxyModel(self)
        proxy_model.setSourceModel(self._list_model)
        proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy = proxy_model

        usernames_list = QListView()
        usernames_list.setModel(self._proxy)
        usernames_list.setSelectionMode(
            QListView.SelectionMode.ExtendedSelection if self._multiple else QListView.SelectionMode.SingleSelection
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
        if self._double_clicked_username:
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
