"""Mixin providing horizontal header context menu and column visibility management."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QMenu, QTableView

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.tables import (
    BANDWIDTH_RATE_STAT_COLUMNS,
    LOCATION_COLUMNS,
    PACKET_STAT_COLUMNS,
    PORT_COLUMNS,
    STATUS_COLUMNS,
)
from session_sniffer.guis.stylesheets import CATEGORY_SUBMENU_CHECKBOX_STYLESHEET, SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import add_column_sizing_actions, size_all_columns_to_fit, size_column_to_fit
from session_sniffer.guis.table_model import GUI_COLUMN_HEADERS_TOOLTIPS
from session_sniffer.guis.utils import PersistentMenu
from session_sniffer.settings.defaults import SETTING_DEFAULTS
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


# Category groupings for the Choose Columns submenu.
# First match wins; columns not matched fall under 'Other'.
_COLUMN_CATEGORY_GROUPS: tuple[tuple[str, frozenset[str]], ...] = (
    ('Session', frozenset({'T. Session Time', 'Session Time', 'Biggest Session Time', 'Lowest Session Time'})),
    (
        'Packets',
        frozenset(
            {
                *PACKET_STAT_COLUMNS,
                'PPS',
                'PPM',
            },
        ),
    ),
    (
        'Bandwidth',
        frozenset(BANDWIDTH_RATE_STAT_COLUMNS),
    ),
    (
        'Network',
        frozenset(
            {
                'Hostname',
                *PORT_COLUMNS,
                *STATUS_COLUMNS,
            },
        ),
    ),
    (
        'Location',
        frozenset(LOCATION_COLUMNS),
    ),
    ('Organization', frozenset({'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN'})),
)


class TableHeaderMenuMixin(QTableView):
    """Mixin that manages header context menu actions and column visibility for SessionTableView."""

    if TYPE_CHECKING:
        is_connected_table: bool

        def _reset_column_sizes(self) -> None:
            """Stub."""

        def setup_static_column_resizing(self) -> None:
            """Stub."""

    def _show_header_context_menu(self, pos: QPoint) -> None:
        """Show a context menu on the column header with sizing and column-visibility actions."""
        toggleable_columns = Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS if self.is_connected_table else Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS

        horizontal_header = self.horizontalHeader()
        clicked_column = horizontal_header.logicalIndexAt(pos)

        clicked_column_name: str | None = None
        if clicked_column >= 0:
            header_label = self.model().headerData(clicked_column, Qt.Orientation.Horizontal)
            if isinstance(header_label, str):
                clicked_column_name = header_label

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        add_column_sizing_actions(menu, self, clicked_column=clicked_column, on_reset=self._reset_column_sizes)

        menu.addSeparator()

        hide_label = f"Hide Column '{clicked_column_name}'" if bool(clicked_column_name) else 'Hide Column'
        hide_column_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye_hide.svg')), hide_label, menu)
        hide_column_action.setEnabled(clicked_column_name is not None and clicked_column_name in toggleable_columns)
        hide_column_action.setToolTip(
            f"Hide the '{clicked_column_name}' column from the table." if bool(clicked_column_name) else 'Hide the selected column from the table.',
        )
        if clicked_column_name is not None:
            hide_column_action.triggered.connect(
                lambda: self._toggle_column_visibility(clicked_column_name, checked=False),
            )
        menu.addAction(hide_column_action)

        choose_columns_menu = PersistentMenu('Choose Columns', menu)
        choose_columns_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')))
        choose_columns_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        choose_columns_menu.setToolTipsVisible(True)
        choose_columns_menu.setToolTip('Choose which columns to show or hide in this table.')

        reset_columns_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'reset.svg')), 'Reset to Default', choose_columns_menu)
        reset_columns_action.setToolTip('Reset column visibility back to default visible columns.')
        reset_columns_action.triggered.connect(self._reset_to_default_columns)
        choose_columns_menu.addAction(reset_columns_action)
        choose_columns_menu.addSeparator()

        select_all_columns_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')), 'Select All', choose_columns_menu)
        select_all_columns_action.setToolTip('Show all available columns in the table.')
        select_all_columns_action.triggered.connect(self._select_all_columns)
        choose_columns_menu.addAction(select_all_columns_action)

        deselect_all_columns_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')), 'Unselect All', choose_columns_menu)
        deselect_all_columns_action.setToolTip('Hide all optional columns from the table.')
        deselect_all_columns_action.triggered.connect(self._deselect_all_columns)
        choose_columns_menu.addAction(deselect_all_columns_action)
        choose_columns_menu.addSeparator()

        # Bucket each toggleable column into its category.
        bucketed: dict[str, list[str]] = {label: [] for label, _ in _COLUMN_CATEGORY_GROUPS}
        bucketed['Other'] = []
        shown_columns = set(
            Settings.gui_columns_connected_shown if self.is_connected_table else Settings.gui_columns_disconnected_shown,
        )
        for column in toggleable_columns:
            placed = False
            for label, members in _COLUMN_CATEGORY_GROUPS:
                if column in members:
                    bucketed[label].append(column)
                    placed = True
                    break
            if not placed:
                bucketed['Other'].append(column)

        for label, _ in (*_COLUMN_CATEGORY_GROUPS, ('Other', frozenset[str]())):
            columns = bucketed[label]
            if not columns:
                continue
            category_menu = PersistentMenu(label, choose_columns_menu)
            category_menu.setStyleSheet(CATEGORY_SUBMENU_CHECKBOX_STYLESHEET)
            category_menu.setToolTipsVisible(True)
            category_menu.setToolTip(f'Toggle columns in the {label} category.')

            column_actions: list[QAction] = []

            select_all_action = QAction('Select All', category_menu)
            select_all_action.setCheckable(True)
            select_all_action.setChecked(True)
            select_all_action.setToolTip(f'Show all columns in the {label} category.')

            def _make_toggle_all_handler(
                target_action: QAction,
                category_columns: list[str],
                actions: list[QAction],
                *,
                select: bool,
            ) -> Callable[[bool], None]:
                def _handler(_checked: bool) -> None:  # noqa: FBT001
                    target_action.setChecked(select)
                    for action_item in actions:
                        action_item.blockSignals(True)  # noqa: FBT003
                        action_item.setChecked(select)
                        action_item.blockSignals(False)  # noqa: FBT003
                    if select:
                        self._select_category_columns(category_columns)
                    else:
                        self._deselect_category_columns(category_columns)

                return _handler

            select_all_action.triggered.connect(
                _make_toggle_all_handler(select_all_action, columns, column_actions, select=True),
            )
            category_menu.addAction(select_all_action)

            deselect_all_action = QAction('Unselect All', category_menu)
            deselect_all_action.setCheckable(True)
            deselect_all_action.setChecked(False)
            deselect_all_action.setToolTip(f'Hide all columns in the {label} category.')

            deselect_all_action.triggered.connect(
                _make_toggle_all_handler(deselect_all_action, columns, column_actions, select=False),
            )
            category_menu.addAction(deselect_all_action)
            category_menu.addSeparator()

            for column_name in columns:
                column_action = QAction(column_name, category_menu)
                column_action.setCheckable(True)
                column_action.setChecked(column_name in shown_columns)
                column_tooltip = GUI_COLUMN_HEADERS_TOOLTIPS.get(column_name)
                if column_tooltip is not None:
                    column_action.setToolTip(column_tooltip)

                def _on_column_toggled(checked: bool, name: str = column_name) -> None:  # noqa: FBT001
                    self._toggle_column_visibility(name, checked=checked)

                column_action.toggled.connect(_on_column_toggled)
                category_menu.addAction(column_action)
                column_actions.append(column_action)
            choose_columns_menu.addMenu(category_menu)

        menu.addMenu(choose_columns_menu)

        menu.popup(horizontal_header.mapToGlobal(pos))

    def _size_column_to_fit(self, column: int) -> None:
        """Resize a single column to fit its contents (header + cell text)."""
        size_column_to_fit(self, column)

    def _size_all_columns_to_fit(self) -> None:
        """Resize every visible column to fit its contents."""
        size_all_columns_to_fit(self)

    def _toggle_column_visibility(self, column_name: str, *, checked: bool) -> None:
        """Toggle a column's visibility and persist the change to settings."""
        shown = set(Settings.gui_columns_connected_shown) if self.is_connected_table else set(Settings.gui_columns_disconnected_shown)

        if checked:
            shown.add(column_name)
        else:
            shown.discard(column_name)

        # Preserve ordering from the toggleable columns tuple
        new_shown = tuple(
            column for column in (Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS if self.is_connected_table else Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS) if column in shown
        )

        if self.is_connected_table:
            Settings.gui_columns_connected_shown = new_shown
        else:
            Settings.gui_columns_disconnected_shown = new_shown

        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()

    def _reset_to_default_columns(self) -> None:
        """Restore the default column visibility and persist the change to settings."""
        if self.is_connected_table:
            Settings.gui_columns_connected_shown = SETTING_DEFAULTS['gui_columns_connected_shown']
        else:
            Settings.gui_columns_disconnected_shown = SETTING_DEFAULTS['gui_columns_disconnected_shown']
        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()

    def _select_all_columns(self) -> None:
        """Show all toggleable columns and persist the change to settings."""
        if self.is_connected_table:
            Settings.gui_columns_connected_shown = Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS
        else:
            Settings.gui_columns_disconnected_shown = Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS
        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()

    def _deselect_all_columns(self) -> None:
        """Hide all toggleable columns and persist the change to settings."""
        if self.is_connected_table:
            Settings.gui_columns_connected_shown = ()
        else:
            Settings.gui_columns_disconnected_shown = ()
        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()

    def _select_category_columns(self, columns: list[str]) -> None:
        """Show a specific subset of columns and persist the change to settings."""
        shown = set(Settings.gui_columns_connected_shown) if self.is_connected_table else set(Settings.gui_columns_disconnected_shown)

        shown.update(columns)
        new_shown = tuple(
            column for column in (Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS if self.is_connected_table else Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS) if column in shown
        )

        if self.is_connected_table:
            Settings.gui_columns_connected_shown = new_shown
        else:
            Settings.gui_columns_disconnected_shown = new_shown
        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()

    def _deselect_category_columns(self, columns: list[str]) -> None:
        """Hide a specific subset of columns and persist the change to settings."""
        shown = set(Settings.gui_columns_connected_shown) if self.is_connected_table else set(Settings.gui_columns_disconnected_shown)

        shown.difference_update(columns)
        new_shown = tuple(
            column for column in (Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS if self.is_connected_table else Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS) if column in shown
        )

        if self.is_connected_table:
            Settings.gui_columns_connected_shown = new_shown
        else:
            Settings.gui_columns_disconnected_shown = new_shown
        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()
