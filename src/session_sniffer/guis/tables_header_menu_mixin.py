"""Mixin providing horizontal header context menu and column visibility management."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, QSignalBlocker, Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QHeaderView, QMenu, QTableView

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.tables import (
    BANDWIDTH_RATE_STAT_COLUMNS,
    DEFAULT_MIN_COLUMN_WIDTH,
    LOCATION_COLUMNS,
    PACKET_STAT_COLUMNS,
    PORT_COLUMNS,
    STATUS_COLUMNS,
)
from session_sniffer.guis.stylesheets import CATEGORY_SUBMENU_CHECKBOX_STYLESHEET, SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import (
    add_column_sizing_actions,
    setup_static_table_column_resizing,
    size_all_columns_to_fit,
    size_column_to_fit,
)
from session_sniffer.guis.table_model import GUI_COLUMN_HEADERS_TOOLTIPS
from session_sniffer.guis.utils import PersistentMenu, scale_by_ui
from session_sniffer.models import GUIState
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
        min_column_widths: dict[str, int]
        max_column_widths: dict[str, int]
        _custom_column_widths: dict[str, int] | None
        _is_programmatic_resizing: bool
        _has_auto_sized_with_data: bool
        _recalculation_payloads_remaining: int

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
            ) -> Callable[[], None]:
                def _handler() -> None:
                    target_action.setChecked(select)
                    for action_item in actions:
                        with QSignalBlocker(action_item):
                            action_item.setChecked(select)
                    if select:
                        self._select_category_columns(category_columns)
                    else:
                        self._deselect_category_columns(category_columns)

                return _handler

            def _make_column_toggled_handler(action: QAction, name: str) -> Callable[[], None]:
                def _on_column_toggled() -> None:
                    self._toggle_column_visibility(name, checked=action.isChecked())

                return _on_column_toggled

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

                column_action.toggled.connect(_make_column_toggled_handler(column_action, column_name))
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

    @property
    def has_custom_column_widths(self) -> bool:
        """Return True if the user has manually resized columns or custom widths were applied."""
        return self._custom_column_widths is not None

    def _on_section_resized(self, logical_index: int, _old_size: int, new_size: int) -> None:
        """Track user-driven column resizing."""
        if self._is_programmatic_resizing:
            return
        model = self.model()
        header_text = model.headerData(logical_index, Qt.Orientation.Horizontal)
        if header_text is not None and header_text:
            if self._custom_column_widths is None:
                self._custom_column_widths = self.get_column_widths()
            min_width = max(
                scale_by_ui(self.min_column_widths.get(header_text, DEFAULT_MIN_COLUMN_WIDTH)),
                self.horizontalHeader().sectionSizeFromContents(logical_index).width(),
            )
            if new_size < min_width:
                self._is_programmatic_resizing = True
                try:
                    self.horizontalHeader().resizeSection(logical_index, min_width)
                finally:
                    self._is_programmatic_resizing = False
                new_size = min_width
            self._custom_column_widths[header_text] = new_size

    def get_column_widths(self) -> dict[str, int]:
        """Return a mapping of column header names to their current section widths."""
        model = self.model()
        header = self.horizontalHeader()
        widths: dict[str, int] = {}
        for column in range(model.columnCount()):
            header_label = model.headerData(column, Qt.Orientation.Horizontal)
            if header_label is not None and header_label:
                widths[header_label] = header.sectionSize(column)
        return widths

    def apply_column_widths(self, widths: dict[str, int]) -> None:
        """Apply saved column widths to matching header sections."""
        self._is_programmatic_resizing = True
        try:
            model = self.model()
            header = self.horizontalHeader()
            for column in range(model.columnCount()):
                header_label = model.headerData(column, Qt.Orientation.Horizontal)
                if header_label in widths and widths[header_label] > 0:
                    min_width = max(
                        scale_by_ui(self.min_column_widths.get(header_label, DEFAULT_MIN_COLUMN_WIDTH)),
                        header.sectionSizeFromContents(column).width(),
                    )
                    width = max(min_width, widths[header_label])
                    header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
                    header.resizeSection(column, width)
            self._custom_column_widths = dict(widths)
        finally:
            self._is_programmatic_resizing = False

    def request_column_recalculation(self, *, payload_count: int = 2) -> None:
        """Flag that columns should be recalculated and resized on subsequent data updates."""
        self._recalculation_payloads_remaining = max(self._recalculation_payloads_remaining, payload_count)

    def clear_custom_column_widths(self, column_names: set[str] | list[str] | tuple[str, ...]) -> None:
        """Remove custom widths for specific columns so they can be recalculated from content."""
        if self._custom_column_widths is not None:
            for column_name in column_names:
                self._custom_column_widths.pop(column_name, None)
            if not self._custom_column_widths:
                self._custom_column_widths = None
        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            widths = gui_state.connected_table_column_widths if self.is_connected_table else gui_state.disconnected_table_column_widths
            if widths is not None:
                changed = False
                for column_name in column_names:
                    if column_name in widths:
                        del widths[column_name]
                        changed = True
                if changed:
                    if not widths:
                        if self.is_connected_table:
                            gui_state.connected_table_column_widths = None
                        else:
                            gui_state.disconnected_table_column_widths = None
                    gui_state.save()

    def setup_static_column_resizing(self) -> None:
        """Set up column sizing for the table, fitting columns and distributing extra space to flexible columns."""
        self._is_programmatic_resizing = True
        try:
            setup_static_table_column_resizing(
                self,
                custom_widths=self._custom_column_widths,
                min_column_widths=self.min_column_widths,
                max_column_widths=self.max_column_widths,
            )
        finally:
            self._is_programmatic_resizing = False

    def check_initial_data_column_sizing(self) -> None:
        """Perform initial or requested content-aware column sizing when row data is populated."""
        if self._recalculation_payloads_remaining > 0 and self.model().rowCount() > 0:
            self._recalculation_payloads_remaining -= 1
            self._has_auto_sized_with_data = True
            self.setup_static_column_resizing()
        elif not self._has_auto_sized_with_data and self.model().rowCount() > 0:
            self._has_auto_sized_with_data = True
            if self._custom_column_widths is None:
                self.setup_static_column_resizing()
        elif not self.model().rowCount():
            self._has_auto_sized_with_data = False

    def reset_initial_data_sizing(self) -> None:
        """Reset the flag tracking whether the table has auto-sized its columns with row data."""
        self._has_auto_sized_with_data = False
        self._recalculation_payloads_remaining = 0

    def _reset_column_sizes(self) -> None:
        """Restore the default column sizing rules (Stretch / ResizeToContents)."""
        self._custom_column_widths = None
        self._has_auto_sized_with_data = False
        self.setup_static_column_resizing()
        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            if self.is_connected_table:
                gui_state.connected_table_column_widths = None
            else:
                gui_state.disconnected_table_column_widths = None
            gui_state.save()
