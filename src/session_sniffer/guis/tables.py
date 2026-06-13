"""Session table view for connected and disconnected players tables."""

from typing import TYPE_CHECKING, cast, override

from PyQt6.QtCore import QAbstractItemModel, QEvent, QItemSelection, QItemSelectionModel, QModelIndex, QObject, QPoint, Qt
from PyQt6.QtGui import QAction, QClipboard, QHoverEvent, QKeyEvent, QMouseEvent
from PyQt6.QtWidgets import (
    QHeaderView,
    QMenu,
    QSizePolicy,
    QTableView,
    QToolTip,
    QWidget,
)

from session_sniffer.error_messages import ensure_instance, format_type_error
from session_sniffer.guis.app import app
from session_sniffer.guis.stylesheets import CUSTOM_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_model import GUI_COLUMN_HEADERS_TOOLTIPS, SessionTableModel
from session_sniffer.guis.tables_context_menu_mixin import TableContextMenuMixin
from session_sniffer.guis.utils import PersistentMenu
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings.defaults import SETTING_DEFAULTS
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.guis.main_window import MainWindow
    from session_sniffer.models.player import Player


# Category groupings for the Choose Columns submenu.
# First match wins; columns not matched fall under 'Other'.
_COLUMN_CATEGORY_GROUPS: tuple[tuple[str, frozenset[str]], ...] = (
    ('⏱ Session', frozenset({'T. Session Time', 'Session Time'})),
    ('📦 Packets', frozenset({
        'T. Packets', 'Packets',
        'T. Packets Received', 'Packets Received',
        'T. Packets Sent', 'Packets Sent',
        'T. Min Packet Length', 'Min Packet Length',
        'T. Avg Packet Length', 'Avg Packet Length',
        'T. Max Packet Length', 'Max Packet Length',
        'PPS', 'PPM',
    })),
    ('📶 Bandwidth', frozenset({
        'T. Bandwidth', 'Bandwidth',
        'T. Download', 'Download',
        'T. Upload', 'Upload',
        'BPS', 'BPM',
    })),
    ('🌐 Network', frozenset({
        'Hostname', 'Last Port', 'Middle Ports', 'First Port',
        'Mobile', 'VPN', 'Hosting', 'Pinging',
    })),
    ('📍 Location', frozenset({
        'Continent', 'Country', 'Region', 'R. Code', 'City', 'District',
        'ZIP Code', 'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency',
    })),
    ('🏢 Organization', frozenset({'Organization', 'ISP', 'ASN / ISP', 'AS', 'ASN'})),
)



class SessionTableView(TableContextMenuMixin, QTableView):  # pylint: disable=too-many-public-methods
    """Render a session table view with custom selection and tooltips."""

    def __init__(
        self,
        model: SessionTableModel,
        sort_column: int,
        sort_order: Qt.SortOrder,
        *,
        is_connected_table: bool,
    ) -> None:
        """Initialize a session table view.

        Args:
            model: The model to display.
            sort_column: Initial column index to sort by.
            sort_order: Initial sort order.
            is_connected_table: Whether this view represents the connected table.
        """
        super().__init__()

        self.is_connected_table = is_connected_table  # Store which table type this is
        self.open_rate_graph_callback: Callable[[str], None] | None = None  # Optional callback to open a rate graph for an IP
        self._drag_selecting: bool = False  # Track if the mouse is being dragged with Ctrl key
        self._previous_cell: QModelIndex | None = None  # Track the previously selected cell
        self._previous_sort_section_index: int | None = None
        self._saved_selection: list[tuple[str, int]] = []  # (ip, column) pairs for selection preservation

        self.setModel(model)
        self.setMouseTracking(True)  # Track mouse without clicks
        self.viewport().installEventFilter(self)  # Install event filter
        # Configure table view settings
        vertical_header = self.verticalHeader()
        vertical_header.setVisible(False)  # Hide row index
        vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)  # Fixed row heights for faster layout
        self.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)  # Smooth pixel-based scrolling
        self.setHorizontalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        horizontal_header = self.horizontalHeader()
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self._on_section_clicked)
        horizontal_header.setSectionsMovable(True)
        horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        horizontal_header.customContextMenuRequested.connect(self._show_header_context_menu)
        self.setSelectionMode(QTableView.SelectionMode.NoSelection)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)

        # Set the sort indicator for the specified column
        self.setSortingEnabled(False)
        horizontal_header.setSortIndicator(sort_column, sort_order)
        horizontal_header.setSortIndicatorShown(True)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    @override
    def setModel(self, model: QAbstractItemModel | None) -> None:
        """Override the setModel method to ensure the model is of type SessionTableModel."""
        super().setModel(ensure_instance(model, SessionTableModel))

    @override
    def model(self) -> SessionTableModel:
        """Override the model method to ensure it returns a SessionTableModel."""
        return ensure_instance(super().model(), SessionTableModel)

    @override
    def selectionModel(self) -> QItemSelectionModel:
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        return ensure_instance(super().selectionModel(), QItemSelectionModel)

    @override
    def viewport(self) -> QWidget:
        """Override the viewport method to ensure it returns a QWidget."""
        return ensure_instance(super().viewport(), QWidget)

    @override
    def verticalHeader(self) -> QHeaderView:
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().verticalHeader(), QHeaderView)

    @override
    def horizontalHeader(self) -> QHeaderView:
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().horizontalHeader(), QHeaderView)

    @override
    def eventFilter(self, object: QObject | None, event: QEvent | None) -> bool:
        """Show country flag tooltips on hover and forward other events."""
        if isinstance(object, QObject) and isinstance(event, QHoverEvent):
            index = self.indexAt(event.position().toPoint())  # Get hovered cell
            if index.isValid():
                model = self.model()
                if (country_col := model.get_column_index('Country')) is not None and country_col == index.column():
                    ip = model.get_display_text(model.index(index.row(), model.ip_column_index))
                    if ip is not None:
                        matched_player = PlayersRegistry.get_player_by_ip(ip)
                        if matched_player is not None and matched_player.country_flag is not None:
                            self._show_flag_tooltip(event, index, matched_player)

        return super().eventFilter(object, event)

    @override
    def keyPressEvent(self, e: QKeyEvent | None) -> None:
        """Handle key press events to capture Ctrl+A for selecting all and Ctrl+C for copying selected data to the clipboard.

        Fall back to default behavior for other key presses.
        """
        if isinstance(e, QKeyEvent) and e.modifiers() == Qt.KeyboardModifier.ControlModifier:
            if e.key() == Qt.Key.Key_A:
                self.select_all_cells()
            elif e.key() == Qt.Key.Key_C:
                self.copy_selected_cells(self.model(), self.selectionModel().selectedIndexes())
            return

        # Fall back to default behavior
        super().keyPressEvent(e)

    @override
    def mousePressEvent(self, e: QMouseEvent | None) -> None:
        """Handle mouse press events for selecting multiple items with Ctrl or single items otherwise.

        Fall back to default behavior for non-cell areas.
        """
        if e is not None:
            index = self.indexAt(e.pos())  # Determine the index of the clicked item
            if index.isValid():
                selection_model = self.selectionModel()
                selection_flag = None

                if e.button() == Qt.MouseButton.LeftButton:
                    if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if selection_model.isSelected(index)
                            else QItemSelectionModel.SelectionFlag.Select
                        )
                        self._drag_selecting = True
                        self._previous_cell = index
                    elif e.modifiers() == Qt.KeyboardModifier.NoModifier:
                        was_selection_index_selected = selection_model.isSelected(index)
                        selection_model.clearSelection()
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if was_selection_index_selected
                            else QItemSelectionModel.SelectionFlag.Select
                        )

                elif e.button() == Qt.MouseButton.RightButton and not selection_model.isSelected(index):
                    selection_flag = QItemSelectionModel.SelectionFlag.ClearAndSelect

                if selection_flag is not None:
                    selection_model.select(index, selection_flag)

        # Fall back to default behavior
        super().mousePressEvent(e)

    @override
    def mouseMoveEvent(self, e: QMouseEvent | None) -> None:
        """Handle mouse movement during Ctrl + Left-Click drag to toggle the selection of multiple cells."""
        if e is not None:
            index = self.indexAt(e.pos())  # Get the index under the cursor
            if index.isValid():
                selection_model = self.selectionModel()

                if e.buttons() == Qt.MouseButton.LeftButton and e.modifiers() == Qt.KeyboardModifier.ControlModifier and self._drag_selecting and self._previous_cell != index:
                    self._previous_cell = index

                    selection_model.select(index, (
                        QItemSelectionModel.SelectionFlag.Deselect
                        if selection_model.isSelected(index)
                        else QItemSelectionModel.SelectionFlag.Select
                    ))

        super().mouseMoveEvent(e)

    @override
    def mouseReleaseEvent(self, e: QMouseEvent | None) -> None:
        """Reset dragging state when the mouse button is released."""
        if e is not None and e.button() == Qt.MouseButton.LeftButton:
            self._drag_selecting = False
            self._previous_cell = None

        super().mouseReleaseEvent(e)

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def setup_static_column_resizing(self) -> None:
        """Set up static column resizing for the table."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        for column in range(model.columnCount()):
            header_label = model.headerData(column, Qt.Orientation.Horizontal)

            if header_label in {
                'First Seen', 'Last Rejoin', 'Last Seen', 'T. Session Time', 'Session Time', 'Rejoins',
                'T. Packets', 'Packets', 'T. Packets Received', 'Packets Received', 'T. Packets Sent', 'Packets Sent', 'PPS', 'PPM',
                'Bandwidth', 'T. Bandwidth', 'Download', 'T. Download', 'Upload', 'T. Upload', 'BPS', 'BPM',
                'IP Address', 'First Port', 'Last Port', 'Mobile', 'VPN', 'Hosting', 'Pinging',
                'R. Code', 'ZIP Code', 'Lat', 'Lon', 'Offset', 'Currency', 'Time Zone',
            }:
                horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
            else:
                horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)

    def adjust_username_column_width(self) -> None:
        """Adjust the 'Usernames' column width based on whether any username is non-empty."""
        model = self.model()
        header = self.horizontalHeader()

        if self._has_any_username():
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.Stretch)
        else:
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.ResizeToContents)

    def sort_current_column(self) -> None:
        """Sort the table by the currently indicated header column and order."""
        model = self.model()
        horizontal_header = self.horizontalHeader()
        model.sort(horizontal_header.sortIndicatorSection(), horizontal_header.sortIndicatorOrder())

    def _has_any_username(self) -> bool:
        """Return True if any row has a non-empty username value."""
        model = self.model()
        col = model.username_column_index
        for row in range(model.rowCount()):
            text = model.data(model.index(row, col), Qt.ItemDataRole.DisplayRole)
            if isinstance(text, str) and text.strip():
                return True
        return False

    def _get_sorted_column(self) -> tuple[str, Qt.SortOrder]:
        """Get the currently sorted column and its order for this table view."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        # Get the index of the currently sorted column
        sorted_column_index = horizontal_header.sortIndicatorSection()

        # Get the sort order (ascending or descending)
        sort_order = horizontal_header.sortIndicatorOrder()

        # Get the name of the sorted column from the model
        sorted_column_name = model.headerData(sorted_column_index, Qt.Orientation.Horizontal)
        if sorted_column_name is None:
            raise TypeError(format_type_error(sorted_column_name, str))

        return sorted_column_name, sort_order

    def capture_selection(self) -> None:
        """Save the current cell selection by player IP for later restoration."""
        selected_indexes = self.selectionModel().selectedIndexes()
        if not selected_indexes:
            self._saved_selection.clear()
            return

        model = self.model()
        self._saved_selection.clear()
        for index in selected_indexes:
            row = index.row()
            if 0 <= row < model.rowCount():
                ip = model.get_ip_for_row(row)
                self._saved_selection.append((ip, index.column()))

    def restore_selection(self) -> None:
        """Restore cell selection from previously captured player IPs."""
        if not self._saved_selection:
            return

        model = self.model()
        selection = QItemSelection()

        for ip, column in self._saved_selection:
            row = model.get_row_index_by_ip(ip)
            if row is not None:
                index = model.index(row, column)
                selection.select(index, index)

        self.selectionModel().select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        self._saved_selection.clear()

    @override
    def handle_menu_hovered(self, action: QAction) -> None:
        """Propagate QAction tooltip text to its parent menu."""
        # Fixes: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        action_parent = action.parent()
        if isinstance(action_parent, QMenu):
            action_parent.setToolTip(action.toolTip())

    def _on_section_clicked(self, section_index: int) -> None:
        """Sort the table by the clicked header section."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        # If it's the first click or sorting is being toggled
        if self._previous_sort_section_index is None or self._previous_sort_section_index != section_index:
            horizontal_header.setSortIndicator(section_index, Qt.SortOrder.DescendingOrder)

        # Sort the model
        model.sort(section_index, horizontal_header.sortIndicatorOrder())
        self._previous_sort_section_index = section_index

    def _show_header_context_menu(self, pos: QPoint) -> None:
        """Show a context menu on the column header with sizing and column-visibility actions."""
        toggleable_columns = (
            Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS
            if self.is_connected_table
            else Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS
        )

        horizontal_header = self.horizontalHeader()
        clicked_column = horizontal_header.logicalIndexAt(pos)

        clicked_column_name: str | None = None
        if clicked_column >= 0:
            header_label = self.model().headerData(clicked_column, Qt.Orientation.Horizontal)
            if isinstance(header_label, str):
                clicked_column_name = header_label

        menu = QMenu(self)
        menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        size_column_action = QAction('↔️ Size Column to Fit', menu)
        size_column_action.setEnabled(clicked_column >= 0)
        size_column_action.triggered.connect(lambda: self._size_column_to_fit(clicked_column))
        menu.addAction(size_column_action)

        size_all_action = QAction('↕️ Size All Columns to Fit', menu)
        size_all_action.triggered.connect(self._size_all_columns_to_fit)
        menu.addAction(size_all_action)

        reset_sizes_action = QAction('🔄 Reset Column Sizes', menu)
        reset_sizes_action.triggered.connect(self._reset_column_sizes)
        menu.addAction(reset_sizes_action)

        menu.addSeparator()

        hide_label = f"👁️‍🗨️ Hide Column '{clicked_column_name}'" if clicked_column_name else '👁️‍🗨️ Hide Column'
        hide_column_action = QAction(hide_label, menu)
        hide_column_action.setEnabled(clicked_column_name is not None and clicked_column_name in toggleable_columns)
        if clicked_column_name is not None:
            hide_column_action.triggered.connect(
                lambda: self._toggle_column_visibility(clicked_column_name, checked=False),
            )
        menu.addAction(hide_column_action)

        choose_columns_menu = PersistentMenu('🧩 Choose Columns', menu)
        choose_columns_menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
        choose_columns_menu.setToolTipsVisible(True)

        reset_columns_action = QAction('↩️ Reset to Default Columns', choose_columns_menu)
        reset_columns_action.triggered.connect(self._reset_to_default_columns)
        choose_columns_menu.addAction(reset_columns_action)
        choose_columns_menu.addSeparator()

        # Bucket each toggleable column into its category.
        bucketed: dict[str, list[str]] = {label: [] for label, _ in _COLUMN_CATEGORY_GROUPS}
        bucketed['Other'] = []
        shown_columns = set(
            Settings.gui_columns_connected_shown
            if self.is_connected_table
            else Settings.gui_columns_disconnected_shown,
        )
        for col in toggleable_columns:
            placed = False
            for label, members in _COLUMN_CATEGORY_GROUPS:
                if col in members:
                    bucketed[label].append(col)
                    placed = True
                    break
            if not placed:
                bucketed['Other'].append(col)

        for label, _ in (*_COLUMN_CATEGORY_GROUPS, ('Other', frozenset[str]())):
            cols = bucketed[label]
            if not cols:
                continue
            category_menu = PersistentMenu(label, choose_columns_menu)
            category_menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
            category_menu.setToolTipsVisible(True)
            for col_name in cols:
                col_action = QAction(col_name, category_menu)
                col_action.setCheckable(True)
                col_action.setChecked(col_name in shown_columns)
                col_tooltip = GUI_COLUMN_HEADERS_TOOLTIPS.get(col_name)
                if col_tooltip is not None:
                    col_action.setToolTip(col_tooltip)

                def _on_col_toggled(checked: bool, name: str = col_name) -> None:  # noqa: FBT001
                    self._toggle_column_visibility(name, checked=checked)

                col_action.toggled.connect(_on_col_toggled)
                category_menu.addAction(col_action)
            choose_columns_menu.addMenu(category_menu)

        menu.addMenu(choose_columns_menu)

        menu.popup(horizontal_header.mapToGlobal(pos))

    def _size_column_to_fit(self, column: int) -> None:
        """Resize a single column to fit its contents (header + cell text)."""
        if column < 0:
            return
        header = self.horizontalHeader()
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        self.resizeColumnToContents(column)

    def _size_all_columns_to_fit(self) -> None:
        """Resize every visible column to fit its contents."""
        header = self.horizontalHeader()
        for column in range(self.model().columnCount()):
            if header.isSectionHidden(column):
                continue
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            self.resizeColumnToContents(column)

    def _reset_column_sizes(self) -> None:
        """Restore the default column sizing rules (Stretch / ResizeToContents)."""
        self.setup_static_column_resizing()
        self.adjust_username_column_width()

    def _toggle_column_visibility(self, column_name: str, *, checked: bool) -> None:
        """Toggle a column's visibility and persist the change to settings."""
        if self.is_connected_table:
            shown = set(Settings.gui_columns_connected_shown)
            toggleable = Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS
        else:
            shown = set(Settings.gui_columns_disconnected_shown)
            toggleable = Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS

        if checked:
            shown.add(column_name)
        else:
            shown.discard(column_name)

        # Preserve ordering from the toggleable columns tuple
        new_shown = tuple(col for col in toggleable if col in shown)

        if self.is_connected_table:
            Settings.gui_columns_connected_shown = new_shown
        else:
            Settings.gui_columns_disconnected_shown = new_shown

        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()
        self.adjust_username_column_width()

    def _reset_to_default_columns(self) -> None:
        """Restore the default column visibility and persist the change to settings."""
        if self.is_connected_table:
            Settings.gui_columns_connected_shown = SETTING_DEFAULTS['gui_columns_connected_shown']
        else:
            Settings.gui_columns_disconnected_shown = SETTING_DEFAULTS['gui_columns_disconnected_shown']
        Settings.rewrite_settings_file()
        self.setup_static_column_resizing()
        self.adjust_username_column_width()

    def _show_flag_tooltip(self, event: QHoverEvent, index: QModelIndex, player: Player) -> None:
        """Show tooltip only if hovering exactly over the flag."""
        # TODO(BUZZARDGTA): Make the tooltip appear precisely when hovering over the flag, using the pixmap or QIcon object if possible.
        cell_rect = self.visualRect(index)   # Get cell rectangle
        flag_x_start = cell_rect.left() + 4  # Assuming flag starts with a 4px horizontal padding
        flag_x_end = flag_x_start + 14       # Assuming flag ends with a 14px horizontal padding
        flag_y_start = cell_rect.top() + 10  # Assuming flag starts with a 10px vertical padding
        flag_y_end = flag_y_start + 10       # Assuming flag ends with a 10px vertical padding
        # Check if the mouse is over the flag both horizontally and vertically
        if flag_x_start <= event.position().toPoint().x() <= flag_x_end and flag_y_start <= event.position().toPoint().y() <= flag_y_end:
            QToolTip.showText(event.globalPosition().toPoint(), player.iplookup.geolite2.country, self)
        else:
            QToolTip.hideText()

    @override
    def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
        """Copy the selected cells data from the table to the clipboard."""
        # Access the system clipboard from the centralized app instance
        clipboard = ensure_instance(app.clipboard(), QClipboard)

        # Prepare a list to store text data from selected cells
        selected_texts: list[str] = []

        # Iterate over each selected index and retrieve its display data
        for index in selected_indexes:
            cell_text = selected_model.get_display_text(index)
            if cell_text is None:
                continue  # Skip if no valid display text is available

            selected_texts.append(cell_text)

        # Return if no text was selected
        if not selected_texts:
            return

        # Join all selected text entries with a newline to format for copying
        clipboard_content = '\n'.join(selected_texts)

        # Set the formatted text in the system clipboard
        clipboard.setText(clipboard_content)

    @override
    def remove_players_by_ip_from_table(self, ips: set[str]) -> None:
        """Remove multiple players from the table by calling the appropriate `MainWindow` method.

        Args:
            ips: Set of IP addresses of the players to remove.
        """
        # Get the MainWindow instance
        main_window = cast('MainWindow', self.window())

        # Remove each player
        for ip in ips:
            if self.is_connected_table:
                main_window.remove_player_from_connected(ip)
            else:
                main_window.remove_player_from_disconnected(ip)

    def _select_all_cells_helper(self, *, select: bool) -> None:
        """Helper function to select or deselect all cells in the table.

        Args:
            select: If True, select all cells; if False, deselect them.
        """
        selected_model = self.model()
        selection_model = self.selectionModel()

        # Early return if no rows exist in the table
        if not selected_model.rowCount():
            return

        # Get the top-left and bottom-right QModelIndex for the entire table
        top_left = selected_model.createIndex(0, 0)  # Top-left item (first row, first column)
        bottom_right = selected_model.createIndex(
            selected_model.rowCount() - 1, selected_model.columnCount() - 1,
        )  # Bottom-right item (last row, last column)

        # Create a selection range from top-left to bottom-right
        selection = QItemSelection(top_left, bottom_right)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    def _select_row_cells_helper(self, row: int, *, select: bool) -> None:
        """Helper function to select or unselect all cells in a specific row.

        Args:
            row: The index of the row to modify selection.
            select: If True, select the row; if False, unselect it.
        """
        selected_model = self.model()
        selection_model = self.selectionModel()

        # Early return if no rows exist in the table
        if not selected_model.rowCount():
            return

        top_index = selected_model.createIndex(row, 0)  # First column of the specified row
        bottom_index = selected_model.createIndex(row, selected_model.columnCount() - 1)  # Last column of the specified row

        # Create a selection range for the entire row
        selection = QItemSelection(top_index, bottom_index)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    def _select_column_cells_helper(self, column: int, *, select: bool) -> None:
        """Helper function to select or unselect all cells in a given column.

        Args:
            column: The index of the column to modify selection.
            select: If True, select the column; if False, unselect it.
        """
        selected_model = self.model()
        selection_model = self.selectionModel()

        # Early return if no rows exist in the table
        if not selected_model.rowCount():
            return

        top_index = selected_model.createIndex(0, column)  # First row of the specified column
        bottom_index = selected_model.createIndex(selected_model.rowCount() - 1, column)  # Last row of the specified column

        # Create a selection range for the entire column
        selection = QItemSelection(top_index, bottom_index)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    @override
    def select_all_cells(self) -> None:
        """Select all cells in the table."""
        self._select_all_cells_helper(select=True)

    @override
    def unselect_all_cells(self) -> None:
        """Unselect all cells in the table."""
        self._select_all_cells_helper(select=False)

    @override
    def select_row_cells(self, row: int) -> None:
        """Select all cells in the specified row."""
        self._select_row_cells_helper(row, select=True)

    @override
    def unselect_row_cells(self, row: int) -> None:
        """Unselect all cells in the specified row."""
        self._select_row_cells_helper(row, select=False)

    @override
    def select_column_cells(self, column: int) -> None:
        """Select all cells in the specified column."""
        self._select_column_cells_helper(column, select=True)

    @override
    def unselect_column_cells(self, column: int) -> None:
        """Unselect all cells in the specified column."""
        self._select_column_cells_helper(column, select=False)
