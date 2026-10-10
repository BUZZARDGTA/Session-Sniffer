"""Session table view for connected and disconnected players tables."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import QAbstractItemModel, QEvent, QItemSelection, QItemSelectionModel, QModelIndex, QObject, QRect, QRectF, QSize, Qt
from PySide6.QtGui import (
    QClipboard,
    QColor,
    QFont,
    QFontMetrics,
    QHoverEvent,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QResizeEvent,
    QShowEvent,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QHeaderView,
    QSizePolicy,
    QTableView,
    QToolTip,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.tables import (
    DEFAULT_MIN_COLUMN_WIDTH,
    SESSION_TABLE_MAX_COLUMN_WIDTHS,
    SESSION_TABLE_MIN_COLUMN_WIDTHS,
)
from session_sniffer.error_messages import ensure_instance, format_type_error
from session_sniffer.guis.app import app
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables_context_menu_mixin import TableContextMenuMixin
from session_sniffer.guis.tables_header_menu_mixin import TableHeaderMenuMixin
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import PaginationState, SearchState, SortState, TableMergeState

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player


class SessionTableView(TableHeaderMenuMixin, TableContextMenuMixin, QTableView):
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
        self.min_column_widths: dict[str, int] = SESSION_TABLE_MIN_COLUMN_WIDTHS
        self.max_column_widths: dict[str, int] = SESSION_TABLE_MAX_COLUMN_WIDTHS
        self.open_rate_graph_callback: Callable[[str], None] | None = None  # Optional callback to open a rate graph for an IP
        self.blacklist_high_rate_callback: Callable[[list[str]], None] | None = None  # Optional callback to blacklist IPs from High Rate Monitor
        self.unblacklist_high_rate_callback: Callable[[list[str]], None] | None = None  # Optional callback to unblacklist IPs from High Rate Monitor
        self.is_high_rate_blacklisted_callback: Callable[[str], bool] | None = None  # Optional callback to check if an IP is blacklisted in High Rate Monitor
        self._drag_selecting: bool = False  # Track if the mouse is being dragged with Ctrl key
        self._previous_cell: QModelIndex | None = None  # Track the previously selected cell
        self._previous_sort_section_index: int | None = sort_column
        self._saved_selection: list[tuple[str, int]] = []  # (ip, column) pairs for selection preservation
        self._saved_h_scroll: int | None = None
        self._saved_v_scroll: int | None = None
        self._custom_column_widths: dict[str, int] | None = None
        self._is_programmatic_resizing: bool = False
        self._has_auto_sized_with_data: bool = False
        self._recalculation_payloads_remaining: int = 0
        empty_icon_filename = 'empty_connected_players.svg' if is_connected_table else 'empty_disconnected_players.svg'
        self._empty_icon_renderer = QSvgRenderer((RESOURCES_DIR_PATH / 'icons' / empty_icon_filename).as_posix())

        self.setModel(model)
        self.setMouseTracking(True)  # Track mouse without clicks
        self.viewport().setMouseTracking(True)
        self.viewport().installEventFilter(self)  # Install event filter
        # Configure table view settings
        vertical_header = self.verticalHeader()
        vertical_header.setVisible(False)  # Hide row index
        vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)  # Fixed row heights for faster layout
        self.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)  # Smooth pixel-based scrolling
        self.setHorizontalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Force the empty "void" space to match the slate blue table background via high CSS specificity
        self.viewport().setObjectName('TableViewport')

        horizontal_header = self.horizontalHeader()
        horizontal_header.setMinimumSectionSize(scale_by_ui(DEFAULT_MIN_COLUMN_WIDTH))
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self._on_section_clicked)
        horizontal_header.sectionResized.connect(self._on_section_resized)
        horizontal_header.setSectionsMovable(True)
        horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        horizontal_header.customContextMenuRequested.connect(self._show_header_context_menu)
        self.setSelectionMode(QTableView.SelectionMode.NoSelection)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.setItemDelegate(ElidedTextTooltipDelegate(self))
        self.setIconSize(QSize(16, 16))
        self.setWordWrap(False)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)

        # Set the sort indicator for the specified column
        self.setSortingEnabled(False)
        horizontal_header.setSortIndicator(sort_column, sort_order)
        horizontal_header.setSortIndicatorShown(True)
        self._push_sort_state(reset_page=False)

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
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """Show country flag tooltips on hover and forward other events."""
        if not isValid(watched):
            return False
        if watched == self.viewport() and isinstance(event, QHoverEvent):
            index = self.indexAt(event.position().toPoint())  # Get hovered cell
            if index.isValid():
                model = self.model()
                if (country_column := model.get_column_index('Country')) is not None and country_column == index.column():
                    ip = model.get_display_text(model.index(index.row(), model.ip_column_index))
                    if ip is not None:
                        matched_player = PlayersRegistry.get_player_by_ip(ip)
                        if matched_player is not None and matched_player.country_flag is not None:
                            self._show_flag_tooltip(event, index, matched_player)

        return super().eventFilter(watched, event)

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Handle key press events to capture Ctrl+A for selecting all and Ctrl+C for copying selected data to the clipboard.

        Fall back to default behavior for other key presses.
        """
        if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            if event.key() == Qt.Key.Key_A:
                self.select_all_cells()
            elif event.key() == Qt.Key.Key_C:
                self.copy_selected_cells(self.model(), self.selectionModel().selectedIndexes())
            return

        # Fall back to default behavior
        super().keyPressEvent(event)

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Handle mouse press events for selecting multiple items with Ctrl or single items otherwise.

        Fall back to default behavior for non-cell areas.
        """
        index = self.indexAt(event.position().toPoint())  # Determine the index of the clicked item
        if index.isValid():
            selection_model = self.selectionModel()
            selection_flag = None

            if event.button() == Qt.MouseButton.LeftButton:
                if event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                    selection_flag = QItemSelectionModel.SelectionFlag.Deselect if selection_model.isSelected(index) else QItemSelectionModel.SelectionFlag.Select
                    self._drag_selecting = True
                    self._previous_cell = index
                elif event.modifiers() == Qt.KeyboardModifier.NoModifier:
                    was_selection_index_selected = selection_model.isSelected(index)
                    selection_model.clearSelection()
                    selection_flag = QItemSelectionModel.SelectionFlag.Deselect if was_selection_index_selected else QItemSelectionModel.SelectionFlag.Select

            elif event.button() == Qt.MouseButton.RightButton and not selection_model.isSelected(index):
                selection_flag = QItemSelectionModel.SelectionFlag.ClearAndSelect

            if selection_flag is not None:
                selection_model.setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
                selection_model.select(index, selection_flag)
                return

        # Fall back to default behavior
        super().mousePressEvent(event)

    @override
    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        """Handle mouse movement during Ctrl + Left-Click drag to toggle the selection of multiple cells."""
        index = self.indexAt(event.position().toPoint())  # Get the index under the cursor
        if index.isValid():
            selection_model = self.selectionModel()

            if (
                event.buttons() == Qt.MouseButton.LeftButton
                and event.modifiers() == Qt.KeyboardModifier.ControlModifier
                and self._drag_selecting
                and self._previous_cell != index
            ):
                self._previous_cell = index
                selection_model.setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
                selection_model.select(
                    index,
                    (QItemSelectionModel.SelectionFlag.Deselect if selection_model.isSelected(index) else QItemSelectionModel.SelectionFlag.Select),
                )
                return

        super().mouseMoveEvent(event)

    @override
    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        """Reset dragging state when the mouse button is released."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_selecting = False
            self._previous_cell = None

        super().mouseReleaseEvent(event)

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Handle table viewport resize."""
        super().resizeEvent(event)
        self.setup_static_column_resizing()

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Handle table view becoming visible."""
        super().showEvent(event)
        self.check_initial_data_column_sizing()

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        """Paint table contents or empty-state placeholder when there are no rows."""
        super().paintEvent(event)

        if not self.model().rowCount():
            self._paint_empty_state()

    def _paint_empty_state(self) -> None:
        """Render a centered icon, title, and subtitle when the table has no rows."""
        viewport_rect = self.viewport().rect()
        if viewport_rect.height() < scale_by_ui(50):
            return

        painter = QPainter(self.viewport())
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
            painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

            icon_size = scale_by_ui(38)
            icon_spacing = scale_by_ui(14)
            title_spacing = scale_by_ui(6)

            title_font = QFont('Segoe UI', scale_by_ui(11), QFont.Weight.DemiBold)
            subtitle_font = QFont('Segoe UI', scale_by_ui(9))

            title_fm = QFontMetrics(title_font)
            subtitle_fm = QFontMetrics(subtitle_font)

            total_height = icon_size + icon_spacing + title_fm.height() + title_spacing + subtitle_fm.height()
            start_y = max(scale_by_ui(10), (viewport_rect.height() - total_height) // 2)

            icon_x = (viewport_rect.width() - icon_size) // 2
            icon_rect = QRectF(icon_x, start_y, icon_size, icon_size)
            self._empty_icon_renderer.render(painter, icon_rect)

            search_text = SearchState.get_text()
            has_registry_players = bool(
                PlayersRegistry.get_default_sorted_players(
                    include_connected=self.is_connected_table,
                    include_disconnected=not self.is_connected_table,
                ),
            )

            is_merged = TableMergeState.is_merged()
            if search_text and has_registry_players:
                title = ('No matching players' if is_merged else 'No matching connected players') if self.is_connected_table else 'No matching disconnected players'
                subtitle = 'No players match the current search filter.'
            elif self.is_connected_table:
                title = 'No players' if is_merged else 'No connected players'
                subtitle = 'Players will appear here.' if is_merged else 'Connected players will appear here.'
            else:
                title = 'No disconnected players'
                subtitle = 'Disconnected players will appear here.'

            curr_y = start_y + icon_size + icon_spacing
            title_rect = QRect(0, curr_y, viewport_rect.width(), title_fm.height())
            painter.setFont(title_font)
            painter.setPen(QColor('#e2e8f0'))
            painter.drawText(title_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, title)

            curr_y += title_fm.height() + title_spacing
            subtitle_rect = QRect(0, curr_y, viewport_rect.width(), subtitle_fm.height())
            painter.setFont(subtitle_font)
            painter.setPen(QColor('#64748b'))
            painter.drawText(subtitle_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, subtitle)
        finally:
            painter.end()

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def apply_sort(self, column_name: str, order: Qt.SortOrder) -> None:
        """Sort the table by column name and sort order."""
        model = self.model()
        column_index = model.get_column_index(column_name)
        if column_index is None:
            fallback = 'Last Rejoin' if self.is_connected_table else 'Last Seen'
            column_index = model.get_column_index(fallback)
            if column_index is None:
                if model.columnCount() > 0:
                    column_index = 0
                else:
                    return
        horizontal_header = self.horizontalHeader()
        sort_column_changed = self._previous_sort_section_index != column_index
        horizontal_header.setSortIndicator(column_index, order)
        self._previous_sort_section_index = column_index
        self.sort_current_column()
        self._push_sort_state(reset_page=False)
        if sort_column_changed:
            self.setup_static_column_resizing()

    def sort_current_column(self) -> None:
        """Sort the table by the currently indicated header column and order, preserving scroll position."""
        h_scroll = self.horizontalScrollBar().value()
        v_scroll = self.verticalScrollBar().value()
        model = self.model()
        horizontal_header = self.horizontalHeader()
        model.sort(horizontal_header.sortIndicatorSection(), horizontal_header.sortIndicatorOrder())
        self.horizontalScrollBar().setValue(h_scroll)
        self.verticalScrollBar().setValue(v_scroll)

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

    def _push_sort_state(self, *, reset_page: bool = False) -> None:
        """Write current sort column and order to the shared SortState."""
        column_name, sort_order = self._get_sorted_column()
        if self.is_connected_table:
            if reset_page:
                PaginationState.set_connected_page(1)
            SortState.set_connected(column_name=column_name, order=sort_order)
        else:
            if reset_page:
                PaginationState.set_disconnected_page(1)
            SortState.set_disconnected(column_name=column_name, order=sort_order)

    def _on_section_clicked(self, section_index: int) -> None:
        """Sort the table by the clicked header section."""
        h_scroll = self.horizontalScrollBar().value()
        v_scroll = self.verticalScrollBar().value()
        model = self.model()
        horizontal_header = self.horizontalHeader()

        sort_column_changed = self._previous_sort_section_index != section_index

        # If it's the first click or sorting is being toggled
        if self._previous_sort_section_index is None or self._previous_sort_section_index != section_index:
            horizontal_header.setSortIndicator(section_index, Qt.SortOrder.DescendingOrder)

        # Sort the model
        model.sort(section_index, horizontal_header.sortIndicatorOrder())
        self._previous_sort_section_index = section_index
        self._push_sort_state(reset_page=True)
        if sort_column_changed:
            self.setup_static_column_resizing()
        self.horizontalScrollBar().setValue(h_scroll)
        self.verticalScrollBar().setValue(v_scroll)

    def _show_flag_tooltip(self, event: QHoverEvent, index: QModelIndex, player: Player) -> None:
        """Show tooltip only if hovering exactly over the flag."""
        cell_rect = self.visualRect(index)
        icon_size = self.iconSize()
        if not icon_size.isValid():
            icon_size = QSize(16, 16)
        flag_rect = QRect(
            cell_rect.left() + 6,
            cell_rect.top() + (cell_rect.height() - icon_size.height()) // 2,
            icon_size.width(),
            icon_size.height(),
        )
        if flag_rect.contains(event.position().toPoint()):
            country_name: str | None = None
            if player.iplookup.geolite2 and player.iplookup.geolite2.country:
                country_name = player.iplookup.geolite2.country
            elif player.iplookup.ipapi and player.iplookup.ipapi.country:
                country_name = player.iplookup.ipapi.country
            if country_name is not None and country_name:
                QToolTip.showText(event.globalPosition().toPoint(), country_name, self)
            else:
                QToolTip.hideText()
        else:
            QToolTip.hideText()

    def capture_selection(self) -> None:
        """Save the current cell selection by player IP and scroll positions for later restoration."""
        if not isValid(self):
            return
        self._saved_h_scroll = self.horizontalScrollBar().value()
        self._saved_v_scroll = self.verticalScrollBar().value()
        selection_model = self.selectionModel()
        if not isValid(selection_model):
            self._saved_selection.clear()
            return
        selected_indexes = selection_model.selectedIndexes()
        if not selected_indexes:
            self._saved_selection.clear()
            return

        model = self.model()
        if not isValid(model):
            self._saved_selection.clear()
            return
        self._saved_selection.clear()
        for model_index in selected_indexes:
            if not model_index.isValid():
                continue
            row = model_index.row()
            column = model_index.column()
            if 0 <= row < model.rowCount() and 0 <= column < model.columnCount():
                ip = model.get_ip_for_row(row)
                if ip:
                    self._saved_selection.append((ip, column))

    def restore_selection(self) -> None:
        """Restore cell selection and scroll positions from previously captured state."""
        if not isValid(self):
            return
        if self._saved_h_scroll is not None:
            self.horizontalScrollBar().setValue(self._saved_h_scroll)
        if self._saved_v_scroll is not None:
            self.verticalScrollBar().setValue(self._saved_v_scroll)
        if not self._saved_selection:
            return

        model = self.model()
        if not isValid(model):
            return
        selection_model = self.selectionModel()
        if not isValid(selection_model):
            return

        selection = QItemSelection()

        for ip, column in self._saved_selection:
            row = model.get_row_index_by_ip(ip)
            if row is not None and 0 <= row < model.rowCount() and 0 <= column < model.columnCount():
                index = model.index(row, column)
                if index.isValid():
                    selection.select(index, index)

        selection_model.select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        self._saved_selection.clear()

    @override
    def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
        """Copy the selected cells data from the table to the clipboard."""
        # Access the system clipboard from the centralized app instance
        clipboard = ensure_instance(app.clipboard(), QClipboard)

        # Prepare a list to store text data from selected cells
        selected_texts: list[str] = []

        # Iterate over each selected index and retrieve its display data
        for model_index in selected_indexes:
            cell_text = selected_model.get_display_text(model_index)
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
            selected_model.rowCount() - 1,
            selected_model.columnCount() - 1,
        )  # Bottom-right item (last row, last column)

        # Create a selection range from top-left to bottom-right
        selection = QItemSelection(top_left, bottom_right)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

    @override
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

    @override
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
