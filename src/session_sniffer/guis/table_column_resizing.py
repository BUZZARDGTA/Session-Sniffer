"""Utilities for sizing and interactively resizing QTableView, QTreeView, and QTableWidget columns."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QHeaderView, QMenu, QTableView, QTableWidget, QTreeView

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.tables import (
    DEFAULT_MIN_COLUMN_WIDTH,
    FLEXIBLE_COLUMN_WEIGHTS,
    FLEXIBLE_STRETCH_COLUMNS,
)
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.utils import scale_by_ui

_MINIMUM_VIEWPORT_WIDTH_THRESHOLD = 100
_STANDARD_ICON_SIZE = 16

if TYPE_CHECKING:
    from collections.abc import Callable


def _get_horizontal_header(table: QTableView | QTreeView | QTableWidget) -> QHeaderView | None:
    """Return the horizontal header for a QTableView, QTableWidget, or QTreeView."""
    if isinstance(table, QTableView):
        return table.horizontalHeader()
    return table.header()


def size_column_to_fit(table: QTableView | QTreeView, column_index: int) -> None:
    """Resize a single column to fit its contents (header label and cell values)."""
    table_model = table.model()
    if not table_model:
        return

    if not 0 <= column_index < table_model.columnCount():
        return

    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        return

    horizontal_header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)
    table.resizeColumnToContents(column_index)


def size_all_columns_to_fit(table: QTableView | QTreeView) -> None:
    """Resize all visible columns in *table* to fit their contents."""
    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        return

    for column_index in range(horizontal_header.count()):
        if not horizontal_header.isSectionHidden(column_index):
            size_column_to_fit(table, column_index)


def add_column_sizing_actions(
    menu: QMenu,
    table: QTableView | QTreeView,
    *,
    clicked_column: int | None = None,
    on_reset: Callable[[], None] | None = None,
) -> None:
    """Add standardized 'Size Column to Fit', 'Size All Columns to Fit', and optional 'Reset Column Sizes' actions to *menu*."""
    table_model = table.model()
    clicked_column_name: str | None = None
    is_valid_clicked_column = False

    if clicked_column is not None and table_model and 0 <= clicked_column < table_model.columnCount():
        is_valid_clicked_column = True
        header_value = table_model.headerData(clicked_column, Qt.Orientation.Horizontal)
        if isinstance(header_value, str) and header_value:
            clicked_column_name = header_value

    size_column_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'fit_width.svg')), 'Size Column to Fit', menu)
    size_column_action.setEnabled(is_valid_clicked_column)
    if bool(clicked_column_name):
        size_column_action.setToolTip(f"Resize the '{clicked_column_name}' column so all text is fully visible without truncation or ellipses.")
    else:
        size_column_action.setToolTip('Resize the selected column so all text is fully visible without truncation or ellipses.')

    if is_valid_clicked_column and clicked_column is not None:
        target_column = clicked_column
        size_column_action.triggered.connect(lambda: size_column_to_fit(table, target_column))

    menu.addAction(size_column_action)

    size_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'fit_all.svg')), 'Size All Columns to Fit', menu)
    size_all_action.setToolTip('Resize all visible columns so that any truncated text across the entire table is fully visible without ellipses.')
    size_all_action.triggered.connect(lambda: size_all_columns_to_fit(table))
    menu.addAction(size_all_action)

    if on_reset is not None:
        reset_sizes_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), 'Reset Column Sizes', menu)
        reset_sizes_action.setToolTip('Reset all column widths back to their initial default layout.')
        reset_sizes_action.triggered.connect(on_reset)
        menu.addAction(reset_sizes_action)


def setup_table_header_context_menu(
    table: QTableView | QTreeView,
    *,
    on_reset: Callable[[], None] | None = None,
    extra_menu_builder: Callable[[QMenu, int], None] | None = None,
) -> QHeaderView:
    """Configure the horizontal header of *table* with a standardized right-click context menu for column sizing."""
    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        message = 'Failed to get horizontal header from table'
        raise RuntimeError(message)

    horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def _on_header_context_menu_requested(position: QPoint) -> None:
        clicked_column = horizontal_header.logicalIndexAt(position)
        menu = QMenu(table)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        add_column_sizing_actions(menu, table, clicked_column=clicked_column, on_reset=on_reset)

        if extra_menu_builder is not None:
            extra_menu_builder(menu, clicked_column)

        menu.popup(horizontal_header.mapToGlobal(position))

    horizontal_header.customContextMenuRequested.connect(_on_header_context_menu_requested)
    return horizontal_header


def setup_static_table_column_resizing(
    table: QTableView,
    *,
    custom_widths: dict[str, int] | None = None,
    min_column_widths: dict[str, int] | None = None,
    max_column_widths: dict[str, int] | None = None,
) -> None:
    """Set up column sizing for a table, fitting columns and distributing extra space to flexible columns."""
    table_model = table.model()
    if not table_model:
        return

    horizontal_header = table.horizontalHeader()
    if not horizontal_header:
        return

    viewport = table.viewport()
    viewport_width = viewport.width() if viewport and viewport.width() > _MINIMUM_VIEWPORT_WIDTH_THRESHOLD else table.width()
    if viewport_width <= 0:
        return

    font_metrics = table.fontMetrics()
    header_font_metrics = horizontal_header.fontMetrics()
    header_sort_padding = scale_by_ui(28)
    cell_padding = scale_by_ui(32)
    row_count = table_model.rowCount()
    widths_map = min_column_widths or {}
    max_bounds_map = max_column_widths or {}

    is_sort_active = horizontal_header.isSortIndicatorShown()
    sorted_column_index = horizontal_header.sortIndicatorSection() if is_sort_active else -1

    visible_columns: list[tuple[int, str, int, int]] = []
    for column in range(table_model.columnCount()):
        if horizontal_header.isSectionHidden(column):
            continue
        header_label = str(table_model.headerData(column, Qt.Orientation.Horizontal) or '')
        sort_padding = header_sort_padding if column == sorted_column_index else 0
        header_needed = max(
            header_font_metrics.horizontalAdvance(header_label) + sort_padding,
            horizontal_header.sectionSizeFromContents(column).width(),
        )
        min_width = max(scale_by_ui(widths_map.get(header_label, DEFAULT_MIN_COLUMN_WIDTH)), header_needed)
        custom_width = custom_widths.get(header_label) if custom_widths is not None else None
        floor_width = max(min_width, custom_width) if custom_width is not None else min_width

        needed_width = min_width

        sample_rows = min(row_count, 100)
        for row in range(sample_rows):
            index = table_model.index(row, column)
            text = table_model.data(index, Qt.ItemDataRole.DisplayRole)
            text_str = str(text) if text is not None and not isinstance(text, bool) else ''
            text_width = font_metrics.horizontalAdvance(text_str) if text_str else 0
            icon = table_model.data(index, Qt.ItemDataRole.DecorationRole)
            icon_offset = 0
            if isinstance(icon, QIcon):
                icon_width = icon.actualSize(QSize(100, _STANDARD_ICON_SIZE)).width()
                icon_offset = icon_width + scale_by_ui(6)
            elif icon is not None:
                icon_offset = scale_by_ui(22)
            cell_needed = text_width + icon_offset + cell_padding
            needed_width = max(needed_width, cell_needed)

        max_bound = scale_by_ui(max_bounds_map[header_label]) if header_label in max_bounds_map else None
        if max_bound is not None:
            needed_width = min(needed_width, max(floor_width, max_bound))

        visible_columns.append((column, header_label, floor_width, needed_width))

    if not visible_columns:
        return

    final_widths: dict[int, int] = {column_index: floor_width for column_index, _, floor_width, _ in visible_columns}
    total_allocated = sum(final_widths.values())
    surplus = viewport_width - total_allocated

    # Detect truncated columns: columns whose needed content width exceeds currently allocated floor width
    truncated_columns: dict[int, int] = {}
    for column_index, _, floor_width, needed_width in visible_columns:
        if needed_width > floor_width:
            truncated_columns[column_index] = needed_width - floor_width

    total_deficit = sum(truncated_columns.values())

    # If there is a deficit and surplus is insufficient, reclaim excess width from columns sitting above their needed width
    if total_deficit > 0 and surplus < total_deficit:
        deficit_to_cover = total_deficit - max(0, surplus)
        for column_index, header_label, _, needed_width in visible_columns:
            if custom_widths is not None and header_label in custom_widths:
                continue
            if deficit_to_cover <= 0:
                break
            sort_padding = header_sort_padding if column_index == sorted_column_index else 0
            header_needed = max(
                header_font_metrics.horizontalAdvance(header_label) + sort_padding,
                horizontal_header.sectionSizeFromContents(column_index).width(),
            )
            min_bound = max(scale_by_ui(widths_map.get(header_label, DEFAULT_MIN_COLUMN_WIDTH)), header_needed)
            reclaim_limit = max(min_bound, needed_width)
            if final_widths[column_index] > reclaim_limit:
                available_to_reclaim = final_widths[column_index] - reclaim_limit
                reclaimed_amount = min(available_to_reclaim, deficit_to_cover)
                final_widths[column_index] -= reclaimed_amount
                surplus += reclaimed_amount
                deficit_to_cover -= reclaimed_amount

    # Allocate surplus to truncated columns to eliminate or reduce text clipping
    if surplus > 0 and total_deficit > 0:
        if surplus >= total_deficit:
            for column_index, deficit in truncated_columns.items():
                final_widths[column_index] += deficit
            surplus -= total_deficit
        else:
            allocated = 0
            for column_index, deficit in truncated_columns.items():
                share = (surplus * deficit) // total_deficit
                final_widths[column_index] += share
                allocated += share
            remainder = surplus - allocated
            if remainder > 0:
                top_column = max(truncated_columns, key=lambda col_idx: truncated_columns[col_idx])
                final_widths[top_column] += remainder
            surplus = 0

    # Distribute any remaining surplus across flexible stretch columns to fill the table to the right edge
    if surplus > 0:
        flexible_columns = [
            (column_index, label)
            for column_index, label, _, _ in visible_columns
            if label in FLEXIBLE_STRETCH_COLUMNS and (custom_widths is None or label not in custom_widths)
        ]
        if not flexible_columns:
            flexible_columns = [(column_index, label) for column_index, label, _, _ in visible_columns if label in FLEXIBLE_STRETCH_COLUMNS]
        if not flexible_columns:
            non_custom_visible = [(column_index, label) for column_index, label, _, _ in visible_columns if custom_widths is None or label not in custom_widths]
            flexible_columns = [non_custom_visible[-1]] if non_custom_visible else [(visible_columns[-1][0], visible_columns[-1][1])]

        total_weight = sum(FLEXIBLE_COLUMN_WEIGHTS.get(label, 1) for _, label in flexible_columns)
        if total_weight <= 0:
            total_weight = len(flexible_columns)

        allocated = 0
        for column_index, label in flexible_columns:
            weight = FLEXIBLE_COLUMN_WEIGHTS.get(label, 1)
            share = (surplus * weight) // total_weight
            final_widths[column_index] += share
            allocated += share

        remainder = surplus - allocated
        if remainder > 0:
            top_column = max(flexible_columns, key=lambda item: FLEXIBLE_COLUMN_WEIGHTS.get(item[1], 1))[0]
            final_widths[top_column] += remainder

    for column, width in final_widths.items():
        horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        if horizontal_header.sectionSize(column) != width:
            horizontal_header.resizeSection(column, width)


class TableColumnResizeController:
    """Manages custom column widths, user interactive resizing constraints, and smart layout."""

    def __init__(
        self,
        table: QTableView,
        *,
        min_column_widths: dict[str, int] | None = None,
        max_column_widths: dict[str, int] | None = None,
    ) -> None:
        """Initialize the column resize controller for *table*."""
        self._table = table
        self.min_column_widths: dict[str, int] | None = min_column_widths
        self.max_column_widths: dict[str, int] | None = max_column_widths
        self.custom_widths: dict[str, int] | None = None
        self.is_programmatic_resizing: bool = False

    def on_section_resized(self, logical_index: int, _old_size: int, new_size: int) -> None:
        """Track user column resize interactions while respecting minimum column width limits."""
        if self.is_programmatic_resizing:
            return

        header = _get_horizontal_header(self._table)
        if not header:
            return

        header_model = header.model()
        column_name = str(header_model.headerData(logical_index, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)) if header_model else ''
        if not column_name:
            return

        if self.custom_widths is None:
            self.custom_widths = self.get_column_widths()

        widths_map = self.min_column_widths or {}
        min_width = max(
            scale_by_ui(widths_map.get(column_name, DEFAULT_MIN_COLUMN_WIDTH)),
            header.sectionSizeFromContents(logical_index).width(),
        )

        if new_size < min_width:
            self.is_programmatic_resizing = True
            try:
                header.resizeSection(logical_index, min_width)
            finally:
                self.is_programmatic_resizing = False
            effective_size = min_width
        else:
            effective_size = new_size

        self.custom_widths[column_name] = effective_size

    def get_column_widths(self) -> dict[str, int]:
        """Return the current column widths as a dictionary mapping header label to pixel width."""
        model = self._table.model()
        header = _get_horizontal_header(self._table)
        if not model or not header:
            return {}
        widths: dict[str, int] = {}
        for column in range(model.columnCount()):
            label = str(model.headerData(column, Qt.Orientation.Horizontal) or '')
            if label:
                widths[label] = header.sectionSize(column)
        return widths

    def setup_column_resizing(self) -> None:
        """Apply smart column resizing to the table."""
        self.is_programmatic_resizing = True
        try:
            setup_static_table_column_resizing(
                self._table,
                custom_widths=self.custom_widths,
                min_column_widths=self.min_column_widths,
                max_column_widths=self.max_column_widths,
            )
        finally:
            self.is_programmatic_resizing = False

    def reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        self.custom_widths = None
        self.setup_column_resizing()
