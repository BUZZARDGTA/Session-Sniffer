"""Utilities for sizing and interactively resizing QTableView, QTreeView, and QTableWidget columns."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QHeaderView, QMenu, QTableView, QTreeView

from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET

if TYPE_CHECKING:
    from collections.abc import Callable


def _get_horizontal_header(table: QTableView | QTreeView) -> QHeaderView | None:
    """Return the horizontal header for a QTableView or QTreeView."""
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


# pylint: disable=duplicate-code
def size_all_columns_to_fit(table: QTableView | QTreeView) -> None:
    """Resize all visible columns in *table* to fit their contents."""
    table_model = table.model()
    if not table_model:
        return

    horizontal_header = _get_horizontal_header(table)
    if not horizontal_header:
        return

    for column_index in range(table_model.columnCount()):
        if horizontal_header.isSectionHidden(column_index):
            continue
        horizontal_header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)
        table.resizeColumnToContents(column_index)


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

    size_column_action = QAction('↔️ Size Column to Fit', menu)
    size_column_action.setEnabled(is_valid_clicked_column)
    if clicked_column_name:
        size_column_action.setToolTip(f"Resize the '{clicked_column_name}' column so all text is fully visible without truncation or ellipses.")
    else:
        size_column_action.setToolTip('Resize the selected column so all text is fully visible without truncation or ellipses.')

    if is_valid_clicked_column and clicked_column is not None:
        target_column = clicked_column
        size_column_action.triggered.connect(lambda: size_column_to_fit(table, target_column))

    menu.addAction(size_column_action)

    size_all_action = QAction('↕️ Size All Columns to Fit', menu)
    size_all_action.setToolTip('Resize all visible columns so that any truncated text across the entire table is fully visible without ellipses.')
    size_all_action.triggered.connect(lambda: size_all_columns_to_fit(table))
    menu.addAction(size_all_action)

    if on_reset is not None:
        reset_sizes_action = QAction('🔄 Reset Column Sizes', menu)
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
