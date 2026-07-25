"""Provides a manager for standard QTableWidget context menus."""

import functools
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu

from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.utils import copy_table_widget_selection, popup_menu_at_table_widget

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QPoint
    from PySide6.QtWidgets import QTableWidget, QWidget


def skip_if_menu_open(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that skips the method if the instance's context menu is currently open."""

    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        # pylint: disable=protected-access
        if getattr(self, '_context_menu_manager', None) and self._context_menu_manager.is_menu_open():
            return None
        return func(self, *args, **kwargs)

    return wrapper


class TableContextMenuManager:
    """Manages a standard context menu for tables with copy and select functionality."""

    def __init__(self, table: QTableWidget, parent: QWidget) -> None:
        """Initialize the context menu manager for the given table."""
        self._table = table
        self._parent = parent
        self._is_open = False

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self.show_context_menu)

    def is_menu_open(self) -> bool:
        """Return whether the context menu is currently open."""
        return self._is_open

    def show_context_menu(self, pos: QPoint) -> None:
        """Show a context menu with copy and selection options for the table."""
        index = self._table.indexAt(pos)

        menu = QMenu(self._parent)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        copy_row_action = QAction('📝 Copy Row', menu)
        copy_row_action.setToolTip('Copy the selected row(s) to the clipboard as tab-separated text.')
        copy_row_action.setEnabled(index.isValid())
        copy_row_action.triggered.connect(lambda: copy_table_widget_selection(self._table))
        menu.addAction(copy_row_action)

        copy_all_action = QAction('📋 Copy All', menu)
        copy_all_action.setToolTip('Select all rows, then copy them to the clipboard.')
        copy_all_action.setEnabled(self._table.rowCount() > 0)

        def _copy_all() -> None:
            self._table.selectAll()
            copy_table_widget_selection(self._table)

        copy_all_action.triggered.connect(_copy_all)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        select_all_action = QAction('☑️ Select All', menu)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip('Select all rows in the table.')
        select_all_action.setEnabled(self._table.rowCount() > 0)
        select_all_action.triggered.connect(self._table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction('⬜ Clear Selection', menu)
        clear_selection_action.setToolTip('Deselect all currently selected rows.')
        clear_selection_action.triggered.connect(self._table.clearSelection)
        menu.addAction(clear_selection_action)

        popup_menu_at_table_widget(menu, self._table, pos)

        self._is_open = True
        menu.aboutToHide.connect(lambda: setattr(self, '_is_open', False))
