"""Provides a manager for standard QTableWidget context menus."""

import functools
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QKeySequence, QResizeEvent, QShortcut, QShowEvent

from session_sniffer.guis.live_language import CANONICAL_HEADER_ROLE
from session_sniffer.guis.table_column_resizing import ColumnSizingMenuCallbacks, TableColumnLayoutController, setup_table_header_context_menu
from session_sniffer.guis.tables_player_actions._actions import (
    create_ping_menu,
    scan_ports_ip,
)
from session_sniffer.guis.tables_player_actions._ip_lookup_dialog import (
    show_detailed_ip_lookup,
)
from session_sniffer.guis.utils import (
    ToggleAlwaysOnTopMixin,
    add_icon_menu_action,
    apply_always_on_top,
    copy_table_selection,
    create_styled_context_menu,
    popup_menu_at_table,
    set_clipboard_text,
)
from session_sniffer.guis.window_layout import (
    apply_maximize_on_show,
    apply_table_sort_state,
    capture_table_sort_state,
    clear_table_layout,
    restore_table_layout,
    restore_window_layout,
    save_table_layout,
    save_window_layout_with_always_on_top,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models import GUIState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QPoint
    from PySide6.QtWidgets import QBoxLayout, QMenu, QTableWidget, QWidget

    from session_sniffer.models.gui_state import TableLayoutState


def add_copy_usernames_and_ips_actions(
    menu: QMenu,
    _parent: QWidget,
    usernames: list[str],
    ip_addresses: list[str],
) -> None:
    """Add 'Copy Usernames' and 'Copy IPs' actions to *menu* if usernames or IP addresses are present."""
    if usernames:
        add_icon_menu_action(
            menu,
            'copy.svg',
            tr('Copy Usernames ({count})', count=len(usernames)),
            lambda: set_clipboard_text('\n'.join(usernames)),
            tooltip=tr('Copy all selected usernames.'),
        )
    if ip_addresses:
        add_icon_menu_action(
            menu,
            'copy.svg',
            tr('Copy IPs ({count})', count=len(ip_addresses)),
            lambda: set_clipboard_text('\n'.join(ip_addresses)),
            tooltip=tr('Copy all selected IP addresses.'),
        )


def extract_ip_addresses_from_table_selection(table: QTableWidget) -> list[str]:
    """Extract IP addresses from selected items in *table* if their column is an IP Address column."""
    selected_items = table.selectedItems()
    ip_addresses: list[str] = []
    for item in selected_items:
        header_item = table.horizontalHeaderItem(item.column())
        if header_item is None:
            continue
        canonical_header = header_item.data(CANONICAL_HEADER_ROLE)
        header_name = canonical_header if isinstance(canonical_header, str) and canonical_header else header_item.text()
        if header_name not in ('IP Address', 'IP', 'Gateway IP'):
            continue
        ip_address = item.text().strip()
        if ip_address and ip_address not in ip_addresses:
            ip_addresses.append(ip_address)
    return ip_addresses


def skip_if_menu_open[**P, R](func: Callable[P, R]) -> Callable[P, R | None]:
    """Decorator that skips the method if the instance's context menu is currently open."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
        menu_manager = getattr(args[0], '_context_menu_manager', None) if args else None
        if menu_manager is not None and menu_manager.is_menu_open():
            return None
        return func(*args, **kwargs)

    return wrapper


class TableContextMenuManager:
    """Manages a standard context menu for tables with copy, select, and IP ping functionality."""

    def __init__(
        self,
        table: QTableWidget,
        parent: QWidget,
        *,
        header_callbacks: ColumnSizingMenuCallbacks | None = None,
    ) -> None:
        """Initialize the context menu manager for the given table."""
        self._table = table
        self._parent = parent
        self._is_open = False

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self.show_context_menu)
        setup_table_header_context_menu(self._table, callbacks=header_callbacks)
        QShortcut(QKeySequence('Ctrl+C'), self._table).activated.connect(lambda: copy_table_selection(self._table))
        QShortcut(QKeySequence('Ctrl+A'), self._table).activated.connect(self._table.selectAll)

    def is_menu_open(self) -> bool:
        """Return whether the context menu is currently open."""
        return self._is_open

    def show_context_menu(self, pos: QPoint) -> None:
        """Show a context menu with copy, selection, and ping options for the table."""
        index = self._table.indexAt(pos)
        if index.isValid():
            item = self._table.item(index.row(), index.column())
            if item is not None and not item.isSelected():
                self._table.clearSelection()
                self._table.selectRow(index.row())

        selected_row_count = len({item.row() for item in self._table.selectedItems()})

        menu = create_styled_context_menu(self._parent)

        copy_label = tr_plural('Copy Row', 'Copy Rows ({count})', max(selected_row_count, 1))
        copy_row_action = add_icon_menu_action(
            menu,
            'copy.svg',
            copy_label,
            lambda: copy_table_selection(self._table),
            tooltip=tr_plural(
                'Copy the selected row to the clipboard as tab-separated text.',
                'Copy the selected rows to the clipboard as tab-separated text.',
                max(selected_row_count, 1),
            ),
        )
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setEnabled(selected_row_count > 0)

        def _copy_all() -> None:
            self._table.selectAll()
            copy_table_selection(self._table)

        copy_all_action = add_icon_menu_action(
            menu,
            'copy.svg',
            tr('Copy All'),
            _copy_all,
            tooltip=tr('Select all rows, then copy them to the clipboard.'),
        )
        copy_all_action.setEnabled(self._table.rowCount() > 0)

        menu.addSeparator()

        select_all_action = add_icon_menu_action(
            menu,
            'square-check.svg',
            tr('Select All'),
            self._table.selectAll,
            tooltip=tr('Select all rows in the table.'),
        )
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setEnabled(self._table.rowCount() > 0)

        add_icon_menu_action(
            menu,
            'square.svg',
            tr('Clear Selection'),
            self._table.clearSelection,
            tooltip=tr('Deselect all currently selected rows.'),
        )

        selected_ip_addresses = extract_ip_addresses_from_table_selection(self._table)
        if selected_ip_addresses:
            menu.addSeparator()

            if len(selected_ip_addresses) == 1:
                target_ip = selected_ip_addresses[0]
                add_icon_menu_action(
                    menu,
                    'search.svg',
                    tr('IP Lookup Details…'),
                    lambda: show_detailed_ip_lookup(target_ip),
                    tooltip=tr('Show detailed IP lookup information for this IP address.'),
                )

            create_ping_menu(self._parent, menu, selected_ip_addresses)

            add_icon_menu_action(
                menu,
                'radar.svg',
                tr('Scan Ports…'),
                lambda: scan_ports_ip(selected_ip_addresses),
                tooltip=tr_plural(
                    'Scan TCP and UDP ports on the selected host.',
                    'Scan TCP and UDP ports on the selected hosts.',
                    len(selected_ip_addresses),
                ),
            )

        popup_menu_at_table(menu, self._table, pos)

        self._is_open = True
        menu.aboutToHide.connect(lambda: setattr(self, '_is_open', False))


class StatTableWindowMixin(ToggleAlwaysOnTopMixin):
    """Mixin for statistic table windows providing resizing, column order, layout persistence, context menu, and always-on-top setup."""

    LAYOUT_KEY: ClassVar[str | None] = None

    _table: QTableWidget
    _column_resizer: TableColumnLayoutController
    _context_menu_manager: TableContextMenuManager
    _saved_table_state: TableLayoutState | None = None

    def setup_stat_table_controls(
        self,
        layout: QBoxLayout,
        *,
        always_on_top: bool,
        min_column_widths: dict[str, int] | None = None,
    ) -> None:
        """Initialize column layout, context menu, layout restoration, and the always-on-top checkbox."""
        self._column_resizer = TableColumnLayoutController(
            self._table,
            min_column_widths=min_column_widths,
            on_after_move=self._setup_column_resizing,
        )
        self._column_resizer.bind_header()
        self._context_menu_manager = TableContextMenuManager(
            self._table,
            self,
            header_callbacks=self._column_resizer.menu_callbacks(on_reset=self._reset_column_sizes, on_reset_order=self._reset_column_order),
        )
        effective_always_on_top = always_on_top
        self._saved_table_state = None
        if self.LAYOUT_KEY is not None and Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            win_state = restore_window_layout(self, self.LAYOUT_KEY, gui_state=gui_state)
            if win_state is not None and win_state.always_on_top is not None:
                effective_always_on_top = win_state.always_on_top
                apply_always_on_top(self, checked=effective_always_on_top)
            self._saved_table_state = restore_table_layout(self.LAYOUT_KEY, self._column_resizer, gui_state=gui_state)
        self.add_always_on_top_checkbox(layout, always_on_top=effective_always_on_top)

    def _apply_default_or_saved_sort(self, default_column: int, default_order: Qt.SortOrder) -> None:
        """Apply persisted sort state if available, otherwise fall back to *default_column* and *default_order*."""
        if not apply_table_sort_state(self._table, self._saved_table_state):
            self._table.sortByColumn(default_column, default_order)

    def _setup_column_resizing(self) -> None:
        """Apply smart column resizing to the statistics table."""
        self._column_resizer.setup_column_resizing()

    def _apply_initial_column_resizing(self) -> None:
        """Apply initial column sizing if custom widths have not been set by user."""
        if self._column_resizer.custom_widths is None:
            self._setup_column_resizing()

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        self._column_resizer.reset_column_sizes()
        if self.LAYOUT_KEY is not None:
            clear_table_layout(self.LAYOUT_KEY, reset_widths=True)

    def _reset_column_order(self) -> None:
        """Reset column visual order back to the initial default layout."""
        self._column_resizer.reset_column_order()
        self._setup_column_resizing()
        if self.LAYOUT_KEY is not None:
            clear_table_layout(self.LAYOUT_KEY, reset_order=True)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Apply deferred maximization and adjust column widths when the window is shown."""
        super().showEvent(event)
        apply_maximize_on_show(self)
        self._setup_column_resizing()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adjust column widths when the window is resized."""
        super().resizeEvent(event)
        self._setup_column_resizing()

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Persist window geometry, Always on Top, and table column/sort state on close."""
        if self.LAYOUT_KEY is not None and Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            save_window_layout_with_always_on_top(self, self.LAYOUT_KEY, gui_state=gui_state)
            if (table_state := save_table_layout(self.LAYOUT_KEY, self._column_resizer, gui_state=gui_state)) is not None:
                capture_table_sort_state(table_state, self._table)
            gui_state.save()
        super().closeEvent(event)
