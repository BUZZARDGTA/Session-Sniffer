"""Provides a manager for standard QTableWidget context menus."""

import functools
from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QResizeEvent, QShortcut, QShowEvent

from session_sniffer.constants.tables import DEFAULT_MIN_COLUMN_WIDTH
from session_sniffer.guis.table_column_resizing import TableColumnResizeController, setup_table_header_context_menu
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
    copy_table_selection,
    create_styled_context_menu,
    popup_menu_at_table,
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QPoint
    from PySide6.QtWidgets import QBoxLayout, QMenu, QTableWidget, QWidget


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
            f'Copy Usernames ({len(usernames)})',
            lambda: set_clipboard_text('\n'.join(usernames)),
            tooltip='Copy all selected usernames.',
        )
    if ip_addresses:
        add_icon_menu_action(
            menu,
            'copy.svg',
            f'Copy IPs ({len(ip_addresses)})',
            lambda: set_clipboard_text('\n'.join(ip_addresses)),
            tooltip='Copy all selected IP addresses.',
        )


def extract_ip_addresses_from_table_selection(table: QTableWidget) -> list[str]:
    """Extract IP addresses from selected items in *table* if their column is an IP Address column."""
    selected_items = table.selectedItems()
    ip_addresses: list[str] = []
    for item in selected_items:
        header_item = table.horizontalHeaderItem(item.column())
        if header_item is None or header_item.text() not in ('IP Address', 'IP', 'Gateway IP'):
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
        on_reset_column_sizes: Callable[[], None] | None = None,
    ) -> None:
        """Initialize the context menu manager for the given table."""
        self._table = table
        self._parent = parent
        self._is_open = False
        self._on_reset_column_sizes = on_reset_column_sizes

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self.show_context_menu)
        setup_table_header_context_menu(self._table, on_reset=self._on_reset_column_sizes)
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

        copy_label = f'Copy Rows ({selected_row_count})' if selected_row_count > 1 else 'Copy Row'
        copy_row_action = add_icon_menu_action(
            menu,
            'copy.svg',
            copy_label,
            lambda: copy_table_selection(self._table),
            tooltip=f'Copy the selected row{pluralize(selected_row_count)} to the clipboard as tab-separated text.',
        )
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setEnabled(selected_row_count > 0)

        def _copy_all() -> None:
            self._table.selectAll()
            copy_table_selection(self._table)

        copy_all_action = add_icon_menu_action(menu, 'copy.svg', 'Copy All', _copy_all, tooltip='Select all rows, then copy them to the clipboard.')
        copy_all_action.setEnabled(self._table.rowCount() > 0)

        menu.addSeparator()

        select_all_action = add_icon_menu_action(menu, 'square-check.svg', 'Select All', self._table.selectAll, tooltip='Select all rows in the table.')
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setEnabled(self._table.rowCount() > 0)

        add_icon_menu_action(menu, 'square.svg', 'Clear Selection', self._table.clearSelection, tooltip='Deselect all currently selected rows.')

        selected_ip_addresses = extract_ip_addresses_from_table_selection(self._table)
        if selected_ip_addresses:
            menu.addSeparator()

            if len(selected_ip_addresses) == 1:
                target_ip = selected_ip_addresses[0]
                add_icon_menu_action(
                    menu,
                    'search.svg',
                    'IP Lookup Details…',
                    lambda: show_detailed_ip_lookup(target_ip),
                    tooltip='Show detailed IP lookup information for this IP address.',
                )

            create_ping_menu(self._parent, menu, selected_ip_addresses)

            add_icon_menu_action(
                menu,
                'radar.svg',
                'Scan Ports…',
                lambda: scan_ports_ip(selected_ip_addresses),
                tooltip=f'Scan TCP and UDP ports on the selected host{pluralize(len(selected_ip_addresses))}.',
            )

        popup_menu_at_table(menu, self._table, pos)

        self._is_open = True
        menu.aboutToHide.connect(lambda: setattr(self, '_is_open', False))


class StatTableWindowMixin(ToggleAlwaysOnTopMixin):
    """Mixin for statistic table windows providing resizing, context menu, and always-on-top setup."""

    _table: QTableWidget
    _column_resizer: TableColumnResizeController
    _context_menu_manager: TableContextMenuManager

    def setup_stat_table_controls(
        self,
        layout: QBoxLayout,
        *,
        always_on_top: bool,
        min_column_widths: dict[str, int] | None = None,
    ) -> None:
        """Initialize the context menu manager, column resizing hooks, and add the always-on-top checkbox."""
        self._column_resizer = TableColumnResizeController(
            self._table,
            min_column_widths=min_column_widths,
        )
        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(scale_by_ui(DEFAULT_MIN_COLUMN_WIDTH))
        header.sectionResized.connect(self._column_resizer.on_section_resized)
        self._context_menu_manager = TableContextMenuManager(self._table, self, on_reset_column_sizes=self._column_resizer.reset_column_sizes)
        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)

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

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Adjust column widths when the window is shown."""
        super().showEvent(event)
        self._setup_column_resizing()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adjust column widths when the window is resized."""
        super().resizeEvent(event)
        self._setup_column_resizing()
