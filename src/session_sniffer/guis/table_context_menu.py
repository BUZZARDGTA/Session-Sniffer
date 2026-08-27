"""Provides a manager for standard QTableWidget context menus."""

import functools
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu

from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions import (
    ping_ip,
    tcp_port_ping,
    tcp_port_ping_multi,
)
from session_sniffer.guis.utils import copy_table_widget_selection, popup_menu_at_table_widget

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QPoint
    from PySide6.QtWidgets import QTableWidget, QWidget


def extract_ip_addresses_from_table_selection(table: QTableWidget) -> list[str]:
    """Extract IP addresses from selected items in *table* if their column is an IP Address column."""
    selected_items = table.selectedItems()
    ip_addresses: list[str] = []
    for item in selected_items:
        header_item = table.horizontalHeaderItem(item.column())
        if header_item is None or header_item.text() not in ('IP Address', 'IP', 'Gateway IP'):
            continue
        ip_address = item.text().removesuffix(' 👑').strip()
        if ip_address and ip_address not in ip_addresses:
            ip_addresses.append(ip_address)
    return ip_addresses


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
    """Manages a standard context menu for tables with copy, select, and IP ping functionality."""

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
        """Show a context menu with copy, selection, and ping options for the table."""
        index = self._table.indexAt(pos)

        menu = QMenu(self._parent)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        copy_row_action = QAction('📋 Copy Row', menu)
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

        selected_ip_addresses = extract_ip_addresses_from_table_selection(self._table)
        if selected_ip_addresses:
            # pylint: disable=duplicate-code
            ping_menu = QMenu('📡 Ping', menu)
            ping_menu.setToolTipsVisible(True)
            if len(selected_ip_addresses) == 1:
                target_ip = selected_ip_addresses[0]
                normal_action = QAction('🏓 Normal (ICMP)', ping_menu)
                normal_action.setToolTip('Checks if selected IP address responds to pings.')
                normal_action.triggered.connect(lambda _checked=False, ip_address=target_ip: ping_ip(ip_address))
                ping_menu.addAction(normal_action)

                tcp_action = QAction('🔌 TCP Port (paping.exe)', ping_menu)
                tcp_action.setToolTip('Checks if selected IP address responds to TCP pings on a given port.')
                tcp_action.triggered.connect(lambda _checked=False, ip_address=target_ip: tcp_port_ping(self._parent, ip_address))
                ping_menu.addAction(tcp_action)
            else:
                ip_list = list(selected_ip_addresses)
                normal_action = QAction('🏓 Normal (ICMP)', ping_menu)
                normal_action.setToolTip('Checks if selected IP addresses respond to pings.')

                def _ping_all() -> None:
                    for ip_address in ip_list:
                        ping_ip(ip_address)

                normal_action.triggered.connect(_ping_all)
                ping_menu.addAction(normal_action)

                tcp_menu = QMenu('🔌 TCP Port (paping.exe)', ping_menu)
                tcp_menu.setToolTipsVisible(True)

                tcp_one_action = QAction('🔌 One Port for All', tcp_menu)
                tcp_one_action.setToolTip('Ask for a port once, then TCP ping all selected IPs on that port.')

                def _tcp_ping_multi() -> None:
                    tcp_port_ping_multi(self._parent, ip_list)

                tcp_one_action.triggered.connect(_tcp_ping_multi)
                tcp_menu.addAction(tcp_one_action)

                tcp_indiv_action = QAction('🔌 Individual Port per IP', tcp_menu)
                tcp_indiv_action.setToolTip('Ask for a separate port for each selected IP.')

                def _tcp_ping_indiv() -> None:
                    for ip_address in ip_list:
                        tcp_port_ping(self._parent, ip_address)

                tcp_indiv_action.triggered.connect(_tcp_ping_indiv)
                tcp_menu.addAction(tcp_indiv_action)

                ping_menu.addMenu(tcp_menu)

            menu.addMenu(ping_menu)
            # pylint: enable=duplicate-code
            menu.addSeparator()

        select_all_action = QAction('⬛ Select All', menu)
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
