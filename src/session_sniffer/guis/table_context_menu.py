"""Provides a manager for standard QTableWidget context menus."""

import functools
from typing import TYPE_CHECKING, Any, override

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon, QKeySequence, QResizeEvent, QShortcut, QShowEvent
from PySide6.QtWidgets import QBoxLayout, QMenu, QTableWidget, QWidget

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import DEFAULT_MIN_COLUMN_WIDTH
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import TableColumnResizeController, setup_table_header_context_menu
from session_sniffer.guis.tables_player_actions import (
    create_multi_tcp_ping_menu,
    create_multi_udp_ping_menu,
    ping_ip,
    scan_ports_ip,
    show_detailed_ip_lookup,
    tcp_port_ping,
    udp_port_ping,
    web_ping,
)
from session_sniffer.guis.utils import (
    ToggleAlwaysOnTopMixin,
    copy_table_widget_selection,
    popup_menu_at_table_widget,
    scale_by_ui,
    set_clipboard_text,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QPoint


def add_copy_usernames_and_ips_actions(
    menu: QMenu,
    parent: QWidget,
    usernames: list[str],
    ip_addresses: list[str],
) -> None:
    """Add 'Copy Usernames' and 'Copy IPs' actions to *menu* if usernames or IP addresses are present."""
    if usernames:
        copy_usernames_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Usernames ({len(usernames)})', parent)
        copy_usernames_action.setToolTip('Copy all selected usernames.')
        copy_usernames_action.setEnabled(bool(usernames))
        copy_usernames_action.triggered.connect(lambda: set_clipboard_text('\n'.join(usernames)))
        menu.addAction(copy_usernames_action)

    if ip_addresses:
        copy_ips_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy IPs ({len(ip_addresses)})', parent)
        copy_ips_action.setToolTip('Copy all selected IP addresses.')
        copy_ips_action.triggered.connect(lambda: set_clipboard_text('\n'.join(ip_addresses)))
        menu.addAction(copy_ips_action)


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
        QShortcut(QKeySequence('Ctrl+C'), self._table).activated.connect(lambda: copy_table_widget_selection(self._table))
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

        menu = QMenu(self._parent)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        copy_label = f'Copy Rows ({selected_row_count})' if selected_row_count > 1 else 'Copy Row'
        copy_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), copy_label, menu)
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setToolTip('Copy the selected row(s) to the clipboard as tab-separated text.')
        copy_row_action.setEnabled(selected_row_count > 0)
        copy_row_action.triggered.connect(lambda: copy_table_widget_selection(self._table))
        menu.addAction(copy_row_action)

        copy_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy All', menu)
        copy_all_action.setToolTip('Select all rows, then copy them to the clipboard.')
        copy_all_action.setEnabled(self._table.rowCount() > 0)

        def _copy_all() -> None:
            self._table.selectAll()
            copy_table_widget_selection(self._table)

        copy_all_action.triggered.connect(_copy_all)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        select_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')), 'Select All', menu)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip('Select all rows in the table.')
        select_all_action.setEnabled(self._table.rowCount() > 0)
        select_all_action.triggered.connect(self._table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')), 'Clear Selection', menu)
        clear_selection_action.setToolTip('Deselect all currently selected rows.')
        clear_selection_action.triggered.connect(self._table.clearSelection)
        menu.addAction(clear_selection_action)

        selected_ip_addresses = extract_ip_addresses_from_table_selection(self._table)
        if selected_ip_addresses:
            menu.addSeparator()

            if len(selected_ip_addresses) == 1:
                target_ip = selected_ip_addresses[0]
                lookup_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')), 'IP Lookup Details…', menu)
                lookup_action.setToolTip('Show detailed IP lookup information for this IP address.')
                lookup_action.triggered.connect(lambda _checked=False, ip_address=target_ip: show_detailed_ip_lookup(self._parent, ip_address))
                menu.addAction(lookup_action)

            # pylint: disable=duplicate-code
            ping_menu = QMenu('Ping', menu)
            ping_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')))
            ping_menu.setToolTipsVisible(True)
            if len(selected_ip_addresses) == 1:
                target_ip = selected_ip_addresses[0]
                normal_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'Normal (ICMP)', ping_menu)
                normal_action.setToolTip('Checks if selected IP address responds to pings.')
                normal_action.triggered.connect(lambda _checked=False, ip_address=target_ip: ping_ip(ip_address))
                ping_menu.addAction(normal_action)

                tcp_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'TCP Port Ping', ping_menu)
                tcp_action.setToolTip('Checks if selected IP address responds to TCP pings on a given port.')
                tcp_action.triggered.connect(lambda _checked=False, ip_address=target_ip: tcp_port_ping(self._parent, ip_address))
                ping_menu.addAction(tcp_action)

                udp_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'UDP Port Ping', ping_menu)
                udp_action.setToolTip('Checks if selected IP address responds to UDP pings on a given port.')
                udp_action.triggered.connect(lambda _checked=False, ip_address=target_ip: udp_port_ping(self._parent, ip_address))
                ping_menu.addAction(udp_action)

                web_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'Web (Check-Host)', ping_menu)
                web_action.setToolTip('Checks if selected IP address responds via Check-Host.net distributed nodes.')
                web_action.triggered.connect(lambda _checked=False, ip_address=target_ip: web_ping(ip_address))
                ping_menu.addAction(web_action)
            else:
                ip_list = list(selected_ip_addresses)
                normal_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'Normal (ICMP)', ping_menu)
                normal_action.setToolTip('Checks if selected IP addresses respond to pings.')

                def _ping_all() -> None:
                    ping_ip(ip_list)

                normal_action.triggered.connect(_ping_all)
                ping_menu.addAction(normal_action)

                create_multi_tcp_ping_menu(self._parent, ip_list, ping_menu)
                create_multi_udp_ping_menu(self._parent, ip_list, ping_menu)

                web_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'Web (Check-Host)', ping_menu)
                web_action.setToolTip('Checks if selected IP addresses respond via Check-Host.net distributed nodes.')

                def _web_ping_all() -> None:
                    web_ping(ip_list)

                web_action.triggered.connect(_web_ping_all)
                ping_menu.addAction(web_action)

            menu.addMenu(ping_menu)

            scan_ports_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'port_scanner.svg')), 'Scan Ports…', menu)
            scan_ports_action.setToolTip('Scan TCP and UDP ports on the selected host(s).')

            def _scan_selected_ports() -> None:
                scan_ports_ip(selected_ip_addresses)

            scan_ports_action.triggered.connect(_scan_selected_ports)
            menu.addAction(scan_ports_action)

        popup_menu_at_table_widget(menu, self._table, pos)

        self._is_open = True
        menu.aboutToHide.connect(lambda: setattr(self, '_is_open', False))


class StatTableWindowMixin(ToggleAlwaysOnTopMixin):
    """Mixin for statistic table windows providing resizing, context menu, and always-on-top setup."""

    _table: QTableWidget
    _column_resizer: TableColumnResizeController
    _context_menu_manager: TableContextMenuManager

    @property
    def _custom_column_widths(self) -> dict[str, int] | None:
        return self._column_resizer.custom_widths

    @_custom_column_widths.setter
    def _custom_column_widths(self, value: dict[str, int] | None) -> None:
        self._column_resizer.custom_widths = value

    def setup_stat_table_controls(self, layout: QBoxLayout, *, always_on_top: bool) -> None:
        """Initialize the context menu manager, column resizing hooks, and add the always-on-top checkbox."""
        self._column_resizer = TableColumnResizeController(self._table)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(scale_by_ui(DEFAULT_MIN_COLUMN_WIDTH))
        header.sectionResized.connect(self._column_resizer.on_section_resized)
        self._context_menu_manager = TableContextMenuManager(self._table, self, on_reset_column_sizes=self._column_resizer.reset_column_sizes)
        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    def _setup_column_resizing(self) -> None:
        """Apply smart column resizing to the statistics table."""
        self._column_resizer.setup_column_resizing()

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
