"""Reconnect frequency statistics window."""

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QHeaderView, QMenu, QTableWidget, QTableWidgetItem

from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, copy_table_widget_selection, popup_menu_at_table_widget, setup_stat_table_with_header
from session_sniffer.player.registry import PlayersRegistry


class ReconnectFrequencyWindow(ToggleAlwaysOnTopMixin):
    """A standalone window listing players sorted by reconnect (rejoin) count."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the reconnect frequency window."""
        super().__init__()

        self.setWindowTitle('Reconnect Frequency')
        self.resize(520, 420)
        layout = self.setup_window_layout(always_on_top=always_on_top)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Rejoins', 'IP', 'Usernames'])
        h_header = setup_stat_table_with_header(self._table, layout)
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 100)
        self._table.setColumnWidth(1, 130)

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)
        # Prevents refresh() from clearing the row selection while a context menu is open.
        self._context_menu_open: bool = False

    # Context menu —————————————————————————————————————————————————————————————

    def _show_context_menu(self, pos: QPoint) -> None:
        """Show a context menu with copy and selection options for the frequency table."""
        index = self._table.indexAt(pos)

        menu = QMenu(self)
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

        self._context_menu_open = True
        menu.aboutToHide.connect(lambda: setattr(self, '_context_menu_open', False))

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Rebuild the table with current rejoin data."""
        if self._context_menu_open:
            return
        all_players = PlayersRegistry.get_all_players()
        entries = [(player.rejoins, player.ip, ', '.join(player.usernames) if player.usernames else '—') for player in all_players if player.rejoins > 0]
        entries.sort(key=lambda e: e[0], reverse=True)

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for rejoins, ip, usernames in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            rejoins_item = NumericTableWidgetItem(rejoins)
            rejoins_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            ip_item = QTableWidgetItem(ip)
            ip_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            usernames_item = QTableWidgetItem(usernames)
            self._table.setItem(row, 0, rejoins_item)
            self._table.setItem(row, 1, ip_item)
            self._table.setItem(row, 2, usernames_item)
        self._table.setSortingEnabled(True)
        self._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
