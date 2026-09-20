"""Context menu for the Player Identifier z-score table."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelection, QItemSelectionModel, QPoint
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QMenu, QTableWidget, QWidget

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis._player_identifier_core import UPDATE_INTERVAL_MS
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_context_menu import add_copy_usernames_and_ips_actions
from session_sniffer.guis.utils import (
    copy_table_cells,
    copy_table_widget_selection,
    popup_menu_at_table_widget,
    set_clipboard_text,
)
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QTimer


def select_table_row(table: QTableWidget, row: int) -> None:
    """Select all cells across *row* in *table*."""
    selection_model = table.selectionModel()
    table_model = table.model()
    if not selection_model or not table_model:
        return
    top_left = table_model.index(row, 0)
    bottom_right = table_model.index(row, table.columnCount() - 1)
    selection = QItemSelection(top_left, bottom_right)
    selection_model.select(selection, QItemSelectionModel.SelectionFlag.Select)


def select_table_column(table: QTableWidget, column: int) -> None:
    """Select all cells down *column* in *table*."""
    selection_model = table.selectionModel()
    table_model = table.model()
    if not selection_model or not table_model:
        return
    top_left = table_model.index(0, column)
    bottom_right = table_model.index(table.rowCount() - 1, column)
    selection = QItemSelection(top_left, bottom_right)
    selection_model.select(selection, QItemSelectionModel.SelectionFlag.Select)


def show_player_identifier_context_menu(
    parent: QWidget,
    table: QTableWidget,
    pos: QPoint,
    timer: QTimer,
    add_to_searchlist_callback: Callable[..., None],
) -> None:
    """Show the context menu for the Player Identifier z-score table."""
    index = table.indexAt(pos)
    if not index.isValid():
        return

    selection_model = table.selectionModel()
    if selection_model and not selection_model.isSelected(index):
        selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect)

    selected_row_indexes = sorted({item_index.row() for item_index in (selection_model.selectedIndexes() if selection_model else [])})
    if not selected_row_indexes:
        selected_row_indexes = [index.row()]

    selected_players_data: list[tuple[str, str]] = []  # (username, ip)
    for row in selected_row_indexes:
        ip_item = table.item(row, 1)
        if not ip_item:
            continue
        ip_address = ip_item.text().strip()
        username_item = table.item(row, 0)
        username = username_item.text().strip() if username_item and username_item.text() != '—' else ''
        if not username and (player := PlayersRegistry.get_player_by_ip(ip_address)) and player.usernames:
            username = player.usernames[0]
        selected_players_data.append((username, ip_address))

    if not selected_players_data:
        return

    selected_indexes = selection_model.selectedIndexes() if selection_model else []
    selected_cell_count = len(selected_indexes)

    menu = QMenu(parent)
    menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
    menu.setToolTipsVisible(True)

    copy_selection_label = f'Copy Selection ({selected_cell_count})' if selected_cell_count > 1 else 'Copy Selection'
    copy_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), copy_selection_label, parent)
    copy_selection_action.setShortcut('Ctrl+C')
    copy_selection_action.setToolTip('Copy selected cell(s) to the clipboard.')
    copy_selection_action.triggered.connect(lambda: copy_table_cells(table))
    menu.addAction(copy_selection_action)

    if len(selected_players_data) == 1:
        username, ip_address = selected_players_data[0]

        copy_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Row', parent)
        copy_row_action.setToolTip('Copy the entire row to the clipboard as tab-separated text.')
        copy_row_action.triggered.connect(lambda: copy_table_widget_selection(table))
        menu.addAction(copy_row_action)

        copy_username_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Username', parent)
        copy_username_action.setToolTip("Copy this player's username to the clipboard.")
        copy_username_action.setEnabled(bool(username))
        copy_username_action.triggered.connect(lambda: set_clipboard_text(username))
        menu.addAction(copy_username_action)

        copy_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy IP ({ip_address})', parent)
        copy_ip_action.setToolTip("Copy this player's IP to the clipboard.")
        copy_ip_action.triggered.connect(lambda: set_clipboard_text(ip_address))
        menu.addAction(copy_ip_action)
    else:
        all_ip_addresses = [ip_addr for _, ip_addr in selected_players_data]
        all_usernames = [user_name for user_name, _ in selected_players_data if user_name]

        copy_rows_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Rows ({len(selected_players_data)})', parent)
        copy_rows_action.setToolTip('Copy selected rows to the clipboard as tab-separated text.')
        copy_rows_action.triggered.connect(lambda: copy_table_widget_selection(table))
        menu.addAction(copy_rows_action)

        add_copy_usernames_and_ips_actions(menu, parent, all_usernames, all_ip_addresses)

    menu.addSeparator()

    select_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')), 'Select All', parent)
    select_all_action.setShortcut('Ctrl+A')
    select_all_action.setToolTip('Select all cells in the table.')
    select_all_action.setEnabled(table.rowCount() > 0)
    select_all_action.triggered.connect(table.selectAll)
    menu.addAction(select_all_action)

    select_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_right.svg')), 'Select Row', parent)
    select_row_action.setToolTip('Select all cells in this row.')
    select_row_action.triggered.connect(lambda: select_table_row(table, index.row()))
    menu.addAction(select_row_action)

    select_col_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_down.svg')), 'Select Column', parent)
    select_col_action.setToolTip('Select all cells in this column.')
    select_col_action.triggered.connect(lambda: select_table_column(table, index.column()))
    menu.addAction(select_col_action)

    clear_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')), 'Clear Selection', parent)
    clear_selection_action.setToolTip('Deselect all currently selected cells.')
    clear_selection_action.triggered.connect(table.clearSelection)
    menu.addAction(clear_selection_action)

    menu.addSeparator()

    if len(selected_players_data) == 1:
        username, ip_address = selected_players_data[0]
        add_searchlist_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')), 'Add to Searchlist', parent)
        add_searchlist_action.setToolTip("Add this player's IP to the Searchlist UserIP database.")
        add_searchlist_action.triggered.connect(lambda: add_to_searchlist_callback([ip_address], default_username=username))
        menu.addAction(add_searchlist_action)
    else:
        all_ip_addresses = [ip_addr for _, ip_addr in selected_players_data]
        all_usernames = [user_name for user_name, _ in selected_players_data if user_name]
        add_searchlist_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')), f'Add to Searchlist ({len(selected_players_data)})', parent)
        add_searchlist_action.setToolTip('Add all selected players to the Searchlist UserIP database.')
        add_searchlist_action.triggered.connect(lambda: add_to_searchlist_callback(all_ip_addresses, usernames=all_usernames or None))
        menu.addAction(add_searchlist_action)

    popup_menu_at_table_widget(menu, table, pos)

    timer_was_active = timer.isActive()
    timer.stop()
    menu.aboutToHide.connect(lambda: timer.start(UPDATE_INTERVAL_MS) if timer_was_active else None)
