"""Session table view for connected and disconnected players tables."""

import re
from typing import TYPE_CHECKING

from PyQt6.QtCore import QAbstractItemModel, QEvent, QItemSelection, QItemSelectionModel, QModelIndex, QObject, QPoint, Qt
from PyQt6.QtGui import QAction, QClipboard, QHoverEvent, QKeyEvent, QMouseEvent
from PyQt6.QtWidgets import QHeaderView, QInputDialog, QMenu, QMessageBox, QSizePolicy, QTableView, QToolTip, QWidget

from session_sniffer.constants.local import BIN_DIR_PATH, BUILTIN_SCRIPTS_DIR_PATH, USER_SCRIPTS_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT, TITLE
from session_sniffer.error_messages import ensure_instance, format_type_error
from session_sniffer.guis.app import app
from session_sniffer.guis.stylesheets import CUSTOM_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.text_utils import format_triple_quoted_text, pluralize
from session_sniffer.utils import run_cmd_command, run_cmd_script, write_lines_to_file

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from session_sniffer.guis.main_window import MainWindow
    from session_sniffer.models.player import Player

RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')
PAPING_PATH = BIN_DIR_PATH / 'paping.exe'


class SessionTableView(QTableView):
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

        self._is_connected_table = is_connected_table  # Store which table type this is
        self._drag_selecting: bool = False  # Track if the mouse is being dragged with Ctrl key
        self._previous_cell: QModelIndex | None = None  # Track the previously selected cell
        self._previous_sort_section_index: int | None = None

        self.setModel(model)
        self.setMouseTracking(True)  # Track mouse without clicks
        viewport = self.viewport()
        viewport.installEventFilter(self)  # Install event filter
        # Configure table view settings
        vertical_header = self.verticalHeader()
        vertical_header.setVisible(False)  # Hide row index
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        horizontal_header = self.horizontalHeader()
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self.on_section_clicked)  # pyright: ignore[reportUnknownMemberType]
        horizontal_header.setSectionsMovable(True)
        self.setSelectionMode(QTableView.SelectionMode.NoSelection)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)

        # Set the sort indicator for the specified column
        self.setSortingEnabled(False)
        horizontal_header.setSortIndicator(sort_column, sort_order)
        horizontal_header.setSortIndicatorShown(True)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)  # pyright: ignore[reportUnknownMemberType]

    # pylint: disable=invalid-name
    def setModel(self, model: QAbstractItemModel | None) -> None:  # noqa: N802
        """Override the setModel method to ensure the model is of type SessionTableModel."""
        super().setModel(ensure_instance(model, SessionTableModel))

    def model(self) -> SessionTableModel:
        """Override the model method to ensure it returns a SessionTableModel."""
        return ensure_instance(super().model(), SessionTableModel)

    def selectionModel(self) -> QItemSelectionModel:  # noqa: N802
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        return ensure_instance(super().selectionModel(), QItemSelectionModel)

    def viewport(self) -> QWidget:
        """Override the viewport method to ensure it returns a QWidget."""
        return ensure_instance(super().viewport(), QWidget)

    def verticalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().verticalHeader(), QHeaderView)

    def horizontalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().horizontalHeader(), QHeaderView)

    def window(self) -> MainWindow:
        """Override the window method to ensure it returns the parent `MainWindow`.

        Raises:
            TypeError: If the view is not attached to a `MainWindow`.
        """
        from session_sniffer.guis.main_window import MainWindow as _MainWindow  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

        return ensure_instance(super().window(), _MainWindow)

    def eventFilter(self, object: QObject | None, event: QEvent | None) -> bool:  # pylint: disable=redefined-builtin  # noqa: A002, N802
        """Show country flag tooltips on hover and forward other events."""
        if isinstance(object, QWidget) and isinstance(event, QHoverEvent):
            index = self.indexAt(event.position().toPoint())  # Get hovered cell
            if index.isValid():
                model = self.model()

                if model.has_column('Country') and model.get_column_index('Country') == index.column():
                    ip = model.get_display_text(model.index(index.row(), model.ip_column_index))
                    if ip is not None:
                        matched_player = PlayersRegistry.get_player_by_ip(ip)
                        if matched_player is not None and matched_player.country_flag is not None:
                            self.show_flag_tooltip(event, index, matched_player)

        return super().eventFilter(object, event)

    def keyPressEvent(self, e: QKeyEvent | None) -> None:  # noqa: N802
        """Handle key press events to capture Ctrl+A for selecting all and Ctrl+C for copying selected data to the clipboard.

        Fall back to default behavior for other key presses.
        """
        if isinstance(e, QKeyEvent):  # noqa: SIM102
            if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                if e.key() == Qt.Key.Key_A:
                    self.select_all_cells()
                elif e.key() == Qt.Key.Key_C:
                    self.copy_selected_cells(self.model(), self.selectionModel().selectedIndexes())
                return

        # Fall back to default behavior
        super().keyPressEvent(e)

    def mousePressEvent(self, e: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse press events for selecting multiple items with Ctrl or single items otherwise.

        Fall back to default behavior for non-cell areas.
        """
        if isinstance(e, QMouseEvent):
            index = self.indexAt(e.pos())  # Determine the index of the clicked item
            if index.isValid():
                selection_model = self.selectionModel()
                selection_flag = None

                if e.button() == Qt.MouseButton.LeftButton:
                    if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if selection_model.isSelected(index)
                            else QItemSelectionModel.SelectionFlag.Select
                        )
                        self._drag_selecting = True
                        self._previous_cell = index
                    elif e.modifiers() == Qt.KeyboardModifier.NoModifier:
                        was_selection_index_selected = selection_model.isSelected(index)
                        selection_model.clearSelection()
                        selection_flag = (
                            QItemSelectionModel.SelectionFlag.Deselect
                            if was_selection_index_selected
                            else QItemSelectionModel.SelectionFlag.Select
                        )

                elif e.button() == Qt.MouseButton.RightButton:  # noqa: SIM102
                    if not selection_model.isSelected(index):
                        selection_flag = QItemSelectionModel.SelectionFlag.ClearAndSelect

                if selection_flag is not None:
                    selection_model.select(index, selection_flag)

        # Fall back to default behavior
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e: QMouseEvent | None) -> None:  # noqa: N802
        """Handle mouse movement during Ctrl + Left-Click drag to toggle the selection of multiple cells."""
        if isinstance(e, QMouseEvent):
            index = self.indexAt(e.pos())  # Get the index under the cursor
            if index.isValid():
                selection_model = self.selectionModel()

                if e.buttons() == Qt.MouseButton.LeftButton:  # noqa: SIM102
                    if e.modifiers() == Qt.KeyboardModifier.ControlModifier:  # noqa: SIM102
                        if self._drag_selecting and self._previous_cell != index:
                            self._previous_cell = index

                            selection_model.select(index, (
                                QItemSelectionModel.SelectionFlag.Deselect
                                if selection_model.isSelected(index)
                                else QItemSelectionModel.SelectionFlag.Select
                            ))

        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e: QMouseEvent | None) -> None:  # noqa: N802
        """Reset dragging state when the mouse button is released."""
        if isinstance(e, QMouseEvent):  # noqa: SIM102
            if e.button() == Qt.MouseButton.LeftButton:
                self._drag_selecting = False
                self._previous_cell = None

        super().mouseReleaseEvent(e)
    # pylint: enable=invalid-name

    # --------------------------------------------------------------------------
    # Custom / internal management methods
    # --------------------------------------------------------------------------

    def setup_static_column_resizing(self) -> None:
        """Set up static column resizing for the table."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        for column in range(model.columnCount()):
            header_label = model.headerData(column, Qt.Orientation.Horizontal)

            if header_label in {
                'First Seen', 'Last Rejoin', 'Last Seen', 'T. Session Time', 'Session Time', 'Rejoins',
                'T. Packets', 'Packets', 'T. Packets Received', 'Packets Received', 'T. Packets Sent', 'Packets Sent', 'PPS', 'PPM',
                'Bandwith', 'T. Bandwith', 'Download', 'T. Download', 'Upload', 'T. Upload', 'BPS', 'BPM',
                'IP Address', 'First Port', 'Last Port', 'Mobile', 'VPN', 'Hosting', 'Pinging',
                'R. Code', 'ZIP Code', 'Lat', 'Lon', 'Offset', 'Currency', 'Time Zone',
            }:
                horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
            else:
                horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)

    def adjust_username_column_width(self) -> None:
        """Adjust the 'Usernames' column width based on whether any username is non-empty."""
        model = self.model()
        header = self.horizontalHeader()

        found_username = False
        for row in range(model.rowCount()):
            index = model.index(row, model.username_column_index)
            data = model.get_display_text(index)
            if data and data.strip():  # Check for non-empty, non-whitespace
                found_username = True
                break

        if found_username:
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.Stretch)
        else:
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.ResizeToContents)

    def get_sorted_column(self) -> tuple[str, Qt.SortOrder]:
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

    def handle_menu_hovered(self, action: QAction) -> None:
        """Propagate QAction tooltip text to its parent menu."""
        # Fixes: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        action_parent = action.parent()
        if isinstance(action_parent, QMenu):
            action_parent.setToolTip(action.toolTip())

    def on_section_clicked(self, section_index: int) -> None:
        """Sort the table by the clicked header section and reset selections."""
        model = self.model()
        horizontal_header = self.horizontalHeader()
        selection_model = self.selectionModel()

        # Clear selections when a header section is clicked
        selection_model.clearSelection()

        # If it's the first click or sorting is being toggled
        if self._previous_sort_section_index is None or self._previous_sort_section_index != section_index:
            horizontal_header.setSortIndicator(section_index, Qt.SortOrder.DescendingOrder)

        # Sort the model
        model.sort(section_index, horizontal_header.sortIndicatorOrder())
        self._previous_sort_section_index = section_index

    def show_flag_tooltip(self, event: QHoverEvent, index: QModelIndex, player: Player) -> None:
        """Show tooltip only if hovering exactly over the flag."""
        # TODO(BUZZARDGTA): Make the tooltip appear precisely when hovering over the flag, using the pixmap or QIcon object if possible.
        cell_rect = self.visualRect(index)   # Get cell rectangle
        flag_x_start = cell_rect.left() + 4  # Assuming flag starts with a 4px horizontal padding
        flag_x_end = flag_x_start + 14       # Assuming flag ends with a 14px horizontal padding
        flag_y_start = cell_rect.top() + 10  # Assuming flag starts with a 10px vertical padding
        flag_y_end = flag_y_start + 10       # Assuming flag ends with a 10px vertical padding
        # Check if the mouse is over the flag both horizontally and vertically
        if flag_x_start <= event.position().toPoint().x() <= flag_x_end and flag_y_start <= event.position().toPoint().y() <= flag_y_end:
            QToolTip.showText(event.globalPosition().toPoint(), player.iplookup.geolite2.country, self)
        else:
            QToolTip.hideText()

    def show_context_menu(self, pos: QPoint) -> None:
        """Show the context menu at the specified position with options to interact with the table's content."""
        def add_action(
            menu: QMenu,
            label: str,
            shortcut: str | None = None,
            tooltip: str | None = None,
            handler: Callable[..., None] | None = None,
        ) -> QAction:
            """Helper to create and configure a QAction."""
            action = ensure_instance(menu.addAction(label), QAction)  # pyright: ignore[reportUnknownMemberType]

            if shortcut:
                action.setShortcut(shortcut)
            if tooltip:
                action.setToolTip(tooltip)
            if handler:
                action.triggered.connect(handler)  # pyright: ignore[reportUnknownMemberType]

            return action

        def add_menu(parent_menu: QMenu, label: str, tooltip: str | None = None) -> QMenu:
            """Helper to create and configure a QMenu."""
            menu = ensure_instance(parent_menu.addMenu(label), QMenu)

            if tooltip:
                menu.setToolTip(tooltip)

            return menu

        # Determine the index at the clicked position
        index = self.indexAt(pos)
        if not index.isValid():
            return  # Do nothing if the click is outside valid cells

        selected_model = self.model()
        selection_model = self.selectionModel()
        selected_indexes = selection_model.selectedIndexes()

        # Create the main context menu
        context_menu = QMenu(self)
        context_menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
        context_menu.setToolTipsVisible(True)
        context_menu.hovered.connect(self.handle_menu_hovered)  # pyright: ignore[reportUnknownMemberType]

        # Add "Copy Selection" action
        add_action(
            context_menu,
            'Copy Selection',
            shortcut='Ctrl+C',
            tooltip='Copy selected cells to your clipboard.',
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
        )
        context_menu.addSeparator()

        # Add "Remove Player" action if all selected cells are in IP Address column
        if selected_indexes and all(  # Check if all selected cells are in the IP Address column
            selected_model.headerData(idx.column(), Qt.Orientation.Horizontal) == 'IP Address'
            for idx in selected_indexes
        ):
            ips_to_remove: set[str] = set()
            for idx in selected_indexes:
                displayed_ip = selected_model.get_display_text(idx)
                if displayed_ip and displayed_ip not in ips_to_remove:
                    ips_to_remove.add(displayed_ip)

            if ips_to_remove:
                # Use singular or plural label based on count
                if len(ips_to_remove) == 1:
                    label = '🗑️ Remove Player'
                    tooltip = 'Remove this player from the table and registry.'
                else:
                    label = f'🗑️ Remove {len(ips_to_remove)} Players'
                    tooltip = f'Remove {len(ips_to_remove)} selected players from the table and registry.'

                def create_remove_handler(ip_list: set[str]) -> Callable[[], None]:
                    return lambda: self.remove_players_by_ip_from_table(ip_list)

                add_action(
                    context_menu,
                    label,
                    tooltip=tooltip,
                    handler=create_remove_handler(ips_to_remove),
                )
        context_menu.addSeparator()

        # "Select" submenu
        select_menu = add_menu(context_menu, 'Select  ')
        add_action(
            select_menu,
            'Select All',
            shortcut='Ctrl+A',
            tooltip='Select all cells in the table.',
            handler=self.select_all_cells,
        )
        add_action(
            select_menu,
            'Select Row',
            tooltip='Select all cells in this row.',
            handler=lambda: self.select_row_cells(index.row()),
        )
        add_action(
            select_menu,
            'Select Column',
            tooltip='Select all cells in this column.',
            handler=lambda: self.select_column_cells(index.column()),
        )

        # "Unselect" submenu
        unselect_menu = add_menu(context_menu, 'Unselect')
        add_action(
            unselect_menu,
            'Unselect All',
            tooltip='Unselect all cells in the table.',
            handler=self.unselect_all_cells,
        )
        add_action(
            unselect_menu,
            'Unselect Row',
            tooltip='Unselect all cells in this row.',
            handler=lambda: self.unselect_row_cells(index.row()),
        )
        add_action(
            unselect_menu,
            'Unselect Column',
            tooltip='Unselect all cells in this column.',
            handler=lambda: self.unselect_column_cells(index.column()),
        )
        context_menu.addSeparator()

        # Process if one cell is selected
        if len(selected_indexes) == 1:
            selected_column = selected_indexes[0].column()

            column_name = ensure_instance(selected_model.headerData(selected_column, Qt.Orientation.Horizontal), str)
            if column_name == 'IP Address':
                # Get the IP address from the selected cell
                displayed_ip = selected_model.get_display_text(selected_indexes[0])
                if not displayed_ip:
                    return

                userip_database_filepaths = UserIPDatabases.get_userip_database_filepaths()
                matched_player = PlayersRegistry.get_player_by_ip(displayed_ip)
                if matched_player is None:
                    return

                # Create local copies to use in lambdas
                ip_address = displayed_ip
                player_obj = matched_player

                add_action(
                    context_menu,
                    'IP Lookup Details',
                    tooltip='Displays a notification with a detailed IP lookup report for selected player.',
                    handler=lambda: self.show_detailed_ip_lookup_player_cell(player_obj),
                )

                ping_menu = add_menu(context_menu, 'Ping    ')
                add_action(
                    ping_menu,
                    'Normal',
                    tooltip='Checks if selected IP address responds to pings.',
                    handler=lambda: self.ping(ip_address),
                )
                add_action(
                    ping_menu,
                    'TCP Port (paping.exe)',
                    tooltip='Checks if selected IP address responds to TCP pings on a given port.',
                    handler=lambda: self.tcp_port_ping(ip_address),
                )

                scripts_menu = add_menu(context_menu, 'User Scripts ')

                def create_script_handler(script_path: Path) -> Callable[[], None]:
                    return lambda: run_cmd_script(script_path, [ip_address])

                def get_script_candidates(directory: Path) -> list[Path]:
                    allowed_suffixes = {'.bat', '.cmd', '.exe', '.py', '.lnk'}
                    return [
                        script
                        for script in directory.glob('*')
                        if (
                            script.is_file()
                            and not script.name.startswith(('_', '.'))
                            and script.suffix.casefold() in allowed_suffixes
                        )
                    ]

                def add_scripts_to_menu(menu: QMenu, scripts: list[Path]) -> None:
                    for script in scripts:
                        script_resolved = script.resolve()
                        add_action(
                            menu,
                            script_resolved.name,
                            tooltip='',
                            handler=create_script_handler(script_resolved),
                        )

                builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
                user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)

                add_scripts_to_menu(scripts_menu, builtin_scripts)

                # Separator between builtin/user scripts
                if builtin_scripts and user_scripts:
                    scripts_menu.addSeparator()

                add_scripts_to_menu(scripts_menu, user_scripts)

                userip_menu = add_menu(context_menu, 'UserIP  ')

                if matched_player.userip is None:
                    add_userip_menu = add_menu(userip_menu, 'Add     ', 'Add selected IP address to UserIP database.')  # Extra spaces for alignment
                    for database_path in userip_database_filepaths:
                        def create_add_handler(db_path: Path) -> Callable[[], None]:
                            return lambda: self.userip_manager__add([ip_address], db_path)

                        add_action(
                            add_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')),
                            tooltip='Add selected IP address to this UserIP database.',
                            handler=create_add_handler(database_path),
                        )
                else:
                    move_userip_menu = add_menu(userip_menu, 'Move    ', 'Move selected IP address to another database.')
                    for database_path in userip_database_filepaths:
                        def create_move_handler(db_path: Path) -> Callable[[], None]:
                            return lambda: self.userip_manager__move([ip_address], db_path)

                        action = add_action(
                            move_userip_menu,
                            str(database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')),
                            tooltip='Move selected IP address to this UserIP database.',
                            handler=create_move_handler(database_path),
                        )
                        action.setEnabled(matched_player.userip.database_path != database_path)
                    add_action(
                        userip_menu,
                        'Delete  ',  # Extra spaces for alignment
                        tooltip='Delete selected IP address from UserIP databases.',
                        handler=lambda: self.userip_manager__del([ip_address]),
                    )

        # Check if all selected cells are in the "IP Address" column
        elif all(
            selected_model.headerData(index.column(), Qt.Orientation.Horizontal) == 'IP Address'
            for index in selected_indexes
        ):
            all_ips: list[str] = []

            # Get the IP addresses from the selected cells
            for index in selected_indexes:
                displayed_ip = selected_model.get_display_text(index)
                if displayed_ip:
                    all_ips.append(displayed_ip)

            if all(ip not in UserIPDatabases.ips_set for ip in all_ips):
                userip_menu = add_menu(context_menu, 'UserIP  ')

                add_userip_menu = add_menu(userip_menu, 'Add Selected')
                for database_path in UserIPDatabases.get_userip_database_filepaths():
                    def create_multi_add_handler(db_path: Path, ip_list: list[str]) -> Callable[[], None]:
                        return lambda: self.userip_manager__add(ip_list, db_path)

                    add_action(
                        add_userip_menu,
                        str(database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')),
                        tooltip='Add selected IP addresses to this UserIP database.',
                        handler=create_multi_add_handler(database_path, all_ips),
                    )
            elif all(ip in UserIPDatabases.ips_set for ip in all_ips):
                userip_menu = add_menu(context_menu, 'UserIP  ')

                move_userip_menu = add_menu(userip_menu, 'Move Selected')
                for database_path in UserIPDatabases.get_userip_database_filepaths():
                    def create_multi_move_handler(db_path: Path, ip_list: list[str]) -> Callable[[], None]:
                        return lambda: self.userip_manager__move(ip_list, db_path)

                    add_action(
                        move_userip_menu,
                        str(database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')),
                        tooltip='Move selected IP addresses to this UserIP database.',
                        handler=create_multi_move_handler(database_path, all_ips),
                    )

                add_action(
                    userip_menu,
                    'Delete Selected',  # Extra spaces for alignment
                    tooltip='Delete selected IP addresses from UserIP databases.',
                    handler=lambda: self.userip_manager__del(all_ips),
                )

        # Execute the context menu at the right-click position
        context_menu.exec(self.mapToGlobal(pos))  # pyright: ignore[reportUnknownMemberType]

    def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
        """Copy the selected cells data from the table to the clipboard."""
        # Access the system clipboard from the centralized app instance
        clipboard = ensure_instance(app.clipboard(), QClipboard)

        # Prepare a list to store text data from selected cells
        selected_texts: list[str] = []

        # Iterate over each selected index and retrieve its display data
        for index in selected_indexes:
            cell_text = selected_model.get_display_text(index)
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

    def remove_players_by_ip_from_table(self, ips: set[str]) -> None:
        """Remove multiple players from the table by calling the appropriate `MainWindow` method.

        Args:
            ips: Set of IP addresses of the players to remove.
        """
        # Get the MainWindow instance
        main_window = self.window()

        # Remove each player
        for ip in ips:
            if self._is_connected_table:
                main_window.remove_player_from_connected(ip)
            else:
                main_window.remove_player_from_disconnected(ip)

    def show_detailed_ip_lookup_player_cell(self, player: Player) -> None:
        """Show a detailed information dialog for the given player."""
        QMessageBox.information(self, TITLE, format_triple_quoted_text(f"""
            ############ Player Infos #############
            IP Address: {player.ip}
            Hostname: {player.reverse_dns.hostname}
            Username{pluralize(len(player.usernames))}: {', '.join(player.usernames) or ""}
            In UserIP database: {(
                player.userip_detection is not None
                and f"{player.userip and player.userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')}"
            ) or "No"}
            Last Port: {player.ports.last}
            Middle Port{pluralize(len(player.ports.middle))}: {', '.join(map(str, player.ports.middle))}
            First Port: {player.ports.first}

            ########## IP Lookup Details ##########
            Continent: {player.iplookup.ipapi.continent}
            Country: {player.iplookup.geolite2.country}
            Country Code: {player.iplookup.geolite2.country_code}
            Region: {player.iplookup.ipapi.region}
            Region Code: {player.iplookup.ipapi.region_code}
            City: {player.iplookup.geolite2.city}
            District: {player.iplookup.ipapi.district}
            ZIP Code: {player.iplookup.ipapi.zip_code}
            Lat: {player.iplookup.ipapi.lat}
            Lon: {player.iplookup.ipapi.lon}
            Time Zone: {player.iplookup.ipapi.time_zone}
            Offset: {player.iplookup.ipapi.offset}
            Currency: {player.iplookup.ipapi.currency}
            Organization: {player.iplookup.ipapi.org}
            ISP: {player.iplookup.ipapi.isp}
            ASN / ISP: {player.iplookup.geolite2.asn}
            AS: {player.iplookup.ipapi.asn}
            ASN: {player.iplookup.ipapi.as_name}
            Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
            Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
            Hosting, colocated or data center: {player.iplookup.ipapi.hosting}

            ############ Ping Response ############
            Ping Times: {player.ping.ping_times}
            Packets Transmitted: {player.ping.packets_transmitted}
            Packets Received: {player.ping.packets_received}
            Packet Loss: {player.ping.packet_loss}
            Packet Errors: {player.ping.packet_errors}
            Round-Trip Time Minimum: {player.ping.rtt_min}
            Round-Trip Time Average: {player.ping.rtt_avg}
            Round-Trip Time Maximum: {player.ping.rtt_max}
            Round-Trip Time Mean Deviation: {player.ping.rtt_mdev}
        """),
        )

    def ping(self, ip: str) -> None:
        """Runs a continuous ping to a specified IP address in a new terminal window."""
        run_cmd_command('ping', [ip, '-t'])

    def tcp_port_ping(self, ip: str) -> None:
        """Runs paping to check TCP connectivity to a host on a user-specified port indefinitely."""

        def run_paping(host: str, port: int) -> None:
            """Runs paping in a new terminal window to check TCP connectivity continuously."""
            run_cmd_script(PAPING_PATH, [host, '-p', str(port)])

        port_str, ok = QInputDialog.getText(self, 'Input Port', 'Enter the port number to check TCP connectivity:')

        if not ok:
            return

        port_str = port_str.strip()

        if not port_str.isdigit():
            QMessageBox.warning(self, 'Error', 'No valid port number provided.')
            return

        port = int(port_str)

        if not MIN_PORT <= port <= MAX_PORT:
            QMessageBox.warning(self, 'Error', 'Please enter a valid port number between 1 and 65535.')
            return

        run_paping(ip, port)

    def userip_manager__add(self, selected_ips: list[str], selected_database: Path) -> None:
        """Add the selected IP address(es) to the chosen UserIP database."""
        # Prompt the user for a username
        username, ok = QInputDialog.getText(self, 'Input Username', f'Please enter the username to associate with the selected IP{pluralize(len(selected_ips))}:')

        if not ok:
            return

        username = username.strip()

        if username:  # Only proceed if the user clicked 'OK' and provided a username
            # Append the username and associated IP(s) to the corresponding database file
            write_lines_to_file(selected_database, 'a', [f'{username}={ip}\n' for ip in selected_ips])

            QMessageBox.information(
                self, TITLE,
                (
                    f'Selected IP{pluralize(len(selected_ips))} {list(selected_ips)} '
                    f'ha{pluralize(len(selected_ips), singular="s", plural="ve")} been added with username "{username}" '
                    f'to UserIP database "{selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}".'
                ),
            )
        else:
            # If the user canceled or left the input empty, show an error
            QMessageBox.warning(self, TITLE, 'ERROR:\nNo username was provided.')

    def userip_manager__move(self, selected_ips: list[str], selected_database: Path) -> None:
        """Move the selected IP address(es) to the chosen UserIP database."""
        # Dictionary to store removed entries by database
        deleted_entries_by_database: dict[Path, list[str]] = {}

        # Iterate over each UserIP database
        for database_path in UserIPDatabases.get_userip_database_filepaths():
            if database_path == selected_database:
                continue

            # Read the database file
            lines = database_path.read_text(encoding='utf-8').splitlines(keepends=True)
            if not lines:
                continue

            # List to store deleted entries in this particular database
            deleted_entries_in_this_database: list[str] = []

            # Remove any lines containing the IP address
            lines_to_keep: list[str] = []
            for line in lines:
                # Try to match the regex
                match = RE_USERIP_INI_PARSER_PATTERN.search(line)
                if match:
                    # Extract username and ip using named groups
                    username, ip = match.group('username', 'ip')

                    # Only process if username and ip are strings
                    if isinstance(username, str) and isinstance(ip, str):
                        # Ensure both username and ip are non-empty strings
                        username, ip = username.strip(), ip.strip()

                        # If IP is one of the selected ones, record it as deleted and exclude this line from lines_to_keep
                        if ip in selected_ips:
                            deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                            continue  # skip appending this line

                # All other lines should be kept
                lines_to_keep.append(line)

            if deleted_entries_in_this_database:
                # Only update the database file if there were any deletions
                write_lines_to_file(database_path, 'w', lines_to_keep)

                # Store the deleted entries for this database
                deleted_entries_by_database[database_path] = deleted_entries_in_this_database

                # Move the deleted entries to the target database
                write_lines_to_file(selected_database, 'a', [f'{entry}\n' for entry in deleted_entries_in_this_database])

        # After processing all databases, show a detailed report
        if deleted_entries_by_database:
            report = (
                f'<b>Selected IP{pluralize(len(selected_ips))} {selected_ips} moved from the following '
                f'UserIP database{pluralize(len(deleted_entries_by_database))} to UserIP database '
                f'"{selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}":</b><br><br><br>'
            )
            for database_path, deleted_entries in deleted_entries_by_database.items():
                report += f'<b>{database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}:</b><br>'
                report += '<ul>'
                for entry in deleted_entries:
                    report += f'<li>{entry}</li>'
                report += '</ul><br>'
            report = report.removesuffix('<br>')

            QMessageBox.information(self, TITLE, report)

    def userip_manager__del(self, selected_ips: list[str]) -> None:
        """Remove the selected IP address(es) from all enabled UserIP databases."""
        # Dictionary to store removed entries by database
        deleted_entries_by_database: dict[Path, list[str]] = {}

        # Iterate over each UserIP database
        for database_path in UserIPDatabases.get_userip_database_filepaths():
            # Read the database file
            lines = database_path.read_text(encoding='utf-8').splitlines(keepends=True)
            if not lines:
                continue

            # List to store deleted entries in this particular database
            deleted_entries_in_this_database: list[str] = []

            # Remove any lines containing the IP address
            lines_to_keep: list[str] = []
            for line in lines:
                # Try to match the regex
                match = RE_USERIP_INI_PARSER_PATTERN.search(line)
                if match:
                    # Extract username and ip using named groups
                    username, ip = match.group('username', 'ip')

                    # Only process if username and ip are strings
                    if isinstance(username, str) and isinstance(ip, str):
                        # Ensure both username and ip are non-empty strings
                        username, ip = username.strip(), ip.strip()

                        # If IP is one of the selected ones, record it as deleted and exclude this line from lines_to_keep
                        if ip in selected_ips:
                            deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                            continue  # skip appending this line

                # All other lines should be kept
                lines_to_keep.append(line)

            if deleted_entries_in_this_database:
                # Only update the database file if there were any deletions
                write_lines_to_file(database_path, 'w', lines_to_keep)

                # Store the deleted entries for this database
                deleted_entries_by_database[database_path] = deleted_entries_in_this_database

        # After processing all databases, show a detailed report
        if deleted_entries_by_database:
            report = (
                f'<b>Selected IP{pluralize(len(selected_ips))} {selected_ips} removed from the following '
                f'UserIP database{pluralize(len(deleted_entries_by_database))}:</b><br><br><br>'
            )
            for database_path, deleted_entries in deleted_entries_by_database.items():
                report += f'<b>{database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}:</b><br>'
                report += '<ul>'
                for entry in deleted_entries:
                    report += f'<li>{entry}</li>'
                report += '</ul><br>'
            report = report.removesuffix('<br>')

            QMessageBox.information(self, TITLE, report)

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
            selected_model.rowCount() - 1, selected_model.columnCount() - 1,
        )  # Bottom-right item (last row, last column)

        # Create a selection range from top-left to bottom-right
        selection = QItemSelection(top_left, bottom_right)

        # Use the appropriate selection flag based on the `select` argument
        flag = QItemSelectionModel.SelectionFlag.Select if select else QItemSelectionModel.SelectionFlag.Deselect
        selection_model.select(selection, flag)

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

    def select_all_cells(self) -> None:
        """Select all cells in the table."""
        self._select_all_cells_helper(select=True)

    def unselect_all_cells(self) -> None:
        """Unselect all cells in the table."""
        self._select_all_cells_helper(select=False)

    def select_row_cells(self, row: int) -> None:
        """Select all cells in the specified row."""
        self._select_row_cells_helper(row, select=True)

    def unselect_row_cells(self, row: int) -> None:
        """Unselect all cells in the specified row."""
        self._select_row_cells_helper(row, select=False)

    def select_column_cells(self, column: int) -> None:
        """Select all cells in the specified column."""
        self._select_column_cells_helper(column, select=True)

    def unselect_column_cells(self, column: int) -> None:
        """Unselect all cells in the specified column."""
        self._select_column_cells_helper(column, select=False)
