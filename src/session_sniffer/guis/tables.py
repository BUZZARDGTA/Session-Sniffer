"""Session table view for connected and disconnected players tables."""

from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QAbstractItemModel, QEvent, QItemSelection, QItemSelectionModel, QModelIndex, QObject, QPoint, Qt, QUrl
from PyQt6.QtGui import QAction, QClipboard, QDesktopServices, QHoverEvent, QKeyEvent, QMouseEvent
from PyQt6.QtWidgets import QHeaderView, QMenu, QSizePolicy, QTableView, QToolTip, QWidget

from session_sniffer.constants.local import BUILTIN_SCRIPTS_DIR_PATH, USER_SCRIPTS_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.error_messages import ensure_instance, format_type_error
from session_sniffer.guis.app import app
from session_sniffer.guis.stylesheets import CUSTOM_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables_detections_mixin import build_detections_menu, build_detections_menu_multi
from session_sniffer.guis.tables_player_actions import ping_ip, show_detailed_ip_lookup, show_seen_stats, tcp_port_ping
from session_sniffer.guis.tables_userip_mixin import (
    MIN_USERNAMES_FOR_REMOVAL,
    userip_add,
    userip_add_as_range,
    userip_add_username,
    userip_delete,
    userip_move,
    userip_remove_username,
    userip_rename,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.utils import run_cmd_script

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from session_sniffer.guis.main_window import MainWindow
    from session_sniffer.models.player import Player


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
        self.open_rate_graph_callback: Callable[[str], None] | None = None  # Optional callback to open a rate graph for an IP
        self._drag_selecting: bool = False  # Track if the mouse is being dragged with Ctrl key
        self._previous_cell: QModelIndex | None = None  # Track the previously selected cell
        self._previous_sort_section_index: int | None = None
        self._saved_selection: list[tuple[str, int]] = []  # (ip, column) pairs for selection preservation

        self.setModel(model)
        self.setMouseTracking(True)  # Track mouse without clicks
        viewport = self.viewport()
        viewport.installEventFilter(self)  # Install event filter
        # Configure table view settings
        vertical_header = self.verticalHeader()
        vertical_header.setVisible(False)  # Hide row index
        vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)  # Fixed row heights for faster layout
        self.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)  # Smooth pixel-based scrolling
        self.setHorizontalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        horizontal_header = self.horizontalHeader()
        horizontal_header.setSectionsClickable(True)
        horizontal_header.sectionClicked.connect(self._on_section_clicked)
        horizontal_header.setSectionsMovable(True)
        horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        horizontal_header.customContextMenuRequested.connect(self._show_header_context_menu)
        self.setSelectionMode(QTableView.SelectionMode.NoSelection)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)

        # Set the sort indicator for the specified column
        self.setSortingEnabled(False)
        horizontal_header.setSortIndicator(sort_column, sort_order)
        horizontal_header.setSortIndicatorShown(True)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def setModel(self, model: QAbstractItemModel | None) -> None:
        """Override the setModel method to ensure the model is of type SessionTableModel."""
        super().setModel(ensure_instance(model, SessionTableModel))

    def model(self) -> SessionTableModel:
        """Override the model method to ensure it returns a SessionTableModel."""
        return ensure_instance(super().model(), SessionTableModel)

    def selectionModel(self) -> QItemSelectionModel:
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        return ensure_instance(super().selectionModel(), QItemSelectionModel)

    def viewport(self) -> QWidget:
        """Override the viewport method to ensure it returns a QWidget."""
        return ensure_instance(super().viewport(), QWidget)

    def verticalHeader(self) -> QHeaderView:
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().verticalHeader(), QHeaderView)

    def horizontalHeader(self) -> QHeaderView:
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().horizontalHeader(), QHeaderView)

    def window(self) -> MainWindow:
        """Override the window method to ensure it returns the parent `MainWindow`."""
        return cast('MainWindow', super().window())

    def eventFilter(self, object: QObject | None, event: QEvent | None) -> bool:
        """Show country flag tooltips on hover and forward other events."""
        if isinstance(object, QObject) and isinstance(event, QHoverEvent):
            index = self.indexAt(event.position().toPoint())  # Get hovered cell
            if index.isValid():
                model = self.model()
                if (country_col := model.get_column_index('Country')) is not None and country_col == index.column():
                    ip = model.get_display_text(model.index(index.row(), model.ip_column_index))
                    if ip is not None:
                        matched_player = PlayersRegistry.get_player_by_ip(ip)
                        if matched_player is not None and matched_player.country_flag is not None:
                            self._show_flag_tooltip(event, index, matched_player)

        return super().eventFilter(object, event)

    def keyPressEvent(self, e: QKeyEvent | None) -> None:
        """Handle key press events to capture Ctrl+A for selecting all and Ctrl+C for copying selected data to the clipboard.

        Fall back to default behavior for other key presses.
        """
        if isinstance(e, QKeyEvent):
            if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                if e.key() == Qt.Key.Key_A:
                    self._select_all_cells()
                elif e.key() == Qt.Key.Key_C:
                    self._copy_selected_cells(self.model(), self.selectionModel().selectedIndexes())
                return

        # Fall back to default behavior
        super().keyPressEvent(e)

    def mousePressEvent(self, e: QMouseEvent | None) -> None:
        """Handle mouse press events for selecting multiple items with Ctrl or single items otherwise.

        Fall back to default behavior for non-cell areas.
        """
        if e is not None:
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

                elif e.button() == Qt.MouseButton.RightButton:
                    if not selection_model.isSelected(index):
                        selection_flag = QItemSelectionModel.SelectionFlag.ClearAndSelect

                if selection_flag is not None:
                    selection_model.select(index, selection_flag)

        # Fall back to default behavior
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e: QMouseEvent | None) -> None:
        """Handle mouse movement during Ctrl + Left-Click drag to toggle the selection of multiple cells."""
        if e is not None:
            index = self.indexAt(e.pos())  # Get the index under the cursor
            if index.isValid():
                selection_model = self.selectionModel()

                if e.buttons() == Qt.MouseButton.LeftButton:
                    if e.modifiers() == Qt.KeyboardModifier.ControlModifier:
                        if self._drag_selecting and self._previous_cell != index:
                            self._previous_cell = index

                            selection_model.select(index, (
                                QItemSelectionModel.SelectionFlag.Deselect
                                if selection_model.isSelected(index)
                                else QItemSelectionModel.SelectionFlag.Select
                            ))

        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e: QMouseEvent | None) -> None:
        """Reset dragging state when the mouse button is released."""
        if e is not None:
            if e.button() == Qt.MouseButton.LeftButton:
                self._drag_selecting = False
                self._previous_cell = None

        super().mouseReleaseEvent(e)

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
                'Bandwidth', 'T. Bandwidth', 'Download', 'T. Download', 'Upload', 'T. Upload', 'BPS', 'BPM',
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

        if self._has_any_username():
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.Stretch)
        else:
            header.setSectionResizeMode(model.username_column_index, QHeaderView.ResizeMode.ResizeToContents)

    def sort_current_column(self) -> None:
        """Sort the table by the currently indicated header column and order."""
        model = self.model()
        horizontal_header = self.horizontalHeader()
        model.sort(horizontal_header.sortIndicatorSection(), horizontal_header.sortIndicatorOrder())

    def _has_any_username(self) -> bool:
        """Return True if any row has a non-empty username value."""
        model = self.model()
        col = model.username_column_index
        for row in range(model.rowCount()):
            text = model.data(model.index(row, col), Qt.ItemDataRole.DisplayRole)
            if isinstance(text, str) and text.strip():
                return True
        return False

    def _get_sorted_column(self) -> tuple[str, Qt.SortOrder]:
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

    def capture_selection(self) -> None:
        """Save the current cell selection by player IP for later restoration."""
        selected_indexes = self.selectionModel().selectedIndexes()
        if not selected_indexes:
            self._saved_selection.clear()
            return

        model = self.model()
        self._saved_selection.clear()
        for index in selected_indexes:
            row = index.row()
            if 0 <= row < model.rowCount():
                ip = model.get_ip_for_row(row)
                self._saved_selection.append((ip, index.column()))

    def restore_selection(self) -> None:
        """Restore cell selection from previously captured player IPs."""
        if not self._saved_selection:
            return

        model = self.model()
        selection = QItemSelection()

        for ip, column in self._saved_selection:
            row = model.get_row_index_by_ip(ip)
            if row is not None:
                index = model.index(row, column)
                selection.select(index, index)

        self.selectionModel().select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        self._saved_selection.clear()

    def _handle_menu_hovered(self, action: QAction) -> None:
        """Propagate QAction tooltip text to its parent menu."""
        # Fixes: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        action_parent = action.parent()
        if isinstance(action_parent, QMenu):
            action_parent.setToolTip(action.toolTip())

    def _on_section_clicked(self, section_index: int) -> None:
        """Sort the table by the clicked header section."""
        model = self.model()
        horizontal_header = self.horizontalHeader()

        # If it's the first click or sorting is being toggled
        if self._previous_sort_section_index is None or self._previous_sort_section_index != section_index:
            horizontal_header.setSortIndicator(section_index, Qt.SortOrder.DescendingOrder)

        # Sort the model
        model.sort(section_index, horizontal_header.sortIndicatorOrder())
        self._previous_sort_section_index = section_index

    def _show_header_context_menu(self, pos: QPoint) -> None:
        """Show a context menu on the column header with checkboxes to toggle column visibility."""
        if self._is_connected_table:
            toggleable_columns = Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS
            shown_columns = set(Settings.gui_columns_connected_shown)
        else:
            toggleable_columns = Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS
            shown_columns = set(Settings.gui_columns_disconnected_shown)

        menu = QMenu(self)
        menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)

        for col_name in toggleable_columns:
            action = QAction(col_name, menu)
            action.setCheckable(True)
            action.setChecked(col_name in shown_columns)

            def _on_toggled(checked: bool, name: str = col_name) -> None:  # noqa: FBT001
                self._toggle_column_visibility(name, checked=checked)

            action.toggled.connect(_on_toggled)
            menu.addAction(action)

        menu.popup(self.horizontalHeader().mapToGlobal(pos))

    def _toggle_column_visibility(self, column_name: str, *, checked: bool) -> None:
        """Toggle a column's visibility and persist the change to settings."""
        if self._is_connected_table:
            shown = set(Settings.gui_columns_connected_shown)
            toggleable = Settings.GUI_TOGGLEABLE_CONNECTED_COLUMNS
        else:
            shown = set(Settings.gui_columns_disconnected_shown)
            toggleable = Settings.GUI_TOGGLEABLE_DISCONNECTED_COLUMNS

        if checked:
            shown.add(column_name)
        else:
            shown.discard(column_name)

        # Preserve ordering from the toggleable columns tuple
        new_shown = tuple(col for col in toggleable if col in shown)

        if self._is_connected_table:
            Settings.gui_columns_connected_shown = new_shown
        else:
            Settings.gui_columns_disconnected_shown = new_shown

        Settings.rewrite_settings_file()

    def _show_flag_tooltip(self, event: QHoverEvent, index: QModelIndex, player: Player) -> None:
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

    def _show_context_menu(self, pos: QPoint) -> None:
        """Show the context menu at the specified position with options to interact with the table's content."""
        def add_action(
            menu: QMenu,
            label: str,
            shortcut: str | None = None,
            tooltip: str | None = None,
            handler: Callable[..., None] | None = None,
        ) -> QAction:
            """Helper to create and configure a QAction."""
            action = ensure_instance(menu.addAction(label), QAction)

            if shortcut:
                action.setShortcut(shortcut)
            if tooltip:
                action.setToolTip(tooltip)
            if handler:
                action.triggered.connect(handler)

            return action

        def add_menu(parent_menu: QMenu, label: str, tooltip: str | None = None) -> QMenu:
            """Helper to create and configure a QMenu."""
            menu = ensure_instance(parent_menu.addMenu(label), QMenu)

            if tooltip:
                menu.setToolTip(tooltip)

            return menu

        def populate_db_menu(
            parent_menu: QMenu,
            database_paths: list[Path],
            tooltip: str,
            handler_factory: Callable[[Path], Callable[[], None]],
            disabled_path: Path | None = None,
        ) -> None:
            """Add database entries to *parent_menu*, nesting subfolders as child menus."""
            folder_menus: dict[tuple[str, ...], QMenu] = {}

            for database_path in database_paths:
                rel = database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
                parts = rel.parts

                if len(parts) == 1:
                    action = add_action(parent_menu, parts[0], tooltip=tooltip, handler=handler_factory(database_path))
                    if disabled_path is not None and database_path == disabled_path:
                        action.setEnabled(False)
                else:
                    # Build / reuse nested submenus for each folder level
                    current_menu = parent_menu
                    for depth in range(len(parts) - 1):
                        folder_key = parts[: depth + 1]
                        if folder_key not in folder_menus:
                            folder_menus[folder_key] = add_menu(current_menu, parts[depth])
                        current_menu = folder_menus[folder_key]

                    action = add_action(current_menu, parts[-1], tooltip=tooltip, handler=handler_factory(database_path))
                    if disabled_path is not None and database_path == disabled_path:
                        action.setEnabled(False)

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
        context_menu.hovered.connect(self._handle_menu_hovered)

        # Add "Copy Selection" action
        add_action(
            context_menu,
            'Copy Selection',
            shortcut='Ctrl+C',
            tooltip='Copy selected cells to your clipboard.',
            handler=lambda: self._copy_selected_cells(selected_model, selected_indexes),
        )
        context_menu.addSeparator()

        # Add "Remove Player" action for any selection (resolve IPs from selected rows)
        if selected_indexes:
            ips_to_remove: set[str] = set()
            seen_rows: set[int] = set()
            for idx in selected_indexes:
                row = idx.row()
                if row not in seen_rows:
                    seen_rows.add(row)
                    ip_idx = selected_model.index(row, selected_model.ip_column_index)
                    displayed_ip = selected_model.get_display_text(ip_idx)
                    if displayed_ip:
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
                    return lambda: self._remove_players_by_ip_from_table(ip_list)

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
            handler=self._select_all_cells,
        )
        add_action(
            select_menu,
            'Select Row',
            tooltip='Select all cells in this row.',
            handler=lambda: self._select_row_cells(index.row()),
        )
        add_action(
            select_menu,
            'Select Column',
            tooltip='Select all cells in this column.',
            handler=lambda: self._select_column_cells(index.column()),
        )

        # "Unselect" submenu
        unselect_menu = add_menu(context_menu, 'Unselect')
        add_action(
            unselect_menu,
            'Unselect All',
            tooltip='Unselect all cells in the table.',
            handler=self._unselect_all_cells,
        )
        add_action(
            unselect_menu,
            'Unselect Row',
            tooltip='Unselect all cells in this row.',
            handler=lambda: self._unselect_row_cells(index.row()),
        )
        add_action(
            unselect_menu,
            'Unselect Column',
            tooltip='Unselect all cells in this column.',
            handler=lambda: self._unselect_column_cells(index.column()),
        )
        context_menu.addSeparator()

        # Process if one cell is selected
        if len(selected_indexes) == 1:
            # Resolve the IP address from the selected row regardless of which column was clicked
            ip_index = selected_model.index(selected_indexes[0].row(), selected_model.ip_column_index)
            displayed_ip = selected_model.get_display_text(ip_index)
            if displayed_ip:
                userip_database_filepaths = UserIPDatabases.get_userip_database_filepaths()
                matched_player = PlayersRegistry.get_player_by_ip(displayed_ip)
                if matched_player is not None:
                    # Create local copies to use in lambdas
                    ip_address = displayed_ip
                    player_obj = matched_player

                    add_action(
                        context_menu,
                        'IP Lookup Details',
                        tooltip='Displays a notification with a detailed IP lookup report for selected player.',
                        handler=lambda: show_detailed_ip_lookup(self, player_obj),
                    )

                    add_action(
                        context_menu,
                        'Seen Stats',
                        tooltip='Shows how many sessions this IP appeared in (today, week, month, year, total).',
                        handler=lambda: show_seen_stats(self, player_obj),
                    )

                    if self._is_connected_table and self.open_rate_graph_callback is not None:
                        _graph_cb = self.open_rate_graph_callback
                        add_action(
                            context_menu,
                            'Rate Graph',
                            tooltip='Open a live PPS/BPS graph for this player.',
                            handler=lambda: _graph_cb(ip_address),
                        )

                    ping_menu = add_menu(context_menu, 'Ping    ')
                    add_action(
                        ping_menu,
                        'Normal',
                        tooltip='Checks if selected IP address responds to pings.',
                        handler=lambda: ping_ip(ip_address),
                    )
                    add_action(
                        ping_menu,
                        'TCP Port (paping.exe)',
                        tooltip='Checks if selected IP address responds to TCP pings on a given port.',
                        handler=lambda: tcp_port_ping(self, ip_address),
                    )

                    # --- Detections submenu (single IP) ---
                    if Settings.capture_program_preset == 'GTA5' and not CaptureState.is_arp_interface:
                        detections_menu = add_menu(context_menu, 'Detections')
                        build_detections_menu(detections_menu, add_action, player_obj)

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
                        populate_db_menu(
                            add_userip_menu,
                            userip_database_filepaths,
                            tooltip='Add selected IP address to this UserIP database.',
                            handler_factory=lambda db_path: lambda: userip_add(self, [ip_address], db_path),
                        )
                        add_range_userip_menu = add_menu(userip_menu, 'Add as Range', 'Add selected IP as a range entry to a UserIP database.')
                        populate_db_menu(
                            add_range_userip_menu,
                            userip_database_filepaths,
                            tooltip='Add selected IP as a range to this UserIP database.',
                            handler_factory=lambda db_path: lambda: userip_add_as_range(self, ip_address, db_path),
                        )
                    else:
                        userip = player_obj.userip
                        if userip is None:
                            msg = 'Expected player_obj.userip to be set in else branch'
                            raise TypeError(msg)

                        def _open_userip_database() -> None:
                            QDesktopServices.openUrl(QUrl.fromLocalFile(str(userip.database_path)))

                        add_action(
                            userip_menu,
                            'Open Database',
                            tooltip="Open this player's UserIP database file in the default text editor.",
                            handler=_open_userip_database,
                        )
                        userip_menu.addSeparator()
                        add_action(
                            userip_menu,
                            'Add Username',
                            tooltip='Add an additional username for this IP address in its UserIP database.',
                            handler=lambda: userip_add_username(self, ip_address, player_obj),
                        )
                        add_action(
                            userip_menu,
                            'Rename  ',
                            tooltip='Rename all entries for this IP address by picking from existing usernames in its database.',
                            handler=lambda: userip_rename(self, ip_address, player_obj),
                        )
                        if userip.usernames and len(userip.usernames) >= MIN_USERNAMES_FOR_REMOVAL:
                            add_action(
                                userip_menu,
                                'Remove Username',
                                tooltip='Remove selected username(s) for this IP address while keeping others.',
                                handler=lambda: userip_remove_username(self, ip_address, player_obj),
                            )
                        move_userip_menu = add_menu(userip_menu, 'Move    ', 'Move selected IP address to another database.')
                        populate_db_menu(
                            move_userip_menu,
                            userip_database_filepaths,
                            tooltip='Move selected IP address to this UserIP database.',
                            handler_factory=lambda db_path: lambda: userip_move(self, [ip_address], db_path),
                            disabled_path=userip.database_path,
                        )
                        add_action(
                            userip_menu,
                            'Delete  ',  # Extra spaces for alignment
                            tooltip='Delete selected IP address from UserIP databases.',
                            handler=lambda: userip_delete(self, [ip_address]),
                        )

        # Check if multiple cells are selected in the same column
        elif len(selected_indexes) > 1:
            # Resolve unique IPs from all selected rows
            seen_multi_rows: set[int] = set()
            all_ips: list[str] = []
            for idx in selected_indexes:
                row = idx.row()
                if row in seen_multi_rows:
                    continue
                seen_multi_rows.add(row)
                ip_idx = selected_model.index(row, selected_model.ip_column_index)
                displayed_ip = selected_model.get_display_text(ip_idx)
                if displayed_ip and displayed_ip not in all_ips:
                    all_ips.append(displayed_ip)

            if all_ips:
                # --- Detections submenu (multi-IP) ---
                matched_players = [
                    player
                    for ip in all_ips
                    if (player := PlayersRegistry.get_player_by_ip(ip)) is not None
                ]
                if matched_players and Settings.capture_program_preset == 'GTA5' and not CaptureState.is_arp_interface:
                    detections_menu = add_menu(context_menu, 'Detections')
                    build_detections_menu_multi(detections_menu, add_action, matched_players)

                if all(not UserIPDatabases.is_known_ip(ip) for ip in all_ips):
                    userip_menu = add_menu(context_menu, 'UserIP  ')

                    add_userip_menu = add_menu(userip_menu, 'Add Selected')
                    populate_db_menu(
                        add_userip_menu,
                        UserIPDatabases.get_userip_database_filepaths(),
                        tooltip='Add selected IP addresses to this UserIP database.',
                        handler_factory=lambda db_path: lambda: userip_add(self, all_ips, db_path),
                    )
                elif all(UserIPDatabases.is_known_ip(ip) for ip in all_ips):
                    userip_menu = add_menu(context_menu, 'UserIP  ')

                    move_userip_menu = add_menu(userip_menu, 'Move Selected')
                    populate_db_menu(
                        move_userip_menu,
                        UserIPDatabases.get_userip_database_filepaths(),
                        tooltip='Move selected IP addresses to this UserIP database.',
                        handler_factory=lambda db_path: lambda: userip_move(self, all_ips, db_path),
                    )

                    add_action(
                        userip_menu,
                        'Delete Selected',  # Extra spaces for alignment
                        tooltip='Delete selected IP addresses from UserIP databases.',
                        handler=lambda: userip_delete(self, all_ips),
                    )

        # Execute the context menu at the right-click position
        context_menu.popup(self.mapToGlobal(pos))

    def _copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
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

    def _remove_players_by_ip_from_table(self, ips: set[str]) -> None:
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

    def _select_all_cells(self) -> None:
        """Select all cells in the table."""
        self._select_all_cells_helper(select=True)

    def _unselect_all_cells(self) -> None:
        """Unselect all cells in the table."""
        self._select_all_cells_helper(select=False)

    def _select_row_cells(self, row: int) -> None:
        """Select all cells in the specified row."""
        self._select_row_cells_helper(row, select=True)

    def _unselect_row_cells(self, row: int) -> None:
        """Unselect all cells in the specified row."""
        self._select_row_cells_helper(row, select=False)

    def _select_column_cells(self, column: int) -> None:
        """Select all cells in the specified column."""
        self._select_column_cells_helper(column, select=True)

    def _unselect_column_cells(self, column: int) -> None:
        """Unselect all cells in the specified column."""
        self._select_column_cells_helper(column, select=False)
