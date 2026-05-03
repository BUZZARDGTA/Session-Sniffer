"""Context menu mixin for SessionTableView right-click interactions."""

from typing import TYPE_CHECKING

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import QMenu

from session_sniffer.constants.local import BUILTIN_SCRIPTS_DIR_PATH, USER_SCRIPTS_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.stylesheets import CUSTOM_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_detections_mixin import build_detections_menu, build_detections_menu_multi
from session_sniffer.guis.tables_player_actions import (
    block_ip_as_range,
    copy_player_info_for_discord,
    copy_players_info_for_discord,
    ping_ip,
    show_detailed_ip_lookup,
    show_seen_stats,
    tcp_port_ping,
    tcp_port_ping_multi,
)
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
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.utils import run_cmd_script

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtCore import QPoint

    from session_sniffer.guis.tables import SessionTableView
    from session_sniffer.models.player import Player


class TableContextMenuMixin:  # pylint: disable=too-few-public-methods
    """Mixin that adds a context menu to SessionTableView."""

    def _show_context_menu(self: SessionTableView, pos: QPoint) -> None:  # type: ignore[misc]
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
        context_menu.hovered.connect(self.handle_menu_hovered)

        # Resolve a single selected player early so Copy for Discord can sit near Copy Selection
        _early_player: Player | None = None
        if len(selected_indexes) == 1:
            _early_ip_idx = selected_model.index(selected_indexes[0].row(), selected_model.ip_column_index)
            _early_ip = selected_model.get_display_text(_early_ip_idx)
            if _early_ip:
                _early_player = PlayersRegistry.get_player_by_ip(_early_ip)

        # Add "Copy Selection" action
        add_action(
            context_menu,
            '📋 Copy Selection',
            shortcut='Ctrl+C',
            tooltip='Copy selected cells to your clipboard.',
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
        )
        if _early_player is not None:
            _discord_player = _early_player
            add_action(
                context_menu,
                '📋 Copy for Discord',
                tooltip='Copy a detailed player info report formatted for Discord to the clipboard.',
                handler=lambda: copy_player_info_for_discord(_discord_player),
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
                    return lambda: self.remove_players_by_ip_from_table(ip_list)

                add_action(
                    context_menu,
                    label,
                    tooltip=tooltip,
                    handler=create_remove_handler(ips_to_remove),
                )
        context_menu.addSeparator()

        # "Select" submenu
        select_menu = add_menu(context_menu, '☑️ Select')
        add_action(select_menu, '☑️ Select All', shortcut='Ctrl+A', tooltip='Select all cells in the table.', handler=self.select_all_cells)
        add_action(select_menu, '➡️ Select Row', tooltip='Select all cells in this row.', handler=lambda: self.select_row_cells(index.row()))
        add_action(select_menu, '⬇️ Select Column', tooltip='Select all cells in this column.', handler=lambda: self.select_column_cells(index.column()))

        # "Unselect" submenu
        unselect_menu = add_menu(context_menu, '⬜ Unselect')
        add_action(unselect_menu, '⬜ Unselect All', tooltip='Unselect all cells in the table.', handler=self.unselect_all_cells)
        add_action(unselect_menu, '➡️ Unselect Row', tooltip='Unselect all cells in this row.', handler=lambda: self.unselect_row_cells(index.row()))
        add_action(unselect_menu, '⬇️ Unselect Column', tooltip='Unselect all cells in this column.', handler=lambda: self.unselect_column_cells(index.column()))
        context_menu.addSeparator()

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

        def create_script_handler(script_path: Path, ips: list[str]) -> Callable[[], None]:
            return lambda: run_cmd_script(script_path, ips)

        def create_script_handler_per_ip(script_path: Path, ips: list[str]) -> Callable[[], None]:
            def _run() -> None:
                for ip in ips:
                    run_cmd_script(script_path, [ip])
            return _run

        def add_scripts_to_menu(menu: QMenu, scripts: list[Path], ips: list[str], *, per_ip: bool = False) -> None:
            factory = create_script_handler_per_ip if per_ip else create_script_handler
            for script in scripts:
                add_action(menu, script.resolve().name, tooltip='', handler=factory(script.resolve(), ips))

        def _populate_scripts_menu(menu: QMenu, builtin: list[Path], user: list[Path], ips: list[str], *, per_ip: bool = False) -> None:
            add_scripts_to_menu(menu, builtin, ips, per_ip=per_ip)
            if builtin and user:
                menu.addSeparator()
            add_scripts_to_menu(menu, user, ips, per_ip=per_ip)

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
                        '🔎 IP Lookup Details',
                        tooltip='Displays a notification with a detailed IP lookup report for selected player.',
                        handler=lambda: show_detailed_ip_lookup(self, player_obj),
                    )

                    add_action(
                        context_menu,
                        '📅 Seen Stats',
                        tooltip='Shows how many sessions this IP appeared in (today, week, month, year, total).',
                        handler=lambda: show_seen_stats(self, player_obj),
                    )

                    if self.is_connected_table and self.open_rate_graph_callback is not None:
                        _graph_cb = self.open_rate_graph_callback
                        add_action(
                            context_menu,
                            '📈 Rate Graph',
                            tooltip='Open a live PPS/BPS graph for this player.',
                            handler=lambda: _graph_cb(ip_address),
                        )

                    ping_menu = add_menu(context_menu, '📡 Ping')
                    add_action(
                        ping_menu,
                        '🏓 Normal',
                        tooltip='Checks if selected IP address responds to pings.',
                        handler=lambda: ping_ip(ip_address),
                    )
                    add_action(
                        ping_menu,
                        '🔌 TCP Port (paping.exe)',
                        tooltip='Checks if selected IP address responds to TCP pings on a given port.',
                        handler=lambda: tcp_port_ping(self, ip_address),
                    )

                    # --- Detections submenu (single IP) ---
                    if Settings.capture_program_preset == 'GTA5' and not CaptureState.is_arp_interface:
                        detections_menu = add_menu(context_menu, '🚨 Detections')
                        build_detections_menu(detections_menu, add_action, player_obj, self)

                    # --- Block IP (single IP) ---
                    def _do_block_single_ip() -> None:
                        entry = block_ip_as_range(self, ip_address)
                        if entry is None:
                            return
                        _main_window = self.window()
                        for _player in PlayersRegistry.get_default_sorted_players():
                            if check_ip_against_ranges(_player.ip, Settings.blocked_ip_ranges):
                                if _player.left_event.is_set():
                                    _main_window.remove_player_from_disconnected(_player.ip)
                                else:
                                    _main_window.remove_player_from_connected(_player.ip)

                    add_action(
                        context_menu,
                        '🚫 Block IP / Range',
                        tooltip='Block this IP or a range/subnet from appearing in the session. Persisted to settings.',
                        handler=_do_block_single_ip,
                    )

                    scripts_menu = add_menu(context_menu, '📜 User Scripts')
                    _single_ip = [ip_address]
                    builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
                    user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)
                    _populate_scripts_menu(scripts_menu, builtin_scripts, user_scripts, _single_ip)

                    userip_menu = add_menu(context_menu, '🗂️ UserIP')

                    if matched_player.userip is None:
                        add_userip_menu = add_menu(userip_menu, '📥 Add', 'Add selected IP address to UserIP database.')
                        populate_db_menu(
                            add_userip_menu,
                            userip_database_filepaths,
                            tooltip='Add selected IP address to this UserIP database.',
                            handler_factory=lambda db_path: lambda: userip_add(self, [ip_address], db_path),
                        )
                        add_range_userip_menu = add_menu(userip_menu, '📥 Add as Range', 'Add selected IP as a range entry to a UserIP database.')
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
                            '📂 Open Database',
                            tooltip="Open this player's UserIP database file in the default text editor.",
                            handler=_open_userip_database,
                        )
                        userip_menu.addSeparator()
                        add_action(
                            userip_menu,
                            '📥 Add Username',
                            tooltip='Add an additional username for this IP address in its UserIP database.',
                            handler=lambda: userip_add_username(self, ip_address, player_obj),
                        )
                        add_action(
                            userip_menu,
                            '✏️ Rename',
                            tooltip='Rename all entries for this IP address by picking from existing usernames in its database.',
                            handler=lambda: userip_rename(self, ip_address, player_obj),
                        )
                        if userip.usernames and len(userip.usernames) >= MIN_USERNAMES_FOR_REMOVAL:
                            add_action(
                                userip_menu,
                                '❌ Remove Username',
                                tooltip='Remove selected username(s) for this IP address while keeping others.',
                                handler=lambda: userip_remove_username(self, ip_address, player_obj),
                            )
                        move_userip_menu = add_menu(userip_menu, '📦 Move', 'Move selected IP address to another database.')
                        populate_db_menu(
                            move_userip_menu,
                            userip_database_filepaths,
                            tooltip='Move selected IP address to this UserIP database.',
                            handler_factory=lambda db_path: lambda: userip_move(self, [ip_address], db_path),
                            disabled_path=userip.database_path,
                        )
                        add_action(
                            userip_menu,
                            '🗑️ Delete',
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
                matched_players = [p for ip in all_ips if (p := PlayersRegistry.get_player_by_ip(ip)) is not None]

                # --- IP Lookup Details / Seen Stats (multi-IP) ---
                if matched_players:
                    def _show_all_lookups() -> None:
                        for _p in matched_players:
                            show_detailed_ip_lookup(self, _p)

                    def _show_all_seen_stats() -> None:
                        for _p in matched_players:
                            show_seen_stats(self, _p)

                    add_action(context_menu, '🔎 IP Lookup Details', tooltip='Displays a detailed IP lookup report for each selected player.', handler=_show_all_lookups)
                    add_action(context_menu, '📅 Seen Stats', tooltip='Shows session appearance stats for each selected player.', handler=_show_all_seen_stats)
                    add_action(
                        context_menu, '📋 Copy for Discord',
                        tooltip='Copy Discord-formatted reports for all selected players to the clipboard.',
                        handler=lambda: copy_players_info_for_discord(matched_players),
                    )

                # --- Rate Graph (multi-IP, connected table only) ---
                if self.is_connected_table and self.open_rate_graph_callback is not None:
                    _multi_graph_cb = self.open_rate_graph_callback
                    _multi_ips = list(all_ips)

                    def _open_multi_graphs() -> None:
                        for _ip in _multi_ips:
                            _multi_graph_cb(_ip)

                    add_action(
                        context_menu,
                        '📈 Rate Graph',
                        tooltip='Open a live PPS/BPS graph for each selected player.',
                        handler=_open_multi_graphs,
                    )

                # --- Ping submenu (multi-IP) ---
                ping_menu = add_menu(context_menu, '📡 Ping')
                _ping_ips = list(all_ips)

                def _ping_all() -> None:
                    for _ip in _ping_ips:
                        ping_ip(_ip)

                def _tcp_ping_all_one_port() -> None:
                    tcp_port_ping_multi(self, _ping_ips)

                def _tcp_ping_all_diff_ports() -> None:
                    for _ip in _ping_ips:
                        tcp_port_ping(self, _ip)

                add_action(
                    ping_menu,
                    '🏓 Normal',
                    tooltip='Checks if selected IP addresses respond to pings.',
                    handler=_ping_all,
                )
                tcp_menu = add_menu(ping_menu, '🔌 TCP Port (paping.exe)')
                add_action(
                    tcp_menu,
                    '🔌 One Port for All',
                    tooltip='Ask for a port once, then TCP ping all selected IPs on that port.',
                    handler=_tcp_ping_all_one_port,
                )
                add_action(
                    tcp_menu,
                    '🔌 Individual Port per IP',
                    tooltip='Ask for a separate port for each selected IP.',
                    handler=_tcp_ping_all_diff_ports,
                )

                # --- User Scripts submenu (multi-IP) ---
                multi_scripts_menu = add_menu(context_menu, '📜 User Scripts')

                _script_ips = list(all_ips)
                multi_builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
                multi_user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)

                all_scripts = multi_builtin_scripts + multi_user_scripts
                if all_scripts:
                    all_at_once_menu = add_menu(multi_scripts_menu, '📜 All IPs as Args', 'Pass all selected IPs as arguments to the script in one call.')
                    _populate_scripts_menu(all_at_once_menu, multi_builtin_scripts, multi_user_scripts, _script_ips)

                    per_ip_menu = add_menu(multi_scripts_menu, '📜 One Process per IP', 'Spawn a separate script process for each selected IP.')
                    _populate_scripts_menu(per_ip_menu, multi_builtin_scripts, multi_user_scripts, _script_ips, per_ip=True)

                # --- Detections submenu (multi-IP) ---
                if matched_players and Settings.capture_program_preset == 'GTA5' and not CaptureState.is_arp_interface:
                    detections_menu = add_menu(context_menu, '🚨 Detections')
                    build_detections_menu_multi(detections_menu, add_action, matched_players, self)

                # --- Block IPs (multi-IP) ---
                _block_ips = list(all_ips)

                def _do_block_multi_ips() -> None:
                    for _ip in _block_ips:
                        block_ip_as_range(self, _ip)
                    if not Settings.blocked_ip_ranges:
                        return
                    _main_window = self.window()
                    for _player in PlayersRegistry.get_default_sorted_players():
                        if check_ip_against_ranges(_player.ip, Settings.blocked_ip_ranges):
                            if _player.left_event.is_set():
                                _main_window.remove_player_from_disconnected(_player.ip)
                            else:
                                _main_window.remove_player_from_connected(_player.ip)

                add_action(
                    context_menu,
                    f'🚫 Block {len(_block_ips)} IPs / Ranges',
                    tooltip='For each selected IP, prompt whether to block as single IP, range, or subnet. Persisted to settings.',
                    handler=_do_block_multi_ips,
                )

                if all(not UserIPDatabases.is_known_ip(ip) for ip in all_ips):
                    userip_menu = add_menu(context_menu, '🗂️ UserIP')

                    add_userip_menu = add_menu(userip_menu, '📥 Add Selected')
                    populate_db_menu(
                        add_userip_menu,
                        UserIPDatabases.get_userip_database_filepaths(),
                        tooltip='Add selected IP addresses to this UserIP database.',
                        handler_factory=lambda db_path: lambda: userip_add(self, all_ips, db_path),
                    )
                elif all(UserIPDatabases.is_known_ip(ip) for ip in all_ips):
                    userip_menu = add_menu(context_menu, '🗂️ UserIP')

                    move_userip_menu = add_menu(userip_menu, '📦 Move Selected')
                    populate_db_menu(
                        move_userip_menu,
                        UserIPDatabases.get_userip_database_filepaths(),
                        tooltip='Move selected IP addresses to this UserIP database.',
                        handler_factory=lambda db_path: lambda: userip_move(self, all_ips, db_path),
                    )

                    add_action(
                        userip_menu,
                        '🗑️ Delete Selected',
                        tooltip='Delete selected IP addresses from UserIP databases.',
                        handler=lambda: userip_delete(self, all_ips),
                    )

        # Execute the context menu at the right-click position
        context_menu.popup(self.mapToGlobal(pos))
