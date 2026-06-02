"""Context menu mixin for SessionTableView right-click interactions."""

from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QItemSelectionModel, QUrl
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import QMenu, QTableView

from session_sniffer.constants.local import BUILTIN_SCRIPTS_DIR_PATH, USER_SCRIPTS_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.stylesheets import CUSTOM_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables_detections_mixin import build_detections_menu, build_detections_menu_multi
from session_sniffer.guis.tables_player_actions import (
    block_ip_as_range,
    copy_player_info_for_discord,
    copy_players_info_for_discord,
    ping_ip,
    show_crawler_request,
    show_detailed_ip_lookup,
    show_looky_lookup,
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
    userip_rename_multi,
)
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.player.registry import PlayersRegistry, SessionHost, is_third_party_server_ip
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.utils import run_cmd_script

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtCore import QModelIndex, QPoint

    from session_sniffer.guis.main_window import MainWindow
    from session_sniffer.models.player import Player


class TableContextMenuMixin(QTableView):
    """Mixin that adds a context menu to SessionTableView."""

    if TYPE_CHECKING:
        is_connected_table: bool
        open_rate_graph_callback: Callable[[str], None] | None
        handle_menu_hovered: Callable[[QAction], None]
        copy_selected_cells: Callable[[SessionTableModel, list[QModelIndex]], None]
        remove_players_by_ip_from_table: Callable[[set[str]], None]
        select_all_cells: Callable[[], None]
        unselect_all_cells: Callable[[], None]
        select_row_cells: Callable[[int], None]
        unselect_row_cells: Callable[[int], None]
        select_column_cells: Callable[[int], None]
        unselect_column_cells: Callable[[int], None]

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
            menu.setToolTipsVisible(True)

            if tooltip:
                menu.setToolTip(tooltip)
                menu_action = menu.menuAction()
                if menu_action is not None:
                    menu_action.setToolTip(tooltip)

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

                if len(rel.parts) == 1:
                    action = add_action(parent_menu, rel.parts[0], tooltip=tooltip, handler=handler_factory(database_path))
                    if disabled_path is not None and database_path == disabled_path:
                        action.setEnabled(False)
                else:
                    # Build / reuse nested submenus for each folder level
                    current_menu = parent_menu
                    for depth in range(len(rel.parts) - 1):
                        folder_key = rel.parts[: depth + 1]
                        if folder_key not in folder_menus:
                            folder_menus[folder_key] = add_menu(current_menu, rel.parts[depth])
                        current_menu = folder_menus[folder_key]

                    action = add_action(current_menu, rel.parts[-1], tooltip=tooltip, handler=handler_factory(database_path))
                    if disabled_path is not None and database_path == disabled_path:
                        action.setEnabled(False)

        # Determine the index at the clicked position
        index = self.indexAt(pos)
        if not index.isValid():
            return  # Do nothing if the click is outside valid cells

        selected_model = ensure_instance(self.model(), SessionTableModel)
        selection_model = ensure_instance(self.selectionModel(), QItemSelectionModel)
        selected_indexes = selection_model.selectedIndexes()

        # Create the main context menu
        context_menu = QMenu(self)
        context_menu.setStyleSheet(CUSTOM_CONTEXT_MENU_STYLESHEET)
        context_menu.setToolTipsVisible(True)
        context_menu.hovered.connect(self.handle_menu_hovered)

        def get_selected_ips(indexes: list[QModelIndex]) -> list[str]:
            seen_rows: set[int] = set()
            ips: list[str] = []
            for selected_index in indexes:
                if selected_index.row() in seen_rows:
                    continue
                seen_rows.add(selected_index.row())
                ip_index = selected_model.index(selected_index.row(), selected_model.ip_column_index)
                displayed_ip = selected_model.get_display_text(ip_index)
                if displayed_ip and displayed_ip not in ips:
                    ips.append(displayed_ip)
            return ips

        def get_matched_players(ips: list[str]) -> list[Player]:
            return [player for ip in ips if (player := PlayersRegistry.get_player_by_ip(ip)) is not None]

        def remove_blocked_players_from_tables() -> None:
            main_window = cast('MainWindow', self.window())
            for player in PlayersRegistry.get_default_sorted_players():
                if check_ip_against_ranges(player.ip, Settings.blocked_ip_ranges):
                    if player.left_event.is_set():
                        main_window.remove_player_from_disconnected(player.ip)
                    else:
                        main_window.remove_player_from_connected(player.ip)

        def add_copy_for_discord_action(players: list[Player]) -> None:
            if not players:
                return

            if len(selected_indexes) == 1 and len(players) == 1:
                add_action(
                    context_menu,
                    '📋 Copy for Discord',
                    tooltip='Copy a detailed player info report formatted for Discord to the clipboard.',
                    handler=lambda: copy_player_info_for_discord(players[0]),
                )
                return

            add_action(
                context_menu,
                '📋 Copy for Discord',
                tooltip='Copy Discord-formatted reports for all selected players to the clipboard.',
                handler=lambda: copy_players_info_for_discord(players),
            )

        def add_remove_players_action(ips: list[str]) -> None:
            if not ips:
                return

            ips_to_remove = set(ips)
            if len(ips_to_remove) == 1:
                label = '🗑️ Remove Player'
                tooltip = 'Remove this player from the table and registry.'
            else:
                label = f'🗑️ Remove {len(ips_to_remove)} Players'
                tooltip = f'Remove {len(ips_to_remove)} selected players from the table and registry.'

            add_action(
                context_menu,
                label,
                tooltip=tooltip,
                handler=lambda: self.remove_players_by_ip_from_table(ips_to_remove),
            )

        def add_exclude_ips_action(ips: list[str]) -> None:
            if not ips:
                return

            if len(ips) == 1:
                def _do_block_single_ip() -> None:
                    if block_ip_as_range(self, ips[0]) is None:
                        return
                    remove_blocked_players_from_tables()

                add_action(
                    context_menu,
                    '🚫 Exclude IP / Range',
                    tooltip='Exclude this IP or a range/subnet from appearing in the session. Persisted to settings.',
                    handler=_do_block_single_ip,
                )
                return

            def _do_block_multi_ips() -> None:
                for ip in ips:
                    block_ip_as_range(self, ip)
                if not Settings.blocked_ip_ranges:
                    return
                remove_blocked_players_from_tables()

            add_action(
                context_menu,
                f'🚫 Exclude {len(ips)} IPs / Ranges',
                tooltip='For each selected IP, prompt whether to exclude as single IP, range, or subnet. Persisted to settings.',
                handler=_do_block_multi_ips,
            )

        def add_ip_lookup_action(players: list[Player]) -> None:
            if not players:
                return

            if len(players) == 1:
                add_action(
                    context_menu,
                    '🔎 IP Lookup Details',
                    tooltip='Displays a notification with a detailed IP lookup report for selected player.',
                    handler=lambda: show_detailed_ip_lookup(self, players[0]),
                )
                return

            def _show_all_lookups() -> None:
                for player in players:
                    show_detailed_ip_lookup(self, player)

            add_action(
                context_menu,
                '🔎 IP Lookup Details',
                tooltip='Displays a detailed IP lookup report for each selected player.',
                handler=_show_all_lookups,
            )

        def add_rate_graph_action(ips: list[str]) -> None:
            if not ips or not self.is_connected_table or self.open_rate_graph_callback is None:
                return

            rate_graph_callback = self.open_rate_graph_callback

            if len(ips) == 1:
                add_action(
                    context_menu,
                    '📈 Rate Graph',
                    tooltip='Open a live PPS/BPS graph for this player.',
                    handler=lambda: rate_graph_callback(ips[0]),
                )
                return

            def _open_multi_graphs() -> None:
                for ip in ips:
                    rate_graph_callback(ip)

            add_action(
                context_menu,
                '📈 Rate Graph',
                tooltip='Open a live PPS/BPS graph for each selected player.',
                handler=_open_multi_graphs,
            )

        def add_seen_stats_action(players: list[Player]) -> None:
            if not players:
                return

            if len(players) == 1:
                add_action(
                    context_menu,
                    '📅 Seen Stats',
                    tooltip='Shows how many sessions this IP appeared in (today, week, month, year, total).',
                    handler=lambda: show_seen_stats(self, players[0]),
                )
                return

            def _show_all_seen_stats() -> None:
                for player in players:
                    show_seen_stats(self, player)

            add_action(
                context_menu,
                '📅 Seen Stats',
                tooltip='Shows session appearance stats for each selected player.',
                handler=_show_all_seen_stats,
            )

        def add_looky_system_menu(parent_menu: QMenu, players: list[Player]) -> None:
            if not players:
                return

            if any(is_third_party_server_ip(p.ip) for p in players):
                return

            looky_menu = add_menu(parent_menu, '👁 Looky System', 'Looky System tools and shortcuts.')

            def _open_looky_website() -> None:
                QDesktopServices.openUrl(QUrl(LOOKY_BASE_HOST))

            add_action(
                looky_menu,
                '\ud83c\udf10 Open Website',
                tooltip='Open the Looky System website in your default browser.',
                handler=_open_looky_website,
            )

            looky_menu.addSeparator()

            if len(players) == 1:
                add_action(
                    looky_menu,
                    '🔎 Lookup',
                    tooltip='Query the Looky System API to find players associated with this IP.',
                    handler=lambda: show_looky_lookup(self, players[0]),
                )
                if not CaptureState.gta5_is_enhanced and not (players[0].looky_system.is_initialized and not players[0].looky_system.rockstarids):
                    add_action(
                        looky_menu,
                        '🤖 Request Crawler',
                        tooltip='Call the crawler bot to resolve usernames for players in the session associated with this IP.',
                        handler=lambda: show_crawler_request(self, players[0]),
                    )
                return

            def _show_looky_lookup_for_all() -> None:
                for player in players:
                    show_looky_lookup(self, player)

            add_action(
                looky_menu,
                '🔎 Lookup (All Selected)',
                tooltip='Query the Looky System API for each selected player IP.',
                handler=_show_looky_lookup_for_all,
            )

        def add_ping_menu(ips: list[str]) -> None:
            if not ips:
                return

            ping_menu = add_menu(context_menu, '📡 Ping')

            if len(ips) == 1:
                add_action(
                    ping_menu,
                    '🏓 Normal',
                    tooltip='Checks if selected IP address responds to pings.',
                    handler=lambda: ping_ip(ips[0]),
                )
                add_action(
                    ping_menu,
                    '🔌 TCP Port (paping.exe)',
                    tooltip='Checks if selected IP address responds to TCP pings on a given port.',
                    handler=lambda: tcp_port_ping(self, ips[0]),
                )
                return

            def _ping_all() -> None:
                for ip in ips:
                    ping_ip(ip)

            def _tcp_ping_all_one_port() -> None:
                tcp_port_ping_multi(self, ips)

            def _tcp_ping_all_diff_ports() -> None:
                for ip in ips:
                    tcp_port_ping(self, ip)

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

        def add_user_scripts_menu(ips: list[str]) -> None:
            scripts_menu = add_menu(context_menu, '📜 User Scripts')
            builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
            user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)

            if len(ips) == 1:
                _populate_scripts_menu(scripts_menu, builtin_scripts, user_scripts, ips)
                return

            if builtin_scripts or user_scripts:
                all_at_once_menu = add_menu(scripts_menu, '📜 All IPs as Args', 'Pass all selected IPs as arguments to the script in one call.')
                _populate_scripts_menu(all_at_once_menu, builtin_scripts, user_scripts, ips)

                per_ip_menu = add_menu(scripts_menu, '📜 One Process per IP', 'Spawn a separate script process for each selected IP.')
                _populate_scripts_menu(per_ip_menu, builtin_scripts, user_scripts, ips, per_ip=True)

        def add_detections_menu(players: list[Player]) -> None:
            if Settings.capture_game_preset != 'GTA5' or CaptureState.is_neighbour_interface:
                return
            if not players:
                return

            detections_menu = add_menu(context_menu, '🚨 Detections')
            if len(players) == 1:
                build_detections_menu(detections_menu, add_action, players[0], self)
                return
            build_detections_menu_multi(detections_menu, add_action, players, self)

        def add_userip_single_menu(ip_address: str, player_obj: Player) -> None:
            userip_menu = add_menu(context_menu, '🗂️ UserIP')

            if player_obj.userip is None:
                database_paths = UserIPDatabases.get_userip_database_filepaths()
                add_userip_menu = add_menu(userip_menu, '📥 Add', 'Add selected IP address to UserIP database.')
                populate_db_menu(
                    add_userip_menu,
                    database_paths,
                    tooltip='Add selected IP address to this UserIP database.',
                    handler_factory=lambda db_path: lambda: userip_add(self, [ip_address], db_path),
                )
                add_range_userip_menu = add_menu(userip_menu, '📥 Add as Range', 'Add selected IP as a range entry to a UserIP database.')
                populate_db_menu(
                    add_range_userip_menu,
                    database_paths,
                    tooltip='Add selected IP as a range to this UserIP database.',
                    handler_factory=lambda db_path: lambda: userip_add_as_range(self, ip_address, db_path),
                )
                return

            def _open_userip_database() -> None:
                if player_obj.userip is None:
                    return
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(player_obj.userip.database_path)))

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
            if player_obj.userip.usernames and len(player_obj.userip.usernames) >= MIN_USERNAMES_FOR_REMOVAL:
                add_action(
                    userip_menu,
                    '❌ Remove Username',
                    tooltip='Remove selected usernames for this IP address while keeping others.',
                    handler=lambda: userip_remove_username(self, ip_address, player_obj),
                )
            move_userip_menu = add_menu(userip_menu, '📦 Move', 'Move selected IP address to another database.')
            populate_db_menu(
                move_userip_menu,
                UserIPDatabases.get_userip_database_filepaths(),
                tooltip='Move selected IP address to this UserIP database.',
                handler_factory=lambda db_path: lambda: userip_move(self, [ip_address], db_path),
                disabled_path=player_obj.userip.database_path,
            )
            add_action(
                userip_menu,
                '🗑️ Delete',
                tooltip='Delete selected IP address from UserIP databases.',
                handler=lambda: userip_delete(self, [ip_address]),
            )

        def add_userip_multi_menu(ips: list[str], players: list[Player]) -> None:
            if all(not UserIPDatabases.is_known_ip(ip) for ip in ips):
                userip_menu = add_menu(context_menu, '🗂️ UserIP')
                add_userip_menu = add_menu(userip_menu, '📥 Add Selected')
                populate_db_menu(
                    add_userip_menu,
                    UserIPDatabases.get_userip_database_filepaths(),
                    tooltip='Add selected IP addresses to this UserIP database.',
                    handler_factory=lambda db_path: lambda: userip_add(self, ips, db_path),
                )
                return

            if all(UserIPDatabases.is_known_ip(ip) for ip in ips):
                userip_menu = add_menu(context_menu, '🗂️ UserIP')

                rename_players = [player for player in players if player.userip is not None]
                if rename_players:
                    add_action(
                        userip_menu,
                        '✏️ Rename Selected',
                        tooltip='Rename the username for each selected IP address in its UserIP database.',
                        handler=lambda: userip_rename_multi(self, rename_players),
                    )

                move_userip_menu = add_menu(userip_menu, '📦 Move Selected')
                populate_db_menu(
                    move_userip_menu,
                    UserIPDatabases.get_userip_database_filepaths(),
                    tooltip='Move selected IP addresses to this UserIP database.',
                    handler_factory=lambda db_path: lambda: userip_move(self, ips, db_path),
                )

                add_action(
                    userip_menu,
                    '🗑️ Delete Selected',
                    tooltip='Delete selected IP addresses from UserIP databases.',
                    handler=lambda: userip_delete(self, ips),
                )

        selected_ips = get_selected_ips(selected_indexes)
        selected_players = get_matched_players(selected_ips)
        selected_cell_count = len(selected_indexes)

        def add_shared_selected_players_actions(ips: list[str], players: list[Player]) -> None:
            add_exclude_ips_action(ips)
            add_ip_lookup_action(players)
            add_rate_graph_action(ips)
            add_seen_stats_action(players)
            context_menu.addSeparator()
            add_looky_system_menu(context_menu, players)
            add_ping_menu(ips)
            add_detections_menu(players)
            add_user_scripts_menu(ips)

        def add_clear_session_host_action(ip_address: str) -> None:
            if (
                Settings.capture_game_preset != 'GTA5'
                or SessionHost.player is None
                or SessionHost.player.ip != ip_address
            ):
                return

            add_action(
                context_menu,
                '❌ Clear Session Host',
                tooltip='Manually clear this player as the detected session host.',
                handler=SessionHost.clear_session_host_data,
            )

        add_action(
            context_menu,
            '📋 Copy Selection',
            shortcut='Ctrl+C',
            tooltip='Copy selected cells to your clipboard.',
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
        )
        add_copy_for_discord_action(selected_players)
        context_menu.addSeparator()

        add_remove_players_action(selected_ips)
        context_menu.addSeparator()

        select_menu = add_menu(context_menu, '☑️ Select')
        add_action(select_menu, '☑️ Select All', shortcut='Ctrl+A', tooltip='Select all cells in the table.', handler=self.select_all_cells)
        add_action(select_menu, '➡️ Select Row', tooltip='Select all cells in this row.', handler=lambda: self.select_row_cells(index.row()))
        add_action(select_menu, '⬇️ Select Column', tooltip='Select all cells in this column.', handler=lambda: self.select_column_cells(index.column()))

        unselect_menu = add_menu(context_menu, '⬜ Unselect')
        add_action(unselect_menu, '⬜ Unselect All', tooltip='Unselect all cells in the table.', handler=self.unselect_all_cells)
        add_action(unselect_menu, '➡️ Unselect Row', tooltip='Unselect all cells in this row.', handler=lambda: self.unselect_row_cells(index.row()))
        add_action(unselect_menu, '⬇️ Unselect Column', tooltip='Unselect all cells in this column.', handler=lambda: self.unselect_column_cells(index.column()))
        context_menu.addSeparator()

        is_single_player_selection = selected_cell_count == 1 and len(selected_ips) == 1 and len(selected_players) == 1
        is_multi_selection_with_ips = selected_cell_count > 1 and bool(selected_ips)

        if is_single_player_selection:
            add_clear_session_host_action(selected_ips[0])

        if is_single_player_selection or is_multi_selection_with_ips:
            add_shared_selected_players_actions(selected_ips, selected_players)

        if is_single_player_selection:
            add_userip_single_menu(selected_ips[0], selected_players[0])
        elif is_multi_selection_with_ips:
            add_userip_multi_menu(selected_ips, selected_players)

        context_menu.popup(self.mapToGlobal(pos))
