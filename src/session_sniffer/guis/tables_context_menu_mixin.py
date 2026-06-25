"""Context menu mixin for SessionTableView right-click interactions."""

from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QItemSelectionModel, QUrl
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import QMenu, QTableView

from session_sniffer.constants.local import BUILTIN_SCRIPTS_DIR_PATH, USER_SCRIPTS_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.looky_text import (
    LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS,
    LOOKY_MENU_TOOLTIP_API_KEY_MISSING,
    LOOKY_MENU_TOOLTIP_DISABLED,
    LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING,
)
from session_sniffer.guis.stylesheets import CUSTOM_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables_detections_mixin import build_detections_menu, build_detections_menu_multi
from session_sniffer.guis.tables_player_actions import (
    block_ip_as_range,
    copy_player_info_for_discord,
    copy_players_info_for_discord,
    looky_refresh_userip_entries,
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
    userip_convert_to_range,
    userip_delete,
    userip_edit_range,
    userip_move,
    userip_remove_username,
    userip_rename,
    userip_rename_multi,
)
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import run_cmd_script

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtCore import QModelIndex, QPoint

    from session_sniffer.guis.main_window import MainWindow
    from session_sniffer.models.player import Player


def _classify_range_raw(raw: str) -> str:
    """Return the concrete UserIP range type for a raw entry string.

    Start-end notation (`1.2.3.10-1.2.3.20`) is an `IP range`; CIDR (`/`) and wildcard (`*`)
    notations are a `subnet`. This mirrors the mode taxonomy used by `IPRangeBuilderDialog`.
    """
    if '-' in raw and '/' not in raw and '*' not in raw:
        return 'IP range'
    return 'subnet'


def _classify_userip_entry(ip: str) -> str:
    """Return the concrete entry label (`single IP`, `subnet`, `IP range`, or `range`) for one IP.

    Exact members of `UserIPDatabases.ips_set` are a `single IP`. Otherwise the covering range
    entries are classified; a uniform kind yields its specific label, while overlapping kinds of
    different types fall back to the neutral `range`.
    """
    if ip in UserIPDatabases.ips_set:
        return 'single IP'
    labels = {_classify_range_raw(raw) for raw in UserIPDatabases.get_matching_range_raws(ip)}
    return labels.pop() if len(labels) == 1 else 'range'


def _describe_selected_userip_entries(ip_addresses: list[str]) -> str:
    """Return wording like 'the selected subnet' or 'the 3 selected single IPs' for a UserIP selection.

    Each IP is classified as an exact single-IP entry (a member of `UserIPDatabases.ips_set`) or a
    range-covered entry, then the phrase is built with the matching noun and correct plurality. When
    every entry is a range of the same concrete kind the specific noun (`subnet`/`IP range`) is used;
    a selection mixing single IPs with ranges is described with the neutral noun `entries`.
    """
    total_selected_ips = len(ip_addresses)

    single_ip_count = sum(1 for ip_address in ip_addresses if ip_address in UserIPDatabases.ips_set)

    range_ip_count = total_selected_ips - single_ip_count

    if single_ip_count and range_ip_count:
        noun_label = 'entries'

    elif range_ip_count:
        entry_types = {_classify_userip_entry(ip_address) for ip_address in ip_addresses}

        noun_label = f'{entry_types.pop()}{pluralize(total_selected_ips)}' if len(entry_types) == 1 else f'range{pluralize(total_selected_ips)}'

    else:
        noun_label = f'single IP{pluralize(total_selected_ips)}'

    total_prefix = '' if total_selected_ips == 1 else f'{total_selected_ips} '

    return f'the {total_prefix}selected {noun_label}'


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

            for db_path in database_paths:
                rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

                if len(rel.parts) == 1:
                    action = add_action(parent_menu, rel.parts[0], tooltip=tooltip, handler=handler_factory(db_path))
                    if disabled_path is not None and db_path == disabled_path:
                        action.setEnabled(False)
                else:
                    # Build / reuse nested submenus for each folder level
                    current_menu = parent_menu
                    for depth in range(len(rel.parts) - 1):
                        folder_key = rel.parts[: depth + 1]
                        if folder_key not in folder_menus:
                            folder_menus[folder_key] = add_menu(current_menu, rel.parts[depth])
                        current_menu = folder_menus[folder_key]

                    action = add_action(current_menu, rel.parts[-1], tooltip=tooltip, handler=handler_factory(db_path))
                    if disabled_path is not None and db_path == disabled_path:
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
            ip_addresses: list[str] = []
            for selected_index in indexes:
                if selected_index.row() in seen_rows:
                    continue
                seen_rows.add(selected_index.row())
                ip_index = selected_model.index(selected_index.row(), selected_model.ip_column_index)
                displayed_ip = selected_model.get_display_text(ip_index)
                if displayed_ip and displayed_ip not in ip_addresses:
                    ip_addresses.append(displayed_ip)
            return ip_addresses

        def get_matched_players(ip_addresses: list[str]) -> list[Player]:
            return [player for ip in ip_addresses if (player := PlayersRegistry.get_player_by_ip(ip)) is not None]

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

        def add_remove_players_action(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return

            ips_to_remove = set(ip_addresses)
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

        def add_exclude_ips_action(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return

            if len(ip_addresses) == 1:

                def _do_block_single_ip() -> None:
                    if block_ip_as_range(self, ip_addresses[0]) is None:
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
                for ip in ip_addresses:
                    block_ip_as_range(self, ip)
                if not Settings.blocked_ip_ranges:
                    return
                remove_blocked_players_from_tables()

            add_action(
                context_menu,
                f'🚫 Exclude {len(ip_addresses)} IPs / Ranges',
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

        def add_rate_graph_action(ip_addresses: list[str]) -> None:
            if not ip_addresses or not self.is_connected_table or self.open_rate_graph_callback is None:
                return

            rate_graph_callback = self.open_rate_graph_callback

            if len(ip_addresses) == 1:
                add_action(
                    context_menu,
                    '📈 Rate Graph',
                    tooltip='Open a live PPS/BPS graph for this player.',
                    handler=lambda: rate_graph_callback(ip_addresses[0]),
                )
                return

            def _open_multi_graphs() -> None:
                for ip in ip_addresses:
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
            if not Settings.is_gta5_preset() or not players or any(is_third_party_server_ip(player.ip) for player in players):
                return

            def _apply_looky_gating(action: QAction, *, require_gta5_running: bool) -> None:
                if not Settings.looky_enabled:
                    action.setEnabled(False)
                    action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
                elif not Settings.looky_api_key:
                    action.setEnabled(False)
                    action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
                elif not LookyState.api_access:
                    action.setEnabled(False)
                    action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
                elif require_gta5_running and not CaptureState.gta5_is_running:
                    action.setEnabled(False)
                    action.setToolTip(LOOKY_MENU_TOOLTIP_GTA5_NOT_RUNNING)

            looky_menu = add_menu(parent_menu, '👁 Looky System', 'Looky System tools and shortcuts.')

            def _open_looky_website() -> None:
                QDesktopServices.openUrl(QUrl(LOOKY_BASE_HOST))

            add_action(
                looky_menu,
                '🌐 Open Website',
                tooltip='Open the Looky System website in your default browser.',
                handler=_open_looky_website,
            )

            looky_menu.addSeparator()

            if len(players) == 1:
                lookup_action = add_action(
                    looky_menu,
                    '🔎 Lookup',
                    tooltip='Query the Looky System API to find players associated with this IP.',
                    handler=lambda: show_looky_lookup(self, players[0]),
                )
                _apply_looky_gating(lookup_action, require_gta5_running=False)
                if not CaptureState.gta5_is_enhanced and players[0].looky_system.rockstarids:
                    crawler_action = add_action(
                        looky_menu,
                        '🤖 Request Crawler',
                        tooltip='Call the crawler bot to resolve usernames for players in the session associated with this IP.',
                        handler=lambda: show_crawler_request(self, players[0]),
                    )
                    _apply_looky_gating(crawler_action, require_gta5_running=True)
                return

            def _show_looky_lookup_for_all() -> None:
                for player in players:
                    show_looky_lookup(self, player)

            lookup_all_action = add_action(
                looky_menu,
                '🔎 Lookup (All Selected)',
                tooltip='Query the Looky System API for each selected player IP.',
                handler=_show_looky_lookup_for_all,
            )
            _apply_looky_gating(lookup_all_action, require_gta5_running=False)

        def add_ping_menu(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return

            ping_menu = add_menu(context_menu, '📡 Ping')

            if len(ip_addresses) == 1:
                add_action(
                    ping_menu,
                    '🏓 Normal',
                    tooltip='Checks if selected IP address responds to pings.',
                    handler=lambda: ping_ip(ip_addresses[0]),
                )
                add_action(
                    ping_menu,
                    '🔌 TCP Port (paping.exe)',
                    tooltip='Checks if selected IP address responds to TCP pings on a given port.',
                    handler=lambda: tcp_port_ping(self, ip_addresses[0]),
                )
                return

            def _ping_all() -> None:
                for ip in ip_addresses:
                    ping_ip(ip)

            def _tcp_ping_all_one_port() -> None:
                tcp_port_ping_multi(self, ip_addresses)

            def _tcp_ping_all_diff_ports() -> None:
                for ip in ip_addresses:
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
            return [script for script in directory.glob('*') if (script.is_file() and not script.name.startswith(('_', '.')) and script.suffix.casefold() in allowed_suffixes)]

        def create_script_handler(script_path: Path, ip_addresses: list[str]) -> Callable[[], None]:
            return lambda: run_cmd_script(script_path, ip_addresses)

        def create_script_handler_per_ip(script_path: Path, ip_addresses: list[str]) -> Callable[[], None]:
            def _run() -> None:
                for ip in ip_addresses:
                    run_cmd_script(script_path, [ip])

            return _run

        def add_scripts_to_menu(menu: QMenu, scripts: list[Path], ip_addresses: list[str], *, per_ip: bool = False) -> None:
            factory = create_script_handler_per_ip if per_ip else create_script_handler
            for script in scripts:
                add_action(menu, script.resolve().name, tooltip='', handler=factory(script.resolve(), ip_addresses))

        def _populate_scripts_menu(menu: QMenu, builtin_scripts: list[Path], user_scripts: list[Path], ip_addresses: list[str], *, per_ip: bool = False) -> None:
            add_scripts_to_menu(menu, builtin_scripts, ip_addresses, per_ip=per_ip)
            if builtin_scripts and user_scripts:
                menu.addSeparator()
            add_scripts_to_menu(menu, user_scripts, ip_addresses, per_ip=per_ip)

        def add_user_scripts_menu(ip_addresses: list[str]) -> None:
            scripts_menu = add_menu(context_menu, '📜 User Scripts')
            builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
            user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)

            if len(ip_addresses) == 1:
                _populate_scripts_menu(scripts_menu, builtin_scripts, user_scripts, ip_addresses)
                return

            if builtin_scripts or user_scripts:
                all_at_once_menu = add_menu(scripts_menu, '📜 All IPs as Args', 'Pass all selected IPs as arguments to the script in one call.')
                _populate_scripts_menu(all_at_once_menu, builtin_scripts, user_scripts, ip_addresses)

                per_ip_menu = add_menu(scripts_menu, '📜 One Process per IP', 'Spawn a separate script process for each selected IP.')
                _populate_scripts_menu(per_ip_menu, builtin_scripts, user_scripts, ip_addresses, per_ip=True)

        def add_detections_menu(players: list[Player]) -> None:
            if not Settings.is_gta5_preset() or not CaptureState.is_local_capture():
                return
            if not players:
                return

            detections_menu = add_menu(context_menu, '🚨 Detections')
            if len(players) == 1:
                build_detections_menu(detections_menu, add_action, players[0], self)
                return
            build_detections_menu_multi(detections_menu, add_action, players, self)

        def add_userip_single_menu(ip_address: str, player: Player) -> None:
            userip_menu = add_menu(context_menu, '🗂️ UserIP')

            if player.userip is None:
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
                if player.userip is None:
                    return
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(player.userip.db_path)))

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
                handler=lambda: userip_add_username(self, ip_address, player),
            )
            if Settings.is_gta5_preset():
                refresh_action = add_action(
                    userip_menu,
                    '👁 Add Username (Looky)',
                    tooltip='Look up this IP via Looky System and add any new usernames to its UserIP database.',
                    handler=lambda: looky_refresh_userip_entries(self, [(player.userip.db_path, [ip_address])]) if player.userip else None,
                )
                if not Settings.looky_enabled:
                    refresh_action.setEnabled(False)
                    refresh_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
                elif not Settings.looky_api_key:
                    refresh_action.setEnabled(False)
                    refresh_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
                elif not LookyState.api_access:
                    refresh_action.setEnabled(False)
                    refresh_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)
            add_action(
                userip_menu,
                '✏️ Rename',
                tooltip='Rename all entries for this IP address by picking from existing usernames in its database.',
                handler=lambda: userip_rename(self, ip_address, player),
            )
            entry_desc = _classify_userip_entry(ip_address)
            if entry_desc == 'single IP':
                add_action(
                    userip_menu,
                    '🔁 Convert to Range',
                    tooltip=f'Replace this single IP entry with a range, e.g. a VPN or subnet, keeping its username{pluralize(len(player.userip.usernames))}.',
                    handler=lambda: userip_convert_to_range(self, ip_address, player),
                )
            else:
                add_action(
                    userip_menu,
                    '📏 Edit Range',
                    tooltip=f'Edit this {entry_desc} entry, or narrow it back to a single IP, keeping its username{pluralize(len(player.userip.usernames))}.',
                    handler=lambda: userip_edit_range(self, ip_address, player),
                )
            if player.userip.usernames and len(player.userip.usernames) >= MIN_USERNAMES_FOR_REMOVAL:
                add_action(
                    userip_menu,
                    '❌ Remove Username',
                    tooltip='Remove selected usernames for this IP address while keeping others.',
                    handler=lambda: userip_remove_username(self, ip_address, player),
                )
            move_userip_menu = add_menu(userip_menu, '📦 Move', f'Move this {entry_desc} entry to another UserIP database.')
            populate_db_menu(
                move_userip_menu,
                UserIPDatabases.get_userip_database_filepaths(),
                tooltip=f'Move this {entry_desc} entry to this UserIP database.',
                handler_factory=lambda db_path: lambda: userip_move(self, [ip_address], db_path),
                disabled_path=player.userip.db_path,
            )
            add_action(
                userip_menu,
                '🗑️ Delete',
                tooltip=f'Delete this {entry_desc} entry from its UserIP database.',
                handler=lambda: userip_delete(self, [ip_address]),
            )

        def add_userip_multi_menu(ip_addresses: list[str], players: list[Player]) -> None:
            if all(not UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
                userip_menu = add_menu(context_menu, '🗂️ UserIP')
                add_count = '' if len(ip_addresses) == 1 else f'{len(ip_addresses)} '
                add_userip_menu = add_menu(userip_menu, '📥 Add Selected')
                populate_db_menu(
                    add_userip_menu,
                    UserIPDatabases.get_userip_database_filepaths(),
                    tooltip=f'Add the {add_count}selected IP address{pluralize(len(ip_addresses), plural="es")} to this UserIP database.',
                    handler_factory=lambda db_path: lambda: userip_add(self, ip_addresses, db_path),
                )
                return

            if all(UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
                userip_menu = add_menu(context_menu, '🗂️ UserIP')
                entries_phrase = _describe_selected_userip_entries(ip_addresses)

                rename_players = [player for player in players if player.userip is not None]
                if rename_players:
                    rename_phrase = _describe_selected_userip_entries([player.ip for player in rename_players])
                    add_action(
                        userip_menu,
                        '✏️ Rename Selected',
                        tooltip=f'Rename the username for {rename_phrase} in its UserIP database.',
                        handler=lambda: userip_rename_multi(self, rename_players),
                    )

                if Settings.is_gta5_preset():
                    # Group IPs by their UserIP database path for the batch refresh
                    _refresh_by_db: dict[Path, list[str]] = {}
                    for _p in players:
                        if _p.userip is not None:
                            _refresh_by_db.setdefault(_p.userip.db_path, []).append(_p.ip)
                    if _refresh_by_db:
                        refresh_multi_action = add_action(
                            userip_menu,
                            '👁 Add Usernames (Looky)',
                            tooltip=f'Look up {entries_phrase} via Looky System and add any new usernames to their UserIP databases.',
                            handler=lambda: looky_refresh_userip_entries(self, list(_refresh_by_db.items())),
                        )
                        if not Settings.looky_enabled:
                            refresh_multi_action.setEnabled(False)
                            refresh_multi_action.setToolTip(LOOKY_MENU_TOOLTIP_DISABLED)
                        elif not Settings.looky_api_key:
                            refresh_multi_action.setEnabled(False)
                            refresh_multi_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_MISSING)
                        elif not LookyState.api_access:
                            refresh_multi_action.setEnabled(False)
                            refresh_multi_action.setToolTip(LOOKY_MENU_TOOLTIP_API_KEY_INVALID_OR_NO_ACCESS)

                move_userip_menu = add_menu(userip_menu, '📦 Move Selected', f'Move {entries_phrase} to another UserIP database.')
                populate_db_menu(
                    move_userip_menu,
                    UserIPDatabases.get_userip_database_filepaths(),
                    tooltip=f'Move {entries_phrase} to this UserIP database.',
                    handler_factory=lambda db_path: lambda: userip_move(self, ip_addresses, db_path),
                )

                add_action(
                    userip_menu,
                    '🗑️ Delete Selected',
                    tooltip=f'Delete {entries_phrase} from the UserIP databases.',
                    handler=lambda: userip_delete(self, ip_addresses),
                )

        selected_ips = get_selected_ips(selected_indexes)
        selected_players = get_matched_players(selected_ips)
        selected_cell_count = len(selected_indexes)

        def add_shared_selected_players_actions(ip_addresses: list[str], players: list[Player]) -> None:
            add_exclude_ips_action(ip_addresses)
            add_ip_lookup_action(players)
            add_rate_graph_action(ip_addresses)
            add_seen_stats_action(players)
            context_menu.addSeparator()
            add_looky_system_menu(context_menu, players)
            add_ping_menu(ip_addresses)
            add_detections_menu(players)
            add_user_scripts_menu(ip_addresses)

        def add_clear_session_host_action(ip_address: str) -> None:
            if not Settings.is_gta5_preset() or SessionHost.player is None or SessionHost.player.ip != ip_address:
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
