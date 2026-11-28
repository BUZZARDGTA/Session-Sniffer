"""Context menu mixin for SessionTableView right-click interactions."""

import sys
from datetime import datetime
from typing import TYPE_CHECKING, cast

from PySide6.QtCore import QItemSelectionModel
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QInputDialog, QMenu, QTableView

from session_sniffer.constants.local import BUILTIN_SCRIPTS_DIR_PATH, USER_SCRIPTS_DIR_PATH
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.session_host_diagnostics_dialog import show_session_host_diagnostics_dialog
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables_detections_mixin import build_detections_menu, build_detections_menu_multi
from session_sniffer.guis.tables_looky_menu import build_looky_system_menu
from session_sniffer.guis.tables_player_actions import (
    block_ip_as_range,
    copy_player_info_for_discord,
    copy_players_info_for_discord,
    create_ping_menu,
    filter_player_isp,
    scan_ports_ip,
    show_detailed_ip_lookup,
    show_player_joins,
    show_seen_stats,
)
from session_sniffer.guis.tables_userip_menu import add_action, add_menu, build_userip_menu, build_userip_menu_multi
from session_sniffer.guis.tables_userip_mixin import resolve_usernames_for_player
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.networking.isp_filter import get_player_primary_isp, is_player_isp_filtered
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.session_host import HostDiagnosticsSnapshot, SessionHost
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import format_elapsed_time
from session_sniffer.utils import dedup_preserve_order, run_cmd_script

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PySide6.QtCore import QModelIndex, QPoint

    from session_sniffer.guis.main_window import MainWindow
    from session_sniffer.models.player import Player


class TableContextMenuMixin(QTableView):
    """Mixin that adds a context menu to SessionTableView."""

    if TYPE_CHECKING:
        is_connected_table: bool
        open_rate_graph_callback: Callable[[str], None] | None
        blacklist_high_rate_callback: Callable[[list[str]], None] | None
        unblacklist_high_rate_callback: Callable[[list[str]], None] | None
        is_high_rate_blacklisted_callback: Callable[[str], bool] | None

        def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
            """Stub."""

        def _select_all_cells_helper(self, *, select: bool) -> None:
            """Stub."""

        def _select_row_cells_helper(self, row: int, *, select: bool) -> None:
            """Stub."""

        def _select_column_cells_helper(self, column: int, *, select: bool) -> None:
            """Stub."""

    def show_context_menu(self, pos: QPoint) -> None:
        """Show the context menu at the specified position with options to interact with the table's content."""
        # Determine the index at the clicked position
        index = self.indexAt(pos)
        if not index.isValid():
            return  # Do nothing if the click is outside valid cells

        selected_model = ensure_instance(self.model(), SessionTableModel)
        selection_model = ensure_instance(self.selectionModel(), QItemSelectionModel)
        selected_indexes = selection_model.selectedIndexes()

        # Create the main context menu
        context_menu = QMenu(self)
        context_menu.setToolTipsVisible(True)
        context_menu.hovered.connect(self._handle_menu_hovered)

        def get_selected_ips(indexes: list[QModelIndex]) -> list[str]:
            seen_rows: set[int] = set()
            ip_addresses: list[str] = []
            for selected_index in indexes:
                if selected_index.row() in seen_rows:
                    continue
                seen_rows.add(selected_index.row())
                ip_index = selected_model.index(selected_index.row(), selected_model.ip_column_index)
                displayed_ip = selected_model.get_display_text(ip_index)
                if displayed_ip is not None and displayed_ip and displayed_ip not in ip_addresses:
                    ip_addresses.append(displayed_ip)
            return ip_addresses

        def get_matched_players(ip_addresses: list[str]) -> list[Player]:
            return [player for ip in ip_addresses if (player := selected_model.resolve_row_player(ip)) is not None]

        def remove_matching_players_from_tables(predicate: Callable[[Player], bool]) -> None:
            main_window = cast('MainWindow', self.window())
            for player in PlayersRegistry.get_default_sorted_players():
                if predicate(player):
                    if not PlayersRegistry.is_player_connected(player):
                        main_window.remove_player_from_disconnected(player.ip, all_sessions=True)
                    else:
                        main_window.remove_player_from_connected(player.ip)
            for snapshot_player in SessionTracker.get_all_snapshot_players():
                if predicate(snapshot_player):
                    main_window.remove_player_from_disconnected(snapshot_player.ip, all_sessions=True)

        def remove_blocked_players_from_tables() -> None:
            remove_matching_players_from_tables(lambda player: check_ip_against_ranges(player.ip, Settings.blocked_ip_ranges) is not None)

        def add_copy_for_discord_action(players: list[Player]) -> None:
            if not players:
                return

            if len(selected_indexes) == 1 and len(players) == 1:
                add_action(
                    context_menu,
                    tr('Copy for Discord'),
                    tooltip=tr('Copy a detailed player info report formatted for Discord to the clipboard.'),
                    handler=lambda: copy_player_info_for_discord(players[0]),
                    icon=QIcon(str(ICONS_DIR_PATH / 'copy.svg')),
                )
                return

            add_action(
                context_menu,
                tr('Copy for Discord'),
                tooltip=tr('Copy Discord-formatted reports for all selected players to the clipboard.'),
                handler=lambda: copy_players_info_for_discord(players),
                icon=QIcon(str(ICONS_DIR_PATH / 'copy.svg')),
            )

        def add_remove_players_action(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return

            ips_to_remove = set(ip_addresses)
            label = tr_plural('Remove Player', 'Remove {count} Players', len(ips_to_remove))
            tooltip = tr_plural('Remove this player from the table and registry.', 'Remove {count} selected players from the table and registry.', len(ips_to_remove))

            remove_action = add_action(
                context_menu, label, tooltip=tooltip,
                handler=lambda: self.remove_players_by_ip_from_table(ips_to_remove), icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
            )
            if not self.is_connected_table:
                remove_action.setShortcut('Delete')

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
                    tr('Exclude IP / Range'),
                    tooltip=tr('Exclude this IP or a range/subnet from appearing in the session. Persisted to settings.'),
                    handler=_do_block_single_ip,
                    icon=QIcon(str(ICONS_DIR_PATH / 'x.svg')),
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
                tr('Exclude IPs / Ranges'),
                tooltip=tr('For each selected IP, prompt whether to exclude as single IP, range, or subnet. Persisted to settings.'),
                handler=_do_block_multi_ips,
                icon=QIcon(str(ICONS_DIR_PATH / 'x.svg')),
            )

        def remove_isp_filtered_players_from_tables() -> None:
            remove_matching_players_from_tables(lambda player: is_player_isp_filtered(player, Settings.capture_filtered_isps))

        def create_filter_isp_handler(target_isp: str) -> Callable[[], None]:
            def _filter() -> None:
                if filter_player_isp(self, target_isp) is None:
                    return
                remove_isp_filtered_players_from_tables()

            return _filter

        def add_filter_isp_action(players: list[Player]) -> None:
            if not players:
                return

            unique_isps: list[str] = dedup_preserve_order([isp_name for player in players if (isp_name := get_player_primary_isp(player)) is not None])
            if not unique_isps:
                return

            if len(unique_isps) == 1:
                isp_name = unique_isps[0]
                add_action(
                    context_menu,
                    tr("Filter ISP '{isp}'", isp=isp_name),
                    tooltip=tr("Exclude players whose ISP or ASN matches '{isp}'. Persisted to settings.", isp=isp_name),
                    handler=create_filter_isp_handler(isp_name),
                    icon=QIcon(str(ICONS_DIR_PATH / 'globe.svg')),
                )
                return

            filter_isps_menu = add_menu(
                context_menu,
                tr('Filter ISPs'),
                tooltip=tr('Exclude players belonging to the selected ISP or ASN. Persisted to settings.'),
                icon=QIcon(str(ICONS_DIR_PATH / 'globe.svg')),
            )
            for isp_name in unique_isps:
                add_action(
                    filter_isps_menu,
                    f"'{isp_name}'",
                    tooltip=tr("Exclude players whose ISP or ASN matches '{isp}'.", isp=isp_name),
                    handler=create_filter_isp_handler(isp_name),
                    icon=QIcon(str(ICONS_DIR_PATH / 'globe.svg')),
                )

        def add_per_item_action[T](
            items: list[T],
            *,
            label: str,
            tooltips: tuple[str, str],
            icon_name: str,
            item_handler: Callable[[T], None],
        ) -> None:
            if not items:
                return

            single_tooltip, multi_tooltip = tooltips
            icon = QIcon(str(ICONS_DIR_PATH / icon_name))
            if len(items) == 1:
                add_action(
                    context_menu,
                    label,
                    tooltip=single_tooltip,
                    handler=lambda: item_handler(items[0]),
                    icon=icon,
                )
                return

            def _run_for_all() -> None:
                for item in items:
                    item_handler(item)

            add_action(
                context_menu,
                label,
                tooltip=multi_tooltip,
                handler=_run_for_all,
                icon=icon,
            )

        def add_ip_lookup_action(players: list[Player]) -> None:
            add_per_item_action(
                players,
                label=tr('IP Lookup Details'),
                tooltips=(
                    tr('Displays a notification with a detailed IP lookup report for selected player.'),
                    tr('Displays a detailed IP lookup report for each selected player.'),
                ),
                icon_name='search.svg',
                item_handler=show_detailed_ip_lookup,
            )

        def add_rate_graph_action(ip_addresses: list[str]) -> None:
            if not ip_addresses or not self.is_connected_table or self.open_rate_graph_callback is None:
                return

            open_rate_graph_callback = self.open_rate_graph_callback
            add_per_item_action(
                ip_addresses,
                label=tr('Rate Graph'),
                tooltips=(
                    tr('Open a live PPS/BPS graph for this player.'),
                    tr('Open a live PPS/BPS graph for each selected player.'),
                ),
                icon_name='chart-line.svg',
                item_handler=open_rate_graph_callback,
            )

        def add_high_rate_blacklist_action(ip_addresses: list[str]) -> None:
            if not ip_addresses or self.blacklist_high_rate_callback is None or self.unblacklist_high_rate_callback is None or self.is_high_rate_blacklisted_callback is None:
                return

            blacklist_callback = self.blacklist_high_rate_callback
            unblacklist_callback = self.unblacklist_high_rate_callback
            is_blacklisted = self.is_high_rate_blacklisted_callback

            blacklisted_ip_addresses = [ip_address for ip_address in ip_addresses if is_blacklisted(ip_address)]
            unblacklisted_ip_addresses = [ip_address for ip_address in ip_addresses if not is_blacklisted(ip_address)]

            icon = QIcon(str(ICONS_DIR_PATH / 'gauge.svg'))

            def _blacklist_handler(target_ip_addresses: list[str]) -> None:
                blacklist_callback(target_ip_addresses)
                self.viewport().update()

            def _unblacklist_handler(target_ip_addresses: list[str]) -> None:
                unblacklist_callback(target_ip_addresses)
                self.viewport().update()

            def _add_hrm_action(text: str, tooltip: str, target_ips: list[str], handler: Callable[[list[str]], None]) -> None:
                add_action(context_menu, text, tooltip=tooltip, handler=lambda: handler(target_ips), icon=icon)

            if len(ip_addresses) == 1:
                single_ip = ip_addresses[0]
                if is_blacklisted(single_ip):
                    _add_hrm_action(
                        tr('Unblacklist from Player High Rate Monitor'),
                        tr('Allow this IP to be tracked by the Player High Rate Monitor again.'),
                        [single_ip],
                        _unblacklist_handler,
                    )
                else:
                    _add_hrm_action(
                        tr('Blacklist in Player High Rate Monitor'),
                        tr('Exclude this IP from Player High Rate Monitor tracking.'),
                        [single_ip],
                        _blacklist_handler,
                    )
                return

            if not blacklisted_ip_addresses:
                tip = tr_plural(
                    'Exclude {count} selected IP from Player High Rate Monitor tracking.',
                    'Exclude {count} selected IPs from Player High Rate Monitor tracking.',
                    len(unblacklisted_ip_addresses),
                )
                _add_hrm_action(tr('Blacklist in Player High Rate Monitor'), tip, unblacklisted_ip_addresses, _blacklist_handler)
            elif not unblacklisted_ip_addresses:
                tip = tr_plural(
                    'Allow {count} selected IP to be tracked by the Player High Rate Monitor again.',
                    'Allow {count} selected IPs to be tracked by the Player High Rate Monitor again.',
                    len(blacklisted_ip_addresses),
                )
                _add_hrm_action(tr('Unblacklist from Player High Rate Monitor'), tip, blacklisted_ip_addresses, _unblacklist_handler)
            else:
                bl_count = len(unblacklisted_ip_addresses)
                ubl_count = len(blacklisted_ip_addresses)
                bl_tip = tr_plural(
                    'Exclude {count} unblacklisted IP from Player High Rate Monitor tracking.',
                    'Exclude {count} unblacklisted IPs from Player High Rate Monitor tracking.',
                    bl_count,
                )
                _add_hrm_action(
                    tr('Blacklist in Player High Rate Monitor ({count})', count=bl_count), bl_tip, unblacklisted_ip_addresses, _blacklist_handler,
                )
                ubl_tip = tr_plural(
                    'Allow {count} blacklisted IP to be tracked by the Player High Rate Monitor again.',
                    'Allow {count} blacklisted IPs to be tracked by the Player High Rate Monitor again.',
                    ubl_count,
                )
                _add_hrm_action(
                    tr('Unblacklist from Player High Rate Monitor ({count})', count=ubl_count), ubl_tip, blacklisted_ip_addresses, _unblacklist_handler,
                )

        def add_player_joins_action(players: list[Player]) -> None:
            multi_tip = tr_plural(
                'Shows session join and rejoin history for {count} selected player.', 'Shows session join and rejoin history for {count} selected players.', len(players),
            )
            add_per_item_action(
                players, label=tr('Player Joins'), icon_name='rotate-ccw-clock.svg',
                tooltips=(tr('Shows session join and rejoin history for this player.'), multi_tip),
                item_handler=lambda player: show_player_joins(self, player),
            )

        def add_seen_stats_action(players: list[Player]) -> None:
            add_per_item_action(
                players, label=tr('Seen Stats'), icon_name='calendar-days.svg',
                tooltips=(tr('Shows how many sessions this IP appeared in (today, week, month, year, total).'), tr('Shows session appearance stats for each selected player.')),
                item_handler=lambda player: show_seen_stats(self, player),
            )

        def add_looky_system_menu(parent_menu: QMenu, players: list[Player]) -> None:
            build_looky_system_menu(parent_menu, players, self)

        def add_ping_menu(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return
            create_ping_menu(self, context_menu, ip_addresses)

        def add_scan_ports_action(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return
            add_action(
                context_menu,
                tr('Scan Ports…'),
                tooltip=tr_plural(
                    'Scan TCP and UDP ports on the selected host.',
                    'Scan TCP and UDP ports on the selected hosts.',
                    len(ip_addresses),
                ),
                handler=lambda: scan_ports_ip(ip_addresses),
                icon=QIcon(str(ICONS_DIR_PATH / 'radar.svg')),
            )

        def get_script_candidates(directory: Path) -> list[Path]:
            if sys.platform == 'win32':
                allowed_suffixes = {'.bat', '.cmd', '.exe', '.py', '.lnk'}
            elif sys.platform == 'darwin':
                allowed_suffixes = {'.py', '.sh', '.command'}
            else:
                allowed_suffixes = {'.py', '.sh'}
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
            scripts_menu = add_menu(context_menu, tr('User Scripts'), icon=QIcon(str(ICONS_DIR_PATH / 'code.svg')))
            builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
            user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)

            if len(ip_addresses) == 1:
                _populate_scripts_menu(scripts_menu, builtin_scripts, user_scripts, ip_addresses)
                return

            if builtin_scripts or user_scripts:
                all_at_once_menu = add_menu(
                    scripts_menu,
                    tr('All IPs as Args'),
                    tr('Pass all selected IPs as arguments to the script in one call.'),
                    icon=QIcon(str(ICONS_DIR_PATH / 'folder.svg')),
                )
                _populate_scripts_menu(all_at_once_menu, builtin_scripts, user_scripts, ip_addresses)

                per_ip_menu = add_menu(
                    scripts_menu,
                    tr('One Process per IP'),
                    tr('Spawn a separate script process for each selected IP.'),
                    icon=QIcon(str(ICONS_DIR_PATH / 'file-plus.svg')),
                )
                _populate_scripts_menu(per_ip_menu, builtin_scripts, user_scripts, ip_addresses, per_ip=True)

        def add_detections_menu(players: list[Player]) -> None:
            if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
                return
            if not players:
                return

            detections_menu = add_menu(context_menu, tr('Detections'), icon=QIcon(str(ICONS_DIR_PATH / 'shield.svg')))
            if len(players) == 1:
                build_detections_menu(detections_menu, add_action, players[0], self)
                return
            build_detections_menu_multi(detections_menu, add_action, players, self)

        selected_ips = get_selected_ips(selected_indexes)
        selected_players = get_matched_players(selected_ips)
        selected_cell_count = len(selected_indexes)

        def add_search_in_menu() -> None:
            cell_text = selected_model.get_display_text(index)
            if cell_text is None or not cell_text:
                return

            def _resolve_search_text() -> str | None:
                if index.column() != selected_model.username_column_index:
                    return cell_text

                # When the cell belongs to the Usernames column, offer the exact structured usernames
                # from the matched player (UserIP, Looky System, PS3, etc.) without string splitting.
                player = selected_model.get_player_for_row(index.row())

                usernames: list[str] = resolve_usernames_for_player(player, include_relay_mod_menus=True) if player else []

                if not usernames:
                    usernames = [cell_text]

                if len(usernames) == 1:
                    return usernames[0].strip() or None

                chosen_username, success = QInputDialog.getItem(
                    self,
                    tr('Search Username'),
                    tr('Select or enter the username to search for:'),
                    usernames,
                    0,
                    editable=True,
                )
                if not success or not chosen_username.strip():
                    return None
                return chosen_username.strip()

            main_window = cast('MainWindow', self.window())

            def _make_search_handler(search_fn: Callable[[str], None]) -> Callable[[], None]:
                def _run_search() -> None:
                    search_query = _resolve_search_text()
                    if search_query is not None and search_query:
                        search_fn(search_query)

                return _run_search

            search_menu = add_menu(
                context_menu,
                tr('Search in\u2026'),
                tr("Search this cell's text in logs and the UserIP database."),
                icon=QIcon(str(ICONS_DIR_PATH / 'search.svg')),
            )
            add_action(
                search_menu,
                tr('UserIP All Databases'),
                tooltip=tr('Open the UserIP Manager searching across all databases with this text pre-filled.'),
                handler=_make_search_handler(main_window.open_userip_manager_and_search),
                icon=QIcon(str(ICONS_DIR_PATH / 'database.svg')),
            )
            add_action(
                search_menu,
                tr('UserIP Logging'),
                tooltip=tr('Open the Logs Manager on the UserIP Logging tab and filter by this text.'),
                handler=_make_search_handler(main_window.open_logs_manager_and_search_userip),
                icon=QIcon(str(ICONS_DIR_PATH / 'file-text.svg')),
            )
            add_action(
                search_menu,
                tr('Sessions Logging'),
                tooltip=tr('Open the Logs Manager on the Sessions Logging tab and search across all session files for this text.'),
                handler=_make_search_handler(main_window.open_logs_manager_and_search_sessions),
                icon=QIcon(str(ICONS_DIR_PATH / 'folder.svg')),
            )

        def add_shared_selected_players_actions(ip_addresses: list[str], players: list[Player]) -> None:
            add_exclude_ips_action(ip_addresses)
            add_filter_isp_action(players)
            add_ip_lookup_action(players)
            add_rate_graph_action(ip_addresses)
            add_high_rate_blacklist_action(ip_addresses)
            add_player_joins_action(players)
            add_seen_stats_action(players)
            context_menu.addSeparator()
            add_looky_system_menu(context_menu, players)
            add_ping_menu(ip_addresses)
            add_scan_ports_action(ip_addresses)
            add_detections_menu(players)
            add_user_scripts_menu(ip_addresses)

        def add_clear_session_host_action(ip_address: str) -> None:
            if not Settings.gui_session_host_detection or not Settings.is_session_host_feature_set() or not SessionHost.is_host(ip_address):
                return

            add_action(
                context_menu,
                tr('Clear Session Host'),
                tooltip=tr('Manually clear this player as the detected session host.'),
                handler=lambda: SessionHost.clear_session_host_data(
                    clear_pending_disconnections=False,
                    mark_manually_cleared=True,
                ),
                icon=QIcon(str(ICONS_DIR_PATH / 'x.svg')),
            )

        def add_host_diagnostics_action(ip_address: str) -> None:
            if not Settings.gui_session_host_detection or not Settings.is_session_host_feature_set():
                return

            main_window = cast('MainWindow', self.window())

            def _show_diagnostics(snapshot: HostDiagnosticsSnapshot, dialog_key: str) -> None:
                show_session_host_diagnostics_dialog(
                    main_window,
                    snapshot,
                    dialog_key=dialog_key,
                    redetect_callback=main_window.redetect_host_from_diagnostics if dialog_key == 'host_diagnostics' else None,
                )

            def _build_diagnostics_handler(
                target_snapshot: HostDiagnosticsSnapshot,
                target_dialog_key: str,
            ) -> Callable[[], None]:
                def _handler() -> None:
                    _show_diagnostics(target_snapshot, target_dialog_key)

                return _handler

            player_history_entries = [entry for entry in SessionHost.get_history() if entry.ip == ip_address and entry.diagnostics is not None]

            if len(player_history_entries) == 1:
                history_entry = player_history_entries[0]
                history_diagnostics = history_entry.diagnostics
                if history_diagnostics is not None:
                    add_action(
                        context_menu,
                        tr('Host Diagnostics…'),
                        tooltip=tr('Show session host detection diagnostics recorded for this player.'),
                        handler=_build_diagnostics_handler(history_diagnostics, history_entry.dialog_key),
                        icon=QIcon(str(ICONS_DIR_PATH / 'bug.svg')),
                    )
            elif len(player_history_entries) > 1:
                host_diagnostics_menu = add_menu(
                    context_menu,
                    tr('Host Diagnostics'),
                    icon=QIcon(str(ICONS_DIR_PATH / 'bug.svg')),
                )
                now = datetime.now(tz=LOCAL_TZ)
                for history_entry in reversed(player_history_entries):
                    history_diagnostics = history_entry.diagnostics
                    if history_diagnostics is None:
                        continue
                    elapsed_time_string = format_elapsed_time(now - history_entry.detected_at)
                    time_label = tr('{time} ({elapsed} ago)', time=history_entry.detected_at.strftime('%H:%M:%S'), elapsed=elapsed_time_string)
                    add_action(
                        host_diagnostics_menu,
                        time_label,
                        tooltip=tr('Show session host detection diagnostics from {time}.', time=time_label),
                        handler=_build_diagnostics_handler(history_diagnostics, history_entry.dialog_key),
                    )
            elif SessionHost.is_host(ip_address) and SessionHost.last_diagnostics is not None:
                current_host_diagnostics = SessionHost.last_diagnostics
                add_action(
                    context_menu,
                    tr('Host Diagnostics…'),
                    tooltip=tr('Show session host detection diagnostics for the currently detected host.'),
                    handler=_build_diagnostics_handler(current_host_diagnostics, 'host_diagnostics'),
                    icon=QIcon(str(ICONS_DIR_PATH / 'bug.svg')),
                )
            elif SessionHost.last_diagnostics is not None:
                latest_diagnostics = SessionHost.last_diagnostics
                add_action(
                    context_menu,
                    tr('Host Diagnostics…'),
                    tooltip=tr('Show session host detection diagnostics from the last evaluation.'),
                    handler=_build_diagnostics_handler(latest_diagnostics, 'host_diagnostics'),
                    icon=QIcon(str(ICONS_DIR_PATH / 'bug.svg')),
                )
            else:
                action = add_action(
                    context_menu,
                    tr('Host Diagnostics…'),
                    tooltip=tr('No session host detection diagnostics are available yet.'),
                    handler=None,
                    icon=QIcon(str(ICONS_DIR_PATH / 'bug.svg')),
                )
                action.setEnabled(False)

        copy_selection_action = add_action(
            context_menu,
            tr('Copy Selection'),
            tooltip=tr('Copy selected cells to your clipboard.'),
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
            icon=QIcon(str(ICONS_DIR_PATH / 'copy.svg')),
        )
        copy_selection_action.setShortcut('Ctrl+C')
        add_copy_for_discord_action(selected_players)
        context_menu.addSeparator()

        select_menu = add_menu(context_menu, tr('Select'), icon=QIcon(str(ICONS_DIR_PATH / 'square-check.svg')))
        select_all_action = add_action(
            select_menu,
            tr('Select All'),
            tooltip=tr('Select all cells in the table.'),
            handler=self.select_all_cells,
            icon=QIcon(str(ICONS_DIR_PATH / 'square-check.svg')),
        )
        select_all_action.setShortcut('Ctrl+A')
        add_action(
            select_menu,
            tr('Select Row'),
            tooltip=tr('Select all cells in this row.'),
            handler=lambda: self.select_row_cells(index.row()),
            icon=QIcon(str(ICONS_DIR_PATH / 'arrow-right.svg')),
        )
        add_action(
            select_menu,
            tr('Select Column'),
            tooltip=tr('Select all cells in this column.'),
            handler=lambda: self.select_column_cells(index.column()),
            icon=QIcon(str(ICONS_DIR_PATH / 'arrow-down.svg')),
        )

        unselect_menu = add_menu(context_menu, tr('Unselect'), icon=QIcon(str(ICONS_DIR_PATH / 'square.svg')))
        add_action(
            unselect_menu,
            tr('Unselect All'),
            tooltip=tr('Unselect all cells in the table.'),
            handler=self.unselect_all_cells,
            icon=QIcon(str(ICONS_DIR_PATH / 'square.svg')),
        )
        add_action(
            unselect_menu,
            tr('Unselect Row'),
            tooltip=tr('Unselect all cells in this row.'),
            handler=lambda: self.unselect_row_cells(index.row()),
            icon=QIcon(str(ICONS_DIR_PATH / 'arrow-right.svg')),
        )
        add_action(
            unselect_menu,
            tr('Unselect Column'),
            tooltip=tr('Unselect all cells in this column.'),
            handler=lambda: self.unselect_column_cells(index.column()),
            icon=QIcon(str(ICONS_DIR_PATH / 'arrow-down.svg')),
        )
        context_menu.addSeparator()

        add_remove_players_action(selected_ips)
        context_menu.addSeparator()

        is_single_player_selection = selected_cell_count == 1 and len(selected_ips) == 1 and len(selected_players) == 1
        is_multi_selection_with_ips = selected_cell_count > 1 and bool(selected_ips)

        if is_single_player_selection:
            add_clear_session_host_action(selected_ips[0])
            add_host_diagnostics_action(selected_ips[0])

        if is_single_player_selection or is_multi_selection_with_ips:
            add_shared_selected_players_actions(selected_ips, selected_players)

        if is_single_player_selection:
            build_userip_menu(context_menu, selected_ips[0], selected_players[0], self)
        elif is_multi_selection_with_ips:
            build_userip_menu_multi(context_menu, selected_ips, selected_players, self)

        add_search_in_menu()

        context_menu.popup(self.mapToGlobal(pos))

    def _handle_menu_hovered(self, action: QAction) -> None:
        """Propagate QAction tooltip text to its parent menu."""
        # Fixes: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        action_parent = action.parent()
        if isinstance(action_parent, QMenu):
            action_parent.setToolTip(action.toolTip())

    def remove_players_by_ip_from_table(self, ip_addresses: set[str]) -> None:
        """Remove multiple players from the table by calling the appropriate `MainWindow` method.

        Args:
            ip_addresses: Set of IP addresses of the players to remove.
        """
        # Get the MainWindow instance
        main_window = cast('MainWindow', self.window())

        # Remove each player
        for ip in ip_addresses:
            if self.is_connected_table:
                main_window.remove_player_from_connected(ip)
            else:
                main_window.remove_player_from_disconnected(ip)

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
