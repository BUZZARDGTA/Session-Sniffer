"""Context menu mixin for SessionTableView right-click interactions."""

from datetime import datetime
from typing import TYPE_CHECKING, cast

from PySide6.QtCore import QItemSelectionModel, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import QInputDialog, QMenu, QTableView

from session_sniffer.constants.local import BUILTIN_SCRIPTS_DIR_PATH, RESOURCES_DIR_PATH, USER_SCRIPTS_DIR_PATH
from session_sniffer.constants.standalone import LOOKY_BASE_HOST
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.looky_text import configure_looky_action
from session_sniffer.guis.session_host_diagnostics_dialog import show_session_host_diagnostics_dialog
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables_detections_mixin import build_detections_menu, build_detections_menu_multi
from session_sniffer.guis.tables_player_actions import (
    block_ip_as_range,
    copy_player_info_for_discord,
    copy_players_info_for_discord,
    create_ping_menu,
    filter_player_isp,
    scan_ports_ip,
    show_crawler_request,
    show_detailed_ip_lookup,
    show_looky_lookup,
    show_player_joins,
    show_seen_stats,
)
from session_sniffer.guis.tables_userip_menu import add_action, add_menu, build_userip_menu, build_userip_menu_multi
from session_sniffer.guis.tables_userip_mixin import resolve_usernames_for_player
from session_sniffer.networking.ip_range import check_ip_against_ranges
from session_sniffer.networking.isp_filter import get_player_primary_isp, is_player_isp_filtered
from session_sniffer.networking.looky_system import get_looky_user_url
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.session_host import HostDiagnosticsSnapshot, SessionHost
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import format_elapsed_time, pluralize
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

        def handle_menu_hovered(self, action: QAction) -> None:
            """Stub."""

        def copy_selected_cells(self, selected_model: SessionTableModel, selected_indexes: list[QModelIndex]) -> None:
            """Stub."""

        def remove_players_by_ip_from_table(self, ip_addresses: set[str]) -> None:
            """Stub."""

        def select_all_cells(self) -> None:
            """Stub."""

        def unselect_all_cells(self) -> None:
            """Stub."""

        def select_row_cells(self, row: int) -> None:
            """Stub."""

        def unselect_row_cells(self, row: int) -> None:
            """Stub."""

        def select_column_cells(self, column: int) -> None:
            """Stub."""

        def unselect_column_cells(self, column: int) -> None:
            """Stub."""

        def _reset_column_sizes(self) -> None:
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
                if displayed_ip is not None and displayed_ip and displayed_ip not in ip_addresses:
                    ip_addresses.append(displayed_ip)
            return ip_addresses

        def get_matched_players(ip_addresses: list[str]) -> list[Player]:
            return [player for ip in ip_addresses if (player := PlayersRegistry.get_player_by_ip(ip)) is not None]

        def remove_blocked_players_from_tables() -> None:
            main_window = cast('MainWindow', self.window())
            for player in PlayersRegistry.get_default_sorted_players():
                if check_ip_against_ranges(player.ip, Settings.blocked_ip_ranges):
                    if not PlayersRegistry.is_player_connected(player):
                        main_window.remove_player_from_disconnected(player.ip)
                    else:
                        main_window.remove_player_from_connected(player.ip)

        def add_copy_for_discord_action(players: list[Player]) -> None:
            if not players:
                return

            if len(selected_indexes) == 1 and len(players) == 1:
                add_action(
                    context_menu,
                    'Copy for Discord',
                    tooltip='Copy a detailed player info report formatted for Discord to the clipboard.',
                    handler=lambda: copy_player_info_for_discord(players[0]),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
                )
                return

            add_action(
                context_menu,
                'Copy for Discord',
                tooltip='Copy Discord-formatted reports for all selected players to the clipboard.',
                handler=lambda: copy_players_info_for_discord(players),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
            )

        def add_remove_players_action(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return

            ips_to_remove = set(ip_addresses)
            if len(ips_to_remove) == 1:
                label = 'Remove Player'
                tooltip = 'Remove this player from the table and registry.'
            else:
                label = f'Remove {len(ips_to_remove)} Players'
                tooltip = f'Remove {len(ips_to_remove)} selected players from the table and registry.'

            add_action(
                context_menu,
                label,
                tooltip=tooltip,
                handler=lambda: self.remove_players_by_ip_from_table(ips_to_remove),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
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
                    'Exclude IP / Range',
                    tooltip='Exclude this IP or a range/subnet from appearing in the session. Persisted to settings.',
                    handler=_do_block_single_ip,
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')),
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
                'Exclude IPs / Ranges',
                tooltip='For each selected IP, prompt whether to exclude as single IP, range, or subnet. Persisted to settings.',
                handler=_do_block_multi_ips,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')),
            )

        def remove_isp_filtered_players_from_tables() -> None:
            main_window = cast('MainWindow', self.window())
            for player in PlayersRegistry.get_default_sorted_players():
                if is_player_isp_filtered(player, Settings.capture_filtered_isps):
                    if not PlayersRegistry.is_player_connected(player):
                        main_window.remove_player_from_disconnected(player.ip)
                    else:
                        main_window.remove_player_from_connected(player.ip)

        def create_filter_isp_handler(target_isp: str) -> Callable[[], None]:
            def _filter() -> None:
                if filter_player_isp(self, target_isp) is None:
                    return
                remove_isp_filtered_players_from_tables()

            return _filter

        def add_filter_isp_action(players: list[Player]) -> None:
            if not players:
                return

            unique_isps: list[str] = dedup_preserve_order([
                isp_name for player in players if (isp_name := get_player_primary_isp(player)) is not None
            ])
            if not unique_isps:
                return

            if len(unique_isps) == 1:
                isp_name = unique_isps[0]
                add_action(
                    context_menu,
                    f"Filter ISP '{isp_name}'",
                    tooltip=f"Exclude players whose ISP or ASN matches '{isp_name}'. Persisted to settings.",
                    handler=create_filter_isp_handler(isp_name),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg')),
                )
                return

            filter_isps_menu = add_menu(
                context_menu,
                'Filter ISPs',
                tooltip='Exclude players belonging to the selected ISP or ASN. Persisted to settings.',
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg')),
            )
            for isp_name in unique_isps:
                add_action(
                    filter_isps_menu,
                    f"'{isp_name}'",
                    tooltip=f"Exclude players whose ISP or ASN matches '{isp_name}'.",
                    handler=create_filter_isp_handler(isp_name),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg')),
                )

        def add_ip_lookup_action(players: list[Player]) -> None:
            if not players:
                return

            if len(players) == 1:
                add_action(
                    context_menu,
                    'IP Lookup Details',
                    tooltip='Displays a notification with a detailed IP lookup report for selected player.',
                    handler=lambda: show_detailed_ip_lookup(self, players[0]),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')),
                )
                return

            def _show_all_lookups() -> None:
                for player in players:
                    show_detailed_ip_lookup(self, player)

            add_action(
                context_menu,
                'IP Lookup Details',
                tooltip='Displays a detailed IP lookup report for each selected player.',
                handler=_show_all_lookups,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')),
            )

        def add_rate_graph_action(ip_addresses: list[str]) -> None:
            if not ip_addresses or not self.is_connected_table or self.open_rate_graph_callback is None:
                return

            open_rate_graph_callback = self.open_rate_graph_callback

            if len(ip_addresses) == 1:
                add_action(
                    context_menu,
                    'Rate Graph',
                    tooltip='Open a live PPS/BPS graph for this player.',
                    handler=lambda: open_rate_graph_callback(ip_addresses[0]),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'chart.svg')),
                )
                return

            def _open_multi_graphs() -> None:
                for ip in ip_addresses:
                    open_rate_graph_callback(ip)

            add_action(
                context_menu,
                'Rate Graph',
                tooltip='Open a live PPS/BPS graph for each selected player.',
                handler=_open_multi_graphs,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'chart.svg')),
            )

        def add_high_rate_blacklist_action(ip_addresses: list[str]) -> None:
            if (
                not ip_addresses
                or self.blacklist_high_rate_callback is None
                or self.unblacklist_high_rate_callback is None
                or self.is_high_rate_blacklisted_callback is None
            ):
                return

            blacklist_callback = self.blacklist_high_rate_callback
            unblacklist_callback = self.unblacklist_high_rate_callback
            is_blacklisted = self.is_high_rate_blacklisted_callback

            blacklisted_ip_addresses = [ip_address for ip_address in ip_addresses if is_blacklisted(ip_address)]
            unblacklisted_ip_addresses = [ip_address for ip_address in ip_addresses if not is_blacklisted(ip_address)]

            icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'speedometer.svg'))

            def _blacklist_handler(target_ip_addresses: list[str]) -> None:
                blacklist_callback(target_ip_addresses)
                self.viewport().update()

            def _unblacklist_handler(target_ip_addresses: list[str]) -> None:
                unblacklist_callback(target_ip_addresses)
                self.viewport().update()

            if len(ip_addresses) == 1:
                single_ip = ip_addresses[0]
                if is_blacklisted(single_ip):
                    add_action(
                        context_menu,
                        'Unblacklist from High Rate Monitor',
                        tooltip='Allow this IP to be tracked by the High Rate Monitor again.',
                        handler=lambda: _unblacklist_handler([single_ip]),
                        icon=icon,
                    )
                else:
                    add_action(
                        context_menu,
                        'Blacklist in High Rate Monitor',
                        tooltip='Exclude this IP from High Rate Monitor tracking.',
                        handler=lambda: _blacklist_handler([single_ip]),
                        icon=icon,
                    )
                return

            if not blacklisted_ip_addresses:
                count = len(unblacklisted_ip_addresses)
                add_action(
                    context_menu,
                    'Blacklist in High Rate Monitor',
                    tooltip=f'Exclude {count} selected IP{pluralize(count)} from High Rate Monitor tracking.',
                    handler=lambda: _blacklist_handler(unblacklisted_ip_addresses),
                    icon=icon,
                )
            elif not unblacklisted_ip_addresses:
                count = len(blacklisted_ip_addresses)
                add_action(
                    context_menu,
                    'Unblacklist from High Rate Monitor',
                    tooltip=f'Allow {count} selected IP{pluralize(count)} to be tracked by the High Rate Monitor again.',
                    handler=lambda: _unblacklist_handler(blacklisted_ip_addresses),
                    icon=icon,
                )
            else:
                blacklist_count = len(unblacklisted_ip_addresses)
                unblacklist_count = len(blacklisted_ip_addresses)
                add_action(
                    context_menu,
                    f'Blacklist in High Rate Monitor ({blacklist_count})',
                    tooltip=f'Exclude {blacklist_count} unblacklisted IP{pluralize(blacklist_count)} from High Rate Monitor tracking.',
                    handler=lambda: _blacklist_handler(unblacklisted_ip_addresses),
                    icon=icon,
                )
                add_action(
                    context_menu,
                    f'Unblacklist from High Rate Monitor ({unblacklist_count})',
                    tooltip=f'Allow {unblacklist_count} blacklisted IP{pluralize(unblacklist_count)} to be tracked by the High Rate Monitor again.',
                    handler=lambda: _unblacklist_handler(blacklisted_ip_addresses),
                    icon=icon,
                )

        def add_player_joins_action(players: list[Player]) -> None:
            if not players:
                return

            if len(players) == 1:
                add_action(
                    context_menu,
                    'Player Joins',
                    tooltip='Shows session join and rejoin history for this player.',
                    handler=lambda: show_player_joins(self, players[0]),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'history.svg')),
                )
                return

            def _show_all_player_joins() -> None:
                for player in players:
                    show_player_joins(self, player)

            add_action(
                context_menu,
                'Player Joins',
                tooltip=f'Shows session join and rejoin history for {len(players)} selected player{pluralize(len(players))}.',
                handler=_show_all_player_joins,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'history.svg')),
            )

        def add_seen_stats_action(players: list[Player]) -> None:
            if not players:
                return

            if len(players) == 1:
                add_action(
                    context_menu,
                    'Seen Stats',
                    tooltip='Shows how many sessions this IP appeared in (today, week, month, year, total).',
                    handler=lambda: show_seen_stats(self, players[0]),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'calendar.svg')),
                )
                return

            def _show_all_seen_stats() -> None:
                for player in players:
                    show_seen_stats(self, player)

            add_action(
                context_menu,
                'Seen Stats',
                tooltip='Shows session appearance stats for each selected player.',
                handler=_show_all_seen_stats,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'calendar.svg')),
            )

        def add_looky_system_menu(parent_menu: QMenu, players: list[Player]) -> None:
            if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture() or not players or any(player.is_third_party_server for player in players):
                return

            def _apply_looky_gating(action: QAction) -> None:
                configure_looky_action(
                    action,
                    default_tooltip=action.toolTip(),
                    check_gta5_restriction=any(not player.is_gta5_process for player in players),
                )

            looky_menu = add_menu(parent_menu, 'Looky System', 'Looky System tools and shortcuts.', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')))

            def _open_looky_website() -> None:
                QDesktopServices.openUrl(QUrl(LOOKY_BASE_HOST))

            add_action(
                looky_menu,
                'Open Website',
                tooltip='Open the Looky System website in your default browser.',
                handler=_open_looky_website,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
            )

            looky_menu.addSeparator()

            if len(players) == 1:
                lookup_action = add_action(
                    looky_menu,
                    'Lookup',
                    tooltip='Query the Looky System API to find players associated with this IP.',
                    handler=lambda: show_looky_lookup(self, players[0]),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')),
                )
                _apply_looky_gating(lookup_action)
                if players[0].looky_system.rockstarids:
                    rockstar_ids = players[0].looky_system.rockstarids
                    usernames = players[0].looky_system.usernames
                    if len(rockstar_ids) == 1:
                        target_rockstar_id = rockstar_ids[0]
                        target_name = usernames[0] if usernames else str(target_rockstar_id)
                        profile_url = get_looky_user_url(target_rockstar_id)

                        def _open_single_profile() -> None:
                            QDesktopServices.openUrl(QUrl(profile_url))

                        add_action(
                            looky_menu,
                            'View on Website',
                            tooltip=f"Open {target_name}'s profile on the Looky System website ({profile_url}).",
                            handler=_open_single_profile,
                            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
                        )
                    else:
                        view_website_menu = add_menu(
                            looky_menu,
                            'View on Website',
                            "Open this player's profile on the Looky System website.",
                            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
                        )

                        def _make_profile_opener(url: str) -> Callable[[], None]:
                            def _open() -> None:
                                QDesktopServices.openUrl(QUrl(url))

                            return _open

                        all_profile_urls: list[str] = []
                        for i, target_rockstar_id in enumerate(rockstar_ids):
                            user_name = usernames[i] if i < len(usernames) else ''
                            label = f'{user_name} ({target_rockstar_id})' if user_name else str(target_rockstar_id)
                            target_name = user_name or str(target_rockstar_id)
                            profile_url = get_looky_user_url(target_rockstar_id)
                            all_profile_urls.append(profile_url)
                            add_action(
                                view_website_menu,
                                label,
                                tooltip=f"Open {target_name}'s profile on the Looky System website ({profile_url}).",
                                handler=_make_profile_opener(profile_url),
                                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
                            )
                        view_website_menu.addSeparator()

                        def _open_all_player_profiles() -> None:
                            for profile_url in all_profile_urls:
                                QDesktopServices.openUrl(QUrl(profile_url))

                        add_action(
                            view_website_menu,
                            f'Open All ({len(rockstar_ids)})',
                            tooltip=f'Open all {len(rockstar_ids)} player profiles on the Looky System website.',
                            handler=_open_all_player_profiles,
                            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
                        )

                    crawler_action = add_action(
                        looky_menu,
                        'Request Crawler',
                        tooltip='Call the crawler bot to resolve usernames for players in the session associated with this IP.',
                        handler=lambda: show_crawler_request(self, players[0]),
                        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bot.svg')),
                    )
                    _apply_looky_gating(crawler_action)
                return

            def _show_looky_lookup_for_all() -> None:
                for player in players:
                    show_looky_lookup(self, player)

            lookup_all_action = add_action(
                looky_menu,
                'Lookup (All Selected)',
                tooltip='Query the Looky System API for each selected player IP.',
                handler=_show_looky_lookup_for_all,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')),
            )
            _apply_looky_gating(lookup_all_action)

            all_selected_rockstar_ids: list[int] = []
            for player in players:
                for rockstar_id in player.looky_system.rockstarids:
                    if rockstar_id not in all_selected_rockstar_ids:
                        all_selected_rockstar_ids.append(rockstar_id)

            if all_selected_rockstar_ids:

                def _open_all_selected_profiles() -> None:
                    for rockstar_id in all_selected_rockstar_ids:
                        QDesktopServices.openUrl(QUrl(get_looky_user_url(rockstar_id)))

                profile_count = len(all_selected_rockstar_ids)
                add_action(
                    looky_menu,
                    'View on Website (All Selected)',
                    tooltip=f'Open {profile_count} player profile{pluralize(profile_count)} on the Looky System website.',
                    handler=_open_all_selected_profiles,
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
                )

        def add_ping_menu(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return
            create_ping_menu(self, context_menu, ip_addresses)

        def add_scan_ports_action(ip_addresses: list[str]) -> None:
            if not ip_addresses:
                return
            add_action(
                context_menu,
                'Scan Ports…',
                tooltip='Scan TCP and UDP ports on the selected host(s).',
                handler=lambda: scan_ports_ip(ip_addresses),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'port_scanner.svg')),
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
            scripts_menu = add_menu(context_menu, 'User Scripts', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'code.svg')))
            builtin_scripts = get_script_candidates(BUILTIN_SCRIPTS_DIR_PATH)
            user_scripts = get_script_candidates(USER_SCRIPTS_DIR_PATH)

            if len(ip_addresses) == 1:
                _populate_scripts_menu(scripts_menu, builtin_scripts, user_scripts, ip_addresses)
                return

            if builtin_scripts or user_scripts:
                all_at_once_menu = add_menu(
                    scripts_menu,
                    'All IPs as Args',
                    'Pass all selected IPs as arguments to the script in one call.',
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')),
                )
                _populate_scripts_menu(all_at_once_menu, builtin_scripts, user_scripts, ip_addresses)

                per_ip_menu = add_menu(
                    scripts_menu,
                    'One Process per IP',
                    'Spawn a separate script process for each selected IP.',
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'new_file.svg')),
                )
                _populate_scripts_menu(per_ip_menu, builtin_scripts, user_scripts, ip_addresses, per_ip=True)

        def add_detections_menu(players: list[Player]) -> None:
            if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
                return
            if not players:
                return

            detections_menu = add_menu(context_menu, 'Detections', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'shield.svg')))
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
                row_ip_index = selected_model.index(index.row(), selected_model.ip_column_index)
                row_ip = selected_model.get_display_text(row_ip_index)
                player = PlayersRegistry.get_player_by_ip(row_ip) if row_ip is not None and row_ip else None

                usernames: list[str] = resolve_usernames_for_player(player) if player else []

                if not usernames:
                    usernames = [cell_text]

                if len(usernames) == 1:
                    return usernames[0].strip() or None

                chosen_username, success = QInputDialog.getItem(
                    self,
                    'Search Username',
                    'Select or enter the username to search for:',
                    usernames,
                    0,
                    editable=True,
                )
                if not success or not chosen_username.strip():
                    return None
                return chosen_username.strip()

            main_window = cast('MainWindow', self.window())

            def _search_userip_all_databases() -> None:
                search_query = _resolve_search_text()
                if search_query is not None and search_query:
                    main_window.open_userip_manager_and_search(search_query)

            def _search_userip_logging() -> None:
                search_query = _resolve_search_text()
                if search_query is not None and search_query:
                    main_window.open_logs_manager_and_search_userip(search_query)

            def _search_sessions_logging() -> None:
                search_query = _resolve_search_text()
                if search_query is not None and search_query:
                    main_window.open_logs_manager_and_search_sessions(search_query)

            search_menu = add_menu(
                context_menu,
                'Search in\u2026',
                "Search this cell's text in logs and the UserIP database.",
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')),
            )
            add_action(
                search_menu,
                'UserIP All Databases',
                tooltip='Open the UserIP Manager searching across all databases with this text pre-filled.',
                handler=_search_userip_all_databases,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')),
            )
            add_action(
                search_menu,
                'UserIP Logging',
                tooltip='Open the Logs Manager on the UserIP Logging tab and filter by this text.',
                handler=_search_userip_logging,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')),
            )
            add_action(
                search_menu,
                'Sessions Logging',
                tooltip='Open the Logs Manager on the Sessions Logging tab and search across all session files for this text.',
                handler=_search_sessions_logging,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')),
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
            if not Settings.is_session_host_feature_set() or not SessionHost.is_host(ip_address):
                return

            add_action(
                context_menu,
                'Clear Session Host',
                tooltip='Manually clear this player as the detected session host.',
                handler=SessionHost.clear_session_host_data,
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')),
            )

        def add_host_diagnostics_action(ip_address: str) -> None:
            if not Settings.is_session_host_feature_set():
                return

            def _show_diagnostics(snapshot: HostDiagnosticsSnapshot, dialog_key: str) -> None:
                show_session_host_diagnostics_dialog(
                    self.window(),
                    snapshot,
                    dialog_key=dialog_key,
                )

            def _build_diagnostics_handler(
                target_snapshot: HostDiagnosticsSnapshot,
                target_dialog_key: str,
            ) -> Callable[[], None]:
                def _handler() -> None:
                    _show_diagnostics(target_snapshot, target_dialog_key)

                return _handler

            player_history_entries = [
                entry
                for entry in SessionHost.get_history()
                if entry.ip == ip_address and entry.diagnostics is not None
            ]

            if len(player_history_entries) == 1:
                history_entry = player_history_entries[0]
                history_diagnostics = history_entry.diagnostics
                if history_diagnostics is not None:
                    add_action(
                        context_menu,
                        'Host Diagnostics…',
                        tooltip='Show session host detection diagnostics recorded for this player.',
                        handler=_build_diagnostics_handler(history_diagnostics, history_entry.dialog_key),
                        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')),
                    )
            elif len(player_history_entries) > 1:
                host_diagnostics_menu = add_menu(
                    context_menu,
                    'Host Diagnostics',
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')),
                )
                now = datetime.now(tz=LOCAL_TZ)
                for history_entry in reversed(player_history_entries):
                    history_diagnostics = history_entry.diagnostics
                    if history_diagnostics is None:
                        continue
                    elapsed_time_string = format_elapsed_time(now - history_entry.detected_at)
                    time_label = f'{history_entry.detected_at.strftime("%H:%M:%S")} ({elapsed_time_string} ago)'
                    add_action(
                        host_diagnostics_menu,
                        time_label,
                        tooltip=f'Show session host detection diagnostics from {time_label}.',
                        handler=_build_diagnostics_handler(history_diagnostics, history_entry.dialog_key),
                    )
            elif SessionHost.is_host(ip_address) and SessionHost.last_diagnostics is not None:
                current_host_diagnostics = SessionHost.last_diagnostics
                add_action(
                    context_menu,
                    'Host Diagnostics…',
                    tooltip='Show session host detection diagnostics for the currently detected host.',
                    handler=_build_diagnostics_handler(current_host_diagnostics, 'host_diagnostics'),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')),
                )
            elif SessionHost.last_diagnostics is not None:
                latest_diagnostics = SessionHost.last_diagnostics
                add_action(
                    context_menu,
                    'Host Diagnostics…',
                    tooltip='Show session host detection diagnostics from the last evaluation.',
                    handler=_build_diagnostics_handler(latest_diagnostics, 'host_diagnostics'),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')),
                )
            else:
                action = add_action(
                    context_menu,
                    'Host Diagnostics…',
                    tooltip='No session host detection diagnostics are available yet.',
                    handler=None,
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')),
                )
                action.setEnabled(False)

        copy_selection_action = add_action(
            context_menu,
            'Copy Selection',
            tooltip='Copy selected cells to your clipboard.',
            handler=lambda: self.copy_selected_cells(selected_model, selected_indexes),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
        )
        copy_selection_action.setShortcut('Ctrl+C')
        add_copy_for_discord_action(selected_players)
        context_menu.addSeparator()

        select_menu = add_menu(context_menu, 'Select', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')))
        select_all_action = add_action(
            select_menu,
            'Select All',
            tooltip='Select all cells in the table.',
            handler=self.select_all_cells,
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')),
        )
        select_all_action.setShortcut('Ctrl+A')
        add_action(
            select_menu,
            'Select Row',
            tooltip='Select all cells in this row.',
            handler=lambda: self.select_row_cells(index.row()),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_right.svg')),
        )
        add_action(
            select_menu,
            'Select Column',
            tooltip='Select all cells in this column.',
            handler=lambda: self.select_column_cells(index.column()),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_down.svg')),
        )

        unselect_menu = add_menu(context_menu, 'Unselect', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')))
        add_action(
            unselect_menu,
            'Unselect All',
            tooltip='Unselect all cells in the table.',
            handler=self.unselect_all_cells,
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')),
        )
        add_action(
            unselect_menu,
            'Unselect Row',
            tooltip='Unselect all cells in this row.',
            handler=lambda: self.unselect_row_cells(index.row()),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_right.svg')),
        )
        add_action(
            unselect_menu,
            'Unselect Column',
            tooltip='Unselect all cells in this column.',
            handler=lambda: self.unselect_column_cells(index.column()),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'menu_arrow_down.svg')),
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
