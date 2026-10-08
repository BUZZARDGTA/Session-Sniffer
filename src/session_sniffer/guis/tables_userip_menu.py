"""Right-click UserIP menu helpers for session tables."""

from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import QMenu

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.looky_text import (
    configure_looky_action,
)
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.tables_userip_mixin import (
    MIN_USERNAMES_FOR_REMOVAL,
    resolve_usernames_for_player,
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
from session_sniffer.guis.userip_manager_helpers import populate_userip_databases_menu
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PySide6.QtWidgets import QWidget

    from session_sniffer.models.player import Player


def add_action(
    menu: QMenu,
    label: str,
    *,
    tooltip: str | None = None,
    handler: Callable[..., None] | None = None,
    icon: QIcon | None = None,
) -> QAction:
    """Helper to create and configure a QAction."""
    action = ensure_instance(menu.addAction(icon, label), QAction) if icon is not None else ensure_instance(menu.addAction(label), QAction)
    if tooltip is not None and tooltip:
        action.setToolTip(tooltip)
    if handler:
        action.triggered.connect(handler)
    return action


def add_menu(
    parent_menu: QMenu,
    label: str,
    tooltip: str | None = None,
    icon: QIcon | None = None,
) -> QMenu:
    """Helper to create and configure a QMenu."""
    menu = ensure_instance(parent_menu.addMenu(icon, label), QMenu) if icon is not None else ensure_instance(parent_menu.addMenu(label), QMenu)
    menu.setToolTipsVisible(True)
    if tooltip is not None and tooltip:
        menu.setToolTip(tooltip)
        menu_action = menu.menuAction()
        if menu_action:
            menu_action.setToolTip(tooltip)
    return menu


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


def build_userip_menu(
    context_menu: QMenu,
    ip_address: str,
    player: Player,
    parent: QWidget,
) -> None:
    """Build the UserIP submenu for a single selected player."""
    userip_menu = add_menu(context_menu, 'UserIP', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')))

    if player.userip is None:
        database_paths = UserIPDatabases.get_userip_database_filepaths()
        player_usernames = resolve_usernames_for_player(player)
        add_userip_menu = add_menu(userip_menu, 'Add', tooltip='Add selected IP address to UserIP database.', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')))
        populate_userip_databases_menu(
            add_userip_menu,
            database_paths,
            tooltip='Add selected IP address to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_add(parent, [ip_address], db_path, usernames=player_usernames),
        )
        add_range_userip_menu = add_menu(
            userip_menu,
            'Add as Range',
            tooltip='Add selected IP as a range entry to a UserIP database.',
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')),
        )
        populate_userip_databases_menu(
            add_range_userip_menu,
            database_paths,
            tooltip='Add selected IP as a range to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_add_as_range(parent, ip_address, db_path, usernames=player_usernames),
        )
        return

    def _open_userip_database() -> None:
        if player.userip is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(player.userip.db_path)))

    add_action(
        userip_menu,
        'Open Database',
        tooltip="Open this player's UserIP database file in the default text editor.",
        handler=_open_userip_database,
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')),
    )
    userip_menu.addSeparator()
    add_action(
        userip_menu,
        'Add Username',
        tooltip='Add an additional username for this IP address in its UserIP database.',
        handler=lambda: userip_add_username(parent, ip_address, player),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')),
    )
    if Settings.is_gta5_feature_set():
        userip_menu.addSeparator()
        refresh_action = add_action(
            userip_menu,
            'Add Username (Looky System)',
            tooltip='Look up this IP via Looky System and add any new usernames to its UserIP database.',
            handler=lambda: looky_refresh_userip_entries(parent, [(player.userip.db_path, [ip_address])]) if player.userip else None,
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')),
        )
        configure_looky_action(refresh_action, default_tooltip=refresh_action.toolTip(), players=player)
        userip_menu.addSeparator()
    entry_desc = _classify_userip_entry(ip_address)
    if entry_desc == 'single IP':
        add_action(
            userip_menu,
            'Convert to Range',
            tooltip=f'Replace this single IP entry with a range, e.g. a VPN or subnet, keeping its username{pluralize(len(player.userip.usernames))}.',
            handler=lambda: userip_convert_to_range(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')),
        )
    else:
        add_action(
            userip_menu,
            'Edit Range',
            tooltip=f'Edit this {entry_desc} entry, or narrow it back to a single IP, keeping its username{pluralize(len(player.userip.usernames))}.',
            handler=lambda: userip_edit_range(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')),
        )
    add_action(
        userip_menu,
        'Rename',
        tooltip='Rename all entries for this IP address by picking from existing usernames in its database.',
        handler=lambda: userip_rename(parent, ip_address, player),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')),
    )
    move_userip_menu = add_menu(
        userip_menu,
        'Move',
        tooltip=f'Move this {entry_desc} entry to another UserIP database.',
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'move_box.svg')),
    )
    populate_userip_databases_menu(
        move_userip_menu,
        UserIPDatabases.get_userip_database_filepaths(),
        tooltip=f'Move this {entry_desc} entry to this UserIP database.',
        handler_factory=lambda db_path: lambda: userip_move(parent, [ip_address], db_path),
        disabled_path=player.userip.db_path,
    )
    if player.userip.usernames and len(player.userip.usernames) >= MIN_USERNAMES_FOR_REMOVAL:
        add_action(
            userip_menu,
            'Remove Username',
            tooltip='Remove selected usernames for this IP address while keeping others.',
            handler=lambda: userip_remove_username(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
        )
    add_action(
        userip_menu,
        'Delete',
        tooltip=f'Delete this {entry_desc} entry from its UserIP database.',
        handler=lambda: userip_delete(parent, [ip_address]),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
    )


def build_userip_menu_multi(
    context_menu: QMenu,
    ip_addresses: list[str],
    players: list[Player],
    parent: QWidget,
) -> None:
    """Build the UserIP submenu for multiple selected players."""
    if all(not UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
        userip_menu = add_menu(context_menu, 'UserIP', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')))
        add_count = '' if len(ip_addresses) == 1 else f'{len(ip_addresses)} '
        add_userip_menu = add_menu(userip_menu, 'Add Selected', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')))
        all_usernames = dedup_preserve_order(
            *(
                ([player.ps3_username] if player.ps3_username is not None and player.ps3_username else [])
                + (list(player.userip.usernames) if player.userip else [])
                + (player.mod_menus.usernames if player.mod_menus else [])
                + (player.looky_system.usernames if player.looky_system.is_initialized else [])
                + player.usernames
                for player in players
            )
        )
        populate_userip_databases_menu(
            add_userip_menu,
            UserIPDatabases.get_userip_database_filepaths(),
            tooltip=f'Add the {add_count}selected IP address{pluralize(len(ip_addresses), plural="es")} to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_add(parent, ip_addresses, db_path, usernames=all_usernames),
        )
        return

    if all(UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
        userip_menu = add_menu(context_menu, 'UserIP', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')))
        entries_phrase = _describe_selected_userip_entries(ip_addresses)

        rename_players = [player for player in players if player.userip is not None]
        if rename_players:
            rename_phrase = _describe_selected_userip_entries([player.ip for player in rename_players])
            add_action(
                userip_menu,
                'Rename Selected',
                tooltip=f'Rename the username for {rename_phrase} in its UserIP database.',
                handler=lambda: userip_rename_multi(parent, rename_players),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')),
            )

        if Settings.is_gta5_feature_set():
            # Group IPs by their UserIP database path for the batch refresh
            _refresh_by_db: dict[Path, list[str]] = {}
            for _p in players:
                if _p.userip is not None:
                    if Settings.looky_exclusive_gta5_process and CaptureState.is_local_capture() and not _p.is_gta5_process:
                        continue
                    _refresh_by_db.setdefault(_p.userip.db_path, []).append(_p.ip)
            if _refresh_by_db:
                if rename_players:
                    userip_menu.addSeparator()
                refresh_multi_action = add_action(
                    userip_menu,
                    'Add Usernames (Looky System)',
                    tooltip=f'Look up {entries_phrase} via Looky System and add any new usernames to their UserIP databases.',
                    handler=lambda: looky_refresh_userip_entries(parent, list(_refresh_by_db.items())),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')),
                )
                configure_looky_action(refresh_multi_action, default_tooltip=refresh_multi_action.toolTip(), players=players)
                userip_menu.addSeparator()

        move_userip_menu = add_menu(
            userip_menu,
            'Move Selected',
            tooltip=f'Move {entries_phrase} to another UserIP database.',
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'move_box.svg')),
        )
        populate_userip_databases_menu(
            move_userip_menu,
            UserIPDatabases.get_userip_database_filepaths(),
            tooltip=f'Move {entries_phrase} to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_move(parent, ip_addresses, db_path),
        )

        add_action(
            userip_menu,
            'Delete Selected',
            tooltip=f'Delete {entries_phrase} from the UserIP databases.',
            handler=lambda: userip_delete(parent, ip_addresses),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
        )
