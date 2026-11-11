"""Right-click UserIP menu helpers for session tables."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from PySide6.QtCore import QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import QMenu

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.looky_text import (
    configure_looky_action,
    get_looky_restriction,
)
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.tables_userip_mixin import (
    MIN_USERNAMES_FOR_REMOVAL,
    collect_grouped_usernames_for_player,
    collect_persisted_usernames_for_ip,
    get_player_userip_group_seeds,
    resolve_usernames_for_player,
    userip_add,
    userip_add_as_range,
    userip_add_username,
    userip_convert_to_ip,
    userip_convert_to_range,
    userip_delete,
    userip_edit_note,
    userip_edit_range,
    userip_group_selected,
    userip_group_with,
    userip_move,
    userip_remove_username,
    userip_rename,
    userip_rename_multi,
    userip_ungroup,
)
from session_sniffer.guis.userip_conflict_resolver import open_userip_conflict_resolver
from session_sniffer.guis.userip_manager_helpers import populate_userip_databases_menu
from session_sniffer.guis.utils import set_clipboard_text
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import MIN_GROUP_USERNAMES
from session_sniffer.player.userip_loader import collect_split_account_groups, collect_userip_account_groups, get_cached_userip_databases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
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


def _add_resolve_conflict_action(userip_menu: QMenu, ip_address: str) -> None:
    """Add the single action offered for conflicting IPs: opening the UserIP Conflict Resolver on that IP."""
    add_action(
        userip_menu,
        'Resolve Conflict…',
        tooltip='This IP is claimed by multiple UserIP databases. Open the UserIP Conflict Resolver to fix it.',
        handler=lambda: open_userip_conflict_resolver(ip_address),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'scale.svg')),
    )


def _add_resolve_split_group_if_needed(userip_menu: QMenu, usernames: Sequence[str]) -> bool:
    """Append a 'Resolve Split Group…' action if any username in *usernames* belongs to a split account group."""
    candidates = [(u.strip(), u.strip().casefold()) for u in usernames if u.strip()]
    if not candidates:
        return False
    split_groups, _ = collect_split_account_groups(include_disabled=False)
    matched_user = next((raw for raw, cf in candidates if any(cf in g.usernames_cf for g in split_groups)), None)
    if matched_user is None:
        return False
    add_action(
        userip_menu,
        'Resolve Split Group…',
        tooltip='This account group has entries split across multiple UserIP databases. Open the resolver to consolidate or ungroup them.',
        handler=lambda: open_userip_conflict_resolver(focus_split_username=matched_user),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'link.svg')),
    )
    return True


@dataclass(frozen=True, slots=True)
class _UserIPGroupMoveSummary:
    """Summary of enabled-database entries belonging to one or more players' account groups."""

    entry_keys: frozenset[tuple[Path, str, str]]
    source_databases: frozenset[Path]
    username_count: int
    ip_count: int
    ip_noun: str
    has_extra_entries: bool


def _collect_group_move_summary(players: Sequence[Player], selected_ips: Sequence[str]) -> _UserIPGroupMoveSummary:
    """Collect all enabled-database `(db_path, username_cf, ip)` entry keys for *players*' account groups."""
    enabled_set = set(UserIPDatabases.get_userip_database_filepaths())
    ip_list = list(selected_ips)
    direct_keys = {
        (db_path, entry.username.strip().casefold(), entry.ip.strip())
        for db_path, entries in get_cached_userip_databases()
        if db_path in enabled_set
        for entry in entries
        if entry.username.strip() and entry.ip.strip() and any(entry_ip_covers_ip(entry.ip.strip(), sel_ip) for sel_ip in ip_list)
    }

    matched_keys: set[tuple[Path, str, str]] = set()
    for player in players:
        seeds, excluded_cfs = get_player_userip_group_seeds(player, exact_ip_first=True)
        if not seeds:
            continue
        seed_cfs = {u.casefold() for u in seeds}
        for group in collect_userip_account_groups(include_disabled=False, excluded_cfs=excluded_cfs, extra_seed_usernames=seeds):
            if group.usernames_cf & seed_cfs:
                matched_keys.update(group.entry_keys)

    entry_keys = frozenset(matched_keys)
    distinct_ips = {ip_val for _, _, ip_val in entry_keys}
    ip_count = len(distinct_ips)
    has_single = any('/' not in ip_val and '-' not in ip_val and '*' not in ip_val for ip_val in distinct_ips)
    has_range = any('/' in ip_val or '-' in ip_val or '*' in ip_val for ip_val in distinct_ips)
    ip_noun = f'IP/range{pluralize(ip_count)}' if (has_single and has_range) else (f'range{pluralize(ip_count)}' if has_range else f'IP{pluralize(ip_count)}')
    return _UserIPGroupMoveSummary(
        entry_keys=entry_keys,
        source_databases=frozenset(db_path for db_path, _, _ in entry_keys),
        username_count=len({u_cf for _, u_cf, _ in entry_keys}),
        ip_count=ip_count,
        ip_noun=ip_noun,
        has_extra_entries=len(entry_keys) > 1 and entry_keys != frozenset(direct_keys),
    )


def _add_move_group_menu(
    userip_menu: QMenu,
    parent: QWidget,
    players: Sequence[Player],
    selected_ips: list[str],
) -> None:
    """Append a 'Move Group (N)' submenu when *players*' account groups span additional UserIP entries."""
    summary = _collect_group_move_summary(players, selected_ips)
    if not summary.has_extra_entries:
        return
    count = len(summary.entry_keys)
    u_count = summary.username_count
    group_scope = 'the selected account groups' if len(players) > 1 else 'this account group'
    move_group_menu = add_menu(
        userip_menu,
        f'Move Group ({count})',
        tooltip=f'Move all {count} entries in {group_scope} ({u_count} username{pluralize(u_count)}, {summary.ip_count} {summary.ip_noun}) to another UserIP database.',
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'box.svg')),
    )
    disabled_db = next(iter(summary.source_databases)) if len(summary.source_databases) == 1 else None
    populate_userip_databases_menu(
        move_group_menu,
        UserIPDatabases.get_userip_database_filepaths(),
        tooltip=f'Move all {count} entries in {group_scope} to this UserIP database.',
        handler_factory=lambda db_path: lambda: userip_move(
            parent,
            selected_ips,
            db_path,
            group_keys_fn=lambda: _collect_group_move_summary(players, selected_ips).entry_keys,
        ),
        disabled_path=disabled_db,
    )


def build_userip_menu(
    context_menu: QMenu,
    ip_address: str,
    player: Player,
    parent: QWidget,
) -> None:
    """Build the UserIP submenu for a single selected player."""
    userip_menu = add_menu(context_menu, 'UserIP', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')))

    if UserIPDatabases.is_conflicting_ip(ip_address):
        _add_resolve_conflict_action(userip_menu, ip_address)
        return

    if player.userip is None:
        database_paths = UserIPDatabases.get_userip_database_filepaths()
        player_usernames = resolve_usernames_for_player(player)
        if _add_resolve_split_group_if_needed(userip_menu, player_usernames):
            userip_menu.addSeparator()
        add_userip_menu = add_menu(userip_menu, 'Add', tooltip='Add selected IP address to UserIP database.', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')))
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
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')),
        )
        populate_userip_databases_menu(
            add_range_userip_menu,
            database_paths,
            tooltip='Add selected IP as a range to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_add_as_range(parent, ip_address, db_path, usernames=player_usernames),
        )
        if player_usernames:
            userip_menu.addSeparator()
            add_action(
                userip_menu,
                'Group With…',
                tooltip='Group this player with another username in your UserIP databases.',
                handler=lambda: userip_group_with(parent, [player]),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-plus.svg')),
            )
            grouped_names = collect_grouped_usernames_for_player(player)
            if len(grouped_names) >= MIN_GROUP_USERNAMES:
                group_text = ', '.join(grouped_names)
                add_action(
                    userip_menu,
                    f'Copy Usernames ({len(grouped_names)})',
                    tooltip=f'Copy all {len(grouped_names)} usernames in this account group ({group_text}) to the clipboard.',
                    handler=lambda: set_clipboard_text(group_text),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
                )
                add_action(
                    userip_menu,
                    'Ungroup…',
                    tooltip='Ungroup linked usernames from this account group.',
                    handler=lambda: userip_ungroup(parent, player),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
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
    persisted_usernames = collect_persisted_usernames_for_ip(player.userip.db_path, ip_address)
    userip_seeds, _ = get_player_userip_group_seeds(player, persisted_usernames=persisted_usernames)
    live_non_detached = [u for u in resolve_usernames_for_player(player) if u.casefold() not in player.detached_userip_usernames_cf]
    _add_resolve_split_group_if_needed(userip_menu, dedup_preserve_order(userip_seeds, live_non_detached))
    userip_menu.addSeparator()
    add_action(
        userip_menu,
        'Add Username…',
        tooltip='Add an additional username for this IP address in its UserIP database.',
        handler=lambda: userip_add_username(parent, ip_address, player),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')),
    )
    add_action(
        userip_menu,
        'Group With…',
        tooltip='Group this player with another username so their accounts stay linked in UserIP.',
        handler=lambda: userip_group_with(parent, [player]),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-plus.svg')),
    )
    grouped_names = collect_grouped_usernames_for_player(player, persisted_usernames=persisted_usernames)
    if len(grouped_names) >= MIN_GROUP_USERNAMES:
        group_text = ', '.join(grouped_names)
        add_action(
            userip_menu,
            f'Copy Usernames ({len(grouped_names)})',
            tooltip=f'Copy all {len(grouped_names)} usernames in this account group ({group_text}) to the clipboard.',
            handler=lambda: set_clipboard_text(group_text),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
        )
        add_action(
            userip_menu,
            'Ungroup…',
            tooltip='Ungroup linked usernames from this account group (prevents false-positive grouping).',
            handler=lambda: userip_ungroup(parent, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
        )
    if Settings.is_gta5_feature_set() and CaptureState.is_local_capture() and not player.is_third_party_server:
        userip_menu.addSeparator()
        is_searchlist = player.userip.db_path.stem.casefold() == 'searchlist'
        restriction = get_looky_restriction([player])
        refresh_action = add_action(
            userip_menu,
            'Verify IP (Looky System)' if is_searchlist else 'Refresh IP (Looky System)',
            tooltip=(
                'Verify this IP in Searchlist via Looky System to confirm matching usernames or remove wrong IPs.'
                if is_searchlist
                else 'Look up this IP via Looky System to confirm existing usernames and discover any additional usernames.'
            ),
            handler=lambda: looky_refresh_userip_entries(parent, [(player.userip.db_path, [ip_address])], restriction=restriction) if player.userip else None,
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')),
        )
        configure_looky_action(refresh_action, default_tooltip=refresh_action.toolTip(), restriction=restriction)
        userip_menu.addSeparator()
    entry_desc = _classify_userip_entry(ip_address)
    matching_ranges = UserIPDatabases.get_matching_range_raws(ip_address)
    is_single_ip = ip_address in UserIPDatabases.ips_set
    if is_single_ip and not matching_ranges:
        add_action(
            userip_menu,
            'Convert to Range',
            tooltip=f'Replace this single IP entry with a range, e.g. a VPN or subnet, keeping its username{pluralize(len(player.userip.usernames))}.',
            handler=lambda: userip_convert_to_range(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg')),
        )
    if matching_ranges:
        range_labels = {_classify_range_raw(raw) for raw in matching_ranges}
        range_desc = range_labels.pop() if len(range_labels) == 1 else 'range'
        add_action(
            userip_menu,
            'Edit Range',
            tooltip=f'Edit this {range_desc} entry, or narrow it back to a single IP, keeping its username{pluralize(len(player.userip.usernames))}.',
            handler=lambda: userip_edit_range(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')),
        )
        add_action(
            userip_menu,
            'Convert to IP',
            tooltip=f'Replace this {range_desc} entry with single IP {ip_address}, keeping its username{pluralize(len(player.userip.usernames))}.',
            handler=lambda: userip_convert_to_ip(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg')),
        )
    if persisted_usernames:
        add_action(
            userip_menu,
            'Rename',
            tooltip='Rename all entries for this IP address by picking from existing usernames in its database.',
            handler=lambda: userip_rename(parent, ip_address, player),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')),
        )
    note_action = 'Edit' if player.userip.notes else 'Add'
    note_label = f'{note_action} Note…'
    add_action(
        userip_menu,
        note_label,
        tooltip=f'{note_action} the note for this IP address in its UserIP database.',
        handler=lambda: userip_edit_note(parent, ip_address, player),
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'notepad-text.svg')),
    )
    move_userip_menu = add_menu(
        userip_menu,
        'Move',
        tooltip=f'Move this {entry_desc} entry to another UserIP database.',
        icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'box.svg')),
    )
    populate_userip_databases_menu(
        move_userip_menu,
        UserIPDatabases.get_userip_database_filepaths(),
        tooltip=f'Move this {entry_desc} entry to this UserIP database.',
        handler_factory=lambda db_path: lambda: userip_move(parent, [ip_address], db_path),
        disabled_path=player.userip.db_path,
    )
    _add_move_group_menu(userip_menu, parent, [player], [ip_address])
    if len(persisted_usernames) >= MIN_USERNAMES_FOR_REMOVAL:
        add_action(
            userip_menu,
            'Remove Username…',
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
    conflicting_ip = next((ip for ip in ip_addresses if UserIPDatabases.is_conflicting_ip(ip)), None)
    if conflicting_ip is not None:
        userip_menu = add_menu(context_menu, 'UserIP', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')))
        _add_resolve_conflict_action(userip_menu, conflicting_ip)
        return

    if all(not UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
        userip_menu = add_menu(context_menu, 'UserIP', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')))
        add_count = '' if len(ip_addresses) == 1 else f'{len(ip_addresses)} '
        add_userip_menu = add_menu(userip_menu, 'Add Selected', icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')))
        all_usernames = dedup_preserve_order(*(resolve_usernames_for_player(player) for player in players))
        populate_userip_databases_menu(
            add_userip_menu,
            UserIPDatabases.get_userip_database_filepaths(),
            tooltip=f'Add the {add_count}selected IP address{pluralize(len(ip_addresses), plural="es")} to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_add(parent, ip_addresses, db_path, usernames=all_usernames),
        )
        if len(all_usernames) >= MIN_GROUP_USERNAMES:
            userip_menu.addSeparator()
            add_action(
                userip_menu,
                'Group Selected',
                tooltip='Group all usernames across the selected players together.',
                handler=lambda: userip_group_selected(parent, players),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-plus.svg')),
            )
        if all_usernames:
            add_action(
                userip_menu,
                'Group With…',
                tooltip='Group the selected players with another username.',
                handler=lambda: userip_group_with(parent, players),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-plus.svg')),
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
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')),
            )

        selected_usernames = dedup_preserve_order(
            *((p.userip.usernames if p.userip is not None else resolve_usernames_for_player(p)) for p in players),
        )
        if len(selected_usernames) >= MIN_GROUP_USERNAMES:
            add_action(
                userip_menu,
                'Group Selected',
                tooltip='Group all usernames across the selected players together.',
                handler=lambda: userip_group_selected(parent, players),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-plus.svg')),
            )
        if selected_usernames:
            add_action(
                userip_menu,
                'Group With…',
                tooltip='Group the selected players with another username.',
                handler=lambda: userip_group_with(parent, players),
                icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-plus.svg')),
            )

        if Settings.is_gta5_feature_set() and CaptureState.is_local_capture() and all(not p.is_third_party_server for p in players):
            # Group IPs by their UserIP database path for the batch refresh
            _refresh_by_db: dict[Path, list[str]] = {}
            for _p in players:
                if _p.userip is not None:
                    _refresh_by_db.setdefault(_p.userip.db_path, []).append(_p.ip)
            if _refresh_by_db:
                if rename_players:
                    userip_menu.addSeparator()
                is_all_searchlist = all(db_path.stem.casefold() == 'searchlist' for db_path in _refresh_by_db)
                restriction = get_looky_restriction(players)
                refresh_multi_action = add_action(
                    userip_menu,
                    'Verify IPs (Looky System)' if is_all_searchlist else 'Refresh IPs (Looky System)',
                    tooltip=(
                        f'Verify {entries_phrase} in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.'
                        if is_all_searchlist
                        else f'Look up {entries_phrase} via Looky System to confirm existing usernames and discover any additional usernames.'
                    ),
                    handler=lambda: looky_refresh_userip_entries(parent, list(_refresh_by_db.items()), restriction=restriction),
                    icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')),
                )
                configure_looky_action(refresh_multi_action, default_tooltip=refresh_multi_action.toolTip(), restriction=restriction)
                userip_menu.addSeparator()

        move_userip_menu = add_menu(
            userip_menu,
            'Move Selected',
            tooltip=f'Move {entries_phrase} to another UserIP database.',
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'box.svg')),
        )
        populate_userip_databases_menu(
            move_userip_menu,
            UserIPDatabases.get_userip_database_filepaths(),
            tooltip=f'Move {entries_phrase} to this UserIP database.',
            handler_factory=lambda db_path: lambda: userip_move(parent, ip_addresses, db_path),
            disabled_path=next(iter(selected_dbs)) if len(selected_dbs := {p.userip.db_path for p in rename_players if p.userip is not None}) == 1 else None,
        )
        _add_move_group_menu(userip_menu, parent, players, ip_addresses)

        add_action(
            userip_menu,
            'Delete Selected',
            tooltip=f'Delete {entries_phrase} from the UserIP databases.',
            handler=lambda: userip_delete(parent, ip_addresses),
            icon=QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')),
        )
