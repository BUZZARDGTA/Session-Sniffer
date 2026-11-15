"""Right-click UserIP menu helpers for session tables."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from PySide6.QtCore import QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWidgets import QMenu

from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis._userip_tree_batch_ops import populate_userip_databases_menu
from session_sniffer.guis.looky_text import (
    configure_looky_action,
    get_looky_restriction,
)
from session_sniffer.guis.tables_player_actions._userip_dialog import (
    collect_grouped_usernames_for_player,
    get_player_userip_group_seeds,
    userip_group_selected,
    userip_group_with,
    userip_ungroup,
)
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_userip import looky_refresh_userip_entries
from session_sniffer.guis.tables_userip_mixin import (
    MIN_USERNAMES_FOR_REMOVAL,
    collect_persisted_usernames_for_ip,
    resolve_usernames_for_player,
    userip_add,
    userip_add_as_range,
    userip_add_username,
    userip_convert_to_ip,
    userip_convert_to_range,
    userip_delete,
    userip_edit_note,
    userip_edit_range,
    userip_move,
    userip_remove_username,
    userip_rename,
    userip_rename_multi,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.userip_conflict_resolver import open_userip_conflict_resolver
from session_sniffer.guis.utils import set_clipboard_text
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import MIN_GROUP_USERNAMES
from session_sniffer.player.userip_loader import collect_split_account_groups, collect_userip_account_groups, get_cached_userip_databases
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings
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


_RangeKind = Literal['ip_range', 'subnet']
_EntryKind = Literal['single_ip', 'subnet', 'ip_range', 'range']
_SelectionKind = Literal['single_ip', 'subnet', 'ip_range', 'range', 'mixed']
_MultiActionKind = Literal['rename', 'verify_looky', 'refresh_looky', 'move_another', 'move_this', 'delete']

_MULTI_ENTRY_TOOLTIPS: dict[tuple[_MultiActionKind, _SelectionKind], tuple[str, str]] = {
    ('rename', 'single_ip'): (
        'Rename the username for the selected single IP in its UserIP database.',
        'Rename the username for the {count} selected single IPs in their UserIP databases.',
    ),
    ('rename', 'subnet'): (
        'Rename the username for the selected subnet in its UserIP database.',
        'Rename the username for the {count} selected subnets in their UserIP databases.',
    ),
    ('rename', 'ip_range'): (
        'Rename the username for the selected IP range in its UserIP database.',
        'Rename the username for the {count} selected IP ranges in their UserIP databases.',
    ),
    ('rename', 'range'): (
        'Rename the username for the selected range in its UserIP database.',
        'Rename the username for the {count} selected ranges in their UserIP databases.',
    ),
    ('rename', 'mixed'): (
        'Rename the username for the selected entry in its UserIP database.',
        'Rename the username for the {count} selected entries in their UserIP databases.',
    ),
    ('verify_looky', 'single_ip'): (
        'Verify the selected single IP in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
        'Verify the {count} selected single IPs in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
    ),
    ('verify_looky', 'subnet'): (
        'Verify the selected subnet in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
        'Verify the {count} selected subnets in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
    ),
    ('verify_looky', 'ip_range'): (
        'Verify the selected IP range in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
        'Verify the {count} selected IP ranges in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
    ),
    ('verify_looky', 'range'): (
        'Verify the selected range in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
        'Verify the {count} selected ranges in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
    ),
    ('verify_looky', 'mixed'): (
        'Verify the selected entry in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
        'Verify the {count} selected entries in Searchlist via Looky System to confirm matching usernames and remove wrong IPs.',
    ),
    ('refresh_looky', 'single_ip'): (
        'Look up the selected single IP via Looky System to confirm existing usernames and discover any additional usernames.',
        'Look up the {count} selected single IPs via Looky System to confirm existing usernames and discover any additional usernames.',
    ),
    ('refresh_looky', 'subnet'): (
        'Look up the selected subnet via Looky System to confirm existing usernames and discover any additional usernames.',
        'Look up the {count} selected subnets via Looky System to confirm existing usernames and discover any additional usernames.',
    ),
    ('refresh_looky', 'ip_range'): (
        'Look up the selected IP range via Looky System to confirm existing usernames and discover any additional usernames.',
        'Look up the {count} selected IP ranges via Looky System to confirm existing usernames and discover any additional usernames.',
    ),
    ('refresh_looky', 'range'): (
        'Look up the selected range via Looky System to confirm existing usernames and discover any additional usernames.',
        'Look up the {count} selected ranges via Looky System to confirm existing usernames and discover any additional usernames.',
    ),
    ('refresh_looky', 'mixed'): (
        'Look up the selected entry via Looky System to confirm existing usernames and discover any additional usernames.',
        'Look up the {count} selected entries via Looky System to confirm existing usernames and discover any additional usernames.',
    ),
    ('move_another', 'single_ip'): (
        'Move the selected single IP to another UserIP database.',
        'Move the {count} selected single IPs to another UserIP database.',
    ),
    ('move_another', 'subnet'): (
        'Move the selected subnet to another UserIP database.',
        'Move the {count} selected subnets to another UserIP database.',
    ),
    ('move_another', 'ip_range'): (
        'Move the selected IP range to another UserIP database.',
        'Move the {count} selected IP ranges to another UserIP database.',
    ),
    ('move_another', 'range'): (
        'Move the selected range to another UserIP database.',
        'Move the {count} selected ranges to another UserIP database.',
    ),
    ('move_another', 'mixed'): (
        'Move the selected entry to another UserIP database.',
        'Move the {count} selected entries to another UserIP database.',
    ),
    ('move_this', 'single_ip'): (
        'Move the selected single IP to this UserIP database.',
        'Move the {count} selected single IPs to this UserIP database.',
    ),
    ('move_this', 'subnet'): (
        'Move the selected subnet to this UserIP database.',
        'Move the {count} selected subnets to this UserIP database.',
    ),
    ('move_this', 'ip_range'): (
        'Move the selected IP range to this UserIP database.',
        'Move the {count} selected IP ranges to this UserIP database.',
    ),
    ('move_this', 'range'): (
        'Move the selected range to this UserIP database.',
        'Move the {count} selected ranges to this UserIP database.',
    ),
    ('move_this', 'mixed'): (
        'Move the selected entry to this UserIP database.',
        'Move the {count} selected entries to this UserIP database.',
    ),
    ('delete', 'single_ip'): (
        'Delete the selected single IP from the UserIP databases.',
        'Delete the {count} selected single IPs from the UserIP databases.',
    ),
    ('delete', 'subnet'): (
        'Delete the selected subnet from the UserIP databases.',
        'Delete the {count} selected subnets from the UserIP databases.',
    ),
    ('delete', 'ip_range'): (
        'Delete the selected IP range from the UserIP databases.',
        'Delete the {count} selected IP ranges from the UserIP databases.',
    ),
    ('delete', 'range'): (
        'Delete the selected range from the UserIP databases.',
        'Delete the {count} selected ranges from the UserIP databases.',
    ),
    ('delete', 'mixed'): (
        'Delete the selected entry from the UserIP databases.',
        'Delete the {count} selected entries from the UserIP databases.',
    ),
}


def _classify_range_raw(raw: str) -> _RangeKind:
    """Return the concrete UserIP range type for a raw entry string.

    Start-end notation (`1.2.3.10-1.2.3.20`) is an `ip_range`; CIDR (`/`) and wildcard (`*`)
    notations are a `subnet`. This mirrors the mode taxonomy used by `IPRangeBuilderDialog`.
    """
    if '-' in raw and '/' not in raw and '*' not in raw:
        return 'ip_range'
    return 'subnet'


def _classify_userip_entry(ip: str) -> _EntryKind:
    """Return the concrete entry kind (`single_ip`, `subnet`, `ip_range`, or `range`) for one IP."""
    if ip in UserIPDatabases.ips_set:
        return 'single_ip'
    labels: set[_RangeKind] = {_classify_range_raw(raw) for raw in UserIPDatabases.get_matching_range_raws(ip)}
    return labels.pop() if len(labels) == 1 else 'range'


def _classify_selected_userip_entries(ip_addresses: list[str]) -> _SelectionKind:
    """Classify a non-empty list of selected IPs into a canonical entry-selection kind."""
    single_ip_count = sum(1 for ip_address in ip_addresses if ip_address in UserIPDatabases.ips_set)
    range_ip_count = len(ip_addresses) - single_ip_count
    if single_ip_count and range_ip_count:
        return 'mixed'
    if range_ip_count:
        entry_types: set[_EntryKind] = {_classify_userip_entry(ip_address) for ip_address in ip_addresses}
        return entry_types.pop() if len(entry_types) == 1 else 'range'
    return 'single_ip'


def _format_multi_entry_tooltip(action: _MultiActionKind, ip_addresses: list[str]) -> str:
    """Return the localized tooltip for a batch UserIP action on *ip_addresses*."""
    kind = _classify_selected_userip_entries(ip_addresses)
    singular, plural = _MULTI_ENTRY_TOOLTIPS[(action, kind)]
    return tr_plural(singular, plural, len(ip_addresses))


def _add_resolve_conflict_action(userip_menu: QMenu, ip_address: str) -> None:
    """Add the single action offered for conflicting IPs: opening the UserIP Conflict Resolver on that IP."""
    add_action(
        userip_menu,
        tr('Resolve Conflict…'),
        tooltip=tr('This IP is claimed by multiple UserIP databases. Open the UserIP Conflict Resolver to fix it.'),
        handler=lambda: open_userip_conflict_resolver(ip_address),
        icon=QIcon(str(ICONS_DIR_PATH / 'scale.svg')),
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
        tr('Resolve Split Group…'),
        tooltip=tr('This account group has entries split across multiple UserIP databases. Open the resolver to consolidate or ungroup them.'),
        handler=lambda: open_userip_conflict_resolver(focus_split_username=matched_user),
        icon=QIcon(str(ICONS_DIR_PATH / 'link.svg')),
    )
    return True


@dataclass(frozen=True, slots=True)
class _UserIPGroupMoveSummary:
    """Summary of enabled-database entries belonging to one or more players' account groups."""

    entry_keys: frozenset[tuple[Path, str, str]]
    source_databases: frozenset[Path]
    username_count: int
    ip_count: int
    ip_kind: Literal['ip', 'range', 'mixed']
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
    ip_kind: Literal['ip', 'range', 'mixed'] = 'mixed' if (has_single and has_range) else ('range' if has_range else 'ip')
    return _UserIPGroupMoveSummary(
        entry_keys=entry_keys,
        source_databases=frozenset(db_path for db_path, _, _ in entry_keys),
        username_count=len({u_cf for _, u_cf, _ in entry_keys}),
        ip_count=ip_count,
        ip_kind=ip_kind,
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
    usernames_text = tr_plural('{count} username', '{count} usernames', u_count)
    if summary.ip_kind == 'mixed':
        targets_text = tr_plural('{count} IP/range', '{count} IPs/ranges', summary.ip_count)
    elif summary.ip_kind == 'range':
        targets_text = tr_plural('{count} range', '{count} ranges', summary.ip_count)
    else:
        targets_text = tr_plural('{count} IP', '{count} IPs', summary.ip_count)
    if len(players) > 1:
        move_another_tooltip = tr(
            'Move all {count} entries in the selected account groups ({usernames}, {targets}) to another UserIP database.',
            count=count,
            usernames=usernames_text,
            targets=targets_text,
        )
        move_this_tooltip = tr(
            'Move all {count} entries in the selected account groups to this UserIP database.',
            count=count,
        )
    else:
        move_another_tooltip = tr(
            'Move all {count} entries in this account group ({usernames}, {targets}) to another UserIP database.',
            count=count,
            usernames=usernames_text,
            targets=targets_text,
        )
        move_this_tooltip = tr(
            'Move all {count} entries in this account group to this UserIP database.',
            count=count,
        )
    move_group_menu = add_menu(
        userip_menu,
        tr('Move Group ({count})', count=count),
        tooltip=move_another_tooltip,
        icon=QIcon(str(ICONS_DIR_PATH / 'box.svg')),
    )
    disabled_db = next(iter(summary.source_databases)) if len(summary.source_databases) == 1 else None
    populate_userip_databases_menu(
        move_group_menu,
        UserIPDatabases.get_userip_database_filepaths(),
        tooltip=move_this_tooltip,
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
    userip_menu = add_menu(context_menu, tr('UserIP'), icon=QIcon(str(ICONS_DIR_PATH / 'database.svg')))

    if UserIPDatabases.is_conflicting_ip(ip_address):
        _add_resolve_conflict_action(userip_menu, ip_address)
        return

    if player.userip is None:
        database_paths = UserIPDatabases.get_userip_database_filepaths()
        player_usernames = resolve_usernames_for_player(player)
        if _add_resolve_split_group_if_needed(userip_menu, player_usernames):
            userip_menu.addSeparator()
        add_userip_menu = add_menu(
            userip_menu,
            tr('Add'),
            tooltip=tr('Add selected IP address to UserIP database.'),
            icon=QIcon(str(ICONS_DIR_PATH / 'plus.svg')),
        )
        populate_userip_databases_menu(
            add_userip_menu,
            database_paths,
            tooltip=tr('Add selected IP address to this UserIP database.'),
            handler_factory=lambda db_path: lambda: userip_add(parent, [ip_address], db_path, usernames=player_usernames),
        )
        add_range_userip_menu = add_menu(
            userip_menu,
            tr('Add as Range'),
            tooltip=tr('Add selected IP as a range entry to a UserIP database.'),
            icon=QIcon(str(ICONS_DIR_PATH / 'plus.svg')),
        )
        populate_userip_databases_menu(
            add_range_userip_menu,
            database_paths,
            tooltip=tr('Add selected IP as a range to this UserIP database.'),
            handler_factory=lambda db_path: lambda: userip_add_as_range(parent, ip_address, db_path, usernames=player_usernames),
        )
        if player_usernames:
            userip_menu.addSeparator()
            add_action(
                userip_menu,
                tr('Group With…'),
                tooltip=tr('Group this player with another username in your UserIP databases.'),
                handler=lambda: userip_group_with(parent, [player]),
                icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
            )
            grouped_names = collect_grouped_usernames_for_player(player)
            if len(grouped_names) >= MIN_GROUP_USERNAMES:
                group_text = ', '.join(grouped_names)
                add_action(
                    userip_menu,
                    tr('Copy Usernames ({count})', count=len(grouped_names)),
                    tooltip=tr(
                        'Copy all {count} usernames in this account group ({usernames}) to the clipboard.',
                        count=len(grouped_names),
                        usernames=group_text,
                    ),
                    handler=lambda: set_clipboard_text(group_text),
                    icon=QIcon(str(ICONS_DIR_PATH / 'copy.svg')),
                )
                add_action(
                    userip_menu,
                    tr('Ungroup…'),
                    tooltip=tr('Ungroup linked usernames from this account group.'),
                    handler=lambda: userip_ungroup(parent, player),
                    icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
                )
        return

    def _open_userip_database() -> None:
        if player.userip is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(player.userip.db_path)))

    add_action(
        userip_menu,
        tr('Open Database'),
        tooltip=tr("Open this player's UserIP database file in the default text editor."),
        handler=_open_userip_database,
        icon=QIcon(str(ICONS_DIR_PATH / 'folder.svg')),
    )
    persisted_usernames = collect_persisted_usernames_for_ip(player.userip.db_path, ip_address)
    userip_seeds, _ = get_player_userip_group_seeds(player, persisted_usernames=persisted_usernames)
    live_non_detached = [u for u in resolve_usernames_for_player(player) if u.casefold() not in player.detached_userip_usernames_cf]
    _add_resolve_split_group_if_needed(userip_menu, dedup_preserve_order(userip_seeds, live_non_detached))
    userip_menu.addSeparator()
    add_action(
        userip_menu,
        tr('Add Username…'),
        tooltip=tr('Add an additional username for this IP address in its UserIP database.'),
        handler=lambda: userip_add_username(parent, ip_address, player),
        icon=QIcon(str(ICONS_DIR_PATH / 'plus.svg')),
    )
    add_action(
        userip_menu,
        tr('Group With…'),
        tooltip=tr('Group this player with another username so their accounts stay linked in UserIP.'),
        handler=lambda: userip_group_with(parent, [player]),
        icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
    )
    grouped_names = collect_grouped_usernames_for_player(player, persisted_usernames=persisted_usernames)
    if len(grouped_names) >= MIN_GROUP_USERNAMES:
        group_text = ', '.join(grouped_names)
        add_action(
            userip_menu,
            tr('Copy Usernames ({count})', count=len(grouped_names)),
            tooltip=tr(
                'Copy all {count} usernames in this account group ({usernames}) to the clipboard.',
                count=len(grouped_names),
                usernames=group_text,
            ),
            handler=lambda: set_clipboard_text(group_text),
            icon=QIcon(str(ICONS_DIR_PATH / 'copy.svg')),
        )
        add_action(
            userip_menu,
            tr('Ungroup…'),
            tooltip=tr('Ungroup linked usernames from this account group (prevents false-positive grouping).'),
            handler=lambda: userip_ungroup(parent, player),
            icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
        )
    if Settings.is_gta5_feature_set() and CaptureState.is_local_capture() and not player.is_third_party_server:
        userip_menu.addSeparator()
        is_searchlist = player.userip.db_path.stem.casefold() == 'searchlist'
        restriction = get_looky_restriction([player])
        refresh_action = add_action(
            userip_menu,
            tr('Verify IP (Looky System)') if is_searchlist else tr('Refresh IP (Looky System)'),
            tooltip=(
                tr('Verify this IP in Searchlist via Looky System to confirm matching usernames or remove wrong IPs.')
                if is_searchlist
                else tr('Look up this IP via Looky System to confirm existing usernames and discover any additional usernames.')
            ),
            handler=lambda: looky_refresh_userip_entries(parent, [(player.userip.db_path, [ip_address])], restriction=restriction) if player.userip else None,
            icon=QIcon(str(ICONS_DIR_PATH / 'eye.svg')),
        )
        configure_looky_action(refresh_action, default_tooltip=refresh_action.toolTip(), restriction=restriction)
        userip_menu.addSeparator()
    entry_kind = _classify_userip_entry(ip_address)
    matching_ranges = UserIPDatabases.get_matching_range_raws(ip_address)
    is_single_ip = ip_address in UserIPDatabases.ips_set
    username_count = len(player.userip.usernames)
    if is_single_ip and not matching_ranges:
        add_action(
            userip_menu,
            tr('Convert to Range'),
            tooltip=tr_plural(
                'Replace this single IP entry with a range, e.g. a VPN or subnet, keeping its username.',
                'Replace this single IP entry with a range, e.g. a VPN or subnet, keeping its usernames.',
                username_count,
            ),
            handler=lambda: userip_convert_to_range(parent, ip_address, player),
            icon=QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')),
        )
    if matching_ranges:
        range_labels: set[_RangeKind] = {_classify_range_raw(raw) for raw in matching_ranges}
        range_kind: Literal['subnet', 'ip_range', 'range'] = range_labels.pop() if len(range_labels) == 1 else 'range'
        if range_kind == 'subnet':
            edit_tooltip = tr_plural(
                'Edit this subnet entry, or narrow it back to a single IP, keeping its username.',
                'Edit this subnet entry, or narrow it back to a single IP, keeping its usernames.',
                username_count,
            )
            convert_tooltip = tr_plural(
                'Replace this subnet entry with single IP {ip}, keeping its username.',
                'Replace this subnet entry with single IP {ip}, keeping its usernames.',
                username_count,
                ip=ip_address,
            )
        elif range_kind == 'ip_range':
            edit_tooltip = tr_plural(
                'Edit this IP range entry, or narrow it back to a single IP, keeping its username.',
                'Edit this IP range entry, or narrow it back to a single IP, keeping its usernames.',
                username_count,
            )
            convert_tooltip = tr_plural(
                'Replace this IP range entry with single IP {ip}, keeping its username.',
                'Replace this IP range entry with single IP {ip}, keeping its usernames.',
                username_count,
                ip=ip_address,
            )
        else:
            edit_tooltip = tr_plural(
                'Edit this range entry, or narrow it back to a single IP, keeping its username.',
                'Edit this range entry, or narrow it back to a single IP, keeping its usernames.',
                username_count,
            )
            convert_tooltip = tr_plural(
                'Replace this range entry with single IP {ip}, keeping its username.',
                'Replace this range entry with single IP {ip}, keeping its usernames.',
                username_count,
                ip=ip_address,
            )
        add_action(
            userip_menu,
            tr('Edit Range'),
            tooltip=edit_tooltip,
            handler=lambda: userip_edit_range(parent, ip_address, player),
            icon=QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')),
        )
        add_action(
            userip_menu,
            tr('Convert to IP'),
            tooltip=convert_tooltip,
            handler=lambda: userip_convert_to_ip(parent, ip_address, player),
            icon=QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')),
        )
    if persisted_usernames:
        add_action(
            userip_menu,
            tr('Rename'),
            tooltip=tr('Rename all entries for this IP address by picking from existing usernames in its database.'),
            handler=lambda: userip_rename(parent, ip_address, player),
            icon=QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')),
        )
    if player.userip.notes:
        note_label = tr('Edit Note…')
        note_tooltip = tr('Edit the note for this IP address in its UserIP database.')
    else:
        note_label = tr('Add Note…')
        note_tooltip = tr('Add the note for this IP address in its UserIP database.')
    add_action(
        userip_menu,
        note_label,
        tooltip=note_tooltip,
        handler=lambda: userip_edit_note(parent, ip_address, player),
        icon=QIcon(str(ICONS_DIR_PATH / 'notepad-text.svg')),
    )
    move_single_tooltips = {
        'single_ip': (
            tr('Move this single IP entry to another UserIP database.'),
            tr('Move this single IP entry to this UserIP database.'),
            tr('Delete this single IP entry from its UserIP database.'),
        ),
        'subnet': (
            tr('Move this subnet entry to another UserIP database.'),
            tr('Move this subnet entry to this UserIP database.'),
            tr('Delete this subnet entry from its UserIP database.'),
        ),
        'ip_range': (
            tr('Move this IP range entry to another UserIP database.'),
            tr('Move this IP range entry to this UserIP database.'),
            tr('Delete this IP range entry from its UserIP database.'),
        ),
        'range': (
            tr('Move this range entry to another UserIP database.'),
            tr('Move this range entry to this UserIP database.'),
            tr('Delete this range entry from its UserIP database.'),
        ),
    }
    move_another_single_tip, move_this_single_tip, delete_single_tip = move_single_tooltips[entry_kind]
    move_userip_menu = add_menu(
        userip_menu,
        tr('Move'),
        tooltip=move_another_single_tip,
        icon=QIcon(str(ICONS_DIR_PATH / 'box.svg')),
    )
    populate_userip_databases_menu(
        move_userip_menu,
        UserIPDatabases.get_userip_database_filepaths(),
        tooltip=move_this_single_tip,
        handler_factory=lambda db_path: lambda: userip_move(parent, [ip_address], db_path),
        disabled_path=player.userip.db_path,
    )
    _add_move_group_menu(userip_menu, parent, [player], [ip_address])
    if len(persisted_usernames) >= MIN_USERNAMES_FOR_REMOVAL:
        add_action(
            userip_menu,
            tr('Remove Username…'),
            tooltip=tr('Remove selected usernames for this IP address while keeping others.'),
            handler=lambda: userip_remove_username(parent, ip_address, player),
            icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
        )
    add_action(
        userip_menu,
        tr('Delete'),
        tooltip=delete_single_tip,
        handler=lambda: userip_delete(parent, [ip_address]),
        icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
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
        userip_menu = add_menu(context_menu, tr('UserIP'), icon=QIcon(str(ICONS_DIR_PATH / 'database.svg')))
        _add_resolve_conflict_action(userip_menu, conflicting_ip)
        return

    if all(not UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
        userip_menu = add_menu(context_menu, tr('UserIP'), icon=QIcon(str(ICONS_DIR_PATH / 'database.svg')))
        add_userip_menu = add_menu(userip_menu, tr('Add Selected'), icon=QIcon(str(ICONS_DIR_PATH / 'plus.svg')))
        all_usernames = dedup_preserve_order(*(resolve_usernames_for_player(player) for player in players))
        populate_userip_databases_menu(
            add_userip_menu,
            UserIPDatabases.get_userip_database_filepaths(),
            tooltip=tr_plural(
                'Add the selected IP address to this UserIP database.',
                'Add the {count} selected IP addresses to this UserIP database.',
                len(ip_addresses),
            ),
            handler_factory=lambda db_path: lambda: userip_add(parent, ip_addresses, db_path, usernames=all_usernames),
        )
        if len(all_usernames) >= MIN_GROUP_USERNAMES:
            userip_menu.addSeparator()
            add_action(
                userip_menu,
                tr('Group Selected'),
                tooltip=tr('Group all usernames across the selected players together.'),
                handler=lambda: userip_group_selected(parent, players),
                icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
            )
        if all_usernames:
            add_action(
                userip_menu,
                tr('Group With…'),
                tooltip=tr('Group the selected players with another username.'),
                handler=lambda: userip_group_with(parent, players),
                icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
            )
        return

    if all(UserIPDatabases.is_known_ip(ip) for ip in ip_addresses):
        userip_menu = add_menu(context_menu, tr('UserIP'), icon=QIcon(str(ICONS_DIR_PATH / 'database.svg')))

        rename_players = [player for player in players if player.userip is not None]
        if rename_players:
            add_action(
                userip_menu,
                tr('Rename Selected'),
                tooltip=_format_multi_entry_tooltip('rename', [player.ip for player in rename_players]),
                handler=lambda: userip_rename_multi(parent, rename_players),
                icon=QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')),
            )

        selected_usernames = dedup_preserve_order(
            *((p.userip.usernames if p.userip is not None else resolve_usernames_for_player(p)) for p in players),
        )
        if len(selected_usernames) >= MIN_GROUP_USERNAMES:
            add_action(
                userip_menu,
                tr('Group Selected'),
                tooltip=tr('Group all usernames across the selected players together.'),
                handler=lambda: userip_group_selected(parent, players),
                icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
            )
        if selected_usernames:
            add_action(
                userip_menu,
                tr('Group With…'),
                tooltip=tr('Group the selected players with another username.'),
                handler=lambda: userip_group_with(parent, players),
                icon=QIcon(str(ICONS_DIR_PATH / 'user-plus.svg')),
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
                    tr('Verify IPs (Looky System)') if is_all_searchlist else tr('Refresh IPs (Looky System)'),
                    tooltip=(
                        _format_multi_entry_tooltip('verify_looky', ip_addresses)
                        if is_all_searchlist
                        else _format_multi_entry_tooltip('refresh_looky', ip_addresses)
                    ),
                    handler=lambda: looky_refresh_userip_entries(parent, list(_refresh_by_db.items()), restriction=restriction),
                    icon=QIcon(str(ICONS_DIR_PATH / 'eye.svg')),
                )
                configure_looky_action(refresh_multi_action, default_tooltip=refresh_multi_action.toolTip(), restriction=restriction)
                userip_menu.addSeparator()

        move_userip_menu = add_menu(
            userip_menu,
            tr('Move Selected'),
            tooltip=_format_multi_entry_tooltip('move_another', ip_addresses),
            icon=QIcon(str(ICONS_DIR_PATH / 'box.svg')),
        )
        populate_userip_databases_menu(
            move_userip_menu,
            UserIPDatabases.get_userip_database_filepaths(),
            tooltip=_format_multi_entry_tooltip('move_this', ip_addresses),
            handler_factory=lambda db_path: lambda: userip_move(parent, ip_addresses, db_path),
            disabled_path=next(iter(selected_dbs)) if len(selected_dbs := {p.userip.db_path for p in rename_players if p.userip is not None}) == 1 else None,
        )
        _add_move_group_menu(userip_menu, parent, players, ip_addresses)

        add_action(
            userip_menu,
            tr('Delete Selected'),
            tooltip=_format_multi_entry_tooltip('delete', ip_addresses),
            handler=lambda: userip_delete(parent, ip_addresses),
            icon=QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
        )
