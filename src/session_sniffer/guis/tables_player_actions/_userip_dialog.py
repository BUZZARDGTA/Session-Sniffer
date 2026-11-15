"""UserIPDetectedDialog and show_userip_detected_dialog helper."""

from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QMessageBox,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.select_usernames_dialog import SelectUsernamesDialog, UsernameSelectionConfig, prompt_username_input
from session_sniffer.guis.tables_player_actions._format import format_bool, format_text
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import sync_player_looky_usernames_and_userip
from session_sniffer.guis.tables_userip_mixin import collect_persisted_usernames_for_ip, resolve_usernames_for_player
from session_sniffer.guis.userip_manager_helpers import (
    format_userip_db_display_name,
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
)
from session_sniffer.guis.utils import ActiveDialogRegistry, format_player_display, set_dialog_window_flags
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.userip_settings_model import format_iso_timestamp_display
from session_sniffer.notifications_state import notifications_state
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.userip import UserIP, UserIPDatabases
from session_sniffer.player.userip_groups import (
    MIN_GROUP_USERNAMES,
    are_usernames_unlinked,
    exclude_looky_usernames,
    get_excluded_looky_usernames,
    get_excluded_looky_usernames_cf,
    group_usernames,
    restore_looky_usernames,
    ungroup_usernames,
)
from session_sniffer.player.userip_loader import collect_userip_account_groups, get_account_group_clusters_map
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.models.player import Player


class UserIPDetectedDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing UserIP detection data for a player, updating live as lookups resolve."""

    _REFRESH_INTERVAL_MS = 500

    def __init__(self, parent: QWidget | None, player: Player, userip: UserIP | None = None) -> None:
        """Snapshot player data at detection time, build the dialog UI, and start the refresh timer."""
        super().__init__(parent)
        set_dialog_window_flags(self, keep_on_top=True)
        self._player = player
        self._userip: UserIP | None = userip or player.userip
        if self._player.userip is None and self._userip is not None:
            self._player.userip = self._userip
        if self._userip is not None and self._userip.usernames:
            self._player.usernames = dedup_preserve_order(self._player.usernames, self._userip.usernames)

        initial_usernames = self._get_usernames()
        display = format_player_display(player.ip, initial_usernames)
        self.setWindowTitle(f'{TITLE} - {tr("UserIP Detected")} ({display})')
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)
        self._header_label = self._add_header_label(outer_layout, f'{tr("UserIP Detected")} — {display}', '#c53030', '#dd6b20')

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_detection_group(scroll_layout, player)
        self._build_iplookup_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

        self._timer = self._init_refresh_timer(self._REFRESH_INTERVAL_MS, self._refresh)
        register_language_refresh(self, self._refresh)

        self._refresh()

    def _get_userip(self) -> UserIP | None:
        if self._player.userip is not None:
            return self._player.userip
        if self._userip is not None:
            return self._userip
        resolved = UserIPDatabases.resolve_userip(self._player.ip)
        if resolved is not None:
            self._player.userip = resolved
            if resolved.usernames:
                self._player.usernames = dedup_preserve_order(self._player.usernames, resolved.usernames)
            return resolved
        return None

    def _get_usernames(self) -> list[str]:
        userip = self._get_userip()
        userip_names = userip.usernames if userip is not None else []
        if self._player.usernames and userip_names:
            return dedup_preserve_order(self._player.usernames, userip_names)
        if self._player.usernames:
            return self._player.usernames
        return list(userip_names)

    def _get_notes(self) -> list[str]:
        userip = self._get_userip()
        return list(userip.notes) if userip is not None and userip.notes else []

    def _get_sources(self) -> list[str]:
        userip = self._get_userip()
        return list(userip.sources) if userip is not None and userip.sources else []

    def _get_database_name(self) -> str:
        userip = self._get_userip()
        return format_userip_db_display_name(userip.db_path) if userip is not None else tr('N/A')

    def _build_detection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Details' section to the scroll layout."""
        group, form = self._make_group(tr('Detection Details'), accent='#c53030')
        detection_type = player.userip_detection.type if player.userip_detection is not None else None
        self._add_live_row(form, 'Detection Time', lambda: player.userip_detection.time if player.userip_detection is not None else tr('N/A'))
        self._add_live_row(
            form,
            lambda: tr_plural('Username', 'Usernames', len(self._get_usernames())),
            lambda: ', '.join(self._get_usernames()) or tr('N/A'),
        )
        self._add_row(form, 'IP Address', player.ip)
        self._add_live_row(form, 'Hostname', lambda: format_text(player.reverse_dns.hostname))
        self._add_live_row(
            form,
            lambda: tr_plural('Port', 'Ports', len(player.ports.all)),
            lambda: ', '.join(map(str, reversed(player.ports.all))) if player.ports.all else tr('N/A'),
        )
        self._add_live_row(form, 'Country Code', lambda: format_text(player.iplookup.resolve_country_code()))
        self._add_live_row(
            form,
            'Detection Type',
            lambda: player.userip_detection.type if player.userip_detection is not None else (detection_type or tr('N/A')),
        )
        self._add_live_row(form, 'Database', self._get_database_name)
        self._add_live_row(
            form,
            lambda: tr_plural('Note', 'Notes', len(self._get_notes())),
            lambda: ', '.join(self._get_notes()) or tr('N/A'),
        )
        self._add_live_row(
            form,
            lambda: tr_plural('Source', 'Sources', len(self._get_sources())),
            lambda: ', '.join(self._get_sources()) or tr('N/A'),
        )
        self._add_live_row(
            form,
            'Detections',
            lambda: str(userip.detections_count) if (userip := self._get_userip()) is not None else tr('N/A'),
        )
        self._add_live_row(
            form,
            'Added',
            lambda: (format_iso_timestamp_display(userip.added_at) or tr('N/A')) if (userip := self._get_userip()) is not None else tr('N/A'),
        )
        self._add_live_row(
            form,
            'Updated',
            lambda: (format_iso_timestamp_display(userip.updated_at) or tr('N/A')) if (userip := self._get_userip()) is not None else tr('N/A'),
        )
        self._add_live_row(
            form,
            'First Seen (DB)',
            lambda: (format_iso_timestamp_display(userip.first_seen_at) or tr('N/A')) if (userip := self._get_userip()) is not None else tr('N/A'),
        )
        self._add_live_row(
            form,
            'Last Seen (DB)',
            lambda: (format_iso_timestamp_display(userip.last_seen_at) or tr('N/A')) if (userip := self._get_userip()) is not None else tr('N/A'),
        )
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'IP Lookup' section to the scroll layout."""
        group, form = self._make_group(tr('IP Lookup'), accent='#38a169')
        self._add_live_row(form, 'Continent', lambda: format_text(player.iplookup.resolve_continent()[0]))
        self._add_live_row(form, 'Country', lambda: format_text(player.iplookup.resolve_country()[0]))
        self._add_live_row(form, 'Region', lambda: format_text(player.iplookup.ipapi.region))
        self._add_live_row(form, 'City', lambda: format_text(player.iplookup.resolve_city()))
        self._add_live_row(form, 'Organization', lambda: format_text(player.iplookup.ipapi.org))
        self._add_live_row(form, 'ISP', lambda: format_text(player.iplookup.ipapi.isp))
        self._add_live_row(form, 'GeoLite2 ASN / ISP', lambda: format_text(player.iplookup.geolite2.asn))
        self._add_live_row(form, 'AS Name', lambda: format_text(player.iplookup.ipapi.as_name))
        self._add_live_row(form, 'Mobile (cellular)', lambda: format_bool(player.iplookup.ipapi.mobile))
        self._add_live_row(form, 'Proxy / VPN / Tor', lambda: format_bool(player.iplookup.ipapi.proxy))
        self._add_live_row(form, 'Hosting / Datacenter', lambda: format_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    def _refresh(self) -> None:
        """Re-evaluate dynamic row providers and update the UI."""
        if not isValid(self):
            return
        usernames = self._get_usernames()
        display = format_player_display(self._player.ip, usernames)
        new_title = f'{TITLE} - {tr("UserIP Detected")} ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
        new_header = f'{tr("UserIP Detected")} — {display}'
        if self._header_label.text() != new_header:
            self._header_label.setText(new_header)

        self._refresh_live_rows()


_active_dialogs: ActiveDialogRegistry[str, UserIPDetectedDialog] = ActiveDialogRegistry()


def show_userip_detected_dialog(parent: QWidget | None, player: Player, userip: UserIP | None = None) -> None:
    """Open or focus the UserIP Detected dialog for *player*."""
    if userip is not None and player.userip is None:
        player.userip = userip
    if not notifications_state.visual_enabled:
        return
    _active_dialogs.show_or_focus(player.ip, lambda: UserIPDetectedDialog(parent, player, userip))


def close_all_userip_detected_dialogs() -> None:
    """Close all open UserIP Detected notification dialogs."""
    _active_dialogs.close_all()


_MAX_GROUP_PROMPT_NAMES = 3


def _format_group_source_display(names: Sequence[str]) -> str:
    """Format up to `_MAX_GROUP_PROMPT_NAMES` usernames for the Group With dialog prompt."""
    preview = ', '.join(names[:_MAX_GROUP_PROMPT_NAMES])
    extra = len(names) - _MAX_GROUP_PROMPT_NAMES
    return tr('{preview} (+{extra} more)', preview=preview, extra=extra) if extra > 0 else preview


def _update_detached_usernames_for_player(player: Player, cfs: set[str], *, detach: bool) -> None:
    """Add or remove casefolded usernames in `cfs` from `detached_userip_usernames_cf` on `player` and its registry/snapshot counterparts."""
    if not cfs:
        return
    live_player = PlayersRegistry.get_player_by_ip(player.ip)
    targets = [
        player,
        *([live_player] if live_player is not None and live_player is not player else []),
        *(s for s in SessionTracker.get_all_snapshot_players() if s is not player and s.ip == player.ip),
    ]
    for target in targets:
        if detach:
            target.detached_userip_usernames_cf.update(cfs)
        else:
            target.detached_userip_usernames_cf.difference_update(cfs)


def get_player_userip_group_seeds(player: Player, *, persisted_usernames: Sequence[str] | None = None, exact_ip_first: bool = False) -> tuple[list[str], frozenset[str]]:
    """Return `(seed_usernames, excluded_cfs)` for resolving *player*'s UserIP account group(s)."""
    filtered = UserIPDatabases.filter_userip_for_player(player, player.userip) or UserIPDatabases.resolve_userip_for_player(player)
    if filtered is None:
        seeds = [u for u in resolve_usernames_for_player(player) if u.strip() and u.strip().casefold() not in player.detached_userip_usernames_cf]
        return dedup_preserve_order(seeds), frozenset(player.detached_userip_usernames_cf)

    filtered_cfs = {u.strip().casefold() for u in filtered.usernames if u.strip()}
    raw_persisted = list(persisted_usernames) if persisted_usernames is not None else collect_persisted_usernames_for_ip(filtered.db_path, player.ip)
    if exact_ip_first and filtered.db_path.is_file() and (
        exact_names := [
            e.username.strip() for e in load_userip_database_model(filtered.db_path).entries
            if e.username.strip() and e.ip.strip() == player.ip and (not filtered_cfs or e.username.strip().casefold() in filtered_cfs)
        ]
    ):
        raw_persisted = dedup_preserve_order(exact_names)

    base_candidates = raw_persisted if (exact_ip_first and raw_persisted) else list(filtered.usernames)
    non_detached = [u for u in base_candidates if u.strip() and u.strip().casefold() not in player.detached_userip_usernames_cf]
    anchors = non_detached or [u for u in base_candidates if u.strip()]
    extra_persisted = [
        u for u in raw_persisted
        if u.strip() and u.strip().casefold() not in player.detached_userip_usernames_cf and not any(are_usernames_unlinked(u, a) for a in anchors)
    ]
    return dedup_preserve_order(anchors, extra_persisted), frozenset(player.detached_userip_usernames_cf) if non_detached else frozenset()


def collect_grouped_usernames_for_player(player: Player, *, persisted_usernames: Sequence[str] | None = None) -> list[str]:
    """Return all usernames currently grouped with *player* across UserIP databases and persisted links."""
    seeds, excluded_cfs = get_player_userip_group_seeds(player, persisted_usernames=persisted_usernames)
    if not seeds:
        return []
    seed_cfs = {u.casefold() for u in seeds}
    groups = collect_userip_account_groups(include_disabled=False, excluded_cfs=excluded_cfs, extra_seed_usernames=seeds)
    matched_names = [u for group in groups if group.usernames_cf & seed_cfs for u in group.usernames]
    candidates = [u for u in dedup_preserve_order(seeds, matched_names) if u.casefold() not in excluded_cfs]
    if len(candidates) <= 1:
        return candidates
    return [u for u in candidates if any(u.casefold() != v.casefold() and not are_usernames_unlinked(u, v) for v in candidates)]


def prompt_and_group_with(parent: QWidget, source_usernames: Sequence[str]) -> tuple[str, str] | None:
    """Prompt the user for a username to group with `source_usernames`, persist the group, and refresh UserIP."""
    if not source_usernames:
        return None
    source_display = _format_group_source_display(source_usernames)
    target_username, ok = prompt_username_input(
        parent,
        f'{tr("Group With")} - {TITLE}',
        tr('Enter the username to group with "{source}":', source=source_display),
    )
    if not ok or not target_username.strip():
        return None
    target_clean = target_username.strip()
    combined = dedup_preserve_order(source_usernames, [target_clean])
    if len(combined) < MIN_GROUP_USERNAMES:
        QMessageBox.information(parent, TITLE, tr('Please enter a different username to group with.'))
        return None
    if group_usernames(combined, get_account_group_clusters_map(include_disabled=True)):
        refresh_userip_and_wake_renderer()
        return target_clean, source_display
    return None


def prompt_and_ungroup(parent: QWidget, group_members: list[str], *, selected_ips: list[str] | None = None) -> list[str]:
    """Open the Ungroup Usernames dialog for `group_members`, persist the ungrouping, and refresh UserIP."""
    if len(group_members) < MIN_GROUP_USERNAMES:
        return []
    dlg = SelectUsernamesDialog(parent, group_members, UsernameSelectionConfig.for_ungroup(selected_ips=selected_ips))
    if dlg.exec() != SelectUsernamesDialog.DialogCode.Accepted:
        return []
    chosen = dlg.selected_usernames()
    if chosen:
        ungroup_usernames(chosen, group_members)
        refresh_userip_and_wake_renderer()
        return chosen
    return []


def userip_group_with(parent: QWidget, players: Sequence[Player]) -> None:
    """Prompt the user to type/select a username and group it with the selected player(s)' usernames."""
    source_usernames = dedup_preserve_order(
        *((player.userip.usernames if player.userip is not None and player.userip.usernames else resolve_usernames_for_player(player)) for player in players),
    )
    if not source_usernames:
        typed_source, ok_source = prompt_username_input(
            parent,
            f'{tr("Group With")} - {TITLE}',
            tr('Enter the username for the selected player:'),
        )
        if not ok_source or not typed_source.strip():
            return
        source_usernames = [typed_source.strip()]

    if result := prompt_and_group_with(parent, source_usernames):
        target_clean, source_display = result
        grouped_cfs = {u.casefold() for u in (*source_usernames, target_clean)}
        for player in players:
            _update_detached_usernames_for_player(player, grouped_cfs, detach=False)
        refresh_userip_and_wake_renderer()
        QMessageBox.information(parent, TITLE, tr('Grouped username "{username}" with {source}.', username=target_clean, source=source_display))


def userip_group_selected(parent: QWidget, players: Sequence[Player]) -> None:
    """Group all usernames across the selected players together."""
    usernames = dedup_preserve_order(
        *((player.userip.usernames if player.userip is not None and player.userip.usernames else resolve_usernames_for_player(player)) for player in players),
    )
    if len(usernames) < MIN_GROUP_USERNAMES:
        QMessageBox.information(parent, TITLE, tr('Select at least two players with distinct usernames to group them together.'))
        return

    grouped_cfs = {u.casefold() for u in usernames}
    for player in players:
        _update_detached_usernames_for_player(player, grouped_cfs, detach=False)
    if group_usernames(usernames, get_account_group_clusters_map(include_disabled=True)):
        refresh_userip_and_wake_renderer()
        names_display = ', '.join(f'"{name}"' for name in usernames)
        QMessageBox.information(
            parent,
            TITLE,
            tr('Grouped {count} usernames together: {usernames}.', count=len(usernames), usernames=names_display),
        )


def userip_ungroup(parent: QWidget, player: Player) -> None:
    """Open a selection dialog to ungroup false-positive or unlinked usernames from *player*'s account group."""
    group_members = collect_grouped_usernames_for_player(player)
    if chosen := prompt_and_ungroup(parent, group_members, selected_ips=[player.ip]):
        if len(chosen) < len(group_members):
            detached_cf = {u.casefold() for u in chosen}
        else:
            include_looky = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
            live_cfs = {u.casefold() for u in player.get_live_non_userip_usernames(include_looky=include_looky)}
            matching_live_cfs = {u.casefold() for u in group_members if u.casefold() in live_cfs}
            detached_cf = {u.casefold() for u in group_members if u.casefold() not in matching_live_cfs} if matching_live_cfs else {u.casefold() for u in group_members[1:]}
        _update_detached_usernames_for_player(player, detached_cf, detach=True)
        refresh_userip_and_wake_renderer()
        removed_display = ', '.join(f'"{name}"' for name in chosen)
        QMessageBox.information(parent, TITLE, tr('Ungrouped {usernames} from the account group.', usernames=removed_display))


def get_player_looky_username_lists(player: Player) -> tuple[list[str], list[str]]:
    """Return `(active_looky_usernames, removed_looky_usernames)` for *player*."""
    with player.looky_system.lock:
        active_names = list(player.looky_system.usernames)
        cached_removed = list(player.looky_system.removed_usernames)
    removed_names = dedup_preserve_order(cached_removed, get_excluded_looky_usernames(player.ip))
    return active_names, removed_names


def _refresh_player_looky_exclusions(player: Player, *, reset_userip_checked: bool = False) -> None:
    """Re-apply per-IP Looky username exclusions to *player* (and its live/snapshot counterparts) and wake the renderer."""
    excluded_cfs = get_excluded_looky_usernames_cf(player.ip)
    updated_names = player.looky_system.refresh_filtered_usernames(excluded_cfs)
    live_player = PlayersRegistry.get_player_by_ip(player.ip)
    live_update = (live_player, live_player.looky_system.refresh_filtered_usernames(excluded_cfs)) if live_player is not None and live_player is not player else None
    if reset_userip_checked:
        for target_p in (player, live_player):
            if target_p is not None:
                with target_p.looky_system.lock:
                    target_p.looky_system.as_userip_checked = False
    snap_updates = [
        (s, s.looky_system.refresh_filtered_usernames(excluded_cfs)) for s in SessionTracker.get_all_snapshot_players() if s is not player and s.ip == player.ip
    ]
    sync_player_looky_usernames_and_userip(player, updated_names, live_update, snap_updates)


def looky_remove_usernames_for_player(parent: QWidget, player: Player, active_looky_names: list[str]) -> None:
    """Open a dialog to exclude/hide selected Looky System usernames on *player*'s IP."""
    dlg = SelectUsernamesDialog(
        parent,
        active_looky_names,
        UsernameSelectionConfig(
            title=tr('Remove Looky Usernames'),
            instructions=tr_plural(
                'Select Looky username to hide on this IP:',
                'Select Looky usernames to hide on this IP:',
                len(active_looky_names),
            ),
            action_button_text=tr('Remove'),
            multiple=True,
            default_checked=False,
            selected_ips=[player.ip],
        ),
    )
    if dlg.exec() == SelectUsernamesDialog.DialogCode.Accepted:
        chosen = dlg.selected_usernames()
        peer_names = dedup_preserve_order(active_looky_names, player.userip.usernames if player.userip is not None else (), player.usernames)
        if chosen and exclude_looky_usernames(player.ip, chosen, peer_usernames=peer_names):
            _refresh_player_looky_exclusions(player)


def looky_restore_usernames_for_player(parent: QWidget, player: Player, removed_looky_names: list[str]) -> None:
    """Open a dialog to restore previously excluded Looky System usernames on *player*'s IP."""
    dlg = SelectUsernamesDialog(
        parent,
        removed_looky_names,
        UsernameSelectionConfig(
            title=tr('Restore Removed Looky Usernames'),
            instructions=tr_plural(
                'Select removed Looky username to re-add on this IP:',
                'Select removed Looky usernames to re-add on this IP:',
                len(removed_looky_names),
            ),
            action_button_text=tr('Restore'),
            multiple=True,
            default_checked=True,
            selected_ips=[player.ip],
        ),
    )
    if dlg.exec() == SelectUsernamesDialog.DialogCode.Accepted:
        chosen = dlg.selected_usernames()
        if chosen and restore_looky_usernames(player.ip, chosen):
            _refresh_player_looky_exclusions(player, reset_userip_checked=True)
