"""UserIP database operations for the session table context menu."""

import html
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QWidget

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.select_usernames_dialog import SelectUsernamesDialog, prompt_username_input, prompt_usernames_and_notes_input
from session_sniffer.guis.userip_manager_helpers import (
    IPRangeBuilderDialog,
    format_userip_db_display_name,
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    rewrite_db_edit_entry_ip,
    rewrite_db_edit_ip_notes,
    rewrite_db_rename_entries,
    save_userip_database_model,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.userip_settings_model import UserIPDatabaseFile, UserIPEntryModel
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import (
    MIN_GROUP_USERNAMES,
    are_usernames_unlinked,
    group_usernames,
)
from session_sniffer.player.userip_loader import (
    append_userip_entries,
    get_account_group_clusters_map,
    move_userip_entries_to_database,
    userip_databases_lock,
)
from session_sniffer.rendering_core.types import CaptureState, SessionFilterState
from session_sniffer.settings import Settings
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from session_sniffer.models.player import Player


def _collect_matching_entries_in_db(db_path: Path, ip_address: str, *, ranges_only: bool = False) -> list[str]:
    """Return distinct `UserIP` entry IP/range strings in `db_path` that match `ip_address`."""
    if not db_path.is_file():
        return []
    db_model = load_userip_database_model(db_path)
    matching_entries: list[str] = []
    for entry in db_model.entries:
        entry_ip = entry.ip.strip()
        if ranges_only and entry_ip == ip_address:
            continue
        if entry_ip not in matching_entries and entry_ip_covers_ip(entry_ip, ip_address):
            matching_entries.append(entry_ip)
    return matching_entries


def collect_persisted_usernames_for_ip(db_path: Path, ip_address: str) -> list[str]:
    """Return deduplicated usernames from entries in `db_path` whose IP/range covers `ip_address`."""
    if not db_path.is_file():
        return []
    db_model = load_userip_database_model(db_path)
    return dedup_preserve_order(entry.username.strip() for entry in db_model.entries if entry.username.strip() and entry_ip_covers_ip(entry.ip.strip(), ip_address))


def _show_modal_info_on_top(parent: QWidget, title: str, text: str) -> None:
    """Show a modal information message box that stays on top of other windows."""
    message_box = QMessageBox(parent)
    message_box.setIcon(QMessageBox.Icon.Information)
    message_box.setWindowTitle(title)
    message_box.setText(text)
    message_box.setStandardButtons(QMessageBox.StandardButton.Ok)
    message_box.setWindowModality(Qt.WindowModality.WindowModal)
    message_box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
    message_box.exec()


def _entry_ip_matches_any(entry_ip: str, selected_ips: list[str]) -> bool:
    """Return True if *entry_ip* exactly matches or is a range containing any IP in *selected_ips*."""
    return any(entry_ip_covers_ip(entry_ip, selected_ip) for selected_ip in selected_ips)


def resolve_usernames_for_player(player: Player, *, include_relay_mod_menus: bool = False) -> list[str]:
    """Return deduplicated usernames associated with the given player from all sources."""
    include_looky = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
    if include_relay_mod_menus or not player.has_relay_mod_menus:
        live_names = player.get_live_non_userip_usernames(include_looky=include_looky)
        base_usernames: Sequence[str] = player.usernames
    else:
        persisted = player.get_persisted_usernames(include_looky=include_looky)
        userip_cfs: set[str] = {u.casefold() for u in player.userip.usernames} if player.userip is not None else set()
        live_names = [u for u in persisted if u.casefold() not in userip_cfs]
        base_usernames = persisted
    player_names = dedup_preserve_order(live_names[:1] if bool(player.ps3_username) else (), player.userip.usernames if player.userip else (), live_names, base_usernames)
    names: list[str] = [name.strip() for name in player_names if name.strip()]
    return UserIPDatabases.expand_with_known_alts(names) if Settings.userip_sync_known_alts else names


def resolve_usernames_for_ips(selected_ips: list[str]) -> list[str]:
    """Return deduplicated usernames associated with the given IP addresses from the player registry."""
    selected_session = SessionFilterState.get_selected_session()
    is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
    all_usernames: list[str] = []
    for ip_address in selected_ips:
        player = (SessionTracker.get_session_snapshot_player(selected_session, ip_address) if is_past_session else None) or PlayersRegistry.get_player_by_ip(ip_address)
        if player is not None:
            all_usernames.extend(resolve_usernames_for_player(player))
    return dedup_preserve_order(all_usernames)


def _prompt_usernames_to_add(
    parent: QWidget,
    selected_ips: list[str],
    selected_database: Path,
    *,
    candidate_usernames: list[str] | None = None,
    prompt_message: str | Callable[[int], str] | None = None,
) -> tuple[list[str], dict[str, str]] | None:
    """Prompt the user for one or more usernames to associate with the selected IP(s).

    If exactly one username is found/provided, pre-fills the input dialog.
    If multiple usernames are found, shows a selection dialog to pick which one(s) to add.
    If no usernames are found, displays a standard blank input dialog.
    Both dialogs also let the user enter an optional note per username.

    Returns a tuple of the non-empty list of chosen usernames and `{username: note}`
    for usernames with a non-empty note, or None if cancelled/empty.
    """
    candidates = (
        [name.strip() for name in dedup_preserve_order(candidate_usernames) if name.strip()] if candidate_usernames is not None else resolve_usernames_for_ips(selected_ips)
    )
    if Settings.userip_sync_known_alts:
        candidates = UserIPDatabases.expand_with_known_alts(candidates)

    db_display = format_userip_db_display_name(selected_database)

    if len(candidates) > 1:
        dialog = SelectUsernamesDialog.for_add(
            parent,
            candidates,
            database=db_display,
            selected_ips=selected_ips,
        )
        if dialog.exec() != SelectUsernamesDialog.DialogCode.Accepted:
            return None

        if not dialog.custom_requested():
            selected = dialog.selected_usernames()
            if not selected:
                return None
            return selected, dialog.notes_by_username()

        # User clicked 'Custom…' in the selection dialog
        initial_usernames = dialog.selected_usernames()
        initial_notes = dialog.notes_by_username()
    elif len(candidates) == 1:
        initial_usernames = [candidates[0]]
        initial_notes = {}
    else:
        initial_usernames = []
        initial_notes = {}

    if prompt_message is None:

        def _default_prompt(count: int) -> str:
            if len(selected_ips) == 1:
                return tr_plural(
                    'Please enter the username to associate with the selected IP:',
                    'Please enter the usernames to associate with the selected IP:',
                    count,
                )
            return tr_plural(
                'Please enter the username to associate with the selected IPs:',
                'Please enter the usernames to associate with the selected IPs:',
                count,
            )

        prompt_message = _default_prompt

    entered_usernames, entered_notes, success = prompt_usernames_and_notes_input(
        parent,
        tr('Input Username(s)'),
        prompt_message,
        initial_usernames,
        initial_notes,
    )

    if not success:
        return None

    if not entered_usernames:
        QMessageBox.warning(parent, TITLE, tr('ERROR:\nNo username was provided.'))
        return None

    return entered_usernames, entered_notes


def userip_add(
    parent: QWidget,
    selected_ips: list[str],
    selected_database: Path,
    *,
    usernames: list[str] | None = None,
) -> None:
    """Add the selected IP address(es) to the chosen UserIP database."""
    candidates = list(usernames) if usernames is not None else None
    prompt_result = _prompt_usernames_to_add(parent, selected_ips, selected_database, candidate_usernames=candidates)
    if prompt_result is None:
        return
    chosen_usernames, notes_by_username = prompt_result
    if not chosen_usernames:
        return

    with userip_databases_lock():
        existing_pairs: set[tuple[str, str]] = set()
        if selected_database.is_file():
            db_model = load_userip_database_model(selected_database)
            existing_pairs = {(entry.username.casefold(), entry.ip) for entry in db_model.entries}

        new_entries = [
            UserIPEntryModel(username=username, ip=ip_address, notes=notes_by_username.get(username, ''))
            for username in chosen_usernames
            for ip_address in selected_ips
            if (username.casefold(), ip_address) not in existing_pairs
        ]
        if new_entries:
            append_userip_entries(selected_database, new_entries)
            if len(chosen_usernames) >= MIN_GROUP_USERNAMES:
                group_usernames(chosen_usernames, get_account_group_clusters_map(include_disabled=True))
        refresh_userip_and_wake_renderer()

    db_display = format_userip_db_display_name(selected_database)
    usernames_display = ', '.join(f'"{name}"' for name in chosen_usernames)
    ips_display = ', '.join(selected_ips)
    if len(selected_ips) == 1:
        added_text = tr_plural(
            'Selected IP {ips} has been added with username {usernames} to UserIP database "{database}".',
            'Selected IP {ips} has been added with usernames {usernames} to UserIP database "{database}".',
            len(chosen_usernames),
            ips=ips_display,
            usernames=usernames_display,
            database=db_display,
        )
    else:
        added_text = tr_plural(
            'Selected IPs {ips} have been added with username {usernames} to UserIP database "{database}".',
            'Selected IPs {ips} have been added with usernames {usernames} to UserIP database "{database}".',
            len(chosen_usernames),
            ips=ips_display,
            usernames=usernames_display,
            database=db_display,
        )
    _show_modal_info_on_top(parent, TITLE, added_text)
    UserIPDatabases.renotify_if_conflicting(selected_ips)


def userip_add_as_range(parent: QWidget, ip_address: str, selected_database: Path, *, usernames: list[str] | None = None) -> None:
    """Add the selected IP address as a range entry to the chosen UserIP database."""
    range_dialog = IPRangeBuilderDialog(parent, initial_ip=ip_address, allow_single_ip=False)
    if range_dialog.exec() != IPRangeBuilderDialog.DialogCode.Accepted:
        return

    range_input = range_dialog.result_entry()
    if not range_input:
        return

    candidates = list(usernames) if usernames is not None else None
    prompt_result = _prompt_usernames_to_add(
        parent,
        [ip_address],
        selected_database,
        candidate_usernames=candidates,
        prompt_message=lambda count: tr_plural(
            'Enter the username to associate with range "{range}":',
            'Enter the usernames to associate with range "{range}":',
            count,
            range=range_input,
        ),
    )
    if prompt_result is None:
        return
    chosen_usernames, notes_by_username = prompt_result
    if not chosen_usernames:
        return

    append_userip_entries(selected_database, [UserIPEntryModel(username=u, ip=range_input, notes=notes_by_username.get(u, '')) for u in chosen_usernames])
    if len(chosen_usernames) >= MIN_GROUP_USERNAMES:
        group_usernames(chosen_usernames, get_account_group_clusters_map(include_disabled=True))
    refresh_userip_and_wake_renderer()

    db_display = format_userip_db_display_name(selected_database)
    usernames_display = ', '.join(f'"{name}"' for name in chosen_usernames)
    _show_modal_info_on_top(
        parent,
        TITLE,
        tr_plural(
            'Range "{range}" has been added with username {usernames} to UserIP database "{database}".',
            'Range "{range}" has been added with usernames {usernames} to UserIP database "{database}".',
            len(chosen_usernames),
            range=range_input,
            usernames=usernames_display,
            database=db_display,
        ),
    )
    UserIPDatabases.renotify_if_conflicting([range_input])


def userip_convert_to_range(parent: QWidget, ip_address: str, player: Player) -> None:
    """Convert a single-IP UserIP entry into a range entry in place, keeping its username(s).

    Useful when an IP that was tagged with a username later turns out to belong to a
    VPN/subnet: instead of deleting the entry and re-adding it as a range, every exact
    single-IP entry matching `ip_address` is rewritten to the range built via the dialog.
    """
    if player.userip is None or not player.userip.usernames:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)

    range_dlg = IPRangeBuilderDialog(parent, initial_ip=ip_address, allow_single_ip=False)
    if range_dlg.exec() != IPRangeBuilderDialog.DialogCode.Accepted:
        return

    range_input = range_dlg.result_entry()
    if not range_input:
        return

    converted_count = rewrite_db_edit_entry_ip(db_path, ip_address, range_input)
    if not converted_count:
        QMessageBox.information(parent, TITLE, tr('No single-IP entries found for IP {ip} in the database.', ip=ip_address))
        return

    refresh_userip_and_wake_renderer()
    _show_modal_info_on_top(
        parent,
        TITLE,
        tr_plural(
            'Converted {count} entry for IP {ip} to range "{range}" in UserIP database "{database}".',
            'Converted {count} entries for IP {ip} to range "{range}" in UserIP database "{database}".',
            converted_count,
            ip=ip_address,
            range=range_input,
            database=db_display,
        ),
    )
    UserIPDatabases.renotify_if_conflicting([range_input])


def _select_covering_range_in_db(
    parent: QWidget,
    db_path: Path,
    ip_address: str,
    *,
    dialog_title: str,
    prompt_text: str,
) -> str | None:
    """Return the single range covering `ip_address` in `db_path`, or prompt the user when multiple ranges match."""
    matching_ranges = _collect_matching_entries_in_db(db_path, ip_address, ranges_only=True)
    if not matching_ranges:
        QMessageBox.information(parent, TITLE, tr('No range entries found covering IP {ip} in the database.', ip=ip_address))
        return None
    if len(matching_ranges) == 1:
        return matching_ranges[0]
    chosen, success = QInputDialog.getItem(
        parent,
        dialog_title,
        prompt_text,
        matching_ranges,
        editable=False,
    )
    if not success or not chosen:
        return None
    return chosen


def userip_convert_to_ip(parent: QWidget, ip_address: str, player: Player) -> None:
    """Convert a covering range UserIP entry into a single-IP entry in place, keeping its username(s)."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)

    old_range = _select_covering_range_in_db(
        parent,
        db_path,
        ip_address,
        dialog_title=tr('Convert to IP'),
        prompt_text=tr('Multiple ranges cover IP {ip}.\nSelect the range to convert to single IP {ip}:', ip=ip_address),
    )
    if old_range is None:
        return

    converted_count = rewrite_db_edit_entry_ip(db_path, old_range, ip_address)
    if not converted_count:
        QMessageBox.information(parent, TITLE, tr('No entries found for range "{range}" in the database.', range=old_range))
        return

    refresh_userip_and_wake_renderer()
    _show_modal_info_on_top(
        parent,
        TITLE,
        tr_plural(
            'Converted {count} entry from range "{range}" to single IP {ip} in UserIP database "{database}".',
            'Converted {count} entries from range "{range}" to single IP {ip} in UserIP database "{database}".',
            converted_count,
            range=old_range,
            ip=ip_address,
            database=db_display,
        ),
    )
    UserIPDatabases.renotify_if_conflicting([ip_address])


def userip_edit_range(parent: QWidget, ip_address: str, player: Player) -> None:
    """Edit an existing range entry that covers `ip_address` in its UserIP database, keeping its username(s).

    The player's matched range is located by scanning its database for range entries that contain
    `ip_address`. When several distinct ranges cover the IP, the user picks which one to edit. Every
    entry whose value equals the chosen range is then rewritten to the new range built via the dialog.
    """
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)

    old_range = _select_covering_range_in_db(
        parent,
        db_path,
        ip_address,
        dialog_title=tr('Edit Range'),
        prompt_text=tr('Multiple ranges cover IP {ip}.\nSelect the range to edit:', ip=ip_address),
    )
    if old_range is None:
        return

    # Single IP is allowed here so a range can be narrowed back down to one address.
    range_dlg = IPRangeBuilderDialog(parent, initial_entry=old_range)
    if range_dlg.exec() != IPRangeBuilderDialog.DialogCode.Accepted:
        return

    new_range = range_dlg.result_entry()
    if not new_range or new_range == old_range:
        return

    edited_count = rewrite_db_edit_entry_ip(db_path, old_range, new_range)
    if not edited_count:
        QMessageBox.information(parent, TITLE, tr('No entries found for range "{range}" in the database.', range=old_range))
        return

    refresh_userip_and_wake_renderer()
    _show_modal_info_on_top(
        parent,
        TITLE,
        tr_plural(
            'Updated {count} entry from range "{old_range}" to "{new_range}" in UserIP database "{database}".',
            'Updated {count} entries from range "{old_range}" to "{new_range}" in UserIP database "{database}".',
            edited_count,
            old_range=old_range,
            new_range=new_range,
            database=db_display,
        ),
    )
    UserIPDatabases.renotify_if_conflicting([new_range])


def userip_edit_note(parent: QWidget, ip_address: str, player: Player) -> None:
    """Edit the note associated with a known player's UserIP entry."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)
    current_note = ', '.join(player.userip.notes) if player.userip.notes else ''

    dialog_title = tr('Edit Note') if current_note else tr('Add Note')
    new_note, success = QInputDialog.getText(
        parent,
        dialog_title,
        tr('Note for IP {ip}.\nDatabase: {database}\n\nEnter the note (leave empty to clear):', ip=ip_address, database=db_display),
        QLineEdit.EchoMode.Normal,
        current_note,
    )
    if not success:
        return

    new_note = new_note.strip()
    if new_note == current_note:
        return

    matched_count = rewrite_db_edit_ip_notes(db_path, ip_address, new_note)
    if not matched_count:
        QMessageBox.information(parent, TITLE, tr('No entries found covering IP {ip} in the database.', ip=ip_address))
        return

    refresh_userip_and_wake_renderer()
    if new_note:
        QMessageBox.information(parent, TITLE, tr('Updated note for IP {ip} in UserIP database "{database}".', ip=ip_address, database=db_display))
    else:
        QMessageBox.information(parent, TITLE, tr('Cleared note for IP {ip} in UserIP database "{database}".', ip=ip_address, database=db_display))


def userip_add_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Add an additional username for an IP address that is already in a UserIP database."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)
    existing_count = len(player.userip.usernames)
    existing = ', '.join(player.userip.usernames) if player.userip.usernames else tr('None')
    candidates = [name for name in resolve_usernames_for_player(player) if name not in player.userip.usernames]

    def _add_username_prompt(count: int) -> str:
        header_line = tr_plural(
            'Current username for {ip}: {existing}',
            'Current usernames for {ip}: {existing}',
            max(existing_count, 1),
            ip=ip_address,
            existing=existing,
        )
        ask_line = tr_plural(
            'Enter the new username to add:',
            'Enter the new usernames to add:',
            count,
        )
        return f'{header_line}\n\n{ask_line}'

    prompt_result = _prompt_usernames_to_add(
        parent,
        [ip_address],
        db_path,
        candidate_usernames=candidates,
        prompt_message=_add_username_prompt,
    )

    if prompt_result is None:
        return
    entered_usernames, notes_by_username = prompt_result
    if not entered_usernames:
        return

    target_options = _collect_matching_entries_in_db(db_path, ip_address, ranges_only=False)
    if not target_options:
        target_entry = ip_address
    elif len(target_options) == 1:
        target_entry = target_options[0]
    else:
        chosen_target, selection_success = QInputDialog.getItem(
            parent,
            tr('Select Target Entry'),
            tr('Multiple UserIP entries match {ip}.\nSelect which entry to add the username to:', ip=ip_address),
            target_options,
            editable=False,
        )
        if not selection_success or not chosen_target:
            return
        target_entry = chosen_target

    existing_usernames, existing_note = list(player.userip.usernames), ', '.join(player.userip.notes) if player.userip.notes else ''
    append_userip_entries(
        db_path,
        [UserIPEntryModel(username=username, ip=target_entry, notes=notes_by_username.get(username) or existing_note) for username in entered_usernames],
        anchor_usernames_by_ip={target_entry: existing_usernames[0]} if existing_usernames else None,
    )
    if existing_usernames:
        anchor_name = existing_usernames[0]
        linked_existing = [name for name in existing_usernames if not are_usernames_unlinked(name, anchor_name)]
        group_usernames([*linked_existing, *entered_usernames], get_account_group_clusters_map(include_disabled=True))
    refresh_userip_and_wake_renderer()

    usernames_display = ', '.join(f'"{username}"' for username in entered_usernames)
    count = len(entered_usernames)
    if target_entry == ip_address:
        added_info_text = tr_plural(
            'Username {usernames} has been added for IP {target} in UserIP database "{database}".',
            'Usernames {usernames} have been added for IP {target} in UserIP database "{database}".',
            count,
            usernames=usernames_display,
            target=target_entry,
            database=db_display,
        )
    else:
        added_info_text = tr_plural(
            'Username {usernames} has been added for range {target} in UserIP database "{database}".',
            'Usernames {usernames} have been added for range {target} in UserIP database "{database}".',
            count,
            usernames=usernames_display,
            target=target_entry,
            database=db_display,
        )
    _show_modal_info_on_top(parent, TITLE, added_info_text)
    UserIPDatabases.renotify_if_conflicting([target_entry])


def userip_rename_multi(parent: QWidget, players: list[Player]) -> None:
    """Prompt once for a new username and apply it to all selected players' IP entries."""
    eligible: list[tuple[str, Path, list[str]]] = []
    for player in players:
        if player.userip is None or not player.userip.usernames:
            continue
        db_usernames = collect_persisted_usernames_for_ip(player.userip.db_path, player.ip)
        if db_usernames:
            eligible.append((player.ip, player.userip.db_path, db_usernames))
    if not eligible:
        return

    ips_display = ', '.join(ip for ip, _, _ in eligible)

    # Pre-fill with the shared username if every selected player has exactly the same one
    all_username_sets = [frozenset(db_usernames) for _, _, db_usernames in eligible]
    shared_username = (
        next(iter(all_username_sets[0])) if len(all_username_sets[0]) == 1 and all(username_set == all_username_sets[0] for username_set in all_username_sets) else ''
    )

    new_username, success = prompt_username_input(
        parent,
        tr('Rename Selected'),
        tr_plural(
            'Enter a new username for {count} selected IP:\n{ips}',
            'Enter a new username for {count} selected IPs:\n{ips}',
            len(eligible),
            ips=ips_display,
        ),
        shared_username,
    )
    new_username = new_username.strip() if success else ''
    if not new_username:
        if success:
            QMessageBox.warning(parent, TITLE, tr('No username was provided.'))
        return

    # Build mapping: db_path → list of (old_username, ip) pairs to rename
    by_db: dict[Path, list[tuple[str, str]]] = {}
    for ip, db_path, db_usernames in eligible:
        if db_path not in by_db:
            by_db[db_path] = []
        for old_u in db_usernames:
            by_db[db_path].append((old_u, ip))

    total_renamed = 0
    with userip_databases_lock():
        for db_path, pairs in by_db.items():
            total_renamed += rewrite_db_rename_entries(db_path, pairs, new_username, match_ip_ranges=True)
        if total_renamed:
            refresh_userip_and_wake_renderer()

    if not total_renamed:
        QMessageBox.information(
            parent,
            TITLE,
            tr_plural(
                'No entries were found for the selected IP.',
                'No entries were found for the selected IPs.',
                len(eligible),
            ),
        )
        return

    QMessageBox.information(
        parent,
        TITLE,
        tr_plural(
            'Renamed {count} entry to "{username}".',
            'Renamed {count} entries to "{username}".',
            total_renamed,
            username=new_username,
        ),
    )


def userip_rename(parent: QWidget, ip_address: str, player: Player) -> None:
    """Rename all entries for an IP address in its UserIP database using a picker dialog."""
    if player.userip is None or not player.userip.usernames:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)
    ip_usernames = collect_persisted_usernames_for_ip(db_path, ip_address)
    if not ip_usernames:
        QMessageBox.information(parent, TITLE, tr('No entries found for IP {ip} in the database.', ip=ip_address))
        return

    # Step 1: Determine which username to rename
    old_username: str | None
    if len(ip_usernames) == 1:
        old_username = ip_usernames[0]
    else:
        current_name = ', '.join(ip_usernames)
        dialog = SelectUsernamesDialog.for_rename(
            parent,
            ip_usernames,
            current_username=current_name,
            database=db_display,
            ip_address=ip_address,
        )
        old_username = dialog.selected_username() if dialog.exec() == SelectUsernamesDialog.DialogCode.Accepted else None
        if old_username is None or not old_username:
            return

    # Step 2: Prompt for the new username
    new_username, success = prompt_username_input(
        parent,
        tr('Rename Username'),
        tr(
            'Renaming "{username}" for IP {ip}.\nDatabase: {database}\n\nEnter the new username:',
            username=old_username,
            ip=ip_address,
            database=db_display,
        ),
        old_username,
    )
    new_username = new_username.strip() if success else ''
    if not new_username:
        if success:
            QMessageBox.warning(parent, TITLE, tr('No username was provided.'))
        return

    renamed_count = rewrite_db_rename_entries(db_path, [(old_username, ip_address)], new_username, match_ip_ranges=True)
    if not renamed_count:
        QMessageBox.information(parent, TITLE, tr('No entries found for IP {ip} in the database.', ip=ip_address))
        return

    refresh_userip_and_wake_renderer()
    QMessageBox.information(
        parent,
        TITLE,
        tr_plural(
            'Renamed {count} entry for IP {ip} to "{username}" in UserIP database "{database}".',
            'Renamed {count} entries for IP {ip} to "{username}" in UserIP database "{database}".',
            renamed_count,
            ip=ip_address,
            username=new_username,
            database=db_display,
        ),
    )


def _format_database_entries_html_list(entries_by_database: dict[Path, list[str]]) -> str:
    """Format a mapping of database paths to HTML-escaped entry strings as an HTML list."""
    sections: list[str] = []
    for db_path, entry_labels in entries_by_database.items():
        db_display = html.escape(format_userip_db_display_name(db_path))
        items_html = ''.join(f'<li>{entry_label}</li>' for entry_label in entry_labels)
        sections.append(f'<b>{db_display}:</b><br><ul>{items_html}</ul>')
    return '<br>'.join(sections)


def userip_move(parent: QWidget, selected_ips: list[str], selected_database: Path, *, group_keys_fn: Callable[[], frozenset[tuple[Path, str, str]]] | None = None) -> None:
    """Move the selected IP address(es) or account group entries to the chosen UserIP database."""
    with userip_databases_lock():
        group_keys = group_keys_fn() if group_keys_fn is not None else None
        result = move_userip_entries_to_database(
            selected_database,
            entry_keys=group_keys,
            covering_ips=None if group_keys is not None else selected_ips,
            extra_conflict_check_ips=selected_ips,
        )

    if result.moved_by_db:
        deleted_entries_by_database = {
            db_path: [f'{html.escape(entry.username)}={html.escape(entry.ip)}' for entry in entries]
            for db_path, entries in result.moved_by_db.items()
        }
        target_db_display = format_userip_db_display_name(selected_database)
        n_moved = result.total_moved
        if group_keys is not None:
            if len(deleted_entries_by_database) == 1:
                header_text = tr_plural(
                    'Account group ({count} entry) moved from the following UserIP database to UserIP database "{database}":',
                    'Account group ({count} entries) moved from the following UserIP database to UserIP database "{database}":',
                    n_moved,
                    database=target_db_display,
                )
            else:
                header_text = tr_plural(
                    'Account group ({count} entry) moved from the following UserIP databases to UserIP database "{database}":',
                    'Account group ({count} entries) moved from the following UserIP databases to UserIP database "{database}":',
                    n_moved,
                    database=target_db_display,
                )
        elif len(deleted_entries_by_database) == 1:
            header_text = tr_plural(
                'Selected IP moved from the following UserIP database to UserIP database "{database}":',
                'Selected IPs moved from the following UserIP database to UserIP database "{database}":',
                len(selected_ips),
                database=target_db_display,
            )
        else:
            header_text = tr_plural(
                'Selected IP moved from the following UserIP databases to UserIP database "{database}":',
                'Selected IPs moved from the following UserIP databases to UserIP database "{database}":',
                len(selected_ips),
                database=target_db_display,
            )
        header = f'<b>{html.escape(header_text)}</b><br><br><br>'
        _show_modal_info_on_top(parent, TITLE, header + _format_database_entries_html_list(deleted_entries_by_database))


def userip_delete(parent: QWidget, selected_ips: list[str]) -> None:
    """Remove the selected IP address(es) from all enabled UserIP databases."""
    deleted_entries_by_database: dict[Path, list[str]] = {}

    with userip_databases_lock():
        for db_path in UserIPDatabases.get_userip_database_filepaths():
            if not db_path.is_file():
                continue

            db_model = load_userip_database_model(db_path)
            if not db_model.entries:
                continue

            kept_entries: list[UserIPEntryModel] = []
            deleted_entries: list[UserIPEntryModel] = []

            for entry in db_model.entries:
                if _entry_ip_matches_any(entry.ip, selected_ips):
                    deleted_entries.append(entry)
                else:
                    kept_entries.append(entry)

            if deleted_entries:
                save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept_entries))
                deleted_entries_by_database[db_path] = [f'{html.escape(entry.username)}={html.escape(entry.ip)}' for entry in deleted_entries]

        if deleted_entries_by_database:
            refresh_userip_and_wake_renderer()

    if deleted_entries_by_database:
        if len(deleted_entries_by_database) == 1:
            header_text = tr_plural(
                'Selected IP removed from the following UserIP database:',
                'Selected IPs removed from the following UserIP database:',
                len(selected_ips),
            )
        else:
            header_text = tr_plural(
                'Selected IP removed from the following UserIP databases:',
                'Selected IPs removed from the following UserIP databases:',
                len(selected_ips),
            )
        header = f'<b>{html.escape(header_text)}</b><br><br><br>'
        QMessageBox.information(parent, TITLE, header + _format_database_entries_html_list(deleted_entries_by_database))


MIN_USERNAMES_FOR_REMOVAL = 2


def userip_remove_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Remove selected username(s) for an IP address from its UserIP database."""
    if player.userip is None or not player.userip.usernames:
        return

    db_path = player.userip.db_path
    ip_usernames = collect_persisted_usernames_for_ip(db_path, ip_address)

    if len(ip_usernames) < MIN_USERNAMES_FOR_REMOVAL:
        return

    db_display = format_userip_db_display_name(db_path)
    dialog = SelectUsernamesDialog.for_remove(parent, ip_usernames, database=db_display, ip_address=ip_address)
    if dialog.exec() != SelectUsernamesDialog.DialogCode.Accepted:
        return

    selected = dialog.selected_usernames()
    if not selected:
        return

    # If all usernames are selected, confirm and delegate to full IP deletion
    if dialog.is_all_selected():
        confirm = QMessageBox.question(
            parent,
            TITLE,
            tr('You selected all usernames for IP {ip}.\n\nThis will remove the IP entirely from the database. Continue?', ip=ip_address),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            userip_delete(parent, [ip_address])
        return

    _rewrite_database_removing_usernames(parent, db_path, ip_address, selected)


def _rewrite_database_removing_usernames(parent: QWidget, db_path: Path, ip_address: str, selected: list[str]) -> None:
    """Rewrite a UserIP database file, removing only the specified (username, ip) entries."""
    if not db_path.is_file():
        return
    usernames_to_remove_cf = {name.casefold() for name in selected}
    removed_count = 0
    with userip_databases_lock():
        db_model = load_userip_database_model(db_path)

        kept_entries: list[UserIPEntryModel] = []
        for entry in db_model.entries:
            if _entry_ip_matches_any(entry.ip, [ip_address]) and entry.username.casefold() in usernames_to_remove_cf:
                removed_count += 1
            else:
                kept_entries.append(entry)

        if removed_count:
            save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept_entries))
            refresh_userip_and_wake_renderer()

    if not removed_count:
        QMessageBox.information(parent, TITLE, tr('No matching entries found for IP {ip} in the database.', ip=ip_address))
        return

    db_display = format_userip_db_display_name(db_path)
    removed_names = ', '.join(f'"{name}"' for name in selected)
    QMessageBox.information(
        parent,
        TITLE,
        tr_plural(
            'Removed {count} entry ({usernames}) for IP {ip} from UserIP database "{database}".',
            'Removed {count} entries ({usernames}) for IP {ip} from UserIP database "{database}".',
            removed_count,
            usernames=removed_names,
            ip=ip_address,
            database=db_display,
        ),
    )
