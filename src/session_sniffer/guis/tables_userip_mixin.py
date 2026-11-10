"""UserIP database operations for the session table context menu."""

import html
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QWidget

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.select_usernames_dialog import SelectUsernamesDialog, UsernameSelectionConfig, prompt_username_input, prompt_usernames_and_notes_input
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import sync_player_looky_usernames_and_userip
from session_sniffer.guis.userip_manager_helpers import (
    IPRangeBuilderDialog,
    append_userip_entries,
    format_userip_db_display_name,
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    rewrite_db_edit_entry_ip,
    rewrite_db_edit_ip_notes,
    rewrite_db_rename_entries,
    save_userip_database_model,
)
from session_sniffer.models.userip_settings_model import UserIPDatabaseFile, UserIPEntryModel, get_current_iso_timestamp
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.player.userip import UserIPDatabases
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
from session_sniffer.player.userip_loader import userip_databases_lock
from session_sniffer.rendering_core.types import CaptureState, SessionFilterState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import pluralize
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


def resolve_usernames_for_player(player: Player) -> list[str]:
    """Return deduplicated usernames associated with the given player from all sources."""
    include_looky = Settings.looky_enabled and Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
    live_names = player.get_live_non_userip_usernames(include_looky=include_looky)
    player_names = dedup_preserve_order(live_names[:1] if bool(player.ps3_username) else (), player.userip.usernames if player.userip else (), live_names, player.usernames)
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
            return f'Please enter the username{pluralize(count)} to associate with the selected IP{pluralize(len(selected_ips))}:'

        prompt_message = _default_prompt

    entered_usernames, entered_notes, success = prompt_usernames_and_notes_input(
        parent,
        'Input Username(s)',
        prompt_message,
        initial_usernames,
        initial_notes,
    )

    if not success:
        return None

    if not entered_usernames:
        QMessageBox.warning(parent, TITLE, 'ERROR:\nNo username was provided.')
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
                group_usernames(chosen_usernames, UserIPDatabases.get_known_alts_clusters_snapshot())
        refresh_userip_and_wake_renderer()

    db_display = format_userip_db_display_name(selected_database)
    usernames_display = ', '.join(f'"{name}"' for name in chosen_usernames)
    _show_modal_info_on_top(
        parent,
        TITLE,
        (
            f'Selected IP{pluralize(len(selected_ips))} {", ".join(selected_ips)} '
            f'ha{pluralize(len(selected_ips), singular="s", plural="ve")} been added with username{pluralize(len(chosen_usernames))} '
            f'{usernames_display} to UserIP database "{db_display}".'
        ),
    )
    UserIPDatabases.renotify_if_conflicting(selected_ips)


def userip_add_as_range(
    parent: QWidget,
    ip_address: str,
    selected_database: Path,
    *,
    usernames: list[str] | None = None,
) -> None:
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
        prompt_message=lambda count: f'Enter the username{pluralize(count)} to associate with range "{range_input}":',
    )
    if prompt_result is None:
        return
    chosen_usernames, notes_by_username = prompt_result
    if not chosen_usernames:
        return

    append_userip_entries(selected_database, [UserIPEntryModel(username=u, ip=range_input, notes=notes_by_username.get(u, '')) for u in chosen_usernames])
    if len(chosen_usernames) >= MIN_GROUP_USERNAMES:
        group_usernames(chosen_usernames, UserIPDatabases.get_known_alts_clusters_snapshot())
    refresh_userip_and_wake_renderer()

    db_display = format_userip_db_display_name(selected_database)
    usernames_display = ', '.join(f'"{name}"' for name in chosen_usernames)
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Range "{range_input}" has been added with username{pluralize(len(chosen_usernames))} {usernames_display} to UserIP database "{db_display}".',
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
        QMessageBox.information(parent, TITLE, f'No single-IP entries found for IP {ip_address} in the database.')
        return

    refresh_userip_and_wake_renderer()
    entry_word = pluralize(converted_count, 'entry', 'entries')
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Converted {converted_count} {entry_word} for IP {ip_address} to range "{range_input}" in UserIP database "{db_display}".',
    )
    UserIPDatabases.renotify_if_conflicting([range_input])


def _select_covering_range_in_db(
    parent: QWidget,
    db_path: Path,
    ip_address: str,
    *,
    dialog_title: str,
    prompt_action: str,
) -> str | None:
    """Return the single range covering `ip_address` in `db_path`, or prompt the user when multiple ranges match."""
    matching_ranges = _collect_matching_entries_in_db(db_path, ip_address, ranges_only=True)
    if not matching_ranges:
        QMessageBox.information(parent, TITLE, f'No range entries found covering IP {ip_address} in the database.')
        return None
    if len(matching_ranges) == 1:
        return matching_ranges[0]
    chosen, success = QInputDialog.getItem(
        parent,
        dialog_title,
        f'Multiple ranges cover IP {ip_address}.\nSelect the range to {prompt_action}:',
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
        dialog_title='Convert to IP',
        prompt_action=f'convert to single IP {ip_address}',
    )
    if old_range is None:
        return

    converted_count = rewrite_db_edit_entry_ip(db_path, old_range, ip_address)
    if not converted_count:
        QMessageBox.information(parent, TITLE, f'No entries found for range "{old_range}" in the database.')
        return

    refresh_userip_and_wake_renderer()
    entry_word = pluralize(converted_count, 'entry', 'entries')
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Converted {converted_count} {entry_word} from range "{old_range}" to single IP {ip_address} in UserIP database "{db_display}".',
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
        dialog_title='Edit Range',
        prompt_action='edit',
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
        QMessageBox.information(parent, TITLE, f'No entries found for range "{old_range}" in the database.')
        return

    refresh_userip_and_wake_renderer()
    entry_word = pluralize(edited_count, 'entry', 'entries')
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Updated {edited_count} {entry_word} from range "{old_range}" to "{new_range}" in UserIP database "{db_display}".',
    )
    UserIPDatabases.renotify_if_conflicting([new_range])


def userip_edit_note(parent: QWidget, ip_address: str, player: Player) -> None:
    """Edit the note associated with a known player's UserIP entry."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)
    current_note = ', '.join(player.userip.notes) if player.userip.notes else ''

    dialog_title = 'Edit Note' if current_note else 'Add Note'
    new_note, success = QInputDialog.getText(
        parent,
        dialog_title,
        f'Note for IP {ip_address}.\nDatabase: {db_display}\n\nEnter the note (leave empty to clear):',
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
        QMessageBox.information(parent, TITLE, f'No entries found covering IP {ip_address} in the database.')
        return

    refresh_userip_and_wake_renderer()
    if new_note:
        QMessageBox.information(parent, TITLE, f'Updated note for IP {ip_address} in UserIP database "{db_display}".')
    else:
        QMessageBox.information(parent, TITLE, f'Cleared note for IP {ip_address} in UserIP database "{db_display}".')


def userip_add_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Add an additional username for an IP address that is already in a UserIP database."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)
    existing_count = len(player.userip.usernames)
    existing = ', '.join(player.userip.usernames) if player.userip.usernames else 'None'
    candidates = [name for name in resolve_usernames_for_player(player) if name not in player.userip.usernames]
    prompt_result = _prompt_usernames_to_add(
        parent,
        [ip_address],
        db_path,
        candidate_usernames=candidates,
        prompt_message=lambda count: f'Current username{pluralize(existing_count)} for {ip_address}: {existing}\n\nEnter the new username{pluralize(count)} to add:',
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
            'Select Target Entry',
            f'Multiple UserIP entries match {ip_address}.\nSelect which entry to add the username to:',
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
        group_usernames([*linked_existing, *entered_usernames], UserIPDatabases.get_known_alts_clusters_snapshot())
    refresh_userip_and_wake_renderer()

    usernames_display = ', '.join(f'"{username}"' for username in entered_usernames)
    count = len(entered_usernames)
    has_or_have = pluralize(count, 'has', 'have')
    entry_label = f'IP {target_entry}' if target_entry == ip_address else f'range {target_entry}'
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Username{pluralize(count)} {usernames_display} {has_or_have} been added for {entry_label} in UserIP database "{db_display}".',
    )
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
        'Rename Selected',
        f'Enter a new username for {len(eligible)} selected IP{pluralize(len(eligible))}:\n{ips_display}',
        shared_username,
    )
    new_username = new_username.strip() if success else ''
    if not new_username:
        if success:
            QMessageBox.warning(parent, TITLE, 'No username was provided.')
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
        QMessageBox.information(parent, TITLE, f'No entries were found for the selected IP{pluralize(len(eligible))}.')
        return

    entry_word = pluralize(total_renamed, 'entry', 'entries')
    QMessageBox.information(parent, TITLE, f'Renamed {total_renamed} {entry_word} to "{new_username}".')


def userip_rename(parent: QWidget, ip_address: str, player: Player) -> None:
    """Rename all entries for an IP address in its UserIP database using a picker dialog."""
    if player.userip is None or not player.userip.usernames:
        return

    db_path = player.userip.db_path
    db_display = format_userip_db_display_name(db_path)
    ip_usernames = collect_persisted_usernames_for_ip(db_path, ip_address)
    if not ip_usernames:
        QMessageBox.information(parent, TITLE, f'No entries found for IP {ip_address} in the database.')
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
        'Rename Username',
        f'Renaming "{old_username}" for IP {ip_address}.\nDatabase: {db_display}\n\nEnter the new username:',
        old_username,
    )
    new_username = new_username.strip() if success else ''
    if not new_username:
        if success:
            QMessageBox.warning(parent, TITLE, 'No username was provided.')
        return

    renamed_count = rewrite_db_rename_entries(db_path, [(old_username, ip_address)], new_username, match_ip_ranges=True)
    if not renamed_count:
        QMessageBox.information(parent, TITLE, f'No entries found for IP {ip_address} in the database.')
        return

    refresh_userip_and_wake_renderer()
    entry_word = pluralize(renamed_count, 'entry', 'entries')
    QMessageBox.information(
        parent,
        TITLE,
        f'Renamed {renamed_count} {entry_word} for IP {ip_address} to "{new_username}" in UserIP database "{db_display}".',
    )


def _format_database_entries_html_list(entries_by_database: dict[Path, list[str]]) -> str:
    """Format a mapping of database paths to HTML-escaped entry strings as an HTML list."""
    sections: list[str] = []
    for db_path, entry_labels in entries_by_database.items():
        db_display = html.escape(format_userip_db_display_name(db_path))
        items_html = ''.join(f'<li>{entry_label}</li>' for entry_label in entry_labels)
        sections.append(f'<b>{db_display}:</b><br><ul>{items_html}</ul>')
    return '<br>'.join(sections)


def userip_move(parent: QWidget, selected_ips: list[str], selected_database: Path) -> None:
    """Move the selected IP address(es) to the chosen UserIP database."""
    deleted_entries_by_database: dict[Path, list[str]] = {}
    moved_entry_ips: list[str] = []
    now_iso = get_current_iso_timestamp()

    with userip_databases_lock():
        for db_path in UserIPDatabases.get_userip_database_filepaths():
            if db_path == selected_database or not db_path.is_file():
                continue

            db_model = load_userip_database_model(db_path)
            if not db_model.entries:
                continue

            kept_entries: list[UserIPEntryModel] = []
            moved_entries: list[UserIPEntryModel] = []

            for entry in db_model.entries:
                if _entry_ip_matches_any(entry.ip, selected_ips):
                    moved_entries.append(entry.model_copy(update={'updated_at': now_iso}))
                else:
                    kept_entries.append(entry)

            if moved_entries:
                append_userip_entries(selected_database, moved_entries)
                save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept_entries))
                moved_entry_ips.extend(entry.ip for entry in moved_entries)
                deleted_entries_by_database[db_path] = [f'{html.escape(entry.username)}={html.escape(entry.ip)}' for entry in moved_entries]

        if deleted_entries_by_database:
            refresh_userip_and_wake_renderer()

    if deleted_entries_by_database:
        target_db_display = html.escape(format_userip_db_display_name(selected_database))
        header = (
            f'<b>Selected IP{pluralize(len(selected_ips))} moved from the following '
            f'UserIP database{pluralize(len(deleted_entries_by_database))} to UserIP database '
            f'"{target_db_display}":</b><br><br><br>'
        )
        _show_modal_info_on_top(parent, TITLE, header + _format_database_entries_html_list(deleted_entries_by_database))
        UserIPDatabases.renotify_if_conflicting([*selected_ips, *moved_entry_ips])


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
        header = f'<b>Selected IP{pluralize(len(selected_ips))} removed from the following UserIP database{pluralize(len(deleted_entries_by_database))}:</b><br><br><br>'
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
            parent, TITLE, f'You selected all usernames for IP {ip_address}.\n\nThis will remove the IP entirely from the database. Continue?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
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
        QMessageBox.information(parent, TITLE, f'No matching entries found for IP {ip_address} in the database.')
        return

    db_display = format_userip_db_display_name(db_path)
    entry_word = pluralize(removed_count, 'entry', 'entries')
    removed_names = ', '.join(f'"{name}"' for name in selected)
    QMessageBox.information(parent, TITLE, f'Removed {removed_count} {entry_word} ({removed_names}) for IP {ip_address} from UserIP database "{db_display}".')


_MAX_GROUP_PROMPT_NAMES = 3


def _format_group_source_display(names: Sequence[str]) -> str:
    """Format up to `_MAX_GROUP_PROMPT_NAMES` usernames for the Group With dialog prompt."""
    preview = ', '.join(names[:_MAX_GROUP_PROMPT_NAMES])
    extra = len(names) - _MAX_GROUP_PROMPT_NAMES
    return f'{preview} (+{extra} more)' if extra > 0 else preview


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


def collect_grouped_usernames_for_player(player: Player) -> list[str]:
    """Return all usernames currently grouped with *player* (via known-alts clusters or shared UserIP entries)."""
    base_names: list[str] = []
    filtered_userip = UserIPDatabases.filter_userip_for_player(player, player.userip)
    if filtered_userip is not None:
        anchor_names = list(filtered_userip.usernames)
        persisted_names = [
            u
            for u in collect_persisted_usernames_for_ip(filtered_userip.db_path, player.ip)
            if u.casefold() not in player.detached_userip_usernames_cf and not any(are_usernames_unlinked(u, anchor) for anchor in anchor_names)
        ]
        base_names.extend(anchor_names)
        base_names.extend(persisted_names)
    else:
        base_names.extend(u for u in resolve_usernames_for_player(player) if u.casefold() not in player.detached_userip_usernames_cf)
    candidates = [u for u in UserIPDatabases.expand_with_known_alts(dedup_preserve_order(base_names)) if u.casefold() not in player.detached_userip_usernames_cf]
    if len(candidates) <= 1:
        return candidates
    return [u for u in candidates if any(u.casefold() != v.casefold() and not are_usernames_unlinked(u, v) for v in candidates)]


def prompt_and_group_with(parent: QWidget, source_usernames: Sequence[str]) -> tuple[str, str] | None:
    """Prompt the user for a username to group with `source_usernames`, persist the group, and refresh UserIP."""
    if not source_usernames:
        return None
    source_display = _format_group_source_display(source_usernames)
    target_username, ok = prompt_username_input(parent, f'Group With - {TITLE}', f'Enter the username to group with "{source_display}":')
    if not ok or not target_username.strip():
        return None
    target_clean = target_username.strip()
    combined = dedup_preserve_order(source_usernames, [target_clean])
    if len(combined) < MIN_GROUP_USERNAMES:
        QMessageBox.information(parent, TITLE, 'Please enter a different username to group with.')
        return None
    if group_usernames(combined, UserIPDatabases.get_known_alts_clusters_snapshot()):
        refresh_userip_and_wake_renderer()
        return target_clean, source_display
    return None


def prompt_and_ungroup(parent: QWidget, group_members: list[str], *, selected_ips: list[str] | None = None) -> list[str]:
    """Open the Ungroup Usernames dialog for `group_members`, persist the ungrouping, and refresh UserIP."""
    if len(group_members) < MIN_GROUP_USERNAMES:
        return []
    dlg = SelectUsernamesDialog(
        parent, group_members,
        UsernameSelectionConfig(
            title='Ungroup Usernames', instructions='Select username(s) to unlink from this account group (prevents false-positive grouping):',
            action_button_text='Ungroup', multiple=True, default_checked=False, selected_ips=selected_ips,
        ),
    )
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
        typed_source, ok_source = prompt_username_input(parent, f'Group With - {TITLE}', 'Enter the username for the selected player:')
        if not ok_source or not typed_source.strip():
            return
        source_usernames = [typed_source.strip()]

    if result := prompt_and_group_with(parent, source_usernames):
        target_clean, source_display = result
        grouped_cfs = {u.casefold() for u in (*source_usernames, target_clean)}
        for player in players:
            _update_detached_usernames_for_player(player, grouped_cfs, detach=False)
        refresh_userip_and_wake_renderer()
        QMessageBox.information(parent, TITLE, f'Grouped username "{target_clean}" with {source_display}.')


def userip_group_selected(parent: QWidget, players: Sequence[Player]) -> None:
    """Group all usernames across the selected players together."""
    usernames = dedup_preserve_order(
        *((player.userip.usernames if player.userip is not None and player.userip.usernames else resolve_usernames_for_player(player)) for player in players),
    )
    if len(usernames) < MIN_GROUP_USERNAMES:
        QMessageBox.information(parent, TITLE, 'Select at least two players with distinct usernames to group them together.')
        return

    grouped_cfs = {u.casefold() for u in usernames}
    for player in players:
        _update_detached_usernames_for_player(player, grouped_cfs, detach=False)
    if group_usernames(usernames, UserIPDatabases.get_known_alts_clusters_snapshot()):
        refresh_userip_and_wake_renderer()
        names_display = ', '.join(f'"{name}"' for name in usernames)
        QMessageBox.information(parent, TITLE, f'Grouped {len(usernames)} usernames together: {names_display}.')


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
        QMessageBox.information(parent, TITLE, f'Ungrouped {removed_display} from the account group.')


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
        parent, active_looky_names,
        UsernameSelectionConfig(
            title='Remove Looky Usernames', instructions=f'Select Looky username{pluralize(len(active_looky_names))} to hide on this IP:',
            action_button_text='Remove', multiple=True, default_checked=False, selected_ips=[player.ip],
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
        parent, removed_looky_names,
        UsernameSelectionConfig(
            title='Restore Removed Looky Usernames', instructions=f'Select removed Looky username{pluralize(len(removed_looky_names))} to re-add on this IP:',
            action_button_text='Restore', multiple=True, default_checked=True, selected_ips=[player.ip],
        ),
    )
    if dlg.exec() == SelectUsernamesDialog.DialogCode.Accepted:
        chosen = dlg.selected_usernames()
        if chosen and restore_looky_usernames(player.ip, chosen):
            _refresh_player_looky_exclusions(player, reset_userip_checked=True)
