"""UserIP database operations for the session table context menu."""

import html
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QWidget

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.select_usernames_dialog import SelectUsernamesDialog
from session_sniffer.guis.userip_manager_helpers import (
    IPRangeBuilderDialog,
    append_userip_entries,
    load_userip_database_model,
    rewrite_db_edit_entry_ip,
    rewrite_db_edit_ip_notes,
    rewrite_db_rename_entries,
    save_userip_database_model,
)
from session_sniffer.models.userip_settings_model import UserIPDatabaseFile, UserIPEntryModel, get_current_iso_timestamp
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_loader import update_userip_databases
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.settings import Settings
from session_sniffer.text_utils import pluralize, split_usernames
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from pathlib import Path

    from session_sniffer.models.player import Player


def _refresh_userip_and_wake_renderer() -> None:
    """Rebuild UserIP lookup structures immediately and wake the rendering loop."""
    update_userip_databases()
    wake_rendering_core()


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


def _remove_exact_ips_from_other_databases(selected_ips: list[str], target_database: Path) -> None:
    """Remove exact single-IP entries for `selected_ips` from enabled UserIP databases other than `target_database`."""
    selected_ip_set = set(selected_ips)
    for db_path in UserIPDatabases.get_userip_database_filepaths():
        if db_path == target_database or not db_path.is_file():
            continue
        db_model = load_userip_database_model(db_path)
        kept_entries = [entry for entry in db_model.entries if entry.ip not in selected_ip_set]
        if len(kept_entries) != len(db_model.entries):
            save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept_entries))


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
    player_names = dedup_preserve_order(
        [player.ps3_username] if player.ps3_username is not None and player.ps3_username else [],
        player.userip.usernames if player.userip else [],
        player.mod_menus.usernames if player.mod_menus else [],
        player.looky_system.usernames if player.looky_system.is_initialized else [],
        player.usernames,
    )
    names: list[str] = [name.strip() for name in player_names if name.strip()]
    if Settings.userip_sync_known_alts:
        return UserIPDatabases.expand_with_known_alts(names)
    return names


def resolve_usernames_for_ips(selected_ips: list[str]) -> list[str]:
    """Return deduplicated usernames associated with the given IP addresses from the player registry."""
    all_usernames: list[str] = []
    for ip_address in selected_ips:
        player = PlayersRegistry.get_player_by_ip(ip_address)
        if player is not None:
            all_usernames.extend(resolve_usernames_for_player(player))
    return dedup_preserve_order(all_usernames)


def _prompt_usernames_to_add(
    parent: QWidget,
    selected_ips: list[str],
    selected_database: Path,
    *,
    candidate_usernames: list[str] | None = None,
    prompt_message: str | None = None,
) -> list[str] | None:
    """Prompt the user for one or more usernames to associate with the selected IP(s).

    If exactly one username is found/provided, pre-fills the input dialog.
    If multiple usernames are found, shows a selection dialog to pick which one(s) to add.
    If no usernames are found, displays a standard blank input dialog.

    Returns a non-empty list of chosen usernames, or None if cancelled/empty.
    """
    candidates = (
        [name.strip() for name in dedup_preserve_order(candidate_usernames) if name.strip()] if candidate_usernames is not None else resolve_usernames_for_ips(selected_ips)
    )
    if Settings.userip_sync_known_alts:
        candidates = UserIPDatabases.expand_with_known_alts(candidates)

    db_display = str(selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))

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
            if Settings.userip_sync_known_alts:
                selected = UserIPDatabases.expand_with_known_alts(selected)
            return selected

        # User clicked 'Custom…' in the selection dialog
        selected_candidates = dialog.selected_usernames()
        initial_text = ', '.join(selected_candidates)
        usernames_count = len(selected_candidates) or 1
    elif len(candidates) == 1:
        initial_text = candidates[0]
        usernames_count = 1
    else:
        initial_text = ''
        usernames_count = 1

    if prompt_message is None:
        prompt_message = f'Please enter the username{pluralize(usernames_count)} to associate with the selected IP{pluralize(len(selected_ips))}:'

    entered_username, success = QInputDialog.getText(
        parent,
        'Input Username',
        prompt_message,
        QLineEdit.EchoMode.Normal,
        initial_text,
    )

    if not success:
        return None

    entered_usernames = dedup_preserve_order(split_usernames(entered_username))
    if not entered_usernames:
        QMessageBox.warning(parent, TITLE, 'ERROR:\nNo username was provided.')
        return None

    if Settings.userip_sync_known_alts:
        entered_usernames = UserIPDatabases.expand_with_known_alts(entered_usernames)

    return entered_usernames


def userip_add(
    parent: QWidget,
    selected_ips: list[str],
    selected_database: Path,
    *,
    usernames: list[str] | None = None,
) -> None:
    """Add the selected IP address(es) to the chosen UserIP database."""
    candidates = list(usernames) if usernames is not None else None
    chosen_usernames = _prompt_usernames_to_add(
        parent,
        selected_ips,
        selected_database,
        candidate_usernames=candidates,
    )
    if chosen_usernames is None or not chosen_usernames:
        return

    if Settings.userip_sync_known_alts:
        chosen_usernames = UserIPDatabases.expand_with_known_alts(chosen_usernames)

    _remove_exact_ips_from_other_databases(selected_ips, selected_database)

    existing_pairs: set[tuple[str, str]] = set()
    if selected_database.is_file():
        db_model = load_userip_database_model(selected_database)
        existing_pairs = {(entry.username.casefold(), entry.ip) for entry in db_model.entries}

    new_entries = [
        UserIPEntryModel(username=username, ip=ip_address, source='Session')
        for username in chosen_usernames
        for ip_address in selected_ips
        if (username.casefold(), ip_address) not in existing_pairs
    ]
    if new_entries:
        append_userip_entries(selected_database, new_entries)
    _refresh_userip_and_wake_renderer()

    db_display = selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    usernames_display = ', '.join(f'"{name}"' for name in chosen_usernames)
    _show_modal_info_on_top(
        parent,
        TITLE,
        (
            f'Selected IP{pluralize(len(selected_ips))} {list(selected_ips)} '
            f'ha{pluralize(len(selected_ips), singular="s", plural="ve")} been added with username{pluralize(len(chosen_usernames))} '
            f'{usernames_display} to UserIP database "{db_display}".'
        ),
    )


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
    prompt_message = f'Enter the username to associate with range "{range_input}":'
    chosen_usernames = _prompt_usernames_to_add(
        parent,
        [ip_address],
        selected_database,
        candidate_usernames=candidates,
        prompt_message=prompt_message,
    )
    if chosen_usernames is None or not chosen_usernames:
        return

    if Settings.userip_sync_known_alts:
        chosen_usernames = UserIPDatabases.expand_with_known_alts(chosen_usernames)

    append_userip_entries(
        selected_database,
        [UserIPEntryModel(username=username, ip=range_input, source='Session') for username in chosen_usernames],
    )
    _refresh_userip_and_wake_renderer()

    db_display = selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    usernames_display = ', '.join(f'"{name}"' for name in chosen_usernames)
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Range "{range_input}" has been added with username{pluralize(len(chosen_usernames))} {usernames_display} to UserIP database "{db_display}".',
    )


def userip_convert_to_range(parent: QWidget, ip_address: str, player: Player) -> None:
    """Convert a single-IP UserIP entry into a range entry in place, keeping its username(s).

    Useful when an IP that was tagged with a username later turns out to belong to a
    VPN/subnet: instead of deleting the entry and re-adding it as a range, every exact
    single-IP entry matching `ip_address` is rewritten to the range built via the dialog.
    """
    if player.userip is None or not player.userip.usernames:
        return

    db_path = player.userip.db_path
    db_display = player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

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

    _refresh_userip_and_wake_renderer()
    entry_word = pluralize(converted_count, 'entry', 'entries')
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Converted {converted_count} {entry_word} for IP {ip_address} to range "{range_input}" in UserIP database "{db_display}".',
    )


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
    db_display = player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

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

    _refresh_userip_and_wake_renderer()
    entry_word = pluralize(converted_count, 'entry', 'entries')
    _show_modal_info_on_top(
        parent,
        TITLE,
        f'Converted {converted_count} {entry_word} from range "{old_range}" to single IP {ip_address} in UserIP database "{db_display}".',
    )


def userip_edit_range(parent: QWidget, ip_address: str, player: Player) -> None:
    """Edit an existing range entry that covers `ip_address` in its UserIP database, keeping its username(s).

    The player's matched range is located by scanning its database for range entries that contain
    `ip_address`. When several distinct ranges cover the IP, the user picks which one to edit. Every
    entry whose value equals the chosen range is then rewritten to the new range built via the dialog.
    """
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

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

    _refresh_userip_and_wake_renderer()
    entry_word = pluralize(edited_count, 'entry', 'entries')
    QMessageBox.information(
        parent,
        TITLE,
        f'Updated {edited_count} {entry_word} from range "{old_range}" to "{new_range}" in UserIP database "{db_display}".',
    )


def userip_edit_note(parent: QWidget, ip_address: str, player: Player) -> None:
    """Edit the note associated with a known player's UserIP entry."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = str(db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
    current_note = ', '.join(player.userip.notes) if player.userip.notes else ''

    new_note, success = QInputDialog.getText(
        parent,
        'Edit Note',
        f'Editing note for IP {ip_address}.\nDatabase: {db_display}\n\nEnter the note (leave empty to clear):',
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

    _refresh_userip_and_wake_renderer()
    if new_note:
        QMessageBox.information(parent, TITLE, f'Updated note for IP {ip_address} in UserIP database "{db_display}".')
    else:
        QMessageBox.information(parent, TITLE, f'Cleared note for IP {ip_address} in UserIP database "{db_display}".')


def userip_add_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Add an additional username for an IP address that is already in a UserIP database."""
    if player.userip is None:
        return

    db_path = player.userip.db_path
    db_display = player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    existing = ', '.join(player.userip.usernames) if player.userip.usernames else 'None'
    candidates = [name for name in resolve_usernames_for_player(player) if name not in player.userip.usernames]
    prompt_message = f'Current username{pluralize(len(player.userip.usernames))} for {ip_address}: {existing}\n\nEnter the new username to add:'
    entered_usernames = _prompt_usernames_to_add(
        parent,
        [ip_address],
        db_path,
        candidate_usernames=candidates,
        prompt_message=prompt_message,
    )

    if entered_usernames is None or not entered_usernames:
        return

    if Settings.userip_sync_known_alts:
        entered_usernames = UserIPDatabases.expand_with_known_alts(entered_usernames)

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

    existing_note = ', '.join(player.userip.notes) if player.userip.notes else ''
    append_userip_entries(
        db_path,
        [UserIPEntryModel(username=username, ip=target_entry, notes=existing_note, source='Session') for username in entered_usernames],
    )
    _refresh_userip_and_wake_renderer()

    usernames_display = ', '.join(f'"{username}"' for username in entered_usernames)
    count = len(entered_usernames)
    has_or_have = pluralize(count, 'has', 'have')
    entry_label = f'IP {target_entry}' if target_entry == ip_address else f'range {target_entry}'
    QMessageBox.information(
        parent,
        TITLE,
        f'Username{pluralize(count)} {usernames_display} {has_or_have} been added for {entry_label} in UserIP database "{db_display}".',
    )


def userip_rename_multi(parent: QWidget, players: list[Player]) -> None:
    """Prompt once for a new username and apply it to all selected players' IP entries."""
    eligible = [(player.ip, player.userip) for player in players if player.userip is not None and player.userip.usernames]
    if not eligible:
        return

    ips_display = ', '.join(ip for ip, _ in eligible)

    # Pre-fill with the shared username if every selected player has exactly the same one
    all_username_sets = [frozenset(userip.usernames) for _, userip in eligible]
    shared_username = (
        next(iter(all_username_sets[0])) if len(all_username_sets[0]) == 1 and all(username_set == all_username_sets[0] for username_set in all_username_sets) else ''
    )

    new_username, success = QInputDialog.getText(
        parent,
        'Rename Selected',
        f'Enter a new username for {len(eligible)} selected IP{pluralize(len(eligible))}:\n{ips_display}',
        QLineEdit.EchoMode.Normal,
        shared_username,
    )
    new_username = new_username.strip() if success else ''
    if not new_username:
        if success:
            QMessageBox.warning(parent, TITLE, 'No username was provided.')
        return

    # Build mapping: db_path → list of (old_username, ip) pairs to rename
    by_db: dict[Path, list[tuple[str, str]]] = {}
    for ip, userip in eligible:
        if userip.db_path not in by_db:
            by_db[userip.db_path] = []
        for old_u in userip.usernames:
            by_db[userip.db_path].append((old_u, ip))

    total_renamed = 0
    for db_path, pairs in by_db.items():
        total_renamed += rewrite_db_rename_entries(db_path, pairs, new_username, match_ip_ranges=True)

    if not total_renamed:
        QMessageBox.information(parent, TITLE, f'No entries were found for the selected IP{pluralize(len(eligible))}.')
        return

    _refresh_userip_and_wake_renderer()
    entry_word = pluralize(total_renamed, 'entry', 'entries')
    QMessageBox.information(parent, TITLE, f'Renamed {total_renamed} {entry_word} to "{new_username}".')


def userip_rename(parent: QWidget, ip_address: str, player: Player) -> None:
    """Rename all entries for an IP address in its UserIP database using a picker dialog."""
    if player.userip is None or not player.userip.usernames:
        return

    db_path = player.userip.db_path
    db_display = str(db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
    ip_usernames = list(player.userip.usernames)

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
    new_username, success = QInputDialog.getText(
        parent,
        'Rename Username',
        f'Renaming "{old_username}" for IP {ip_address}.\nDatabase: {db_display}\n\nEnter the new username:',
        QLineEdit.EchoMode.Normal,
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

    _refresh_userip_and_wake_renderer()
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
        db_display = html.escape(str(db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')))
        items_html = ''.join(f'<li>{entry_label}</li>' for entry_label in entry_labels)
        sections.append(f'<b>{db_display}:</b><br><ul>{items_html}</ul>')
    return '<br>'.join(sections)


def userip_move(parent: QWidget, selected_ips: list[str], selected_database: Path) -> None:
    """Move the selected IP address(es) to the chosen UserIP database."""
    deleted_entries_by_database: dict[Path, list[str]] = {}
    now_iso = get_current_iso_timestamp()

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
            save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept_entries))
            append_userip_entries(selected_database, moved_entries)
            deleted_entries_by_database[db_path] = [f'{html.escape(entry.username)}={html.escape(entry.ip)}' for entry in moved_entries]

    if deleted_entries_by_database:
        _refresh_userip_and_wake_renderer()
        target_db_display = html.escape(str(selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')))
        header = (
            f'<b>Selected IP{pluralize(len(selected_ips))} {html.escape(str(selected_ips))} moved from the following '
            f'UserIP database{pluralize(len(deleted_entries_by_database))} to UserIP database '
            f'"{target_db_display}":</b><br><br><br>'
        )
        QMessageBox.information(parent, TITLE, header + _format_database_entries_html_list(deleted_entries_by_database))


def userip_delete(parent: QWidget, selected_ips: list[str]) -> None:
    """Remove the selected IP address(es) from all enabled UserIP databases."""
    deleted_entries_by_database: dict[Path, list[str]] = {}

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
        _refresh_userip_and_wake_renderer()
        header = (
            f'<b>Selected IP{pluralize(len(selected_ips))} {html.escape(str(selected_ips))} removed from the following '
            f'UserIP database{pluralize(len(deleted_entries_by_database))}:</b><br><br><br>'
        )
        QMessageBox.information(parent, TITLE, header + _format_database_entries_html_list(deleted_entries_by_database))


MIN_USERNAMES_FOR_REMOVAL = 2


def userip_remove_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Remove selected username(s) for an IP address from its UserIP database."""
    if player.userip is None or not player.userip.usernames:
        return

    ip_usernames = list(player.userip.usernames)

    if len(ip_usernames) < MIN_USERNAMES_FOR_REMOVAL:
        return

    db_path = player.userip.db_path
    db_display = str(db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
    dialog = SelectUsernamesDialog.for_remove(
        parent,
        ip_usernames,
        database=db_display,
        ip_address=ip_address,
    )
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
            f'You selected all usernames for IP {ip_address}.\n\nThis will remove the IP entirely from the database. Continue?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            userip_delete(parent, [ip_address])
        return

    _rewrite_database_removing_usernames(parent, db_path, ip_address, selected)


def _rewrite_database_removing_usernames(
    parent: QWidget,
    db_path: Path,
    ip_address: str,
    selected: list[str],
) -> None:
    """Rewrite a UserIP database file, removing only the specified (username, ip) entries."""
    if not db_path.is_file():
        return
    usernames_to_remove_cf = {name.casefold() for name in selected}
    db_model = load_userip_database_model(db_path)

    kept_entries: list[UserIPEntryModel] = []
    removed_count = 0
    for entry in db_model.entries:
        if _entry_ip_matches_any(entry.ip, [ip_address]) and entry.username.casefold() in usernames_to_remove_cf:
            removed_count += 1
        else:
            kept_entries.append(entry)

    if not removed_count:
        QMessageBox.information(parent, TITLE, f'No matching entries found for IP {ip_address} in the database.')
        return

    save_userip_database_model(db_path, UserIPDatabaseFile(settings=db_model.settings, entries=kept_entries))
    _refresh_userip_and_wake_renderer()

    db_display = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    entry_word = pluralize(removed_count, 'entry', 'entries')
    removed_names = ', '.join(f'"{name}"' for name in selected)
    QMessageBox.information(
        parent,
        TITLE,
        f'Removed {removed_count} {entry_word} ({removed_names}) for IP {ip_address} from UserIP database "{db_display}".',
    )
