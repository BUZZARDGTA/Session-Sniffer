"""UserIP database operations for the session table context menu."""

import re
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QWidget

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog, RemoveUsernameDialog, RenameUsernameDialog
from session_sniffer.networking.ip_range import check_ip_against_ranges, parse_ip_range_entry
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import write_lines_to_file

if TYPE_CHECKING:
    from pathlib import Path

    from session_sniffer.models.player import Player

RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')


def _entry_ip_matches_any(entry_ip: str, selected_ips: list[str]) -> bool:
    """Return True if *entry_ip* exactly matches or is a range containing any IP in *selected_ips*."""
    if entry_ip in selected_ips:
        return True
    try:
        ranges = parse_ip_range_entry(entry_ip)
    except (ValueError, TypeError):
        return False
    return any(check_ip_against_ranges(sel_ip, ranges) is not None for sel_ip in selected_ips)


def userip_add(parent: QWidget, selected_ips: list[str], selected_database: Path) -> None:
    """Add the selected IP address(es) to the chosen UserIP database."""
    # Prompt the user for a username
    username, ok = QInputDialog.getText(parent, 'Input Username', f'Please enter the username to associate with the selected IP{pluralize(len(selected_ips))}:')

    if not ok:
        return

    username = username.strip()

    if username:  # Only proceed if the user clicked 'OK' and provided a username
        # Append the username and associated IP(s) to the corresponding database file
        write_lines_to_file(selected_database, 'a', [f'{username}={ip}\n' for ip in selected_ips])

        QMessageBox.information(
            parent, TITLE,
            (
                f'Selected IP{pluralize(len(selected_ips))} {list(selected_ips)} '
                f'ha{pluralize(len(selected_ips), singular="s", plural="ve")} been added with username "{username}" '
                f'to UserIP database "{selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}".'
            ),
        )
    else:
        # If the user canceled or left the input empty, show an error
        QMessageBox.warning(parent, TITLE, 'ERROR:\nNo username was provided.')


def userip_add_as_range(parent: QWidget, ip_address: str, selected_database: Path) -> None:
    """Add the selected IP address as a range entry to the chosen UserIP database."""
    range_dlg = IPRangeBuilderDialog(parent, initial_ip=ip_address)
    if range_dlg.exec() != IPRangeBuilderDialog.DialogCode.Accepted:
        return

    range_input = range_dlg.result_entry()

    username, ok = QInputDialog.getText(
        parent,
        'Input Username',
        f'Enter the username to associate with range "{range_input}":',
    )

    if not ok:
        return

    username = username.strip()

    if not username:
        QMessageBox.warning(parent, TITLE, 'ERROR:\nNo username was provided.')
        return

    write_lines_to_file(selected_database, 'a', [f'{username}={range_input}\n'])

    db_display = selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    QMessageBox.information(
        parent, TITLE,
        f'Range "{range_input}" has been added with username "{username}" to UserIP database "{db_display}".',
    )


def userip_add_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Add an additional username for an IP address that is already in a UserIP database."""
    if player.userip is None:
        return

    existing = ', '.join(player.userip.usernames) if player.userip.usernames else 'None'
    username, ok = QInputDialog.getText(
        parent, 'Add Username',
        f'Current username(s) for {ip_address}: {existing}\n\nEnter the new username to add:',
    )

    if not ok:
        return

    username = username.strip()

    if username:
        write_lines_to_file(player.userip.database_path, 'a', [f'{username}={ip_address}\n'])

        db_display = player.userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        QMessageBox.information(
            parent, TITLE,
            f'Username "{username}" has been added for IP {ip_address} in UserIP database "{db_display}".',
        )
    else:
        QMessageBox.warning(parent, TITLE, 'ERROR:\nNo username was provided.')


def userip_rename(parent: QWidget, ip_address: str, player: Player) -> None:
    """Rename all entries for an IP address in its UserIP database using a picker dialog."""
    if player.userip is None or not player.userip.usernames:
        return

    database_path = player.userip.database_path
    ip_usernames = list(player.userip.usernames)

    # Read the database content
    content = database_path.read_text('utf-8')

    # Step 1: Determine which username to rename
    old_username: str | None
    if len(ip_usernames) == 1:
        old_username = ip_usernames[0]
    else:
        current_name = ', '.join(ip_usernames)
        dialog = RenameUsernameDialog(parent, ip_usernames, current_name)
        old_username = dialog.selected_username() if dialog.exec() == RenameUsernameDialog.DialogCode.Accepted else None
        if not old_username:
            return

    # Step 2: Prompt for the new username
    db_display = database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    new_username, ok = QInputDialog.getText(
        parent, 'Rename Username',
        f'Renaming "{old_username}" for IP {ip_address}.\nDatabase: {db_display}\n\nEnter the new username:',
        QLineEdit.EchoMode.Normal,
        old_username,
    )
    new_username = new_username.strip() if ok else ''
    if not new_username:
        if ok:
            QMessageBox.warning(parent, TITLE, 'No username was provided.')
        return

    # Rewrite the database file, replacing only entries matching old_username + ip_address
    new_lines: list[str] = []
    renamed_count = 0
    in_userip_section = False
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.strip()
        if line.startswith('[') and line.endswith(']'):
            in_userip_section = line == '[UserIP]'
            new_lines.append(raw_line)
            continue
        if in_userip_section:
            match = RE_USERIP_INI_PARSER_PATTERN.search(line)
            if match:
                username_raw = match.group('username')
                ip_raw = match.group('ip')
                if (
                    username_raw is not None and ip_raw is not None
                    and username_raw.strip() == old_username and _entry_ip_matches_any(ip_raw.strip(), [ip_address])
                ):
                    ending = raw_line[len(raw_line.rstrip()):]
                    new_lines.append(f'{new_username}={ip_raw.strip()}{ending}')
                    renamed_count += 1
                    continue
        new_lines.append(raw_line)

    if not renamed_count:
        QMessageBox.information(parent, TITLE, f'No entries found for IP {ip_address} in the database.')
        return

    write_lines_to_file(database_path, 'w', new_lines)

    entry_word = 'entry' if renamed_count == 1 else 'entries'
    QMessageBox.information(
        parent, TITLE,
        f'Renamed {renamed_count} {entry_word} for IP {ip_address} to "{new_username}" in UserIP database "{db_display}".',
    )


def userip_move(parent: QWidget, selected_ips: list[str], selected_database: Path) -> None:
    """Move the selected IP address(es) to the chosen UserIP database."""
    # Dictionary to store removed entries by database
    deleted_entries_by_database: dict[Path, list[str]] = {}

    # Iterate over each UserIP database
    for database_path in UserIPDatabases.get_userip_database_filepaths():
        if database_path == selected_database:
            continue

        # Read the database file
        lines = database_path.read_text(encoding='utf-8').splitlines(keepends=True)
        if not lines:
            continue

        # List to store deleted entries in this particular database
        deleted_entries_in_this_database: list[str] = []

        # Remove any lines containing the IP address
        lines_to_keep: list[str] = []
        for line in lines:
            # Try to match the regex
            match = RE_USERIP_INI_PARSER_PATTERN.search(line)
            if match:
                # Extract username and ip using named groups
                username, ip = match.group('username', 'ip')

                # Only process if username and ip are strings
                if isinstance(username, str) and isinstance(ip, str):
                    # Ensure both username and ip are non-empty strings
                    username, ip = username.strip(), ip.strip()

                    # If IP is one of the selected ones, record it as deleted and exclude this line from lines_to_keep
                    if _entry_ip_matches_any(ip, selected_ips):
                        deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                        continue  # skip appending this line

            # All other lines should be kept
            lines_to_keep.append(line)

        if deleted_entries_in_this_database:
            # Only update the database file if there were any deletions
            write_lines_to_file(database_path, 'w', lines_to_keep)

            # Store the deleted entries for this database
            deleted_entries_by_database[database_path] = deleted_entries_in_this_database

            # Move the deleted entries to the target database
            write_lines_to_file(selected_database, 'a', [f'{entry}\n' for entry in deleted_entries_in_this_database])

    # After processing all databases, show a detailed report
    if deleted_entries_by_database:
        report = (
            f'<b>Selected IP{pluralize(len(selected_ips))} {selected_ips} moved from the following '
            f'UserIP database{pluralize(len(deleted_entries_by_database))} to UserIP database '
            f'"{selected_database.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}":</b><br><br><br>'
        )
        for database_path, deleted_entries in deleted_entries_by_database.items():
            report += f'<b>{database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}:</b><br>'
            report += '<ul>'
            for entry in deleted_entries:
                report += f'<li>{entry}</li>'
            report += '</ul><br>'
        report = report.removesuffix('<br>')

        QMessageBox.information(parent, TITLE, report)


def userip_delete(parent: QWidget, selected_ips: list[str]) -> None:
    """Remove the selected IP address(es) from all enabled UserIP databases."""
    # Dictionary to store removed entries by database
    deleted_entries_by_database: dict[Path, list[str]] = {}

    # Iterate over each UserIP database
    for database_path in UserIPDatabases.get_userip_database_filepaths():
        # Read the database file
        lines = database_path.read_text(encoding='utf-8').splitlines(keepends=True)
        if not lines:
            continue

        # List to store deleted entries in this particular database
        deleted_entries_in_this_database: list[str] = []

        # Remove any lines containing the IP address
        lines_to_keep: list[str] = []
        for line in lines:
            # Try to match the regex
            match = RE_USERIP_INI_PARSER_PATTERN.search(line)
            if match:
                # Extract username and ip using named groups
                username, ip = match.group('username', 'ip')

                # Only process if username and ip are strings
                if isinstance(username, str) and isinstance(ip, str):
                    # Ensure both username and ip are non-empty strings
                    username, ip = username.strip(), ip.strip()

                    # If IP is one of the selected ones, record it as deleted and exclude this line from lines_to_keep
                    if _entry_ip_matches_any(ip, selected_ips):
                        deleted_entries_in_this_database.append(line.strip())  # Store the deleted entry
                        continue  # skip appending this line

            # All other lines should be kept
            lines_to_keep.append(line)

        if deleted_entries_in_this_database:
            # Only update the database file if there were any deletions
            write_lines_to_file(database_path, 'w', lines_to_keep)

            # Store the deleted entries for this database
            deleted_entries_by_database[database_path] = deleted_entries_in_this_database

    # After processing all databases, show a detailed report
    if deleted_entries_by_database:
        report = (
            f'<b>Selected IP{pluralize(len(selected_ips))} {selected_ips} removed from the following '
            f'UserIP database{pluralize(len(deleted_entries_by_database))}:</b><br><br><br>'
        )
        for database_path, deleted_entries in deleted_entries_by_database.items():
            report += f'<b>{database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix("")}:</b><br>'
            report += '<ul>'
            for entry in deleted_entries:
                report += f'<li>{entry}</li>'
            report += '</ul><br>'
        report = report.removesuffix('<br>')

        QMessageBox.information(parent, TITLE, report)


MIN_USERNAMES_FOR_REMOVAL = 2


def userip_remove_username(parent: QWidget, ip_address: str, player: Player) -> None:
    """Remove selected username(s) for an IP address from its UserIP database."""
    if player.userip is None or not player.userip.usernames:
        return

    database_path = player.userip.database_path
    ip_usernames = list(player.userip.usernames)

    if len(ip_usernames) < MIN_USERNAMES_FOR_REMOVAL:
        return

    dialog = RemoveUsernameDialog(parent, ip_usernames, ip_address)
    if dialog.exec() != RemoveUsernameDialog.DialogCode.Accepted:
        return

    selected = dialog.selected_usernames()
    if not selected:
        return

    # If all usernames are selected, confirm and delegate to full IP deletion
    if dialog.is_all_selected():
        confirm = QMessageBox.question(
            parent, TITLE,
            f'You selected all usernames for IP {ip_address}.\n\n'
            f'This will remove the IP entirely from the database. Continue?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            userip_delete(parent, [ip_address])
        return

    _rewrite_database_removing_usernames(parent, database_path, ip_address, selected)


def _rewrite_database_removing_usernames(
    parent: QWidget, database_path: Path, ip_address: str, selected: list[str],
) -> None:
    """Rewrite a UserIP database file, removing only the specified (username, ip) entries."""
    usernames_to_remove = set(selected)

    content = database_path.read_text('utf-8')

    new_lines: list[str] = []
    removed_count = 0
    in_userip_section = False
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.strip()
        if line.startswith('[') and line.endswith(']'):
            in_userip_section = line == '[UserIP]'
            new_lines.append(raw_line)
            continue
        if in_userip_section:
            match = RE_USERIP_INI_PARSER_PATTERN.search(line)
            if match:
                username_raw = match.group('username')
                ip_raw = match.group('ip')
                if (
                    username_raw is not None and ip_raw is not None
                    and username_raw.strip() in usernames_to_remove and _entry_ip_matches_any(ip_raw.strip(), [ip_address])
                ):
                    removed_count += 1
                    continue
        new_lines.append(raw_line)

    if not removed_count:
        QMessageBox.information(parent, TITLE, f'No matching entries found for IP {ip_address} in the database.')
        return

    write_lines_to_file(database_path, 'w', new_lines)

    db_display = database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    entry_word = 'entry' if removed_count == 1 else 'entries'
    removed_names = ', '.join(f'"{name}"' for name in selected)
    QMessageBox.information(
        parent, TITLE,
        f'Removed {removed_count} {entry_word} ({removed_names}) for IP {ip_address} '
        f'from UserIP database "{db_display}".',
    )
