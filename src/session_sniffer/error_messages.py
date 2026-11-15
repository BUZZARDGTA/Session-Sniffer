"""GUI dialog/message-box text formatting.

This module contains functions that build user-facing text intended ONLY for GUI dialogs/message boxes
(e.g., messages shown via the app's message box / dialog helpers).
"""

from typing import TYPE_CHECKING

from session_sniffer.constants.standalone import GITHUB_VERSIONS_URL, TITLE
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from session_sniffer.networking.interface import SelectedInterfaceRow
    from session_sniffer.player.userip import UserIPConflict


def format_type_error(
    obj: object,
    expected_types: type | tuple[type, ...],
) -> str:
    """Generate a formatted error message for a type mismatch.

    Args:
        obj: The object whose type is being checked.
        expected_types: The expected type(s) for the object.

    Returns:
        The formatted error message.
    """
    actual_type = type(obj).__name__

    if isinstance(expected_types, tuple):
        expected_types_names = ' | '.join(expected_type.__name__ for expected_type in expected_types)
        expected_type_count = len(expected_types)
    else:
        expected_types_names = expected_types.__name__
        expected_type_count = 1

    return f'Expected type{pluralize(expected_type_count)} {expected_types_names}, got {actual_type} instead.'


def ensure_instance[T](obj: object, expected_types: type[T] | tuple[type[T], ...]) -> T:
    """Ensure an object is an instance of the expected type.

    Args:
        obj: The object to validate.
        expected_types: The expected type(s) for `obj`.

    Returns:
        The same object, typed as `T`.

    Raises:
        TypeError: If `obj` is not an instance of `expected_types`.
    """
    if not isinstance(obj, expected_types):
        raise TypeError(format_type_error(obj, expected_types))
    return obj


def format_invalid_datetime_columns_settings_message() -> str:
    """Format the settings.json error shown when all datetime columns are disabled."""
    return tr(
        'ERROR in your custom "settings.json" file:\n\n'
        'At least one of these settings must be set to "true" value:\n'
        '<GUI_COLUMNS_DATETIME_SHOW_DATE>\n'
        '<GUI_COLUMNS_DATETIME_SHOW_TIME>\n'
        '<GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME>\n\n'
        'Default values will be applied to fix this issue.',
    )


def format_failed_check_for_updates_message(
    *,
    exception_name: str,
    http_code: str,
) -> str:
    """Format the retry/abort message shown when update checks fail."""
    return tr(
        'ERROR:\n'
        '    Failed to check for updates.\n\n'
        '    DEBUG:\n'
        '        Exception: {exception_name}\n'
        '        HTTP Code: {http_code}\n\n'
        'Please check your internet connection and ensure you have access to:\n'
        '{github_versions_url}\n\n'
        'Abort:\n'
        '    Exit and open the "{title}" GitHub page to\n'
        '    download the latest version.\n'
        'Retry:\n'
        '    Try checking for updates again.\n'
        'Ignore:\n'
        '    Continue using the current version (not recommended).',
        exception_name=exception_name,
        http_code=http_code,
        github_versions_url=GITHUB_VERSIONS_URL,
        title=TITLE,
    )


def format_geolite2_download_flags_failed_message(
    *,
    failed_flags: list[str],
    geolite2_release_api_url: str,
) -> str:
    """Format the message shown when one or more GeoLite2 assets have no version/download URL."""
    flags_str = "', '".join(failed_flags)
    flag_count = len(failed_flags)
    header = tr_plural(
        'ERROR:\n    Failed fetching MaxMind GeoLite2 "{flags_str}" database.',
        'ERROR:\n    Failed fetching MaxMind GeoLite2 "{flags_str}" databases.',
        flag_count,
        flags_str=flags_str,
    )
    footer = tr_plural(
        'This MaxMind GeoLite2 database will not be updated.',
        'These MaxMind GeoLite2 databases will not be updated.',
        flag_count,
    )
    return (
        f'{header}\n\n'
        f'DEBUG:\n'
        f'    GITHUB_RELEASE_API__GEOLITE2__URL={geolite2_release_api_url}\n'
        f'    failed_fetching_flag_list={failed_flags}\n\n'
        f'{footer}'
    )


def format_geolite2_update_initialize_error_message(
    *,
    update_exception: Exception | None,
    failed_url: str | None,
    http_code: int | str | None,
    initialize_exception: Exception | None,
) -> tuple[bool, str | None]:
    """Format the GeoLite2 initialization error summary.

    Returns:
        Tuple of (geoip2_enabled, message). If message is None, nothing should be shown.
    """
    show_error = False
    msgbox_message = ''

    if update_exception is not None:
        msgbox_message += tr('Exception Error: {error}', error=update_exception) + '\n\n'
        show_error = True

    if failed_url is not None:
        msgbox_message += tr('Error: Failed fetching url: "{url}".', url=failed_url)
        if http_code is not None:
            msgbox_message += ' ' + tr('(http_code: {http_code})', http_code=http_code)
        msgbox_message += '\n' + tr("Impossible to keep Maxmind's GeoLite2 IP to Country, City and ASN resolutions feature up-to-date.") + '\n\n'
        show_error = True

    if initialize_exception is not None:
        msgbox_message += tr('Exception Error: {error}', error=initialize_exception) + '\n\n'
        msgbox_message += tr("Now disabling MaxMind's GeoLite2 IP to Country, City and ASN resolutions feature.") + '\n'
        msgbox_message += tr("Country, City, and ASN columns won't show up in the players table.")
        geoip2_enabled = False
        show_error = True
    else:
        geoip2_enabled = True

    if not show_error:
        return geoip2_enabled, None

    return geoip2_enabled, msgbox_message.rstrip('\n')


def format_outdated_packages_message(
    *,
    app_title: str,
    outdated_packages: Sequence[tuple[str, object, str]],
) -> str:
    """Format the warning shown when project dependency specs and installed packages mismatch."""
    msgbox_message = tr('The following packages have version mismatches:') + '\n\n'

    for package_name, required_version, installed_version in outdated_packages:
        installed_display = tr('Not Installed') if installed_version == 'Not Installed' else installed_version
        msgbox_message += (
            tr(
                '{package_name} (required {required_version}, installed {installed_version})',
                package_name=package_name,
                required_version=required_version,
                installed_version=installed_display,
            )
            + '\n'
        )

    msgbox_message += '\n' + tr('Keeping your packages synced with "{app_title}" ensures smooth script execution and prevents compatibility issues.', app_title=app_title)
    msgbox_message += '\n\n' + tr('Do you want to ignore this warning and continue with script execution?')
    return msgbox_message


def format_userip_ip_conflict_message(
    *,
    conflicts: Sequence[UserIPConflict],
    userip_databases_dir: Path,
) -> tuple[str, str | None]:
    """Format the error shown when one or more IPs exist in multiple UserIP databases.

    Returns:
        A tuple of (summary_message, detailed_text). If detailed_text is None, no details section is needed.
    """
    count = len(conflicts)
    if count == 1:
        conflict = conflicts[0]
        db1_name = conflict.existing_userip.db_path.relative_to(userip_databases_dir).with_suffix('')
        db2_name = conflict.conflicting_database_path.relative_to(userip_databases_dir).with_suffix('')
        usernames1 = ', '.join(conflict.existing_userip.usernames)
        conflict_message = tr(
            'ERROR:\n'
            '    UserIP databases IP conflict\n\n'
            'INFOS:\n'
            '    The same IP cannot be assigned to multiple\n'
            '    databases.\n'
            '    Users assigned to this IP will be ignored until\n'
            '    the conflict is resolved.\n\n'
            'DEBUG:\n'
            '    "{db1_name}":\n'
            '    {usernames1}={ip1}\n\n'
            '    "{db2_name}":\n'
            '    {username2}={ip2}',
            db1_name=db1_name,
            usernames1=usernames1,
            ip1=conflict.existing_userip.ip,
            db2_name=db2_name,
            username2=conflict.conflicting_username,
            ip2=conflict.conflicting_ip,
        )
        return conflict_message, None

    preview_lines: list[str] = []
    preview_count = min(count, 5)
    for conflict in conflicts[:preview_count]:
        db1_name = conflict.existing_userip.db_path.relative_to(userip_databases_dir).with_suffix('')
        db2_name = conflict.conflicting_database_path.relative_to(userip_databases_dir).with_suffix('')
        usernames1 = ', '.join(conflict.existing_userip.usernames)
        preview_lines.append(
            f'    "{db1_name}" ({usernames1}={conflict.existing_userip.ip})\n'
            f'    "{db2_name}" ({conflict.conflicting_username}={conflict.conflicting_ip})',
        )

    preview_block = '\n\n'.join(preview_lines)
    remaining_count = count - preview_count
    remaining_suffix = (
        '\n\n    '
        + tr_plural(
            '... and {count} more conflict (see "Show Details...").',
            '... and {count} more conflicts (see "Show Details...").',
            remaining_count,
        )
        if remaining_count > 0
        else ''
    )

    summary = tr(
        'ERROR:\n'
        '    UserIP databases IP conflicts ({count} conflicts detected)\n\n'
        'INFOS:\n'
        '    The same IP cannot be assigned to multiple\n'
        '    databases.\n'
        '    Users assigned to conflicting IPs will be ignored until\n'
        '    conflicts are resolved.\n\n'
        'DEBUG:\n'
        '{preview_block}{remaining_suffix}',
        count=count,
        preview_block=preview_block,
        remaining_suffix=remaining_suffix,
    )

    detailed_lines: list[str] = []
    max_detailed = min(count, 1000)
    for i, conflict in enumerate(conflicts[:max_detailed], start=1):
        db1_name = conflict.existing_userip.db_path.relative_to(userip_databases_dir).with_suffix('')
        db2_name = conflict.conflicting_database_path.relative_to(userip_databases_dir).with_suffix('')
        usernames1 = ', '.join(conflict.existing_userip.usernames)
        ip_label = (
            conflict.existing_userip.ip
            if conflict.existing_userip.ip == conflict.conflicting_ip
            else f'{conflict.existing_userip.ip} vs {conflict.conflicting_ip}'
        )
        detailed_lines.append(
            f'[{i}] IP: {ip_label}\n'
            f'    "{db1_name}": {usernames1}\n'
            f'    "{db2_name}": {conflict.conflicting_username}\n',
        )
    if count > max_detailed:
        remaining_detailed_count = count - max_detailed
        detailed_lines.append(
            tr_plural(
                '... and {count} more conflict (see application logs).',
                '... and {count} more conflicts (see application logs).',
                remaining_detailed_count,
            )
            + '\n',
        )

    detailed_text = '\n'.join(detailed_lines)
    return summary, detailed_text


def format_arp_spoofing_failed_message(
    selected_interface: SelectedInterfaceRow,
    error_details: str | None,
) -> str:
    """Format an ARP spoofing failure message for display in a message box.

    Returns:
        A formatted error message string ready for display.
    """
    na_text = tr('N/A')
    interface_vendor_name = na_text if selected_interface.vendor_name is None else selected_interface.vendor_name
    gateway_ip = selected_interface.gateway_ip or na_text
    error_details_output = f'\n{error_details}' if bool(error_details) else ''

    return tr(
        'ARP Spoofing failed to start.\n\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        'INTERFACE DETAILS:\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        'Name: {name}\n'
        'Description: {description}\n'
        'Gateway IP: {gateway_ip}\n'
        'IP Address: {ip_address}\n'
        'MAC Address: {mac_address}\n'
        'Vendor Name: {vendor_name}\n\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        'DIAGNOSTICS:\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        'Error: {error_details}\n\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        'COMMON CAUSES:\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        '• Shared/bridged network adapter (most common)\n'
        '• Stale ARP table entry (target device at {ip_address} changed IP address)\n\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        'RECOMMENDATIONS:\n'
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        '• If adapter "{name}" is shared/bridged, disable ARP Spoofing in the Network Interface Selection screen and try again\n'
        '• If available, try sniffing target device {ip_address} on a different network adapter (e.g., Wi-Fi instead of Ethernet)',
        name=selected_interface.name,
        description=selected_interface.description,
        gateway_ip=gateway_ip,
        ip_address=selected_interface.ip_address,
        mac_address=selected_interface.mac_address,
        vendor_name=interface_vendor_name,
        error_details=error_details_output,
    )


def format_capture_interrupted_message() -> str:
    """Format the warning shown when packet capture exits unexpectedly."""
    return tr(
        'Packet capture has stopped unexpectedly.\n\n'
        'This is likely caused by your network adapter being removed or disabled.\n\n'
        'Please select a network interface to resume capture.',
    )


def format_npcap_adapter_binding_disabled_message(interface_name: str) -> str:
    """Format the warning shown when the Npcap driver binding is disabled on the selected adapter."""
    return tr(
        'Packet capture could not open network adapter "{interface_name}".\n\n'
        'The "Npcap Packet Driver (NPCAP)" binding is currently disabled on this network adapter in Windows.\n\n'
        'Enable "Npcap Packet Driver (NPCAP)" in the adapter properties for "{interface_name}" '
        '(or accept the administrator prompt when selecting the interface), or choose another network interface.',
        interface_name=interface_name,
    )


def format_npcap_required_message() -> str:
    """Format the initial NPCAP-required notification shown when Npcap is missing."""
    return tr('Session Sniffer requires the Npcap packet capture driver to monitor and analyze network traffic on Windows.')


def format_game_solo_session_process_not_running_message(game_name: str) -> str:
    """Format the warning shown when Solo Public Session is triggered but the game process is not running."""
    return tr('{game_name} is not currently running.\n\nPlease launch {game_name} before using this feature.', game_name=game_name)


def format_game_solo_session_suspend_failed_message(game_name: str) -> str:
    """Format the error shown when the game process suspend attempt fails."""
    return tr('Failed to suspend the {game_name} process.\n\nTry running Session Sniffer as administrator.', game_name=game_name)
