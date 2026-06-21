"""GUI dialog/message-box text formatting.

This module contains functions that build user-facing text intended ONLY for GUI dialogs/message boxes
(e.g., messages shown via the app's message box / dialog helpers).
"""

from typing import TYPE_CHECKING

from session_sniffer.constants.standalone import GITHUB_VERSIONS_URL, TITLE
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from session_sniffer.networking.interface import SelectedInterfaceRow
    from session_sniffer.player.userip import UserIP


def format_type_error(
    obj: object,
    expected_types: type | tuple[type, ...],
    suffix: str = '',
) -> str:
    """Generate a formatted error message for a type mismatch.

    Args:
        obj: The object whose type is being checked.
        expected_types: The expected type(s) for the object.
        suffix: An optional suffix to append to the error message.

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

    plural_suffix = '' if expected_type_count == 1 else 's'
    return f'Expected type{plural_suffix} {expected_types_names}, got {actual_type} instead.{suffix}'


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
    return obj  # type: ignore[return-value]


def format_invalid_datetime_columns_settings_message() -> str:
    """Format the Settings.ini error shown when all datetime columns are disabled."""
    return """
        ERROR in your custom "Settings.ini" file:

        At least one of these settings must be set to "True" value:
        <GUI_COLUMNS_DATETIME_SHOW_DATE>
        <GUI_COLUMNS_DATETIME_SHOW_TIME>
        <GUI_COLUMNS_DATETIME_SHOW_ELAPSED_TIME>

        Default values will be applied to fix this issue.
    """


def format_failed_check_for_updates_message(
    *,
    exception_name: str,
    http_code: str,
) -> str:
    """Format the retry/abort message shown when update checks fail."""
    return f"""
        ERROR:
            Failed to check for updates.

            DEBUG:
                Exception: {exception_name}
                HTTP Code: {http_code}

        Please check your internet connection and ensure you have access to:
        {GITHUB_VERSIONS_URL}

        Abort:
            Exit and open the "{TITLE}" GitHub page to
            download the latest version.
        Retry:
            Try checking for updates again.
        Ignore:
            Continue using the current version (not recommended).
    """


def format_geolite2_download_flags_failed_message(
    *,
    failed_flags: list[str],
    geolite2_release_api_url: str,
) -> str:
    """Format the message shown when one or more GeoLite2 assets have no version/download URL."""
    flags_str = "', '".join(failed_flags)
    return f"""
        ERROR:
            Failed fetching MaxMind GeoLite2 "{flags_str}" database{pluralize(len(failed_flags))}.

        DEBUG:
            GITHUB_RELEASE_API__GEOLITE2__URL={geolite2_release_api_url}
            failed_fetching_flag_list={failed_flags}

        These MaxMind GeoLite2 database{pluralize(len(failed_flags))} will not be updated.
    """


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
        msgbox_message += f'Exception Error: {update_exception}\n\n'
        show_error = True

    if failed_url is not None:
        msgbox_message += f'Error: Failed fetching url: "{failed_url}".'
        if http_code is not None:
            msgbox_message += f' (http_code: {http_code})'
        msgbox_message += "\nImpossible to keep Maxmind's GeoLite2 IP to Country, City and ASN resolutions feature up-to-date.\n\n"
        show_error = True

    if initialize_exception is not None:
        msgbox_message += f'Exception Error: {initialize_exception}\n\n'
        msgbox_message += "Now disabling MaxMind's GeoLite2 IP to Country, City and ASN resolutions feature.\n"
        msgbox_message += "Countrys, Citys and ASN from players won't shows up from the players columns."
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
    msgbox_message = 'The following packages have version mismatches:\n\n'

    for package_name, required_version, installed_version in outdated_packages:
        msgbox_message += f'{package_name} (required {required_version}, installed {installed_version})\n'

    msgbox_message += f'\nKeeping your packages synced with "{app_title}" ensures smooth script execution and prevents compatibility issues.'
    msgbox_message += '\n\nDo you want to ignore this warning and continue with script execution?'
    return msgbox_message


def format_userip_ip_conflict_message(
    *,
    existing_userip: UserIP,
    conflicting_database_path: Path,
    conflicting_username: str,
    userip_databases_dir: Path,
) -> str:
    """Format the error shown when the same IP exists in multiple UserIP databases."""
    return f"""
        ERROR:
            UserIP databases IP conflict

        INFOS:
            The same IP cannot be assigned to multiple
            databases.
            Users assigned to this IP will be ignored until
            the conflict is resolved.

        DEBUG:
            "{existing_userip.db_path.relative_to(userip_databases_dir).with_suffix('')}":
            {', '.join(existing_userip.usernames)}={existing_userip.ip}

            "{conflicting_database_path.relative_to(userip_databases_dir).with_suffix('')}":
            {conflicting_username}={existing_userip.ip}
    """


def format_arp_spoofing_failed_message(
    selected_interface: SelectedInterfaceRow,
    exit_code: int | None,
    error_details: str | None,
) -> str:
    """Format an ARP spoofing failure message for display in a message box.

    Returns:
        A formatted error message string ready for display.
    """
    interface_vendor_name = 'N/A' if selected_interface.vendor_name is None else selected_interface.vendor_name
    exit_code_output = f'{exit_code}' if exit_code is not None else ''
    error_details_output = f'\n{error_details}' if error_details else ''

    return (
        f'ARP Spoofing failed to start.\n\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'INTERFACE DETAILS:\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'Name: {selected_interface.name}\n'
        f'Description: {selected_interface.description}\n'
        f'Gateway IP: {selected_interface.gateway_ip or "N/A"}\n'
        f'IP Address: {selected_interface.ip_address}\n'
        f'MAC Address: {selected_interface.mac_address}\n'
        f'Vendor Name: {interface_vendor_name}\n\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'DIAGNOSTICS:\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'Exit code: {exit_code_output}\n'
        f'Error output: {error_details_output}\n\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'COMMON CAUSES:\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'• Shared/bridged network adapter (most common)\n'
        f'• Stale ARP table entry (target device at {selected_interface.ip_address} changed IP address)\n\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'RECOMMENDATIONS:\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'• If adapter "{selected_interface.name}" is shared/bridged, disable ARP Spoofing in the Network Interface Selection screen and try again\n'
        f'• If available, try sniffing target device {selected_interface.ip_address} on a different network adapter (e.g., Wi-Fi instead of Ethernet)'
    )


def format_capture_interrupted_message() -> str:
    """Format the warning shown when packet capture exits unexpectedly."""
    return (
        'Packet capture has stopped unexpectedly.\n\n'
        'This is likely caused by your network adapter being removed or disabled.\n\n'
        'Please select a network interface to resume capture.'
    )


def format_npcap_required_message() -> str:
    """Format the initial NPCAP-required notification shown when Npcap is missing."""
    return """
        NPCAP REQUIRED:
            Npcap is required for network packet capturing.

        ACTION REQUIRED:
            1. Npcap download page opened in your browser
            2. Download and install Npcap from:
                https://npcap.com/#download
            3. Follow the installation instructions on the website
            4. Click OK after installation is complete

        IMPORTANT:
            Waiting for installation to complete...
            Please do not close this dialog until Npcap is installed.
    """


def format_npcap_installation_check_message() -> str:
    """Format the retry/cancel prompt shown while waiting for Npcap to be installed."""
    return """
        NPCAP INSTALLATION CHECK:
            Npcap is still not detected on your system.

        OPTIONS:
            • Click "Retry" if you have completed the installation
            • Click "Cancel" to exit the application
    """


def format_npcap_success_message() -> str:
    """Format the success notification shown when Npcap detection succeeds."""
    return """
        SUCCESS:
            Npcap has been successfully detected!

        The application will now continue normally.
    """


def format_gta5_solo_session_process_not_running_message() -> str:
    """Format the warning shown when Solo Public Session is triggered but GTA5 is not running."""
    return 'GTA5 is not currently running.\n\nPlease launch GTA5 before using this feature.'


def format_gta5_solo_session_suspend_failed_message() -> str:
    """Format the error shown when the GTA5 process suspend attempt fails."""
    return 'Failed to suspend the GTA5 process.\n\nTry running Session Sniffer as administrator.'
