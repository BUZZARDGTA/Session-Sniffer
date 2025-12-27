"""Error message formatting functions.

This module contains functions for formatting error messages and dialogs.
"""

from typing import TYPE_CHECKING

from modules.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


def format_attribute_error(cls: type, name: str) -> str:
    """Format an attribute error message.

    Args:
        cls: The class of the object.
        name: The name of the missing attribute.

    Returns:
        The formatted error message.
    """
    return f"'{cls.__name__}' object has no attribute '{name}'"


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
        expected_types_names = ' | '.join(t.__name__ for t in expected_types)
        expected_type_count = len(expected_types)
    else:
        expected_types_names = expected_types.__name__
        expected_type_count = 1

    plural_suffix = '' if expected_type_count == 1 else 's'
    return f'Expected type{plural_suffix} {expected_types_names}, got {actual_type} instead.{suffix}'


def format_file_not_found_error(file_path: Path) -> str:
    """Format the file-not-found error message."""
    return f'File not found: {file_path.absolute()}'


def format_uncaught_exception_report_message(*, issues_url: str) -> str:
    """Format the generic uncaught-exception message shown to the user."""
    return (
        'An unexpected (uncaught) error occurred.\n\n'
        'Please kindly report it to:\n'
        f'{issues_url}'
    )


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
    app_title: str,
    exception_name: str,
    http_code: str,
    versions_url: str,
) -> str:
    """Format the retry/abort message shown when update checks fail."""
    return f"""
        ERROR:
            Failed to check for updates.

            DEBUG:
                Exception: {exception_name}
                HTTP Code: {http_code}

        Please check your internet connection and ensure you have access to:
        {versions_url}

        Abort:
            Exit and open the "{app_title}" GitHub page to
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
    """Format the warning shown when requirements and installed packages mismatch."""
    msgbox_message = 'The following packages have version mismatches:\n\n'

    for package_name, required_version, installed_version in outdated_packages:
        msgbox_message += f'{package_name} (required {required_version}, installed {installed_version})\n'

    msgbox_message += f'\nKeeping your packages synced with "{app_title}" ensures smooth script execution and prevents compatibility issues.'
    msgbox_message += '\n\nDo you want to ignore this warning and continue with script execution?'
    return msgbox_message


def format_port_number_not_provided_message() -> str:
    """Format the warning shown when a port input is missing/invalid."""
    return 'No valid port number provided.'


def format_port_number_out_of_range_message(*, min_port: int, max_port: int) -> str:
    """Format the warning shown when a port input is out of range."""
    return f'Please enter a valid port number between {min_port} and {max_port}.'


def format_no_username_provided_message() -> str:
    """Format the warning shown when the user submits an empty username."""
    return 'ERROR:\nNo username was provided.'


def format_userip_ip_conflict_message(  # pylint: disable=too-many-arguments,  # noqa: PLR0913
    *,
    existing_database_path: Path,
    existing_usernames: list[str],
    ip: str,
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
            "{existing_database_path.relative_to(userip_databases_dir).with_suffix('')}":
            {', '.join(existing_usernames)}={ip}

            "{conflicting_database_path.relative_to(userip_databases_dir).with_suffix('')}":
            {conflicting_username}={ip}
    """


def format_userip_corrupted_settings_message(
    *,
    ini_path: Path,
    setting: str,
    value: str,
    configuration_guide_url: str,
) -> str:
    """Format the error shown when UserIP database settings are corrupted."""
    return f"""
        ERROR:
            Corrupted UserIP Database File (Settings)

        INFOS:
            UserIP database file:
            "{ini_path}"
            has an invalid settings value:

            {setting}={value}

        For more information on formatting, please refer to the
        documentation:
        {configuration_guide_url}
    """


def format_userip_invalid_ip_entry_message(
    *,
    ini_path: Path,
    username: str,
    ip: str,
    configuration_guide_url: str,
) -> str:
    """Format the error shown for invalid IP entries in a UserIP database."""
    return f"""
        ERROR:
            UserIP database invalid IP address

        INFOS:
            The IP address from this database entry is invalid.

        DEBUG:
            {ini_path}
            {username}={ip}

        For more information on formatting, please refer to the
        documentation:
        {configuration_guide_url}
    """


def format_userip_missing_settings_message(
    *,
    ini_path: Path,
    missing_settings: list[str],
    configuration_guide_url: str,
) -> str:
    """Format the error shown when one or more required settings are missing."""
    number_of_settings_missing = len(missing_settings)
    missing_settings_list = '\n                '.join(f'<{setting.upper()}>' for setting in missing_settings)
    return f"""
        ERROR:
            Missing setting{pluralize(number_of_settings_missing)} in UserIP Database File

        INFOS:
            {number_of_settings_missing} missing setting{pluralize(number_of_settings_missing)} in UserIP database file:
            "{ini_path}"

            {missing_settings_list}

        For more information on formatting, please refer to the
        documentation:
        {configuration_guide_url}
    """


def format_arp_spoofing_failed_message(  # pylint: disable=too-many-arguments,too-many-positional-arguments  # noqa: PLR0913
    interface_name: str,
    interface_description: str,
    interface_ip: str,
    interface_mac: str | None,
    interface_vendor_name: str | None,
    exit_code: int | None,
    error_details: str | None,
) -> str:
    """Format an ARP spoofing failure message for display in a message box.

    Returns:
        A formatted error message string ready for display.
    """
    interface_mac = 'N/A' if interface_mac is None else interface_mac
    interface_vendor_name = 'N/A' if interface_vendor_name is None else interface_vendor_name
    exit_code_output = f'{exit_code}' if exit_code is not None else ''
    error_details_output = f'\n{error_details}' if error_details else ''

    return (
        f'ARP Spoofing failed to start.\n\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'INTERFACE DETAILS:\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'Name: {interface_name}\n'
        f'Description: {interface_description}\n'
        f'IP Address: {interface_ip}\n'
        f'MAC Address: {interface_mac}\n'
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
        f'• Stale ARP table entry (target device at {interface_ip} changed IP address)\n\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'RECOMMENDATIONS:\n'
        f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        f'• If adapter "{interface_name}" is shared/bridged, disable ARP Spoofing in the Network Interface Selection screen and try again\n'
        f'• If available, try sniffing target device {interface_ip} on a different network adapter (e.g., Wi-Fi instead of Ethernet)'
    )
