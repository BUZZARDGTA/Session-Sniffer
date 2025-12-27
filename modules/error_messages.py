"""Error message formatting functions.

This module contains functions for formatting error messages and dialogs.
"""


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
