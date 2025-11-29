"""Error message formatting functions.

This module contains functions for formatting error messages and dialogs.
"""


def format_arp_spoofing_failed_message(  # pylint: disable=too-many-arguments,too-many-positional-arguments  # noqa: PLR0913
    interface_name: str,
    interface_description: str,
    interface_ip: str,
    interface_mac: str | None = None,
    vendor_name: str | None = None,
    exit_code: int | None = None,
    error_details: str | None = None,
) -> str:
    """Format an ARP spoofing failure message for display in a message box.

    Args:
        interface_name: The name of the network interface.
        interface_description: The description of the network interface.
        interface_ip: The IP address of the interface.
        interface_mac: The MAC address of the interface (optional).
        vendor_name: The vendor name associated with the MAC address (optional).
        exit_code: The exit code from the ARP spoofing process (optional).
        error_details: Additional error details from stderr/stdout (optional).

    Returns:
        A formatted error message string ready for display.
    """
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
        f'MAC Address: {interface_mac or ""}\n'
        f'Vendor Name: {vendor_name or ""}\n\n'
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
