"""Module for defining networking utility functions."""
import re
from contextlib import suppress
from ipaddress import AddressValueError, IPv4Address

from modules.networking.exceptions import (
    InvalidIPv4AddressError,
    InvalidMacAddressError,
)

RE_MAC_ADDRESS_PATTERN = re.compile(r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', re.IGNORECASE)
IPV4_LAST_OCTET_VALUE = 255


def is_mac_address(mac_address: str, /, *, raise_exception: bool = False) -> bool:
    """Check if the given MAC address is valid.

    If `raise_exception` is True, raises an `InvalidMacAddressError` if the MAC address is invalid.

    Args:
        mac_address: The MAC address to check.
        raise_exception: If True, raise an exception for invalid MAC addresses.

    Returns:
        True if the MAC address is valid, False otherwise.

    Raises:
        InvalidMacAddressError: If the MAC address is invalid and `raise_exception` is True.
    """
    if RE_MAC_ADDRESS_PATTERN.fullmatch(mac_address):
        return True
    if raise_exception:
        raise InvalidMacAddressError(mac_address)
    return False


def sanitize_mac_address(mac_address: str, /) -> str:
    """Remove any separators from the MAC address and convert to uppercase."""
    return ''.join(c for c in mac_address if c.isalnum()).upper()


def format_mac_address(mac_address: str, /, separator: str = ':') -> str:
    """Format the MAC address using the specified separator (default: XX:XX:XX:XX:XX:XX)."""
    sanitized_mac = sanitize_mac_address(mac_address)
    return separator.join(sanitized_mac[i:i + 2] for i in range(0, len(sanitized_mac), 2))


def get_mac_oui(mac_address: str, /, separator: str = '') -> str:
    """Extract the OUI (first three hexadecimal pairs) from a MAC address and formats it with the specified separator."""
    sanitized_mac = sanitize_mac_address(mac_address)
    return separator.join(sanitized_mac[i:i + 2] for i in range(0, 6, 2))


def is_ipv4_address(ipv4_address: str, /, *, raise_exception: bool = False) -> bool:
    """Check if the given IPv4 address is valid.

    If `raise_exception` is True, raises an `InvalidIPv4AddressError` if the IP address is invalid.

    Args:
        ipv4_address: The IP address to check.
        raise_exception: If True, raise an exception for invalid IP addresses.

    Returns:
        True if the IP address is valid, False otherwise.

    Raises:
        InvalidIPv4AddressError: If the IP address is invalid and `raise_exception` is True.
    """
    with suppress(AddressValueError):
        IPv4Address(ipv4_address)
        return True
    if raise_exception:
        raise InvalidIPv4AddressError(ipv4_address)
    return False


def is_private_device_ipv4(ip_address: str, /) -> bool:
    try:
        ipv4_obj = IPv4Address(ip_address)
    except AddressValueError:
        return False
    return ipv4_obj.is_private


def is_valid_non_special_ipv4(ip_address: str, /) -> bool:
    try:
        ipv4_obj = IPv4Address(ip_address)
    except AddressValueError:
        return False

    invalid_conditions = (
        ipv4_obj.packed[-1] == IPV4_LAST_OCTET_VALUE,
        ipv4_obj.is_link_local,  # might want to remove this
        ipv4_obj.is_loopback,
        ipv4_obj.is_reserved,
        ipv4_obj.is_unspecified,
        ipv4_obj.is_global,
        ipv4_obj.is_multicast,
    )

    return not any(invalid_conditions)
