"""Networking-related custom exceptions.

This module contains custom exception classes for networking operations.
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modules.networking.endpoint_ping_manager import PingResult


class InvalidMacAddressError(Exception):
    """Exception raised when an invalid MAC address is found."""

    def __init__(self, mac_address: str) -> None:
        """Initialize the exception with the invalid MAC address.

        Args:
            mac_address: The invalid MAC address that caused the error.
        """
        super().__init__(f'Invalid MAC address: {mac_address}\n'
                         f'A MAC address must be a 12-digit hexadecimal number long.')


class InvalidIPv4AddressError(Exception):
    """Exception raised when an invalid IPv4 address is found."""

    def __init__(self, ipv4_address: str) -> None:
        """Initialize the exception with the invalid IPv4 address.

        Args:
            ipv4_address: The invalid IPv4 address that caused the error.
        """
        super().__init__(f'Invalid IPv4 address: {ipv4_address}')


class ManufLineParseError(ValueError):
    """Exception raised when parsing a manuf line fails."""

    def __init__(self, line: str) -> None:
        """Initialize the exception with the failed line."""
        super().__init__(f'Failed to parse manuf line: {line!r}')


class InvalidManufEntryFieldError(TypeError):
    """Base class for all ManufEntry field type errors."""

    def __init__(self, field_name: str, value: object) -> None:
        """Initialize the exception with field information."""
        super().__init__(
            f'Invalid type for {field_name}: expected str but got {type(value).__name__} ({value!r})',
        )


class InvalidMacPrefixError(InvalidManufEntryFieldError):
    """Exception raised when MAC prefix is invalid."""

    def __init__(self, value: object) -> None:
        """Initialize the exception with the invalid MAC prefix."""
        super().__init__('mac_prefix', value)


class InvalidCidrError(InvalidManufEntryFieldError):
    """Exception raised when CIDR is invalid."""

    def __init__(self, value: object) -> None:
        """Initialize the exception with the invalid CIDR."""
        super().__init__('cidr', value)


class InvalidManufacturerError(InvalidManufEntryFieldError):
    """Exception raised when manufacturer is invalid."""

    def __init__(self, value: object) -> None:
        """Initialize the exception with the invalid manufacturer."""
        super().__init__('manufacturer', value)


class InvalidVendorNameError(InvalidManufEntryFieldError):
    """Exception raised when vendor name is invalid."""

    def __init__(self, value: object) -> None:
        """Initialize the exception with the invalid vendor name."""
        super().__init__('vendor_name', value)


class InvalidPingResultError(Exception):
    """Exception raised when the parsed ping result contains invalid or missing data."""

    def __init__(self, ip: str, response_content: str, ping_result: PingResult) -> None:
        """Initialize the exception with ping result information."""
        attributes = '\n'.join(f'{attr}={getattr(ping_result, attr)}'
                               for attr in ping_result._fields)
        super().__init__(f'Invalid ping result for {ip}:\n'
                         f'Response: {response_content}\n'
                         f'{attributes}')


class AllEndpointsExhaustedError(Exception):
    """Exception raised when all endpoints have been exhausted."""

    def __init__(self) -> None:
        """Initialize the exception with a default message."""
        super().__init__('All ping endpoints have been exhausted')


class InterfaceAlreadyExistsError(Exception):
    """Raised when attempting to add a network interface that already exists."""

    def __init__(self, index: int, name: str | None = None) -> None:
        """Initialize the exception with interface identity details.

        Args:
            index: Interface index.
            name: Optional interface name.
        """
        details = f'index={index}' + (f', name="{name}"' if name else '')
        super().__init__(f'Interface already exists in registry ({details})')
