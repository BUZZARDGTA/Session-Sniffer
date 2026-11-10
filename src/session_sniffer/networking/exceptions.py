"""Networking-related custom exceptions.

This module contains custom exception classes for networking operations.
"""


class InvalidMacAddressError(Exception):
    """Exception raised when an invalid MAC address is found."""

    def __init__(self, mac_address: str) -> None:
        """Initialize the exception with the invalid MAC address.

        Args:
            mac_address: The invalid MAC address that caused the error.
        """
        super().__init__(f'Invalid MAC address: {mac_address}\nA MAC address must be a 12-digit hexadecimal number long.')


class ManufLineParseError(ValueError):
    """Exception raised when parsing a manuf line fails."""

    def __init__(self, line: str) -> None:
        """Initialize the exception with the failed line."""
        super().__init__(f'Failed to parse manuf line: {line!r}')


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
        details = f'index={index}' + (f', name="{name}"' if bool(name) else '')
        super().__init__(f'Interface already exists in registry ({details})')
