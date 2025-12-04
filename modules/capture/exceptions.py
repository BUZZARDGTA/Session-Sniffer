"""Capture-related custom exceptions.

This module contains custom exception classes for packet capture operations.
"""

from modules.constants.standalone import MAX_PORT, MIN_PORT


class TSharkOutputParsingError(Exception):
    """Raised when TShark output cannot be parsed correctly."""

    def __init__(self, expected_parts: int, actual_parts: int, output_line: str) -> None:
        super().__init__(f'Expected "{expected_parts}" parts, got "{actual_parts}" in "{output_line}"')


class TSharkProcessingError(ValueError):
    """Base class for TShark packet parsing errors."""

    def __init__(self, message: str) -> None:
        """Initialize the exception with a custom message."""
        super().__init__(message)


class InvalidIPv4AddressError(TSharkProcessingError):
    """Raised when the source or destination IP addresses are not valid IPv4 addresses."""

    def __init__(self, ip: str) -> None:
        """Initialize the InvalidIPv4AddressError exception."""
        super().__init__(f'Invalid IPv4 address: {ip}. IP must be a valid IPv4 address.')


class InvalidIPv4AddressMultipleError(InvalidIPv4AddressError):
    """Raised when an IP field contains multiple comma-separated values."""


class InvalidIPv4AddressFormatError(InvalidIPv4AddressError):
    """Raised when an IP field is not a valid IPv4 format."""


class InvalidPortFormatError(TSharkProcessingError):
    """Raised when source or destination ports are not digits."""

    def __init__(self, port: str) -> None:
        """Initialize the InvalidPortFormatError exception."""
        super().__init__(f'Invalid port format: {port}. Port must be a number.')


class InvalidPortMultipleError(InvalidPortFormatError):
    """Raised when a port field contains multiple comma-separated values."""


class InvalidPortNumericError(InvalidPortFormatError):
    """Raised when a port field is not a valid numeric format."""


class InvalidPortNumberError(TSharkProcessingError):
    """Raised when source or destination ports are not valid."""

    def __init__(self, port: int) -> None:
        """Initialize the InvalidPortNumberError exception."""
        super().__init__(f'Invalid port number: {port}. Port must be a number between {MIN_PORT} and {MAX_PORT}.')


class TSharkCrashExceptionError(Exception):
    """Exception raised when TShark crashes.

    Attributes:
        returncode (int): The return code of the TShark process.
        stderr_output (str): The standard error output from TShark.
    """

    def __init__(self, returncode: int, stderr_output: str) -> None:
        """Initialize the exception with the return code and standard error output.

        Args:
            returncode (int): The return code of the TShark process.
            stderr_output (str): The standard error output from TShark.
        """
        super().__init__(f'TShark crashed with return code {returncode}: {stderr_output}')


class TSharkProcessInitializationError(Exception):
    """Exception raised when TShark process initialization fails.

    This exception is raised when the TShark subprocess is created but its
    stdout or stderr streams are not available despite being configured with PIPE.
    """

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('TShark process stdout/stderr not available')
