"""Capture-related custom exceptions.

This module contains custom exception classes for packet capture operations.
"""

from modules.constants.standalone import MAX_PORT, MIN_PORT


class TSharkError(Exception):
    """Base exception for all TShark-related errors."""


class TSharkOutputParsingError(TSharkError):
    """Raised when TShark output cannot be parsed correctly."""

    def __init__(self, expected_parts: int, actual_parts: int, output_line: str) -> None:
        super().__init__(f'Expected "{expected_parts}" parts, got "{actual_parts}" in "{output_line}"')


class MalformedPacketError(TSharkError):
    """Base exception for malformed packet errors.

    These exceptions are meant to be self-describing: `str(exc)` should produce
    a user-friendly reason suitable for logs/UI.
    """

    message_template: str = 'Malformed packet'

    def __init__(self, value: object | None = None) -> None:
        self.value = value
        super().__init__()

    def __str__(self) -> str:
        """Return a user-friendly reason for the malformed packet."""
        try:
            return self.message_template.format(value=self.value)
        except (IndexError, KeyError, ValueError):
            return self.message_template


class MissingRequiredPacketFieldError(MalformedPacketError):
    """Raised when a required packet field is missing/empty."""

    message_template = 'Missing required packet field(s)'


class MissingPortError(MalformedPacketError):
    """Raised when source or destination port is missing/empty."""

    message_template = 'Missing port(s)'


class InvalidIPv4AddressError(MalformedPacketError):
    """Raised when the source or destination IP addresses are not valid IPv4 addresses."""


class InvalidIPv4AddressMultipleError(InvalidIPv4AddressError):
    """Raised when an IP field contains multiple comma-separated values."""

    message_template = 'Invalid IPv4 address: {value}. IP must be a valid IPv4 address.'


class InvalidIPv4AddressFormatError(InvalidIPv4AddressError):
    """Raised when an IP field is not a valid IPv4 format."""

    message_template = 'Invalid IPv4 address: {value}. IP must be a valid IPv4 address.'


class InvalidPortFormatError(MalformedPacketError):
    """Raised when source or destination ports are not digits."""


class InvalidPortMultipleError(InvalidPortFormatError):
    """Raised when a port field contains multiple comma-separated values."""

    message_template = 'Invalid port format: {value}. Port must be a number.'


class InvalidPortNumericError(InvalidPortFormatError):
    """Raised when a port field is not a valid numeric format."""

    message_template = 'Invalid port format: {value}. Port must be a number.'


class InvalidPortNumberError(MalformedPacketError):
    """Raised when source or destination ports are not valid."""

    message_template = f'Invalid port number: {{value}}. Port must be a number between {MIN_PORT} and {MAX_PORT}.'


class InvalidLengthFormatError(MalformedPacketError):
    """Raised when frame length is not in the expected format."""


class InvalidLengthNumericError(InvalidLengthFormatError):
    """Raised when a length field is not a valid numeric format."""

    message_template = 'Invalid length format: {value}. Length must be a number.'


class TSharkCrashExceptionError(TSharkError):
    """Exception raised when TShark crashes.

    Attributes:
        returncode: The return code of the TShark process.
        stderr_output: The standard error output from TShark.
    """

    def __init__(self, returncode: int, stderr_output: str) -> None:
        """Initialize the exception with the return code and standard error output.

        Args:
            returncode: The return code of the TShark process.
            stderr_output: The standard error output from TShark.
        """
        super().__init__(f'TShark crashed with return code {returncode}: {stderr_output}')


class TSharkProcessInitializationError(TSharkError):
    """Exception raised when TShark process initialization fails.

    This exception is raised when the TShark subprocess is created but its
    stdout or stderr streams are not available despite being configured with PIPE.
    """

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('TShark process stdout/stderr not available')


class TSharkAlreadyRunningError(TSharkError):
    """Exception raised when attempting to start capture while it's already running."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Capture is already running')


class TSharkNotRunningError(TSharkError):
    """Exception raised when attempting to stop capture that is not running."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Capture is not running')


class TSharkNoProcessError(TSharkError):
    """Exception raised when attempting to terminate a non-existent TShark process."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('No TShark process to terminate')


class TSharkThreadAlreadyRunningError(TSharkError):
    """Exception raised when attempting to start a capture thread that is already running."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Capture thread is already running')
