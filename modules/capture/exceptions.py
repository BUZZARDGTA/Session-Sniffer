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


class UnexpectedFieldCountError(TSharkProcessingError):
    """Raised when the number of fields in TShark output is unexpected."""

    def __init__(self, actual: int, fields: tuple[str, ...]) -> None:
        """Initialize the UnexpectedFieldCountError exception."""
        super().__init__(
            f'Unexpected number of fields in TShark output. '
            f'Expected "5", got "{actual}": "{fields}"',
        )


class MissingRequiredFieldsError(TSharkProcessingError):
    """Raised when required fields are missing in TShark output."""

    def __init__(self, fields: tuple[str, ...]) -> None:
        """Initialize the MissingRequiredFieldsError exception."""
        super().__init__(
            f'One of the required first three fields is empty. Fields: {fields}',
        )


class InvalidIPv4AddressInCaptureError(TSharkProcessingError):
    """Raised when the source or destination IP addresses are not valid IPv4 addresses."""

    def __init__(self, ip: str) -> None:
        """Initialize the InvalidIPv4AddressError exception."""
        super().__init__(f'Invalid IPv4 address: {ip}. IP must be a valid IPv4 address.')


class InvalidPortFormatError(TSharkProcessingError):
    """Raised when source or destination ports are not digits."""

    def __init__(self, port: str) -> None:
        """Initialize the InvalidPortFormatError exception."""
        super().__init__(f'Invalid port format: {port}. Port must be a number.')


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
