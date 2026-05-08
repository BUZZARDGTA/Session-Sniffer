"""Capture-related custom exceptions.

This module contains custom exception classes for packet capture operations.
"""

from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT
from session_sniffer.error_messages import format_arp_spoofing_gateway_error_message


class CaptureError(Exception):
    """Base exception for all capture-related errors."""


class MalformedPacketError(CaptureError):
    """Base exception for malformed packet errors.

    These exceptions are meant to be self-describing: `str(exc)` should produce
    a user-friendly reason suitable for logs/UI.
    """

    message_template: str = 'Malformed packet'

    def __init__(self, value: object | None = None) -> None:
        """Initialize the exception with the offending value (if any).

        Args:
            value: Optional value associated with the malformed packet.
        """
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


class CaptureExitError(CaptureError):
    """Exception raised when the packet capture stops unexpectedly.

    Attributes:
        cause: The underlying exception from the sniffer thread, if any.
    """

    def __init__(self, cause: BaseException | None = None) -> None:
        """Initialize the exception with an optional underlying cause.

        Args:
            cause: The underlying exception from the sniffer thread, if any.
        """
        self.cause = cause
        detail = f': {cause}' if cause is not None else ''
        super().__init__(f'Packet capture stopped unexpectedly{detail}')


class CaptureAlreadyRunningError(CaptureError):
    """Exception raised when attempting to start capture while it's already running."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Capture is already running')


class CaptureNotRunningError(CaptureError):
    """Exception raised when attempting to stop capture that is not running."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Capture is not running')


class CaptureNoSnifferError(CaptureError):
    """Exception raised when attempting to terminate a non-existent sniffer."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('No active sniffer to terminate')


class CaptureThreadAlreadyRunningError(CaptureError):
    """Exception raised when attempting to start a capture thread that is already running."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Capture thread is already running')


class MissingGatewayIPForARPSpoofingError(Exception):
    """Raised when ARP spoofing is enabled but the selected interface has no usable gateway IP."""

    def __init__(
        self,
        *,
        interface_name: str,
        interface_ip: str,
        gateway_ip: str | None,
    ) -> None:
        """Initialize with the interface details that caused the error."""
        self.interface_name = interface_name
        self.interface_ip = interface_ip
        self.gateway_ip = gateway_ip
        self.msgbox_text = format_arp_spoofing_gateway_error_message(
            interface_name=interface_name,
            interface_ip=interface_ip,
            gateway_ip=gateway_ip,
        )
        super().__init__(self.msgbox_text)
