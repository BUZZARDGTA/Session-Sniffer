"""General custom exceptions.

This module contains custom exception classes for general application operations.
"""


class PlayerAlreadyExistsError(ValueError):
    """Raised when attempting to add a player that already exists in the registry."""

    def __init__(self, ip: str) -> None:
        """Initialize the exception with a message."""
        super().__init__(f'Player with IP "{ip}" already exists.')


class PlayerNotFoundInRegistryError(Exception):
    """Raised when a player with the specified IP address is not found in the players registry."""

    def __init__(self, ip: str) -> None:
        super().__init__(f'Player with IP "{ip}" not found in the players registry.')


class UnexpectedPlayerCountError(Exception):
    """Raised when an unexpected number of connected players is encountered in session host detection."""

    def __init__(self, player_count: int) -> None:
        super().__init__(f'Unexpected number of connected players: {player_count}')


class FunctionExecutionError(Exception):
    """Raised when a function encounters an unexpected execution state."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ConfigurationError(Exception):
    """Raised when there's an issue with configuration or settings."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class DataConsistencyError(Exception):
    """Raised when data structures are in an inconsistent state."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PlayerDateTimeCorruptionError(Exception):
    """Raised when player datetime fields are in an invalid state (e.g., last_rejoin > last_seen)."""

    def __init__(self, last_rejoin: str, last_seen: str) -> None:
        super().__init__(f'Player data corruption: last_rejoin ({last_rejoin}) > last_seen ({last_seen})')


class UnsupportedPlatformError(RuntimeError):
    """Raised when attempting to run Session Sniffer on a non-Windows platform."""

    def __init__(self, platform: str) -> None:
        super().__init__(f'This application only supports Windows (current platform: {platform}).')
