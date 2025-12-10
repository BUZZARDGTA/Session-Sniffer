"""GUI-related custom exceptions.

This module contains custom exception classes for GUI operations.
"""


class PrimaryScreenNotFoundError(Exception):
    """Raised when no primary screen is detected in GUI operations."""

    def __init__(self) -> None:
        super().__init__('No primary screen detected')


class UnsupportedSortColumnError(Exception):
    """Raised when an unsupported column name is used for sorting."""

    def __init__(self, column_name: str) -> None:
        super().__init__(f"Sorting by column '{column_name}' is not supported.")


class TableDataConsistencyError(Exception):
    """Raised when table data and color arrays are in an inconsistent state."""

    def __init__(self, *, case: str) -> None:
        error_messages = {
            'colors_without_data': "Inconsistent state: It's not possible to have colors if there's no data.",
            'data_without_colors': "Inconsistent state: It's not possible to have data without colors.",
            'empty_combined': "Inconsistent state: 'combined' is unexpectedly empty at this point.",
        }

        super().__init__(error_messages[case])


class InvalidDateColumnConfigurationError(Exception):
    """Raised when GUI date column settings are invalid (both date and time disabled)."""

    def __init__(self) -> None:
        super().__init__('Invalid settings: Both date and time are disabled.')


class UnsupportedScreenResolutionError(Exception):
    """Raised when screen resolution is below minimum requirements."""

    def __init__(self, screen_width: int, screen_height: int, min_width: int, min_height: int) -> None:
        self.screen_width = screen_width
        self.screen_height = screen_height
        self.min_width = min_width
        self.min_height = min_height
        self.msgbox_text = (
            f'Session Sniffer requires a minimum screen resolution of {min_width}x{min_height} pixels.\n\n'
            f'Your current screen resolution: {screen_width}x{screen_height}\n\n'
            'Please increase your screen resolution or use a larger monitor to run Session Sniffer.'
        )
        super().__init__(self.msgbox_text)
