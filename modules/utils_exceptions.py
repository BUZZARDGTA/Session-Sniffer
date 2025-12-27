"""Utility-related exception classes for Session Sniffer."""

from typing import TYPE_CHECKING

from modules.text_utils import pluralize

if TYPE_CHECKING:
    from pathlib import Path


class InvalidFileError(Exception):
    """Exception raised when a file is not valid."""

    def __init__(self, file_path: Path) -> None:
        """Initialize the exception with a default error message.

        Args:
            file_path: The path to the invalid file.
        """
        super().__init__(f'Invalid file: {file_path.absolute()}')


class InvalidBooleanValueError(Exception):
    """Exception raised when a value is not a valid boolean."""

    def __init__(self) -> None:
        """Initialize the exception with a default error message."""
        super().__init__('Input is not a valid boolean value')


class MismatchedBooleanValueError(Exception):
    """Exception raised when the resolved value does not match the expected boolean value."""

    def __init__(self) -> None:
        """Initialize the exception with a default error message."""
        super().__init__('Input does not match the specified boolean value')


class InvalidNoneTypeValueError(Exception):
    """Exception raised when a string is not a valid NoneType value."""

    def __init__(self) -> None:
        """Initialize the exception with a default error message."""
        super().__init__('Input is not a valid NoneType value')


class NoMatchFoundError(Exception):
    """Exception raised when no case-insensitive match is found."""

    def __init__(self, input_value: str) -> None:
        """Initialize the exception with the input value and an optional custom message.

        Args:
            input_value: The value that did not match any item in the list.
        """
        super().__init__(f"No matching value found in the provided list: '{input_value}'")


class ParenthesisMismatchError(Exception):
    """Exception raised when parentheses are mismatched in an expression."""

    def __init__(self, expr: str, unmatched_opening: list[int], unmatched_closing: list[int]) -> None:
        """Initialize the exception with unmatched parentheses positions.

        Args:
            expr: The expression with mismatched parentheses.
            unmatched_opening: Positions of unmatched opening parentheses.
            unmatched_closing: Positions of unmatched closing parentheses.
        """
        message = '\n'.join(
            f'Unmatched {type_} parentheses at position{pluralize(len(positions))}: {positions}'
            for type_, positions in (
                ('opening', unmatched_opening),
                ('closing', unmatched_closing),
            )
            if positions
        )
        super().__init__(f'Expression has mismatched parentheses: {expr}\n{message}')
