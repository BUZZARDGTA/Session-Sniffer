"""Lightweight text helpers.

Keep this module dependency-free and safe to import from anywhere.
"""

import textwrap


def pluralize(count: int, singular: str = '', plural: str = 's') -> str:
    """Return the singular/plural suffix based on a count.

    Args:
        count: The count to decide plurality.
        singular: Suffix to use when count is exactly 1.
        plural: Suffix to use otherwise.

    Returns:
        The chosen suffix.
    """
    return singular if count == 1 else plural


def format_triple_quoted_text(
    text: str,
    /,
    *,
    add_leading_newline: bool = False,
    add_trailing_newline: bool = False,
) -> str:
    """Format a triple-quoted string by removing leading whitespace and optionally adding newlines.

    Args:
        text: The text to format.
        add_leading_newline: Whether to add a leading newline.
        add_trailing_newline: Whether to add a trailing newline.

    Returns:
        The formatted text.
    """
    formatted_text = textwrap.dedent(text).strip()

    if add_leading_newline:
        formatted_text = '\n' + formatted_text
    if add_trailing_newline:
        formatted_text += '\n'

    return formatted_text
