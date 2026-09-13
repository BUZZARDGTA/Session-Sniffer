"""Lightweight text helpers.

Keep this module dependency-free and safe to import from anywhere.
"""

import textwrap
from datetime import timedelta
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS = 60
_ONE_MS = timedelta(milliseconds=1)


def format_elapsed_time(duration: timedelta) -> str:
    """Format a timedelta duration into a compact human-readable string."""
    total_ms = duration // _ONE_MS
    hours, remainder = divmod(total_ms, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    seconds, milliseconds = divmod(remainder, 1_000)

    if hours:
        return f'{hours:02}h {minutes:02}m {seconds:02}s'
    if minutes:
        return f'{minutes:02}m {seconds:02}s'
    if seconds:
        return f'{seconds:02}s'
    if milliseconds:
        return f'{milliseconds:03}ms'
    return '000ms'


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


def parse_voice_notifications(value: str) -> Literal['Male', 'Female'] | bool:
    """Parse a voice notification setting string to its typed value."""
    upper = value.upper()
    if upper == 'MALE':
        return 'Male'
    if upper == 'FEMALE':
        return 'Female'
    return False


def parse_suspend_duration_setting(raw: str) -> int | Literal['Auto']:
    """Parse a protection suspend-duration setting string to its typed value."""
    try:
        return int(raw)
    except ValueError:
        if raw == 'Manual':
            return DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS
        if raw.startswith('Manual(') and raw.endswith(')'):
            try:
                return int(raw.removeprefix('Manual(').removesuffix(')'))
            except ValueError:
                return DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS
        return 'Auto'


def format_suspend_duration_setting(value: int | Literal['Auto']) -> str:
    """Format a protection suspend-duration value for persistence."""
    if isinstance(value, int):
        return f'Manual({value})'
    return value


def format_single_border_table(
    columns: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    title: str | None = None,
) -> str:
    """Render a text table with single-line box-drawing characters and left-aligned columns.

    Args:
        columns: Column header names.
        rows: Rows of string cell values.
        title: Optional title displayed centered across the top of the table.

    Returns:
        The formatted single-border table string, or an empty string if columns is empty.
    """
    if not columns:
        return ''

    column_widths = [len(column) for column in columns]
    rows_list = [list(row) for row in rows]
    for row in rows_list:
        for i, cell in enumerate(row):
            if i < len(column_widths):
                column_widths[i] = max(column_widths[i], len(cell))

    total_inner_width = sum(width + 2 for width in column_widths) + (len(column_widths) - 1)

    if title:
        min_inner_width = len(title) + 2
        if min_inner_width > total_inner_width:
            extra_content_width = min_inner_width - total_inner_width
            current_content_width = sum(column_widths) or 1
            scale = (current_content_width + extra_content_width) / current_content_width
            column_widths = [int(width * scale) for width in column_widths]
            remaining = (current_content_width + extra_content_width) - sum(column_widths)
            if remaining > 0:
                column_widths[-1] += remaining
            total_inner_width = sum(width + 2 for width in column_widths) + (len(column_widths) - 1)

    lines: list[str] = []
    if title:
        lines.append(f'┌{"─" * total_inner_width}┐')
        lines.append(f'│{title.center(total_inner_width)}│')
        lines.append(f'├{"┬".join("─" * (width + 2) for width in column_widths)}┤')
    else:
        lines.append(f'┌{"┬".join("─" * (width + 2) for width in column_widths)}┐')

    lines.append(f'│ {" │ ".join(column.ljust(width) for column, width in zip(columns, column_widths, strict=True))} │')
    lines.append(f'├{"┼".join("─" * (width + 2) for width in column_widths)}┤')

    for row in rows_list:
        row_cells = [(row[i] if i < len(row) else '').ljust(width) for i, width in enumerate(column_widths)]
        lines.append(f'│ {" │ ".join(row_cells)} │')

    lines.append(f'└{"┴".join("─" * (width + 2) for width in column_widths)}┘')

    return '\n'.join(lines)
