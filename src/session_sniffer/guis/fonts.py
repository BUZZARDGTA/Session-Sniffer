"""Font utilities for platform-appropriate typography."""

import sys
from functools import cache

from PySide6.QtGui import QFont


@cache
def get_ui_font_family() -> str:
    """Return the platform-appropriate primary UI font family name."""
    if sys.platform == 'win32':
        return 'Segoe UI'
    if sys.platform == 'darwin':
        return 'Helvetica Neue'
    return 'DejaVu Sans'


@cache
def get_monospace_font_family() -> str:
    """Return the platform-appropriate monospace font family name."""
    if sys.platform == 'win32':
        return 'Consolas'
    if sys.platform == 'darwin':
        return 'Menlo'
    return 'DejaVu Sans Mono'


def get_ui_font(
    point_size: int = -1,
    weight: QFont.Weight | int = -1,
) -> QFont:
    """Create a QFont with the platform-appropriate UI font family."""
    return QFont(get_ui_font_family(), point_size, weight)


def get_monospace_font(
    point_size: int = -1,
    weight: QFont.Weight | int = -1,
) -> QFont:
    """Create a QFont with the platform-appropriate monospace font family."""
    font = QFont(get_monospace_font_family(), point_size, weight)
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font
