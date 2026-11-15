"""Color palette and semantic color definitions for GUI rendering.

This module provides a modular color system organized into layers:
1. ColorPalette - Base Nordic-inspired color definitions
2. StatusBarColors - Semantic colors for status bar HTML formatting
3. ThresholdColors - Status/health indicator colors for metrics and thresholds
4. TableColors - Row coloring for connected/disconnected player tables
"""

from dataclasses import dataclass
from typing import ClassVar

from PySide6.QtGui import QColor

from session_sniffer.constants.standalone import DEFAULT_DETECTED_SERVER_COLOR
from session_sniffer.guis.theming import (
    DARK_THEME_COLORS,
    get_active_theme,
    proprietary_text_qcolor,
    register_theme_change_callback,
    themed_text_qcolor,
)


def _status_color(dark_color: str, token: str) -> str:
    if get_active_theme().colors == DARK_THEME_COLORS:
        return dark_color
    return themed_text_qcolor(token, '@statusbar[#252526]').name(QColor.NameFormat.HexArgb)


def _table_color(dark_color: str, token: str) -> str:
    if get_active_theme().colors == DARK_THEME_COLORS:
        return dark_color
    return themed_text_qcolor(token, '@table[#121212]').name(QColor.NameFormat.HexArgb)


def _looky_table_color(dark_color: str) -> str:
    if get_active_theme().colors == DARK_THEME_COLORS:
        return dark_color
    return proprietary_text_qcolor(dark_color, '@table[#121212]').name(QColor.NameFormat.HexArgb)


@dataclass(slots=True)
class ColorPalette:
    """Base Nordic-inspired color palette for the entire application."""

    ACCENT_BLUE: ClassVar[str] = ''
    ACCENT_ORANGE: ClassVar[str] = ''
    ACCENT_GRAY: ClassVar[str] = ''
    GOOD_GREEN: ClassVar[str] = ''
    WARNING_YELLOW: ClassVar[str] = ''
    CRITICAL_RED: ClassVar[str] = ''


@dataclass(slots=True)
class StatusBarColors:
    """Color scheme specifically for status bar text rendering."""

    DIVIDER: ClassVar[str] = ''
    ENABLED: ClassVar[str] = ''
    DISABLED: ClassVar[str] = ''
    LABEL_ACCENT: ClassVar[str] = ''
    TITLE_ACCENT: ClassVar[str] = ''


@dataclass(slots=True)
class ThresholdColors:
    """Color scheme for metrics and threshold-based status indication."""

    CRITICAL: ClassVar[str] = ''
    WARNING: ClassVar[str] = ''
    HEALTHY: ClassVar[str] = ''


@dataclass(slots=True)
class TableColors:
    """Color scheme for player table rows and cell rendering."""

    CONNECTED_TEXT: ClassVar[str] = ''
    CONNECTED_USERIP_TEXT: ClassVar[str] = ''
    DISCONNECTED_TEXT: ClassVar[str] = ''
    DISCONNECTED_USERIP_TEXT: ClassVar[str] = ''
    DISCONNECTED_PAST_SESSION_TEXT: ClassVar[str] = ''
    DISCONNECTED_PAST_SESSION_USERIP_TEXT: ClassVar[str] = ''
    LOOKY_TEXT: ClassVar[str] = ''
    DISCONNECTED_LOOKY_TEXT: ClassVar[str] = ''
    SERVER_BACKGROUND: ClassVar[str] = DEFAULT_DETECTED_SERVER_COLOR


def _refresh_gui_color_namespaces() -> None:
    """Recompute all semantic status bar, threshold, and table color strings for the active theme."""
    ColorPalette.ACCENT_BLUE = _status_color('lightblue', '@accent[lightblue]')
    ColorPalette.ACCENT_ORANGE = _status_color('darkorange', '@warning[darkorange]')
    ColorPalette.ACCENT_GRAY = _status_color('steelblue', '@text_muted[steelblue]')
    ColorPalette.GOOD_GREEN = _status_color('lightgreen', '@success[lightgreen]')
    ColorPalette.WARNING_YELLOW = _status_color('khaki', '@warning[khaki]')
    ColorPalette.CRITICAL_RED = _status_color('indianred', '@danger[indianred]')

    StatusBarColors.DIVIDER = ColorPalette.ACCENT_GRAY
    StatusBarColors.ENABLED = ColorPalette.GOOD_GREEN
    StatusBarColors.DISABLED = ColorPalette.CRITICAL_RED
    StatusBarColors.LABEL_ACCENT = ColorPalette.ACCENT_ORANGE
    StatusBarColors.TITLE_ACCENT = ColorPalette.ACCENT_BLUE

    ThresholdColors.CRITICAL = ColorPalette.CRITICAL_RED
    ThresholdColors.WARNING = ColorPalette.WARNING_YELLOW
    ThresholdColors.HEALTHY = ColorPalette.GOOD_GREEN

    TableColors.CONNECTED_TEXT = _table_color('lime', '@success[lime]')
    TableColors.CONNECTED_USERIP_TEXT = _table_color('white', '@text_strong[white]')
    TableColors.DISCONNECTED_TEXT = _table_color('red', '@danger[red]')
    TableColors.DISCONNECTED_USERIP_TEXT = _table_color('white', '@text_strong[white]')
    TableColors.DISCONNECTED_PAST_SESSION_TEXT = _table_color('#8c3e42', '@danger[#8c3e42]')
    TableColors.DISCONNECTED_PAST_SESSION_USERIP_TEXT = _table_color('#a8a8a8', '@text_muted[#a8a8a8]')
    TableColors.LOOKY_TEXT = _looky_table_color('#c084fc')
    TableColors.DISCONNECTED_LOOKY_TEXT = _looky_table_color('#a855f7')
    TableColors.SERVER_BACKGROUND = DEFAULT_DETECTED_SERVER_COLOR


_refresh_gui_color_namespaces()
register_theme_change_callback(_refresh_gui_color_namespaces)
