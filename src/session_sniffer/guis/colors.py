"""Semantic color definitions for GUI table rendering."""

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


def _table_color(dark_color: str, token: str) -> str:
    if get_active_theme().colors == DARK_THEME_COLORS:
        return dark_color
    return themed_text_qcolor(token, '@table[#121212]').name(QColor.NameFormat.HexArgb)


def _looky_table_color(dark_color: str) -> str:
    if get_active_theme().colors == DARK_THEME_COLORS:
        return dark_color
    return proprietary_text_qcolor(dark_color, '@table[#121212]').name(QColor.NameFormat.HexArgb)


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
    """Recompute all semantic table color strings for the active theme."""
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
