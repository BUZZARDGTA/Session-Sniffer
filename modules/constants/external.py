"""Module for defining constants that require imports from third-party libraries."""
from PyQt6.QtGui import QColor
from qdarkstyle.colorsystem import Gray  # pyright: ignore[reportMissingTypeStubs]
from tzlocal import get_localzone

LOCAL_TZ = get_localzone()

# GUI-related constant
HARDCODED_DEFAULT_TABLE_BACKGROUND_CELL_COLOR = QColor(Gray.B10)
