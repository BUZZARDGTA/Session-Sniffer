"""Utility functions for GUI-related operations.

This module provides helper functions to interact with GUI elements.
"""

from typing import TYPE_CHECKING

from .app import app
from .exceptions import PrimaryScreenNotFoundError, UnsupportedScreenResolutionError

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QDialog, QMainWindow


def get_screen_size() -> tuple[int, int]:
    """Get the current screen size and validate minimum resolution requirements.

    Returns:
        tuple[int,int]: Screen width and height in pixels.

    Raises:
        PrimaryScreenNotFoundError: If no primary screen is detected.
        UnsupportedScreenResolutionError: If screen resolution is below minimum requirements.
    """
    min_screen_width = 800
    min_screen_height = 600

    screen = app.primaryScreen()
    if screen is None:
        raise PrimaryScreenNotFoundError

    size = screen.size()
    screen_width = size.width()
    screen_height = size.height()

    if screen_width < min_screen_width or screen_height < min_screen_height:
        raise UnsupportedScreenResolutionError(screen_width, screen_height, min_screen_width, min_screen_height)

    return screen_width, screen_height


def resize_window_for_screen(window: QMainWindow | QDialog, screen_width: int, screen_height: int) -> None:
    """Resize a window based on the screen resolution.

    Args:
        window (QWidget): The window to resize.
        screen_width (int): The width of the screen.
        screen_height (int): The height of the screen.
    """
    if (screen_width, screen_height) >= (2560, 1440):
        window.resize(1400, 900)
    elif (screen_width, screen_height) >= (1920, 1080):
        window.resize(1200, 720)
    elif (screen_width, screen_height) >= (1024, 768):
        window.resize(940, 680)
