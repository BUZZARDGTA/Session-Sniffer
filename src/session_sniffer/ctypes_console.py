"""Console window management via the Windows kernel32/user32 APIs."""

import ctypes
import sys


def hide_console_window() -> None:
    """Hide the console window on Windows (best-effort)."""
    if sys.platform == 'win32':
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
