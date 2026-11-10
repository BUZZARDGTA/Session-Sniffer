"""Console window management via the Windows kernel32/user32 APIs."""

import ctypes
import sys
from ctypes import wintypes

_SW_HIDE = 0

if sys.platform == 'win32':
    _kernel32 = ctypes.windll.kernel32
    _kernel32.GetConsoleWindow.argtypes = []
    _kernel32.GetConsoleWindow.restype = wintypes.HWND

    _user32 = ctypes.windll.user32
    _user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.ShowWindow.restype = wintypes.BOOL


def hide_console_window() -> None:
    """Hide the console window on Windows (best-effort)."""
    if sys.platform == 'win32':
        hwnd = _kernel32.GetConsoleWindow()
        if hwnd:
            _user32.ShowWindow(hwnd, _SW_HIDE)
