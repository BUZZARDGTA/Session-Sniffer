"""Windows-specific ctypes helpers for capture utilities."""

import ctypes
import ctypes.wintypes
from pathlib import Path


def get_system32_dir() -> Path:
    """Return the System32 path via the Win32 API, bypassing environment variables."""
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    ctypes.windll.kernel32.GetSystemDirectoryW(buf, ctypes.wintypes.MAX_PATH)
    return Path(buf.value)
