"""Windows-specific ctypes helpers for capture utilities."""

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

if sys.platform == 'win32':
    _SC_MANAGER_CONNECT = 0x0001
    _SERVICE_QUERY_STATUS = 0x0004
    _SERVICE_RUNNING = 0x00000004

    class _ServiceStatus(ctypes.Structure):
        """ctypes definition for SERVICE_STATUS structure."""
        _fields_ = [
            ('dwServiceType', wintypes.DWORD),
            ('dwCurrentState', wintypes.DWORD),
            ('dwControlsAccepted', wintypes.DWORD),
            ('dwWin32ExitCode', wintypes.DWORD),
            ('dwServiceSpecificExitCode', wintypes.DWORD),
            ('dwCheckPoint', wintypes.DWORD),
            ('dwWaitHint', wintypes.DWORD),
        ]

    _advapi32 = ctypes.windll.advapi32
    _advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    _advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    _advapi32.OpenServiceW.restype = wintypes.HANDLE
    _advapi32.QueryServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ServiceStatus)]
    _advapi32.QueryServiceStatus.restype = wintypes.BOOL
    _advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    _advapi32.CloseServiceHandle.restype = wintypes.BOOL
else:
    _SC_MANAGER_CONNECT = 0
    _SERVICE_QUERY_STATUS = 0
    _SERVICE_RUNNING = 0


def get_system32_dir() -> Path:
    """Return the System32 path via the Win32 API, bypassing environment variables."""
    if sys.platform != 'win32':
        return Path('/bin')
    buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    ctypes.windll.kernel32.GetSystemDirectoryW(buf, wintypes.MAX_PATH)
    return Path(buf.value)


def is_service_running(service_name: str) -> bool:
    """Check if a Windows service is currently active and running via the Service Control Manager."""
    if sys.platform != 'win32':
        return False

    is_running = False
    manager_handle = _advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if manager_handle:
        try:
            service_handle = _advapi32.OpenServiceW(manager_handle, service_name, _SERVICE_QUERY_STATUS)
            if service_handle:
                try:
                    service_status = _ServiceStatus()
                    if _advapi32.QueryServiceStatus(service_handle, ctypes.byref(service_status)):
                        is_running = bool(service_status.dwCurrentState == _SERVICE_RUNNING)
                finally:
                    _advapi32.CloseServiceHandle(service_handle)
        finally:
            _advapi32.CloseServiceHandle(manager_handle)

    return is_running


def is_npcap_setup_window_visible() -> bool:
    """Check if any visible window belongs to the Npcap setup wizard."""
    if sys.platform != 'win32':
        return False

    found = False
    window_enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def enum_windows_callback(hwnd: wintypes.HWND, _lparam: wintypes.LPARAM) -> bool:
        nonlocal found
        if not ctypes.windll.user32.IsWindowVisible(hwnd):
            return True
        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            title_buffer = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, title_buffer, length + 1)
            title = title_buffer.value.lower()
            if 'npcap' in title and 'setup' in title:
                found = True
                return False
        return True

    ctypes.windll.user32.EnumWindows(window_enum_proc(enum_windows_callback), 0)
    return found
