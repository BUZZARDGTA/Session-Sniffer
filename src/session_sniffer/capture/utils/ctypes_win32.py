"""Windows-specific ctypes helpers for capture utilities."""

import ctypes
import sys
from ctypes import wintypes

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

    _iphlpapi = ctypes.windll.iphlpapi
    _iphlpapi.SendARP.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _iphlpapi.SendARP.restype = wintypes.DWORD

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _user32 = ctypes.windll.user32
    _user32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
    _user32.EnumWindows.restype = wintypes.BOOL
    _user32.IsWindowVisible.argtypes = [wintypes.HWND]
    _user32.IsWindowVisible.restype = wintypes.BOOL
    _user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    _user32.GetWindowTextLengthW.restype = ctypes.c_int
    _user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _user32.GetWindowTextW.restype = ctypes.c_int
else:
    _SC_MANAGER_CONNECT = 0
    _SERVICE_QUERY_STATUS = 0
    _SERVICE_RUNNING = 0


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


def iter_visible_window_titles() -> list[str]:
    """Return the window titles of all currently visible top-level Win32 windows."""
    if sys.platform != 'win32':
        return []

    titles: list[str] = []

    def enum_windows_callback(hwnd: int | None, _lparam: int) -> bool:
        if hwnd is None or not hwnd or not _user32.IsWindowVisible(hwnd):
            return True
        length = _user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            title_buffer = ctypes.create_unicode_buffer(length + 1)
            if _user32.GetWindowTextW(hwnd, title_buffer, length + 1) > 0 and title_buffer.value:
                titles.append(title_buffer.value)
        return True

    callback = _WNDENUMPROC(enum_windows_callback)
    _user32.EnumWindows(callback, 0)
    return titles


def send_arp_win32(destination_ip: int, source_ip: int) -> tuple[int, bytes]:
    """Send an IPv4 ARP request via Win32 SendARP and return (error_code, 6_byte_mac)."""
    if sys.platform != 'win32':
        return (1, b'')
    # Allocate 8 bytes for physical address buffer as mandated by MSDN (at least two ULONGs)
    mac_address_buffer = (ctypes.c_ubyte * 8)()
    mac_address_length = wintypes.DWORD(6)
    result = int(
        _iphlpapi.SendARP(
            wintypes.DWORD(destination_ip),
            wintypes.DWORD(source_ip),
            ctypes.byref(mac_address_buffer),
            ctypes.byref(mac_address_length),
        ),
    )
    if not result:
        return (0, bytes(mac_address_buffer[:6]))
    return (result, b'')
