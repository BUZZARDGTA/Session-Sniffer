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
