"""Windows-specific ctypes helpers for capture utilities."""

import ctypes
import logging
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

if sys.platform == 'win32':
    import winreg

logger = logging.getLogger(__name__)

_NPCAP_ADAPTERS_KEY = r'SYSTEM\CurrentControlSet\Services\npcap\Parameters\Adapters'
_NPCAP_NDIS_ADAPTERS_KEY = r'SYSTEM\CurrentControlSet\Services\npcap\Parameters\NdisAdapters'
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SW_HIDE = 0
_BINDING_TIMEOUT_MS = 15_000
_GUID_BODY_LENGTH = 36
_HEX_GUID_CHARS = frozenset('0123456789ABCDEF-')
_attempted_binding_guids: set[str] = set()

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

    class _ShellExecuteInfoW(ctypes.Structure):
        """ctypes definition for SHELLEXECUTEINFOW structure."""

        _fields_ = [
            ('cbSize', wintypes.DWORD),
            ('fMask', wintypes.ULONG),
            ('hwnd', wintypes.HWND),
            ('lpVerb', wintypes.LPCWSTR),
            ('lpFile', wintypes.LPCWSTR),
            ('lpParameters', wintypes.LPCWSTR),
            ('lpDirectory', wintypes.LPCWSTR),
            ('nShow', ctypes.c_int),
            ('hInstApp', wintypes.HINSTANCE),
            ('lpIDList', ctypes.c_void_p),
            ('lpClass', wintypes.LPCWSTR),
            ('hkeyClass', wintypes.HKEY),
            ('dwHotKey', wintypes.DWORD),
            ('hIconOrMonitor', wintypes.HANDLE),
            ('hProcess', wintypes.HANDLE),
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

    _shell32 = ctypes.windll.shell32
    _shell32.IsUserAnAdmin.argtypes = []
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL
    _shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfoW)]
    _shell32.ShellExecuteExW.restype = wintypes.BOOL

    _kernel32 = ctypes.windll.kernel32
    _kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    _kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
else:
    _SC_MANAGER_CONNECT = 0
    _SERVICE_QUERY_STATUS = 0
    _SERVICE_RUNNING = 0


def get_system32_dir() -> Path:
    """Return the System32 path via the Win32 API, bypassing environment variables."""
    if sys.platform != 'win32':
        return Path('/bin')
    buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    _kernel32.GetSystemDirectoryW(buf, wintypes.MAX_PATH)
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


def _normalize_adapter_guid(adapter_guid: str) -> str | None:
    """Validate and normalize an adapter GUID string to uppercase '{...}' format."""
    cleaned = adapter_guid.strip().strip('{}').upper()
    if len(cleaned) != _GUID_BODY_LENGTH or any(ch not in _HEX_GUID_CHARS for ch in cleaned):
        return None
    return f'{{{cleaned}}}'


def extract_npcap_device_guid(device_name: str) -> str | None:
    r"""Extract the normalized '{GUID}' from an Npcap device name such as '\Device\NPF_{...}'."""
    prefix = '\\Device\\NPF_'
    idx = device_name.find(prefix)
    if idx != -1:
        return _normalize_adapter_guid(device_name[idx + len(prefix) :])
    return _normalize_adapter_guid(device_name)


def _has_registry_subkey(parent_key_path: str, subkey_name: str) -> bool:
    r"""Return whether a subkey exists under HKLM\<parent_key_path>."""
    if sys.platform == 'win32':
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'{parent_key_path}\\{subkey_name}'):
                return True
        except OSError:
            return False
    return False


def is_npcap_adapter_bound(adapter_guid: str) -> bool:
    """Return whether the Npcap NDIS filter driver is currently bound to the given adapter GUID."""
    if sys.platform != 'win32':
        return True
    normalized = _normalize_adapter_guid(adapter_guid)
    if normalized is None:
        return True
    return _has_registry_subkey(_NPCAP_ADAPTERS_KEY, normalized)


def is_ndis_adapter_registered(adapter_guid: str) -> bool:
    """Return whether the adapter GUID is registered in Npcap's known NDIS adapters list."""
    if sys.platform != 'win32':
        return False
    normalized = _normalize_adapter_guid(adapter_guid)
    if normalized is None:
        return False
    return _has_registry_subkey(_NPCAP_NDIS_ADAPTERS_KEY, normalized)


def reset_npcap_binding_repair_attempts() -> None:
    """Clear the set of adapter GUIDs for which automatic Npcap binding repair was already attempted."""
    _attempted_binding_guids.clear()


def is_admin() -> bool:
    """Return whether the current process is running with administrative elevation."""
    if sys.platform != 'win32':
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except OSError:
        return False


def run_elevated_powershell_command(ps_command: str, *, timeout_ms: int = _BINDING_TIMEOUT_MS) -> bool:
    """Execute a PowerShell command with administrative privileges, requesting UAC elevation if needed."""
    if sys.platform != 'win32':
        return False
    ps_exe = get_system32_dir() / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    if not ps_exe.is_file():
        return False

    if is_admin():
        try:
            subprocess.run(
                [
                    str(ps_exe),
                    '-NoProfile',
                    '-NonInteractive',
                    '-ExecutionPolicy',
                    'Bypass',
                    '-WindowStyle',
                    'Hidden',
                    '-Command',
                    ps_command,
                ],
                check=False,
                capture_output=True,
                timeout=max(1.0, timeout_ms / 1000.0),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError):
            logger.debug('Failed to execute elevated PowerShell subprocess', exc_info=True)
            return False
        return True

    params = f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_command}"'
    sei = _ShellExecuteInfoW(
        cbSize=ctypes.sizeof(_ShellExecuteInfoW),
        fMask=_SEE_MASK_NOCLOSEPROCESS,
        lpVerb='runas',
        lpFile=str(ps_exe),
        lpParameters=params,
        nShow=_SW_HIDE,
    )
    if not _shell32.ShellExecuteExW(ctypes.byref(sei)):
        logger.debug('User declined or failed UAC elevation for PowerShell command')
        return False
    if sei.hProcess:
        try:
            _kernel32.WaitForSingleObject(sei.hProcess, timeout_ms)
        finally:
            _kernel32.CloseHandle(sei.hProcess)
    return True


def try_enable_npcap_adapter_binding(adapter_guid: str) -> bool:
    """Attempt to enable the 'INSECURE_NPCAP' NDIS filter binding on the given adapter GUID.

    When the current process is already elevated, runs the PowerShell cmdlet directly.
    Otherwise, requests elevation via ShellExecuteExW ('runas') at most once per adapter GUID
    until reset_npcap_binding_repair_attempts() is called.
    """
    if sys.platform != 'win32':
        return False
    normalized = _normalize_adapter_guid(adapter_guid)
    if normalized is None or normalized in _attempted_binding_guids:
        return False

    _attempted_binding_guids.add(normalized)
    ps_command = (
        f"Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq '{normalized}' }} "
        "| Enable-NetAdapterBinding -ComponentID 'INSECURE_NPCAP' -Confirm:$false -ErrorAction Stop"
    )
    if not run_elevated_powershell_command(ps_command):
        return False

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if is_npcap_adapter_bound(normalized):
            return True
        time.sleep(0.1)
    return is_npcap_adapter_bound(normalized)
