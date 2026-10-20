"""Common Windows ctypes structures, COM helpers, and Win32 system bindings."""

import contextlib
import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SW_HIDE = 0
_DEFAULT_ELEVATION_TIMEOUT_MS = 15_000
_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_TERMINATE = 0x0001
_GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004
_SIGABRT = 22


class WindowsGuid(ctypes.Structure):
    """ctypes definition for Windows GUID structure."""

    _fields_ = [
        ('Data1', wintypes.DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', ctypes.c_ubyte * 8),
    ]


class ProcessEntry32W(ctypes.Structure):
    """ctypes definition for PROCESSENTRY32W structure."""

    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260),
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Initialize the PROCESSENTRY32W structure with its byte size."""
        super().__init__(*args, **kwargs)
        self.dwSize = ctypes.sizeof(self)


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


_CLSID_SHELL_LINK = WindowsGuid(0x00021401, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_IID_ISHELL_LINK_W = WindowsGuid(0x000214F9, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_IID_IPERSIST_FILE = WindowsGuid(0x0000010B, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))


_crt_state: dict[str, Any] = {
    'installed': False,
    'c_invalid_param_handler': None,
    'c_purecall_handler': None,
    'c_sigabrt_handler': None,
    'prev_sigabrt_handler': 0,
}

if sys.platform == 'win32':
    _INVALID_PARAM_HANDLER_TYPE = ctypes.CFUNCTYPE(
        None,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint,
        ctypes.c_void_p,
    )
    _PURECALL_HANDLER_TYPE = ctypes.CFUNCTYPE(None)
    _SIGNAL_HANDLER_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_int)

    _shell32 = ctypes.windll.shell32
    _shell32.IsUserAnAdmin.argtypes = []
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL
    _shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfoW)]
    _shell32.ShellExecuteExW.restype = wintypes.BOOL

    _user32 = ctypes.windll.user32
    _user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
    _user32.MessageBoxW.restype = ctypes.c_int

    _kernel32 = ctypes.windll.kernel32
    _kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    _kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
else:
    _INVALID_PARAM_HANDLER_TYPE = None
    _PURECALL_HANDLER_TYPE = None
    _SIGNAL_HANDLER_TYPE = None


def release_com_interface(pointer: wintypes.LPVOID) -> None:
    """Releases a COM interface pointer via its IUnknown vtable."""
    if pointer:
        vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        release_function = ctypes.WINFUNCTYPE(wintypes.ULONG, wintypes.LPVOID)(vtable[2])
        release_function(pointer)


def get_system32_dir() -> Path:
    """Return the System32 path via the Win32 API, bypassing environment variables."""
    if sys.platform != 'win32':
        return Path('/bin')
    buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    _kernel32.GetSystemDirectoryW(buf, wintypes.MAX_PATH)
    return Path(buf.value)


def is_admin() -> bool:
    """Return whether the current process is running with administrative elevation."""
    if sys.platform != 'win32':
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except OSError:
        return False


def shell_execute_runas(
    executable: str,
    parameters: str,
    *,
    timeout_ms: int = _DEFAULT_ELEVATION_TIMEOUT_MS,
) -> bool:
    """Launch an executable with 'runas' UAC elevation and wait up to *timeout_ms* for completion."""
    if sys.platform != 'win32':
        return False
    sei = _ShellExecuteInfoW(
        cbSize=ctypes.sizeof(_ShellExecuteInfoW),
        fMask=_SEE_MASK_NOCLOSEPROCESS,
        lpVerb='runas',
        lpFile=executable,
        lpParameters=parameters,
        nShow=_SW_HIDE,
    )
    if not _shell32.ShellExecuteExW(ctypes.byref(sei)):
        return False
    if sei.hProcess:
        try:
            _kernel32.WaitForSingleObject(sei.hProcess, timeout_ms)
        finally:
            _kernel32.CloseHandle(sei.hProcess)
    return True


def show_win32_message_box(owner_hwnd: int, text: str, title: str, style: int) -> int:
    """Display a native Win32 MessageBoxW dialog and return the selected button identifier."""
    if sys.platform != 'win32':
        return 0
    return int(_user32.MessageBoxW(owner_hwnd, text, title, style))


def iter_win32_toolhelp_processes() -> list[tuple[int, int, str]]:
    """Return a snapshot list of `(pid, parent_pid, exe_name)` for all running Windows processes via Toolhelp32."""
    if sys.platform != 'win32':
        return []
    snapshot_handle = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot_handle or snapshot_handle == wintypes.HANDLE(-1).value:
        return []
    try:
        entry = ProcessEntry32W()
        if not _kernel32.Process32FirstW(snapshot_handle, ctypes.byref(entry)):
            return []
        processes: list[tuple[int, int, str]] = []
        while True:
            processes.append((int(entry.th32ProcessID), int(entry.th32ParentProcessID), str(entry.szExeFile)))
            if not _kernel32.Process32NextW(snapshot_handle, ctypes.byref(entry)):
                break
        return processes
    finally:
        _kernel32.CloseHandle(snapshot_handle)


def terminate_win32_process(pid: int) -> None:
    """Terminate a single Windows process by *pid* via OpenProcess and TerminateProcess."""
    if sys.platform != 'win32':
        return
    handle = _kernel32.OpenProcess(_PROCESS_TERMINATE, 0, pid)
    if handle:
        _kernel32.TerminateProcess(handle, 1)
        _kernel32.CloseHandle(handle)


def resolve_lnk_win32(shortcut_path: Path) -> Path:
    """Resolve a Windows shortcut (.lnk) to its target path via IShellLinkW and IPersistFile COM interfaces."""
    if sys.platform != 'win32':
        return shortcut_path

    ole32 = ctypes.windll.ole32
    hr_init = ole32.CoInitializeEx(None, 2)
    need_uninit = hr_init in (0, 1)

    shell_link_ptr = wintypes.LPVOID()
    hr_create = ole32.CoCreateInstance(
        ctypes.byref(_CLSID_SHELL_LINK),
        None,
        1,
        ctypes.byref(_IID_ISHELL_LINK_W),
        ctypes.byref(shell_link_ptr),
    )
    if hr_create or not shell_link_ptr:
        if need_uninit:
            ole32.CoUninitialize()
        return shortcut_path

    try:
        link_vtable = ctypes.cast(shell_link_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        query_interface = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            ctypes.POINTER(WindowsGuid),
            ctypes.POINTER(wintypes.LPVOID),
        )(link_vtable[0])
        get_path = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )(link_vtable[3])

        persist_file_ptr = wintypes.LPVOID()
        if not query_interface(shell_link_ptr, ctypes.byref(_IID_IPERSIST_FILE), ctypes.byref(persist_file_ptr)) and persist_file_ptr:
            try:
                persist_vtable = ctypes.cast(persist_file_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
                load = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, wintypes.LPCWSTR, wintypes.DWORD)(persist_vtable[5])

                if not load(persist_file_ptr, str(shortcut_path), 0):
                    path_buffer = ctypes.create_unicode_buffer(1024)
                    if not get_path(shell_link_ptr, path_buffer, 1024, None, 0) and path_buffer.value:
                        return Path(path_buffer.value)
            finally:
                release_com_interface(persist_file_ptr)
    finally:
        release_com_interface(shell_link_ptr)
        if need_uninit:
            ole32.CoUninitialize()

    return shortcut_path


def capture_win32_native_stack() -> list[str]:
    """Capture native C/C++ return addresses and module offsets for the current thread on Windows."""
    lines: list[str] = []
    if sys.platform != 'win32':
        return lines
    try:
        max_frames = 32
        frames = (ctypes.c_void_p * max_frames)()
        captured_count = int(_kernel32.RtlCaptureStackBackTrace(0, max_frames, frames, None))
        buffer = ctypes.create_unicode_buffer(512)
        h_module = ctypes.c_void_p()
        lines.append(f'Native C/C++ stack trace ({captured_count} frames):')
        for index in range(captured_count):
            address = frames[index]
            if not address:
                continue
            if _kernel32.GetModuleHandleExW(_GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, ctypes.c_void_p(address), ctypes.byref(h_module)):
                _kernel32.GetModuleFileNameW(h_module, buffer, 512)
                module_name = Path(buffer.value).name
                base_address = h_module.value or 0
                offset = address - base_address
                lines.append(f'  #{index:02d}: 0x{address:016x} -> {module_name}+0x{offset:x}')
            else:
                lines.append(f'  #{index:02d}: 0x{address:016x}')
    except (AttributeError, OSError, ctypes.ArgumentError) as e:
        lines.append(f'  Failed to capture native stack: {e}')
    return lines


def install_win32_crt_handlers(on_crash: Callable[[str], None]) -> bool:
    """Install Windows CRT diagnostic handlers to intercept and report low-level aborts and asserts."""
    if sys.platform != 'win32':
        return False

    def _invalid_param_handler(
        expression: str | None,
        function: str | None,
        file: str | None,
        line: int,
        _reserved: int | None,
    ) -> None:
        on_crash(f'CRT invalid parameter detected: function={function}, file={file}:{line}, expression={expression}')

    def _purecall_handler() -> None:
        on_crash('CRT pure virtual function call detected')

    def _sigabrt_handler(sig: int) -> None:
        on_crash('SIGABRT received (C runtime abort)')
        prev_handler = int(_crt_state['prev_sigabrt_handler'])
        if prev_handler and prev_handler not in (0, 1, 0xFFFFFFFFFFFFFFFF):
            with contextlib.suppress(Exception):
                prev_fn = _SIGNAL_HANDLER_TYPE(prev_handler)
                prev_fn(sig)

    try:
        ucrt = ctypes.cdll.ucrtbase
        if not _crt_state['installed']:
            _crt_state['c_invalid_param_handler'] = _INVALID_PARAM_HANDLER_TYPE(_invalid_param_handler)
            set_invalid_param = ucrt['_set_invalid_parameter_handler']
            set_invalid_param.argtypes = [_INVALID_PARAM_HANDLER_TYPE]
            set_invalid_param.restype = ctypes.c_void_p
            set_invalid_param(_crt_state['c_invalid_param_handler'])

            _crt_state['c_purecall_handler'] = _PURECALL_HANDLER_TYPE(_purecall_handler)
            set_purecall = ucrt['_set_purecall_handler']
            set_purecall.argtypes = [_PURECALL_HANDLER_TYPE]
            set_purecall.restype = ctypes.c_void_p
            set_purecall(_crt_state['c_purecall_handler'])

            with contextlib.suppress(AttributeError, OSError):
                vcruntime_set_purecall_handler = ctypes.cdll.LoadLibrary('vcruntime140.dll')['_set_purecall_handler']
                vcruntime_set_purecall_handler.argtypes = [_PURECALL_HANDLER_TYPE]
                vcruntime_set_purecall_handler.restype = ctypes.c_void_p
                vcruntime_set_purecall_handler(_crt_state['c_purecall_handler'])

            _crt_state['c_sigabrt_handler'] = _SIGNAL_HANDLER_TYPE(_sigabrt_handler)

        ucrt_signal = ucrt.signal
        ucrt_signal.argtypes = [ctypes.c_int, _SIGNAL_HANDLER_TYPE]
        ucrt_signal.restype = ctypes.c_void_p
        raw_prev_sigabrt = ucrt_signal(_SIGABRT, _crt_state['c_sigabrt_handler'])
        prev_sigabrt_ptr = raw_prev_sigabrt if isinstance(raw_prev_sigabrt, int) else 0
        our_sigabrt_ptr = ctypes.cast(_crt_state['c_sigabrt_handler'], ctypes.c_void_p).value or 0
        if prev_sigabrt_ptr != our_sigabrt_ptr:
            _crt_state['prev_sigabrt_handler'] = prev_sigabrt_ptr
        _crt_state['installed'] = True
    except (AttributeError, OSError):
        return False
    return True
