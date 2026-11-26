"""Common Windows ctypes structures, COM helpers, and Win32 system bindings."""

import contextlib
import ctypes
import itertools
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SW_HIDE = 0
_SW_RESTORE = 9
_ASFW_ANY = 0xFFFFFFFF
_ERROR_ACCESS_DENIED = 5
_ERROR_ALREADY_EXISTS = 183
_DEFAULT_ELEVATION_TIMEOUT_MS = 15_000
_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_TERMINATE = 0x0001
_GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002
_GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004
_SIGABRT = 22
_WM_DESTROY = 0x0002
_WM_CLOSE = 0x0010
_WM_INPUT = 0x00FF
_WM_TIMER = 0x0113
_HWND_MESSAGE = -3
_HID_USAGE_PAGE_GENERIC = 0x01
_HID_USAGE_GENERIC_KEYBOARD = 0x06
_RIDEV_REMOVE = 0x00000001
_RIDEV_INPUTSINK = 0x00000100
_RID_INPUT = 0x10000003
_RIM_TYPEKEYBOARD = 1
_RI_KEY_BREAK = 0x01
_RI_KEY_E0 = 0x02
_RAW_KEYBOARD_OVERRUN_VK = 0xFF
_RAW_INPUT_BUFFER_SIZE = 64
_RAW_INPUT_ERROR = 0xFFFFFFFF
_RAW_INPUT_POLL_TIMER_ID = 1
_VK_SHIFT = 0x10
_VK_CONTROL = 0x11
_VK_MENU = 0x12
_VK_LWIN = 0x5B
_VK_RWIN = 0x5C
_ASYNC_KEY_DOWN_MASK = 0x8000
WIN32_MOD_ALT = 0x0001
WIN32_MOD_CONTROL = 0x0002
WIN32_MOD_SHIFT = 0x0004
WIN32_MOD_WIN = 0x0008
_SND_ASYNC = 0x0001
_SND_NODEFAULT = 0x0002
_SND_MEMORY = 0x0004
_CLSCTX_INPROC_SERVER = 0x1
_INET_FW_POLICY2_GET_CURRENT_PROFILE_TYPES_VTABLE_INDEX = 7
NET_FW_PROFILE2_DOMAIN = 0x1
NET_FW_PROFILE2_PRIVATE = 0x2
NET_FW_PROFILE2_PUBLIC = 0x4


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


class _RawInputDevice(ctypes.Structure):
    """ctypes definition for RAWINPUTDEVICE structure."""

    _fields_ = [
        ('usUsagePage', wintypes.USHORT),
        ('usUsage', wintypes.USHORT),
        ('dwFlags', wintypes.DWORD),
        ('hwndTarget', wintypes.HWND),
    ]


class _RawInputHeader(ctypes.Structure):
    """ctypes definition for RAWINPUTHEADER structure."""

    _fields_ = [
        ('dwType', wintypes.DWORD),
        ('dwSize', wintypes.DWORD),
        ('hDevice', wintypes.HANDLE),
        ('wParam', wintypes.WPARAM),
    ]


class _RawKeyboard(ctypes.Structure):
    """ctypes definition for RAWKEYBOARD structure."""

    _fields_ = [
        ('MakeCode', wintypes.USHORT),
        ('Flags', wintypes.USHORT),
        ('Reserved', wintypes.USHORT),
        ('VKey', wintypes.USHORT),
        ('Message', wintypes.UINT),
        ('ExtraInformation', wintypes.ULONG),
    ]


class _RawInputKeyboard(ctypes.Structure):
    """ctypes definition for keyboard RAWINPUT structure."""

    _fields_ = [
        ('header', _RawInputHeader),
        ('keyboard', _RawKeyboard),
    ]


class _WndClassExW(ctypes.Structure):
    """ctypes definition for WNDCLASSEXW structure."""

    _fields_ = [
        ('cbSize', wintypes.UINT),
        ('style', wintypes.UINT),
        ('lpfnWndProc', ctypes.c_void_p),
        ('cbClsExtra', ctypes.c_int),
        ('cbWndExtra', ctypes.c_int),
        ('hInstance', wintypes.HINSTANCE),
        ('hIcon', wintypes.HICON),
        ('hCursor', wintypes.HANDLE),
        ('hbrBackground', wintypes.HBRUSH),
        ('lpszMenuName', wintypes.LPCWSTR),
        ('lpszClassName', wintypes.LPCWSTR),
        ('hIconSm', wintypes.HICON),
    ]


_CLSID_SHELL_LINK = WindowsGuid(0x00021401, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_IID_ISHELL_LINK_W = WindowsGuid(0x000214F9, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_IID_IPERSIST_FILE = WindowsGuid(0x0000010B, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_CLSID_NET_FW_POLICY2 = WindowsGuid(0xE2B3C97F, 0x6AE1, 0x41AC, (ctypes.c_ubyte * 8)(0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD))
_IID_INET_FW_POLICY2 = WindowsGuid(0x98325047, 0xC671, 0x4174, (ctypes.c_ubyte * 8)(0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86))


_crt_state: dict[str, Any] = {
    'installed': False,
    'c_invalid_param_handler': None,
    'c_purecall_handler': None,
    'c_sigabrt_handler': None,
    'prev_sigabrt_handler': 0,
}
_raw_input_class_counter = itertools.count(1)
_wav_memory_state: dict[str, Any] = {
    'active_buffer': None,
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
    _WNDPROC_TYPE = ctypes.WINFUNCTYPE(
        ctypes.c_ssize_t,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )

    _shell32 = ctypes.windll.shell32
    _shell32.IsUserAnAdmin.argtypes = []
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL
    _shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfoW)]
    _shell32.ShellExecuteExW.restype = wintypes.BOOL

    _winmm = ctypes.windll.winmm
    _winmm.PlaySoundW.argtypes = [ctypes.c_void_p, wintypes.HMODULE, wintypes.DWORD]
    _winmm.PlaySoundW.restype = wintypes.BOOL

    _user32 = ctypes.windll.user32
    _user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
    _user32.MessageBoxW.restype = ctypes.c_int
    _user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    _user32.GetAsyncKeyState.restype = wintypes.SHORT
    _user32.VkKeyScanW.argtypes = [wintypes.WCHAR]
    _user32.VkKeyScanW.restype = wintypes.SHORT
    _user32.RegisterRawInputDevices.argtypes = [ctypes.POINTER(_RawInputDevice), wintypes.UINT, wintypes.UINT]
    _user32.RegisterRawInputDevices.restype = wintypes.BOOL
    _user32.GetRawInputData.argtypes = [
        wintypes.HANDLE,
        wintypes.UINT,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.UINT),
        wintypes.UINT,
    ]
    _user32.GetRawInputData.restype = wintypes.UINT
    _user32.RegisterClassExW.argtypes = [ctypes.POINTER(_WndClassExW)]
    _user32.RegisterClassExW.restype = wintypes.ATOM
    _user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    _user32.UnregisterClassW.restype = wintypes.BOOL
    _user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    _user32.CreateWindowExW.restype = wintypes.HWND
    _user32.DestroyWindow.argtypes = [wintypes.HWND]
    _user32.DestroyWindow.restype = wintypes.BOOL
    _user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.DefWindowProcW.restype = ctypes.c_ssize_t
    _user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.PostMessageW.restype = wintypes.BOOL
    _user32.PostQuitMessage.argtypes = [ctypes.c_int]
    _user32.PostQuitMessage.restype = None
    _user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    _user32.GetMessageW.restype = wintypes.BOOL
    _user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _user32.TranslateMessage.restype = wintypes.BOOL
    _user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _user32.DispatchMessageW.restype = ctypes.c_ssize_t
    _user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, wintypes.LPVOID]
    _user32.SetTimer.restype = ctypes.c_size_t
    _user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
    _user32.KillTimer.restype = wintypes.BOOL
    _user32.AllowSetForegroundWindow.argtypes = [wintypes.DWORD]
    _user32.AllowSetForegroundWindow.restype = wintypes.BOOL
    _user32.BringWindowToTop.argtypes = [wintypes.HWND]
    _user32.BringWindowToTop.restype = wintypes.BOOL
    _user32.IsIconic.argtypes = [wintypes.HWND]
    _user32.IsIconic.restype = wintypes.BOOL
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype = wintypes.BOOL
    _user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.ShowWindow.restype = wintypes.BOOL

    _kernel32 = ctypes.windll.kernel32
    _kernel32_last_error = ctypes.WinDLL('kernel32', use_last_error=True)
    _kernel32_last_error.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    _kernel32_last_error.CreateMutexW.restype = wintypes.HANDLE
    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype = wintypes.HMODULE
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
    _kernel32.RtlCaptureStackBackTrace.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.RtlCaptureStackBackTrace.restype = wintypes.WORD
    _kernel32.GetModuleHandleExW.argtypes = [
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _kernel32.GetModuleHandleExW.restype = wintypes.BOOL
    _kernel32.GetModuleFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    _kernel32.GetModuleFileNameW.restype = wintypes.DWORD

    _ole32 = ctypes.windll.ole32
    _ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _ole32.CoInitializeEx.restype = wintypes.HRESULT
    _ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(WindowsGuid),
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(WindowsGuid),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _ole32.CoCreateInstance.restype = wintypes.HRESULT
    _ole32.CLSIDFromProgID.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(WindowsGuid)]
    _ole32.CLSIDFromProgID.restype = wintypes.HRESULT
    _ole32.CoUninitialize.argtypes = []
    _ole32.CoUninitialize.restype = None
else:
    _INVALID_PARAM_HANDLER_TYPE = None
    _PURECALL_HANDLER_TYPE = None
    _SIGNAL_HANDLER_TYPE = None
    _WNDPROC_TYPE = None


def get_com_vtable_entry(pointer: wintypes.LPVOID, method_index: int) -> int:
    """Return the COM vtable method address at *method_index* for *pointer*."""
    vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return int(vtable[method_index] or 0)


def query_com_interface(pointer: wintypes.LPVOID, iid: WindowsGuid) -> wintypes.LPVOID:
    """Query *pointer* for *iid* via IUnknown::QueryInterface, returning a null LPVOID on failure."""
    result_ptr = wintypes.LPVOID()
    if sys.platform != 'win32' or not pointer:
        return result_ptr
    query_interface = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        ctypes.POINTER(WindowsGuid),
        ctypes.POINTER(wintypes.LPVOID),
    )(get_com_vtable_entry(pointer, 0))
    if query_interface(pointer, ctypes.byref(iid), ctypes.byref(result_ptr)):
        return wintypes.LPVOID()
    return result_ptr


def release_com_interface(pointer: wintypes.LPVOID) -> None:
    """Releases a COM interface pointer via its IUnknown vtable."""
    if sys.platform == 'win32' and pointer:
        release_function = ctypes.WINFUNCTYPE(wintypes.ULONG, wintypes.LPVOID)(get_com_vtable_entry(pointer, 2))
        release_function(pointer)


def co_initialize_ex(coinit_flags: int = 2) -> bool:
    """Initialize COM on the calling thread and return whether CoUninitialize must be called."""
    if sys.platform != 'win32':
        return False
    return int(_ole32.CoInitializeEx(None, coinit_flags)) in (0, 1)


def co_uninitialize() -> None:
    """Uninitialize COM on the calling thread."""
    if sys.platform == 'win32':
        _ole32.CoUninitialize()


def clsid_from_progid(progid: str) -> WindowsGuid | None:
    """Resolve a COM ProgID string to its WindowsGuid CLSID, or None on failure."""
    if sys.platform != 'win32':
        return None
    clsid = WindowsGuid()
    if _ole32.CLSIDFromProgID(progid, ctypes.byref(clsid)):
        return None
    return clsid


def co_create_instance(clsid: WindowsGuid, clsctx: int, iid: WindowsGuid) -> wintypes.LPVOID:
    """Create a COM object instance for *clsid* and *iid*, returning a null LPVOID on failure."""
    instance_ptr = wintypes.LPVOID()
    if sys.platform != 'win32':
        return instance_ptr
    if _ole32.CoCreateInstance(ctypes.byref(clsid), None, clsctx, ctypes.byref(iid), ctypes.byref(instance_ptr)):
        return wintypes.LPVOID()
    return instance_ptr


def get_active_windows_firewall_profiles() -> int:
    """Return the active Windows Defender Firewall profile bitmask (`NET_FW_PROFILE2_*`), or `0` if unavailable."""
    if sys.platform != 'win32':
        return 0
    need_uninit = co_initialize_ex(2)
    try:
        policy_ptr = co_create_instance(_CLSID_NET_FW_POLICY2, _CLSCTX_INPROC_SERVER, _IID_INET_FW_POLICY2)
        if not policy_ptr:
            return 0
        try:
            vtable_addr = get_com_vtable_entry(policy_ptr, _INET_FW_POLICY2_GET_CURRENT_PROFILE_TYPES_VTABLE_INDEX)
            if not vtable_addr:
                return 0
            get_profiles = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, ctypes.POINTER(ctypes.c_long))(vtable_addr)
            profile_mask = ctypes.c_long(0)
            if get_profiles(policy_ptr, ctypes.byref(profile_mask)):
                return 0
            return profile_mask.value
        finally:
            release_com_interface(policy_ptr)
    finally:
        if need_uninit:
            co_uninitialize()


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


def vk_key_scan_win32(character: str) -> tuple[int, int] | None:
    """Resolve a single character to `(vk_code, shift_state)` on the active Windows keyboard layout."""
    if sys.platform != 'win32' or len(character) != 1:
        return None
    scanned = int(_user32.VkKeyScanW(character))
    if scanned == -1:
        return None
    return scanned & 0xFF, (scanned >> 8) & 0xFF


def is_win32_vk_down(vk_code: int) -> bool:
    """Return whether *vk_code* is currently physically held down according to GetAsyncKeyState."""
    if sys.platform != 'win32':
        return False
    return bool(_user32.GetAsyncKeyState(vk_code) & _ASYNC_KEY_DOWN_MASK)


def get_win32_active_modifiers() -> int:
    """Return the active Win32 modifier bitmask (`WIN32_MOD_*`) from GetAsyncKeyState."""
    if sys.platform != 'win32':
        return 0
    modifiers = 0
    if _user32.GetAsyncKeyState(_VK_CONTROL) & _ASYNC_KEY_DOWN_MASK:
        modifiers |= WIN32_MOD_CONTROL
    if _user32.GetAsyncKeyState(_VK_SHIFT) & _ASYNC_KEY_DOWN_MASK:
        modifiers |= WIN32_MOD_SHIFT
    if _user32.GetAsyncKeyState(_VK_MENU) & _ASYNC_KEY_DOWN_MASK:
        modifiers |= WIN32_MOD_ALT
    if (_user32.GetAsyncKeyState(_VK_LWIN) | _user32.GetAsyncKeyState(_VK_RWIN)) & _ASYNC_KEY_DOWN_MASK:
        modifiers |= WIN32_MOD_WIN
    return modifiers


def stop_win32_message_window(hwnd: int) -> None:
    """Post `WM_CLOSE` to a message-only Win32 window so its message loop exits cleanly."""
    if sys.platform == 'win32' and hwnd:
        _user32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)


def run_win32_raw_keyboard_message_loop(
    on_raw_key: Callable[[tuple[int, bool, bool]], None],
    on_poll_tick: Callable[[], None],
    on_ready: Callable[[tuple[int | None, bool]], None],
    *,
    poll_interval_ms: int = 20,
) -> None:
    """Run a message-only Win32 window receiving non-consuming Raw Input keyboard events and periodic timer ticks."""
    if sys.platform != 'win32':
        on_ready((None, False))
        return

    raw_buffer = ctypes.create_string_buffer(_RAW_INPUT_BUFFER_SIZE)
    raw_input_registered = False

    def _unregister_raw_keyboard() -> None:
        nonlocal raw_input_registered
        if not raw_input_registered:
            return
        raw_input_registered = False
        unregister_device = _RawInputDevice(
            _HID_USAGE_PAGE_GENERIC,
            _HID_USAGE_GENERIC_KEYBOARD,
            _RIDEV_REMOVE,
            None,
        )
        _user32.RegisterRawInputDevices(
            ctypes.byref(unregister_device),
            1,
            ctypes.sizeof(_RawInputDevice),
        )

    def _window_proc(hwnd: int, message: int, w_param: int, l_param: int) -> int:
        if message == _WM_INPUT and l_param:
            data_size = wintypes.UINT(_RAW_INPUT_BUFFER_SIZE)
            bytes_read = int(
                _user32.GetRawInputData(
                    wintypes.HANDLE(l_param),
                    _RID_INPUT,
                    raw_buffer,
                    ctypes.byref(data_size),
                    ctypes.sizeof(_RawInputHeader),
                ),
            )
            if bytes_read != _RAW_INPUT_ERROR and bytes_read >= ctypes.sizeof(_RawInputKeyboard):
                raw_input = _RawInputKeyboard.from_buffer(raw_buffer)
                if raw_input.header.dwType == _RIM_TYPEKEYBOARD:
                    vk_code = int(raw_input.keyboard.VKey)
                    if vk_code != _RAW_KEYBOARD_OVERRUN_VK:
                        flags = int(raw_input.keyboard.Flags)
                        on_raw_key((vk_code, not bool(flags & _RI_KEY_BREAK), bool(flags & _RI_KEY_E0)))
        elif message == _WM_TIMER and w_param == _RAW_INPUT_POLL_TIMER_ID:
            on_poll_tick()
            return 0
        elif message == _WM_CLOSE:
            _user32.KillTimer(hwnd, _RAW_INPUT_POLL_TIMER_ID)
            _unregister_raw_keyboard()
            _user32.DestroyWindow(hwnd)
            return 0
        elif message == _WM_DESTROY:
            _user32.PostQuitMessage(0)
            return 0
        return int(_user32.DefWindowProcW(hwnd, message, w_param, l_param))

    c_wnd_proc = _WNDPROC_TYPE(_window_proc)
    module_handle = _kernel32.GetModuleHandleW(None)
    class_name = f'SessionSnifferRawInputWindow_{next(_raw_input_class_counter)}'
    wnd_class = _WndClassExW(
        cbSize=ctypes.sizeof(_WndClassExW),
        lpfnWndProc=ctypes.cast(c_wnd_proc, ctypes.c_void_p).value,
        hInstance=module_handle,
        lpszClassName=class_name,
    )
    if not _user32.RegisterClassExW(ctypes.byref(wnd_class)):
        on_ready((None, False))
        return

    try:
        hwnd = _user32.CreateWindowExW(
            0,
            class_name,
            None,
            0,
            0,
            0,
            0,
            0,
            wintypes.HWND(_HWND_MESSAGE),
            None,
            module_handle,
            None,
        )
        if not hwnd:
            on_ready((None, False))
            return

        keyboard_device = _RawInputDevice(
            _HID_USAGE_PAGE_GENERIC,
            _HID_USAGE_GENERIC_KEYBOARD,
            _RIDEV_INPUTSINK,
            hwnd,
        )
        raw_input_registered = bool(
            _user32.RegisterRawInputDevices(
                ctypes.byref(keyboard_device),
                1,
                ctypes.sizeof(_RawInputDevice),
            ),
        )
        _user32.SetTimer(hwnd, _RAW_INPUT_POLL_TIMER_ID, poll_interval_ms, None)
        on_ready((int(hwnd), raw_input_registered))

        win_message = wintypes.MSG()
        while _user32.GetMessageW(ctypes.byref(win_message), None, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(win_message))
            _user32.DispatchMessageW(ctypes.byref(win_message))
    finally:
        _unregister_raw_keyboard()
        _user32.UnregisterClassW(class_name, module_handle)


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

    need_uninit = co_initialize_ex(2)
    shell_link_ptr = co_create_instance(_CLSID_SHELL_LINK, 1, _IID_ISHELL_LINK_W)
    if not shell_link_ptr:
        if need_uninit:
            co_uninitialize()
        return shortcut_path

    try:
        get_path = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )(get_com_vtable_entry(shell_link_ptr, 3))

        persist_file_ptr = query_com_interface(shell_link_ptr, _IID_IPERSIST_FILE)
        if persist_file_ptr:
            try:
                load = ctypes.WINFUNCTYPE(
                    wintypes.HRESULT,
                    wintypes.LPVOID,
                    wintypes.LPCWSTR,
                    wintypes.DWORD,
                )(get_com_vtable_entry(persist_file_ptr, 5))

                if not load(persist_file_ptr, str(shortcut_path), 0):
                    path_buffer = ctypes.create_unicode_buffer(1024)
                    if not get_path(shell_link_ptr, path_buffer, 1024, None, 0) and path_buffer.value:
                        return Path(path_buffer.value)
            finally:
                release_com_interface(persist_file_ptr)
    finally:
        release_com_interface(shell_link_ptr)
        if need_uninit:
            co_uninitialize()

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
            module_flags = _GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | _GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
            if _kernel32.GetModuleHandleExW(module_flags, ctypes.c_void_p(address), ctypes.byref(h_module)):
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
            with contextlib.suppress(OSError, ctypes.ArgumentError):
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
    except AttributeError, OSError:
        return False
    return True


def play_wav_memory_async(wav_bytes: bytes) -> bool:
    """Play an in-memory WAV image asynchronously via Win32 `PlaySoundW` (`SND_MEMORY | SND_ASYNC | SND_NODEFAULT`)."""
    if sys.platform != 'win32' or not wav_bytes:
        return False
    new_buffer = ctypes.create_string_buffer(wav_bytes, len(wav_bytes))
    played = bool(_winmm.PlaySoundW(new_buffer, None, _SND_MEMORY | _SND_NODEFAULT | _SND_ASYNC))
    if played:
        _wav_memory_state['active_buffer'] = new_buffer
    return played


def acquire_win32_named_mutex(mutex_name: str) -> tuple[int | None, bool]:
    """Create or open a named Win32 mutex and return `(handle, already_exists)`.

    Returns `(handle, False)` when this process exclusively created the mutex, and
    `(None, True)` when another process in the same session already owns it (including
    an elevated instance that triggers `ERROR_ACCESS_DENIED`).
    """
    if sys.platform != 'win32':
        return None, False
    ctypes.set_last_error(0)
    handle = _kernel32_last_error.CreateMutexW(None, 0, mutex_name)
    last_error = ctypes.get_last_error()
    if not handle:
        return None, last_error == _ERROR_ACCESS_DENIED
    if last_error == _ERROR_ALREADY_EXISTS:
        _kernel32.CloseHandle(handle)
        return None, True
    return int(handle), False


def release_win32_handle(handle: int) -> None:
    """Close a Win32 kernel handle previously returned by a low-level binding."""
    if sys.platform == 'win32' and handle:
        _kernel32.CloseHandle(wintypes.HANDLE(handle))


def allow_set_foreground_window(process_id: int | None = None) -> bool:
    """Grant foreground-activation permission to *process_id* (or `ASFW_ANY` when omitted)."""
    if sys.platform != 'win32':
        return False
    target_pid = process_id if process_id is not None and process_id > 0 else _ASFW_ANY
    return bool(_user32.AllowSetForegroundWindow(target_pid))


def focus_win32_window(hwnd: int) -> None:
    """Restore if minimized, raise to top, and bring *hwnd* to the foreground via Win32 User32."""
    if sys.platform != 'win32' or not hwnd:
        return
    if _user32.IsIconic(hwnd):
        _user32.ShowWindow(hwnd, _SW_RESTORE)
    _user32.BringWindowToTop(hwnd)
    _user32.SetForegroundWindow(hwnd)
