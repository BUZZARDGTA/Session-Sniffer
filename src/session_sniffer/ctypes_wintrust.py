"""Windows Authenticode signature validation via the WinVerifyTrust API."""

import ctypes
import ctypes.wintypes
import sys
from typing import TYPE_CHECKING

from session_sniffer.ctypes_windows import WindowsGuid as _Guid

if TYPE_CHECKING:
    from pathlib import Path


class _WintrustFileInfo(ctypes.Structure):
    _fields_ = [
        ('cb_struct', ctypes.wintypes.DWORD),
        ('pcwsz_file_path', ctypes.c_wchar_p),
        ('h_file', ctypes.wintypes.HANDLE),
        ('pg_known_subject', ctypes.c_void_p),
    ]

    def __init__(self, path: str) -> None:
        super().__init__()
        self.cb_struct = ctypes.sizeof(_WintrustFileInfo)
        self.pcwsz_file_path = path
        self.h_file = None
        self.pg_known_subject = None


class _WintrustData(ctypes.Structure):
    _fields_ = [
        ('cb_struct', ctypes.wintypes.DWORD),
        ('p_policy_callback_data', ctypes.c_void_p),
        ('p_sip_client_data', ctypes.c_void_p),
        ('dw_ui_choice', ctypes.wintypes.DWORD),
        ('fdw_revocation_checks', ctypes.wintypes.DWORD),
        ('dw_union_choice', ctypes.wintypes.DWORD),
        ('p_file', ctypes.c_void_p),
        ('dw_state_action', ctypes.wintypes.DWORD),
        ('h_wvt_state_data', ctypes.wintypes.HANDLE),
        ('pwsz_url_reference', ctypes.c_wchar_p),
        ('dw_prov_flags', ctypes.wintypes.DWORD),
        ('dw_ui_context', ctypes.wintypes.DWORD),
    ]

    def __init__(self, file_info: _WintrustFileInfo) -> None:
        super().__init__()
        self.cb_struct = ctypes.sizeof(_WintrustData)
        self.p_policy_callback_data = None
        self.p_sip_client_data = None
        self.dw_ui_choice = _WTD_UI_NONE
        self.fdw_revocation_checks = _WTD_REVOKE_NONE
        self.dw_union_choice = _WTD_CHOICE_FILE
        self.p_file = ctypes.cast(ctypes.byref(file_info), ctypes.c_void_p)
        self.dw_state_action = _WTD_STATEACTION_VERIFY
        self.h_wvt_state_data = None
        self.pwsz_url_reference = None
        self.dw_prov_flags = 0
        self.dw_ui_context = 0


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 0x00000001
_WTD_STATEACTION_CLOSE = 0x00000002

# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _Guid(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


if sys.platform == 'win32':
    _WinVerifyTrust = ctypes.windll.wintrust.WinVerifyTrust
    _WinVerifyTrust.argtypes = [
        ctypes.wintypes.HWND,
        ctypes.POINTER(_Guid),
        ctypes.c_void_p,
    ]
    _WinVerifyTrust.restype = ctypes.c_long


def has_valid_authenticode_signature(path: Path) -> bool:
    """Return `True` if the file at `path` carries a valid Authenticode signature.

    Uses the Windows `WinVerifyTrust` API to cryptographically validate the
    Authenticode signature embedded in the PE binary.  A fake executable that
    merely reuses a legitimate name will have no valid signature and will
    therefore return `False`. On non-Windows platforms, returns `True`.
    """
    if sys.platform != 'win32':
        return True
    file_info = _WintrustFileInfo(str(path))
    trust_data = _WintrustData(file_info)

    result = _WinVerifyTrust(
        None,
        ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(trust_data),
    )

    # Always release the state handle regardless of verification outcome
    trust_data.dw_state_action = _WTD_STATEACTION_CLOSE
    _WinVerifyTrust(
        None,
        ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(trust_data),
    )

    return not result
