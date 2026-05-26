"""Windows Authenticode signature validation via the WinVerifyTrust API."""

import ctypes
import ctypes.wintypes
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


# pylint: disable=too-few-public-methods
class _Guid(ctypes.Structure):
    _fields_ = [
        ('Data1', ctypes.c_ulong),
        ('Data2', ctypes.c_ushort),
        ('Data3', ctypes.c_ushort),
        ('Data4', ctypes.c_ubyte * 8),
    ]


class _WintrustFileInfo(ctypes.Structure):
    _fields_ = [
        ('cbStruct',       ctypes.wintypes.DWORD),
        ('pcwszFilePath',  ctypes.c_wchar_p),
        ('hFile',          ctypes.wintypes.HANDLE),
        ('pgKnownSubject', ctypes.c_void_p),
    ]

    def __init__(self, path: str) -> None:
        super().__init__()
        # pylint: disable=invalid-name
        self.cbStruct = ctypes.sizeof(_WintrustFileInfo)
        self.pcwszFilePath = path
        self.hFile = None
        self.pgKnownSubject = None
        # pylint: enable=invalid-name


class _WintrustData(ctypes.Structure):
    _fields_ = [
        ('cbStruct',            ctypes.wintypes.DWORD),
        ('pPolicyCallbackData', ctypes.c_void_p),
        ('pSIPClientData',      ctypes.c_void_p),
        ('dwUIChoice',          ctypes.wintypes.DWORD),
        ('fdwRevocationChecks', ctypes.wintypes.DWORD),
        ('dwUnionChoice',       ctypes.wintypes.DWORD),
        ('pFile',               ctypes.c_void_p),
        ('dwStateAction',       ctypes.wintypes.DWORD),
        ('hWVTStateData',       ctypes.wintypes.HANDLE),
        ('pwszURLReference',    ctypes.c_wchar_p),
        ('dwProvFlags',         ctypes.wintypes.DWORD),
        ('dwUIContext',         ctypes.wintypes.DWORD),
    ]

    def __init__(self, file_info: _WintrustFileInfo) -> None:
        super().__init__()
        # pylint: disable=invalid-name
        self.cbStruct = ctypes.sizeof(_WintrustData)
        self.pPolicyCallbackData = None
        self.pSIPClientData = None
        self.dwUIChoice = _WTD_UI_NONE
        self.fdwRevocationChecks = _WTD_REVOKE_NONE
        self.dwUnionChoice = _WTD_CHOICE_FILE
        self.pFile = ctypes.cast(ctypes.byref(file_info), ctypes.c_void_p)
        self.dwStateAction = _WTD_STATEACTION_VERIFY
        self.hWVTStateData = None
        self.pwszURLReference = None
        self.dwProvFlags = 0
        self.dwUIContext = 0
        # pylint: enable=invalid-name
# pylint: enable=too-few-public-methods


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 0x00000001
_WTD_STATEACTION_CLOSE = 0x00000002

# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _Guid(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

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
    therefore return `False`.
    """
    file_info = _WintrustFileInfo(str(path))
    trust_data = _WintrustData(file_info)

    result = _WinVerifyTrust(
        None,
        ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(trust_data),
    )

    # Always release the state handle regardless of verification outcome
    trust_data.dwStateAction = _WTD_STATEACTION_CLOSE
    _WinVerifyTrust(
        None,
        ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(trust_data),
    )

    return not result
