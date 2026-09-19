"""Detect Windows Network Bridge members and Internet Connection Sharing (ICS) adapters.

Bridge detection uses the Windows registry (stdlib `winreg`).
ICS detection uses the `INetSharingManager` COM interface via `ctypes`,
which is the canonical Win32 API for querying ICS state and reliably distinguishes
the public (sharing) side from the private (shared) side.

Detection is best-effort: any failure results in the adapter being omitted from
the classification rather than raising.
"""

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Literal, cast

if sys.platform == 'win32':
    import winreg
else:
    winreg = None  # type: ignore[assignment]  # pylint: disable=invalid-name

from session_sniffer.logging_setup import get_logger  # pylint: disable=wrong-import-position

logger = get_logger(__name__)

AdapterClassification = Literal['bridged', 'shared', 'sharing']

# Registry locations used for bridge detection.
_BRIDGE_LINKAGE_KEY = r'SYSTEM\CurrentControlSet\Services\BridgeMP\Linkage'
_NETWORK_CONNECTIONS_KEY = r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'

# `\Device\` prefix used in `BridgeMP\Linkage\Bind` values.
_DEVICE_PREFIX = '\\Device\\'

# INetSharingConfiguration::SharingConnectionType values.
# https://learn.microsoft.com/en-us/windows/win32/api/netcon/ne-netcon-sharingconnectiontype
_ICSSHARINGTYPE_PUBLIC = 0  # Adapter is the public (upstream) connection being shared.
_ICSSHARINGTYPE_PRIVATE = 1  # Adapter is the private (LAN) connection serving clients.


# pylint: disable=duplicate-code
class _Guid(ctypes.Structure):
    """ctypes definition for GUID structure."""

    _fields_ = [
        ('Data1', wintypes.DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', ctypes.c_ubyte * 8),
    ]
# pylint: enable=duplicate-code


_IID_INET_SHARING_MANAGER = _Guid(0xC08956B7, 0x1CD3, 0x11D1, (ctypes.c_ubyte * 8)(0xB1, 0xC5, 0x00, 0x80, 0x5F, 0xC1, 0x27, 0x0E))
_IID_IENUM_VARIANT = _Guid(0x00020404, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))


def _normalize_guid(guid_string: str) -> str:
    """Normalizes an adapter GUID string to uppercase with braces."""
    cleaned = guid_string.strip('{}').removeprefix(_DEVICE_PREFIX).upper()
    return f'{{{cleaned}}}'


def _get_bridge_member_guids() -> set[str]:
    """Return the set of adapter GUIDs that are members of a Windows Network Bridge."""
    members: set[str] = set()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _BRIDGE_LINKAGE_KEY) as key:
            bind_value, _ = winreg.QueryValueEx(key, 'Bind')
    except OSError:
        return members

    if not isinstance(bind_value, list):
        return members

    for entry in cast('list[object]', bind_value):
        if isinstance(entry, str) and entry:
            members.add(_normalize_guid(entry))
    return members


def _find_bridge_device_guid() -> str | None:
    """Find the NetCfgInstanceId of the Network Bridge adapter, if one exists."""
    try:
        network_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NETWORK_CONNECTIONS_KEY)
    except OSError:
        return None

    with network_key:
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(network_key, index)
            except OSError:
                break
            index += 1

            if not (subkey_name.startswith('{') and subkey_name.endswith('}')):
                continue

            try:
                with winreg.OpenKey(network_key, rf'{subkey_name}\Connection') as conn_key:
                    name, _ = winreg.QueryValueEx(conn_key, 'Name')
            except OSError:
                continue

            if isinstance(name, str) and name == 'Network Bridge':
                return _normalize_guid(subkey_name)

    return None


def _find_bridge_device_guid_from_pnp() -> str | None:
    """Find the NetCfgInstanceId of the Network Bridge by checking PnpInstanceID."""
    try:
        connections_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NETWORK_CONNECTIONS_KEY)
    except OSError:
        return None

    with connections_key:
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(connections_key, index)
            except OSError:
                break
            index += 1

            if not (subkey_name.startswith('{') and subkey_name.endswith('}')):
                continue

            try:
                with winreg.OpenKey(connections_key, rf'{subkey_name}\Connection') as conn_key:
                    pnp_id, _ = winreg.QueryValueEx(conn_key, 'PnpInstanceID')
            except OSError:
                continue

            if isinstance(pnp_id, str) and 'BRIDGEMP' in pnp_id.upper():
                return _normalize_guid(subkey_name)

    return None


def _get_bridge_host_guid() -> str | None:
    """Return the GUID of the MAC Bridge Miniport adapter itself, if present."""
    return _find_bridge_device_guid() or _find_bridge_device_guid_from_pnp()


def _release_com_interface(pointer: wintypes.LPVOID) -> None:
    """Releases a COM interface pointer via its IUnknown vtable."""
    if pointer:
        vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        release_function = ctypes.WINFUNCTYPE(wintypes.ULONG, wintypes.LPVOID)(vtable[2])
        release_function(pointer)


def _classify_connection(
    manager_ptr: wintypes.LPVOID,
    connection_ptr: wintypes.LPVOID,
    oleaut32: ctypes.WinDLL,
) -> tuple[str, AdapterClassification] | None:
    """Extracts ICS role and adapter GUID for a single connection, if sharing is enabled."""
    manager_vtable = ctypes.cast(manager_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    get_configuration_for_connection = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    )(manager_vtable[10])
    get_connection_props = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID))(manager_vtable[12])

    config_ptr = wintypes.LPVOID()
    if get_configuration_for_connection(manager_ptr, connection_ptr, ctypes.byref(config_ptr)) or not config_ptr:
        return None

    try:
        config_vtable = ctypes.cast(config_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        get_sharing_enabled = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.SHORT),
        )(config_vtable[7])
        get_sharing_type = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_int),
        )(config_vtable[8])

        sharing_enabled = wintypes.SHORT()
        if get_sharing_enabled(config_ptr, ctypes.byref(sharing_enabled)) or not sharing_enabled.value:
            return None

        sharing_type = ctypes.c_int()
        get_sharing_type(config_ptr, ctypes.byref(sharing_type))

        props_ptr = wintypes.LPVOID()
        if get_connection_props(manager_ptr, connection_ptr, ctypes.byref(props_ptr)) or not props_ptr:
            return None

        try:
            props_vtable = ctypes.cast(props_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            get_guid = ctypes.WINFUNCTYPE(
                wintypes.HRESULT,
                wintypes.LPVOID,
                ctypes.POINTER(ctypes.c_wchar_p),
            )(props_vtable[7])
            bstr_guid = ctypes.c_wchar_p()
            if not get_guid(props_ptr, ctypes.byref(bstr_guid)) and bstr_guid.value:
                guid_normalized = _normalize_guid(bstr_guid.value)
                oleaut32.SysFreeString(bstr_guid)
                role: AdapterClassification | None = None
                if sharing_type.value == _ICSSHARINGTYPE_PUBLIC:
                    role = 'sharing'
                elif sharing_type.value == _ICSSHARINGTYPE_PRIVATE:
                    role = 'shared'
                if role:
                    return (guid_normalized, role)
        finally:
            _release_com_interface(props_ptr)
    finally:
        _release_com_interface(config_ptr)

    return None


def _get_enum_variant(manager_ptr: wintypes.LPVOID) -> wintypes.LPVOID:
    """Obtains the IEnumVARIANT interface for all network connections."""
    manager_vtable = ctypes.cast(manager_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    get_enum_every_connection = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID))(manager_vtable[11])

    collection_ptr = wintypes.LPVOID()
    if get_enum_every_connection(manager_ptr, ctypes.byref(collection_ptr)) or not collection_ptr:
        return wintypes.LPVOID()

    try:
        collection_vtable = ctypes.cast(collection_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        get_new_enum = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID))(collection_vtable[7])

        unknown_enum_ptr = wintypes.LPVOID()
        if get_new_enum(collection_ptr, ctypes.byref(unknown_enum_ptr)) or not unknown_enum_ptr:
            return wintypes.LPVOID()

        try:
            unknown_vtable = ctypes.cast(unknown_enum_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            query_interface_unknown = ctypes.WINFUNCTYPE(
                wintypes.HRESULT,
                wintypes.LPVOID,
                ctypes.POINTER(_Guid),
                ctypes.POINTER(wintypes.LPVOID),
            )(unknown_vtable[0])

            enum_variant_ptr = wintypes.LPVOID()
            if query_interface_unknown(unknown_enum_ptr, ctypes.byref(_IID_IENUM_VARIANT), ctypes.byref(enum_variant_ptr)) or not enum_variant_ptr:
                return wintypes.LPVOID()

            return enum_variant_ptr
        finally:
            _release_com_interface(unknown_enum_ptr)
    finally:
        _release_com_interface(collection_ptr)


def _enumerate_ics_connections(
    manager_ptr: wintypes.LPVOID,
    oleaut32: ctypes.WinDLL,
) -> dict[str, AdapterClassification]:
    """Enumerates connections from INetSharingManager and classifies sharing adapters."""
    result: dict[str, AdapterClassification] = {}
    enum_variant_ptr = _get_enum_variant(manager_ptr)
    if not enum_variant_ptr:
        return result

    try:
        enum_vtable = ctypes.cast(enum_variant_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        next_enum = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            wintypes.ULONG,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.ULONG),
        )(enum_vtable[3])

        variant_buffer = (ctypes.c_byte * 24)()
        fetched_count = wintypes.ULONG()
        while not next_enum(enum_variant_ptr, 1, ctypes.byref(variant_buffer), ctypes.byref(fetched_count)) and fetched_count.value == 1:
            connection_val = (ctypes.c_void_p.from_buffer(variant_buffer, 8)).value
            if not connection_val:
                continue
            connection_ptr = wintypes.LPVOID(connection_val)
            try:
                classified = _classify_connection(manager_ptr, connection_ptr, oleaut32)
                if classified is not None:
                    result[classified[0]] = classified[1]
            finally:
                _release_com_interface(connection_ptr)
    finally:
        _release_com_interface(enum_variant_ptr)

    return result


def _get_ics_classification() -> dict[str, AdapterClassification]:
    """Return ICS classifications via `INetSharingManager` COM interface.

    Returns an empty dict if COM access fails (e.g. ICS service stopped, COM
    initialization issues, missing dependencies).
    """
    result: dict[str, AdapterClassification] = {}
    ole32 = ctypes.windll.ole32
    oleaut32 = ctypes.windll.oleaut32

    hr_init = ole32.CoInitializeEx(None, 2)
    need_uninit = hr_init in (0, 1)

    try:
        clsid = _Guid()
        manager_ptr = wintypes.LPVOID()
        if (
            not ole32.CLSIDFromProgID('HNetCfg.HNetShare', ctypes.byref(clsid))
            and not ole32.CoCreateInstance(ctypes.byref(clsid), None, 5, ctypes.byref(_IID_INET_SHARING_MANAGER), ctypes.byref(manager_ptr))
            and manager_ptr
        ):
            try:
                manager_vtable = ctypes.cast(manager_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
                get_sharing_installed = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, ctypes.POINTER(wintypes.SHORT))(manager_vtable[7])

                installed = wintypes.SHORT()
                if not get_sharing_installed(manager_ptr, ctypes.byref(installed)) and installed.value:
                    result = _enumerate_ics_connections(manager_ptr, oleaut32)
            finally:
                _release_com_interface(manager_ptr)
    finally:
        if need_uninit:
            ole32.CoUninitialize()

    return result


def _get_linux_bridge_classification() -> dict[str, AdapterClassification]:
    """Detect bridged interfaces on Linux via sysfs."""
    classification: dict[str, AdapterClassification] = {}
    net_path = Path('/sys/class/net')
    try:
        for entry in net_path.iterdir():
            if (entry / 'brport').exists() or (entry / 'bridge').exists():
                classification[entry.name] = 'bridged'
    except OSError as e:
        logger.debug('Failed to inspect /sys/class/net for bridge classification: %s', e)
    return classification


def get_adapter_classification() -> dict[str, AdapterClassification]:
    """Return a mapping of adapter GUID -> classification.

    GUID keys are upper-cased and braced (e.g. `'{ABCDEF12-...}'`). Adapters not
    in the map are unclassified (treated as plain interfaces by callers). On any
    underlying API failure, the corresponding category is silently skipped.

    When an adapter qualifies for multiple classifications, bridge membership wins.
    """
    if sys.platform != 'win32':
        return _get_linux_bridge_classification()

    classification: dict[str, AdapterClassification] = {}

    try:
        bridged = _get_bridge_member_guids()
        bridge_host = _get_bridge_host_guid()
        if bridge_host is not None:
            bridged.add(bridge_host)
        for guid in bridged:
            classification[guid] = 'bridged'
    except OSError:
        logger.exception('Failed to query Network Bridge registry information')

    for guid, value in _get_ics_classification().items():
        # Bridged classification wins if both apply (rare).
        classification.setdefault(guid, value)

    return classification
