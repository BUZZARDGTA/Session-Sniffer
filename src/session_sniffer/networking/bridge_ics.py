"""Detect Windows Network Bridge members and Internet Connection Sharing (ICS) adapters.

Bridge detection uses the Windows registry (stdlib `winreg`).
ICS detection uses the `INetSharingManager` COM interface via `pywin32`,
which is the canonical Win32 API for querying ICS state and reliably distinguishes
the public (sharing) side from the private (shared) side.

Detection is best-effort: any failure results in the adapter being omitted from
the classification rather than raising.
"""

import winreg
from typing import Literal

from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)

AdapterClassification = Literal['bridged', 'shared', 'sharing']

# Registry locations used for bridge detection.
_BRIDGE_LINKAGE_KEY = r'SYSTEM\CurrentControlSet\Services\BridgeMP\Linkage'
_NETWORK_CONNECTIONS_KEY = r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'

# `\Device\` prefix used in `BridgeMP\Linkage\Bind` values.
_DEVICE_PREFIX = '\\Device\\'

# INetSharingConfiguration::SharingConnectionType values.
# https://learn.microsoft.com/en-us/windows/win32/api/netcon/ne-netcon-sharingconnectiontype
_ICSSHARINGTYPE_PUBLIC = 0   # Adapter is the public (upstream) connection being shared.
_ICSSHARINGTYPE_PRIVATE = 1  # Adapter is the private (LAN) connection serving clients.


def _normalize_guid(value: str) -> str:
    """Normalize a GUID string to upper-case-braced form for stable comparisons."""
    stripped = value.strip().removeprefix(_DEVICE_PREFIX)
    if not (stripped.startswith('{') and stripped.endswith('}')):
        return stripped.upper()
    return stripped.upper()


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

    for entry in bind_value:  # pyright: ignore[reportUnknownVariableType]
        if isinstance(entry, str) and entry:
            members.add(_normalize_guid(entry))
    return members


def _get_bridge_host_guid() -> str | None:
    """Return the GUID of the MAC Bridge Miniport adapter itself, if present.

    Iterates network connection registry entries and returns the first GUID whose
    backing device is a `BridgeMP` instance.
    """
    try:
        connections_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NETWORK_CONNECTIONS_KEY)
    except OSError:
        return None

    with connections_key:
        idx = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(connections_key, idx)
            except OSError:
                break
            idx += 1

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


def _get_ics_classification() -> dict[str, AdapterClassification]:
    """Return ICS classifications via `INetSharingManager` COM interface.

    Returns an empty dict if COM access fails (e.g. ICS service stopped, COM
    initialization issues, missing dependencies).
    """
    result: dict[str, AdapterClassification] = {}

    try:
        import pythoncom  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
        import win32com.client  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    except ImportError:
        return result

    try:
        pythoncom.CoInitialize()  # ty: ignore[unresolved-attribute]
    except pythoncom.com_error:  # ty: ignore[unresolved-attribute]
        return result

    try:
        try:
            manager = win32com.client.Dispatch('HNetCfg.HNetShare')
        except pythoncom.com_error:  # ty: ignore[unresolved-attribute]
            return result

        try:
            connections = manager.EnumEveryConnection
        except (pythoncom.com_error, AttributeError):  # ty: ignore[unresolved-attribute]
            return result

        for connection in connections:
            try:
                config = manager.INetSharingConfigurationForINetConnection(connection)
                if not config.SharingEnabled:
                    continue
                sharing_type = int(config.SharingConnectionType)
                guid_raw = manager.NetConnectionProps(connection).Guid
            except (pythoncom.com_error, AttributeError):  # ty: ignore[unresolved-attribute]
                continue

            if not isinstance(guid_raw, str) or not guid_raw:
                continue
            guid = _normalize_guid(guid_raw)

            if sharing_type == _ICSSHARINGTYPE_PUBLIC:
                result[guid] = 'sharing'
            elif sharing_type == _ICSSHARINGTYPE_PRIVATE:
                result[guid] = 'shared'
    finally:
        pythoncom.CoUninitialize()  # ty: ignore[unresolved-attribute]

    return result


def get_adapter_classification() -> dict[str, AdapterClassification]:
    """Return a mapping of adapter GUID -> classification.

    GUID keys are upper-cased and braced (e.g. `'{ABCDEF12-...}'`). Adapters not
    in the map are unclassified (treated as plain interfaces by callers). On any
    underlying API failure, the corresponding category is silently skipped.

    When an adapter qualifies for multiple classifications, bridge membership wins.
    """
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

    try:
        for guid, value in _get_ics_classification().items():
            # Bridged classification wins if both apply (rare).
            classification.setdefault(guid, value)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception('Failed to query ICS configuration via COM')

    return classification
