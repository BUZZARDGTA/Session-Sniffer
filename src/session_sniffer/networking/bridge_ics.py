"""Detect Windows Network Bridge members and Internet Connection Sharing (ICS) adapters.

Bridge detection uses the Windows registry (stdlib `winreg`).
ICS detection uses the `INetSharingManager` COM interface via `ctypes`,
which is the canonical Win32 API for querying ICS state and reliably distinguishes
the public (sharing) side from the private (shared) side.

Detection is best-effort: any failure results in the adapter being omitted from
the classification rather than raising.
"""

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from session_sniffer.networking.ctypes_adapters_info import query_ics_sharing_types

if TYPE_CHECKING:
    from collections.abc import Callable

if sys.platform == 'win32':
    import winreg

logger = logging.getLogger(__name__)

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


def _normalize_guid(guid_string: str) -> str:
    """Normalizes an adapter GUID string to uppercase with braces."""
    cleaned = guid_string.strip('{}').removeprefix(_DEVICE_PREFIX).upper()
    return f'{{{cleaned}}}'


def _get_bridge_member_guids() -> set[str]:
    """Return the set of adapter GUIDs that are members of a Windows Network Bridge."""
    members: set[str] = set()
    if sys.platform == 'win32':
        bind_value: object = None
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


def _find_connection_guid_by_value(value_name: str, predicate: Callable[[str], bool]) -> str | None:
    """Find the first network connection subkey GUID whose `Connection` `value_name` string satisfies `predicate`."""
    if sys.platform == 'win32':
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
                    with winreg.OpenKey(connections_key, rf'{subkey_name}\Connection') as connection_key:
                        raw_value, _ = winreg.QueryValueEx(connection_key, value_name)
                except OSError:
                    continue

                if isinstance(raw_value, str) and predicate(raw_value):
                    return _normalize_guid(subkey_name)

    return None


def _get_bridge_host_guid() -> str | None:
    """Return the GUID of the MAC Bridge Miniport adapter itself, if present."""
    return (
        _find_connection_guid_by_value('Name', lambda name: name == 'Network Bridge')
        or _find_connection_guid_by_value('PnpInstanceID', lambda pnp_id: 'BRIDGEMP' in pnp_id.upper())
    )


def _get_ics_classification() -> dict[str, AdapterClassification]:
    """Return ICS classifications via `INetSharingManager` COM interface.

    Returns an empty dict if COM access fails (e.g. ICS service stopped, COM
    initialization issues, missing dependencies).
    """
    result: dict[str, AdapterClassification] = {}
    for raw_guid, sharing_type in query_ics_sharing_types():
        guid_normalized = _normalize_guid(raw_guid)
        if sharing_type == _ICSSHARINGTYPE_PUBLIC:
            result[guid_normalized] = 'sharing'
        elif sharing_type == _ICSSHARINGTYPE_PRIVATE:
            result[guid_normalized] = 'shared'
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
    if sys.platform == 'darwin':
        return {}
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

    try:
        for guid, value in _get_ics_classification().items():
            # Bridged classification wins if both apply (rare).
            classification.setdefault(guid, value)
    except OSError as e:
        logger.debug('Failed to query ICS adapter classification: %s', e)

    return classification
