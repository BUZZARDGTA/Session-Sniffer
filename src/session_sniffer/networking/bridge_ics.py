"""Detect Windows Network Bridge members and Internet Connection Sharing (ICS) adapters.

Uses the Windows registry (stdlib `winreg`) to classify network adapters by GUID
as either part of a Network Bridge (`bridged`) or acting as the ICS host
(`shared`). Detection is best-effort: any registry access failure results in the
adapter being omitted from the classification rather than raising.
"""

import contextlib
import winreg
from typing import Literal

from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)

AdapterClassification = Literal['bridged', 'shared']

# Registry locations used for detection.
_BRIDGE_LINKAGE_KEY = r'SYSTEM\CurrentControlSet\Services\BridgeMP\Linkage'
_NETWORK_CONNECTIONS_KEY = r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'
_TCPIP_INTERFACES_KEY = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
_SHARED_ACCESS_PARAMS_KEY = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters'

# Default IP address assigned to the ICS host adapter on Windows.
_ICS_HOST_IP = '192.168.137.1'

# `\Device\` prefix used in `BridgeMP\Linkage\Bind` values.
_DEVICE_PREFIX = '\\Device\\'


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
    backing service is `BridgeMP`.
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


def _adapter_has_ics_host_ip(adapter_guid: str) -> bool:
    """Return whether the adapter has the canonical ICS host IPv4 address (192.168.137.1)."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf'{_TCPIP_INTERFACES_KEY}\{adapter_guid}') as key:
            for value_name in ('IPAddress', 'DhcpIPAddress'):
                with contextlib.suppress(OSError):
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if isinstance(value, str) and value == _ICS_HOST_IP:
                        return True
                    if isinstance(value, list) and _ICS_HOST_IP in value:
                        return True
    except OSError:
        return False
    return False


def _is_ics_enabled() -> bool:
    """Return whether ICS appears to be configured on this machine.

    Checks for the presence of the SharedAccess parameters key. Absence implies
    ICS has never been configured.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SHARED_ACCESS_PARAMS_KEY):
            return True
    except OSError:
        return False


def _get_ics_host_guids() -> set[str]:
    """Return the set of adapter GUIDs that appear to be acting as the ICS host."""
    hosts: set[str] = set()
    if not _is_ics_enabled():
        return hosts

    try:
        interfaces_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_INTERFACES_KEY)
    except OSError:
        return hosts

    with interfaces_key:
        idx = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(interfaces_key, idx)
            except OSError:
                break
            idx += 1

            if not (subkey_name.startswith('{') and subkey_name.endswith('}')):
                continue

            if _adapter_has_ics_host_ip(subkey_name):
                hosts.add(_normalize_guid(subkey_name))

    return hosts


def get_adapter_classification() -> dict[str, AdapterClassification]:
    """Return a mapping of adapter GUID -> classification.

    GUID keys are upper-cased and braced (e.g. `'{ABCDEF12-...}'`). Adapters not
    in the map are unclassified (treated as plain interfaces by callers). On any
    registry access failure, the corresponding category is silently skipped.
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
        for guid in _get_ics_host_guids():
            # Bridged classification wins if both apply (rare).
            classification.setdefault(guid, 'shared')
    except OSError:
        logger.exception('Failed to query ICS registry information')

    return classification
