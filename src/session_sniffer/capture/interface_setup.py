"""Network interface population, scapy interface discovery, and interface refresh logic."""

from typing import TYPE_CHECKING

from session_sniffer.networking.bridge_ics import get_adapter_classification
from session_sniffer.networking.ctypes_adapters_info import get_adapters_info
from session_sniffer.networking.interface import (
    INTERFACE_TYPE_BRIDGED,
    INTERFACE_TYPE_INTERFACE,
    INTERFACE_TYPE_SHARED,
    INTERFACE_TYPE_SHARING,
    AllInterfaces,
    ARPEntry,
    Interface,
    InterfaceIdentity,
    InterfaceTraffic,
)
from session_sniffer.networking.utils import is_valid_private_ipv4

if TYPE_CHECKING:
    from session_sniffer.networking.manuf_lookup import MacLookup

EXCLUDED_CAPTURE_NETWORK_INTERFACES = {
    'Adapter for loopback traffic capture',
    'Event Tracing for Windows (ETW) reader',
}


def populate_network_interfaces_info(mac_lookup: MacLookup) -> None:
    """Populate the AllInterfaces collection with network interface details."""
    adapters = list(get_adapters_info())

    if not adapters:
        return

    classification = get_adapter_classification()

    for adapter in adapters:
        adapter_guid = adapter.identity.adapter_guid
        classification_value = classification.get(adapter_guid) if adapter_guid else None
        if classification_value == 'bridged':
            interface_type = INTERFACE_TYPE_BRIDGED
        elif classification_value == 'shared':
            interface_type = INTERFACE_TYPE_SHARED
        elif classification_value == 'sharing':
            interface_type = INTERFACE_TYPE_SHARING
        else:
            interface_type = INTERFACE_TYPE_INTERFACE

        interface = AllInterfaces.add_interface(Interface(
            identity=InterfaceIdentity(
                index=adapter.identity.interface_index,
                name=adapter.identity.friendly_name,
                description=adapter.identity.description,
                mac_address=adapter.identity.mac_address,
                device_name=None,
                vendor_name=mac_lookup.get_mac_address_vendor_name(adapter.identity.mac_address) if adapter.identity.mac_address else None,
                adapter_guid=adapter_guid,
            ),
            traffic=InterfaceTraffic(
                packets_sent=adapter.traffic.packets_sent,
                packets_recv=adapter.traffic.packets_recv,
                transmit_link_speed=adapter.traffic.transmit_link_speed,
                receive_link_speed=adapter.traffic.receive_link_speed,
            ),
            ip_enabled=adapter.status.ip_enabled,
            state=adapter.status.operational_status,
            media_connect_state=adapter.status.media_connect_state,
            interface_type=interface_type,
            ip_addresses=adapter.ipv4_addresses,
            gateway_addresses=adapter.gateway_addresses,
        ))

        for neighbor_ip, neighbor_mac in adapter.neighbors:
            if (
                not neighbor_ip or not neighbor_mac
                or neighbor_mac.upper() in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}  # Filter placeholder/broadcast MACs
                or not is_valid_private_ipv4(neighbor_ip)
            ):
                continue

            vendor_name = mac_lookup.get_mac_address_vendor_name(neighbor_mac)
            interface.add_arp_entry(ARPEntry(
                ip_address=neighbor_ip,
                mac_address=neighbor_mac,
                vendor_name=vendor_name,
            ))


def get_filtered_scapy_interfaces() -> list[tuple[str, str]]:
    r"""Build the list of capture-capable interfaces from Windows API data.

    Uses the GUID already stored in `AllInterfaces` (populated by
    `populate_network_interfaces_info`) to construct the NPF device path
    (`\Device\NPF_{GUID}`) directly, avoiding a dependency on scapy's own
    interface enumeration which requires elevated privileges to succeed.

    Returns:
        A list of `(device_name, friendly_name)` tuples where `device_name` is
        the NPF device path (e.g. `\Device\NPF_{GUID}`) and `friendly_name`
        is the Windows adapter name.
    """
    result: list[tuple[str, str]] = []
    for interface in AllInterfaces.iterate():
        guid = interface.identity.adapter_guid
        if guid is None:
            continue
        # Strip enclosing braces if present, then rebuild to normalise form.
        clean_guid = guid.strip('{}')
        device_name = f'\\Device\\NPF_{{{clean_guid}}}'
        friendly_name = interface.identity.name
        if friendly_name not in EXCLUDED_CAPTURE_NETWORK_INTERFACES:
            result.append((device_name, friendly_name))
    return result


def refresh_available_interfaces(mac_lookup: MacLookup) -> list[Interface]:
    """Re-query the OS for network adapters and return capture-capable interfaces.

    Clears the AllInterfaces registry, re-populates it from the Windows API,
    then matches against scapy-discoverable interfaces and populates device names.

    Args:
        mac_lookup: MAC vendor lookup instance.

    Returns:
        The updated list of capture-capable Interface objects.
    """
    AllInterfaces.clear()
    populate_network_interfaces_info(mac_lookup)

    available: list[Interface] = []
    for device_name, friendly_name in get_filtered_scapy_interfaces():
        interface = AllInterfaces.get_interface_by_name(friendly_name)
        if interface is None:
            continue
        interface.identity.device_name = device_name
        available.append(interface)

    return available
