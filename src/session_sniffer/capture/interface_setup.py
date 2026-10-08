"""Network interface population, capture interface discovery, and interface refresh logic."""

import logging
import sys

from session_sniffer.networking.bridge_ics import get_adapter_classification
from session_sniffer.networking.ctypes_adapters_info import get_adapters_info
from session_sniffer.networking.interface import (
    INTERFACE_TYPE_BRIDGED,
    INTERFACE_TYPE_INTERFACE,
    INTERFACE_TYPE_SHARED,
    INTERFACE_TYPE_SHARING,
    AllInterfaces,
    Interface,
    InterfaceIdentity,
    InterfaceTraffic,
    NeighbourEntry,
)
from session_sniffer.networking.manuf_lookup import MacLookup
from session_sniffer.networking.utils import is_valid_private_ipv4

logger = logging.getLogger(__name__)

EXCLUDED_CAPTURE_NETWORK_INTERFACES = {
    'Adapter for loopback traffic capture',
    'Event Tracing for Windows (ETW) reader',
}


def populate_network_interfaces_info() -> None:
    """Populate the AllInterfaces collection with network interface details."""
    adapters = list(get_adapters_info())

    if not adapters:
        return

    classification = get_adapter_classification()

    for adapter in adapters:
        classification_value = classification.get(adapter.identity.adapter_guid) if adapter.identity.adapter_guid is not None else None
        if classification_value == 'bridged':
            interface_type = INTERFACE_TYPE_BRIDGED
        elif classification_value == 'shared':
            interface_type = INTERFACE_TYPE_SHARED
        elif classification_value == 'sharing':
            interface_type = INTERFACE_TYPE_SHARING
        else:
            interface_type = INTERFACE_TYPE_INTERFACE

        interface = AllInterfaces.add_interface(
            Interface(
                identity=InterfaceIdentity(
                    index=adapter.identity.interface_index,
                    name=adapter.identity.friendly_name,
                    description=adapter.identity.description,
                    mac_address=adapter.identity.mac_address,
                    device_name=None,
                    vendor_name=MacLookup.get_vendor_name(adapter.identity.mac_address) if adapter.identity.mac_address is not None else None,
                    adapter_guid=adapter.identity.adapter_guid,
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
            ),
        )

        for neighbor_ip, neighbor_mac in adapter.neighbors:
            if neighbor_ip is None or neighbor_mac is None:
                continue
            if not neighbor_ip or not neighbor_mac:
                continue
            if neighbor_mac.upper() in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'} or not is_valid_private_ipv4(neighbor_ip):
                continue

            vendor_name = MacLookup.get_vendor_name(neighbor_mac)
            interface.add_neighbour_entry(
                NeighbourEntry(
                    ip_address=neighbor_ip,
                    mac_address=neighbor_mac,
                    vendor_name=vendor_name,
                ),
            )


def get_filtered_capture_interfaces() -> list[tuple[str, str]]:
    r"""Build the list of capture-capable interfaces from OS network data.

    Returns:
        A list of `(device_name, friendly_name)` tuples where `device_name` is
        the capture device identifier and `friendly_name` is the display adapter name.
    """
    result: list[tuple[str, str]] = []
    for interface in AllInterfaces.iterate():
        if sys.platform != 'win32':
            if interface.identity.name != 'lo' and interface.identity.name not in EXCLUDED_CAPTURE_NETWORK_INTERFACES:
                result.append((interface.identity.name, interface.identity.name))
            continue

        if interface.identity.adapter_guid is None:
            continue
        # Strip enclosing braces if present, then rebuild to normalise form.
        clean_guid = interface.identity.adapter_guid.strip('{}')
        device_name = f'\\Device\\NPF_{{{clean_guid}}}'
        if interface.identity.name not in EXCLUDED_CAPTURE_NETWORK_INTERFACES:
            result.append((device_name, interface.identity.name))
    return result


def refresh_available_interfaces() -> list[Interface]:
    """Re-query the OS for network adapters and return capture-capable interfaces.

    Clears the AllInterfaces registry, re-populates it from the network adapter APIs,
    then populates device names.

    Returns:
        The updated list of capture-capable Interface objects.
    """
    AllInterfaces.clear()
    try:
        populate_network_interfaces_info()
    except OSError as e:
        logger.warning('Failed to refresh network interfaces: %s', e)
        return []

    available: list[Interface] = []
    for device_name, friendly_name in get_filtered_capture_interfaces():
        interface = AllInterfaces.get_interface_by_name(friendly_name)
        if interface is None:
            continue
        interface.identity.device_name = device_name
        available.append(interface)

    return available
