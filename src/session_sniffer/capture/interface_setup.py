"""Network interface population, TShark discovery, and interface refresh logic."""

import subprocess
from typing import TYPE_CHECKING

from session_sniffer.capture.exceptions import TSharkOutputParsingError
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
INTERFACE_PARTS_LENGTH = 3


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


def get_filtered_tshark_interfaces(tshark_path: str) -> list[tuple[int, str, str]]:
    """Retrieve a list of available TShark interfaces, excluding a list of exclusions.

    Returns:
        A list of interfaces as `(index, device_name, name)` tuples.
    """
    def process_stdout(stdout_line: str) -> tuple[int, str, str]:
        parts = stdout_line.strip().split(' ', maxsplit=INTERFACE_PARTS_LENGTH - 1)

        if len(parts) != INTERFACE_PARTS_LENGTH:
            raise TSharkOutputParsingError(INTERFACE_PARTS_LENGTH, len(parts), stdout_line)

        index = int(parts[0].removesuffix('.'))
        device_name = parts[1]
        name = parts[2].removeprefix('(').removesuffix(')')

        return index, device_name, name

    tshark_output = subprocess.check_output([tshark_path, '-D'], encoding='utf-8', text=True, creationflags=subprocess.CREATE_NO_WINDOW)

    return [
        (index, device_name, name)
        for index, device_name, name in map(process_stdout, tshark_output.splitlines())
        if name not in EXCLUDED_CAPTURE_NETWORK_INTERFACES
    ]


def refresh_available_interfaces(mac_lookup: MacLookup, tshark_path: str) -> list[Interface]:
    """Re-query the OS for network adapters and return the current TShark-capable interfaces.

    Clears the AllInterfaces registry, re-populates it from the Windows API,
    then matches against TShark-discoverable interfaces and populates device names.

    Args:
        mac_lookup: MAC vendor lookup instance.
        tshark_path: Path to the TShark executable.

    Returns:
        The updated list of TShark-capable Interface objects.
    """
    AllInterfaces.clear()
    populate_network_interfaces_info(mac_lookup)

    available: list[Interface] = []
    for _index, device_name, name in get_filtered_tshark_interfaces(tshark_path):
        interface = AllInterfaces.get_interface_by_name(name)
        if interface is None:
            continue
        interface.identity.device_name = device_name
        available.append(interface)

    return available
