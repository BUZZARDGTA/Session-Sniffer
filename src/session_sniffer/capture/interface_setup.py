"""Network interface population, TShark discovery, and interface selection logic."""

import subprocess
from typing import TYPE_CHECKING

from session_sniffer.capture.exceptions import TSharkOutputParsingError
from session_sniffer.guis.interface_selection_dialog import show_interface_selection_dialog
from session_sniffer.networking.bridge_ics import get_adapter_classification
from session_sniffer.networking.ctypes_adapters_info import get_adapters_info
from session_sniffer.networking.interface import (
    INTERFACE_TYPE_BRIDGED,
    INTERFACE_TYPE_INTERFACE,
    INTERFACE_TYPE_SHARED,
    AllInterfaces,
    ARPEntry,
    Interface,
    InterfaceIdentity,
    InterfaceTraffic,
    SelectedInterfaceRow,
)
from session_sniffer.networking.utils import is_valid_private_ipv4
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

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


def select_interface(  # noqa: PLR0913  # pylint: disable=too-many-arguments
    interfaces: list[Interface],
    screen_width: int,
    screen_height: int,
    *,
    force_dialog: bool = False,
    before_dialog: Callable[[], None] | None = None,
    mac_lookup: MacLookup | None = None,
    tshark_path: str | None = None,
) -> SelectedInterfaceRow | None:
    """Select the best matching interface based on current settings.

    If auto-selection is not possible or results in ambiguity,
    prompt the user with the interface selection dialog.

    Args:
        interfaces: Available Interface objects to choose from.
        screen_width: Screen width in pixels.
        screen_height: Screen height in pixels.
        force_dialog: If True, always show the selection dialog even when auto-connect would succeed.
        before_dialog: Optional callback invoked once, right before the dialog is shown (skipped on auto-select).
        mac_lookup: Optional MacLookup instance for live refresh in the dialog.
        tshark_path: Optional TShark path for live refresh in the dialog.

    Returns:
        A SelectedInterfaceRow referencing the live Interface, or None if cancelled.
        Note: ip_address can be None or 'N/A' if interface has no IP addresses.
    """

    def _can_auto_select_interface() -> bool:
        """Whether the application has enough configuration to attempt auto-selecting an interface."""
        if not Settings.gui_interface_selection_auto_connect:
            return False

        return any(
            setting is not None
            for setting in (
                Settings.capture_interface_name,
                Settings.capture_mac_address,
                Settings.capture_ip_address,
            )
        )

    def _auto_select_best_interface() -> SelectedInterfaceRow | None:
        """Return the best matching interface, or `None` if ambiguous or no match."""
        if not _can_auto_select_interface():
            return None

        def calculate_score(interface: Interface, ip_address: str, *, is_arp: bool) -> int:
            """Calculate the score of an interface based on matching criteria.

            Args:
                interface: The interface to calculate the score for
                ip_address: The IP address for this row
                is_arp: Whether this is an ARP entry
            """
            score = 0
            if Settings.capture_interface_name is not None and interface.identity.name == Settings.capture_interface_name:
                score += 4

            # Get the MAC address for this specific row
            mac_address = (
                next((arp.mac_address for arp in interface.arp_entries if arp.ip_address == ip_address), None)
                if is_arp
                else interface.identity.mac_address
            )

            if Settings.capture_mac_address is not None and mac_address == Settings.capture_mac_address:
                score += 2
            if Settings.capture_ip_address is not None and ip_address == Settings.capture_ip_address:
                score += 1
            return score

        best_score = 0
        best_match: tuple[Interface, str, bool] | None = None
        ambiguous = False

        # Check all possible rows (interface IPs + ARP entries)
        for interface in interfaces:
            # Check regular IP addresses
            if interface.ip_addresses:
                for ip_address in interface.ip_addresses:
                    score = calculate_score(interface, ip_address, is_arp=False)
                    if score > best_score:
                        best_score = score
                        best_match = (interface, ip_address, False)
                        ambiguous = False
                    elif score == best_score and score > 0:
                        ambiguous = True
            else:
                # No IP addresses case
                score = calculate_score(interface, 'N/A', is_arp=False)
                if score > best_score:
                    best_score = score
                    best_match = (interface, 'N/A', False)
                    ambiguous = False
                elif score == best_score and score > 0:
                    ambiguous = True

            # Check ARP entries
            for arp_entry in interface.arp_entries:
                score = calculate_score(interface, arp_entry.ip_address, is_arp=True)
                if score > best_score:
                    best_score = score
                    best_match = (interface, arp_entry.ip_address, True)
                    ambiguous = False
                elif score == best_score and score > 0:
                    ambiguous = True

        if best_match is None or ambiguous:
            return None

        interface, ip_address, is_arp = best_match
        return SelectedInterfaceRow(interface=interface, ip_address=ip_address, is_arp=is_arp)

    if not force_dialog:
        auto_selected = _auto_select_best_interface()
        if auto_selected is not None:
            return auto_selected

    # If no suitable interface was found, prompt the user to select an interface
    if before_dialog is not None:
        before_dialog()
    selected_interface: SelectedInterfaceRow | None
    (
        selected_interface,
        arp_spoofing_enabled,
        hide_inactive_enabled,
        hide_arp_enabled,
    ) = show_interface_selection_dialog(
        screen_width,
        screen_height,
        interfaces,
        (Settings.gui_interface_selection_hide_inactive, Settings.gui_interface_selection_hide_arp, Settings.capture_arp_spoofing),
        (Settings.capture_interface_name, Settings.capture_ip_address, Settings.capture_mac_address),
        mac_lookup=mac_lookup,
        tshark_path=tshark_path,
    )

    if selected_interface is None:
        return None

    need_rewrite_settings = False

    if arp_spoofing_enabled != Settings.capture_arp_spoofing:
        Settings.capture_arp_spoofing = arp_spoofing_enabled
        need_rewrite_settings = True

    if hide_inactive_enabled != Settings.gui_interface_selection_hide_inactive:
        Settings.gui_interface_selection_hide_inactive = hide_inactive_enabled
        need_rewrite_settings = True

    if hide_arp_enabled != Settings.gui_interface_selection_hide_arp:
        Settings.gui_interface_selection_hide_arp = hide_arp_enabled
        need_rewrite_settings = True

    if need_rewrite_settings:
        Settings.rewrite_settings_file()

    return selected_interface
