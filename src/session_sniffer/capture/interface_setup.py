"""Network interface population, TShark discovery, and interface selection logic."""

import subprocess
from typing import TYPE_CHECKING

from session_sniffer.capture.exceptions import TSharkOutputParsingError
from session_sniffer.guis.interface_selection_dialog import show_interface_selection_dialog
from session_sniffer.networking.ctypes_adapters_info import get_adapters_info
from session_sniffer.networking.interface import AllInterfaces, ARPEntry, Interface, SelectedInterface
from session_sniffer.networking.utils import is_valid_non_special_ipv4
from session_sniffer.settings import Settings

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

    for adapter in adapters:
        interface = AllInterfaces.add_interface(Interface(
            index=adapter.interface_index,
            ip_enabled=adapter.ip_enabled,
            state=adapter.operational_status,
            media_connect_state=adapter.media_connect_state,
            name=adapter.friendly_name,
            packets_sent=adapter.packets_sent,
            packets_recv=adapter.packets_recv,
            transmit_link_speed=adapter.transmit_link_speed,
            receive_link_speed=adapter.receive_link_speed,
            description=adapter.description,
            ip_addresses=adapter.ipv4_addresses,
            mac_address=adapter.mac_address,
            device_name=None,
            vendor_name=mac_lookup.get_mac_address_vendor_name(adapter.mac_address) if adapter.mac_address else None,
        ))

        for neighbor_ip, neighbor_mac in adapter.neighbors:
            if (
                not neighbor_ip or not neighbor_mac
                or neighbor_mac.upper() in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}  # Filter placeholder/broadcast MACs
                or not is_valid_non_special_ipv4(neighbor_ip)
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

    tshark_output = subprocess.check_output([tshark_path, '-D'], encoding='utf-8', text=True)

    return [
        (index, device_name, name)
        for index, device_name, name in map(process_stdout, tshark_output.splitlines())
        if name not in EXCLUDED_CAPTURE_NETWORK_INTERFACES
    ]


def select_interface(
    interfaces: list[Interface],
    screen_width: int,
    screen_height: int,
) -> SelectedInterface | None:
    """Select the best matching interface based on current settings.

    If auto-selection is not possible or results in ambiguity,
    prompt the user with the interface selection dialog.

    Returns:
        A SelectedInterface snapshot, or None if cancelled.
        Note: ip_address can be None or 'N/A' if interface has no IP addresses.
    """

    def _can_auto_select_interface() -> bool:
        """Whether the application has enough configuration to attempt auto-selecting an interface."""
        if not Settings.GUI_INTERFACE_SELECTION_AUTO_CONNECT:
            return False

        return any(
            setting is not None
            for setting in (
                Settings.CAPTURE_INTERFACE_NAME,
                Settings.CAPTURE_MAC_ADDRESS,
                Settings.CAPTURE_IP_ADDRESS,
            )
        )

    def _build_selected_interface(interface: Interface, ip_address: str | None, *, is_arp: bool) -> SelectedInterface:
        mac_address = (
            next((arp.mac_address for arp in interface.arp_entries if arp.ip_address == ip_address), None)
            if is_arp
            else interface.mac_address
        )
        vendor_name = (
            next((arp.vendor_name for arp in interface.arp_entries if arp.ip_address == ip_address), None)
            if is_arp
            else interface.vendor_name
        )

        return SelectedInterface(
            name=interface.name,
            description=interface.description,
            device_name=interface.device_name,
            ip_address=ip_address,
            mac_address=mac_address,
            vendor_name=vendor_name,
            is_arp=is_arp,
        )

    def _auto_select_best_interface() -> SelectedInterface | None:
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
            if Settings.CAPTURE_INTERFACE_NAME is not None and interface.name == Settings.CAPTURE_INTERFACE_NAME:
                score += 4

            # Get the MAC address for this specific row
            mac_address = (
                next((arp.mac_address for arp in interface.arp_entries if arp.ip_address == ip_address), None)
                if is_arp
                else interface.mac_address
            )

            if Settings.CAPTURE_MAC_ADDRESS is not None and mac_address == Settings.CAPTURE_MAC_ADDRESS:
                score += 2
            if Settings.CAPTURE_IP_ADDRESS is not None and ip_address == Settings.CAPTURE_IP_ADDRESS:
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
        return _build_selected_interface(interface, ip_address, is_arp=is_arp)

    if auto_selected := _auto_select_best_interface():
        return auto_selected

    # If no suitable interface was found, prompt the user to select an interface
    (
        selected_interface,
        arp_spoofing_enabled,
        hide_inactive_enabled,
        hide_arp_enabled,
    ) = show_interface_selection_dialog(
        screen_width,
        screen_height,
        interfaces,
        (Settings.GUI_INTERFACE_SELECTION_HIDE_INACTIVE, Settings.GUI_INTERFACE_SELECTION_HIDE_ARP, Settings.CAPTURE_ARP_SPOOFING),
        (Settings.CAPTURE_INTERFACE_NAME, Settings.CAPTURE_IP_ADDRESS, Settings.CAPTURE_MAC_ADDRESS),
    )

    if selected_interface is None:
        return None

    need_rewrite_settings = False

    if arp_spoofing_enabled != Settings.CAPTURE_ARP_SPOOFING:
        Settings.CAPTURE_ARP_SPOOFING = arp_spoofing_enabled
        need_rewrite_settings = True

    if hide_inactive_enabled != Settings.GUI_INTERFACE_SELECTION_HIDE_INACTIVE:
        Settings.GUI_INTERFACE_SELECTION_HIDE_INACTIVE = hide_inactive_enabled
        need_rewrite_settings = True

    if hide_arp_enabled != Settings.GUI_INTERFACE_SELECTION_HIDE_ARP:
        Settings.GUI_INTERFACE_SELECTION_HIDE_ARP = hide_arp_enabled
        need_rewrite_settings = True

    if need_rewrite_settings:
        Settings.rewrite_settings_file()

    return selected_interface
