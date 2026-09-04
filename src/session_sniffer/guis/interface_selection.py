"""High-level helpers for interface selection.

Module-level orchestration functions that wrap `InterfaceSelectionDialog`:
- `show_interface_selection_dialog`: creates and runs the dialog, returning results.
- `select_interface`: auto-selects or falls back to the dialog based on current settings.
"""

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QDialog

from session_sniffer.guis.interface_selection_dialog import InterfaceSelectionDialog
from session_sniffer.networking.interface import Interface, SelectedInterfaceRow
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


def show_interface_selection_dialog(
    screen_size: tuple[int, int],
    interfaces: list[Interface],
    filter_defaults: tuple[bool, bool, bool],
    saved_selection: tuple[str | None, str | None, str | None] = (None, None, None),
) -> tuple[SelectedInterfaceRow | None, bool, bool, bool, bool]:
    """Show the interface selection dialog and return the chosen interface and toggles.

    Args:
        screen_size: Screen dimensions as (width, height) in pixels.
        interfaces: Available Interface objects to display.
        filter_defaults: Default states as (hide_inactive, hide_neighbours, arp_spoofing).
        saved_selection: Previously saved (interface_name, ip_address, mac_address).

    Returns:
        Tuple of (selected_interface, arp_spoofing_enabled, hide_inactive_enabled, hide_neighbours_enabled, remember_interface_enabled).
    """
    hide_inactive_default, hide_neighbours_default, arp_spoofing_default = filter_defaults
    saved_interface_name, saved_ip_address, saved_mac_address = saved_selection
    dialog = InterfaceSelectionDialog(
        screen_size,
        interfaces,
        filter_defaults,
    )
    dialog.restore_saved_interface_selection(saved_interface_name, saved_ip_address, saved_mac_address)

    if dialog.exec() == QDialog.DialogCode.Accepted:  # Blocks until the dialog is accepted or rejected
        return (
            dialog.selected_interface,
            dialog.arp_spoofing_enabled,
            dialog.hide_inactive_enabled,
            dialog.hide_neighbours_enabled,
            dialog.remember_interface_enabled,
        )
    return None, arp_spoofing_default, hide_inactive_default, hide_neighbours_default, Settings.gui_interface_selection_auto_connect


def select_interface(
    interfaces: list[Interface],
    screen_size: tuple[int, int],
    *,
    force_dialog: bool = False,
    before_dialog: Callable[[], None] | None = None,
) -> SelectedInterfaceRow | None:
    """Select the best matching interface based on current settings.

    If auto-selection is not possible or results in ambiguity,
    prompt the user with the interface selection dialog.

    Args:
        interfaces: Available Interface objects to choose from.
        screen_size: Screen dimensions as (width, height) in pixels.
        force_dialog: If True, always show the selection dialog even when auto-connect would succeed.
        before_dialog: Optional callback invoked once, right before the dialog is shown (skipped on auto-select).

    Returns:
        A SelectedInterfaceRow referencing the live Interface, or None if cancelled.
        Note: ip_address can be None or 'N/A' if interface has no IP addresses.
    """

    def _can_auto_select_interface() -> bool:
        """Whether the application has enough configuration to attempt auto-selecting an interface."""
        if not Settings.gui_interface_selection_auto_connect:
            return False

        return (
            Settings.capture_interface_name is not None
            and Settings.capture_ip_address is not None
            and Settings.capture_ip_address not in ('', 'N/A', '127.0.0.1')
        )

    def _auto_select_best_interface() -> SelectedInterfaceRow | None:
        """Return the exactly matching saved interface row, or `None` if ambiguous, obsolete, or not found."""
        if not _can_auto_select_interface():
            return None

        matching_rows: list[SelectedInterfaceRow] = []

        for interface in interfaces:
            if Settings.gui_interface_selection_hide_inactive and interface.is_interface_inactive():
                continue

            if not interface.ip_addresses:
                continue

            if interface.identity.name != Settings.capture_interface_name:
                continue

            if Settings.capture_arp_spoofing:
                for neighbour_entry in interface.neighbour_entries:
                    if neighbour_entry.ip_address != Settings.capture_ip_address:
                        continue
                    if Settings.capture_mac_address is not None and neighbour_entry.mac_address != Settings.capture_mac_address:
                        continue
                    matching_rows.append(
                        SelectedInterfaceRow(
                            interface=interface,
                            ip_address=neighbour_entry.ip_address,
                            is_neighbour=True,
                        ),
                    )
            else:
                if Settings.capture_mac_address is not None and interface.identity.mac_address != Settings.capture_mac_address:
                    continue
                if Settings.capture_ip_address in interface.ip_addresses and Settings.capture_ip_address != '127.0.0.1':
                    matching_rows.append(
                        SelectedInterfaceRow(
                            interface=interface,
                            ip_address=Settings.capture_ip_address,
                            is_neighbour=False,
                        ),
                    )

        if len(matching_rows) == 1:
            return matching_rows[0]

        return None

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
        hide_neighbours_enabled,
        remember_interface_enabled,
    ) = show_interface_selection_dialog(
        screen_size,
        interfaces,
        (Settings.gui_interface_selection_hide_inactive, Settings.gui_interface_selection_hide_neighbours, Settings.capture_arp_spoofing),
        (Settings.capture_interface_name, Settings.capture_ip_address, Settings.capture_mac_address),
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

    if hide_neighbours_enabled != Settings.gui_interface_selection_hide_neighbours:
        Settings.gui_interface_selection_hide_neighbours = hide_neighbours_enabled
        need_rewrite_settings = True

    if remember_interface_enabled != Settings.gui_interface_selection_auto_connect:
        Settings.gui_interface_selection_auto_connect = remember_interface_enabled
        need_rewrite_settings = True

    if need_rewrite_settings:
        Settings.rewrite_settings_file()

    return selected_interface
