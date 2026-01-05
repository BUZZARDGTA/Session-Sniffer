"""GUI dialog for selecting network capture interfaces.

This module provides the InterfaceSelectionDialog for displaying available
network interfaces and allowing users to select one for packet capture.
"""
from typing import TYPE_CHECKING

from PyQt6.QtCore import QItemSelectionModel, Qt
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
)

from modules.error_messages import ensure_instance
from modules.guis.utils import resize_window_for_screen
from modules.networking.interface import SelectedInterface

if TYPE_CHECKING:
    from modules.networking.interface import Interface


def _calculate_interface_score(  # pylint: disable=too-many-arguments  # noqa: PLR0913
    interface: Interface,
    ip_address: str,
    *,
    is_arp: bool,
    saved_interface_name: str | None,
    saved_ip_address: str | None,
    saved_mac_address: str | None,
) -> int:
    """Calculate weighted matching score for an interface row.

    Args:
        interface: The interface object
        ip_address: The IP address for this row
        is_arp: Whether this row represents an ARP entry
        saved_interface_name: Previously saved interface name
        saved_ip_address: Previously saved IP address
        saved_mac_address: Previously saved MAC address

    Returns:
        Weighted score: name match=4, MAC match=2, IP match=1
    """
    score = 0
    if saved_interface_name is not None and interface.name == saved_interface_name:
        score += 4

    mac_address = interface.mac_address if not is_arp else (
        next((arp.mac_address for arp in interface.arp_entries if arp.ip_address == ip_address), None)
    )
    if saved_mac_address is not None and mac_address == saved_mac_address:
        score += 2

    if saved_ip_address is not None and ip_address == saved_ip_address:
        score += 1

    return score


def _find_best_matching_interface_row(
    interface_rows: list[tuple[Interface, str, bool]],
    saved_interface_name: str | None,
    saved_ip_address: str | None,
    saved_mac_address: str | None,
) -> int | None:
    """Return the row index of the best matching interface, or None if ambiguous.

    Weighted scoring favors name > MAC > IP to reduce ties while still rejecting
    ambiguous top scores (e.g., duplicate adapters).

    Args:
        interface_rows: List of (Interface, ip_address, is_arp) tuples
        saved_interface_name: Previously saved interface name
        saved_ip_address: Previously saved IP address
        saved_mac_address: Previously saved MAC address

    Returns:
        Row index of best match, or None if no match or ambiguous
    """
    if not any((saved_interface_name, saved_ip_address, saved_mac_address)):
        return None

    best_score = 0
    best_index: int | None = None
    ambiguous = False

    for idx, (interface, ip_address, is_arp) in enumerate(interface_rows):
        score = _calculate_interface_score(
            interface,
            ip_address,
            is_arp=is_arp,
            saved_interface_name=saved_interface_name,
            saved_ip_address=saved_ip_address,
            saved_mac_address=saved_mac_address,
        )
        if not score:
            continue

        if score > best_score:
            best_score = score
            best_index = idx
            ambiguous = False
        elif score == best_score:
            ambiguous = True

    if best_index is None or ambiguous:
        return None

    return best_index


class SafeQTableWidget(QTableWidget):
    """A subclass of QTableWidget that ensures the selection model is of the correct type."""

    # pylint: disable=invalid-name
    def selectionModel(self) -> QItemSelectionModel:  # noqa: N802
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        return ensure_instance(super().selectionModel(), QItemSelectionModel)

    def verticalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().verticalHeader(), QHeaderView)

    def horizontalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().horizontalHeader(), QHeaderView)
    # pylint: enable=invalid-name


class InterfaceSelectionDialog(QDialog):  # pylint: disable=too-many-instance-attributes
    """Display a dialog to select the capture network interface."""

    def __init__(  # pylint: disable=too-many-arguments  # noqa: PLR0913
        self,
        screen_width: int,
        screen_height: int,
        interfaces: list[Interface],
        *,
        hide_inactive_default: bool,
        hide_arp_default: bool,
        arp_spoofing_default: bool,
    ) -> None:
        """Initialize the interface selection dialog.

        Args:
            screen_width: Screen width in pixels.
            screen_height: Screen height in pixels.
            interfaces: Available Interface objects to display.
            hide_inactive_default: Default state for hiding inactive interfaces.
            hide_arp_default: Default state for hiding ARP interfaces.
            arp_spoofing_default: Default state for ARP spoofing.
        """
        super().__init__()

        # Set up the window
        self.setWindowTitle('Capture Network Interface Selection - Session Sniffer')
        # Set a minimum size for the window
        self.setMinimumSize(800, 600)
        resize_window_for_screen(self, screen_width, screen_height)

        # Custom variables
        self.selected_interface: SelectedInterface | None = None
        self.selected_ip_address: str | None = None
        self.selected_is_arp: bool = False

        self.all_interfaces = interfaces  # Store the complete list of Interface objects
        self.hide_inactive_enabled = hide_inactive_default
        self.hide_arp_enabled = hide_arp_default

        # Will be populated with (Interface, ip_address, is_arp) tuples
        self.interface_rows: list[tuple[Interface, str, bool]] = []

        # Layout for the dialog
        layout = QVBoxLayout()

        # Header above the table
        header_label = QLabel('Available Network Interfaces for Packet Capture')
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_label.setStyleSheet('font-size: 16pt; font-weight: bold; margin-bottom: 10px;')
        layout.addWidget(header_label)

        # Table widget for displaying interfaces
        self.table = SafeQTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(  # pyright: ignore[reportUnknownMemberType]
            ['Name', 'Description', 'Packets Sent', 'Packets Received', 'IP Address', 'MAC Address', 'Vendor Name'],
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        # Connect cell hover to tooltip logic
        self.table.cellEntered.connect(self.show_tooltip_if_elided)  # pyright: ignore[reportUnknownMemberType]

        horizontal_header = self.table.horizontalHeader()
        horizontal_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        horizontal_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        horizontal_header.setStretchLastSection(True)

        vertical_header = self.table.verticalHeader()
        vertical_header.setVisible(False)

        # Add widgets to layout
        layout.addWidget(self.table)

        # Filter controls layout
        filter_layout = QHBoxLayout()
        filter_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.hide_inactive_checkbox = QCheckBox('Hide Inactive Interfaces')
        self.hide_inactive_checkbox.setChecked(hide_inactive_default)
        self.hide_inactive_checkbox.setToolTip('Hide interfaces with no traffic, disconnected media, or missing IP addresses')
        self.hide_inactive_checkbox.setStyleSheet('font-size: 12pt;')
        self.hide_inactive_checkbox.stateChanged.connect(self.apply_filters)  # pyright: ignore[reportUnknownMemberType]
        filter_layout.addWidget(self.hide_inactive_checkbox)

        self.hide_arp_checkbox = QCheckBox('Hide ARP Entries')
        self.hide_arp_checkbox.setChecked(hide_arp_default)
        self.hide_arp_checkbox.setToolTip('Hide external devices discovered via ARP protocol')
        self.hide_arp_checkbox.setStyleSheet('font-size: 12pt;')
        self.hide_arp_checkbox.stateChanged.connect(self.apply_filters)  # pyright: ignore[reportUnknownMemberType]
        self.hide_arp_checkbox.stateChanged.connect(self.enforce_spoofing_constraints)  # pyright: ignore[reportUnknownMemberType]
        filter_layout.addWidget(self.hide_arp_checkbox)

        self.arp_spoofing_checkbox = QCheckBox('Enable ARP Spoofing')
        self.arp_spoofing_checkbox.setChecked(arp_spoofing_default)
        self.arp_spoofing_checkbox.setToolTip('Capture packets from other devices on your local network, not just this computer')
        self.arp_spoofing_checkbox.setStyleSheet('font-size: 12pt;')
        self.arp_spoofing_checkbox.stateChanged.connect(self.apply_filters)  # pyright: ignore[reportUnknownMemberType]
        self.arp_spoofing_checkbox.stateChanged.connect(self.enforce_spoofing_constraints)  # pyright: ignore[reportUnknownMemberType]
        filter_layout.addWidget(self.arp_spoofing_checkbox)

        # Will be set on accept
        self.arp_spoofing_enabled: bool = arp_spoofing_default

        layout.addLayout(filter_layout)

        # Bottom layout for buttons
        bottom_layout = QHBoxLayout()
        instruction_label = QLabel('Select the network interface you want to sniff.')
        instruction_label.setStyleSheet('font-size: 15pt;')

        self.select_button = QPushButton('Start Sniffing')
        self.select_button.setStyleSheet('font-size: 18pt;')
        self.select_button.setEnabled(False)  # Initially disabled

        # Set fixed size for the button
        self.select_button.setFixedSize(300, 50)  # Adjusted width and height for slightly larger button

        self.select_button.clicked.connect(self.select_interface)  # pyright: ignore[reportUnknownMemberType]

        bottom_layout.addWidget(instruction_label)
        bottom_layout.addWidget(self.select_button)

        # Center the button in the layout
        bottom_layout.setAlignment(instruction_label, Qt.AlignmentFlag.AlignCenter)
        bottom_layout.setAlignment(self.select_button, Qt.AlignmentFlag.AlignCenter)

        layout.addLayout(bottom_layout)

        # Populate the table with initial filtered data (after button is created)
        self.apply_filters()
        self.setLayout(layout)

        # Connect selection change signal to enable/disable Select button
        selection_model = self.table.selectionModel()
        selection_model.selectionChanged.connect(self.update_select_button_state)  # pyright: ignore[reportUnknownMemberType]
        selection_model.selectionChanged.connect(self.enforce_spoofing_constraints)  # pyright: ignore[reportUnknownMemberType]

        # Connect double-click signal to select interface (simulates Start button)
        self.table.cellDoubleClicked.connect(self.on_cell_double_clicked)  # pyright: ignore[reportUnknownMemberType]

        # Apply initial constraints
        self.enforce_spoofing_constraints()

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

    # Custom Methods:
    def apply_filters(self) -> None:
        """Apply the selected filters and populate the table."""
        # Preserve currently selected row (by object identity) before filtering/rebuilding table
        previously_selected_row: tuple[Interface, str, bool] | None = None
        current_row = self.table.currentRow()
        if current_row != -1 and 0 <= current_row < len(self.interface_rows):
            previously_selected_row = self.interface_rows[current_row]

        hide_inactive = self.hide_inactive_checkbox.isChecked()
        hide_arp = self.hide_arp_checkbox.isChecked()

        # Build filtered list of (Interface, ip_address, is_arp) rows
        self.interface_rows = []
        for interface in self.all_interfaces:
            is_inactive = interface.is_interface_inactive()

            if hide_inactive and is_inactive:
                continue

            # Add rows for regular IP addresses
            if interface.ip_addresses:
                for ip_address in interface.ip_addresses:
                    self.interface_rows.append((interface, ip_address, False))
            else:
                # No IP addresses, show one row with 'N/A'
                self.interface_rows.append((interface, 'N/A', False))

            # Add rows for ARP entries
            if not hide_arp:
                for arp_entry in interface.arp_entries:
                    self.interface_rows.append((interface, arp_entry.ip_address, True))

        self.populate_table()

        # Attempt to restore previous selection if still present & logically allowed
        if previously_selected_row is not None:
            # If ARP spoofing enabled and previous selection is NOT an ARP entry, do not restore (it becomes greyed out)
            interface, _ip, is_arp = previously_selected_row
            if not (self.arp_spoofing_checkbox.isChecked() and not is_arp):
                for idx, row in enumerate(self.interface_rows):
                    if row == previously_selected_row:
                        self.table.selectRow(idx)
                        break

        # Ensure select button state reflects restored selection
        self.update_select_button_state()

    def restore_saved_interface_selection(
        self,
        saved_interface_name: str | None,
        saved_ip_address: str | None = None,
        saved_mac_address: str | None = None,
    ) -> None:
        """Restore the previously saved interface selection from settings.

        Args:
            saved_interface_name: The name of the previously selected interface from settings (optional).
            saved_ip_address: The IP address of the previously selected interface (optional).
            saved_mac_address: The MAC address of the previously selected interface (optional).
        """
        best_match_index = _find_best_matching_interface_row(
            self.interface_rows,
            saved_interface_name,
            saved_ip_address,
            saved_mac_address,
        )
        if best_match_index is None:
            return

        self.table.selectRow(best_match_index)
        self.update_select_button_state()

    def populate_table(self) -> None:
        """Populate the table with the current filtered interface list."""
        # Clear existing rows
        self.table.setRowCount(0)

        # Check if ARP spoofing is enabled to grey out non-ARP interfaces
        arp_spoofing_enabled = self.arp_spoofing_checkbox.isChecked()

        # Populate with filtered data
        for idx, (interface, ip_address, is_arp) in enumerate(self.interface_rows):
            self.table.insertRow(idx)

            # Determine if this row should be disabled (greyed out)
            should_disable = arp_spoofing_enabled and not is_arp

            # Get display values
            mac_address = interface.mac_address or 'N/A'
            vendor_name = interface.vendor_name or 'N/A'
            packets_sent = interface.packets_sent
            packets_recv = interface.packets_recv

            # For ARP entries, get the specific ARP data
            if is_arp:
                arp_entry = next((arp for arp in interface.arp_entries if arp.ip_address == ip_address), None)
                if arp_entry:
                    mac_address = arp_entry.mac_address
                    vendor_name = arp_entry.vendor_name or 'N/A'
                packets_sent_str = 'N/A'
                packets_recv_str = 'N/A'
            else:
                packets_sent_str = str(packets_sent)
                packets_recv_str = str(packets_recv)

            # Name column
            name_display = f'{interface.name} (ARP)' if is_arp else interface.name
            item = QTableWidgetItem(name_display)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 0, item)

            # Description
            item = QTableWidgetItem(interface.description)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 1, item)

            # Packets Sent
            item = QTableWidgetItem(packets_sent_str)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 2, item)

            # Packets Received
            item = QTableWidgetItem(packets_recv_str)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 3, item)

            # IP Address
            item = QTableWidgetItem(ip_address)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 4, item)

            # MAC Address
            item = QTableWidgetItem(mac_address)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 5, item)

            # Vendor Name
            item = QTableWidgetItem(vendor_name)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 6, item)

        # Reset selection state
        self.update_select_button_state()

    def show_tooltip_if_elided(self, row: int, column: int) -> None:
        """Show tooltip if the text in the cell is elided."""

        def is_elided(item: QTableWidgetItem, displayed_text: str) -> bool:
            """Check if the text in the item is elided (truncated)."""
            fm = self.table.fontMetrics()
            rect = self.table.visualItemRect(item)  # Get the cell's rectangle

            # Check if the displayed text's width exceeds the width of the cell
            return fm.horizontalAdvance(displayed_text) > (rect.width() - 6)  # don't really ask why -6

        item = self.table.item(row, column)
        if item is None:
            return

        displayed_text = item.text()

        if not is_elided(item, displayed_text):
            QToolTip.hideText()
            return

        # TODO(BUZZARDGTA): Even tho it should works it doesn't always, probably just a Qt bug.
        QToolTip.showText(QCursor.pos(), '', self.table)  # <-- force refresh tooltip position (see: https://doc.qt.io/qt-6/qtooltip.html#showText)
        QToolTip.showText(QCursor.pos(), displayed_text, self.table)

    def update_select_button_state(self) -> None:
        """Enable the Select button only when a row is selected."""
        # Check if any row is selected
        selected_row = self.table.currentRow()
        if selected_row != -1:
            self.select_button.setEnabled(True)
        else:
            self.select_button.setEnabled(False)

    def enforce_spoofing_constraints(self) -> None:
        """Enforce logical constraints between ARP spoofing, ARP visibility, and selected interface.

        Rules:
        - If ARP entries are hidden, ARP spoofing must be disabled.
        - If ARP entries are visible and an ARP interface is selected, force-enable spoofing.
        - If a non-ARP interface is selected, spoofing must be disabled.
        - If ARP spoofing is enabled and a non-ARP interface is selected, clear the selection.
        """
        # If ARP entries are hidden -> disable and uncheck spoofing
        if self.hide_arp_checkbox.isChecked():
            self.arp_spoofing_checkbox.setChecked(False)
            self.arp_spoofing_checkbox.setEnabled(False)
            return

        # ARP entries are visible -> allow spoofing checkbox, evaluate selection
        self.arp_spoofing_checkbox.setEnabled(True)

        selected_row = self.table.currentRow()
        if selected_row == -1:
            # No selection yet; do not force any state
            return

        try:
            _, _, is_arp = self.interface_rows[selected_row]
        except IndexError:
            return

        # If ARP spoofing is enabled and selected interface is not ARP, clear selection
        if self.arp_spoofing_checkbox.isChecked() and not is_arp:
            self.table.clearSelection()
            return

        # If a non-ARP interface is selected and spoofing is enabled, turn off spoofing
        if not is_arp and self.arp_spoofing_checkbox.isChecked():
            self.arp_spoofing_checkbox.setChecked(False)

    def on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle double-click on table cell - simulates clicking the Start button."""
        # Validate row index
        if row < 0 or row >= len(self.interface_rows):
            return

        # Check if this row is disabled (greyed out due to ARP spoofing)
        item = self.table.item(row, 0)
        if item is None or not (item.flags() & Qt.ItemFlag.ItemIsEnabled):  # pylint: disable=superfluous-parens
            return

        # Select the row and trigger selection
        self.table.selectRow(row)
        self.select_interface()

    def select_interface(self) -> None:
        """Persist the current selection and close the dialog as accepted."""
        selected_row = self.table.currentRow()
        if selected_row != -1:
            # Retrieve the selected interface data
            interface, ip_address, is_arp = self.interface_rows[selected_row]
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
            self.selected_interface = SelectedInterface(
                name=interface.name,
                description=interface.description,
                device_name=interface.device_name,
                vendor_name=vendor_name,
                ip_address=ip_address,
                mac_address=mac_address,
                is_arp=is_arp,
            )
            self.selected_ip_address = ip_address
            self.selected_is_arp = is_arp
            self.arp_spoofing_enabled = self.arp_spoofing_checkbox.isChecked()
            self.hide_inactive_enabled = self.hide_inactive_checkbox.isChecked()
            self.hide_arp_enabled = self.hide_arp_checkbox.isChecked()
            self.accept()  # Close the dialog and set its result to QDialog.Accepted


def show_interface_selection_dialog(  # pylint: disable=too-many-arguments  # noqa: PLR0913
    screen_width: int,
    screen_height: int,
    interfaces: list[Interface],
    *,
    hide_inactive_default: bool,
    hide_arp_default: bool,
    arp_spoofing_default: bool,
    saved_interface_name: str | None = None,
    saved_ip_address: str | None = None,
    saved_mac_address: str | None = None,
) -> tuple[SelectedInterface | None, bool, bool, bool]:
    """Show the interface selection dialog and return the chosen interface and toggles.

    Returns:
        Tuple of (selected_interface, arp_spoofing_enabled,
                  hide_inactive_enabled, hide_arp_enabled)
    """
    # Create and show the interface selection dialog
    dialog = InterfaceSelectionDialog(
        screen_width,
        screen_height,
        interfaces,
        hide_inactive_default=hide_inactive_default,
        hide_arp_default=hide_arp_default,
        arp_spoofing_default=arp_spoofing_default,
    )
    # Restore the previously saved interface selection
    dialog.restore_saved_interface_selection(saved_interface_name, saved_ip_address, saved_mac_address)

    if dialog.exec() == QDialog.DialogCode.Accepted:  # Blocks until the dialog is accepted or rejected
        return (
            dialog.selected_interface,
            dialog.arp_spoofing_enabled,
            dialog.hide_inactive_enabled,
            dialog.hide_arp_enabled,
        )
    return None, arp_spoofing_default, hide_inactive_default, hide_arp_default
