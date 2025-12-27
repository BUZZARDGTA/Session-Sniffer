"""Module for handling the selection of network interfaces in a GUI dialog.

It displays a list of interfaces with relevant details and allows users to select an interface
for further network sniffing operations.
"""
from typing import Literal, NamedTuple

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

from modules.error_messages import format_type_error
from modules.guis.utils import resize_window_for_screen


def _find_best_matching_interface_index(
    interfaces: list[InterfaceSelectionData],
    saved_interface_name: str | None,
    saved_ip_address: str | None,
    saved_mac_address: str | None,
) -> int | None:
    """Return the row index of the best matching interface, or None if ambiguous.

    Weighted scoring favors name > MAC > IP to reduce ties while still rejecting
    ambiguous top scores (e.g., duplicate adapters).
    """
    if not any((saved_interface_name, saved_ip_address, saved_mac_address)):
        return None

    def calculate_score(interface: InterfaceSelectionData) -> int:
        score = 0
        if saved_interface_name is not None and interface.name == saved_interface_name:
            score += 4
        if saved_mac_address is not None and interface.mac_address == saved_mac_address:
            score += 2
        if saved_ip_address is not None and interface.ip_address == saved_ip_address:
            score += 1
        return score

    best_score = 0
    best_index: int | None = None
    ambiguous = False

    for idx, interface in enumerate(interfaces):
        score = calculate_score(interface)
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


class InterfaceSelectionData(NamedTuple):
    """Represent a network interface row displayed in the selection dialog."""

    selection_index: int
    name: str
    description: str
    packets_sent: Literal['N/A'] | int
    packets_recv: Literal['N/A'] | int
    ip_address: str
    mac_address: str
    vendor_name: Literal['N/A'] | str  # noqa: PYI051
    device_name: str
    is_inactive: bool
    is_arp: bool


class SafeQTableWidget(QTableWidget):
    """A subclass of QTableWidget that ensures the selection model is of the correct type."""

    # pylint: disable=invalid-name
    def selectionModel(self) -> QItemSelectionModel:  # noqa: N802
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        selection_model = super().selectionModel()
        if not isinstance(selection_model, QItemSelectionModel):
            raise TypeError(format_type_error(selection_model, QItemSelectionModel))
        return selection_model

    def verticalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        header = super().verticalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(format_type_error(header, QHeaderView))
        return header

    def horizontalHeader(self) -> QHeaderView:  # noqa: N802
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        header = super().horizontalHeader()
        if not isinstance(header, QHeaderView):
            raise TypeError(format_type_error(header, QHeaderView))
        return header
    # pylint: enable=invalid-name


class InterfaceSelectionDialog(QDialog):
    """Display a dialog to select the capture network interface."""

    def __init__(  # pylint: disable=too-many-arguments  # noqa: PLR0913
        self,
        screen_width: int,
        screen_height: int,
        interfaces: list[InterfaceSelectionData],
        *,
        hide_inactive_default: bool,
        hide_arp_default: bool,
        arp_spoofing_default: bool,
    ) -> None:
        """Initialize the interface selection dialog.

        Args:
            screen_width: Screen width in pixels.
            screen_height: Screen height in pixels.
            interfaces: Available interfaces to display.
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
        self.selected_interface_data: InterfaceSelectionData | None = None
        self.all_interfaces = interfaces  # Store the complete list of interface data
        self.hide_inactive_enabled = hide_inactive_default
        self.hide_arp_enabled = hide_arp_default
        self.interfaces: list[InterfaceSelectionData] = []  # Will be populated by apply_filters()

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
        # Preserve currently selected interface (object identity) before filtering/rebuilding table
        previously_selected: InterfaceSelectionData | None = None
        current_row = self.table.currentRow()
        if current_row != -1 and 0 <= current_row < len(self.interfaces):
            previously_selected = self.interfaces[current_row]

        hide_inactive = self.hide_inactive_checkbox.isChecked()
        hide_arp = self.hide_arp_checkbox.isChecked()

        # Filter the interfaces based on checkbox states
        self.interfaces = [
            interface for interface in self.all_interfaces
            if not (hide_inactive and interface.is_inactive)
            and not (hide_arp and interface.is_arp)
        ]

        self.populate_table()

        # Attempt to restore previous selection if still present & logically allowed
        if (
            previously_selected is not None
            # If ARP spoofing enabled and previous selection is NOT an ARP entry, do not restore (it becomes greyed out)
            and not (self.arp_spoofing_checkbox.isChecked() and not previously_selected.is_arp)
        ):
            for idx, interface in enumerate(self.interfaces):
                if interface is previously_selected:
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
        best_match_index = _find_best_matching_interface_index(
            self.interfaces,
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
        for idx, interface in enumerate(self.interfaces):
            self.table.insertRow(idx)

            # Determine if this row should be disabled (greyed out)
            should_disable = arp_spoofing_enabled and not interface.is_arp

            item = QTableWidgetItem(str(interface.name) if not interface.is_arp else f'{interface.name} (ARP)')
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 0, item)

            item = QTableWidgetItem(str(interface.description))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 1, item)

            item = QTableWidgetItem(str(interface.packets_sent))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 2, item)

            item = QTableWidgetItem(str(interface.packets_recv))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 3, item)

            item = QTableWidgetItem(str(interface.ip_address))
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 4, item)

            item = QTableWidgetItem(str(interface.mac_address))
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 5, item)

            item = QTableWidgetItem(str(interface.vendor_name))
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
            interface = self.interfaces[selected_row]
        except IndexError:
            return

        # If ARP spoofing is enabled and selected interface is not ARP, clear selection
        if self.arp_spoofing_checkbox.isChecked() and not interface.is_arp:
            self.table.clearSelection()
            return

        # If a non-ARP interface is selected and spoofing is enabled, turn off spoofing
        if not interface.is_arp and self.arp_spoofing_checkbox.isChecked():
            self.arp_spoofing_checkbox.setChecked(False)

    def on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle double-click on table cell - simulates clicking the Start button."""
        # Validate row index
        if row < 0 or row >= len(self.interfaces):
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
            self.selected_interface_data = self.interfaces[selected_row]  # Get the selected interface data
            self.arp_spoofing_enabled = self.arp_spoofing_checkbox.isChecked()
            self.hide_inactive_enabled = self.hide_inactive_checkbox.isChecked()
            self.hide_arp_enabled = self.hide_arp_checkbox.isChecked()
            self.accept()  # Close the dialog and set its result to QDialog.Accepted


def show_interface_selection_dialog(  # pylint: disable=too-many-arguments  # noqa: PLR0913
    screen_width: int,
    screen_height: int,
    interfaces: list[InterfaceSelectionData],
    *,
    hide_inactive_default: bool,
    hide_arp_default: bool,
    arp_spoofing_default: bool,
    saved_interface_name: str | None = None,
    saved_ip_address: str | None = None,
    saved_mac_address: str | None = None,
) -> tuple[InterfaceSelectionData | None, bool, bool, bool]:
    """Show the interface selection dialog and return the chosen interface and toggles."""
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
        return dialog.selected_interface_data, dialog.arp_spoofing_enabled, dialog.hide_inactive_enabled, dialog.hide_arp_enabled
    return None, arp_spoofing_default, hide_inactive_default, hide_arp_default
