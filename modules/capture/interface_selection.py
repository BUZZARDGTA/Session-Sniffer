"""Module for handling the selection of network interfaces in a GUI dialog.

It displays a list of interfaces with relevant details and allows users to select an interface
for further network sniffing operations.
"""
from typing import Literal, NamedTuple

from PyQt6.QtCore import QItemSelectionModel, Qt
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
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

from modules.guis.utils import resize_window_for_screen
from modules.utils import format_type_error


class InterfaceSelectionData(NamedTuple):
    selection_index: int
    name: str
    description: str
    packets_sent: Literal['N/A'] | int
    packets_recv: Literal['N/A'] | int
    ip_address: str
    mac_address: str
    organization_name: Literal['N/A'] | str  # noqa: PYI051
    is_arp: bool = False


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
    def __init__(self, screen_width: int, screen_height: int, interfaces: list[InterfaceSelectionData]) -> None:
        super().__init__()

        # Set up the window
        self.setWindowTitle('Capture Network Interface Selection - Session Sniffer')
        # Set a minimum size for the window
        self.setMinimumSize(800, 600)
        resize_window_for_screen(self, screen_width, screen_height)

        # Custom variables
        self.selected_interface_data: InterfaceSelectionData | None = None
        self.interfaces = interfaces  # Store the list of interface data

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
            ['Name', 'Description', 'Packets Sent', 'Packets Received', 'IP Address', 'MAC Address', 'Organization Name'],
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

        # Populate the table with interface data
        for idx, interface in enumerate(self.interfaces):
            self.table.insertRow(idx)

            item = QTableWidgetItem(str(interface.name) if not interface.is_arp else f'{interface.name} (ARP)')
            self.table.setItem(idx, 0, item)

            item = QTableWidgetItem(str(interface.description))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 1, item)

            item = QTableWidgetItem(str(interface.packets_sent))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 2, item)

            item = QTableWidgetItem(str(interface.packets_recv))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 3, item)

            item = QTableWidgetItem(str(interface.ip_address))
            self.table.setItem(idx, 4, item)

            item = QTableWidgetItem(str(interface.mac_address))
            self.table.setItem(idx, 5, item)

            item = QTableWidgetItem(str(interface.organization_name))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(idx, 6, item)

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

        # Add widgets to layout
        layout.addWidget(self.table)
        layout.addLayout(bottom_layout)
        self.setLayout(layout)

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Connect selection change signal to enable/disable Select button
        selection_model = self.table.selectionModel()
        selection_model.selectionChanged.connect(self.update_select_button_state)  # pyright: ignore[reportUnknownMemberType]

    # Custom Methods:
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
        # Check if any row is selected
        selected_row = self.table.currentRow()
        if selected_row != -1:
            self.select_button.setEnabled(True)
        else:
            self.select_button.setEnabled(False)

    def select_interface(self) -> None:
        selected_row = self.table.currentRow()
        if selected_row != -1:
            # Retrieve the selected interface data
            self.selected_interface_data = self.interfaces[selected_row]  # Get the selected interface data
            self.accept()  # Close the dialog and set its result to QDialog.Accepted


def show_interface_selection_dialog(screen_width: int, screen_height: int, interfaces: list[InterfaceSelectionData]) -> InterfaceSelectionData | None:
    # Create and show the interface selection dialog
    dialog = InterfaceSelectionDialog(screen_width, screen_height, interfaces)
    if dialog.exec() == QDialog.DialogCode.Accepted:  # Blocks until the dialog is accepted or rejected
        return dialog.selected_interface_data
    return None
