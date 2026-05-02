"""GUI dialog for selecting network capture interfaces.

This module provides the InterfaceSelectionDialog for displaying available
network interfaces and allowing users to select one for packet capture.
The dialog refreshes automatically so that plugged/unplugged or
enabled/disabled adapters appear and disappear in real time.
"""
from dataclasses import dataclass, field
from threading import Thread
from typing import TYPE_CHECKING

from PyQt6.QtCore import QItemSelectionModel, Qt, QTimer, pyqtSignal
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

from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.utils import resize_window_for_screen
from session_sniffer.networking.interface import INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_NEIGHBOUR, INTERFACE_TYPE_SHARED, Interface, SelectedInterfaceRow

if TYPE_CHECKING:
    from session_sniffer.networking.manuf_lookup import MacLookup


def _calculate_interface_score(
    interface_row: tuple[Interface, str, bool],
    saved_selection: tuple[str | None, str | None, str | None],
) -> int:
    """Calculate weighted matching score for an interface row.

    Args:
        interface_row: Tuple of (interface, ip_address, is_arp)
        saved_selection: Tuple of (saved_interface_name, saved_ip_address, saved_mac_address)

    Returns:
        Weighted score: name match=4, MAC match=2, IP match=1
    """
    interface, ip_address, is_arp = interface_row
    saved_interface_name, saved_ip_address, saved_mac_address = saved_selection

    score = 0
    if saved_interface_name is not None and interface.identity.name == saved_interface_name:
        score += 4

    mac_address = interface.identity.mac_address if not is_arp else (
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
            (interface, ip_address, is_arp),
            (saved_interface_name, saved_ip_address, saved_mac_address),
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


@dataclass(slots=True)
class _InterfaceData:
    all_interfaces: list[Interface]
    interface_rows: list[tuple[Interface, str, bool]] = field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]


@dataclass(slots=True)
class _FilterControls:
    hide_inactive_checkbox: QCheckBox
    hide_neighbours_checkbox: QCheckBox
    arp_spoofing_checkbox: QCheckBox
    refresh_arp_button: QPushButton
    select_button: QPushButton


class SafeQTableWidget(QTableWidget):
    """A subclass of QTableWidget that ensures the selection model is of the correct type."""

    def selectionModel(self) -> QItemSelectionModel:
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        return ensure_instance(super().selectionModel(), QItemSelectionModel)

    def verticalHeader(self) -> QHeaderView:
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().verticalHeader(), QHeaderView)

    def horizontalHeader(self) -> QHeaderView:
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().horizontalHeader(), QHeaderView)


class InterfaceSelectionDialog(QDialog):
    """Display a dialog to select the capture network interface.

    When *mac_lookup* and *tshark_path* are supplied the dialog polls
    the OS every few seconds so that plugged/unplugged or
    enabled/disabled adapters appear and disappear in real time.
    """

    _REFRESH_INTERVAL_MS = 3_000

    # Bridges background ARP-refresh worker -> GUI thread (queued connection).
    _arp_refresh_progress_signal = pyqtSignal(int, int)
    _arp_refresh_done_signal = pyqtSignal()

    def __init__(  # noqa: PLR0913  # pylint: disable=too-many-arguments
        self,
        screen_width: int,
        screen_height: int,
        interfaces: list[Interface],
        filter_defaults: tuple[bool, bool, bool],
        *,
        mac_lookup: MacLookup | None = None,
        tshark_path: str | None = None,
    ) -> None:
        """Initialize the interface selection dialog.

        Args:
            screen_width: Screen width in pixels.
            screen_height: Screen height in pixels.
            interfaces: Available Interface objects to display.
            filter_defaults: Default states as (hide_inactive, hide_neighbours, arp_spoofing).
            mac_lookup: Optional MacLookup instance for live refresh.
            tshark_path: Optional TShark path for live refresh.
        """
        super().__init__()

        hide_inactive_default, hide_neighbours_default, arp_spoofing_default = filter_defaults

        # Set up the window
        self.setWindowTitle('Capture Network Interface Selection - Session Sniffer')
        # Set a minimum size for the window
        self.setMinimumSize(800, 600)
        resize_window_for_screen(self, screen_width, screen_height)

        # Custom variables
        self.selected_interface: SelectedInterfaceRow | None = None

        self._data: _InterfaceData = _InterfaceData(all_interfaces=interfaces)
        self.hide_inactive_enabled = hide_inactive_default
        self.hide_neighbours_enabled = hide_neighbours_default

        # Layout for the dialog
        layout = QVBoxLayout()

        # Header above the table
        header_label = QLabel('Available Network Interfaces for Packet Capture')
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_label.setStyleSheet('font-size: 16pt; font-weight: bold; margin-bottom: 10px;')
        layout.addWidget(header_label)

        # Table widget for displaying interfaces
        self.table: SafeQTableWidget = SafeQTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ['Name', 'Description', 'Type', 'Packets Sent', 'Packets Received', 'Gateway IP', 'IP Address', 'MAC Address', 'Vendor Name'],
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        # Connect cell hover to tooltip logic
        self.table.cellEntered.connect(self.show_tooltip_if_elided)

        horizontal_header = self.table.horizontalHeader()
        horizontal_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        horizontal_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        horizontal_header.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        horizontal_header.setStretchLastSection(True)

        vertical_header = self.table.verticalHeader()
        vertical_header.setVisible(False)

        # Add widgets to layout
        layout.addWidget(self.table)

        # Filter controls layout
        filter_layout = QHBoxLayout()
        filter_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        refresh_arp_button = QPushButton('Refresh ARP Table')
        refresh_arp_button.setToolTip('Flush the Windows ARP cache and ping the local subnet to rediscover devices')
        refresh_arp_button.setStyleSheet(self._REFRESH_ARP_BUTTON_BASE_STYLE)
        refresh_arp_button.setEnabled(mac_lookup is not None and tshark_path is not None)
        refresh_arp_button.clicked.connect(self._on_refresh_arp_clicked)
        # Lock to its natural idle size so the in-button progress fill / percentage text never resizes it.
        refresh_arp_button.setFixedSize(refresh_arp_button.sizeHint())
        filter_layout.addWidget(refresh_arp_button)

        hide_inactive_checkbox = QCheckBox('Hide Inactive Interfaces')
        hide_inactive_checkbox.setChecked(hide_inactive_default)
        hide_inactive_checkbox.setToolTip('Hide interfaces with no traffic, disconnected media, or missing IP addresses')
        hide_inactive_checkbox.setStyleSheet('font-size: 12pt;')
        hide_inactive_checkbox.stateChanged.connect(self.apply_filters)
        filter_layout.addWidget(hide_inactive_checkbox)

        hide_neighbours_checkbox = QCheckBox('Hide Neighbours')
        hide_neighbours_checkbox.setChecked(hide_neighbours_default)
        hide_neighbours_checkbox.setToolTip('Hide neighbour entries (devices discovered via ARP on the local network)')
        hide_neighbours_checkbox.setStyleSheet('font-size: 12pt;')
        hide_neighbours_checkbox.stateChanged.connect(self.apply_filters)
        hide_neighbours_checkbox.stateChanged.connect(self.enforce_spoofing_constraints)
        filter_layout.addWidget(hide_neighbours_checkbox)

        arp_spoofing_checkbox = QCheckBox('Enable ARP Spoofing')
        arp_spoofing_checkbox.setChecked(arp_spoofing_default)
        arp_spoofing_checkbox.setToolTip('Capture packets from other devices on your local network, not just this computer')
        arp_spoofing_checkbox.setStyleSheet('font-size: 12pt;')
        arp_spoofing_checkbox.stateChanged.connect(self.apply_filters)
        arp_spoofing_checkbox.stateChanged.connect(self.enforce_spoofing_constraints)
        filter_layout.addWidget(arp_spoofing_checkbox)

        # Will be set on accept
        self.arp_spoofing_enabled: bool = arp_spoofing_default

        # Tracks whether an ARP refresh worker is currently running.
        self._arp_refresh_in_progress: bool = False
        # Updated from worker threads with (completed, total) ping counts. (0, 0) means flushing / no ping work yet.
        self._arp_refresh_progress: tuple[int, int] = (0, 0)
        # GUI-thread animation state for the in-button progress indicator.
        self._arp_refresh_sweep_phase: int = 0
        self._arp_refresh_progress_timer: QTimer | None = None
        self._arp_refresh_original_text: str | None = None

        layout.addLayout(filter_layout)

        # Bottom layout for buttons
        bottom_layout = QHBoxLayout()
        instruction_label = QLabel('Select the network interface you want to sniff.')
        instruction_label.setStyleSheet('font-size: 15pt;')

        select_button = QPushButton('Start Sniffing')
        select_button.setStyleSheet('font-size: 18pt;')
        select_button.setEnabled(False)  # Initially disabled

        # Set fixed size for the button
        select_button.setFixedSize(300, 50)  # Adjusted width and height for slightly larger button

        select_button.clicked.connect(self.select_interface)

        self._controls: _FilterControls = _FilterControls(
            hide_inactive_checkbox=hide_inactive_checkbox,
            hide_neighbours_checkbox=hide_neighbours_checkbox,
            arp_spoofing_checkbox=arp_spoofing_checkbox,
            refresh_arp_button=refresh_arp_button,
            select_button=select_button,
        )

        bottom_layout.addWidget(instruction_label)
        bottom_layout.addWidget(select_button)

        # Center the button in the layout
        bottom_layout.setAlignment(instruction_label, Qt.AlignmentFlag.AlignCenter)
        bottom_layout.setAlignment(select_button, Qt.AlignmentFlag.AlignCenter)

        layout.addLayout(bottom_layout)

        # Populate the table with initial filtered data (after button is created)
        self.apply_filters()
        self.setLayout(layout)

        # Connect selection change signal to enable/disable Select button
        selection_model = self.table.selectionModel()
        selection_model.selectionChanged.connect(self.update_select_button_state)
        selection_model.selectionChanged.connect(self.enforce_spoofing_constraints)

        # Connect double-click signal to select interface (simulates Start button)
        self.table.cellDoubleClicked.connect(self.on_cell_double_clicked)

        # Apply initial constraints
        self.enforce_spoofing_constraints()

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Live refresh: periodically re-query the OS for adapter changes
        self._mac_lookup = mac_lookup
        self._tshark_path = tshark_path
        self._refresh_timer: QTimer | None = None
        if mac_lookup is not None and tshark_path is not None:
            self._refresh_timer = QTimer(self)
            self._refresh_timer.setInterval(self._REFRESH_INTERVAL_MS)
            self._refresh_timer.timeout.connect(self._live_refresh_interfaces)
            self._refresh_timer.start()

        # Wire ARP-refresh worker bridges (queued by default since worker lives in another thread).
        self._arp_refresh_progress_signal.connect(self._on_arp_refresh_progress)
        self._arp_refresh_done_signal.connect(self._on_refresh_arp_finished)

    # Custom Methods:
    _REFRESH_ARP_BUTTON_BASE_STYLE = 'font-size: 12pt;'
    _REFRESH_ARP_PROGRESS_TIMER_MS = 80
    # Polished silvery grey for the filled portion (light -> slightly darker across the bar).
    _REFRESH_ARP_PROGRESS_FILL_LIGHT = '#e6e6e6'
    _REFRESH_ARP_PROGRESS_FILL_DARK = '#9a9a9a'
    # Darker grey gradient for the unfilled track.
    _REFRESH_ARP_PROGRESS_TRACK_LIGHT = '#4a4a4a'
    _REFRESH_ARP_PROGRESS_TRACK_DARK = '#2e2e2e'

    def _format_refresh_arp_progress_style(self, fraction: float) -> str:
        """Build a stylesheet that renders a horizontal grey gradient progress fill inside the button."""
        clamped = max(0.0, min(1.0, fraction))
        # Two stops at the same point keep the color transition crisp instead of blended.
        next_stop = min(1.0, clamped + 0.0001)
        # Text color flips to dark once enough of the bar is filled to keep contrast readable.
        text_color = '#1a1a1a' if clamped >= 0.45 else '#f0f0f0'  # noqa: PLR2004
        return (
            'QPushButton {'
            ' font-size: 12pt;'
            ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            f' stop:0 {self._REFRESH_ARP_PROGRESS_FILL_LIGHT},'
            f' stop:{clamped:.4f} {self._REFRESH_ARP_PROGRESS_FILL_DARK},'
            f' stop:{next_stop:.4f} {self._REFRESH_ARP_PROGRESS_TRACK_LIGHT},'
            f' stop:1 {self._REFRESH_ARP_PROGRESS_TRACK_DARK});'
            f' color: {text_color};'
            ' font-weight: bold;'
            ' border: 1px solid #1a1a1a;'
            ' border-radius: 4px;'
            ' padding: 4px 12px;'
            ' }'
        )

    def _refresh_arp_progress_tick(self) -> None:
        """GUI-thread tick: render current ARP-refresh progress on the button."""
        button = self._controls.refresh_arp_button
        completed, total = self._arp_refresh_progress

        if total <= 0:
            # Flush phase or no subnets to ping: indeterminate sweep.
            sweep_period = 20  # ticks per full sweep
            self._arp_refresh_sweep_phase = (self._arp_refresh_sweep_phase + 1) % sweep_period
            fraction = self._arp_refresh_sweep_phase / (sweep_period - 1)
            button.setText('0%')
        else:
            fraction = completed / total
            button.setText(f'{int(fraction * 100)}%')

        button.setStyleSheet(self._format_refresh_arp_progress_style(fraction))

    def _on_refresh_arp_clicked(self) -> None:
        """Flush the Windows ARP cache and ping the local subnet to rediscover devices.

        Runs the ARP refresh on a background daemon thread so the GUI remains
        responsive, then triggers a live interface refresh on completion.
        """
        if self._arp_refresh_in_progress:
            return
        if self._mac_lookup is None or self._tshark_path is None:
            return

        self._arp_refresh_in_progress = True
        button = self._controls.refresh_arp_button
        self._arp_refresh_original_text = button.text()
        button.setEnabled(False)

        # Reset progress state and start the GUI-side animation timer.
        self._arp_refresh_progress = (0, 0)
        self._arp_refresh_sweep_phase = 0
        self._refresh_arp_progress_tick()
        if self._arp_refresh_progress_timer is None:
            self._arp_refresh_progress_timer = QTimer(self)
            self._arp_refresh_progress_timer.setInterval(self._REFRESH_ARP_PROGRESS_TIMER_MS)
            self._arp_refresh_progress_timer.timeout.connect(self._refresh_arp_progress_tick)
        self._arp_refresh_progress_timer.start()

        interfaces_snapshot = list(self._data.all_interfaces)
        progress_signal = self._arp_refresh_progress_signal
        done_signal = self._arp_refresh_done_signal

        def on_progress(completed: int, total: int) -> None:
            # Called from worker threads; emit queued signal to marshal onto GUI thread.
            progress_signal.emit(completed, total)

        def worker() -> None:
            from session_sniffer.capture.utils.arp_refresh import refresh_arp_table  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

            try:
                refresh_arp_table(interfaces_snapshot, on_progress)
            finally:
                done_signal.emit()

        Thread(target=worker, name='ARPRefresh-worker', daemon=True).start()

    def _on_arp_refresh_progress(self, completed: int, total: int) -> None:
        """GUI-thread slot: store the latest worker-reported ping progress."""
        self._arp_refresh_progress = (completed, total)

    def _on_refresh_arp_finished(self) -> None:
        """Restore the Refresh ARP button and trigger an immediate live refresh."""
        self._arp_refresh_in_progress = False
        if self._arp_refresh_progress_timer is not None:
            self._arp_refresh_progress_timer.stop()
        button = self._controls.refresh_arp_button
        button.setStyleSheet(self._REFRESH_ARP_BUTTON_BASE_STYLE)
        button.setText(self._arp_refresh_original_text or 'Refresh ARP Table')
        button.setEnabled(self._mac_lookup is not None and self._tshark_path is not None)
        self._live_refresh_interfaces()

    def _live_refresh_interfaces(self) -> None:
        """Re-query the OS for adapter changes and rebuild the table.

        Preserves the user's current selection by matching on
        (interface_name, ip_address, is_arp).
        """
        from session_sniffer.capture.interface_setup import refresh_available_interfaces  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

        if self._mac_lookup is None or self._tshark_path is None:
            return

        # Snapshot the current selection identity before refresh
        selected_key: tuple[str, str, bool] | None = None
        current_row = self.table.currentRow()
        if current_row != -1 and 0 <= current_row < len(self._data.interface_rows):
            iface, ip, is_arp = self._data.interface_rows[current_row]
            selected_key = (iface.identity.name, ip, is_arp)

        new_interfaces = refresh_available_interfaces(self._mac_lookup, self._tshark_path)
        self._data.all_interfaces = new_interfaces
        self.apply_filters()

        # Restore selection by matching the key
        if selected_key is not None:
            for idx, (iface, ip, is_arp) in enumerate(self._data.interface_rows):
                if (iface.identity.name, ip, is_arp) == selected_key:
                    self.table.selectRow(idx)
                    break

    def apply_filters(self) -> None:
        """Apply the selected filters and populate the table."""
        # Preserve currently selected row (by object identity) before filtering/rebuilding table
        previously_selected_row: tuple[Interface, str, bool] | None = None
        current_row = self.table.currentRow()
        if current_row != -1 and 0 <= current_row < len(self._data.interface_rows):
            previously_selected_row = self._data.interface_rows[current_row]

        hide_inactive = self._controls.hide_inactive_checkbox.isChecked()
        hide_neighbours = self._controls.hide_neighbours_checkbox.isChecked()

        # Build filtered list of (Interface, ip_address, is_arp) rows
        self._data.interface_rows = []
        for interface in self._data.all_interfaces:
            is_inactive = interface.is_interface_inactive()

            if hide_inactive and is_inactive:
                continue

            # Add rows for regular IP addresses
            if interface.ip_addresses:
                for ip_address in interface.ip_addresses:
                    self._data.interface_rows.append((interface, ip_address, False))
            else:
                # No IP addresses, show one row with 'N/A'
                self._data.interface_rows.append((interface, 'N/A', False))

            # Add rows for ARP entries
            if not hide_neighbours:
                for arp_entry in interface.arp_entries:
                    self._data.interface_rows.append((interface, arp_entry.ip_address, True))

        self.populate_table()

        # Attempt to restore previous selection if still present & logically allowed
        if previously_selected_row is not None:
            # If ARP spoofing enabled and previous selection is NOT an ARP entry, do not restore (it becomes greyed out)
            interface, _ip, is_arp = previously_selected_row
            if not (self._controls.arp_spoofing_checkbox.isChecked() and not is_arp):
                for idx, row in enumerate(self._data.interface_rows):
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
            self._data.interface_rows,
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
        arp_spoofing_enabled = self._controls.arp_spoofing_checkbox.isChecked()

        # Populate with filtered data
        for idx, (interface, ip_address, is_arp) in enumerate(self._data.interface_rows):
            self.table.insertRow(idx)

            # Determine if this row should be disabled (greyed out)
            should_disable = arp_spoofing_enabled and not is_arp

            # Get display values
            mac_address = interface.identity.mac_address or 'N/A'
            vendor_name = interface.identity.vendor_name or 'N/A'
            packets_sent = interface.traffic.packets_sent
            packets_recv = interface.traffic.packets_recv

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
            name_display = interface.identity.name
            item = QTableWidgetItem(name_display)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 0, item)

            # Description
            item = QTableWidgetItem(interface.identity.description)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 1, item)

            # Type
            # ARP rows under a Bridged/Shared interface inherit the parent's type because their
            # traffic flows through this machine; otherwise they are plain neighbors.
            type_display = (
                interface.interface_type
                if not is_arp or interface.interface_type in (INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARED)
                else INTERFACE_TYPE_NEIGHBOUR
            )
            item = QTableWidgetItem(type_display)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 2, item)

            # Packets Sent
            item = QTableWidgetItem(packets_sent_str)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 3, item)

            # Packets Received
            item = QTableWidgetItem(packets_recv_str)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 4, item)

            # Gateway IP
            gateway_ip = interface.gateway_addresses[0] if interface.gateway_addresses else 'N/A'
            item = QTableWidgetItem(gateway_ip)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 5, item)

            # IP Address
            item = QTableWidgetItem(ip_address)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 6, item)

            # MAC Address
            item = QTableWidgetItem(mac_address)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 7, item)

            # Vendor Name
            item = QTableWidgetItem(vendor_name)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if should_disable:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(idx, 8, item)

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
            self._controls.select_button.setEnabled(True)
        else:
            self._controls.select_button.setEnabled(False)

    def enforce_spoofing_constraints(self) -> None:
        """Enforce logical constraints between neighbour visibility, ARP spoofing, and selected interface.

        Rules:
        - If neighbours are hidden, ARP spoofing must be disabled.
        - If a non-ARP interface is selected and spoofing is enabled, clear the selection.
        - If a non-ARP interface is selected, spoofing must be disabled.
        """
        # If neighbours are hidden -> disable and uncheck spoofing
        if self._controls.hide_neighbours_checkbox.isChecked():
            self._controls.arp_spoofing_checkbox.setChecked(False)
            self._controls.arp_spoofing_checkbox.setEnabled(False)
            return

        # Neighbours are visible -> allow spoofing checkbox, evaluate selection
        self._controls.arp_spoofing_checkbox.setEnabled(True)

        selected_row = self.table.currentRow()
        if selected_row == -1:
            # No selection yet; do not force any state
            return

        try:
            _, _, is_arp = self._data.interface_rows[selected_row]
        except IndexError:
            return

        # If ARP spoofing is enabled and selected interface is not ARP, clear selection
        if self._controls.arp_spoofing_checkbox.isChecked() and not is_arp:
            self.table.clearSelection()
            return

        # If a non-ARP interface is selected and spoofing is enabled, turn off spoofing
        if not is_arp and self._controls.arp_spoofing_checkbox.isChecked():
            self._controls.arp_spoofing_checkbox.setChecked(False)

    def on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle double-click on table cell - simulates clicking the Start button."""
        # Validate row index
        if row < 0 or row >= len(self._data.interface_rows):
            return

        # Check if this row is disabled (greyed out due to ARP spoofing)
        item = self.table.item(row, 0)
        if item is None or not item.flags() & Qt.ItemFlag.ItemIsEnabled:
            return

        # Select the row and trigger selection
        self.table.selectRow(row)
        self.select_interface()

    def select_interface(self) -> None:
        """Persist the current selection and close the dialog as accepted."""
        selected_row = self.table.currentRow()
        if selected_row != -1:
            # Retrieve the selected interface data
            interface, ip_address, is_arp = self._data.interface_rows[selected_row]
            self.selected_interface = SelectedInterfaceRow(
                interface=interface,
                ip_address=ip_address,
                is_arp=is_arp,
            )
            self.arp_spoofing_enabled = self._controls.arp_spoofing_checkbox.isChecked()
            self.hide_inactive_enabled = self._controls.hide_inactive_checkbox.isChecked()
            self.hide_neighbours_enabled = self._controls.hide_neighbours_checkbox.isChecked()
            self.accept()  # Close the dialog and set its result to QDialog.Accepted


def show_interface_selection_dialog(  # noqa: PLR0913  # pylint: disable=too-many-arguments
    screen_width: int,
    screen_height: int,
    interfaces: list[Interface],
    filter_defaults: tuple[bool, bool, bool],
    saved_selection: tuple[str | None, str | None, str | None] = (None, None, None),
    *,
    mac_lookup: MacLookup | None = None,
    tshark_path: str | None = None,
) -> tuple[SelectedInterfaceRow | None, bool, bool, bool]:
    """Show the interface selection dialog and return the chosen interface and toggles.

    Args:
        screen_width: Screen width in pixels.
        screen_height: Screen height in pixels.
        interfaces: Available Interface objects to display.
        filter_defaults: Default states as (hide_inactive, hide_neighbours, arp_spoofing).
        saved_selection: Previously saved (interface_name, ip_address, mac_address).
        mac_lookup: Optional MacLookup instance for live refresh.
        tshark_path: Optional TShark path for live refresh.

    Returns:
        Tuple of (selected_interface, arp_spoofing_enabled, hide_inactive_enabled, hide_neighbours_enabled).
    """
    hide_inactive_default, hide_neighbours_default, arp_spoofing_default = filter_defaults
    saved_interface_name, saved_ip_address, saved_mac_address = saved_selection
    # Create and show the interface selection dialog
    dialog = InterfaceSelectionDialog(
        screen_width,
        screen_height,
        interfaces,
        filter_defaults,
        mac_lookup=mac_lookup,
        tshark_path=tshark_path,
    )
    # Restore the previously saved interface selection
    dialog.restore_saved_interface_selection(saved_interface_name, saved_ip_address, saved_mac_address)

    if dialog.exec() == QDialog.DialogCode.Accepted:  # Blocks until the dialog is accepted or rejected
        return (
            dialog.selected_interface,
            dialog.arp_spoofing_enabled,
            dialog.hide_inactive_enabled,
            dialog.hide_neighbours_enabled,
        )
    return None, arp_spoofing_default, hide_inactive_default, hide_neighbours_default
