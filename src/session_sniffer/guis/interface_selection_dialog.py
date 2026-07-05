"""GUI dialog for selecting network capture interfaces.

This module provides the InterfaceSelectionDialog for displaying available
network interfaces and allowing users to select one for packet capture.
The dialog refreshes automatically so that plugged/unplugged or
enabled/disabled adapters appear and disappear in real time.
"""

from dataclasses import dataclass, field
from threading import Thread
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import QItemSelectionModel, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCursor, QFont, QIcon, QShowEvent
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
)

from session_sniffer.capture.interface_setup import refresh_available_interfaces
from session_sniffer.capture.utils.arp_refresh import refresh_arp_table
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.stylesheets import (
    INTERFACE_BOTTOM_CONTAINER_STYLESHEET,
    INTERFACE_BOTTOM_SEPARATOR_STYLESHEET,
    INTERFACE_TABLE_CONTAINER_STYLESHEET,
    format_interface_refresh_arp_progress_style,
    interface_checkbox_stylesheet,
    interface_header_label_stylesheet,
    interface_instruction_label_stylesheet,
    interface_refresh_arp_button_disabled_style,
    interface_refresh_arp_button_enabled_style,
    interface_select_button_disabled_style,
    interface_select_button_enabled_style,
    interface_table_stylesheet,
)
from session_sniffer.guis.utils import compute_ui_scale, make_padded_icon, render_svg_pixmap_from_resource, resize_window_for_screen
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.interface import INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_NEIGHBOUR, INTERFACE_TYPE_SHARED, Interface, SelectedInterfaceRow
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from PyQt6.QtGui import QKeyEvent

logger = get_logger(__name__)


def _calculate_interface_score(
    interface_row: tuple[Interface, str, bool],
    saved_selection: tuple[str | None, str | None, str | None],
) -> int:
    """Calculate weighted matching score for an interface row.

    Args:
        interface_row: Tuple of (interface, ip_address, is_neighbour)
        saved_selection: Tuple of (saved_interface_name, saved_ip_address, saved_mac_address)

    Returns:
        Weighted score: name match=4, MAC match=2, IP match=1
    """
    interface, ip_address, is_neighbour = interface_row
    saved_interface_name, saved_ip_address, saved_mac_address = saved_selection

    score = 0
    if saved_interface_name is not None and interface.identity.name == saved_interface_name:
        score += 4

    mac_address = (
        interface.identity.mac_address
        if not is_neighbour
        else (next((neighbour.mac_address for neighbour in interface.neighbour_entries if neighbour.ip_address == ip_address), None))
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
        interface_rows: List of (Interface, ip_address, is_neighbour) tuples
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

    for i, (interface, ip_address, is_neighbour) in enumerate(interface_rows):
        score = _calculate_interface_score(
            (interface, ip_address, is_neighbour),
            (saved_interface_name, saved_ip_address, saved_mac_address),
        )
        if not score:
            continue

        if score > best_score:
            best_score = score
            best_index = i
            ambiguous = False
        elif score == best_score:
            ambiguous = True

    if best_index is None or ambiguous:
        return None

    return best_index


@dataclass(slots=True)
class _InterfaceData:
    all_interfaces: list[Interface]
    interface_rows: list[tuple[Interface, str, bool]] = field(default_factory=list[tuple[Interface, str, bool]])


@dataclass(slots=True)
class _FilterControls:
    remember_interface_checkbox: QCheckBox
    hide_inactive_checkbox: QCheckBox
    hide_neighbours_checkbox: QCheckBox
    arp_spoofing_checkbox: QCheckBox
    refresh_arp_button: QPushButton
    select_button: QPushButton


class SafeQTableWidget(QTableWidget):
    """A subclass of QTableWidget that ensures the selection model is of the correct type."""

    @override
    def selectionModel(self) -> QItemSelectionModel:
        """Override the selectionModel method to ensure it returns a QItemSelectionModel."""
        return ensure_instance(super().selectionModel(), QItemSelectionModel)

    @override
    def verticalHeader(self) -> QHeaderView:
        """Override the verticalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().verticalHeader(), QHeaderView)

    @override
    def horizontalHeader(self) -> QHeaderView:
        """Override the horizontalHeader method to ensure it returns a QHeaderView."""
        return ensure_instance(super().horizontalHeader(), QHeaderView)


class RefreshARPButton(QPushButton):
    """A QPushButton that contains a full-size overlay QLabel without using a layout."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.overlay_label = QLabel(self)
        self.overlay_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.overlay_label.setTextFormat(Qt.TextFormat.RichText)
        self.overlay_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, on=True)
        self.overlay_label.setStyleSheet('background: transparent;')
        self.overlay_label.hide()

    @override
    def resizeEvent(self, event) -> None:
        """Resize the overlay label to match the button's size."""
        super().resizeEvent(event)
        self.overlay_label.resize(self.size())


class InterfaceSelectionDialog(QDialog):
    """Display a dialog to select the capture network interface.

    The dialog polls the OS every few seconds so that plugged/unplugged
    or enabled/disabled adapters appear and disappear in real time.
    """

    _REFRESH_INTERVAL_MS = 3_000

    # Bridges background ARP-refresh worker -> GUI thread (queued connection).
    _arp_refresh_progress_signal = pyqtSignal(int, int, str)
    _arp_refresh_done_signal = pyqtSignal()

    def __init__(
        self,
        screen_size: tuple[int, int],
        interfaces: list[Interface],
        filter_defaults: tuple[bool, bool, bool],
    ) -> None:
        """Initialize the interface selection dialog.

        Args:
            screen_size: Screen dimensions as (width, height) in pixels.
            interfaces: Available Interface objects to display.
            filter_defaults: Default states as (hide_inactive, hide_neighbours, arp_spoofing).
        """
        super().__init__()
        self.setWindowModality(Qt.WindowModality.WindowModal)

        hide_inactive_default, hide_neighbours_default, arp_spoofing_default = filter_defaults

        # UI scale factor - 2K (2560x1440) is the design baseline (1.0).
        # Smaller screens receive proportionally reduced font sizes, row heights and spacings.
        ui_scale = compute_ui_scale(screen_size)
        self._ui_scale = ui_scale

        def scale(value: int) -> int:
            return max(1, round(value * ui_scale))

        # Set up the window
        self.setWindowTitle('Capture Network Interface Selection - Session Sniffer')
        # Set a minimum size for the window
        self.setMinimumSize(scale(1150), scale(620))
        resize_window_for_screen(self, screen_size)

        # Custom variables
        self.selected_interface: SelectedInterfaceRow | None = None

        self._data: _InterfaceData = _InterfaceData(all_interfaces=interfaces)
        self.hide_inactive_enabled = hide_inactive_default
        self.hide_neighbours_enabled = hide_neighbours_default

        # Layout for the dialog
        layout = QVBoxLayout()
        layout.setContentsMargins(scale(12), scale(16), scale(12), scale(12))
        layout.setSpacing(scale(16))

        # Header above the table
        header_label = QLabel('Available Network Interfaces for Packet Capture')
        header_label.setObjectName('dialogTitleLabel')
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_label.setStyleSheet(interface_header_label_stylesheet(ui_scale))
        layout.addWidget(header_label)

        # Table widget for displaying interfaces
        self.table: SafeQTableWidget = SafeQTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ['Name', 'Description', 'Type', 'Packets Sent', 'Packets Received', 'Gateway IP', 'IP Address', 'MAC Address', 'Vendor Name'],
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setStyleSheet(interface_table_stylesheet(ui_scale))

        # Connect cell hover to tooltip logic
        self.table.cellEntered.connect(self.show_tooltip_if_elided)

        horizontal_header = self.table.horizontalHeader()
        header_font = QFont()
        header_font.setPixelSize(scale(14))
        header_font.setBold(True)
        horizontal_header.setFont(header_font)
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
        vertical_header.setDefaultSectionSize(scale(48))

        # Table container with a subtle dark-blue border matching the bottom container
        table_container = QFrame()
        table_container.setObjectName('tableContainer')
        table_container.setFrameShape(QFrame.Shape.NoFrame)
        table_container.setStyleSheet(INTERFACE_TABLE_CONTAINER_STYLESHEET)
        table_container_layout = QVBoxLayout(table_container)
        table_container_layout.setContentsMargins(0, 0, 0, 0)
        table_container_layout.setSpacing(0)
        table_container_layout.addWidget(self.table)

        # Add widgets to layout
        layout.addWidget(table_container)

        # Filter controls layout
        options_layout = QHBoxLayout()
        options_layout.setSpacing(scale(24))
        options_layout.addStretch()

        refresh_arp_button = RefreshARPButton('Refresh ARP Table')
        refresh_arp_button.setToolTip('Ping local subnet devices via ICMP to repopulate the ARP neighbour cache')
        refresh_arp_button.setStyleSheet(interface_refresh_arp_button_enabled_style(self._ui_scale))
        refresh_arp_button.clicked.connect(self._on_refresh_arp_clicked)
        refresh_arp_button.setMinimumHeight(scale(58))
        refresh_arp_button.setFixedWidth(scale(320))
        _refresh_pad = scale(10)
        _refresh_w, _refresh_h = scale(36), scale(28)
        self._refresh_arp_icon = make_padded_icon(
            QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')),
            (_refresh_w, _refresh_h),
            _refresh_pad,
        )
        refresh_arp_button.setIcon(self._refresh_arp_icon)
        refresh_arp_button.setIconSize(QSize(_refresh_w + _refresh_pad, _refresh_h))

        # Rich-text overlay shown only during a refresh; lets us style the
        # percentage line and the IP/count line independently inside the button.
        refresh_arp_overlay = refresh_arp_button.overlay_label
        self._refresh_arp_overlay = refresh_arp_overlay

        options_layout.addWidget(refresh_arp_button)

        remember_interface_checkbox = QCheckBox('Remember Interface')
        remember_interface_checkbox.setObjectName('remember_interface_checkbox')
        remember_interface_checkbox.setChecked(Settings.gui_interface_selection_auto_connect)
        remember_interface_checkbox.setToolTip('Automatically reconnect to this interface on the next startup without showing this dialog')
        remember_interface_checkbox.setStyleSheet(
            interface_checkbox_stylesheet('remember_interface_checkbox', ui_scale),
        )
        remember_interface_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        options_layout.addWidget(remember_interface_checkbox)

        hide_inactive_checkbox = QCheckBox('Hide Inactive Interfaces')
        hide_inactive_checkbox.setObjectName('hide_inactive_checkbox')
        hide_inactive_checkbox.setChecked(hide_inactive_default)
        hide_inactive_checkbox.setToolTip('Hide disabled, disconnected, unconfigured, or interfaces with no traffic')
        hide_inactive_checkbox.setStyleSheet(
            interface_checkbox_stylesheet('hide_inactive_checkbox', ui_scale),
        )
        hide_inactive_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        hide_inactive_checkbox.stateChanged.connect(self.apply_filters)
        options_layout.addWidget(hide_inactive_checkbox)

        hide_neighbours_checkbox = QCheckBox('Hide Neighbours')
        hide_neighbours_checkbox.setObjectName('hide_neighbours_checkbox')
        hide_neighbours_checkbox.setChecked(hide_neighbours_default)
        hide_neighbours_checkbox.setToolTip('Hide neighbour entries (devices discovered via ARP on the local network)')
        hide_neighbours_checkbox.setStyleSheet(
            interface_checkbox_stylesheet('hide_neighbours_checkbox', ui_scale),
        )
        hide_neighbours_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        hide_neighbours_checkbox.stateChanged.connect(self.apply_filters)
        hide_neighbours_checkbox.stateChanged.connect(self.enforce_spoofing_constraints)
        options_layout.addWidget(hide_neighbours_checkbox)

        arp_spoofing_checkbox = QCheckBox('Enable ARP Spoofing')
        arp_spoofing_checkbox.setObjectName('arp_spoofing_checkbox')
        arp_spoofing_checkbox.setChecked(arp_spoofing_default)
        arp_spoofing_checkbox.setToolTip('Capture packets from other devices on your local network instead of this computer')
        arp_spoofing_checkbox.setStyleSheet(
            interface_checkbox_stylesheet('arp_spoofing_checkbox', ui_scale),
        )
        arp_spoofing_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        arp_spoofing_checkbox.stateChanged.connect(self._on_arp_spoofing_changed)
        arp_spoofing_checkbox.stateChanged.connect(self.apply_filters)
        options_layout.addWidget(arp_spoofing_checkbox)

        # Will be set on accept
        self.arp_spoofing_enabled: bool = arp_spoofing_default
        self.remember_interface_enabled: bool = Settings.gui_interface_selection_auto_connect

        # Tracks whether an ARP refresh worker is currently running.
        self._arp_refresh_in_progress: bool = False
        # Updated from worker threads with (completed, total) ping counts. (0, 0) means no ping work yet.
        self._arp_refresh_progress: tuple[int, int] = (0, 0)
        # Most recently completed ping target, shown under the Refresh button.
        self._arp_refresh_last_ip: str = ''
        # GUI-thread animation state for the in-button progress indicator.
        self._arp_refresh_sweep_phase: int = 0
        self._arp_refresh_progress_timer: QTimer | None = None
        self._arp_refresh_original_text: str | None = None

        # Bottom container wrapping options row, separator and action row
        bottom_container = QFrame()
        bottom_container.setObjectName('bottomContainer')
        bottom_container.setFrameShape(QFrame.Shape.NoFrame)
        bottom_container.setStyleSheet(INTERFACE_BOTTOM_CONTAINER_STYLESHEET)
        container_layout = QVBoxLayout(bottom_container)
        container_layout.setContentsMargins(scale(28), scale(18), scale(28), scale(20))
        container_layout.setSpacing(0)

        options_layout.addStretch()
        container_layout.addLayout(options_layout)
        container_layout.addSpacing(scale(16))

        # Horizontal separator between options row and action row
        separator = QFrame()
        separator.setObjectName('bottomSeparator')
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Plain)
        separator.setStyleSheet(INTERFACE_BOTTOM_SEPARATOR_STYLESHEET)
        container_layout.addWidget(separator)
        container_layout.addSpacing(scale(20))

        # Action row: info text left, Start button right
        action_layout = QHBoxLayout()
        action_layout.addSpacing(scale(50))
        info_icon_label = QLabel()
        info_icon_label.setPixmap(render_svg_pixmap_from_resource('info.svg', scale(32), scale(32)))
        info_icon_label.setFixedSize(scale(36), scale(36))
        info_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        instruction_label = QLabel('Select a network interface to start packet capture.')
        instruction_label.setStyleSheet(interface_instruction_label_stylesheet(ui_scale))
        action_layout.addWidget(info_icon_label)
        action_layout.addSpacing(scale(8))
        action_layout.addWidget(instruction_label)
        action_layout.addStretch()

        select_button = QPushButton('Start Sniffing')
        select_button.setStyleSheet(interface_select_button_disabled_style(self._ui_scale))
        select_button.setEnabled(False)  # Initially disabled
        select_button.setMinimumSize(scale(330), scale(56))
        _play_pad = scale(10)
        _play_w, _play_h = scale(46), scale(28)
        select_button.setIcon(
            make_padded_icon(
                QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')),
                (_play_w, _play_h),
                _play_pad,
            ),
        )
        select_button.setIconSize(QSize(_play_w + _play_pad, _play_h))
        select_button.clicked.connect(self.select_interface)

        self._controls: _FilterControls = _FilterControls(
            remember_interface_checkbox=remember_interface_checkbox,
            hide_inactive_checkbox=hide_inactive_checkbox,
            hide_neighbours_checkbox=hide_neighbours_checkbox,
            arp_spoofing_checkbox=arp_spoofing_checkbox,
            refresh_arp_button=refresh_arp_button,
            select_button=select_button,
        )

        action_layout.addWidget(select_button)
        action_layout.addSpacing(scale(50))
        container_layout.addLayout(action_layout)

        layout.addWidget(bottom_container)

        # Populate the table with initial filtered data (after button is created)
        self.apply_filters()
        self.setLayout(layout)

        # Connect selection change signal to enable/disable Select button
        selection_model = self.table.selectionModel()
        selection_model.selectionChanged.connect(self.update_select_button_state)

        # Connect double-click signal to select interface (simulates Start button)
        self.table.cellDoubleClicked.connect(self.on_cell_double_clicked)

        # Apply initial constraints
        self.enforce_spoofing_constraints()

        # Raise and activate window to ensure it gets focus
        self.raise_()
        self.activateWindow()

        # Live refresh: periodically re-query the OS for adapter changes
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(self._REFRESH_INTERVAL_MS)
        self._refresh_timer.timeout.connect(self._live_refresh_interfaces)
        self._refresh_timer.start()

        # Wire ARP-refresh worker bridges (queued by default since worker lives in another thread).
        self._arp_refresh_progress_signal.connect(self._on_arp_refresh_progress)
        self._arp_refresh_done_signal.connect(self._on_refresh_arp_finished)

    # Custom Methods:
    _REFRESH_ARP_PROGRESS_TIMER_MS = 80

    def _refresh_arp_progress_tick(self) -> None:
        """GUI-thread tick: render current ARP-refresh progress on the button."""
        button = self._controls.refresh_arp_button
        completed, total = self._arp_refresh_progress
        hide_neighbours = self._controls.hide_neighbours_checkbox.isChecked()

        # Always animate the dot trail so the button feels alive even after
        # the determinate fill takes over. Pad to a fixed width so the label
        # length stays constant and the centered text doesn't jitter.
        sweep_period = 40  # ticks per full back-and-forth cycle
        self._arp_refresh_sweep_phase = (self._arp_refresh_sweep_phase + 1) % sweep_period
        dot_count = 1 + (self._arp_refresh_sweep_phase // 5) % 3
        dots = ('.' * dot_count).ljust(3).replace(' ', '\u00a0')

        font_pt_main = max(1, round(14 * self._ui_scale))
        font_pt_sub = max(1, round(9 * self._ui_scale))

        if total <= 0:
            # No progress yet: indeterminate ping-pong sweep until first ping completes.
            half = sweep_period // 2
            phase = self._arp_refresh_sweep_phase
            fraction = phase / (half - 1) if phase < half else (sweep_period - 1 - phase) / (half - 1)
            main_text = f'Pinging{dots}'
            sub_text = 'Resolving subnets…'
        else:
            fraction = completed / total
            last_ip = self._arp_refresh_last_ip
            pct = f'{int(fraction * 100):>3}'.replace(' ', '\u00a0')
            main_text = f'Pinging\u00a0{pct}%\u00a0{dots}'
            # Pad IP to 15 chars (max IPv4 length) and counters to total's width
            # so the centered sub-line never jitters as values change. Spaces
            # are emitted as &nbsp; because Qt rich text collapses runs of
            # regular whitespace.
            total_width = len(f'{total:,}')
            counters = f'{completed:,}'.rjust(total_width).replace(' ', '\u00a0')
            ip_text = (last_ip or '').ljust(15).replace(' ', '\u00a0')
            sub_text = f'{ip_text}\u00a0\u00a0\u00a0({counters} / {total:,})'

        button.setText('')
        main_style = f'color:#ffffff; font-weight:700; font-size:{font_pt_main}pt; letter-spacing:1px;'
        sub_style = f'color:#ffd166; font-family:Consolas,monospace; font-size:{font_pt_sub}pt; letter-spacing:0.5px; margin-top:6px;'
        self._refresh_arp_overlay.setText(
            f'<div style="{main_style}">{main_text}</div><div style="{sub_style}">{sub_text}</div>',
        )
        button.setStyleSheet(format_interface_refresh_arp_progress_style(self._ui_scale, fraction, dimmed=hide_neighbours))

    def _on_refresh_arp_clicked(self) -> None:
        """Ping the local subnet via ICMP to repopulate the ARP neighbour cache.

        Runs the ARP refresh on a background daemon thread so the GUI remains
        responsive, then triggers a live interface refresh on completion.
        """
        if self._arp_refresh_in_progress:
            return

        self._arp_refresh_in_progress = True
        button = self._controls.refresh_arp_button
        self._arp_refresh_original_text = button.text()
        button.setEnabled(False)
        button.setIcon(QIcon())
        self._refresh_arp_overlay.show()

        # Reset progress state and start the GUI-side animation timer.
        self._arp_refresh_progress = (0, 0)
        self._arp_refresh_sweep_phase = 0
        self._arp_refresh_last_ip = ''
        self._refresh_arp_progress_tick()
        if self._arp_refresh_progress_timer is None:
            self._arp_refresh_progress_timer = QTimer(self)
            self._arp_refresh_progress_timer.setInterval(self._REFRESH_ARP_PROGRESS_TIMER_MS)
            self._arp_refresh_progress_timer.timeout.connect(self._refresh_arp_progress_tick)
        self._arp_refresh_progress_timer.start()

        interfaces_snapshot = list(self._data.all_interfaces)
        progress_signal = self._arp_refresh_progress_signal
        done_signal = self._arp_refresh_done_signal

        def on_progress(completed: int, total: int, ip: str) -> None:
            # Called from worker threads; emit queued signal to marshal onto GUI thread.
            progress_signal.emit(completed, total, ip)

        def worker() -> None:
            try:
                refresh_arp_table(interfaces_snapshot, on_progress)
            finally:
                done_signal.emit()

        Thread(target=worker, name='ARPRefresh-worker', daemon=True).start()

    def _on_arp_refresh_progress(self, completed: int, total: int, ip: str) -> None:
        """GUI-thread slot: store the latest worker-reported ping progress."""
        self._arp_refresh_progress = (completed, total)
        if ip:
            self._arp_refresh_last_ip = ip

    def _on_refresh_arp_finished(self) -> None:
        """Restore the Refresh ARP button and trigger an immediate live refresh."""
        self._arp_refresh_in_progress = False
        if self._arp_refresh_progress_timer is not None:
            self._arp_refresh_progress_timer.stop()
        button = self._controls.refresh_arp_button
        self._refresh_arp_overlay.hide()
        self._refresh_arp_overlay.clear()
        button.setText(self._arp_refresh_original_text or 'Refresh ARP Table')
        button.setIcon(self._refresh_arp_icon)
        self.enforce_spoofing_constraints()
        self._live_refresh_interfaces()

    def _live_refresh_interfaces(self) -> None:
        """Re-query the OS for adapter changes and rebuild the table.

        Preserves the user's current selection by matching on
        (interface_name, ip_address, is_neighbour).
        """
        # Snapshot the current selection identity before refresh
        selected_key: tuple[str, str, bool] | None = None
        current_row = self.table.currentRow()
        if current_row != -1 and 0 <= current_row < len(self._data.interface_rows):
            iface, ip, is_neighbour = self._data.interface_rows[current_row]
            selected_key = (iface.identity.name, ip, is_neighbour)

        new_interfaces = refresh_available_interfaces()
        self._data.all_interfaces = new_interfaces
        self.apply_filters()

        # Restore selection by matching the key
        if selected_key is not None:
            for i, (iface, ip, is_neighbour) in enumerate(self._data.interface_rows):
                if (iface.identity.name, ip, is_neighbour) == selected_key:
                    self.table.selectRow(i)
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
        arp_spoofing = self._controls.arp_spoofing_checkbox.isChecked()

        # Build filtered list of (Interface, ip_address, is_neighbour) rows
        self._data.interface_rows = []
        for interface in self._data.all_interfaces:
            is_inactive = interface.is_interface_inactive()

            if hide_inactive and is_inactive:
                continue

            if not interface.ip_addresses:
                logger.debug('Skipping interface %r: no IP addresses assigned.', interface.identity.name)
                continue

            # When ARP spoofing is enabled only show neighbour entries.
            if not arp_spoofing:
                # Add rows for regular IP addresses, skipping loopback
                for ip_address in interface.ip_addresses:
                    if ip_address == '127.0.0.1':
                        continue
                    self._data.interface_rows.append((interface, ip_address, False))

            # Add rows for neighbour entries
            if not hide_neighbours:
                for neighbour_entry in interface.neighbour_entries:
                    self._data.interface_rows.append((interface, neighbour_entry.ip_address, True))

        self.populate_table()

        # Attempt to restore previous selection if still present & logically allowed
        if previously_selected_row is not None:
            for i, row in enumerate(self._data.interface_rows):
                if row == previously_selected_row:
                    self.table.selectRow(i)
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

        for i, (interface, ip_address, is_neighbour) in enumerate(self._data.interface_rows):
            self.table.insertRow(i)

            # Get display values
            mac_address = interface.identity.mac_address or 'N/A'
            vendor_name = interface.identity.vendor_name or 'N/A'
            packets_sent = interface.traffic.packets_sent
            packets_recv = interface.traffic.packets_recv

            # For neighbour entries, get the specific neighbour data
            if is_neighbour:
                neighbour_entry = next((neighbour for neighbour in interface.neighbour_entries if neighbour.ip_address == ip_address), None)
                if neighbour_entry:
                    mac_address = neighbour_entry.mac_address
                    vendor_name = neighbour_entry.vendor_name or 'N/A'
                packets_sent_str = 'N/A'
                packets_recv_str = 'N/A'
            else:
                packets_sent_str = f'{packets_sent:,}'
                packets_recv_str = f'{packets_recv:,}'

            # Name column
            item = QTableWidgetItem(interface.identity.name)
            self.table.setItem(i, 0, item)

            # Description
            item = QTableWidgetItem(interface.identity.description)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 1, item)

            # Type
            # Neighbour rows under a Bridged/Shared interface inherit the parent's type because their
            # traffic flows through this machine; otherwise they are plain neighbors.
            type_display = (
                interface.interface_type if not is_neighbour or interface.interface_type in (INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARED) else INTERFACE_TYPE_NEIGHBOUR
            )
            item = QTableWidgetItem(type_display)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 2, item)

            # Packets Sent
            item = QTableWidgetItem(packets_sent_str)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 3, item)

            # Packets Received
            item = QTableWidgetItem(packets_recv_str)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 4, item)

            # Gateway IP
            gateway_ip = interface.gateway_addresses[0] if interface.gateway_addresses else 'N/A'
            item = QTableWidgetItem(gateway_ip)
            self.table.setItem(i, 5, item)

            # IP Address
            item = QTableWidgetItem(ip_address)
            self.table.setItem(i, 6, item)

            # MAC Address
            item = QTableWidgetItem(mac_address)
            self.table.setItem(i, 7, item)

            # Vendor Name
            item = QTableWidgetItem(vendor_name)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 8, item)

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
        selected_row = self.table.currentRow()
        if selected_row != -1:
            self._controls.select_button.setEnabled(True)
            self._controls.select_button.setStyleSheet(interface_select_button_enabled_style(self._ui_scale))
        else:
            self._controls.select_button.setEnabled(False)
            self._controls.select_button.setStyleSheet(interface_select_button_disabled_style(self._ui_scale))

    def _on_arp_spoofing_changed(self) -> None:
        """Mutual-exclusion handler: checking ARP Spoofing automatically unchecks Hide Neighbours."""
        if self._controls.arp_spoofing_checkbox.isChecked():
            self._controls.hide_neighbours_checkbox.setChecked(False)
        self.enforce_spoofing_constraints()

    def enforce_spoofing_constraints(self) -> None:
        """Enforce mutual exclusion: if Hide Neighbours is checked, ARP Spoofing must be unchecked."""
        hide_neighbours = self._controls.hide_neighbours_checkbox.isChecked()
        # If neighbours are hidden -> uncheck spoofing (mutual exclusion; neither checkbox is disabled)
        if hide_neighbours:
            self._controls.arp_spoofing_checkbox.setChecked(False)
        # While a refresh is running the tick manages button appearance; only update it when idle.
        if not self._arp_refresh_in_progress:
            arp_enabled = not hide_neighbours
            self._controls.refresh_arp_button.setEnabled(arp_enabled)
            self._controls.refresh_arp_button.setToolTip('Ping local subnet devices via ICMP to repopulate the ARP neighbour cache' if arp_enabled else '')
            self._controls.refresh_arp_button.setStyleSheet(
                interface_refresh_arp_button_enabled_style(self._ui_scale) if arp_enabled else interface_refresh_arp_button_disabled_style(self._ui_scale),
            )

    def on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle double-click on table cell - simulates clicking the Start button."""
        # Validate row index
        if row < 0 or row >= len(self._data.interface_rows):
            return

        # Select the row and trigger selection
        self.table.selectRow(row)
        self.select_interface()

    @override
    def keyPressEvent(self, a0: QKeyEvent | None) -> None:
        """Trigger interface selection when Enter/Return is pressed with a row selected."""
        if a0 is not None and a0.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self.table.currentRow() != -1:
            self.select_interface()
            return
        super().keyPressEvent(a0)

    def select_interface(self) -> None:
        """Persist the current selection and close the dialog as accepted."""
        selected_row = self.table.currentRow()
        if selected_row != -1:
            # Retrieve the selected interface data
            interface, ip_address, is_neighbour = self._data.interface_rows[selected_row]
            self.selected_interface = SelectedInterfaceRow(
                interface=interface,
                ip_address=ip_address,
                is_neighbour=is_neighbour,
            )
            self.arp_spoofing_enabled = self._controls.arp_spoofing_checkbox.isChecked()
            self.hide_inactive_enabled = self._controls.hide_inactive_checkbox.isChecked()
            self.hide_neighbours_enabled = self._controls.hide_neighbours_checkbox.isChecked()
            self.remember_interface_enabled = self._controls.remember_interface_checkbox.isChecked()
            self._refresh_timer.stop()
            if self._arp_refresh_progress_timer is not None:
                self._arp_refresh_progress_timer.stop()
            self.accept()  # Close the dialog and set its result to QDialog.Accepted

    @override
    def reject(self) -> None:
        """Stop timers and reject the dialog."""
        self._refresh_timer.stop()
        if self._arp_refresh_progress_timer is not None:
            self._arp_refresh_progress_timer.stop()
        super().reject()

    @override
    def showEvent(self, a0: QShowEvent | None) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if self.property('_should_maximize_on_show') is True:
            self.setProperty('_should_maximize_on_show', False)  # noqa: FBT003
            self.showMaximized()
