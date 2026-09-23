"""Hotspot and connection sharing management dialog."""

import logging
from typing import Final, cast, override

from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QHideEvent, QIcon, QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.hotspot_setup_guide import HotspotSetupGuideDialog
from session_sniffer.guis.ping_window import PingWindow
from session_sniffer.guis.port_scanner_window import PortScannerWindow
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
    HOTSPOT_BADGE_ACTIVE_STYLESHEET,
    HOTSPOT_BADGE_INACTIVE_STYLESHEET,
    HOTSPOT_BADGE_TRANSITION_STYLESHEET,
    HOTSPOT_CARD_HEADER_STYLESHEET,
    HOTSPOT_CARD_STYLESHEET,
    HOTSPOT_CHECKBOX_STYLESHEET,
    HOTSPOT_EMPTY_STATE_STYLESHEET,
    HOTSPOT_FIELD_LABEL_STYLESHEET,
    HOTSPOT_INPUT_STYLESHEET,
    HOTSPOT_PILL_INFO_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
)
from session_sniffer.guis.utils import (
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.networking.hotspot import (
    MAX_PASSPHRASE_LENGTH,
    MAX_SSID_LENGTH,
    MIN_PASSPHRASE_LENGTH,
    MIN_SSID_LENGTH,
    ConnectedDevice,
    HotspotInfo,
    configure_hotspot,
    disable_ics,
    enable_ics,
    get_connected_devices,
    get_hotspot_info,
    get_ics_status,
    is_admin,
    start_hotspot,
    stop_hotspot,
)
from session_sniffer.networking.interface import AllInterfaces

logger = logging.getLogger(__name__)

_EXPECTED_ICS_STATUS_TUPLE_LENGTH: Final[int] = 3


class HotspotActionWorker(CrashingQThread):
    """Background worker for asynchronous hotspot and connection sharing tasks."""

    info_ready = Signal(object)
    devices_ready = Signal(object)
    ics_status_ready = Signal(object)
    action_completed = Signal(bool, str)

    def __init__(self, task_name: str, **kwargs: object) -> None:
        """Initialize the HotspotActionWorker."""
        super().__init__()
        self._task_name = task_name
        self._kwargs = kwargs

    @override
    def _run(self) -> None:
        try:
            if self._task_name == 'refresh_all':
                info = get_hotspot_info()
                self.info_ready.emit(info)
                devices = get_connected_devices()
                self.devices_ready.emit(devices)
                ics_status = get_ics_status()
                self.ics_status_ready.emit(ics_status)

            elif self._task_name == 'configure_credentials':
                ssid = str(self._kwargs.get('ssid', ''))
                passphrase = str(self._kwargs.get('passphrase', ''))
                success, error_message = configure_hotspot(ssid, passphrase)
                self.action_completed.emit(success, error_message or 'Hotspot network name and password updated successfully.')

            elif self._task_name == 'start_hotspot':
                success, error_message = start_hotspot()
                self.action_completed.emit(success, error_message or 'Mobile Hotspot started.')

            elif self._task_name == 'stop_hotspot':
                success, error_message = stop_hotspot()
                self.action_completed.emit(success, error_message or 'Mobile Hotspot stopped.')

            elif self._task_name == 'enable_ics':
                public_adapter = str(self._kwargs.get('public_adapter', ''))
                private_adapter = str(self._kwargs.get('private_adapter', ''))
                success, error_message = enable_ics(public_adapter, private_adapter)
                self.action_completed.emit(success, error_message or f'Internet Connection Sharing enabled between {public_adapter} and {private_adapter}.')

            elif self._task_name == 'disable_ics':
                success, error_message = disable_ics()
                self.action_completed.emit(success, error_message or 'Internet Connection Sharing disabled.')

        except (OSError, RuntimeError) as e:
            logger.exception('Hotspot action worker failed on task %s', self._task_name)
            self.action_completed.emit(False, str(e))  # noqa: FBT003


class HotspotManagerWidget(QWidget):
    """Reusable widget for managing Wi-Fi Hotspots and Internet Connection Sharing (ICS)."""

    status_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HotspotManagerWidget."""
        super().__init__(parent)
        self.setObjectName('HotspotManagerWidget')
        self.setStyleSheet('QWidget#HotspotManagerWidget { background: transparent; background-color: transparent; }')

        self._current_hotspot_info: HotspotInfo | None = None
        self._current_devices: list[ConnectedDevice] = []
        self._is_password_revealed: bool = False
        self._active_worker: HotspotActionWorker | None = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(scale_by_ui(12))

        # 1. Header bar
        main_layout.addLayout(self._build_header_bar())

        # 2. Top row cards: Wi-Fi Hotspot & Sharing / Bridge side-by-side
        top_cards_layout = QHBoxLayout()
        top_cards_layout.setSpacing(scale_by_ui(12))
        top_cards_layout.addWidget(self._build_hotspot_card(), 1)
        top_cards_layout.addWidget(self._build_bridge_card(), 1)
        main_layout.addLayout(top_cards_layout)

        # 3. Bottom row card: Connected Devices
        main_layout.addWidget(self._build_devices_card(), 1)

        # 4. Status Bar
        self._status_bar_label = QLabel('Ready')
        self._status_bar_label.setStyleSheet('color: #9cb0c6; font-size: 8.5pt; padding-left: 6px; padding-bottom: 2px; background: transparent;')
        main_layout.addWidget(self._status_bar_label)

        # Auto-refresh timer (polls every 5 seconds while visible)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._start_refresh_task)

    def start_refresh(self) -> None:
        """Trigger an immediate status update and ensure the refresh timer is running."""
        self._populate_adapters()
        self._start_refresh_task()
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def cleanup(self) -> None:
        """Stop refresh timer and await any active background worker."""
        self._refresh_timer.stop()
        if self._active_worker and self._active_worker.isRunning():
            self._active_worker.wait(1000)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self.start_refresh()

    @override
    def hideEvent(self, event: QHideEvent) -> None:
        super().hideEvent(event)
        self._refresh_timer.stop()

    def _build_header_bar(self) -> QHBoxLayout:
        """Construct the top title bar and actions."""
        layout = QHBoxLayout()
        layout.setSpacing(scale_by_ui(10))

        icon_label = QLabel()
        icon_label.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'wifi.svg')).pixmap(scale_by_ui(26), scale_by_ui(26)))
        layout.addWidget(icon_label)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(scale_by_ui(2))
        title_label = QLabel('Hotspot & Connection Sharing')
        title_label.setStyleSheet('color: #f0f4fa; font-size: 13pt; font-weight: 700; background: transparent;')
        title_layout.addWidget(title_label)
        subtitle_label = QLabel('Share internet to consoles (PlayStation, Xbox, Switch) to sniff P2P network sessions.')
        subtitle_label.setStyleSheet('color: #c8ddf0; font-size: 8.5pt; background: transparent;')
        title_layout.addWidget(subtitle_label)
        layout.addLayout(title_layout)

        layout.addStretch()

        if not is_admin():
            admin_badge = QLabel('ADMIN REQUIRED FOR ICS')
            admin_badge.setToolTip('Session Sniffer is running without administrator rights. Hotspot works, but Windows ICS sharing requires admin rights.')
            admin_badge.setStyleSheet(
                'color: #f59e0b; background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.35); '
                'border-radius: 4px; padding: 3px 8px; font-size: 7.5pt; font-weight: 800;'
            )
            layout.addWidget(admin_badge)

        guide_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'book.svg')), ' Setup Guide')
        guide_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        guide_button.setToolTip('Open step-by-step setup instructions for Wi-Fi Hotspot and Ethernet Bridge')
        guide_button.clicked.connect(self._open_setup_guide)
        layout.addWidget(guide_button)

        refresh_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), ' Refresh')
        refresh_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        refresh_button.setToolTip('Refresh hotspot status, connection sharing, and connected clients')
        refresh_button.clicked.connect(self._start_refresh_task)
        layout.addWidget(refresh_button)

        return layout

    def _build_hotspot_card(self) -> QFrame:
        """Construct the Wi-Fi Mobile Hotspot configuration card."""
        card = QFrame()
        card.setObjectName('hotspotCard')
        card.setStyleSheet(HOTSPOT_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        layout.setSpacing(scale_by_ui(10))

        # Header with pills
        header_layout = QHBoxLayout()
        header_title = QLabel('Wi-Fi Hotspot')
        header_title.setStyleSheet(HOTSPOT_CARD_HEADER_STYLESHEET)
        header_layout.addWidget(header_title)

        self._hotspot_status_badge = QLabel('OFF')
        self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
        header_layout.addWidget(self._hotspot_status_badge)

        self._hotspot_ssid_pill = QLabel('-')
        self._hotspot_ssid_pill.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        header_layout.addWidget(self._hotspot_ssid_pill)

        self._hotspot_clients_pill = QLabel('0 clients')
        self._hotspot_clients_pill.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        header_layout.addWidget(self._hotspot_clients_pill)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # SSID input
        ssid_label = QLabel('Hotspot name (SSID)')
        ssid_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        layout.addWidget(ssid_label)

        self._ssid_input = QLineEdit()
        self._ssid_input.setPlaceholderText('Enter Wi-Fi network name...')
        self._ssid_input.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        layout.addWidget(self._ssid_input)

        # Password input with reveal toggle
        password_label = QLabel('Password (WPA2)')
        password_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        layout.addWidget(password_label)

        password_layout = QHBoxLayout()
        self._password_input = QLineEdit()
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setPlaceholderText('Minimum 8 characters...')
        self._password_input.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        password_layout.addWidget(self._password_input)

        self._toggle_password_button = QPushButton()
        self._toggle_password_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')))
        self._toggle_password_button.setToolTip('Reveal / Hide password')
        self._toggle_password_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._toggle_password_button.clicked.connect(self._toggle_password_visibility)
        password_layout.addWidget(self._toggle_password_button)
        layout.addLayout(password_layout)

        password_hint = QLabel('Password can be revealed locally.')
        password_hint.setStyleSheet('color: #8fa2b8; font-size: 8pt;')
        layout.addWidget(password_hint)

        layout.addStretch()

        # Action buttons
        buttons_layout = QHBoxLayout()
        self._save_hotspot_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'save.svg')), ' Save')
        self._save_hotspot_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._save_hotspot_button.setToolTip('Save updated SSID and password to Windows Mobile Hotspot')
        self._save_hotspot_button.clicked.connect(self._save_hotspot_credentials)
        buttons_layout.addWidget(self._save_hotspot_button)

        self._toggle_hotspot_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' Start Hotspot')
        self._toggle_hotspot_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._toggle_hotspot_button.clicked.connect(self._toggle_hotspot_state)
        buttons_layout.addWidget(self._toggle_hotspot_button)

        layout.addLayout(buttons_layout)
        return card

    def _build_bridge_card(self) -> QFrame:
        """Construct the Internet Connection Sharing (ICS) card."""
        card = QFrame()
        card.setObjectName('bridgeCard')
        card.setStyleSheet(HOTSPOT_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        layout.setSpacing(scale_by_ui(10))

        # Header with status pill
        header_layout = QHBoxLayout()
        header_title = QLabel('Sharing / Bridge')
        header_title.setStyleSheet(HOTSPOT_CARD_HEADER_STYLESHEET)
        header_layout.addWidget(header_title)

        self._bridge_status_badge = QLabel('OFF')
        self._bridge_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
        header_layout.addWidget(self._bridge_status_badge)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Public adapter dropdown
        public_label = QLabel('Public adapter (internet source)')
        public_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        layout.addWidget(public_label)

        self._public_combo = QComboBox()
        self._public_combo.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        layout.addWidget(self._public_combo)

        # Private adapter dropdown
        private_label = QLabel('Private adapter (to console/device)')
        private_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        layout.addWidget(private_label)

        self._private_combo = QComboBox()
        self._private_combo.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        layout.addWidget(self._private_combo)

        # Show all adapters checkbox
        self._show_all_adapters_checkbox = QCheckBox('Show all adapters')
        self._show_all_adapters_checkbox.setStyleSheet(HOTSPOT_CHECKBOX_STYLESHEET)
        self._show_all_adapters_checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self._show_all_adapters_checkbox.toggled.connect(self._populate_adapters)
        layout.addWidget(self._show_all_adapters_checkbox)

        layout.addStretch()

        # Action buttons
        buttons_layout = QHBoxLayout()
        self._enable_sharing_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'check.svg')), ' Enable Sharing')
        self._enable_sharing_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._enable_sharing_button.clicked.connect(self._enable_sharing_action)
        buttons_layout.addWidget(self._enable_sharing_button)

        self._reset_sharing_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'reset.svg')), ' Reset')
        self._reset_sharing_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._reset_sharing_button.setToolTip('Disable connection sharing on all adapters')
        self._reset_sharing_button.clicked.connect(self._disable_sharing_action)
        buttons_layout.addWidget(self._reset_sharing_button)

        layout.addLayout(buttons_layout)
        return card

    def _build_devices_card(self) -> QFrame:
        """Construct the connected devices table card."""
        card = QFrame()
        card.setObjectName('devicesCard')
        card.setStyleSheet(HOTSPOT_CARD_STYLESHEET)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        layout.setSpacing(scale_by_ui(10))

        # Header
        header_layout = QHBoxLayout()
        devices_icon = QLabel()
        devices_icon.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'devices.svg')).pixmap(scale_by_ui(16), scale_by_ui(16)))
        header_layout.addWidget(devices_icon)

        title = QLabel('Connected devices')
        title.setStyleSheet(HOTSPOT_CARD_HEADER_STYLESHEET)
        header_layout.addWidget(title)

        self._device_count_badge = QLabel('0 devices')
        self._device_count_badge.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        header_layout.addWidget(self._device_count_badge)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Stacked container for Table vs Empty State
        self._devices_stacked = QStackedLayout()

        # Table widget
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(('Device / Hostname', 'IPv4 Address', 'MAC Address', 'Manufacturer / Vendor', 'Connection'))
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_device_context_menu)
        self._table.setStyleSheet(
            'QTableWidget {'
            '    background-color: #141922;'
            '    color: #e0e6ee;'
            '    gridline-color: #222b38;'
            '    border: 1px solid #2a3544;'
            '    border-radius: 6px;'
            '}'
            'QHeaderView::section {'
            '    background-color: #1a222e;'
            '    color: #9cb0c6;'
            '    font-weight: 700;'
            '    border: none;'
            '    padding: 6px;'
            '}'
            'QTableWidget::item:selected {'
            '    background-color: #2a4365;'
            '}'
        )
        self._devices_stacked.addWidget(self._table)

        # Empty state widget
        empty_widget = QWidget()
        empty_widget.setObjectName('emptyDevicesWidget')
        empty_widget.setStyleSheet('background: transparent; background-color: transparent;')
        empty_layout = QVBoxLayout(empty_widget)
        empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.setSpacing(scale_by_ui(6))

        empty_icon = QLabel()
        empty_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_icon.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'controller.svg')).pixmap(scale_by_ui(32), scale_by_ui(32)))
        empty_icon.setStyleSheet('background: transparent; background-color: transparent;')
        empty_layout.addWidget(empty_icon)

        empty_text = QLabel('No connected devices detected yet.')
        empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_text.setStyleSheet(HOTSPOT_EMPTY_STATE_STYLESHEET)
        empty_layout.addWidget(empty_text)

        empty_subtext = QLabel('Connect your console or device to the Wi-Fi hotspot or Ethernet bridge.')
        empty_subtext.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_subtext.setStyleSheet('color: #4a596d; font-size: 8pt; background: transparent; background-color: transparent;')
        empty_layout.addWidget(empty_subtext)

        self._devices_stacked.addWidget(empty_widget)
        self._devices_stacked.setCurrentIndex(1)
        layout.addLayout(self._devices_stacked)

        return card

    def _populate_adapters(self) -> None:
        """Populate the Public and Private adapter comboboxes from AllInterfaces."""
        show_all = self._show_all_adapters_checkbox.isChecked()
        current_public = self._public_combo.currentText()
        current_private = self._private_combo.currentText()

        self._public_combo.clear()
        self._private_combo.clear()

        for interface in AllInterfaces.iterate():
            if not show_all and interface.is_interface_inactive():
                continue
            name = interface.identity.name
            ip_display = f' ({interface.ip_addresses[0]})' if interface.ip_addresses else ''
            label = f'{name}{ip_display}'
            self._public_combo.addItem(label, name)
            self._private_combo.addItem(label, name)

        # Restore previous selections if still present
        public_idx = self._public_combo.findText(current_public)
        if public_idx >= 0:
            self._public_combo.setCurrentIndex(public_idx)

        private_idx = self._private_combo.findText(current_private)
        if private_idx >= 0:
            self._private_combo.setCurrentIndex(private_idx)

    def _start_refresh_task(self) -> None:
        """Launch background task to refresh hotspot state, ICS state, and connected devices."""
        if self._active_worker and self._active_worker.isRunning():
            return
        worker = HotspotActionWorker('refresh_all')
        worker.info_ready.connect(self._on_hotspot_info_ready)
        worker.devices_ready.connect(self._on_devices_ready)
        worker.ics_status_ready.connect(self._on_ics_status_ready)
        self._active_worker = worker
        worker.start()

    def _on_hotspot_info_ready(self, info_object: object) -> None:
        """Handle updated HotspotInfo received from worker thread."""
        if not isinstance(info_object, HotspotInfo):
            return
        self._current_hotspot_info = info_object

        is_active = info_object.operational_state == 'On'
        in_transition = info_object.operational_state == 'InTransition'

        if is_active:
            self._hotspot_status_badge.setText('ON')
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_ACTIVE_STYLESHEET)
            self._toggle_hotspot_button.setText(' Stop Hotspot')
            self._toggle_hotspot_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')))
            self._toggle_hotspot_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        elif in_transition:
            self._hotspot_status_badge.setText('TRANSITION')
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_TRANSITION_STYLESHEET)
        else:
            self._hotspot_status_badge.setText('OFF')
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
            self._toggle_hotspot_button.setText(' Start Hotspot')
            self._toggle_hotspot_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
            self._toggle_hotspot_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)

        self._hotspot_ssid_pill.setText(info_object.ssid or 'No SSID')
        self._hotspot_clients_pill.setText(f'{info_object.client_count} clients')

        # Only update inputs if user is not actively editing them
        if not self._ssid_input.hasFocus():
            self._ssid_input.setText(info_object.ssid)
        if not self._password_input.hasFocus():
            self._password_input.setText(info_object.passphrase)

    def _on_devices_ready(self, devices_object: object) -> None:
        """Handle updated devices list received from worker thread."""
        if not isinstance(devices_object, list):
            return
        raw_list = cast('list[object]', devices_object)
        devices: list[ConnectedDevice] = [device for device in raw_list if isinstance(device, ConnectedDevice)]
        self._current_devices = devices

        self._device_count_badge.setText(f'{len(devices)} device{"s" if len(devices) != 1 else ""}')

        if not devices:
            self._devices_stacked.setCurrentIndex(1)
            self._table.setRowCount(0)
            return

        self._devices_stacked.setCurrentIndex(0)
        self._table.setRowCount(len(devices))

        for row, device in enumerate(devices):
            self._table.setItem(row, 0, QTableWidgetItem(device.hostname))
            self._table.setItem(row, 1, QTableWidgetItem(device.ip_address))
            self._table.setItem(row, 2, QTableWidgetItem(device.mac_address))
            self._table.setItem(row, 3, QTableWidgetItem(device.vendor_name or 'Unknown'))
            self._table.setItem(row, 4, QTableWidgetItem(device.connection_type))

    def _on_ics_status_ready(self, status_object: object) -> None:
        """Handle updated ICS status received from worker thread."""
        if not isinstance(status_object, tuple):
            return
        status_tuple = cast('tuple[object, ...]', status_object)
        if len(status_tuple) != _EXPECTED_ICS_STATUS_TUPLE_LENGTH:
            return
        is_active = bool(status_tuple[0])
        public_adapter = str(status_tuple[1]) if status_tuple[1] is not None else None

        if is_active:
            self._bridge_status_badge.setText('ACTIVE')
            self._bridge_status_badge.setStyleSheet(HOTSPOT_BADGE_ACTIVE_STYLESHEET)
            self._enable_sharing_button.setEnabled(False)
            self._reset_sharing_button.setEnabled(True)
        else:
            self._bridge_status_badge.setText('OFF')
            self._bridge_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
            self._enable_sharing_button.setEnabled(True)
            self._reset_sharing_button.setEnabled(False)

        if public_adapter:
            idx = self._public_combo.findData(public_adapter)
            if idx >= 0:
                self._public_combo.setCurrentIndex(idx)

    def _toggle_password_visibility(self) -> None:
        """Toggle between masked and revealed password text."""
        self._is_password_revealed = not self._is_password_revealed
        if self._is_password_revealed:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_password_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye_hide.svg')))
        else:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_password_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg')))

    def _save_hotspot_credentials(self) -> None:
        """Validate and dispatch credential updates in background worker."""
        ssid = self._ssid_input.text().strip()
        passphrase = self._password_input.text().strip()

        if len(ssid) < MIN_SSID_LENGTH or len(ssid) > MAX_SSID_LENGTH:
            QMessageBox.warning(self, 'Invalid SSID', f'Hotspot SSID must be between {MIN_SSID_LENGTH} and {MAX_SSID_LENGTH} characters long.')
            return
        if len(passphrase) < MIN_PASSPHRASE_LENGTH or len(passphrase) > MAX_PASSPHRASE_LENGTH:
            QMessageBox.warning(self, 'Invalid Password', f'Hotspot password must be at least {MIN_PASSPHRASE_LENGTH} characters long.')
            return

        self._status_bar_label.setText('Saving hotspot credentials...')
        self._save_hotspot_button.setEnabled(False)

        worker = HotspotActionWorker('configure_credentials', ssid=ssid, passphrase=passphrase)
        worker.action_completed.connect(self._on_action_finished)
        self._active_worker = worker
        worker.start()

    def _toggle_hotspot_state(self) -> None:
        """Start or stop the mobile hotspot."""
        is_active = self._current_hotspot_info is not None and self._current_hotspot_info.operational_state == 'On'
        task = 'stop_hotspot' if is_active else 'start_hotspot'

        self._status_bar_label.setText('Starting hotspot...' if not is_active else 'Stopping hotspot...')
        self._toggle_hotspot_button.setEnabled(False)

        worker = HotspotActionWorker(task)
        worker.action_completed.connect(self._on_action_finished)
        self._active_worker = worker
        worker.start()

    def _enable_sharing_action(self) -> None:
        """Enable Windows Internet Connection Sharing between selected adapters."""
        public_name = self._public_combo.currentData()
        private_name = self._private_combo.currentData()

        if not public_name or not private_name:
            QMessageBox.warning(self, 'Selection Required', 'Please select both a Public adapter (internet source) and a Private adapter.')
            return

        if public_name == private_name:
            QMessageBox.warning(self, 'Invalid Selection', 'Public and Private adapters cannot be the same interface.')
            return

        if not is_admin():
            QMessageBox.critical(
                self,
                'Administrator Privileges Required',
                'Enabling Internet Connection Sharing (ICS) requires administrative elevation.\n\n'
                'Please restart Session Sniffer by right-clicking and selecting "Run as administrator".',
            )
            return

        self._status_bar_label.setText(f'Enabling sharing from {public_name} to {private_name}...')
        self._enable_sharing_button.setEnabled(False)

        worker = HotspotActionWorker('enable_ics', public_adapter=public_name, private_adapter=private_name)
        worker.action_completed.connect(self._on_action_finished)
        self._active_worker = worker
        worker.start()

    def _disable_sharing_action(self) -> None:
        """Disable Internet Connection Sharing on all adapters."""
        if not is_admin():
            QMessageBox.critical(
                self,
                'Administrator Privileges Required',
                'Modifying Internet Connection Sharing requires administrative elevation.\n\nPlease run Session Sniffer as administrator.',
            )
            return

        self._status_bar_label.setText('Disabling sharing...')
        self._reset_sharing_button.setEnabled(False)

        worker = HotspotActionWorker('disable_ics')
        worker.action_completed.connect(self._on_action_finished)
        self._active_worker = worker
        worker.start()

    def _on_action_finished(self, success: bool, message: str) -> None:  # noqa: FBT001
        """Handle completion of background worker tasks."""
        self._save_hotspot_button.setEnabled(True)
        self._toggle_hotspot_button.setEnabled(True)
        self._enable_sharing_button.setEnabled(True)
        self._reset_sharing_button.setEnabled(True)
        self._status_bar_label.setText(message)

        if success:
            self.status_changed.emit()
        else:
            QMessageBox.warning(self, 'Hotspot Operation Error', message)

        self._start_refresh_task()

    def _open_setup_guide(self) -> None:
        """Open the interactive setup guide walkthrough modal."""
        guide_dialog = HotspotSetupGuideDialog(self)
        guide_dialog.exec()

    def _show_device_context_menu(self, position: QPoint) -> None:
        """Display right-click context menu for selected device in the table."""
        selected_items = self._table.selectedItems()
        if not selected_items:
            return

        selected_row = selected_items[0].row()
        if selected_row < 0 or selected_row >= len(self._current_devices):
            return

        device = self._current_devices[selected_row]
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        copy_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy IP: {device.ip_address}', self)
        copy_ip_action.triggered.connect(lambda: set_clipboard_text(device.ip_address))
        menu.addAction(copy_ip_action)

        copy_mac_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy MAC: {device.mac_address}', self)
        copy_mac_action.triggered.connect(lambda: set_clipboard_text(device.mac_address))
        menu.addAction(copy_mac_action)

        menu.addSeparator()

        if device.ip_address and device.ip_address != 'Assigned via DHCP':
            ping_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), f'Ping {device.ip_address}...', self)
            ping_action.triggered.connect(lambda: self._open_ping_dialog(device.ip_address))
            menu.addAction(ping_action)

            scan_ports_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'port_scanner.svg')), f'Scan Ports: {device.ip_address}...', self)
            scan_ports_action.triggered.connect(lambda: self._open_port_scanner_dialog(device.ip_address))
            menu.addAction(scan_ports_action)

        menu.exec(self._table.viewport().mapToGlobal(position))

    def _open_ping_dialog(self, target_ip: str) -> None:
        """Open ping diagnostics window targeting selected device IP."""
        PingWindow.open_window(target_ip)

    def _open_port_scanner_dialog(self, target_ip: str) -> None:
        """Open port scanner window targeting selected device IP."""
        PortScannerWindow.open_window(target_ip)
