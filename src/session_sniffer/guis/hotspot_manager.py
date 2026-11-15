"""Hotspot and connection sharing management dialog."""

from typing import Final, cast, override

from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QHideEvent, QIcon, QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.ctypes_windows import is_admin
from session_sniffer.guis.hotspot_setup_guide import HotspotActionResult, HotspotActionWorker, HotspotSetupGuideDialog
from session_sniffer.guis.live_language import register_language_refresh, set_table_headers
from session_sniffer.guis.loading_overlay import LoadingOverlay
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
)
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss, themed_text_qcolor
from session_sniffer.guis.utils import (
    add_icon_menu_action,
    create_styled_context_menu,
    render_svg_icon_from_resource,
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.networking.hotspot import (
    MAX_PASSPHRASE_LENGTH,
    MAX_SSID_LENGTH,
    MIN_PASSPHRASE_LENGTH,
    MIN_SSID_LENGTH,
    ConnectedDevice,
    HotspotInfo,
    has_wifi_adapter,
)
from session_sniffer.networking.interface import AllInterfaces

_EXPECTED_ICS_STATUS_TUPLE_LENGTH: Final[int] = 3


class HotspotManagerWidget(QWidget):
    """Reusable widget for managing Wi-Fi Hotspots and Internet Connection Sharing (ICS)."""

    status_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HotspotManagerWidget."""
        super().__init__(parent)
        self.setObjectName('HotspotManagerWidget')
        self.setStyleSheet('QWidget#HotspotManagerWidget { background: transparent; background-color: transparent; }')

        self._current_hotspot_info: HotspotInfo | None = None
        self._hotspot_is_available: bool = False
        self._hotspot_unavailable_reason: str | None = None
        self._ics_active: bool = False
        self._current_devices: list[ConnectedDevice] = []
        self._status_bar_state: str = 'ready'
        self._status_bar_ics_adapters: tuple[str, str] = ('', '')
        self._last_action_result: HotspotActionResult | None = None
        self._is_password_revealed: bool = False
        self._active_worker: HotspotActionWorker | None = None
        self._action_worker: HotspotActionWorker | None = None
        self._action_overlay: LoadingOverlay | None = None
        self._admin_badge: QLabel | None = None

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
        self._status_bar_label = QLabel()
        self._status_bar_label.setStyleSheet(
            themed_qss('color: #9cb0c6; font-size: 8.5pt; padding-left: 6px; padding-bottom: 2px; background: transparent;'),
        )
        main_layout.addWidget(self._status_bar_label)

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)

        # Auto-refresh timer (polls every 5 seconds while visible)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._start_refresh_task)

    def _apply_translations(self) -> None:
        """Apply current translations to all hotspot controls, status badges, table headers, and data."""
        self._title_label.setText(tr('Hotspot & Connection Sharing'))
        self._subtitle_label.setText(tr('Share internet to consoles (PlayStation, Xbox, Switch) to sniff P2P network sessions.'))
        if self._admin_badge is not None:
            self._admin_badge.setText(tr('UAC PROMPT FOR ICS'))
            self._admin_badge.setToolTip(
                tr(
                    'Session Sniffer is running without administrator rights. '
                    'Enabling or resetting Windows ICS sharing will prompt for administrator permission (UAC).',
                ),
            )
        self._guide_button.setText(f" {tr('Setup Guide')}")
        self._guide_button.setToolTip(tr('Open step-by-step setup instructions for Wi-Fi Hotspot and Ethernet Bridge'))
        self._refresh_button.setText(f" {tr('Refresh')}")
        self._refresh_button.setToolTip(tr('Refresh hotspot status, connection sharing, and connected clients'))

        self._hotspot_title_label.setText(tr('Wi-Fi Hotspot'))
        self._ssid_label.setText(tr('Hotspot name (SSID)'))
        self._password_label.setText(tr('Password (WPA2)'))
        self._toggle_password_button.setToolTip(tr('Reveal / Hide password'))
        self._save_hotspot_button.setText(f" {tr('Save')}")
        self._save_hotspot_button.setToolTip(tr('Save updated SSID and password to Windows Mobile Hotspot'))

        if self._current_hotspot_info is not None:
            self._render_hotspot_info(self._current_hotspot_info, update_inputs=False)
        else:
            self._apply_hotspot_availability(
                is_available=self._hotspot_is_available,
                unavailable_reason=self._hotspot_unavailable_reason,
            )

        self._bridge_title_label.setText(tr('Sharing / Bridge'))
        self._bridge_status_badge.setText(tr('ACTIVE') if self._ics_active else tr('OFF'))
        self._public_label.setText(tr('Public adapter (internet source)'))
        self._private_label.setText(tr('Private adapter (to console/device)'))
        self._show_all_adapters_checkbox.setText(tr('Show all adapters'))
        self._enable_sharing_button.setText(f" {tr('Enable Sharing')}")
        self._reset_sharing_button.setText(f" {tr('Reset')}")
        self._reset_sharing_button.setToolTip(tr('Disable connection sharing on all adapters'))

        self._devices_title_label.setText(tr('Connected devices'))
        set_table_headers(
            self._table,
            ('Device / Hostname', 'IPv4 Address', 'MAC Address', 'Manufacturer / Vendor', 'Connection'),
        )
        self._empty_text_label.setText(tr('No connected devices detected yet.'))
        self._empty_subtext_label.setText(tr('Connect your console or device to the Wi-Fi hotspot or Ethernet bridge.'))
        self._render_devices(self._current_devices)

        self._update_status_bar_label()

    def _update_status_bar_label(self) -> None:
        """Render the status bar label text in the active language."""
        if self._status_bar_state == 'ready':
            self._status_bar_label.setText(tr('Ready'))
            return
        if self._status_bar_state == 'saving_credentials':
            self._status_bar_label.setText(tr('Saving hotspot credentials...'))
            return
        if self._status_bar_state == 'stopping_hotspot':
            self._status_bar_label.setText(tr('Stopping hotspot...'))
            return
        if self._status_bar_state == 'starting_hotspot':
            self._status_bar_label.setText(tr('Starting hotspot...'))
            return
        if self._status_bar_state == 'enabling_ics':
            public_name, private_name = self._status_bar_ics_adapters
            self._status_bar_label.setText(
                tr('Enabling sharing from {public_name} to {private_name}...', public_name=public_name, private_name=private_name),
            )
            return
        if self._status_bar_state == 'disabling_ics':
            self._status_bar_label.setText(tr('Disabling sharing...'))
            return
        if self._status_bar_state == 'action_result' and self._last_action_result is not None:
            if self._last_action_result.message_key:
                self._status_bar_label.setText(
                    tr(self._last_action_result.message_key, **dict(self._last_action_result.message_params)),
                )
            else:
                self._status_bar_label.setText(self._last_action_result.message)

    def start_refresh(self) -> None:
        """Trigger an immediate status update and ensure the refresh timer is running."""
        self._populate_adapters()
        self._start_refresh_task()
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _close_action_overlay(self) -> None:
        """Close and release any active action loading overlay."""
        if self._action_overlay is not None:
            self._action_overlay.close_overlay()
            self._action_overlay = None

    def _launch_action_worker(self, worker: HotspotActionWorker, *, overlay_title: str, status_message: str) -> None:
        """Show a loading overlay on this widget and start an explicit hotspot/ICS action worker."""
        self._status_bar_label.setText(status_message)
        self._close_action_overlay()
        overlay = LoadingOverlay(self, overlay_title, status_message)
        overlay.present_immediately()
        self._action_overlay = overlay
        worker.action_completed.connect(self._on_action_finished)
        worker.finished.connect(self._close_action_overlay)
        self._action_worker = worker
        worker.start()

    def cleanup(self) -> None:
        """Stop refresh timer and await any active background worker."""
        self._refresh_timer.stop()
        self._close_action_overlay()
        if self._active_worker is not None and self._active_worker.isRunning():
            self._active_worker.cancel()
        self._active_worker = None
        if self._action_worker is not None and self._action_worker.isRunning():
            self._action_worker.cancel()
        self._action_worker = None

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

        title_layout = QVBoxLayout()
        title_layout.setSpacing(scale_by_ui(2))
        title_label = QLabel()
        title_label.setStyleSheet(themed_qss('color: #f0f4fa; font-size: 13pt; font-weight: 700; background: transparent;'))
        self._title_label = title_label
        title_layout.addWidget(title_label)
        subtitle_label = QLabel()
        subtitle_label.setStyleSheet(themed_qss('color: #c8ddf0; font-size: 8.5pt; background: transparent;'))
        self._subtitle_label = subtitle_label
        title_layout.addWidget(subtitle_label)
        layout.addLayout(title_layout)

        layout.addStretch()

        if not is_admin():
            admin_badge = QLabel()
            admin_badge.setStyleSheet(
                themed_qss(
                    'color: #f59e0b; background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.35); '
                    'border-radius: 4px; padding: 3px 8px; font-size: 7.5pt; font-weight: 800;',
                ),
            )
            self._admin_badge = admin_badge
            layout.addWidget(admin_badge)

        guide_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'book-text.svg')), '')
        guide_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        guide_button.clicked.connect(self._open_setup_guide)
        self._guide_button = guide_button
        layout.addWidget(guide_button)

        refresh_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'refresh-cw.svg')), '')
        refresh_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        refresh_button.clicked.connect(self._start_refresh_task)
        self._refresh_button = refresh_button
        layout.addWidget(refresh_button)

        return layout

    def _build_hotspot_card(self) -> QFrame:
        """Construct the Wi-Fi Mobile Hotspot configuration card."""
        card = QFrame()
        card.setObjectName('hotspotCard')
        card.setStyleSheet(HOTSPOT_CARD_STYLESHEET)
        self._hotspot_card = card

        layout = QVBoxLayout(card)
        layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        layout.setSpacing(scale_by_ui(10))

        # Header with pills
        header_layout = QHBoxLayout()
        hotspot_icon = QLabel()
        hotspot_icon.setPixmap(QIcon(str(ICONS_DIR_PATH / 'wifi.svg')).pixmap(scale_by_ui(16), scale_by_ui(16)))
        self._hotspot_icon_label = hotspot_icon
        header_layout.addWidget(hotspot_icon)

        header_title = QLabel()
        header_title.setStyleSheet(HOTSPOT_CARD_HEADER_STYLESHEET)
        self._hotspot_title_label = header_title
        header_layout.addWidget(header_title)

        self._hotspot_status_badge = QLabel()
        self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
        header_layout.addWidget(self._hotspot_status_badge)

        self._hotspot_ssid_pill = QLabel('-')
        self._hotspot_ssid_pill.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        header_layout.addWidget(self._hotspot_ssid_pill)

        self._hotspot_band_pill = QLabel('-')
        self._hotspot_band_pill.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        self._hotspot_band_pill.setVisible(False)
        header_layout.addWidget(self._hotspot_band_pill)

        self._hotspot_clients_pill = QLabel()
        self._hotspot_clients_pill.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        header_layout.addWidget(self._hotspot_clients_pill)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # SSID input
        ssid_label = QLabel()
        ssid_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        self._ssid_label = ssid_label
        layout.addWidget(ssid_label)

        self._ssid_input = QLineEdit()
        self._ssid_input.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        layout.addWidget(self._ssid_input)

        # Password input with reveal toggle
        password_label = QLabel()
        password_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        self._password_label = password_label
        layout.addWidget(password_label)

        password_layout = QHBoxLayout()
        self._password_input = QLineEdit()
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        password_layout.addWidget(self._password_input)

        self._toggle_password_button = QPushButton()
        self._toggle_password_button.setIcon(QIcon(str(ICONS_DIR_PATH / 'eye.svg')))
        self._toggle_password_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._toggle_password_button.clicked.connect(self._toggle_password_visibility)
        password_layout.addWidget(self._toggle_password_button)
        layout.addLayout(password_layout)

        password_hint = QLabel()
        password_hint.setStyleSheet(themed_qss('color: #8fa2b8; font-size: 8pt;'))
        self._password_hint_label = password_hint
        layout.addWidget(password_hint)

        layout.addStretch()

        # Action buttons
        buttons_layout = QHBoxLayout()
        self._save_hotspot_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'save.svg')), '')
        self._save_hotspot_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._save_hotspot_button.clicked.connect(self._save_hotspot_credentials)
        buttons_layout.addWidget(self._save_hotspot_button)

        primary_tint = themed_text_qcolor('#ffffff', '#007acc').name(QColor.NameFormat.HexArgb)
        self._toggle_hotspot_button = QPushButton(
            render_svg_icon_from_resource('circle-play.svg', scale_by_ui(16), scale_by_ui(16), primary_tint),
            '',
        )
        self._toggle_hotspot_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._toggle_hotspot_button.clicked.connect(self._toggle_hotspot_state)
        buttons_layout.addWidget(self._toggle_hotspot_button)

        layout.addLayout(buttons_layout)
        self._apply_hotspot_availability(is_available=has_wifi_adapter())
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
        bridge_icon = QLabel()
        bridge_icon.setPixmap(QIcon(str(ICONS_DIR_PATH / 'ethernet-port.svg')).pixmap(scale_by_ui(16), scale_by_ui(16)))
        header_layout.addWidget(bridge_icon)

        header_title = QLabel()
        header_title.setStyleSheet(HOTSPOT_CARD_HEADER_STYLESHEET)
        self._bridge_title_label = header_title
        header_layout.addWidget(header_title)

        self._bridge_status_badge = QLabel()
        self._bridge_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
        header_layout.addWidget(self._bridge_status_badge)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Public adapter dropdown
        public_label = QLabel()
        public_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        self._public_label = public_label
        layout.addWidget(public_label)

        self._public_combo = QComboBox()
        self._public_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._public_combo.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        layout.addWidget(self._public_combo)

        # Private adapter dropdown
        private_label = QLabel()
        private_label.setStyleSheet(HOTSPOT_FIELD_LABEL_STYLESHEET)
        self._private_label = private_label
        layout.addWidget(private_label)

        self._private_combo = QComboBox()
        self._private_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._private_combo.setStyleSheet(HOTSPOT_INPUT_STYLESHEET)
        layout.addWidget(self._private_combo)

        # Show all adapters checkbox
        self._show_all_adapters_checkbox = QCheckBox()
        self._show_all_adapters_checkbox.setStyleSheet(HOTSPOT_CHECKBOX_STYLESHEET)
        self._show_all_adapters_checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self._show_all_adapters_checkbox.toggled.connect(self._populate_adapters)
        layout.addWidget(self._show_all_adapters_checkbox)

        layout.addStretch()

        # Action buttons
        buttons_layout = QHBoxLayout()
        primary_tint = themed_text_qcolor('#ffffff', '#007acc').name(QColor.NameFormat.HexArgb)
        danger_tint = themed_text_qcolor('#ffffff', '#b91c1c').name(QColor.NameFormat.HexArgb)
        self._enable_sharing_button = QPushButton(
            render_svg_icon_from_resource('toggle-right.svg', scale_by_ui(16), scale_by_ui(16), primary_tint),
            '',
        )
        self._enable_sharing_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._enable_sharing_button.clicked.connect(self._enable_sharing_action)
        buttons_layout.addWidget(self._enable_sharing_button)

        self._reset_sharing_button = QPushButton(
            render_svg_icon_from_resource('rotate-ccw.svg', scale_by_ui(16), scale_by_ui(16), danger_tint),
            '',
        )
        self._reset_sharing_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
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
        devices_icon.setPixmap(QIcon(str(ICONS_DIR_PATH / 'monitor-smartphone.svg')).pixmap(scale_by_ui(16), scale_by_ui(16)))
        header_layout.addWidget(devices_icon)

        title = QLabel()
        title.setStyleSheet(HOTSPOT_CARD_HEADER_STYLESHEET)
        self._devices_title_label = title
        header_layout.addWidget(title)

        self._device_count_badge = QLabel()
        self._device_count_badge.setStyleSheet(HOTSPOT_PILL_INFO_STYLESHEET)
        header_layout.addWidget(self._device_count_badge)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Stacked container for Table vs Empty State
        self._devices_stacked = QStackedLayout()

        # Table widget
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        set_table_headers(
            self._table,
            ('Device / Hostname', 'IPv4 Address', 'MAC Address', 'Manufacturer / Vendor', 'Connection'),
        )
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_device_context_menu)
        self._table.setStyleSheet(
            themed_qss(
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
                '}',
            ),
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
        empty_icon.setPixmap(QIcon(str(ICONS_DIR_PATH / 'gamepad-2.svg')).pixmap(scale_by_ui(32), scale_by_ui(32)))
        empty_icon.setStyleSheet('background: transparent; background-color: transparent;')
        empty_layout.addWidget(empty_icon)

        empty_text = QLabel()
        empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_text.setStyleSheet(HOTSPOT_EMPTY_STATE_STYLESHEET)
        self._empty_text_label = empty_text
        empty_layout.addWidget(empty_text)

        empty_subtext = QLabel()
        empty_subtext.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_subtext.setStyleSheet(themed_qss('color: #4a596d; font-size: 8pt; background: transparent; background-color: transparent;'))
        self._empty_subtext_label = empty_subtext
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
        if (self._active_worker and self._active_worker.isRunning()) or (self._action_worker and self._action_worker.isRunning()):
            return
        worker = HotspotActionWorker('refresh_all')
        worker.info_ready.connect(self._on_hotspot_info_ready)
        worker.devices_ready.connect(self._on_devices_ready)
        worker.ics_status_ready.connect(self._on_ics_status_ready)
        self._active_worker = worker
        worker.start()

    def _apply_hotspot_availability(self, *, is_available: bool, unavailable_reason: str | None = None) -> None:
        """Enable or grey out the Wi-Fi Hotspot card controls based on adapter availability."""
        self._hotspot_is_available = is_available
        self._hotspot_unavailable_reason = unavailable_reason
        unavailable_flag = 'false' if is_available else 'true'
        if self._hotspot_card.property('unavailable') != unavailable_flag:
            self._hotspot_card.setProperty('unavailable', unavailable_flag)
            style = self._hotspot_card.style()
            style.unpolish(self._hotspot_card)
            style.polish(self._hotspot_card)

        self._hotspot_icon_label.setEnabled(is_available)
        self._hotspot_title_label.setEnabled(is_available)
        self._ssid_label.setEnabled(is_available)
        self._ssid_input.setEnabled(is_available)
        self._password_label.setEnabled(is_available)
        self._password_input.setEnabled(is_available)
        self._toggle_password_button.setEnabled(is_available)
        self._save_hotspot_button.setEnabled(is_available)
        self._toggle_hotspot_button.setEnabled(is_available)
        self._hotspot_ssid_pill.setVisible(is_available)
        self._hotspot_clients_pill.setVisible(is_available)

        if not is_available:
            reason = unavailable_reason or tr('No Wi-Fi adapter detected on this PC.')
            primary_tint = themed_text_qcolor('#ffffff', '#007acc').name(QColor.NameFormat.HexArgb)
            self._hotspot_band_pill.setVisible(False)
            self._hotspot_status_badge.setText(tr('UNAVAILABLE'))
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
            self._hotspot_status_badge.setToolTip(reason)
            self._toggle_hotspot_button.setText(f" {tr('Start Hotspot')}")
            self._toggle_hotspot_button.setIcon(render_svg_icon_from_resource('circle-play.svg', scale_by_ui(16), scale_by_ui(16), primary_tint))
            self._toggle_hotspot_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
            self._ssid_input.clear()
            unavailable_placeholder = tr('Wi-Fi adapter not available')
            self._ssid_input.setPlaceholderText(unavailable_placeholder)
            self._password_input.clear()
            self._password_input.setPlaceholderText(unavailable_placeholder)
            self._password_hint_label.setText(reason)
            self._password_hint_label.setStyleSheet(themed_qss('color: #5c6d80; font-size: 8pt;'))
        else:
            if self._current_hotspot_info is None:
                self._hotspot_status_badge.setText(tr('OFF'))
                self._toggle_hotspot_button.setText(f" {tr('Start Hotspot')}")
                self._hotspot_clients_pill.setText(
                    tr_plural('{count}/{max_clients} client', '{count}/{max_clients} clients', 0, max_clients=8),
                )
            self._hotspot_status_badge.setToolTip('')
            self._ssid_input.setPlaceholderText(tr('Enter Wi-Fi network name...'))
            self._password_input.setPlaceholderText(tr('Minimum 8 characters...'))
            self._password_hint_label.setText(tr('Password can be revealed locally.'))
            self._password_hint_label.setStyleSheet(themed_qss('color: #8fa2b8; font-size: 8pt;'))

    def _on_hotspot_info_ready(self, info_object: object) -> None:
        """Handle updated HotspotInfo received from worker thread."""
        if not isinstance(info_object, HotspotInfo):
            return
        if self._action_worker is not None and self._action_worker.isRunning():
            return
        self._current_hotspot_info = info_object
        self._render_hotspot_info(info_object, update_inputs=True)

    def _render_hotspot_info(self, info_object: HotspotInfo, *, update_inputs: bool = True) -> None:
        """Render the cached HotspotInfo state onto card controls."""
        self._apply_hotspot_availability(
            is_available=info_object.is_available,
            unavailable_reason=info_object.unavailable_reason,
        )
        if not info_object.is_available:
            return

        is_active = info_object.operational_state == 'On'
        in_transition = info_object.operational_state == 'InTransition'

        if is_active:
            danger_tint = themed_text_qcolor('#ffffff', '#b91c1c').name(QColor.NameFormat.HexArgb)
            self._hotspot_status_badge.setText(tr('ON'))
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_ACTIVE_STYLESHEET)
            self._toggle_hotspot_button.setText(f" {tr('Stop Hotspot')}")
            self._toggle_hotspot_button.setIcon(render_svg_icon_from_resource('circle-stop.svg', scale_by_ui(16), scale_by_ui(16), danger_tint))
            self._toggle_hotspot_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        elif in_transition:
            self._hotspot_status_badge.setText(tr('TRANSITION'))
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_TRANSITION_STYLESHEET)
        else:
            primary_tint = themed_text_qcolor('#ffffff', '#007acc').name(QColor.NameFormat.HexArgb)
            self._hotspot_status_badge.setText(tr('OFF'))
            self._hotspot_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
            self._toggle_hotspot_button.setText(f" {tr('Start Hotspot')}")
            self._toggle_hotspot_button.setIcon(render_svg_icon_from_resource('circle-play.svg', scale_by_ui(16), scale_by_ui(16), primary_tint))
            self._toggle_hotspot_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)

        self._hotspot_ssid_pill.setText(info_object.ssid or tr('No SSID'))
        self._hotspot_ssid_pill.setToolTip(tr('Network SSID: {ssid}', ssid=info_object.ssid or tr('None')))

        band_display = info_object.formatted_band
        if band_display:
            self._hotspot_band_pill.setText(band_display)
            self._hotspot_band_pill.setToolTip(tr('Wi-Fi Band: {band}', band=band_display))
            self._hotspot_band_pill.setVisible(True)
        else:
            self._hotspot_band_pill.setVisible(False)

        client_count = info_object.client_count
        max_clients = info_object.max_clients
        self._hotspot_clients_pill.setText(
            tr_plural('{count}/{max_clients} client', '{count}/{max_clients} clients', client_count, max_clients=max_clients),
        )
        self._hotspot_clients_pill.setToolTip(
            tr(
                'Connected Clients: {client_count} of {max_clients} maximum allowed',
                client_count=client_count,
                max_clients=max_clients,
            ),
        )

        # Only update inputs if user is not actively editing them
        if update_inputs:
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
        self._render_devices(devices)

    def _render_devices(self, devices: list[ConnectedDevice]) -> None:
        """Render the cached connected devices list onto the badge and table."""
        self._device_count_badge.setText(tr_plural('{count} device', '{count} devices', len(devices)))

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
            self._table.setItem(row, 3, QTableWidgetItem(device.vendor_name or tr('Unknown')))
            self._table.setItem(row, 4, QTableWidgetItem(device.connection_type))

    def _on_ics_status_ready(self, status_object: object) -> None:
        """Handle updated ICS status received from worker thread."""
        if not isinstance(status_object, tuple):
            return
        if self._action_worker is not None and self._action_worker.isRunning():
            return
        status_tuple = cast('tuple[object, ...]', status_object)
        if len(status_tuple) != _EXPECTED_ICS_STATUS_TUPLE_LENGTH:
            return
        is_active = bool(status_tuple[0])
        public_adapter = str(status_tuple[1]) if status_tuple[1] is not None else None
        self._ics_active = is_active

        if is_active:
            self._bridge_status_badge.setText(tr('ACTIVE'))
            self._bridge_status_badge.setStyleSheet(HOTSPOT_BADGE_ACTIVE_STYLESHEET)
            self._enable_sharing_button.setEnabled(False)
            self._reset_sharing_button.setEnabled(True)
        else:
            self._bridge_status_badge.setText(tr('OFF'))
            self._bridge_status_badge.setStyleSheet(HOTSPOT_BADGE_INACTIVE_STYLESHEET)
            self._enable_sharing_button.setEnabled(True)
            self._reset_sharing_button.setEnabled(False)

        if bool(public_adapter):
            idx = self._public_combo.findData(public_adapter)
            if idx >= 0:
                self._public_combo.setCurrentIndex(idx)

    def _toggle_password_visibility(self) -> None:
        """Toggle between masked and revealed password text."""
        self._is_password_revealed = not self._is_password_revealed
        if self._is_password_revealed:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_password_button.setIcon(QIcon(str(ICONS_DIR_PATH / 'eye-off.svg')))
        else:
            self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_password_button.setIcon(QIcon(str(ICONS_DIR_PATH / 'eye.svg')))

    def _save_hotspot_credentials(self) -> None:
        """Validate and dispatch credential updates in background worker."""
        if self._action_worker is not None and self._action_worker.isRunning():
            return
        ssid = self._ssid_input.text().strip()
        passphrase = self._password_input.text().strip()

        if len(ssid) < MIN_SSID_LENGTH or len(ssid) > MAX_SSID_LENGTH:
            QMessageBox.warning(
                self,
                tr('Invalid SSID'),
                tr(
                    'Hotspot SSID must be between {min_len} and {max_len} characters long.',
                    min_len=MIN_SSID_LENGTH,
                    max_len=MAX_SSID_LENGTH,
                ),
            )
            return
        if len(passphrase) < MIN_PASSPHRASE_LENGTH or len(passphrase) > MAX_PASSPHRASE_LENGTH:
            QMessageBox.warning(
                self,
                tr('Invalid Password'),
                tr('Hotspot password must be at least {min_len} characters long.', min_len=MIN_PASSPHRASE_LENGTH),
            )
            return

        self._save_hotspot_button.setEnabled(False)
        self._status_bar_state = 'saving_credentials'
        self._update_status_bar_label()
        worker = HotspotActionWorker('configure_credentials', ssid=ssid, passphrase=passphrase)
        self._launch_action_worker(worker, overlay_title=tr('Updating Hotspot\u2026'), status_message=tr('Saving hotspot credentials...'))

    def _toggle_hotspot_state(self) -> None:
        """Start or stop the mobile hotspot."""
        if self._action_worker is not None and self._action_worker.isRunning():
            return
        is_active = self._current_hotspot_info is not None and self._current_hotspot_info.operational_state == 'On'
        task = 'stop_hotspot' if is_active else 'start_hotspot'
        self._status_bar_state = 'stopping_hotspot' if is_active else 'starting_hotspot'
        self._update_status_bar_label()
        overlay_title = tr('Stopping Hotspot\u2026') if is_active else tr('Starting Hotspot\u2026')
        status_message = tr('Stopping hotspot...') if is_active else tr('Starting hotspot...')
        self._toggle_hotspot_button.setEnabled(False)
        self._launch_action_worker(HotspotActionWorker(task), overlay_title=overlay_title, status_message=status_message)

    def _enable_sharing_action(self) -> None:
        """Enable Windows Internet Connection Sharing between selected adapters."""
        if self._action_worker is not None and self._action_worker.isRunning():
            return
        public_name = self._public_combo.currentData()
        private_name = self._private_combo.currentData()

        if not public_name or not private_name:
            QMessageBox.warning(
                self,
                tr('Selection Required'),
                tr('Please select both a Public adapter (internet source) and a Private adapter.'),
            )
            return

        if public_name == private_name:
            QMessageBox.warning(
                self,
                tr('Invalid Selection'),
                tr('Public and Private adapters cannot be the same interface.'),
            )
            return

        self._enable_sharing_button.setEnabled(False)
        self._status_bar_state = 'enabling_ics'
        self._status_bar_ics_adapters = (str(public_name), str(private_name))
        self._update_status_bar_label()
        worker = HotspotActionWorker('enable_ics', public_adapter=public_name, private_adapter=private_name)
        self._launch_action_worker(
            worker,
            overlay_title=tr('Enabling Connection Sharing\u2026'),
            status_message=tr(
                'Enabling sharing from {public_name} to {private_name}...',
                public_name=public_name,
                private_name=private_name,
            ),
        )

    def _disable_sharing_action(self) -> None:
        """Disable Internet Connection Sharing on all adapters."""
        if self._action_worker is not None and self._action_worker.isRunning():
            return

        self._reset_sharing_button.setEnabled(False)
        self._status_bar_state = 'disabling_ics'
        self._update_status_bar_label()
        self._launch_action_worker(
            HotspotActionWorker('disable_ics'),
            overlay_title=tr('Disabling Connection Sharing\u2026'),
            status_message=tr('Disabling sharing...'),
        )

    def _on_action_finished(self, result: HotspotActionResult) -> None:
        """Handle completion of background worker tasks."""
        self._close_action_overlay()
        self._action_worker = None
        hotspot_available = self._current_hotspot_info.is_available if self._current_hotspot_info is not None else has_wifi_adapter()
        self._save_hotspot_button.setEnabled(hotspot_available)
        self._toggle_hotspot_button.setEnabled(hotspot_available)
        self._enable_sharing_button.setEnabled(True)
        self._reset_sharing_button.setEnabled(True)
        self._status_bar_state = 'action_result'
        self._last_action_result = result
        self._update_status_bar_label()

        if result.success:
            self.status_changed.emit()
        else:
            QMessageBox.warning(self, tr('Hotspot Operation Error'), result.message)

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
        menu = create_styled_context_menu(self)
        add_icon_menu_action(menu, 'copy.svg', tr('Copy IP: {ip}', ip=device.ip_address), lambda: set_clipboard_text(device.ip_address))
        add_icon_menu_action(menu, 'copy.svg', tr('Copy MAC: {mac}', mac=device.mac_address), lambda: set_clipboard_text(device.mac_address))
        menu.addSeparator()

        if device.ip_address and device.ip_address != 'Assigned via DHCP':
            add_icon_menu_action(menu, 'radio-tower.svg', tr('Ping {ip}...', ip=device.ip_address), lambda: self._open_ping_dialog(device.ip_address))
            add_icon_menu_action(menu, 'radar.svg', tr('Scan Ports: {ip}...', ip=device.ip_address), lambda: self._open_port_scanner_dialog(device.ip_address))

        menu.exec(self._table.viewport().mapToGlobal(position))

    def _open_ping_dialog(self, target_ip: str) -> None:
        """Open ping diagnostics window targeting selected device IP."""
        PingWindow.open_window(target_ip)

    def _open_port_scanner_dialog(self, target_ip: str) -> None:
        """Open port scanner window targeting selected device IP."""
        PortScannerWindow.open_window(target_ip)
