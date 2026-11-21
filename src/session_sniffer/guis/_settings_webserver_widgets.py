"""Web Server settings tab widgets: beginner-friendly Network Access selector, live Access Card, and QR code."""

from functools import partial
from typing import TYPE_CHECKING, Final, Literal

from PySide6.QtCore import QRegularExpression, QSignalBlocker, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._qrcode import render_qr_pixmap
from session_sniffer.guis._settings_widget_builders import create_help_banner_group, create_standard_form_layout
from session_sniffer.guis.live_language import set_i18n_colon_label
from session_sniffer.guis.stylesheets import (
    COMPACT_BUTTON_STYLESHEET,
    INTERFACE_INFO_CARD_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
    WEBSERVER_ADDRESS_BOX_STYLESHEET,
    WEBSERVER_DIVIDER_STYLESHEET,
    WEBSERVER_HINT_LABEL_STYLESHEET,
    WEBSERVER_INLINE_ERROR_STYLESHEET,
    WEBSERVER_INLINE_WARNING_STYLESHEET,
    WEBSERVER_QR_CAPTION_STYLESHEET,
    WEBSERVER_QR_CARD_STYLESHEET,
    WEBSERVER_SECTION_TITLE_STYLESHEET,
    WEBSERVER_STATUS_BADGE_ERROR_STYLESHEET,
    WEBSERVER_STATUS_BADGE_PENDING_STYLESHEET,
    WEBSERVER_STATUS_BADGE_RUNNING_STYLESHEET,
    WEBSERVER_STATUS_BADGE_STOPPED_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.utils import animate_button_feedback, render_svg_pixmap_from_resource, scale_by_ui, set_clipboard_text
from session_sniffer.i18n import tr
from session_sniffer.networking.utils import is_ipv4_address
from session_sniffer.webserver import (
    WEBSERVER_LAN_HOST,
    WEBSERVER_LOCAL_HOST,
    FirewallStatus,
    LocalNetworkAddress,
    WebServer,
    allow_webserver_firewall_port,
    check_windows_firewall_status,
    detect_local_ipv4_addresses,
    format_webserver_error,
    format_webserver_firewall_failure,
    format_webserver_firewall_warning,
    format_webserver_url,
    is_loopback_ipv4,
    resolve_local_access_url,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QFormLayout

    from session_sniffer.settings import SettingMeta

_ACCESS_MODE_LOCAL: Final[str] = '__webserver_access_local__'
_ACCESS_MODE_LAN: Final[str] = '__webserver_access_lan__'
_ACCESS_MODE_CUSTOM: Final[str] = '__webserver_access_custom__'
_ACCESS_MODE_OPTIONS: Final[tuple[tuple[str, str], ...]] = (
    (_ACCESS_MODE_LOCAL, 'This PC Only (Private)'),
    (_ACCESS_MODE_LAN, 'Local Network (Phone & Other Devices)'),
    (_ACCESS_MODE_CUSTOM, 'Specific IP Address (Advanced)'),
)
_PORT_PRESETS: Final[tuple[tuple[int, str], ...]] = (
    (80, 'Default HTTP port (lets you omit the port number from the URL)'),
    (8080, 'Common alternative port if port 80 is busy or blocked'),
    (8081, 'Alternative port if ports 80 and 8080 are busy'),
)
_SUGGESTED_ALT_PORT: Final[int] = 8080
_QR_DISPLAY_SIZE_PX: Final[int] = 132


def _format_adapter_display(entry: LocalNetworkAddress) -> str:
    """Format a detected adapter entry for display in menus and dropdowns."""
    return f'{entry.ip_address} \u2014 {entry.interface_name}' if entry.interface_name else entry.ip_address


def _make_compact_button(
    text: str,
    *,
    icon_name: str | None = None,
    tooltip: str | None = None,
    on_click: Callable[[], None] | None = None,
) -> QPushButton:
    """Create a styled compact action button with optional themed SVG icon and click slot."""
    btn = QPushButton(QIcon(str(ICONS_DIR_PATH / icon_name)), f' {text}') if icon_name is not None else QPushButton(text)
    btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip is not None:
        btn.setToolTip(tooltip)
    if on_click is not None:
        btn.clicked.connect(on_click)
    return btn


def _make_inline_banner(
    kind: Literal['warning', 'error'],
    *,
    icon_name: str = 'triangle-alert.svg',
) -> tuple[QFrame, QHBoxLayout, QLabel]:
    """Create a hidden styled inline alert banner containing a tinted SVG icon and wrapping label."""
    is_error = kind == 'error'
    banner = QFrame()
    banner.setObjectName('webserverInlineError' if is_error else 'webserverInlineWarning')
    banner.setStyleSheet(WEBSERVER_INLINE_ERROR_STYLESHEET if is_error else WEBSERVER_INLINE_WARNING_STYLESHEET)
    layout = QHBoxLayout(banner)
    vertical_pad = 8 if is_error else 6
    layout.setContentsMargins(10, vertical_pad, 10, vertical_pad)
    layout.setSpacing(8)

    icon_px = scale_by_ui(16 if is_error else 15)
    icon_label = QLabel()
    icon_label.setPixmap(render_svg_pixmap_from_resource(icon_name, icon_px, icon_px, '#f87171' if is_error else '#f59e0b'))
    layout.addWidget(icon_label)

    text_label = QLabel()
    text_label.setWordWrap(True)
    text_label.setStyleSheet(
        themed_qss(
            'color: @danger[#fca5a5]; font-size: 8.5pt; font-weight: 600; background: transparent;'
            if is_error
            else 'color: @warning[#fbbf24]; font-size: 8.5pt; font-weight: 600; background: transparent;',
        ),
    )
    layout.addWidget(text_label, 1)

    banner.setVisible(False)
    return banner, layout, text_label


def _make_address_label() -> QLabel:
    """Create a selectable monospace address display label."""
    label = QLabel()
    label.setStyleSheet(WEBSERVER_ADDRESS_BOX_STYLESHEET)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    return label


def _make_hint_label(text: str = '') -> QLabel:
    """Create a wrapping muted helper label."""
    label = QLabel(text)
    label.setWordWrap(True)
    label.setStyleSheet(WEBSERVER_HINT_LABEL_STYLESHEET)
    return label


def _make_transparent_container() -> QWidget:
    """Create a QWidget with transparent background for nested card sections."""
    widget = QWidget()
    widget.setStyleSheet('background: transparent;')
    return widget


class WebServerAccessWidget(QWidget):
    """Beginner-friendly Network Access selector backed by the `webserver_host` IPv4 value."""

    host_changed: Signal = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the access-mode dropdown, contextual hint, and optional custom IPv4 row."""
        super().__init__(parent)
        self._detected_addresses: tuple[LocalNetworkAddress, ...] = ()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._mode_combo = QComboBox()
        self._mode_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        for mode_id, canonical_label in _ACCESS_MODE_OPTIONS:
            self._mode_combo.addItem(tr(canonical_label), mode_id)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_index_changed)
        layout.addWidget(self._mode_combo)

        self._mode_hint_label = _make_hint_label()
        layout.addWidget(self._mode_hint_label)

        self._custom_ip_container = QWidget()
        custom_layout = QHBoxLayout(self._custom_ip_container)
        custom_layout.setContentsMargins(0, 0, 0, 0)
        custom_layout.setSpacing(6)

        self._custom_ip_edit = QLineEdit()
        self._custom_ip_edit.setPlaceholderText(tr('e.g. 192.168.1.100'))
        self._custom_ip_edit.setMaxLength(15)
        self._custom_ip_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
        self._custom_ip_edit.textChanged.connect(lambda _text='': self.host_changed.emit())
        custom_layout.addWidget(self._custom_ip_edit, 1)

        self._pick_ip_button = _make_compact_button(
            tr('Pick PC IP\u2026'), icon_name='network.svg', tooltip=tr('Fill in one of the network IP addresses detected on this PC'), on_click=self._show_pick_ip_menu,
        )
        custom_layout.addWidget(self._pick_ip_button)
        self._custom_ip_container.setVisible(False)
        layout.addWidget(self._custom_ip_container)

        self._sync_mode_ui()

    def _current_mode_id(self) -> str:
        mode_data = self._mode_combo.currentData(Qt.ItemDataRole.UserRole)
        return mode_data if isinstance(mode_data, str) else _ACCESS_MODE_LAN

    def access_mode(self) -> Literal['local', 'lan', 'custom']:
        """Return the currently selected access mode identifier."""
        mode_id = self._current_mode_id()
        if mode_id == _ACCESS_MODE_LOCAL:
            return 'local'
        if mode_id == _ACCESS_MODE_CUSTOM:
            return 'custom'
        return 'lan'

    def value(self) -> str | None:
        """Return the IPv4 host string represented by the current selection."""
        mode_id = self._current_mode_id()
        if mode_id == _ACCESS_MODE_LOCAL:
            return WEBSERVER_LOCAL_HOST
        if mode_id == _ACCESS_MODE_LAN:
            return WEBSERVER_LAN_HOST
        custom_ip = self._custom_ip_edit.text().strip()
        return custom_ip or None

    def set_value(self, host: str | None) -> None:
        """Populate the widget from a `webserver_host` IPv4 value."""
        normalized = (host or '').strip()
        if normalized == WEBSERVER_LOCAL_HOST:
            target_mode = _ACCESS_MODE_LOCAL
        elif not normalized or normalized == WEBSERVER_LAN_HOST:
            target_mode = _ACCESS_MODE_LAN
        else:
            target_mode = _ACCESS_MODE_CUSTOM

        with QSignalBlocker(self._mode_combo), QSignalBlocker(self._custom_ip_edit):
            for idx in range(self._mode_combo.count()):
                if self._mode_combo.itemData(idx, Qt.ItemDataRole.UserRole) == target_mode:
                    self._mode_combo.setCurrentIndex(idx)
                    break
            if target_mode == _ACCESS_MODE_CUSTOM:
                self._custom_ip_edit.setText(normalized)
        self._sync_mode_ui()

    def select_lan_mode(self) -> None:
        """Switch the selector to Local Network mode so phones and other devices can connect."""
        for idx in range(self._mode_combo.count()):
            if self._mode_combo.itemData(idx, Qt.ItemDataRole.UserRole) == _ACCESS_MODE_LAN:
                if self._mode_combo.currentIndex() != idx:
                    self._mode_combo.setCurrentIndex(idx)
                break

    def set_detected_addresses(self, addresses: tuple[LocalNetworkAddress, ...]) -> None:
        """Update the list of detected local IPv4 addresses offered in the Pick PC IP menu."""
        self._detected_addresses = addresses

    def refresh_language(self) -> None:
        """Retranslate dropdown items, helper description, placeholder, and picker button."""
        with QSignalBlocker(self._mode_combo):
            for idx, (_mode_id, canonical_label) in enumerate(_ACCESS_MODE_OPTIONS):
                if idx < self._mode_combo.count():
                    self._mode_combo.setItemText(idx, tr(canonical_label))
        self._custom_ip_edit.setPlaceholderText(tr('e.g. 192.168.1.100'))
        self._pick_ip_button.setText(f" {tr('Pick PC IP\u2026')}")
        self._pick_ip_button.setToolTip(tr('Fill in one of the network IP addresses detected on this PC'))
        self._sync_mode_ui()

    def _on_mode_index_changed(self, _index: int = 0) -> None:
        if self._current_mode_id() == _ACCESS_MODE_CUSTOM:
            current_custom = self._custom_ip_edit.text().strip()
            if (not current_custom or current_custom in (WEBSERVER_LOCAL_HOST, WEBSERVER_LAN_HOST)) and self._detected_addresses:
                with QSignalBlocker(self._custom_ip_edit):
                    self._custom_ip_edit.setText(self._detected_addresses[0].ip_address)
        self._sync_mode_ui()
        self.host_changed.emit()

    def _sync_mode_ui(self) -> None:
        mode_id = self._current_mode_id()
        self._custom_ip_container.setVisible(mode_id == _ACCESS_MODE_CUSTOM)
        if mode_id == _ACCESS_MODE_LOCAL:
            self._mode_hint_label.setText(tr('Only browsers on this PC can open the web panel. Other devices on your Wi-Fi cannot connect.'))
        elif mode_id == _ACCESS_MODE_CUSTOM:
            self._mode_hint_label.setText(tr('Listen only on one specific IPv4 address assigned to this PC (for multi-network or VPN setups).'))
        else:
            self._mode_hint_label.setText(tr('Phones, tablets, and other devices on the same Wi-Fi or local network can open the web panel.'))

    def _show_pick_ip_menu(self) -> None:
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        if not self._detected_addresses:
            empty_action = menu.addAction(tr('No active network IP addresses detected'))
            empty_action.setEnabled(False)
        else:
            for entry in self._detected_addresses:
                action = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'wifi.svg')), _format_adapter_display(entry))
                action.triggered.connect(lambda _checked=False, ip=entry.ip_address: self._custom_ip_edit.setText(ip))
        menu.exec(self._pick_ip_button.mapToGlobal(self._pick_ip_button.rect().bottomLeft()))


class WebServerSettingsSection:
    """Encapsulates custom Web Server tab UI components (access card, QR code, port presets, password group, tips)."""

    def __init__(self, widgets: dict[str, QWidget], labels: dict[str, QLabel], get_preferred_ip: Callable[[], str | None]) -> None:
        """Bind references to the dialog's setting widget registries."""
        self._widgets = widgets
        self._labels = labels
        self._get_preferred_ip = get_preferred_ip
        self._detected_addresses: tuple[LocalNetworkAddress, ...] = ()
        self._port_preset_buttons: list[tuple[QPushButton, int, str]] = []
        self._current_local_url: str | None = None
        self._current_phone_url: str | None = None
        self._last_qr_url: str | None = None
        self._cached_firewall_check: tuple[int, str | None, FirewallStatus] | None = None

        self._access_card: QGroupBox | None = None
        self._status_badge: QLabel | None = None
        self._security_badge: QLabel | None = None
        self._refresh_ips_button: QPushButton | None = None
        self._error_banner: QFrame | None = None
        self._error_label: QLabel | None = None
        self._use_port_8080_button: QPushButton | None = None
        self._firewall_banner: QFrame | None = None
        self._firewall_label: QLabel | None = None
        self._allow_firewall_button: QPushButton | None = None
        self._pending_banner: QFrame | None = None
        self._pending_label: QLabel | None = None
        self._disabled_notice: QLabel | None = None
        self._active_container: QWidget | None = None
        self._local_section_title: QLabel | None = None
        self._local_url_label: QLabel | None = None
        self._open_button: QPushButton | None = None
        self._copy_local_button: QPushButton | None = None
        self._phone_section_title: QLabel | None = None
        self._phone_blocked_container: QWidget | None = None
        self._phone_blocked_label: QLabel | None = None
        self._enable_lan_button: QPushButton | None = None
        self._phone_url_container: QWidget | None = None
        self._phone_url_label: QLabel | None = None
        self._copy_phone_button: QPushButton | None = None
        self._adapter_row: QWidget | None = None
        self._adapter_label: QLabel | None = None
        self._adapter_combo: QComboBox | None = None
        self._phone_hint_label: QLabel | None = None
        self._phone_unavailable_label: QLabel | None = None
        self._qr_card: QFrame | None = None
        self._qr_image_label: QLabel | None = None
        self._qr_caption_label: QLabel | None = None
        self._password_group: QGroupBox | None = None
        self._password_intro_label: QLabel | None = None
        self._partial_auth_banner: QFrame | None = None
        self._partial_auth_label: QLabel | None = None
        self._help_group: QGroupBox | None = None
        self._help_label: QLabel | None = None

    def build_access_card(self) -> QGroupBox:
        """Build the interactive Web Panel Access card displaying live status, URLs, and phone QR code."""
        group_box = QGroupBox(tr('Web Panel Access').replace('&', '&&'))
        group_box.setStyleSheet(INTERFACE_INFO_CARD_STYLESHEET)
        self._access_card = group_box

        outer = QVBoxLayout(group_box)
        outer.setContentsMargins(12, 8, 12, 12)
        outer.setSpacing(10)

        header_row = QHBoxLayout()
        header_row.setSpacing(8)
        header_icon = QLabel()
        header_icon.setPixmap(QIcon(str(ICONS_DIR_PATH / 'monitor-smartphone.svg')).pixmap(scale_by_ui(18), scale_by_ui(18)))
        header_row.addWidget(header_icon)

        self._status_badge = QLabel()
        self._status_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_STOPPED_STYLESHEET)
        header_row.addWidget(self._status_badge)

        self._security_badge = QLabel()
        self._security_badge.setVisible(False)
        header_row.addWidget(self._security_badge)
        header_row.addStretch()

        self._refresh_ips_button = _make_compact_button(
            tr('Refresh IPs'), icon_name='refresh-cw.svg', tooltip=tr('Re-detect your PC network IP addresses'), on_click=self.refresh_network_addresses,
        )
        header_row.addWidget(self._refresh_ips_button)
        outer.addLayout(header_row)

        self._error_banner, error_layout, self._error_label = _make_inline_banner('error')
        self._use_port_8080_button = _make_compact_button(
            tr('Use Port 8080'), tooltip=tr('Switch the Web Server port to 8080'), on_click=partial(self._set_port_preset, _SUGGESTED_ALT_PORT),
        )
        error_layout.addWidget(self._use_port_8080_button)
        outer.addWidget(self._error_banner)

        self._firewall_banner, firewall_layout, self._firewall_label = _make_inline_banner('warning', icon_name='shield.svg')
        self._allow_firewall_button = _make_compact_button(tr('Allow in Firewall'), icon_name='shield.svg', on_click=self._allow_in_firewall)
        firewall_layout.addWidget(self._allow_firewall_button)
        outer.addWidget(self._firewall_banner)

        self._pending_banner, _pending_layout, self._pending_label = _make_inline_banner('warning', icon_name='info.svg')
        outer.addWidget(self._pending_banner)

        self._disabled_notice = _make_hint_label(
            tr('Turn on "Enable Web Server" below and click Save to view your live session in a web browser on this PC or on your phone.'),
        )
        outer.addWidget(self._disabled_notice)

        active_container = _make_transparent_container()
        active_layout = QHBoxLayout(active_container)
        active_layout.setContentsMargins(0, 0, 0, 0)
        active_layout.setSpacing(14)

        left_col = QVBoxLayout()
        left_col.setSpacing(8)

        self._local_section_title = QLabel(tr('On This PC'))
        self._local_section_title.setStyleSheet(WEBSERVER_SECTION_TITLE_STYLESHEET)
        left_col.addWidget(self._local_section_title)

        local_row = QHBoxLayout()
        local_row.setSpacing(6)
        self._local_url_label = _make_address_label()
        local_row.addWidget(self._local_url_label, 1)
        self._open_button = _make_compact_button(tr('Open'), icon_name='external-link.svg', on_click=self._open_in_browser)
        local_row.addWidget(self._open_button)
        self._copy_local_button = _make_compact_button(
            tr('Copy'), icon_name='copy.svg', tooltip=tr('Copy this address to the clipboard'), on_click=self._copy_local_url,
        )
        local_row.addWidget(self._copy_local_button)
        left_col.addLayout(local_row)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet(WEBSERVER_DIVIDER_STYLESHEET)
        left_col.addWidget(divider)

        self._phone_section_title = QLabel(tr('On Phone, Tablet & Other Devices'))
        self._phone_section_title.setStyleSheet(WEBSERVER_SECTION_TITLE_STYLESHEET)
        left_col.addWidget(self._phone_section_title)

        blocked_container = _make_transparent_container()
        blocked_layout = QHBoxLayout(blocked_container)
        blocked_layout.setContentsMargins(0, 0, 0, 0)
        blocked_layout.setSpacing(8)
        self._phone_blocked_label = _make_hint_label()
        blocked_layout.addWidget(self._phone_blocked_label, 1)
        self._enable_lan_button = _make_compact_button(
            tr('Share on Local Network'),
            icon_name='wifi.svg',
            tooltip=tr('Switch Network Access to Local Network so your phone and other devices on the same Wi-Fi can connect'),
            on_click=self._enable_lan_sharing,
        )
        blocked_layout.addWidget(self._enable_lan_button)
        self._phone_blocked_container = blocked_container
        left_col.addWidget(blocked_container)

        phone_url_container = _make_transparent_container()
        phone_url_outer = QVBoxLayout(phone_url_container)
        phone_url_outer.setContentsMargins(0, 0, 0, 0)
        phone_url_outer.setSpacing(6)

        phone_row = QHBoxLayout()
        phone_row.setSpacing(6)
        self._phone_url_label = _make_address_label()
        phone_row.addWidget(self._phone_url_label, 1)
        self._copy_phone_button = _make_compact_button(
            tr('Copy'), icon_name='copy.svg', tooltip=tr('Copy this address to the clipboard'), on_click=self._copy_phone_url,
        )
        phone_row.addWidget(self._copy_phone_button)
        phone_url_outer.addLayout(phone_row)

        adapter_row = _make_transparent_container()
        adapter_layout = QHBoxLayout(adapter_row)
        adapter_layout.setContentsMargins(0, 0, 0, 0)
        adapter_layout.setSpacing(6)
        self._adapter_label = QLabel()
        set_i18n_colon_label(self._adapter_label, 'Network Adapter')
        self._adapter_label.setStyleSheet(WEBSERVER_HINT_LABEL_STYLESHEET)
        adapter_layout.addWidget(self._adapter_label)
        self._adapter_combo = QComboBox()
        self._adapter_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._adapter_combo.currentIndexChanged.connect(lambda _index=0: self.update_state())
        adapter_layout.addWidget(self._adapter_combo, 1)
        adapter_row.setVisible(False)
        self._adapter_row = adapter_row
        phone_url_outer.addWidget(adapter_row)

        self._phone_hint_label = _make_hint_label()
        phone_url_outer.addWidget(self._phone_hint_label)
        self._phone_url_container = phone_url_container
        left_col.addWidget(phone_url_container)

        self._phone_unavailable_label = _make_hint_label()
        left_col.addWidget(self._phone_unavailable_label)
        active_layout.addLayout(left_col, 1)

        qr_card = QFrame()
        qr_card.setObjectName('webserverQrCard')
        qr_card.setStyleSheet(WEBSERVER_QR_CARD_STYLESHEET)
        qr_card.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        qr_layout = QVBoxLayout(qr_card)
        qr_layout.setContentsMargins(8, 8, 8, 6)
        qr_layout.setSpacing(4)
        qr_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._qr_image_label = QLabel()
        self._qr_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._qr_image_label.setStyleSheet('background: transparent;')
        qr_layout.addWidget(self._qr_image_label)

        self._qr_caption_label = QLabel(tr('Scan on Phone'))
        self._qr_caption_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._qr_caption_label.setStyleSheet(WEBSERVER_QR_CAPTION_STYLESHEET)
        qr_layout.addWidget(self._qr_caption_label)

        qr_card.setVisible(False)
        self._qr_card = qr_card
        active_layout.addWidget(qr_card, 0, Qt.AlignmentFlag.AlignTop)

        self._active_container = active_container
        outer.addWidget(active_container)
        return group_box

    def build_port_row(self, spin_widget: QWidget) -> QWidget:
        """Pair the Port spinbox with 1-click quick preset buttons (80, 8080, 8081)."""
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(6)
        row_layout.addWidget(spin_widget)
        for preset_port, tooltip_key in _PORT_PRESETS:
            preset_btn = _make_compact_button(str(preset_port), tooltip=tr(tooltip_key), on_click=partial(self._set_port_preset, preset_port))
            row_layout.addWidget(preset_btn)
            self._port_preset_buttons.append((preset_btn, preset_port, tooltip_key))
        row_layout.addStretch()
        return row

    def build_authentication_group(self, items: list[tuple[str, SettingMeta]], add_setting_row: Callable[[QFormLayout, str, SettingMeta], None]) -> QGroupBox:
        """Build the Authentication group with plain-language guidance and partial-credential warning."""
        group_box = QGroupBox(tr('Authentication').replace('&', '&&'))
        self._password_group = group_box

        outer = QVBoxLayout(group_box)
        outer.setSpacing(8)
        self._password_intro_label = _make_hint_label(
            tr('Optional. Set both a username and password to require a login prompt before viewing the web panel. Recommended when sharing on a network with others.'),
        )
        outer.addWidget(self._password_intro_label)

        form = create_standard_form_layout()
        for key, meta in items:
            add_setting_row(form, key, meta)
        outer.addLayout(form)

        if isinstance(username_widget := self._widgets.get('webserver_username'), QLineEdit):
            username_widget.setPlaceholderText(tr('Optional username'))
        if isinstance(password_widget := self._widgets.get('webserver_password'), QLineEdit):
            password_widget.setPlaceholderText(tr('Optional password'))

        self._partial_auth_banner, _partial_layout, self._partial_auth_label = _make_inline_banner('warning')
        self._partial_auth_label.setText(tr('Fill in both username and password to enable authentication (having only one leaves the web panel unlocked).'))
        outer.addWidget(self._partial_auth_banner)
        return group_box

    def build_help_group(self) -> QGroupBox:
        """Build a concise, jargon-free troubleshooting guide at the bottom of the Web Server tab."""
        group_box, help_label = create_help_banner_group()
        self._help_group = group_box
        self._help_label = help_label
        self._update_help_text(80)
        return group_box

    def connect_signals(self) -> None:
        """Connect Web Server setting widgets to keep the live access card and cascade synchronized."""
        if isinstance(enabled_widget := self._widgets.get('webserver_enabled'), QCheckBox):
            enabled_widget.toggled.connect(lambda _checked=False: self.update_state())
        if isinstance(host_widget := self._widgets.get('webserver_host'), WebServerAccessWidget):
            host_widget.host_changed.connect(self.update_state)
        if isinstance(port_widget := self._widgets.get('webserver_port'), QSpinBox):
            port_widget.valueChanged.connect(lambda _value=0: self.update_state())
        for auth_key in ('webserver_username', 'webserver_password'):
            if isinstance(auth_widget := self._widgets.get(auth_key), QLineEdit):
                auth_widget.textChanged.connect(lambda _text='': self.update_state())
        self.refresh_network_addresses()

    def refresh_network_addresses(self) -> None:
        """Re-detect active local IPv4 addresses and update the access widget and adapter selector."""
        previous_selected_ip: str | None = None
        if self._adapter_combo is not None:
            raw_ip = self._adapter_combo.currentData(Qt.ItemDataRole.UserRole)
            if isinstance(raw_ip, str) and raw_ip:
                previous_selected_ip = raw_ip

        detected = detect_local_ipv4_addresses(preferred_ip=self._get_preferred_ip())
        self._detected_addresses = detected
        if isinstance(host_widget := self._widgets.get('webserver_host'), WebServerAccessWidget):
            host_widget.set_detected_addresses(detected)

        if self._adapter_combo is not None:
            with QSignalBlocker(self._adapter_combo):
                self._adapter_combo.clear()
                selected_index = 0
                for idx, entry in enumerate(detected):
                    self._adapter_combo.addItem(_format_adapter_display(entry), entry.ip_address)
                    if previous_selected_ip is not None and entry.ip_address == previous_selected_ip:
                        selected_index = idx
                if detected:
                    self._adapter_combo.setCurrentIndex(selected_index)

        self._cached_firewall_check = None
        self.update_state()

    def update_state(self) -> None:
        """Synchronize enable cascade, status badges, preview URLs, QR code, and inline notices."""
        enabled_widget = self._widgets.get('webserver_enabled')
        host_widget = self._widgets.get('webserver_host')
        port_widget = self._widgets.get('webserver_port')
        username_widget = self._widgets.get('webserver_username')
        password_widget = self._widgets.get('webserver_password')

        enabled = isinstance(enabled_widget, QCheckBox) and enabled_widget.isChecked()
        host_value = host_widget.value() if isinstance(host_widget, WebServerAccessWidget) else WEBSERVER_LAN_HOST
        access_mode = host_widget.access_mode() if isinstance(host_widget, WebServerAccessWidget) else 'lan'
        port = port_widget.value() if isinstance(port_widget, QSpinBox) else 80
        username = username_widget.text().strip() if isinstance(username_widget, QLineEdit) else ''
        password = password_widget.text().strip() if isinstance(password_widget, QLineEdit) else ''

        for dep_key in ('webserver_host', 'webserver_port'):
            if (lbl := self._labels.get(dep_key)) is not None:
                lbl.setEnabled(enabled)
            if (wdg := self._widgets.get(dep_key)) is not None:
                wdg.setEnabled(enabled)
        for preset_btn, _preset_port, _tip in self._port_preset_buttons:
            preset_btn.setEnabled(enabled)
        if self._password_group is not None:
            self._password_group.setEnabled(enabled)
        if self._partial_auth_banner is not None:
            self._partial_auth_banner.setVisible(enabled and (bool(username) != bool(password)))

        self._update_help_text(port)

        status = WebServer.get_status()
        matches_running = enabled and status.running and status.host == host_value and status.port == port
        matches_error = enabled and not status.running and status.error_code is not None and status.host == host_value and status.port == port

        if self._status_badge is not None:
            if not enabled:
                self._status_badge.setText(tr('Disabled'))
                self._status_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_STOPPED_STYLESHEET)
            elif matches_running:
                self._status_badge.setText(tr('Running'))
                self._status_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_RUNNING_STYLESHEET)
            elif matches_error:
                self._status_badge.setText(tr('Failed to Start'))
                self._status_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_ERROR_STYLESHEET)
            else:
                self._status_badge.setText(tr('Unsaved Changes'))
                self._status_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_PENDING_STYLESHEET)

        is_network_shared = access_mode == 'lan' or (
            access_mode == 'custom' and isinstance(host_value, str) and is_ipv4_address(host_value) and not is_loopback_ipv4(host_value)
        )
        if self._security_badge is not None:
            if not enabled:
                self._security_badge.setVisible(False)
            elif username and password:
                self._security_badge.setText(tr('Password Protected'))
                self._security_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_RUNNING_STYLESHEET)
                self._security_badge.setToolTip('')
                self._security_badge.setVisible(True)
            elif is_network_shared:
                self._security_badge.setText(tr('No Password'))
                self._security_badge.setStyleSheet(WEBSERVER_STATUS_BADGE_PENDING_STYLESHEET)
                self._security_badge.setToolTip(
                    tr('Anyone on your local network can open the web panel without logging in. Set a username and password below if you want to restrict access.'),
                )
                self._security_badge.setVisible(True)
            else:
                self._security_badge.setVisible(False)

        if self._error_banner is not None and self._error_label is not None:
            self._error_banner.setVisible(matches_error)
            if matches_error:
                self._error_label.setText(format_webserver_error(status))
                if self._use_port_8080_button is not None:
                    self._use_port_8080_button.setVisible(status.error_code in ('port_in_use', 'permission_denied') and port != _SUGGESTED_ALT_PORT)

        self._update_firewall_banner(
            port, can_check=enabled and is_network_shared and not matches_error, target_ip=self._resolve_firewall_target_ip(access_mode, host_value),
        )

        show_pending = enabled and not matches_running and not matches_error
        if self._pending_banner is not None and self._pending_label is not None:
            self._pending_banner.setVisible(show_pending)
            if show_pending:
                self._pending_label.setText(
                    tr('Click Save below to apply your updated address and port.') if status.running else tr('Click Save below to start the web server with these settings.'),
                )

        if self._disabled_notice is not None:
            self._disabled_notice.setVisible(not enabled)
        if self._active_container is not None:
            self._active_container.setVisible(enabled)
        if not enabled:
            self._current_local_url = None
            self._current_phone_url = None
            return

        local_url = resolve_local_access_url(host_value, port) if isinstance(host_value, str) else None
        self._current_local_url = local_url
        if self._local_url_label is not None:
            self._local_url_label.setText(local_url if local_url is not None else '\u2014')
        if self._open_button is not None:
            can_open = matches_running and local_url is not None
            self._open_button.setEnabled(can_open)
            self._open_button.setToolTip(
                tr('Open the web panel in your default web browser') if can_open else tr('Click Save first so the web server is running on this address'),
            )
        if self._copy_local_button is not None:
            self._copy_local_button.setEnabled(local_url is not None)

        self._update_phone_access_state(access_mode=access_mode, host_value=host_value, port=port)

    def refresh_language(self) -> None:
        """Retranslate all custom Web Server tab widgets after a live language switch."""
        if self._access_card is not None:
            self._access_card.setTitle(tr('Web Panel Access').replace('&', '&&'))
        if self._refresh_ips_button is not None:
            self._refresh_ips_button.setText(f" {tr('Refresh IPs')}")
            self._refresh_ips_button.setToolTip(tr('Re-detect your PC network IP addresses'))
        if self._use_port_8080_button is not None:
            self._use_port_8080_button.setText(tr('Use Port 8080'))
            self._use_port_8080_button.setToolTip(tr('Switch the Web Server port to 8080'))
        if self._allow_firewall_button is not None:
            self._allow_firewall_button.setText(f" {tr('Allow in Firewall')}")
        if self._disabled_notice is not None:
            self._disabled_notice.setText(
                tr('Turn on "Enable Web Server" below and click Save to view your live session in a web browser on this PC or on your phone.'),
            )
        if self._local_section_title is not None:
            self._local_section_title.setText(tr('On This PC'))
        if self._open_button is not None:
            self._open_button.setText(f" {tr('Open')}")
        if self._copy_local_button is not None:
            self._copy_local_button.setText(f" {tr('Copy')}")
            self._copy_local_button.setToolTip(tr('Copy this address to the clipboard'))
        if self._phone_section_title is not None:
            self._phone_section_title.setText(tr('On Phone, Tablet & Other Devices'))
        if self._enable_lan_button is not None:
            self._enable_lan_button.setText(f" {tr('Share on Local Network')}")
            self._enable_lan_button.setToolTip(
                tr('Switch Network Access to Local Network so your phone and other devices on the same Wi-Fi can connect'),
            )
        if self._copy_phone_button is not None:
            self._copy_phone_button.setText(f" {tr('Copy')}")
            self._copy_phone_button.setToolTip(tr('Copy this address to the clipboard'))
        if self._adapter_label is not None:
            set_i18n_colon_label(self._adapter_label, 'Network Adapter')
        if self._qr_caption_label is not None:
            self._qr_caption_label.setText(tr('Scan on Phone'))
        for preset_btn, _preset_port, tooltip_key in self._port_preset_buttons:
            preset_btn.setToolTip(tr(tooltip_key))
        if self._password_group is not None:
            self._password_group.setTitle(tr('Authentication').replace('&', '&&'))
        if self._password_intro_label is not None:
            self._password_intro_label.setText(
                tr('Optional. Set both a username and password to require a login prompt before viewing the web panel. Recommended when sharing on a network with others.'),
            )
        if self._partial_auth_label is not None:
            self._partial_auth_label.setText(tr('Fill in both username and password to enable authentication (having only one leaves the web panel unlocked).'))
        if isinstance(username_widget := self._widgets.get('webserver_username'), QLineEdit):
            username_widget.setPlaceholderText(tr('Optional username'))
        if isinstance(password_widget := self._widgets.get('webserver_password'), QLineEdit):
            password_widget.setPlaceholderText(tr('Optional password'))
        if isinstance(host_widget := self._widgets.get('webserver_host'), WebServerAccessWidget):
            host_widget.refresh_language()

        self.update_state()

    def _update_phone_access_state(self, *, access_mode: Literal['local', 'lan', 'custom'], host_value: str | None, port: int) -> None:
        """Update the Phone/Other Devices sub-section and scannable QR code card."""
        phone_url: str | None = None
        selected_adapter = self._selected_lan_adapter()
        show_blocked = False
        blocked_text = ''
        unavailable_text = ''

        if access_mode == 'local':
            show_blocked = True
            blocked_text = tr('Blocked while Network Access is set to This PC Only.')
        elif access_mode == 'lan':
            if selected_adapter is not None:
                phone_url = format_webserver_url(selected_adapter.ip_address, port)
            else:
                unavailable_text = tr('No active local network IP was detected. Connect this PC to Wi-Fi or Ethernet, then click Refresh IPs.')
        elif isinstance(host_value, str) and is_ipv4_address(host_value):
            if is_loopback_ipv4(host_value):
                show_blocked = True
                blocked_text = tr('Only this PC can connect to a loopback address (127.x.x.x).')
            elif host_value == WEBSERVER_LAN_HOST:
                if selected_adapter is not None:
                    phone_url = format_webserver_url(selected_adapter.ip_address, port)
                else:
                    unavailable_text = tr('No active local network IP was detected. Connect this PC to Wi-Fi or Ethernet, then click Refresh IPs.')
            else:
                phone_url = format_webserver_url(host_value, port)
        else:
            unavailable_text = tr('Enter a valid IPv4 address under Network Access below to preview the address.')

        self._current_phone_url = phone_url
        if self._phone_blocked_container is not None:
            self._phone_blocked_container.setVisible(show_blocked)
        if self._phone_blocked_label is not None and show_blocked:
            self._phone_blocked_label.setText(blocked_text)

        has_phone_url = phone_url is not None
        if self._phone_url_container is not None:
            self._phone_url_container.setVisible(has_phone_url)
        if self._phone_url_label is not None and phone_url is not None:
            self._phone_url_label.setText(phone_url)

        show_adapter_picker = has_phone_url and access_mode == 'lan' and len(self._detected_addresses) > 1
        if self._adapter_row is not None:
            self._adapter_row.setVisible(show_adapter_picker)

        if self._phone_hint_label is not None and has_phone_url:
            if access_mode == 'lan' and not show_adapter_picker and selected_adapter is not None and selected_adapter.interface_name:
                self._phone_hint_label.setText(
                    tr(
                        'Connect your phone to the same Wi-Fi or local network ({adapter}), then open this address or scan the QR code.',
                        adapter=selected_adapter.interface_name,
                    ),
                )
            else:
                self._phone_hint_label.setText(
                    tr('Connect your phone to the same Wi-Fi or local network, then open this address or scan the QR code.'),
                )

        if self._phone_unavailable_label is not None:
            show_unavailable = not show_blocked and not has_phone_url
            self._phone_unavailable_label.setVisible(show_unavailable)
            if show_unavailable:
                self._phone_unavailable_label.setText(unavailable_text)

        if self._qr_card is not None and self._qr_image_label is not None:
            if phone_url is not None:
                if phone_url != self._last_qr_url:
                    qr_pixmap = render_qr_pixmap(phone_url, scale_by_ui(_QR_DISPLAY_SIZE_PX))
                    if qr_pixmap is not None:
                        self._qr_image_label.setPixmap(qr_pixmap)
                        self._last_qr_url = phone_url
                        self._qr_card.setVisible(True)
                    else:
                        self._qr_card.setVisible(False)
                else:
                    self._qr_card.setVisible(True)
                self._qr_card.setToolTip(tr('Scan this QR code with your phone camera to open {url}', url=phone_url))
            else:
                self._qr_card.setVisible(False)

    def _update_help_text(self, port: int) -> None:
        if self._help_group is not None:
            self._help_group.setTitle(tr('Troubleshooting Tips').replace('&', '&&'))
        if self._help_label is not None:
            self._help_label.setText(
                tr(
                    '<b>Phone cannot load the page?</b><br>'
                    '- Make sure your phone and this PC are on the same Wi-Fi or local network (not mobile data or guest Wi-Fi).<br>'
                    '- If your phone shows <b>ERR_TOO_MANY_RETRIES</b> or fails to connect, grant your mobile browser the '
                    '<b>Nearby devices</b> (Android: App info \u2192 Permissions \u2192 Nearby devices) or '
                    '<b>Local Network</b> (iOS: Settings \u2192 Privacy &amp; Security \u2192 Local Network) permission, then reopen the browser.<br>'
                    '- If the page times out, allow Session Sniffer or inbound TCP port {port} in your firewall.<br>'
                    '- If port 80 is already used by another app, pick port 8080 or 8081 above and click Save.<br>'
                    '- Always use <b>http://</b> (not https://) when typing the address manually.',
                    port=port,
                ),
            )

    def _selected_lan_adapter(self) -> LocalNetworkAddress | None:
        if not self._detected_addresses:
            return None
        if self._adapter_combo is not None:
            idx = self._adapter_combo.currentIndex()
            if 0 <= idx < len(self._detected_addresses):
                return self._detected_addresses[idx]
        return self._detected_addresses[0]

    def _set_port_preset(self, port: int) -> None:
        if isinstance(port_widget := self._widgets.get('webserver_port'), QSpinBox):
            port_widget.setValue(port)

    def _enable_lan_sharing(self) -> None:
        if isinstance(host_widget := self._widgets.get('webserver_host'), WebServerAccessWidget):
            host_widget.select_lan_mode()

    def _open_in_browser(self) -> None:
        if self._current_local_url is not None and self._current_local_url:
            QDesktopServices.openUrl(QUrl(self._current_local_url))

    def _copy_local_url(self) -> None:
        if self._current_local_url is not None and self._current_local_url and self._copy_local_button is not None:
            set_clipboard_text(self._current_local_url)
            animate_button_feedback(self._copy_local_button)

    def _resolve_firewall_target_ip(self, access_mode: Literal['local', 'lan', 'custom'], host_value: str | None) -> str | None:
        if access_mode == 'custom' and isinstance(host_value, str) and is_ipv4_address(host_value) and host_value != WEBSERVER_LAN_HOST:
            return host_value
        selected = self._selected_lan_adapter()
        return selected.ip_address if selected is not None else None

    def _update_firewall_banner(self, port: int, *, can_check: bool, target_ip: str | None) -> None:
        if self._firewall_banner is None or self._firewall_label is None:
            return
        if not can_check:
            self._firewall_banner.setVisible(False)
            return
        if self._cached_firewall_check is not None and self._cached_firewall_check[0] == port and self._cached_firewall_check[1] == target_ip:
            fw_status = self._cached_firewall_check[2]
        else:
            fw_status = check_windows_firewall_status(port, local_ip=target_ip)
            self._cached_firewall_check = (port, target_ip, fw_status)

        is_warning = fw_status in ('blocked', 'explicitly_blocked', 'block_all_inbound')
        self._firewall_banner.setVisible(is_warning)
        if not is_warning:
            return
        self._firewall_label.setText(format_webserver_firewall_warning(fw_status, port))
        if self._allow_firewall_button is not None:
            self._allow_firewall_button.setVisible(fw_status == 'blocked')
            if fw_status == 'blocked':
                self._allow_firewall_button.setToolTip(
                    tr('Add a Windows Firewall rule allowing devices on your local network to connect on port {port}', port=port),
                )

    def _allow_in_firewall(self) -> None:
        port = port_widget.value() if isinstance(port_widget := self._widgets.get('webserver_port'), QSpinBox) else 80
        host_widget = self._widgets.get('webserver_host')
        access_mode = host_widget.access_mode() if isinstance(host_widget, WebServerAccessWidget) else 'lan'
        host_value = host_widget.value() if isinstance(host_widget, WebServerAccessWidget) else WEBSERVER_LAN_HOST
        target_ip = self._resolve_firewall_target_ip(access_mode, host_value)

        if self._allow_firewall_button is not None:
            self._allow_firewall_button.setEnabled(False)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            allowed = allow_webserver_firewall_port(port, local_ip=target_ip)
        finally:
            QApplication.restoreOverrideCursor()
            if self._allow_firewall_button is not None:
                self._allow_firewall_button.setEnabled(True)

        self._cached_firewall_check = None
        self.update_state()
        if not allowed:
            QMessageBox.warning(self._access_card, TITLE, format_webserver_firewall_failure(port))

    def _copy_phone_url(self) -> None:
        if self._current_phone_url is not None and self._current_phone_url and self._copy_phone_button is not None:
            set_clipboard_text(self._current_phone_url)
            animate_button_feedback(self._copy_phone_button)
