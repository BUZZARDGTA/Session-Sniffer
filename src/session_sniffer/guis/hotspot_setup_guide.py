"""Interactive setup guide dialog for Wi-Fi Hotspot and Ethernet Bridge (ICS)."""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QIcon, QMouseEvent
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis._dialog_mixins import DraggableDialogMixin
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
    HOTSPOT_GUIDE_CARD_STYLESHEET,
    HOTSPOT_GUIDE_CONTAINER_STYLESHEET,
    HOTSPOT_STEP_NUMBER_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr
from session_sniffer.networking.hotspot import (
    configure_hotspot,
    disable_ics,
    enable_ics,
    get_connected_devices,
    get_hotspot_info,
    get_ics_status,
    has_wifi_adapter,
    start_hotspot,
    stop_hotspot,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HotspotActionResult:
    """Result of an asynchronous hotspot or connection sharing action."""

    success: bool
    message: str
    message_key: str = ''
    message_params: tuple[tuple[str, str], ...] = ()


class HotspotActionWorker(CrashingQThread):
    """Background worker for asynchronous hotspot and connection sharing tasks."""

    info_ready = Signal(object)
    devices_ready = Signal(object)
    ics_status_ready = Signal(object)
    action_completed = Signal(HotspotActionResult)

    def __init__(self, task_name: str, **kwargs: object) -> None:
        """Initialize the HotspotActionWorker."""
        super().__init__(name=f'HotspotWorker-{task_name}')
        self._task_name = task_name
        self._kwargs = kwargs

    @override
    def _run(self) -> None:
        try:
            if self._task_name == 'refresh_all':
                info = get_hotspot_info()
                self.info_ready.emit(info)
                devices = get_connected_devices() if info.is_available else []
                self.devices_ready.emit(devices)
                ics_status = get_ics_status()
                self.ics_status_ready.emit(ics_status)

            elif self._task_name == 'configure_credentials':
                ssid = str(self._kwargs.get('ssid', ''))
                passphrase = str(self._kwargs.get('passphrase', ''))
                success, error_message = configure_hotspot(ssid, passphrase)
                has_error = bool(error_message)
                default_key = 'Hotspot network name and password updated successfully.'
                self.action_completed.emit(
                    HotspotActionResult(
                        success=success,
                        message=error_message or tr(default_key),
                        message_key='' if has_error else default_key,
                    ),
                )

            elif self._task_name == 'start_hotspot':
                success, error_message = start_hotspot()
                has_error = bool(error_message)
                default_key = 'Mobile Hotspot started.'
                self.action_completed.emit(
                    HotspotActionResult(
                        success=success,
                        message=error_message or tr(default_key),
                        message_key='' if has_error else default_key,
                    ),
                )

            elif self._task_name == 'stop_hotspot':
                success, error_message = stop_hotspot()
                has_error = bool(error_message)
                default_key = 'Mobile Hotspot stopped.'
                self.action_completed.emit(
                    HotspotActionResult(
                        success=success,
                        message=error_message or tr(default_key),
                        message_key='' if has_error else default_key,
                    ),
                )

            elif self._task_name == 'enable_ics':
                public_adapter = str(self._kwargs.get('public_adapter', ''))
                private_adapter = str(self._kwargs.get('private_adapter', ''))
                success, error_message = enable_ics(public_adapter, private_adapter)
                has_error = bool(error_message)
                default_key = 'Internet Connection Sharing enabled between {public_adapter} and {private_adapter}.'
                params = (('public_adapter', public_adapter), ('private_adapter', private_adapter))
                self.action_completed.emit(
                    HotspotActionResult(
                        success=success,
                        message=error_message or tr(default_key, public_adapter=public_adapter, private_adapter=private_adapter),
                        message_key='' if has_error else default_key,
                        message_params=() if has_error else params,
                    ),
                )

            elif self._task_name == 'disable_ics':
                success, error_message = disable_ics()
                has_error = bool(error_message)
                default_key = 'Internet Connection Sharing disabled.'
                self.action_completed.emit(
                    HotspotActionResult(
                        success=success,
                        message=error_message or tr(default_key),
                        message_key='' if has_error else default_key,
                    ),
                )

        except (OSError, RuntimeError) as e:
            logger.exception('Hotspot action worker failed on task %s', self._task_name)
            self.action_completed.emit(HotspotActionResult(success=False, message=str(e)))


class _ClickableOptionCard(QFrame):
    """Interactive card frame that triggers a callback on mouse release."""

    def __init__(self, on_click: Callable[[], None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._on_click = on_click
        self.setObjectName('guideOptionCard')
        self.setStyleSheet(HOTSPOT_GUIDE_CARD_STYLESHEET)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    @override
    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if self.isEnabled() and event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
            event.accept()
            return
        super().mouseReleaseEvent(event)


class HotspotSetupGuideDialog(DraggableDialogMixin, QDialog):
    """Walkthrough dialog explaining how to configure Wi-Fi Hotspot or Ethernet Bridge for console packet sniffing."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HotspotSetupGuideDialog."""
        super().__init__(parent)
        self._text_bindings: list[tuple[QLabel | QPushButton, str]] = []
        self._apply_translations()
        register_language_refresh(self, self._apply_translations)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, on=True)
        self.setMinimumSize(scale_by_ui(680), scale_by_ui(500))
        self.resize(scale_by_ui(680), scale_by_ui(500))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(scale_by_ui(16), scale_by_ui(16), scale_by_ui(16), scale_by_ui(16))

        container_frame = QFrame()
        container_frame.setObjectName('guideContainer')
        container_frame.setStyleSheet(HOTSPOT_GUIDE_CONTAINER_STYLESHEET)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(36)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 200))
        container_frame.setGraphicsEffect(shadow)

        container_layout = QVBoxLayout(container_frame)
        container_layout.setContentsMargins(scale_by_ui(24), scale_by_ui(20), scale_by_ui(24), scale_by_ui(20))
        container_layout.setSpacing(scale_by_ui(16))

        # Close button in top-right
        top_bar_layout = QHBoxLayout()
        top_bar_layout.addStretch()
        close_button = QPushButton('✕')
        close_button.setStyleSheet(
            themed_qss(
                'QPushButton {'
                '    background: transparent;'
                '    color: #6f7e91;'
                '    border: none;'
                '    font-size: 11pt;'
                '    font-weight: bold;'
                '    min-width: 24px;'
                '    max-width: 24px;'
                '    min-height: 24px;'
                '    max-height: 24px;'
                '}'
                'QPushButton:hover { color: #ffffff; }',
            ),
        )
        close_button.clicked.connect(self.reject)
        top_bar_layout.addWidget(close_button)
        container_layout.addLayout(top_bar_layout)

        self._stacked_widget = QStackedWidget()
        self._stacked_widget.addWidget(self._build_selection_page())
        self._stacked_widget.addWidget(self._build_wifi_guide_page())
        self._stacked_widget.addWidget(self._build_ethernet_guide_page())

        container_layout.addWidget(self._stacked_widget)
        outer_layout.addWidget(container_frame)

    def _build_selection_page(self) -> QWidget:
        """Construct the initial overview and method selection page."""
        page = QWidget()
        page.setStyleSheet('background: transparent; background-color: transparent;')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(scale_by_ui(14))

        # Top icon row
        icons_layout = QHBoxLayout()
        icons_layout.addStretch()
        wifi_pill = QLabel()
        wifi_pill.setFixedSize(scale_by_ui(38), scale_by_ui(38))
        wifi_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        wifi_pill.setPixmap(QIcon(str(ICONS_DIR_PATH / 'wifi.svg')).pixmap(scale_by_ui(22), scale_by_ui(22)))
        wifi_pill.setStyleSheet(themed_qss('padding: 8px; background: rgba(61, 142, 201, 0.15); border-radius: 8px; border: 1px solid rgba(61, 142, 201, 0.35);'))
        ethernet_pill = QLabel()
        ethernet_pill.setFixedSize(scale_by_ui(38), scale_by_ui(38))
        ethernet_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ethernet_pill.setPixmap(QIcon(str(ICONS_DIR_PATH / 'ethernet-port.svg')).pixmap(scale_by_ui(22), scale_by_ui(22)))
        ethernet_pill.setStyleSheet(themed_qss('padding: 8px; background: rgba(61, 142, 201, 0.15); border-radius: 8px; border: 1px solid rgba(61, 142, 201, 0.35);'))
        icons_layout.addWidget(wifi_pill)
        icons_layout.addSpacing(scale_by_ui(8))
        icons_layout.addWidget(ethernet_pill)
        icons_layout.addStretch()
        layout.addLayout(icons_layout)

        title_label = QLabel()
        self._bind_translated_text(title_label, 'Internet Sharing Setup')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(themed_qss('color: #f0f4fa; font-size: 14pt; font-weight: 700;'))
        layout.addWidget(title_label)

        description_label = QLabel()
        self._bind_translated_text(
            description_label,
            "Session Sniffer can share your PC's internet connection to a console or device so you can capture its network traffic. "
            'Choose the method that works best for your setup.',
        )
        description_label.setWordWrap(True)
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet(themed_qss('color: #9cb0c6; font-size: 9pt; line-height: 1.4;'))
        layout.addWidget(description_label)
        layout.addSpacing(scale_by_ui(4))

        # Option Card 1: Wi-Fi Hotspot
        wifi_available = has_wifi_adapter()
        wifi_card = _ClickableOptionCard(lambda: self._stacked_widget.setCurrentIndex(1))
        wifi_card_layout = QHBoxLayout(wifi_card)
        wifi_card_layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        wifi_card_layout.setSpacing(scale_by_ui(14))

        wifi_icon_label = QLabel()
        wifi_icon_label.setFixedSize(scale_by_ui(40), scale_by_ui(40))
        wifi_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        wifi_icon_label.setPixmap(QIcon(str(ICONS_DIR_PATH / 'wifi.svg')).pixmap(scale_by_ui(24), scale_by_ui(24)))
        wifi_icon_label.setStyleSheet(
            themed_qss(
                'padding: 8px; background: rgba(61, 142, 201, 0.20); border-radius: 8px;'
                if wifi_available
                else 'padding: 8px; background: rgba(82, 97, 115, 0.12); border-radius: 8px;',
            ),
        )
        wifi_card_layout.addWidget(wifi_icon_label, 0, Qt.AlignmentFlag.AlignCenter)

        wifi_text_layout = QVBoxLayout()
        wifi_header_layout = QHBoxLayout()
        wifi_title = QLabel()
        self._bind_translated_text(wifi_title, 'Wi-Fi Hotspot')
        wifi_title.setStyleSheet(
            themed_qss(
                'color: #ffffff; font-size: 10.5pt; font-weight: 700;' if wifi_available else 'color: #5c6d80; font-size: 10.5pt; font-weight: 700;',
            ),
        )
        wifi_header_layout.addWidget(wifi_title)
        wifi_badge = QLabel()
        self._bind_translated_text(wifi_badge, 'RECOMMENDED' if wifi_available else 'UNAVAILABLE')
        wifi_badge.setStyleSheet(
            themed_qss(
                (
                    'color: #38bdf8; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.4); '
                    'border-radius: 4px; padding: 1px 6px; font-size: 7pt; font-weight: 800;'
                )
                if wifi_available
                else (
                    'color: #6b7c90; background: rgba(107, 124, 144, 0.12); border: 1px solid rgba(107, 124, 144, 0.3); '
                    'border-radius: 4px; padding: 1px 6px; font-size: 7pt; font-weight: 800;'
                ),
            ),
        )
        wifi_header_layout.addWidget(wifi_badge)
        wifi_header_layout.addStretch()
        wifi_text_layout.addLayout(wifi_header_layout)

        wifi_desc = QLabel()
        self._bind_translated_text(
            wifi_desc,
            'Create a wireless hotspot from your PC. Your console connects over Wi-Fi.' if wifi_available else 'No Wi-Fi adapter detected on this PC.',
        )
        wifi_desc.setWordWrap(True)
        wifi_desc.setStyleSheet(themed_qss('color: #c8ddf0; font-size: 8.5pt;' if wifi_available else 'color: #526173; font-size: 8.5pt;'))
        wifi_text_layout.addWidget(wifi_desc)
        wifi_card_layout.addLayout(wifi_text_layout, 1)
        if not wifi_available:
            wifi_card.setEnabled(False)
            wifi_card.setCursor(Qt.CursorShape.ArrowCursor)
        layout.addWidget(wifi_card)

        # Option Card 2: Ethernet Bridge
        ethernet_card = _ClickableOptionCard(lambda: self._stacked_widget.setCurrentIndex(2))
        ethernet_card_layout = QHBoxLayout(ethernet_card)
        ethernet_card_layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        ethernet_card_layout.setSpacing(scale_by_ui(14))

        ethernet_icon_label = QLabel()
        ethernet_icon_label.setFixedSize(scale_by_ui(40), scale_by_ui(40))
        ethernet_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ethernet_icon_label.setPixmap(QIcon(str(ICONS_DIR_PATH / 'ethernet-port.svg')).pixmap(scale_by_ui(24), scale_by_ui(24)))
        ethernet_icon_label.setStyleSheet(themed_qss('padding: 8px; background: rgba(167, 139, 250, 0.18); border-radius: 8px;'))
        ethernet_card_layout.addWidget(ethernet_icon_label, 0, Qt.AlignmentFlag.AlignCenter)

        ethernet_text_layout = QVBoxLayout()
        ethernet_title = QLabel()
        self._bind_translated_text(ethernet_title, 'Ethernet Bridge (ICS)')
        ethernet_title.setStyleSheet(themed_qss('color: #ffffff; font-size: 10.5pt; font-weight: 700;'))
        ethernet_text_layout.addWidget(ethernet_title)
        ethernet_desc = QLabel()
        self._bind_translated_text(ethernet_desc, 'Share your Wi-Fi or VPN connection over an Ethernet cable plugged directly into your console.')
        ethernet_desc.setWordWrap(True)
        ethernet_desc.setStyleSheet(themed_qss('color: #c8ddf0; font-size: 8.5pt;'))
        ethernet_text_layout.addWidget(ethernet_desc)
        ethernet_card_layout.addLayout(ethernet_text_layout, 1)
        layout.addWidget(ethernet_card)

        layout.addStretch()

        # Footer button
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        skip_button = QPushButton()
        self._bind_translated_text(skip_button, 'Skip for now')
        skip_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        skip_button.clicked.connect(self.accept)
        footer_layout.addWidget(skip_button)
        layout.addLayout(footer_layout)

        return page

    def _bind_translated_text(self, widget: QLabel | QPushButton, canonical_text: str) -> None:
        """Bind a label or button to its canonical string for live language refreshes."""
        widget.setText(tr(canonical_text))
        self._text_bindings.append((widget, canonical_text))

    def _apply_translations(self) -> None:
        """Apply current translations to the dialog title and bound text widgets."""
        setup_title = tr('Internet Sharing Setup')
        self.setWindowTitle(f'{TITLE} - {setup_title}')
        for widget, canonical_text in self._text_bindings:
            widget.setText(tr(canonical_text))

    def _build_guide_page(
        self,
        *,
        icon_name: str,
        pill_stylesheet: str,
        title_text: str,
        steps: list[str],
    ) -> QWidget:
        """Construct a step-by-step walkthrough guide page."""
        page = QWidget()
        page.setStyleSheet('background: transparent; background-color: transparent;')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(scale_by_ui(14))

        icon_row = QHBoxLayout()
        icon_row.addStretch()
        pill = QLabel()
        pill.setFixedSize(scale_by_ui(46), scale_by_ui(46))
        pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pill.setPixmap(QIcon(str(ICONS_DIR_PATH / icon_name)).pixmap(scale_by_ui(26), scale_by_ui(26)))
        pill.setStyleSheet(themed_qss(pill_stylesheet))
        icon_row.addWidget(pill)
        icon_row.addStretch()
        layout.addLayout(icon_row)

        title = QLabel()
        self._bind_translated_text(title, title_text)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(themed_qss('color: #f0f4fa; font-size: 13.5pt; font-weight: 700;'))
        layout.addWidget(title)

        steps_container = QVBoxLayout()
        steps_container.setSpacing(scale_by_ui(12))

        for index, step_text in enumerate(steps, start=1):
            step_row = QHBoxLayout()
            step_row.setSpacing(scale_by_ui(12))
            num_label = QLabel(str(index))
            num_label.setStyleSheet(HOTSPOT_STEP_NUMBER_STYLESHEET)
            text_label = QLabel()
            self._bind_translated_text(text_label, step_text)
            text_label.setWordWrap(True)
            text_label.setStyleSheet(themed_qss('color: #d0dbe8; font-size: 9pt; line-height: 1.35;'))
            step_row.addWidget(num_label, 0, Qt.AlignmentFlag.AlignTop)
            step_row.addWidget(text_label, 1)
            steps_container.addLayout(step_row)

        layout.addLayout(steps_container)
        layout.addStretch()

        footer_layout = QHBoxLayout()
        back_button = QPushButton()
        self._bind_translated_text(back_button, 'Back')
        back_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        back_button.clicked.connect(lambda: self._stacked_widget.setCurrentIndex(0))
        footer_layout.addWidget(back_button)
        footer_layout.addStretch()
        got_it_button = QPushButton()
        self._bind_translated_text(got_it_button, 'Got it')
        got_it_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        got_it_button.clicked.connect(self.accept)
        footer_layout.addWidget(got_it_button)
        layout.addLayout(footer_layout)

        return page

    def _build_wifi_guide_page(self) -> QWidget:
        """Construct the step-by-step walkthrough for Wi-Fi Hotspot."""
        return self._build_guide_page(
            icon_name='wifi.svg',
            pill_stylesheet='padding: 10px; background: rgba(61, 142, 201, 0.18); border-radius: 10px; border: 1px solid rgba(61, 142, 201, 0.4);',
            title_text='Setting up Wi-Fi Hotspot',
            steps=[
                'Enter an SSID (network name) and password in the Hotspot panel, then click Save.',
                'Click Start Hotspot to enable the network. On your console (PlayStation, Xbox, Switch), connect to the Wi-Fi network.',
                'Once connected, start a capture in Session Sniffer — all console game traffic will flow through your PC.',
            ],
        )

    def _build_ethernet_guide_page(self) -> QWidget:
        """Construct the step-by-step walkthrough for Ethernet Bridge (ICS)."""
        return self._build_guide_page(
            icon_name='ethernet-port.svg',
            pill_stylesheet='padding: 10px; background: rgba(167, 139, 250, 0.18); border-radius: 10px; border: 1px solid rgba(167, 139, 250, 0.4);',
            title_text='Setting up Ethernet Bridge',
            steps=[
                'Make sure your PC is connected to the internet (over Wi-Fi or a VPN).',
                'Plug an Ethernet cable from your PC directly into your console.',
                'In the Sharing section, select your internet source as Public and the Ethernet adapter as Private, then click Enable Sharing.',
                'Start a capture in Session Sniffer on the Ethernet adapter — all console traffic will flow through the Ethernet bridge.',
            ],
        )
