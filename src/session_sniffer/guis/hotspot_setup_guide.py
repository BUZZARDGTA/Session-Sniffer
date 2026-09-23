"""Interactive setup guide dialog for Wi-Fi Hotspot and Ethernet Bridge (ICS)."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import Qt
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

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._dialog_mixins import DraggableDialogMixin
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
    HOTSPOT_GUIDE_CARD_STYLESHEET,
    HOTSPOT_GUIDE_CONTAINER_STYLESHEET,
    HOTSPOT_STEP_NUMBER_STYLESHEET,
)
from session_sniffer.guis.utils import scale_by_ui

if TYPE_CHECKING:
    from collections.abc import Callable


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
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
            event.accept()
            return
        super().mouseReleaseEvent(event)


class HotspotSetupGuideDialog(DraggableDialogMixin, QDialog):
    """Walkthrough dialog explaining how to configure Wi-Fi Hotspot or Ethernet Bridge for console packet sniffing."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HotspotSetupGuideDialog."""
        super().__init__(parent)
        self.setWindowTitle(f'{TITLE} - Internet Sharing Setup')
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
            'QPushButton:hover { color: #ffffff; }'
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
        wifi_pill.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'wifi.svg')).pixmap(scale_by_ui(22), scale_by_ui(22)))
        wifi_pill.setStyleSheet('padding: 8px; background: rgba(61, 142, 201, 0.15); border-radius: 8px; border: 1px solid rgba(61, 142, 201, 0.35);')
        ethernet_pill = QLabel()
        ethernet_pill.setFixedSize(scale_by_ui(38), scale_by_ui(38))
        ethernet_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ethernet_pill.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ethernet.svg')).pixmap(scale_by_ui(22), scale_by_ui(22)))
        ethernet_pill.setStyleSheet('padding: 8px; background: rgba(61, 142, 201, 0.15); border-radius: 8px; border: 1px solid rgba(61, 142, 201, 0.35);')
        icons_layout.addWidget(wifi_pill)
        icons_layout.addSpacing(scale_by_ui(8))
        icons_layout.addWidget(ethernet_pill)
        icons_layout.addStretch()
        layout.addLayout(icons_layout)

        title_label = QLabel('Internet Sharing Setup')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet('color: #f0f4fa; font-size: 14pt; font-weight: 700;')
        layout.addWidget(title_label)

        description_label = QLabel(
            "Session Sniffer can share your PC's internet connection to a console or device so you can capture its network traffic. "
            'Choose the method that works best for your setup.'
        )
        description_label.setWordWrap(True)
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet('color: #9cb0c6; font-size: 9pt; line-height: 1.4;')
        layout.addWidget(description_label)
        layout.addSpacing(scale_by_ui(4))

        # Option Card 1: Wi-Fi Hotspot
        wifi_card = _ClickableOptionCard(lambda: self._stacked_widget.setCurrentIndex(1))
        wifi_card_layout = QHBoxLayout(wifi_card)
        wifi_card_layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        wifi_card_layout.setSpacing(scale_by_ui(14))

        wifi_icon_label = QLabel()
        wifi_icon_label.setFixedSize(scale_by_ui(40), scale_by_ui(40))
        wifi_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        wifi_icon_label.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'wifi.svg')).pixmap(scale_by_ui(24), scale_by_ui(24)))
        wifi_icon_label.setStyleSheet('padding: 8px; background: rgba(61, 142, 201, 0.20); border-radius: 8px;')
        wifi_card_layout.addWidget(wifi_icon_label, 0, Qt.AlignmentFlag.AlignCenter)

        wifi_text_layout = QVBoxLayout()
        wifi_header_layout = QHBoxLayout()
        wifi_title = QLabel('Wi-Fi Hotspot')
        wifi_title.setStyleSheet('color: #ffffff; font-size: 10.5pt; font-weight: 700;')
        wifi_header_layout.addWidget(wifi_title)
        wifi_badge = QLabel('RECOMMENDED')
        wifi_badge.setStyleSheet(
            'color: #38bdf8; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.4); '
            'border-radius: 4px; padding: 1px 6px; font-size: 7pt; font-weight: 800;'
        )
        wifi_header_layout.addWidget(wifi_badge)
        wifi_header_layout.addStretch()
        wifi_text_layout.addLayout(wifi_header_layout)

        wifi_desc = QLabel('Create a wireless hotspot from your PC. Your console connects over Wi-Fi.')
        wifi_desc.setWordWrap(True)
        wifi_desc.setStyleSheet('color: #c8ddf0; font-size: 8.5pt;')
        wifi_text_layout.addWidget(wifi_desc)
        wifi_card_layout.addLayout(wifi_text_layout, 1)
        layout.addWidget(wifi_card)

        # Option Card 2: Ethernet Bridge
        ethernet_card = _ClickableOptionCard(lambda: self._stacked_widget.setCurrentIndex(2))
        ethernet_card_layout = QHBoxLayout(ethernet_card)
        ethernet_card_layout.setContentsMargins(scale_by_ui(16), scale_by_ui(14), scale_by_ui(16), scale_by_ui(14))
        ethernet_card_layout.setSpacing(scale_by_ui(14))

        ethernet_icon_label = QLabel()
        ethernet_icon_label.setFixedSize(scale_by_ui(40), scale_by_ui(40))
        ethernet_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ethernet_icon_label.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ethernet.svg')).pixmap(scale_by_ui(24), scale_by_ui(24)))
        ethernet_icon_label.setStyleSheet('padding: 8px; background: rgba(167, 139, 250, 0.18); border-radius: 8px;')
        ethernet_card_layout.addWidget(ethernet_icon_label, 0, Qt.AlignmentFlag.AlignCenter)

        ethernet_text_layout = QVBoxLayout()
        ethernet_title = QLabel('Ethernet Bridge (ICS)')
        ethernet_title.setStyleSheet('color: #ffffff; font-size: 10.5pt; font-weight: 700;')
        ethernet_text_layout.addWidget(ethernet_title)
        ethernet_desc = QLabel('Share your Wi-Fi or VPN connection over an Ethernet cable plugged directly into your console.')
        ethernet_desc.setWordWrap(True)
        ethernet_desc.setStyleSheet('color: #c8ddf0; font-size: 8.5pt;')
        ethernet_text_layout.addWidget(ethernet_desc)
        ethernet_card_layout.addLayout(ethernet_text_layout, 1)
        layout.addWidget(ethernet_card)

        layout.addStretch()

        # Footer button
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        skip_button = QPushButton('Skip for now')
        skip_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        skip_button.clicked.connect(self.accept)
        footer_layout.addWidget(skip_button)
        layout.addLayout(footer_layout)

        return page

    def _build_wifi_guide_page(self) -> QWidget:
        """Construct the step-by-step walkthrough for Wi-Fi Hotspot."""
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
        pill.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'wifi.svg')).pixmap(scale_by_ui(26), scale_by_ui(26)))
        pill.setStyleSheet('padding: 10px; background: rgba(61, 142, 201, 0.18); border-radius: 10px; border: 1px solid rgba(61, 142, 201, 0.4);')
        icon_row.addWidget(pill)
        icon_row.addStretch()
        layout.addLayout(icon_row)

        title = QLabel('Setting up Wi-Fi Hotspot')
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet('color: #f0f4fa; font-size: 13.5pt; font-weight: 700;')
        layout.addWidget(title)

        steps_container = QVBoxLayout()
        steps_container.setSpacing(scale_by_ui(12))

        steps = [
            'Enter an SSID (network name) and password in the Hotspot panel, then click Save.',
            'Click Start Hotspot to enable the network. On your console (PlayStation, Xbox, Switch), connect to the Wi-Fi network.',
            'Once connected, start a capture in Session Sniffer — all console game traffic will flow through your PC.',
        ]

        for index, step_text in enumerate(steps, start=1):
            step_row = QHBoxLayout()
            step_row.setSpacing(scale_by_ui(12))
            num_label = QLabel(str(index))
            num_label.setStyleSheet(HOTSPOT_STEP_NUMBER_STYLESHEET)
            text_label = QLabel(step_text)
            text_label.setWordWrap(True)
            text_label.setStyleSheet('color: #d0dbe8; font-size: 9pt; line-height: 1.35;')
            step_row.addWidget(num_label, 0, Qt.AlignmentFlag.AlignTop)
            step_row.addWidget(text_label, 1)
            steps_container.addLayout(step_row)

        layout.addLayout(steps_container)
        layout.addStretch()

        # Footer buttons
        footer_layout = QHBoxLayout()
        back_button = QPushButton('Back')
        back_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        back_button.clicked.connect(lambda: self._stacked_widget.setCurrentIndex(0))
        footer_layout.addWidget(back_button)
        footer_layout.addStretch()
        got_it_button = QPushButton('Got it')
        got_it_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        got_it_button.clicked.connect(self.accept)
        footer_layout.addWidget(got_it_button)
        layout.addLayout(footer_layout)

        return page

    def _build_ethernet_guide_page(self) -> QWidget:
        """Construct the step-by-step walkthrough for Ethernet Bridge (ICS)."""
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
        pill.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ethernet.svg')).pixmap(scale_by_ui(26), scale_by_ui(26)))
        pill.setStyleSheet('padding: 10px; background: rgba(167, 139, 250, 0.18); border-radius: 10px; border: 1px solid rgba(167, 139, 250, 0.4);')
        icon_row.addWidget(pill)
        icon_row.addStretch()
        layout.addLayout(icon_row)

        title = QLabel('Setting up Ethernet Bridge')
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet('color: #f0f4fa; font-size: 13.5pt; font-weight: 700;')
        layout.addWidget(title)

        steps_container = QVBoxLayout()
        steps_container.setSpacing(scale_by_ui(12))

        steps = [
            'Make sure your PC is connected to the internet (over Wi-Fi or a VPN).',
            'Plug an Ethernet cable from your PC directly into your console.',
            'In the Sharing section, select your internet source as Public and the Ethernet adapter as Private, then click Enable Sharing.',
            'Start a capture in Session Sniffer on the Ethernet adapter — all console traffic will flow through the Ethernet bridge.',
        ]

        for index, step_text in enumerate(steps, start=1):
            step_row = QHBoxLayout()
            step_row.setSpacing(scale_by_ui(12))
            num_label = QLabel(str(index))
            num_label.setStyleSheet(HOTSPOT_STEP_NUMBER_STYLESHEET)
            text_label = QLabel(step_text)
            text_label.setWordWrap(True)
            text_label.setStyleSheet('color: #d0dbe8; font-size: 9pt; line-height: 1.35;')
            step_row.addWidget(num_label, 0, Qt.AlignmentFlag.AlignTop)
            step_row.addWidget(text_label, 1)
            steps_container.addLayout(step_row)

        layout.addLayout(steps_container)
        layout.addStretch()

        # Footer buttons
        footer_layout = QHBoxLayout()
        back_button = QPushButton('Back')
        back_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        back_button.clicked.connect(lambda: self._stacked_widget.setCurrentIndex(0))
        footer_layout.addWidget(back_button)
        footer_layout.addStretch()
        got_it_button = QPushButton('Got it')
        got_it_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        got_it_button.clicked.connect(self.accept)
        footer_layout.addWidget(got_it_button)
        layout.addLayout(footer_layout)

        return page
