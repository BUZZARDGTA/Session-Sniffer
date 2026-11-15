"""Hotspot and connection sharing QSS."""

from session_sniffer.guis.theming import themed_qss

HOTSPOT_CARD_STYLESHEET = themed_qss(
    """
QFrame#hotspotCard, QFrame#bridgeCard, QFrame#devicesCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#232f3e], stop:1 @surface[#18212c]);
    border: 1px solid @border[#2c3a4d];
    border-radius: 10px;
}

QFrame#hotspotCard[unavailable="true"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#18202a], stop:1 @background[#121820]);
    border: 1px solid @border[#222c3a];
}

QFrame#hotspotCard QWidget#emptyDevicesWidget,
QFrame#devicesCard QWidget#emptyDevicesWidget,
QFrame#hotspotCard QCheckBox,
QFrame#bridgeCard QCheckBox,
QFrame#devicesCard QCheckBox {
    background: transparent;
    background-color: transparent;
}
""".strip(),
)

HOTSPOT_CHECKBOX_STYLESHEET = themed_qss(
    """
QCheckBox {
    background: transparent;
    background-color: transparent;
    color: @text_muted[#9cb0c6];
    font-size: 8.5pt;
}

QCheckBox:hover {
    color: @text[#e0e0e0];
}
""".strip(),
)

HOTSPOT_CARD_HEADER_STYLESHEET = themed_qss(
    """
QLabel {
    color: @text_strong[#f0f4fa];
    font-size: 11pt;
    font-weight: 700;
}

QLabel:disabled {
    color: @text_muted[#5c6d80];
}
""".strip(),
)

HOTSPOT_BADGE_ACTIVE_STYLESHEET = themed_qss(
    """
QLabel {
    color: @success[#3dd68c];
    background: @success[rgba(61, 214, 140, 0.12)];
    border: 1px solid @success[rgba(61, 214, 140, 0.35)];
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 800;
    letter-spacing: 0.5px;
}
""".strip(),
)

HOTSPOT_BADGE_INACTIVE_STYLESHEET = themed_qss(
    """
QLabel {
    color: @text_muted[#9cb0c6];
    background: @surface[rgba(156, 176, 198, 0.12)];
    border: 1px solid @border[rgba(156, 176, 198, 0.30)];
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 800;
    letter-spacing: 0.5px;
}
""".strip(),
)

HOTSPOT_BADGE_TRANSITION_STYLESHEET = themed_qss(
    """
QLabel {
    color: @warning[#f59e0b];
    background: @warning[rgba(245, 158, 11, 0.12)];
    border: 1px solid @warning[rgba(245, 158, 11, 0.35)];
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 800;
    letter-spacing: 0.5px;
}
""".strip(),
)

HOTSPOT_PILL_INFO_STYLESHEET = themed_qss(
    """
QLabel {
    color: @accent[#61afef];
    background: @accent[rgba(97, 175, 239, 0.10)];
    border: 1px solid @accent[rgba(97, 175, 239, 0.25)];
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 600;
}
""".strip(),
)

HOTSPOT_FIELD_LABEL_STYLESHEET = themed_qss(
    """
QLabel {
    color: @text_muted[#9cb0c6];
    font-size: 9pt;
    font-weight: 600;
}

QLabel:disabled {
    color: @text_muted[#526173];
}
""".strip(),
)

HOTSPOT_INPUT_STYLESHEET = themed_qss(
    """
QLineEdit, QComboBox {
    background-color: @input[#141922];
    color: @text[#e0e6ee];
    border: 1px solid @border[#2a3544];
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 9pt;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid @accent[#3d8ec9];
    background-color: @input[#171d28];
}

QLineEdit:disabled, QComboBox:disabled {
    background-color: @input[#10141b];
    color: @text_muted[#526173];
    border: 1px solid @border[#1e2631];
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}
""".strip(),
)

HOTSPOT_EMPTY_STATE_STYLESHEET = themed_qss(
    """
QLabel {
    color: @text_muted[#5c6d80];
    font-size: 9.5pt;
    font-weight: 500;
    background: transparent;
    background-color: transparent;
}
""".strip(),
)

HOTSPOT_GUIDE_CONTAINER_STYLESHEET = themed_qss(
    """
QFrame#guideContainer {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#1a222d], stop:1 @background[#121820]);
    border: 1px solid @border[#2d3b4d];
    border-radius: 14px;
}

QFrame#guideContainer QLabel {
    background: transparent;
    border: none;
}

QFrame#guideContainer QWidget,
QFrame#guideContainer QStackedWidget {
    background: transparent;
    background-color: transparent;
}
""".strip(),
)

HOTSPOT_GUIDE_CARD_STYLESHEET = themed_qss(
    """
QFrame#guideOptionCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#1e2836], stop:1 @surface[#141d28]);
    border: 1px solid @border[#2f3e52];
    border-radius: 10px;
}

QFrame#guideOptionCard:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#253346], stop:1 @surface[#192433]);
    border: 1px solid @accent[#3d8ec9];
}

QFrame#guideOptionCard:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#161d26], stop:1 @background[#10161d]);
    border: 1px solid @border[#222c3a];
}

QFrame#guideOptionCard QLabel {
    background: transparent;
    border: none;
}
""".strip(),
)

HOTSPOT_STEP_NUMBER_STYLESHEET = themed_qss(
    """
QLabel {
    color: @text_strong[#ffffff];
    background-color: @accent[#2b7bb9];
    border-radius: 11px;
    font-size: 8.5pt;
    font-weight: 800;
    min-width: 22px;
    max-width: 22px;
    min-height: 22px;
    max-height: 22px;
    qproperty-alignment: AlignCenter;
}
""".strip(),
)
