"""Hotspot and connection sharing QSS."""

from session_sniffer.guis.theming import themed_qss

HOTSPOT_CARD_STYLESHEET = themed_qss(
    """
QFrame#hotspotCard, QFrame#bridgeCard, QFrame#devicesCard {
    background: @surface;
    border: 1px solid @border;
    border-radius: 10px;
}

QFrame#hotspotCard[unavailable="true"] {
    background: @surface:disabled;
    border: 1px solid @border:disabled;
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
    color: @text_muted;
    font-size: 8.5pt;
}

QCheckBox:hover {
    color: @text;
}
""".strip(),
)

HOTSPOT_CARD_HEADER_STYLESHEET = themed_qss(
    """
QLabel {
    color: @text_strong;
    font-size: 11pt;
    font-weight: 700;
}

QLabel:disabled {
    color: @text_muted:disabled;
}
""".strip(),
)

HOTSPOT_BADGE_ACTIVE_STYLESHEET = themed_qss(
    """
QLabel {
    color: @success;
    background: @surface~success/16;
    border: 1px solid @success/45;
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
    color: @text_muted;
    background: @surface;
    border: 1px solid @border;
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
    color: @warning;
    background: @surface~warning/16;
    border: 1px solid @warning/45;
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
    color: @accent;
    background: @surface~accent/14;
    border: 1px solid @accent/35;
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
    color: @text_muted;
    font-size: 9pt;
    font-weight: 600;
}

QLabel:disabled {
    color: @text_muted:disabled;
}
""".strip(),
)

HOTSPOT_INPUT_STYLESHEET = themed_qss(
    """
QLineEdit, QComboBox {
    background-color: @input;
    color: @text;
    border: 1px solid @border;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 9pt;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid @accent;
    background-color: @input;
}

QLineEdit:disabled, QComboBox:disabled {
    background-color: @input:disabled;
    color: @text_muted:disabled;
    border: 1px solid @border:disabled;
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
    color: @text_muted;
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
    background: @surface;
    border: 1px solid @border;
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
    background: @surface;
    border: 1px solid @border;
    border-radius: 10px;
}

QFrame#guideOptionCard:hover {
    background: @surface:hover;
    border: 1px solid @accent;
}

QFrame#guideOptionCard:disabled {
    background: @surface:disabled;
    border: 1px solid @border:disabled;
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
    color: @text_strong;
    background-color: @accent;
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
