"""Hotspot and connection sharing QSS."""

HOTSPOT_CARD_STYLESHEET = """
QFrame#hotspotCard, QFrame#bridgeCard, QFrame#devicesCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #232f3e, stop:1 #18212c);
    border: 1px solid #2c3a4d;
    border-radius: 10px;
}

QFrame#hotspotCard QWidget#emptyDevicesWidget,
QFrame#devicesCard QWidget#emptyDevicesWidget,
QFrame#hotspotCard QCheckBox,
QFrame#bridgeCard QCheckBox,
QFrame#devicesCard QCheckBox {
    background: transparent;
    background-color: transparent;
}
""".strip()

HOTSPOT_CHECKBOX_STYLESHEET = """
QCheckBox {
    background: transparent;
    background-color: transparent;
    color: #9cb0c6;
    font-size: 8.5pt;
}

QCheckBox:hover {
    color: #e0e0e0;
}
""".strip()

HOTSPOT_CARD_HEADER_STYLESHEET = """
QLabel {
    color: #f0f4fa;
    font-size: 11pt;
    font-weight: 700;
}
""".strip()

HOTSPOT_BADGE_ACTIVE_STYLESHEET = """
QLabel {
    color: #3dd68c;
    background: rgba(61, 214, 140, 0.12);
    border: 1px solid rgba(61, 214, 140, 0.35);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 800;
    letter-spacing: 0.5px;
}
""".strip()

HOTSPOT_BADGE_INACTIVE_STYLESHEET = """
QLabel {
    color: #9cb0c6;
    background: rgba(156, 176, 198, 0.12);
    border: 1px solid rgba(156, 176, 198, 0.30);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 800;
    letter-spacing: 0.5px;
}
""".strip()

HOTSPOT_BADGE_TRANSITION_STYLESHEET = """
QLabel {
    color: #f59e0b;
    background: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.35);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 800;
    letter-spacing: 0.5px;
}
""".strip()

HOTSPOT_PILL_INFO_STYLESHEET = """
QLabel {
    color: #61afef;
    background: rgba(97, 175, 239, 0.10);
    border: 1px solid rgba(97, 175, 239, 0.25);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: 600;
}
""".strip()

HOTSPOT_FIELD_LABEL_STYLESHEET = """
QLabel {
    color: #9cb0c6;
    font-size: 9pt;
    font-weight: 600;
}
""".strip()

HOTSPOT_INPUT_STYLESHEET = """
QLineEdit, QComboBox {
    background-color: #141922;
    color: #e0e6ee;
    border: 1px solid #2a3544;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 9pt;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #3d8ec9;
    background-color: #171d28;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}
""".strip()

HOTSPOT_EMPTY_STATE_STYLESHEET = """
QLabel {
    color: #5c6d80;
    font-size: 9.5pt;
    font-weight: 500;
    background: transparent;
    background-color: transparent;
}
""".strip()

HOTSPOT_GUIDE_CONTAINER_STYLESHEET = """
QFrame#guideContainer {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a222d, stop:1 #121820);
    border: 1px solid #2d3b4d;
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
""".strip()

HOTSPOT_GUIDE_CARD_STYLESHEET = """
QFrame#guideOptionCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1e2836, stop:1 #141d28);
    border: 1px solid #2f3e52;
    border-radius: 10px;
}

QFrame#guideOptionCard:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #253346, stop:1 #192433);
    border: 1px solid #3d8ec9;
}

QFrame#guideOptionCard QLabel {
    background: transparent;
    border: none;
}
""".strip()

HOTSPOT_STEP_NUMBER_STYLESHEET = """
QLabel {
    color: #ffffff;
    background-color: #2b7bb9;
    border-radius: 11px;
    font-size: 8.5pt;
    font-weight: 800;
    min-width: 22px;
    max-width: 22px;
    min-height: 22px;
    max-height: 22px;
    qproperty-alignment: AlignCenter;
}
""".strip()
