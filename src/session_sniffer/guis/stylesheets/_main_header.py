"""Stylesheets for the main application dashboard header."""

from session_sniffer.guis.theming import themed_qss

MAIN_HEADER_CONTAINER_STYLESHEET = themed_qss('QFrame#mainHeader { background-color: transparent; border: none; }')

HEADER_TITLE_STYLESHEET = themed_qss('font-size: 13pt; font-weight: 700; color: @text_strong[#ffffff];')

HEADER_VERSION_BADGE_STYLESHEET = themed_qss(
    """
color: @text_muted[#94a3b8];
background-color: @surface[rgba(255, 255, 255, 0.06)];
border: 1px solid @border[rgba(255, 255, 255, 0.1)];
border-radius: 4px;
padding: 1px 6px;
font-size: 8pt;
font-weight: 500;
""".strip(),
)

HEADER_SUBTITLE_STYLESHEET = themed_qss('font-size: 8.5pt; color: @text_muted[#64748b];')

HEADER_STOPPED_BADGE_STYLESHEET = themed_qss(
    """
color: @danger[#ef4444];
background-color: @danger[rgba(239, 68, 68, 0.12)];
border: 1px solid @danger[rgba(239, 68, 68, 0.35)];
border-radius: 4px;
padding: 1px 7px;
font-size: 8pt;
font-weight: 700;
letter-spacing: 0.5px;
""".strip(),
)

HEADER_SEARCH_BAR_STYLESHEET = themed_qss(
    """
QLineEdit#headerSearchBar {
    min-height: 28px;
    max-height: 30px;
    padding: 0 10px 0 8px;
    color: @text[#f1f5f9];
    background-color: @input[rgba(255, 255, 255, 0.04)];
    border: 1px solid @border[rgba(255, 255, 255, 0.1)];
    border-radius: 6px;
    font-size: 9pt;
}
QLineEdit#headerSearchBar:hover {
    background-color: @input[rgba(255, 255, 255, 0.06)];
    border: 1px solid @border[rgba(255, 255, 255, 0.18)];
}
QLineEdit#headerSearchBar:focus {
    border: 1px solid @success[#22c55e];
    background-color: @input[rgba(0, 0, 0, 0.45)];
}
""".strip(),
)

HEADER_SEARCH_COMBO_STYLESHEET = themed_qss(
    """
QComboBox#headerSearchCombo {
    min-height: 28px;
    max-height: 30px;
    padding: 0 24px 0 10px;
    color: @text[#cbd5e1];
    background-color: @input[rgba(255, 255, 255, 0.04)];
    border: 1px solid @border[rgba(255, 255, 255, 0.1)];
    border-radius: 6px;
    font-size: 9pt;
    selection-background-color: @selection[#3e3e42];
}
QComboBox#headerSearchCombo:hover {
    background-color: @input[rgba(255, 255, 255, 0.06)];
    border: 1px solid @border[rgba(255, 255, 255, 0.18)];
}
QComboBox#headerSearchCombo:focus,
QComboBox#headerSearchCombo:on {
    border: 1px solid @success[#22c55e];
}
QComboBox#headerSearchCombo::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: none;
}
QComboBox#headerSearchCombo QAbstractItemView {
    background-color: @popup[#1a1b20];
    color: @text[#e2e8f0];
    border: 1px solid @border[#2d3039];
    border-radius: 6px;
    padding: 4px 2px;
    outline: none;
    selection-background-color: @selection[#3e3e42];
    selection-color: @text_strong[#ffffff];
}
QComboBox#headerSearchCombo QAbstractItemView::item {
    min-height: 24px;
    padding: 3px 8px;
    margin: 1px 2px;
    border-radius: 4px;
    border: none;
    background-color: transparent;
    color: @text[#cbd5e1];
}
QComboBox#headerSearchCombo QAbstractItemView::item:hover,
QComboBox#headerSearchCombo QAbstractItemView::item:selected {
    background-color: @selection[#3e3e42];
    color: @text_strong[#ffffff];
}
QComboBox#headerSearchCombo QAbstractItemView::item:selected:hover {
    background-color: @selection[#4a4a50];
    color: @text_strong[#ffffff];
}
QComboBox#headerSearchCombo QAbstractItemView::item:focus {
    background-color: @selection[#3e3e42];
    color: @text_strong[#ffffff];
    outline: none;
}
""".strip(),
)

HEADER_STAT_CARD_STYLESHEET = themed_qss(
    """
QFrame#headerStatsContainer,
QFrame#headerNotificationsContainer {
    background-color: @surface[rgba(255, 255, 255, 0.03)];
    border: 1px solid @border[rgba(255, 255, 255, 0.08)];
    border-radius: 8px;
}
""".strip(),
)

HEADER_NOTIFICATION_BUTTON_ENABLED_STYLESHEET = themed_qss(
    """
QPushButton {
    background-color: @success[rgba(34, 197, 94, 0.08)];
    border: 1px solid @success[rgba(34, 197, 94, 0.25)];
    border-radius: 5px;
    padding: 0;
}
QPushButton:hover {
    background-color: @success[rgba(34, 197, 94, 0.18)];
    border: 1px solid @success[rgba(34, 197, 94, 0.45)];
}
QPushButton:pressed {
    background-color: @success[rgba(34, 197, 94, 0.26)];
}
""".strip(),
)

HEADER_NOTIFICATION_BUTTON_MUTED_STYLESHEET = themed_qss(
    """
QPushButton {
    background-color: @danger[rgba(239, 68, 68, 0.14)];
    border: 1px solid @danger[rgba(239, 68, 68, 0.38)];
    border-radius: 5px;
    padding: 0;
}
QPushButton:hover {
    background-color: @danger[rgba(239, 68, 68, 0.24)];
    border: 1px solid @danger[rgba(239, 68, 68, 0.55)];
}
QPushButton:pressed {
    background-color: @danger[rgba(239, 68, 68, 0.32)];
}
""".strip(),
)

STAT_CARD_TITLE_STYLESHEET = themed_qss('font-size: 7.5pt; font-weight: 600; color: @text_muted[#64748b]; letter-spacing: 0.3px;')

STAT_CARD_VALUE_STYLESHEET = themed_qss("font-size: 10.5pt; font-weight: 700; color: @success[#22c55e]; font-family: 'Menlo', 'Consolas', 'Courier New', monospace;")

HEADER_STATS_DIVIDER_STYLESHEET = themed_qss('background-color: @border[rgba(255, 255, 255, 0.08)]; border: none; max-width: 1px; min-width: 1px; margin: 4px 8px;')
