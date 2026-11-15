"""Stylesheets for the main application dashboard header."""

from session_sniffer.guis.theming import themed_qss

MAIN_HEADER_CONTAINER_STYLESHEET = themed_qss('QFrame#mainHeader { background-color: transparent; border: none; }')

HEADER_TITLE_STYLESHEET = themed_qss('font-size: 13pt; font-weight: 700; color: @text_strong;')

HEADER_VERSION_BADGE_STYLESHEET = themed_qss(
    """
color: @text_muted;
background-color: @surface;
border: 1px solid @border;
border-radius: 4px;
padding: 1px 6px;
font-size: 8pt;
font-weight: 500;
""".strip(),
)

HEADER_SUBTITLE_STYLESHEET = themed_qss('font-size: 8.5pt; color: @text_muted;')

HEADER_STOPPED_BADGE_STYLESHEET = themed_qss(
    """
color: @danger;
background-color: @surface~danger/16;
border: 1px solid @danger/45;
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
    color: @text;
    background-color: @input;
    border: 1px solid @border;
    border-radius: 6px;
    font-size: 9pt;
    selection-background-color: @selection;
    selection-color: @text_strong;
}
QLineEdit#headerSearchBar:hover {
    background-color: @input:hover;
    border: 1px solid @border:hover;
}
QLineEdit#headerSearchBar:focus {
    border: 1px solid @accent;
    background-color: @input;
}
""".strip(),
)

HEADER_SEARCH_COMBO_STYLESHEET = themed_qss(
    """
QComboBox#headerSearchCombo {
    min-height: 28px;
    max-height: 30px;
    padding: 0 24px 0 10px;
    color: @text;
    background-color: @input;
    border: 1px solid @border;
    border-radius: 6px;
    font-size: 9pt;
    selection-background-color: @selection;
    selection-color: @text_strong;
}
QComboBox#headerSearchCombo:hover {
    background-color: @input:hover;
    border: 1px solid @border:hover;
}
QComboBox#headerSearchCombo:focus,
QComboBox#headerSearchCombo:on {
    border: 1px solid @accent;
}
QComboBox#headerSearchCombo::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: none;
}
QComboBox#headerSearchCombo QAbstractItemView {
    background-color: @popup;
    color: @text;
    border: 1px solid @border;
    border-radius: 6px;
    padding: 4px 2px;
    outline: none;
    selection-background-color: @selection;
    selection-color: @text_strong;
}
QComboBox#headerSearchCombo QAbstractItemView::item {
    min-height: 24px;
    padding: 3px 8px;
    margin: 1px 2px;
    border-radius: 4px;
    border: none;
    background-color: transparent;
    color: @text;
}
QComboBox#headerSearchCombo QAbstractItemView::item:hover {
    background-color: @selection/65;
    color: @text_strong;
}
QComboBox#headerSearchCombo QAbstractItemView::item:selected {
    background-color: @selection;
    color: @text_strong;
}
QComboBox#headerSearchCombo QAbstractItemView::item:selected:hover {
    background-color: @selection:hover;
    color: @text_strong;
}
QComboBox#headerSearchCombo QAbstractItemView::item:focus {
    background-color: @selection;
    color: @text_strong;
    outline: none;
}
""".strip(),
)

HEADER_STAT_CARD_STYLESHEET = themed_qss(
    """
QFrame#headerStatsContainer,
QFrame#headerNotificationsContainer {
    background-color: @surface;
    border: 1px solid @border;
    border-radius: 8px;
}
""".strip(),
)

HEADER_NOTIFICATION_BUTTON_ENABLED_STYLESHEET = themed_qss(
    """
QPushButton {
    background-color: @control~success/16;
    border: 1px solid @success/40;
    border-radius: 5px;
    padding: 0;
}
QPushButton:hover {
    background-color: @control~success/28;
    border: 1px solid @success/65;
}
QPushButton:pressed {
    background-color: @control~success/22:pressed;
}
""".strip(),
)

HEADER_NOTIFICATION_BUTTON_MUTED_STYLESHEET = themed_qss(
    """
QPushButton {
    background-color: @control~danger/20;
    border: 1px solid @danger/45;
    border-radius: 5px;
    padding: 0;
}
QPushButton:hover {
    background-color: @control~danger/32;
    border: 1px solid @danger/70;
}
QPushButton:pressed {
    background-color: @control~danger/26:pressed;
}
""".strip(),
)

STAT_CARD_TITLE_STYLESHEET = themed_qss('font-size: 7.5pt; font-weight: 600; color: @text_muted; letter-spacing: 0.3px;')

STAT_CARD_VALUE_STYLESHEET = themed_qss("font-size: 10.5pt; font-weight: 700; color: @success; font-family: 'Menlo', 'Consolas', 'Courier New', monospace;")

HEADER_STATS_DIVIDER_STYLESHEET = themed_qss('background-color: @border; border: none; max-width: 1px; min-width: 1px; margin: 4px 8px;')
