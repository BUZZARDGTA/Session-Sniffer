"""Stylesheets for the main application dashboard header."""

MAIN_HEADER_CONTAINER_STYLESHEET = 'QFrame#mainHeader { background-color: transparent; border: none; }'

HEADER_TITLE_STYLESHEET = 'font-size: 13pt; font-weight: 700; color: #ffffff;'

HEADER_VERSION_BADGE_STYLESHEET = """
color: #94a3b8;
background-color: rgba(255, 255, 255, 0.06);
border: 1px solid rgba(255, 255, 255, 0.1);
border-radius: 4px;
padding: 1px 6px;
font-size: 8pt;
font-weight: 500;
""".strip()

HEADER_SUBTITLE_STYLESHEET = 'font-size: 8.5pt; color: #64748b;'

HEADER_STOPPED_BADGE_STYLESHEET = """
color: #ef4444;
background-color: rgba(239, 68, 68, 0.12);
border: 1px solid rgba(239, 68, 68, 0.35);
border-radius: 4px;
padding: 1px 7px;
font-size: 8pt;
font-weight: 700;
letter-spacing: 0.5px;
""".strip()

HEADER_SEARCH_BAR_STYLESHEET = """
QLineEdit#headerSearchBar {
    min-height: 28px;
    max-height: 30px;
    padding: 0 10px 0 8px;
    color: #f1f5f9;
    background-color: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    font-size: 9pt;
}
QLineEdit#headerSearchBar:hover {
    background-color: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.18);
}
QLineEdit#headerSearchBar:focus {
    border: 1px solid #22c55e;
    background-color: rgba(0, 0, 0, 0.45);
}
""".strip()

HEADER_SEARCH_COMBO_STYLESHEET = """
QComboBox#headerSearchCombo {
    min-height: 28px;
    max-height: 30px;
    padding: 0 24px 0 10px;
    color: #cbd5e1;
    background-color: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    font-size: 9pt;
    selection-background-color: #3e3e42;
}
QComboBox#headerSearchCombo:hover {
    background-color: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.18);
}
QComboBox#headerSearchCombo:focus,
QComboBox#headerSearchCombo:on {
    border: 1px solid #22c55e;
}
QComboBox#headerSearchCombo::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: none;
}
QComboBox#headerSearchCombo QAbstractItemView {
    background-color: #1a1b20;
    color: #e2e8f0;
    border: 1px solid #2d3039;
    border-radius: 6px;
    padding: 4px 2px;
    outline: none;
    selection-background-color: #3e3e42;
    selection-color: #ffffff;
}
QComboBox#headerSearchCombo QAbstractItemView::item {
    min-height: 24px;
    padding: 3px 8px;
    margin: 1px 2px;
    border-radius: 4px;
    border: none;
    background-color: transparent;
    color: #cbd5e1;
}
QComboBox#headerSearchCombo QAbstractItemView::item:hover,
QComboBox#headerSearchCombo QAbstractItemView::item:selected {
    background-color: #3e3e42;
    color: #ffffff;
}
QComboBox#headerSearchCombo QAbstractItemView::item:selected:hover {
    background-color: #4a4a50;
    color: #ffffff;
}
QComboBox#headerSearchCombo QAbstractItemView::item:focus {
    background-color: #3e3e42;
    color: #ffffff;
    outline: none;
}
""".strip()

HEADER_STAT_CARD_STYLESHEET = """
QFrame#headerStatsContainer {
    background-color: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
}
""".strip()

STAT_CARD_TITLE_STYLESHEET = 'font-size: 7.5pt; font-weight: 600; color: #64748b; letter-spacing: 0.3px;'

STAT_CARD_UPTIME_VALUE_STYLESHEET = "font-size: 10.5pt; font-weight: 700; color: #22c55e; font-family: 'Menlo', 'Consolas', 'Courier New', monospace;"

STAT_CARD_PACKETS_VALUE_STYLESHEET = "font-size: 10.5pt; font-weight: 700; color: #22c55e; font-family: 'Menlo', 'Consolas', 'Courier New', monospace;"

HEADER_STATS_DIVIDER_STYLESHEET = 'background-color: rgba(255, 255, 255, 0.08); border: none; max-width: 1px; min-width: 1px; margin: 4px 8px;'
